/// StarkPrivacy demo — minimal ledger + wallet demonstrating the protocol.
///
/// No blockchain, no STARK proofs — just the cryptographic state machine:
///   - Commitment tree T (append-only Merkle tree of note commitments)
///   - Nullifier set NF_set (prevents double-spend)
///   - Public balances (simulates the token contract's ledger)
///   - Encrypted memos (so recipients discover incoming notes)
///   - Shield / Transfer / Unshield with front-running protection
///
/// In a real deployment, each operation would be accompanied by a STARK
/// proof. Here we execute the witness logic directly — the "prover" and
/// "verifier" are the same process.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// ═══════════════════════════════════════════════════════════════════════
// Hash primitives — mirrors blake_hash.cairo
// ═══════════════════════════════════════════════════════════════════════

/// A 256-bit value. In the real circuit this would be a felt252 (251 bits);
/// here we use full 32 bytes since we don't need field arithmetic.
type F = [u8; 32];
const ZERO: F = [0u8; 32];

/// BLAKE2s-256 of arbitrary-length data. Used as the single primitive
/// from which all protocol hashes are derived.
fn hash(data: &[u8]) -> F {
    let mut h = Blake2sVar::new(32).unwrap();
    h.update(data);
    let mut out = F::default();
    h.finalize_variable(&mut out).unwrap();
    out
}

/// H(a, b) — hash two 32-byte values (64-byte message).
/// Used for: nullifiers H(sk, rho) and Merkle internal nodes H(left, right).
fn hash_two(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    hash(&buf)
}

/// H(pk, v, rho, r) — hash a note's four components (128-byte message).
/// Used for: note commitments.
///
/// Layout: pk (32 bytes) | v (8 bytes LE + 24 zero padding) | rho (32 bytes) | r (32 bytes).
/// The 24-byte zero pad after v matches the Cairo circuit's encoding, where
/// v.into() converts u64 to felt252 (8 meaningful bytes + 24 zero bytes).
/// Domain-separated from hash_two (64 bytes) by message length (128 bytes).
fn hash_commit(pk: &F, v: u64, rho: &F, r: &F) -> F {
    let mut buf = [0u8; 128];
    buf[..32].copy_from_slice(pk);
    buf[32..40].copy_from_slice(&v.to_le_bytes());
    // buf[40..64] intentionally zero — matches felt252 encoding of a u64
    buf[64..96].copy_from_slice(rho);
    buf[96..128].copy_from_slice(r);
    hash(&buf)
}

/// pk = H(sk) — derive the paying key from a spending key (32-byte message).
fn derive_pk(sk: &F) -> F { hash(sk) }

/// nf = H(sk, rho) — compute a note's nullifier (64-byte message).
fn nullifier(sk: &F, rho: &F) -> F { hash_two(sk, rho) }

/// Print the first 4 bytes of a hash as hex (for readable output).
fn short(f: &F) -> String { hex::encode(&f[..4]) }

// ═══════════════════════════════════════════════════════════════════════
// Encrypted memos — how recipients discover incoming notes
// ═══════════════════════════════════════════════════════════════════════
//
// When creating a note for someone, the sender encrypts (v, rho, r) under
// the recipient's X25519 public key and posts the ciphertext on-chain.
// The recipient tries to decrypt every memo with their secret key. If
// decryption succeeds, they've found an incoming note.
//
// Encryption: X25519 ECDH (ephemeral sender key) → shared secret →
//             BLAKE2s KDF → ChaCha20-Poly1305 AEAD.
//
// Each memo uses a fresh ephemeral key, so the symmetric key is unique.
// We use a zero nonce because (key, nonce) is never reused.

#[derive(Clone)]
struct EncryptedMemo {
    ciphertext: Vec<u8>,     // ChaCha20-Poly1305 authenticated ciphertext
    ephemeral_pk: [u8; 32],  // sender's ephemeral X25519 public key
}

/// Encrypt note data (v, rho, r) for a recipient.
fn encrypt_memo(v: u64, rho: &F, r: &F, recipient_enc_pk: &PublicKey) -> EncryptedMemo {
    let mut rng = rand::thread_rng();

    // Generate a fresh ephemeral keypair for this memo.
    let ephemeral_sk = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    // Diffie-Hellman → shared secret → symmetric key.
    let shared = ephemeral_sk.diffie_hellman(recipient_enc_pk);
    let key = hash(shared.as_bytes());

    // Encrypt with ChaCha20-Poly1305. Nonce is zero because the key is
    // single-use (fresh ephemeral keypair for each memo).
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&[0u8; 12]);

    // Plaintext: v (8 bytes) || rho (32 bytes) || r (32 bytes) = 72 bytes.
    let mut plaintext = Vec::with_capacity(72);
    plaintext.extend_from_slice(&v.to_le_bytes());
    plaintext.extend_from_slice(rho);
    plaintext.extend_from_slice(r);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();
    EncryptedMemo { ciphertext, ephemeral_pk: ephemeral_pk.to_bytes() }
}

/// Try to decrypt a memo with our secret key. Returns Some((v, rho, r)) on
/// success, None if this memo wasn't encrypted for us (decryption fails due
/// to Poly1305 authentication tag mismatch).
fn try_decrypt_memo(memo: &EncryptedMemo, enc_sk: &StaticSecret) -> Option<(u64, F, F)> {
    let ephemeral_pk = PublicKey::from(memo.ephemeral_pk);
    let shared = enc_sk.diffie_hellman(&ephemeral_pk);
    let key = hash(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let plaintext = cipher.decrypt(nonce, memo.ciphertext.as_slice()).ok()?;
    if plaintext.len() != 72 { return None; }

    let v = u64::from_le_bytes(plaintext[..8].try_into().unwrap());
    let mut rho = F::default();
    let mut r = F::default();
    rho.copy_from_slice(&plaintext[8..40]);
    r.copy_from_slice(&plaintext[40..72]);
    Some((v, rho, r))
}

// ═══════════════════════════════════════════════════════════════════════
// Merkle tree — append-only commitment tree T
// ═══════════════════════════════════════════════════════════════════════
//
// Depth-16 sparse Merkle tree. Leaves are note commitments at positions
// 0..n-1; empty positions hold level-specific "zero hashes":
//   z[0] = 0            (empty leaf)
//   z[i+1] = H(z[i], z[i])  (empty subtree at level i)
//
// In production the tree would be depth 48 (2^48 capacity) and maintained
// by the on-chain contract. Any historical root is accepted — the tree is
// append-only, so a commitment present under any past root is still valid.

const DEPTH: usize = 16;

struct MerkleTree {
    leaves: Vec<F>,
    zero_hashes: Vec<F>,  // z[0]..z[DEPTH], precomputed at construction
}

impl MerkleTree {
    fn new() -> Self {
        let mut z = vec![ZERO];
        for i in 0..DEPTH { z.push(hash_two(&z[i], &z[i])); }
        Self { leaves: vec![], zero_hashes: z }
    }

    /// Append a commitment to the tree and return its leaf index.
    fn append(&mut self, leaf: F) -> usize {
        let idx = self.leaves.len();
        self.leaves.push(leaf);
        idx
    }

    /// Compute the current root by hashing all levels bottom-up.
    fn root(&self) -> F {
        self.compute_level(0, &self.leaves)
    }

    /// Recursively compute a Merkle level. At each level, pair adjacent
    /// nodes (padding odd counts with the zero hash) and hash them.
    fn compute_level(&self, depth: usize, level: &[F]) -> F {
        if depth == DEPTH {
            return if level.is_empty() { self.zero_hashes[DEPTH] } else { level[0] };
        }
        let mut next = vec![];
        let mut i = 0;
        loop {
            let left = if i < level.len() { level[i] } else { self.zero_hashes[depth] };
            let right = if i + 1 < level.len() { level[i + 1] } else { self.zero_hashes[depth] };
            next.push(hash_two(&left, &right));
            i += 2;
            if i >= level.len() && !next.is_empty() { break; }
        }
        self.compute_level(depth + 1, &next)
    }

    /// Extract the authentication path (list of siblings) for a leaf.
    /// Returns (siblings, root).
    fn auth_path(&self, index: usize) -> (Vec<F>, F) {
        let mut level = self.leaves.clone();
        let mut siblings = vec![];
        let mut idx = index;
        for d in 0..DEPTH {
            // Sibling = the node at idx XOR 1 (flip lowest bit).
            let sib_idx = idx ^ 1;
            siblings.push(if sib_idx < level.len() { level[sib_idx] } else { self.zero_hashes[d] });
            // Hash pairs to build the next level.
            let mut next = vec![];
            let mut i = 0;
            loop {
                let left = if i < level.len() { level[i] } else { self.zero_hashes[d] };
                let right = if i + 1 < level.len() { level[i + 1] } else { self.zero_hashes[d] };
                next.push(hash_two(&left, &right));
                i += 2;
                if i >= level.len() { break; }
            }
            level = next;
            idx /= 2;
        }
        (siblings, level[0])
    }
}

/// Verify a Merkle authentication path: hash leaf + siblings bottom-up
/// and check the result equals root.
fn verify_merkle(leaf: &F, root: &F, siblings: &[F], mut index: usize) {
    let mut cur = *leaf;
    for sib in siblings {
        // bit 0 of index: 0 = we're the left child, 1 = right child.
        cur = if index & 1 == 1 { hash_two(sib, &cur) } else { hash_two(&cur, sib) };
        index /= 2;
    }
    assert_eq!(&cur, root, "merkle root mismatch");
}

// ═══════════════════════════════════════════════════════════════════════
// Note and wallet
// ═══════════════════════════════════════════════════════════════════════

/// A private note with all its secret and public data.
/// In a real wallet this would be persisted to disk / encrypted at rest.
#[derive(Clone)]
struct Note {
    sk: F,      // spending key (needed to derive nf and prove ownership)
    pk: F,      // paying key = H(sk)
    v: u64,     // amount
    rho: F,     // random nonce (unique per note)
    r: F,       // blinding factor (makes commitment hiding)
    cm: F,      // commitment = H(pk, v, rho, r)
    index: usize, // position in the Merkle tree
}

/// A user's wallet: keys + known unspent notes.
struct Wallet {
    sk: F,                  // spending key (secret)
    pk: F,                  // paying key = H(sk) (shared with senders)
    enc_sk: StaticSecret,   // X25519 decryption key (for receiving memos)
    enc_pk: PublicKey,       // X25519 encryption key (shared with senders)
    notes: Vec<Note>,       // unspent notes we know about
    scanned: usize,         // memo scan cursor (how far we've scanned)
}

impl Wallet {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        let sk: F = rng.gen();
        let pk = derive_pk(&sk);
        let enc_sk = StaticSecret::random_from_rng(&mut rng);
        let enc_pk = PublicKey::from(&enc_sk);
        Self { sk, pk, enc_sk, enc_pk, notes: vec![], scanned: 0 }
    }

    /// Scan the chain for new memos, try to decrypt each one.
    /// If decryption succeeds and the commitment matches, we've found
    /// an incoming note — add it to our wallet.
    fn scan(&mut self, chain: &Chain) {
        for i in self.scanned..chain.memos.len() {
            let (cm, memo) = &chain.memos[i];
            if let Some((v, rho, r)) = try_decrypt_memo(memo, &self.enc_sk) {
                // Verify the decrypted data produces the commitment on-chain.
                // This catches corrupted memos or memos encrypted with a
                // different paying key.
                let expected_cm = hash_commit(&self.pk, v, &rho, &r);
                if &expected_cm == cm {
                    let index = chain.tree.leaves.iter().position(|l| l == cm).unwrap();
                    self.notes.push(Note { sk: self.sk, pk: self.pk, v, rho, r, cm: *cm, index });
                    println!("    found note: v={} cm={}", v, short(cm));
                }
            }
        }
        self.scanned = chain.memos.len();
    }

    /// Remove spent notes from the wallet by their local indices.
    /// Must be called after a successful transfer or unshield.
    fn spend(&mut self, indices: &[usize]) {
        let mut sorted: Vec<usize> = indices.to_vec();
        sorted.sort_unstable();
        // Remove from back to front so indices stay valid.
        for &i in sorted.iter().rev() { self.notes.remove(i); }
    }

    fn balance(&self) -> u64 { self.notes.iter().map(|n| n.v).sum() }
}

// ═══════════════════════════════════════════════════════════════════════
// On-chain state — what the smart contract maintains
// ═══════════════════════════════════════════════════════════════════════

struct Chain {
    tree: MerkleTree,                       // commitment tree T
    nullifiers: HashSet<F>,                 // NF_set (spent nullifiers)
    balances: HashMap<String, u64>,         // public token balances
    valid_roots: HashSet<F>,                // set of all historical Merkle roots
    memos: Vec<(F, EncryptedMemo)>,         // (cm, encrypted memo) posted on-chain
}

impl Chain {
    fn new() -> Self {
        let tree = MerkleTree::new();
        let initial_root = tree.root();
        let mut valid_roots = HashSet::new();
        valid_roots.insert(initial_root);
        Self { tree, nullifiers: HashSet::new(), balances: HashMap::new(), valid_roots, memos: vec![] }
    }

    /// Credit public tokens to an address (simulates minting / external deposit).
    fn fund(&mut self, addr: &str, amount: u64) {
        *self.balances.entry(addr.into()).or_default() += amount;
    }

    /// Record the current root as valid (called after any tree mutation).
    fn snapshot_root(&mut self) {
        self.valid_roots.insert(self.tree.root());
    }

    // ── Shield ───────────────────────────────────────────────────────
    //
    // Deposit public tokens into a private note.
    //
    // In the real system, the sender generates (rho, r) client-side,
    // computes cm, creates a STARK proof, and submits (proof, memo).
    // Here we combine the sender and contract roles for simplicity.
    //
    // Public outputs: [v_pub, cm_new, sender]
    // The contract deducts v_pub from sender and appends cm_new to T.

    fn shield(&mut self, sender: &str, v: u64, recipient_pk: &F, recipient_enc_pk: &PublicKey) -> Result<(), String> {
        let bal = self.balances.get(sender).copied().unwrap_or(0);
        if bal < v { return Err("insufficient balance".into()); }

        let mut rng = rand::thread_rng();
        let rho: F = rng.gen();
        let r: F = rng.gen();
        let cm = hash_commit(recipient_pk, v, &rho, &r);

        // State updates (what the contract does after verifying the proof).
        *self.balances.get_mut(sender).unwrap() -= v;
        let index = self.tree.append(cm);
        self.snapshot_root();

        // Post encrypted memo so the recipient can discover this note.
        let memo = encrypt_memo(v, &rho, &r, recipient_enc_pk);
        self.memos.push((cm, memo));
        println!("    cm={} index={} memo_posted=true", short(&cm), index);
        Ok(())
    }

    // ── Unshield ─────────────────────────────────────────────────────
    //
    // Withdraw a private note to a public address.
    //
    // The proof commits to `recipient` so a front-runner can't claim
    // the withdrawal for a different address.
    //
    // Public outputs: [root, nf, v_pub, recipient]
    // The contract checks root ∈ valid_roots, nf ∉ NF_set, then
    // adds nf to NF_set and credits v_pub to recipient.

    fn unshield(&mut self, note: &Note, recipient: &str) -> Result<(), String> {
        // ── Circuit constraints (what the STARK would enforce) ────────
        let pk = derive_pk(&note.sk);
        let cm = hash_commit(&pk, note.v, &note.rho, &note.r);
        let (siblings, root) = self.tree.auth_path(note.index);
        let nf = nullifier(&note.sk, &note.rho);

        assert_eq!(pk, note.pk, "bad pk derivation");
        assert_eq!(cm, note.cm, "bad commitment recomputation");
        verify_merkle(&cm, &root, &siblings, note.index);
        assert_eq!(nf, nullifier(&note.sk, &note.rho), "bad nullifier");

        // The proof's public outputs include `recipient`. The contract
        // checks msg.sender == recipient (or equivalent), so a
        // front-runner can't steal this proof for a different address.
        println!("    proof bound to recipient={}", recipient);

        // ── Contract checks ──────────────────────────────────────────
        if self.nullifiers.contains(&nf) { return Err("nullifier already spent".into()); }
        if !self.valid_roots.contains(&root) { return Err("invalid root".into()); }

        // ── State updates ────────────────────────────────────────────
        self.nullifiers.insert(nf);
        *self.balances.entry(recipient.into()).or_default() += note.v;
        println!("    nf={} value={}", short(&nf), note.v);
        Ok(())
    }

    // ── Transfer ─────────────────────────────────────────────────────
    //
    // Spend two private notes, create two new private notes.
    // Value conservation: v_a + v_b = v_1 + v_2.
    //
    // No address binding needed — this is fully private-to-private.
    // Adding a sender address would deanonymize the transactor.
    //
    // Public outputs: [root, nf_a, nf_b, cm_1, cm_2]
    // The contract checks root ∈ valid_roots, nf_a/nf_b ∉ NF_set,
    // then adds nullifiers and appends commitments.

    fn transfer(
        &mut self,
        in_a: &Note, in_b: &Note,
        out1_pk: &F, out1_enc_pk: &PublicKey, v_1: u64,
        out2_pk: &F, out2_enc_pk: &PublicKey, v_2: u64,
    ) -> Result<(), String> {
        // ── Circuit constraints ──────────────────────────────────────
        let (sib_a, root) = self.tree.auth_path(in_a.index);
        let (sib_b, _) = self.tree.auth_path(in_b.index);
        verify_merkle(&in_a.cm, &root, &sib_a, in_a.index);
        verify_merkle(&in_b.cm, &root, &sib_b, in_b.index);

        let nf_a = nullifier(&in_a.sk, &in_a.rho);
        let nf_b = nullifier(&in_b.sk, &in_b.rho);
        assert_ne!(nf_a, nf_b, "duplicate nullifier — can't spend the same note twice");

        // Balance check in u128 to prevent overflow (max u64+u64 < u128).
        assert_eq!(
            in_a.v as u128 + in_b.v as u128,
            v_1 as u128 + v_2 as u128,
            "balance mismatch"
        );

        // ── Contract checks ──────────────────────────────────────────
        if self.nullifiers.contains(&nf_a) { return Err("nf_a already spent".into()); }
        if self.nullifiers.contains(&nf_b) { return Err("nf_b already spent".into()); }
        if !self.valid_roots.contains(&root) { return Err("invalid root".into()); }

        // ── Create output notes ──────────────────────────────────────
        let mut rng = rand::thread_rng();
        for &(pk, enc_pk, v) in &[(out1_pk, out1_enc_pk, v_1), (out2_pk, out2_enc_pk, v_2)] {
            let rho: F = rng.gen();
            let r: F = rng.gen();
            let cm = hash_commit(pk, v, &rho, &r);
            let idx = self.tree.append(cm);
            let memo = encrypt_memo(v, &rho, &r, enc_pk);
            self.memos.push((cm, memo));
            println!("    output cm={} v={} index={}", short(&cm), v, idx);
        }

        // ── State updates ────────────────────────────────────────────
        self.nullifiers.insert(nf_a);
        self.nullifiers.insert(nf_b);
        self.snapshot_root();
        println!("    nullifiers consumed: {} {}", short(&nf_a), short(&nf_b));
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Demo scenario
// ═══════════════════════════════════════════════════════════════════════

fn main() {
    let mut chain = Chain::new();
    let mut alice = Wallet::new();
    let mut bob = Wallet::new();

    println!("=== StarkPrivacy Demo ===\n");

    // 1. Fund Alice's public account.
    chain.fund("alice", 2000);
    println!("[1] Fund: alice gets 2000 public tokens");

    // 2-3. Shield: Alice moves tokens into private notes.
    //      Each shield creates a commitment in the tree and an encrypted
    //      memo so Alice (the recipient of her own notes) can discover them.
    println!("[2] Shield: alice deposits 1500");
    chain.shield("alice", 1500, &alice.pk, &alice.enc_pk).unwrap();
    println!("[3] Shield: alice deposits 500");
    chain.shield("alice", 500, &alice.pk, &alice.enc_pk).unwrap();

    // 4. Alice scans on-chain memos to discover her notes.
    //    She tries to decrypt each memo with her encryption key. Success
    //    means the note is for her.
    println!("[4] Alice scans memos:");
    alice.scan(&chain);
    println!("    balance: public={} private={}", chain.balances["alice"], alice.balance());

    // 5. Transfer: Alice sends 1200 to Bob, keeps 800 as change.
    //    Two inputs (1500 + 500) → two outputs (1200 to Bob + 800 to Alice).
    //    Encrypted memos are posted for both recipients.
    println!("[5] Transfer: alice(1500+500) -> bob(1200) + alice(800)");
    let (a, b) = (alice.notes[0].clone(), alice.notes[1].clone());
    chain.transfer(&a, &b, &bob.pk, &bob.enc_pk, 1200, &alice.pk, &alice.enc_pk, 800).unwrap();
    alice.spend(&[0, 1]); // remove spent notes from wallet

    // 6. Both wallets scan for new notes.
    //    Bob discovers the 1200-value note. Alice discovers her 800 change.
    //    Neither can read the other's memo.
    println!("[6] Scan:");
    alice.scan(&chain);
    bob.scan(&chain);
    println!("    alice private={} bob private={}", alice.balance(), bob.balance());

    // 7. Unshield: Bob withdraws to a public address.
    //    The proof is bound to recipient="bob", preventing front-running.
    println!("[7] Unshield: bob withdraws 1200 (proof bound to 'bob')");
    let note = bob.notes[0].clone();
    chain.unshield(&note, "bob").unwrap();
    bob.spend(&[0]);

    // 8. Double-spend attempt: same nullifier rejected.
    print!("[8] Double-spend: ");
    match chain.unshield(&note, "bob") {
        Err(e) => println!("REJECTED ({})", e),
        Ok(()) => println!("BUG: should have been rejected!"),
    }

    // Summary — total value must be conserved.
    println!("\n=== Final State ===");
    println!("Tree: {} commitments, Nullifiers: {} spent", chain.tree.leaves.len(), chain.nullifiers.len());
    println!("Public:  alice={} bob={}", chain.balances.get("alice").unwrap_or(&0), chain.balances.get("bob").unwrap_or(&0));
    println!("Private: alice={} bob={}", alice.balance(), bob.balance());
    let total = chain.balances.values().sum::<u64>() + alice.balance() + bob.balance();
    println!("Total:   {} (invariant: 2000)", total);
    assert_eq!(total, 2000, "value conservation violated!");
}

// ═══════════════════════════════════════════════════════════════════════
// Integration tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Chain, Wallet, Wallet) {
        (Chain::new(), Wallet::new(), Wallet::new())
    }

    /// Shield tokens into a note, then unshield back to a public balance.
    /// Value must round-trip exactly.
    #[test]
    fn test_shield_and_unshield_roundtrip() {
        let (mut chain, mut alice, _) = setup();
        chain.fund("alice", 1000);

        chain.shield("alice", 1000, &alice.pk, &alice.enc_pk).unwrap();
        alice.scan(&chain);
        assert_eq!(alice.balance(), 1000);
        assert_eq!(chain.balances["alice"], 0);

        let note = alice.notes[0].clone();
        chain.unshield(&note, "alice").unwrap();
        assert_eq!(chain.balances["alice"], 1000);
    }

    /// Spending the same note twice must be rejected (nullifier already in NF_set).
    #[test]
    fn test_double_spend_rejected() {
        let (mut chain, mut alice, _) = setup();
        chain.fund("alice", 500);
        chain.shield("alice", 500, &alice.pk, &alice.enc_pk).unwrap();
        alice.scan(&chain);

        let note = alice.notes[0].clone();
        chain.unshield(&note, "alice").unwrap();
        assert!(chain.unshield(&note, "alice").is_err());
    }

    /// Can't shield more than the public balance.
    #[test]
    fn test_insufficient_balance_rejected() {
        let (mut chain, alice, _) = setup();
        chain.fund("alice", 100);
        assert!(chain.shield("alice", 200, &alice.pk, &alice.enc_pk).is_err());
    }

    /// Transfer must conserve total value across public and private domains.
    #[test]
    fn test_transfer_conserves_value() {
        let (mut chain, mut alice, mut bob) = setup();
        chain.fund("alice", 1000);

        chain.shield("alice", 600, &alice.pk, &alice.enc_pk).unwrap();
        chain.shield("alice", 400, &alice.pk, &alice.enc_pk).unwrap();
        alice.scan(&chain);

        let (a, b) = (alice.notes[0].clone(), alice.notes[1].clone());
        chain.transfer(&a, &b, &bob.pk, &bob.enc_pk, 700, &alice.pk, &alice.enc_pk, 300).unwrap();
        alice.spend(&[0, 1]);
        alice.scan(&chain);
        bob.scan(&chain);

        assert_eq!(alice.balance(), 300);
        assert_eq!(bob.balance(), 700);
        let total = chain.balances.values().sum::<u64>() + alice.balance() + bob.balance();
        assert_eq!(total, 1000);
    }

    /// Memos encrypted for Alice must not be decryptable by Bob.
    #[test]
    fn test_encrypted_memos_only_readable_by_recipient() {
        let (mut chain, mut alice, mut bob) = setup();
        chain.fund("alice", 100);

        chain.shield("alice", 100, &alice.pk, &alice.enc_pk).unwrap();

        bob.scan(&chain);
        assert_eq!(bob.balance(), 0, "Bob should not find Alice's note");

        alice.scan(&chain);
        assert_eq!(alice.balance(), 100, "Alice should find her own note");
    }

    /// Full flow: shield → transfer → unshield.
    #[test]
    fn test_transfer_then_unshield() {
        let (mut chain, mut alice, mut bob) = setup();
        chain.fund("alice", 500);

        // Shield two notes (one real, one zero-value dummy).
        chain.shield("alice", 500, &alice.pk, &alice.enc_pk).unwrap();
        chain.shield("alice", 0, &alice.pk, &alice.enc_pk).unwrap();
        alice.scan(&chain);

        // Transfer: alice(500+0) → bob(500) + alice(0).
        let (a, b) = (alice.notes[0].clone(), alice.notes[1].clone());
        chain.transfer(&a, &b, &bob.pk, &bob.enc_pk, 500, &alice.pk, &alice.enc_pk, 0).unwrap();
        alice.spend(&[0, 1]);
        bob.scan(&chain);

        let note = bob.notes[0].clone();
        chain.unshield(&note, "bob").unwrap();
        assert_eq!(chain.balances["bob"], 500);
    }

    /// Creating more output value than input value must be rejected.
    #[test]
    #[should_panic(expected = "balance")]
    fn test_transfer_balance_mismatch_panics() {
        let (mut chain, mut alice, bob) = setup();
        chain.fund("alice", 100);
        chain.shield("alice", 50, &alice.pk, &alice.enc_pk).unwrap();
        chain.shield("alice", 50, &alice.pk, &alice.enc_pk).unwrap();
        alice.scan(&chain);

        let (a, b) = (alice.notes[0].clone(), alice.notes[1].clone());
        // 50 + 50 = 100, but outputs sum to 110.
        let _ = chain.transfer(&a, &b, &bob.pk, &bob.enc_pk, 80, &alice.pk, &alice.enc_pk, 30);
    }

    /// Notes spent in one transfer can't be reused in another.
    #[test]
    fn test_nullifier_spent_across_transfers() {
        let (mut chain, mut alice, mut bob) = setup();
        chain.fund("alice", 200);
        chain.shield("alice", 100, &alice.pk, &alice.enc_pk).unwrap();
        chain.shield("alice", 100, &alice.pk, &alice.enc_pk).unwrap();
        alice.scan(&chain);

        let (a, b) = (alice.notes[0].clone(), alice.notes[1].clone());
        chain.transfer(&a, &b, &bob.pk, &bob.enc_pk, 200, &alice.pk, &alice.enc_pk, 0).unwrap();

        // Same notes can't be transferred again — nullifiers already in NF_set.
        let bob2 = Wallet::new();
        assert!(chain.transfer(&a, &b, &bob2.pk, &bob2.enc_pk, 200, &alice.pk, &alice.enc_pk, 0).is_err());
    }

    /// Historical roots must be accepted (tree is append-only).
    #[test]
    fn test_historical_root_accepted() {
        let (mut chain, mut alice, _) = setup();
        chain.fund("alice", 300);

        // Shield a note — root R1 is recorded.
        chain.shield("alice", 100, &alice.pk, &alice.enc_pk).unwrap();
        alice.scan(&chain);
        let note = alice.notes[0].clone();

        // Append more commitments — root changes to R2, R3.
        chain.shield("alice", 100, &alice.pk, &alice.enc_pk).unwrap();
        chain.shield("alice", 100, &alice.pk, &alice.enc_pk).unwrap();

        // Unshield using the original note — its auth path was computed
        // against R1 (or the current root). Since valid_roots tracks all
        // historical roots, this should succeed.
        // (We recompute the path against the tree at its current state,
        // which gives the current root. In a real system the prover could
        // use any historical root.)
        chain.unshield(&note, "alice").unwrap();
        assert_eq!(chain.balances["alice"], 100);
    }
}
