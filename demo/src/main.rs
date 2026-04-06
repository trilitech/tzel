/// StarkPrivacy v2 demo — post-quantum ledger + wallet.
///
/// This program demonstrates the full StarkPrivacy v2 protocol without a
/// blockchain or STARK proofs. It simulates:
///
///   - **Commitment tree T**: append-only Merkle tree of note commitments
///   - **Nullifier set NF_set**: prevents double-spend
///   - **Public balances**: simulates a token contract's ledger
///   - **ML-KEM-768 memos**: post-quantum encrypted note discovery
///   - **ML-KEM-768 detection**: fuzzy message detection with k-bit tags
///   - **Three-stage wallet scanning**: detect → decrypt → match address
///   - **Shield / Transfer / Unshield**: with value conservation checks
///
/// # v2 Key Hierarchy
///
/// ```text
///   master_sk
///   ├── spend_seed = H("spend", master_sk)
///   │   ├── nk       = H("nk",  spend_seed)    — account nullifier key
///   │   └── ask_base = H("ask", spend_seed)     — authorization derivation root
///   │       └── ak_j = H(H(ask_base, j))        — per-address auth verifying key
///   │
///   └── incoming_seed = H("incoming", master_sk)
///       └── dsk = H("dsk", incoming_seed)
///           └── d_j = H(dsk, j)                  — diversified address
/// ```
///
/// - Commitment: `cm = H_commit(d_j, v, rcm, ak)` — binds address + auth key
/// - Nullifier:  `nf = H_null(nk, cm)` — account-level, binds to commitment
/// - All hashing: BLAKE2s-256, 251-bit truncated, personalized IVs

use blake2s_simd::Params;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ml_kem::kem::{Encapsulate, Kem, TryDecapsulate};
use ml_kem::ml_kem_768;
use rand::Rng as _;
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════════════════════════
// BLAKE2s hashing — uses blake2s_simd with native personalization
// ═══════════════════════════════════════════════════════════════════════
//
// Each hash domain uses a different BLAKE2s personalization string:
//   - (none):       key derivation (hash, hash_two)
//   - "mrklSP__":   Merkle internal nodes
//   - "nulfSP__":   nullifiers
//   - "cmmtSP__":   note commitments
//
// All outputs are truncated to 251 bits (out[31] &= 0x07) to match
// Cairo's felt252 field.

/// A 256-bit value representing a field element (251-bit effective).
type F = [u8; 32];
const ZERO: F = [0u8; 32];

/// Detection tag precision: 10-bit tag → ~1/1024 false positive rate.
const DETECT_K: usize = 10;

/// User memo size: 1024 bytes for arbitrary data (payment refs, messages, etc.).
/// Padded with zeros if the sender provides less. Set to 0xF6 || zeros for "no memo"
/// (following the Zcash convention from ZIP 302).
const MEMO_SIZE: usize = 1024;

/// BLAKE2s-256 with personalization, truncated to 251 bits.
fn blake2s(personal: &[u8; 8], data: &[u8]) -> F {
    let digest = Params::new()
        .hash_length(32)
        .personal(personal)
        .hash(data);
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07; // truncate to 251 bits
    out
}

/// BLAKE2s-256 without personalization (generic), truncated to 251 bits.
fn blake2s_generic(data: &[u8]) -> F {
    let digest = Params::new()
        .hash_length(32)
        .hash(data);
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07;
    out
}

// ── Domain-specific hash functions ───────────────────────────────────

/// H(data) — generic hash (no personalization). Used for key derivation.
fn hash(data: &[u8]) -> F { blake2s_generic(data) }

/// H(a, b) — generic two-element hash. Used for key derivation intermediates.
fn hash_two(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    hash(&buf)
}

/// H_merkle(a, b) — Merkle tree internal node hash.
fn hash_merkle(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    blake2s(b"mrklSP__", &buf)
}

/// H_null(nk, cm) — nullifier hash.
fn hash_null(nk: &F, cm: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(nk);
    buf[32..].copy_from_slice(cm);
    blake2s(b"nulfSP__", &buf)
}

/// H_commit(data) — commitment hash.
fn hash_commit_raw(data: &[u8]) -> F {
    blake2s(b"cmmtSP__", data)
}

/// Derive commitment randomness: rcm = H(H(0x72636D), rseed).
/// The tag 0x72636D ("rcm" as an integer) is encoded in LE byte order
/// to match Cairo's felt252 encoding of integer literals.
fn derive_rcm(rseed: &F) -> F {
    let mut tag = ZERO;
    tag[0] = 0x6D; tag[1] = 0x63; tag[2] = 0x72; // 0x72636D in LE
    hash_two(&hash(&tag), rseed)
}

/// Note commitment: cm = H_commit(d_j, v, rcm, ak).
///
/// Layout of the 128-byte input:
///   bytes  0..31:  d_j (diversified address)
///   bytes 32..39:  v as u64 LE
///   bytes 40..63:  zeros (felt252 encoding of u64)
///   bytes 64..95:  rcm (commitment randomness)
///   bytes 96..127: ak (authorization verifying key — prevents prover substitution)
fn commit(d_j: &F, v: u64, rcm: &F, ak: &F) -> F {
    let mut buf = [0u8; 128];
    buf[..32].copy_from_slice(d_j);
    buf[32..40].copy_from_slice(&v.to_le_bytes());
    // bytes 40..64 intentionally zero — matches felt252 encoding of a u64
    buf[64..96].copy_from_slice(rcm);
    buf[96..128].copy_from_slice(ak);
    hash_commit_raw(&buf)
}

/// Nullifier: nf = H_null(nk, cm). Account-level nk bound to this commitment.
fn nullifier(nk: &F, cm: &F) -> F { hash_null(nk, cm) }

/// Display first 4 bytes as hex for readable output.
fn short(f: &F) -> String { hex::encode(&f[..4]) }

// ═══════════════════════════════════════════════════════════════════════
// Key derivation — matches common.cairo v2
// ═══════════════════════════════════════════════════════════════════════

/// Encode a tag string as a felt252 in LE byte order.
///
/// Cairo treats hex literals like 0x7370656E64 ("spend") as integers and
/// encodes them as LE bytes: "spend" → 0x7370656E64 → [0x64, 0x6E, 0x65, 0x70, 0x73, 0, ...].
/// This function reproduces that encoding so Rust and Cairo derive identical keys.
fn felt_tag(s: &[u8]) -> F {
    // Interpret ASCII string as a big-endian integer, then encode as LE bytes.
    let mut val = 0u128;
    for &b in s { val = (val << 8) | b as u128; }
    let mut f = ZERO;
    let le = val.to_le_bytes();
    f[..16].copy_from_slice(&le);
    f
}

/// Account keys derived from master_sk.
struct Account {
    nk: F,              // account nullifier key
    ask_base: F,        // authorization derivation root
    incoming_seed: F,   // root for address derivation
}

/// Derive account keys from master secret.
fn derive_account(master_sk: &F) -> Account {
    let spend_seed = hash_two(&felt_tag(b"spend"), master_sk);
    Account {
        nk: hash_two(&felt_tag(b"nk"), &spend_seed),
        ask_base: hash_two(&felt_tag(b"ask"), &spend_seed),
        incoming_seed: hash_two(&felt_tag(b"incoming"), master_sk),
    }
}

/// Derive a diversified address index d_j from the incoming seed.
fn derive_address(incoming_seed: &F, j: u32) -> F {
    let dsk = hash_two(&felt_tag(b"dsk"), incoming_seed);
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&j.to_le_bytes());
    hash_two(&dsk, &idx)
}

/// Derive the authorization verifying key ak_j = H(H(ask_base, j)).
fn derive_ak(ask_base: &F, j: u32) -> F {
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&j.to_le_bytes());
    hash(&hash_two(ask_base, &idx))
}

// ═══════════════════════════════════════════════════════════════════════
// ML-KEM-768 encryption + detection (post-quantum)
// ═══════════════════════════════════════════════════════════════════════
//
// Memos: sender encapsulates under the recipient's ML-KEM viewing key,
// derives a symmetric key, and encrypts (v, rseed) with ChaCha20-Poly1305.
//
// Detection: sender encapsulates under a separate ML-KEM detection key,
// computes a k-bit tag from the shared secret. The detection server
// decapsulates and checks the tag. ML-KEM's implicit rejection ensures
// non-matching ciphertexts produce pseudorandom shared secrets, giving
// a 2^(-k) false positive rate.

type Ek = ml_kem_768::EncapsulationKey;
type Dk = ml_kem_768::DecapsulationKey;

fn kem_gen() -> (Ek, Dk) {
    let (dk, ek) = ml_kem::MlKem768::generate_keypair();
    (ek, dk)
}

/// An encrypted note posted on-chain alongside its commitment.
///
/// On-chain layout per output note:
///   ct_d:           1088 bytes  ML-KEM detection ciphertext
///   tag:               2 bytes  k-bit detection tag
///   ct_v:           1088 bytes  ML-KEM memo ciphertext
///   encrypted_data: 1080 bytes  ChaCha20-Poly1305(v || rseed || user_memo) + 16-byte tag
///                  ────────────
///                   3258 bytes  (~3.2 KB per output note)
#[derive(Clone)]
struct EncryptedNote {
    ct_d: Vec<u8>,           // ML-KEM detection ciphertext (~1088 bytes)
    tag: u16,                // k-bit detection tag
    ct_v: Vec<u8>,           // ML-KEM memo ciphertext (~1088 bytes)
    encrypted_data: Vec<u8>, // AEAD(v:8 || rseed:32 || user_memo:1024) + 16 auth tag
}

/// Encrypt a note for the recipient. The `user_memo` is an arbitrary 1 KB
/// payload (payment references, messages, return addresses, etc.).
/// If shorter than 1024 bytes, it's zero-padded. If None, the memo field
/// is set to 0xF6 followed by zeros (Zcash "no memo" convention).
fn encrypt_note(v: u64, rseed: &F, user_memo: Option<&[u8]>, ek_v: &Ek, ek_d: &Ek) -> EncryptedNote {
    // Detection: encapsulate under ek_d, compute k-bit tag from shared secret.
    let (ct_d, ss_d): (ml_kem_768::Ciphertext, _) = ek_d.encapsulate();
    let tag_hash = hash(ss_d.as_slice());
    let tag = u16::from_le_bytes([tag_hash[0], tag_hash[1]]) & ((1 << DETECT_K) - 1);

    // Build plaintext: v (8 bytes) || rseed (32 bytes) || user_memo (1024 bytes).
    let mut plaintext = Vec::with_capacity(8 + 32 + MEMO_SIZE);
    plaintext.extend_from_slice(&v.to_le_bytes());
    plaintext.extend_from_slice(rseed);
    // Append user memo, padded to MEMO_SIZE.
    let mut memo_padded = vec![0u8; MEMO_SIZE];
    match user_memo {
        Some(m) => {
            let len = m.len().min(MEMO_SIZE);
            memo_padded[..len].copy_from_slice(&m[..len]);
        }
        None => {
            memo_padded[0] = 0xF6; // "no memo" marker (ZIP 302 convention)
        }
    }
    plaintext.extend_from_slice(&memo_padded);

    // Encrypt with ChaCha20-Poly1305. Key from fresh ML-KEM encapsulation.
    let (ct_v, ss_v): (ml_kem_768::Ciphertext, _) = ek_v.encapsulate();
    let key = hash(ss_v.as_slice());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    // Nonce is zero because the key is single-use (fresh KEM encapsulation).
    let encrypted_data = cipher.encrypt(Nonce::from_slice(&[0u8; 12]), plaintext.as_slice()).unwrap();

    EncryptedNote { ct_d: ct_d.to_vec(), tag, ct_v: ct_v.to_vec(), encrypted_data }
}

/// Detection: fast check if this note MIGHT be for us.
/// Returns true for real matches + ~2^(-k) false positives.
fn detect(enc: &EncryptedNote, dk_d: &Dk) -> bool {
    let ct = ml_kem_768::Ciphertext::try_from(enc.ct_d.as_slice()).unwrap();
    // ML-KEM implicit rejection: decapsulation always returns a shared secret,
    // but for non-matching ciphertexts it's pseudorandom (not the real one).
    let ss = dk_d.try_decapsulate(&ct).unwrap();
    let tag_hash = hash(ss.as_slice());
    let computed = u16::from_le_bytes([tag_hash[0], tag_hash[1]]) & ((1 << DETECT_K) - 1);
    computed == enc.tag
}

/// Decrypt a note: recover (v, rseed, user_memo) from ML-KEM + AEAD layers.
/// Returns None if decryption fails (wrong key or tampered ciphertext).
fn decrypt_memo(enc: &EncryptedNote, dk_v: &Dk) -> Option<(u64, F, Vec<u8>)> {
    let ct = ml_kem_768::Ciphertext::try_from(enc.ct_v.as_slice()).unwrap();
    let ss = dk_v.try_decapsulate(&ct).ok()?;
    let key = hash(ss.as_slice());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let pt = cipher.decrypt(Nonce::from_slice(&[0u8; 12]), enc.encrypted_data.as_slice()).ok()?;
    if pt.len() != 8 + 32 + MEMO_SIZE { return None; }
    let v = u64::from_le_bytes(pt[..8].try_into().unwrap());
    let mut rseed = ZERO;
    rseed.copy_from_slice(&pt[8..40]);
    let user_memo = pt[40..].to_vec();
    Some((v, rseed, user_memo))
}

// ═══════════════════════════════════════════════════════════════════════
// Merkle tree (depth 16, sparse, append-only)
// ═══════════════════════════════════════════════════════════════════════
//
// Empty leaves are 0. Zero hashes: z[0] = 0, z[i+1] = H_merkle(z[i], z[i]).
// The tree supports any historical root (append-only property).

const DEPTH: usize = 16;

struct MerkleTree {
    leaves: Vec<F>,
    zero_hashes: Vec<F>,
}

impl MerkleTree {
    fn new() -> Self {
        let mut z = vec![ZERO];
        for i in 0..DEPTH { z.push(hash_merkle(&z[i], &z[i])); }
        Self { leaves: vec![], zero_hashes: z }
    }

    /// Append a commitment and return its leaf index.
    fn append(&mut self, leaf: F) -> usize {
        let i = self.leaves.len();
        self.leaves.push(leaf);
        i
    }

    /// Compute the current root by hashing all levels bottom-up.
    fn root(&self) -> F { self.compute_level(0, &self.leaves) }

    fn compute_level(&self, depth: usize, level: &[F]) -> F {
        if depth == DEPTH {
            return if level.is_empty() { self.zero_hashes[DEPTH] } else { level[0] };
        }
        let mut next = vec![];
        let mut i = 0;
        loop {
            let left = if i < level.len() { level[i] } else { self.zero_hashes[depth] };
            let right = if i + 1 < level.len() { level[i + 1] } else { self.zero_hashes[depth] };
            next.push(hash_merkle(&left, &right));
            i += 2;
            if i >= level.len() && !next.is_empty() { break; }
        }
        self.compute_level(depth + 1, &next)
    }

    /// Extract the authentication path (DEPTH siblings) for a leaf.
    fn auth_path(&self, index: usize) -> (Vec<F>, F) {
        let mut level = self.leaves.clone();
        let mut siblings = vec![];
        let mut idx = index;
        for d in 0..DEPTH {
            let sib_idx = idx ^ 1;
            siblings.push(
                if sib_idx < level.len() { level[sib_idx] } else { self.zero_hashes[d] }
            );
            let mut next = vec![];
            let mut i = 0;
            loop {
                let left = if i < level.len() { level[i] } else { self.zero_hashes[d] };
                let right = if i + 1 < level.len() { level[i + 1] } else { self.zero_hashes[d] };
                next.push(hash_merkle(&left, &right));
                i += 2;
                if i >= level.len() { break; }
            }
            level = next;
            idx /= 2;
        }
        (siblings, level[0])
    }
}

/// Verify a Merkle path: hash leaf + siblings bottom-up, check == root.
fn verify_merkle(leaf: &F, root: &F, siblings: &[F], mut index: usize) {
    let mut current = *leaf;
    for sib in siblings {
        current = if index & 1 == 1 {
            hash_merkle(sib, &current)
        } else {
            hash_merkle(&current, sib)
        };
        index /= 2;
    }
    assert_eq!(&current, root, "merkle root mismatch");
}

// ═══════════════════════════════════════════════════════════════════════
// Wallet — three-stage scanning: detect → decrypt → match address
// ═══════════════════════════════════════════════════════════════════════

/// A private note with all its data.
#[derive(Clone)]
struct Note {
    nk: F,      // account nullifier key
    ak: F,      // authorization verifying key (bound into commitment)
    d_j: F,     // diversified address
    v: u64,     // amount
    rseed: F,   // per-note randomness
    cm: F,      // commitment
    index: usize, // Merkle tree leaf index
}

struct Wallet {
    account: Account,
    addr_counter: u32,
    ek_v: Ek, dk_v: Dk,  // ML-KEM viewing keys (memo decryption)
    ek_d: Ek, dk_d: Dk,  // ML-KEM detection keys
    notes: Vec<Note>,
    scanned: usize,       // memo scan cursor
}

impl Wallet {
    fn new() -> Self {
        let mut rng = rand::rng();
        let master_sk: F = rng.random();
        let account = derive_account(&master_sk);
        let (ek_v, dk_v) = kem_gen();
        let (ek_d, dk_d) = kem_gen();
        Self { account, addr_counter: 0, ek_v, dk_v, ek_d, dk_d, notes: vec![], scanned: 0 }
    }

    /// Generate a new diversified address + authorization key.
    fn next_address(&mut self) -> (F, F) {
        let j = self.addr_counter;
        let d_j = derive_address(&self.account.incoming_seed, j);
        let ak = derive_ak(&self.account.ask_base, j);
        self.addr_counter += 1;
        (d_j, ak)
    }

    /// Three-stage scanning:
    /// 1. Detection (ML-KEM decaps + tag check) — fast, ~1/1024 false positives
    /// 2. Memo decryption (ML-KEM decaps + AEAD) — filters false positives
    /// 3. Address matching — find which diversified address owns this note
    fn scan(&mut self, chain: &Chain) {
        let (mut detected, mut decrypted) = (0usize, 0usize);
        for i in self.scanned..chain.memos.len() {
            let (cm, enc) = &chain.memos[i];

            // Stage 1: detection — fast filter.
            if !detect(enc, &self.dk_d) { continue; }
            detected += 1;

            // Stage 2: memo decryption — authenticate and recover note data + user memo.
            let Some((v, rseed, _user_memo)) = decrypt_memo(enc, &self.dk_v) else { continue; };
            decrypted += 1;

            // Stage 3: try each address to find which d_j + ak produces this cm.
            let rcm = derive_rcm(&rseed);
            for j in 0..self.addr_counter {
                let d_j = derive_address(&self.account.incoming_seed, j);
                let ak = derive_ak(&self.account.ask_base, j);
                if &commit(&d_j, v, &rcm, &ak) == cm {
                    let index = chain.tree.leaves.iter().position(|l| l == cm).unwrap();
                    self.notes.push(Note { nk: self.account.nk, ak, d_j, v, rseed, cm: *cm, index });
                    println!("    found: v={} cm={} (det={} dec={})", v, short(cm), detected, decrypted);
                    break;
                }
            }
        }
        self.scanned = chain.memos.len();
    }

    /// Remove spent notes by their local indices.
    fn spend(&mut self, indices: &[usize]) {
        let mut sorted = indices.to_vec();
        sorted.sort_unstable();
        for &i in sorted.iter().rev() { self.notes.remove(i); }
    }

    fn balance(&self) -> u64 { self.notes.iter().map(|n| n.v).sum() }
}

// ═══════════════════════════════════════════════════════════════════════
// On-chain state
// ═══════════════════════════════════════════════════════════════════════

struct Chain {
    tree: MerkleTree,
    nullifiers: HashSet<F>,
    balances: HashMap<String, u64>,
    valid_roots: HashSet<F>,
    memos: Vec<(F, EncryptedNote)>,
}

impl Chain {
    fn new() -> Self {
        let tree = MerkleTree::new();
        let mut roots = HashSet::new();
        roots.insert(tree.root());
        Self { tree, nullifiers: HashSet::new(), balances: HashMap::new(), valid_roots: roots, memos: vec![] }
    }

    fn fund(&mut self, addr: &str, amount: u64) {
        *self.balances.entry(addr.into()).or_default() += amount;
    }

    fn snapshot_root(&mut self) { self.valid_roots.insert(self.tree.root()); }

    /// Shield: deposit public tokens into a private note.
    fn shield(&mut self, sender: &str, v: u64, d_j: &F, ak: &F, memo: Option<&[u8]>, ek_v: &Ek, ek_d: &Ek) -> Result<(), String> {
        let bal = self.balances.get(sender).copied().unwrap_or(0);
        if bal < v { return Err("insufficient balance".into()); }
        let mut rng = rand::rng();
        let rseed: F = rng.random();
        let rcm = derive_rcm(&rseed);
        let cm = commit(d_j, v, &rcm, ak);
        *self.balances.get_mut(sender).unwrap() -= v;
        let index = self.tree.append(cm);
        self.snapshot_root();
        self.memos.push((cm, encrypt_note(v, &rseed, memo, ek_v, ek_d)));
        println!("    cm={} index={}", short(&cm), index);
        Ok(())
    }

    /// Unshield: spend N notes → public withdrawal + optional private change.
    /// Mirrors the Cairo N→change+withdrawal circuit.
    fn unshield(
        &mut self, inputs: &[Note], v_pub: u64, recipient: &str,
        change: Option<(&F, &F, &Ek, &Ek)>, // (d_j, ak, ek_v, ek_d) for change output
    ) -> Result<(), String> {
        assert!(!inputs.is_empty() && inputs.len() <= 16);
        let root = self.tree.root();

        // Verify all inputs, compute nullifiers, sum values.
        let mut sum_in: u128 = 0;
        let mut nfs = vec![];
        for note in inputs {
            let (siblings, r) = self.tree.auth_path(note.index);
            assert_eq!(r, root, "root mismatch across inputs");
            verify_merkle(&note.cm, &root, &siblings, note.index);
            let nf = nullifier(&note.nk, &note.cm);
            if self.nullifiers.contains(&nf) { return Err("nullifier spent".into()); }
            nfs.push(nf);
            sum_in += note.v as u128;
        }
        if !self.valid_roots.contains(&root) { return Err("invalid root".into()); }

        // Pairwise nullifier distinctness.
        for i in 0..nfs.len() {
            for j in i+1..nfs.len() {
                assert_ne!(nfs[i], nfs[j], "duplicate nullifier");
            }
        }

        // Balance: sum_in = v_pub + v_change
        let v_change = sum_in - v_pub as u128;

        // Create change output if requested.
        if let Some((d_j, ak, ek_v, ek_d)) = change {
            assert!(v_change <= u64::MAX as u128);
            let mut rng = rand::rng();
            let rseed: F = rng.random();
            let rcm = derive_rcm(&rseed);
            let cm = commit(d_j, v_change as u64, &rcm, ak);
            let index = self.tree.append(cm);
            self.memos.push((cm, encrypt_note(v_change as u64, &rseed, None, ek_v, ek_d)));
            println!("    change cm={} v={} index={}", short(&cm), v_change, index);
        } else {
            assert_eq!(v_change, 0, "no change output but value remains");
        }

        // State updates.
        for nf in &nfs { self.nullifiers.insert(*nf); }
        *self.balances.entry(recipient.into()).or_default() += v_pub;
        self.snapshot_root();
        println!("    withdrawn v_pub={} to {} ({} inputs)", v_pub, recipient, inputs.len());
        Ok(())
    }

    /// Transfer: spend N notes → 2 private outputs. Value conserved.
    /// Mirrors the Cairo N→2 transfer circuit.
    fn transfer(
        &mut self, inputs: &[Note],
        d1: &F, ak1: &F, v1: u64, memo1: Option<&[u8]>, ev1: &Ek, ed1: &Ek,
        d2: &F, ak2: &F, v2: u64, memo2: Option<&[u8]>, ev2: &Ek, ed2: &Ek,
    ) -> Result<(), String> {
        assert!(!inputs.is_empty() && inputs.len() <= 16);
        let root = self.tree.root();

        // Verify all inputs.
        let mut sum_in: u128 = 0;
        let mut nfs = vec![];
        for note in inputs {
            let (siblings, r) = self.tree.auth_path(note.index);
            assert_eq!(r, root, "root mismatch");
            verify_merkle(&note.cm, &root, &siblings, note.index);
            let nf = nullifier(&note.nk, &note.cm);
            if self.nullifiers.contains(&nf) { return Err(format!("nf {} spent", short(&nf))); }
            nfs.push(nf);
            sum_in += note.v as u128;
        }
        if !self.valid_roots.contains(&root) { return Err("invalid root".into()); }

        // Pairwise nullifier distinctness.
        for i in 0..nfs.len() {
            for j in i+1..nfs.len() {
                assert_ne!(nfs[i], nfs[j], "duplicate nullifier");
            }
        }

        // Balance conservation.
        assert_eq!(sum_in, v1 as u128 + v2 as u128, "balance mismatch");

        // Create two output notes.
        let mut rng = rand::rng();
        for (d, ak, v, memo, ev, ed) in [(d1, ak1, v1, memo1, ev1, ed1), (d2, ak2, v2, memo2, ev2, ed2)] {
            let rseed: F = rng.random();
            let rcm = derive_rcm(&rseed);
            let cm = commit(d, v, &rcm, ak);
            let index = self.tree.append(cm);
            self.memos.push((cm, encrypt_note(v, &rseed, memo, ev, ed)));
            println!("    output cm={} v={} index={}", short(&cm), v, index);
        }
        for nf in &nfs { self.nullifiers.insert(*nf); }
        self.snapshot_root();
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

    println!("=== StarkPrivacy v2 (PQ, ML-KEM-768, diversified addresses) ===\n");

    // 1. Fund Alice publicly.
    chain.fund("alice", 2000);
    println!("[1] Fund alice with 2000");

    // 2-3. Shield: Alice deposits into private notes at diversified addresses.
    let (da1, ak_a1) = alice.next_address();
    let (da2, ak_a2) = alice.next_address();
    println!("[2] Shield 1500");
    chain.shield("alice", 1500, &da1, &ak_a1, None, &alice.ek_v, &alice.ek_d).unwrap();
    println!("[3] Shield 500");
    chain.shield("alice", 500, &da2, &ak_a2, None, &alice.ek_v, &alice.ek_d).unwrap();

    // 4. Alice scans: detection → decryption → address matching.
    println!("[4] Alice scans:");
    alice.scan(&chain);
    println!("    public={} private={}", chain.balances["alice"], alice.balance());

    // 5. Transfer N=2: Alice(1500+500) → Bob(1200) + Alice(800 change).
    let (db1, ak_b1) = bob.next_address();
    let (da3, ak_a3) = alice.next_address();
    println!("[5] Transfer (N=2): alice(1500+500) -> bob(1200) + alice(800)");
    println!("    (with memo: 'Payment for mass relay parts')");
    let inputs: Vec<Note> = alice.notes.clone();
    chain.transfer(
        &inputs,
        &db1, &ak_b1, 1200, Some(b"Payment for mass relay parts"), &bob.ek_v, &bob.ek_d,
        &da3, &ak_a3, 800, None, &alice.ek_v, &alice.ek_d,
    ).unwrap();
    alice.spend(&[0, 1]);

    // 6. Both scan.
    println!("[6] Scan:");
    alice.scan(&chain);
    bob.scan(&chain);
    println!("    alice={} bob={}", alice.balance(), bob.balance());

    // 7. Split N=1: Bob(1200) → Carol(500) + Bob(700 change).
    //    Demonstrates N=1 transfer — no dummy notes needed!
    let mut carol = Wallet::new();
    let (dc1, ak_c1) = carol.next_address();
    let (db2, ak_b2) = bob.next_address();
    println!("[7] Split (N=1): bob(1200) -> carol(500) + bob(700)");
    chain.transfer(
        &[bob.notes[0].clone()], // N=1: single input
        &dc1, &ak_c1, 500, None, &carol.ek_v, &carol.ek_d,
        &db2, &ak_b2, 700, None, &bob.ek_v, &bob.ek_d,
    ).unwrap();
    bob.spend(&[0]);

    println!("[8] Scan:");
    bob.scan(&chain);
    carol.scan(&chain);
    println!("    bob={} carol={}", bob.balance(), carol.balance());

    // 9. Unshield N=1 with change: Carol withdraws 200, keeps 300 private.
    let (dc2, ak_c2) = carol.next_address();
    println!("[9] Unshield (N=1 + change): carol withdraws 200, keeps 300");
    chain.unshield(
        &[carol.notes[0].clone()], 200, "carol",
        Some((&dc2, &ak_c2, &carol.ek_v, &carol.ek_d)),
    ).unwrap();
    carol.spend(&[0]);
    carol.scan(&chain);
    println!("    carol public={} private={}", chain.balances.get("carol").unwrap_or(&0), carol.balance());

    // 10. Double-spend rejected: try to re-spend Alice's notes (already spent in step 5).
    print!("[10] Double-spend (alice's notes from step 5): ");
    match chain.transfer(
        &inputs, // alice's notes, already spent in step 5
        &db1, &ak_b1, 1200, None, &bob.ek_v, &bob.ek_d,
        &da3, &ak_a3, 800, None, &alice.ek_v, &alice.ek_d,
    ) {
        Err(e) => println!("REJECTED ({})", e),
        Ok(()) => println!("BUG!"),
    }

    // Value conservation check.
    println!("\n=== Final State ===");
    let total = chain.balances.values().sum::<u64>()
        + alice.balance() + bob.balance() + carol.balance();
    println!("Tree: {} commitments, Nullifiers: {} spent",
        chain.tree.leaves.len(), chain.nullifiers.len());
    println!("Public:  alice={} bob={} carol={}",
        chain.balances.get("alice").unwrap_or(&0),
        chain.balances.get("bob").unwrap_or(&0),
        chain.balances.get("carol").unwrap_or(&0));
    println!("Private: alice={} bob={} carol={}",
        alice.balance(), bob.balance(), carol.balance());
    println!("Total:   {} (invariant: 2000)", total);
    assert_eq!(total, 2000, "value conservation violated!");
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Chain, Wallet, Wallet) {
        (Chain::new(), Wallet::new(), Wallet::new())
    }

    /// Shield → unshield roundtrip: value must return exactly.
    #[test]
    fn test_roundtrip() {
        let (mut c, mut a, _) = setup();
        c.fund("a", 1000);
        let (d, ak) = a.next_address();
        c.shield("a", 1000, &d, &ak, None, &a.ek_v, &a.ek_d).unwrap();
        a.scan(&c);
        assert_eq!(a.balance(), 1000);
        c.unshield(&[a.notes[0].clone()], 1000, "a", None).unwrap();
        assert_eq!(c.balances["a"], 1000);
    }

    /// Same nullifier rejected on second spend.
    #[test]
    fn test_double_spend() {
        let (mut c, mut a, _) = setup();
        c.fund("a", 500);
        let (d, ak) = a.next_address();
        c.shield("a", 500, &d, &ak, None, &a.ek_v, &a.ek_d).unwrap();
        a.scan(&c);
        let n = a.notes[0].clone();
        c.unshield(&[n.clone()], 500, "a", None).unwrap();
        assert!(c.unshield(&[n], 500, "a", None).is_err());
    }

    /// N=2 transfer conserves value.
    #[test]
    fn test_transfer_n2() {
        let (mut c, mut a, mut b) = setup();
        c.fund("a", 1000);
        let (d1, ak1) = a.next_address();
        let (d2, ak2) = a.next_address();
        c.shield("a", 600, &d1, &ak1, None, &a.ek_v, &a.ek_d).unwrap();
        c.shield("a", 400, &d2, &ak2, None, &a.ek_v, &a.ek_d).unwrap();
        a.scan(&c);
        let (db, akb) = b.next_address();
        let (da, aka) = a.next_address();
        let inputs: Vec<Note> = a.notes.clone();
        c.transfer(&inputs, &db, &akb, 700, None, &b.ek_v, &b.ek_d, &da, &aka, 300, None, &a.ek_v, &a.ek_d).unwrap();
        a.spend(&[0, 1]); a.scan(&c); b.scan(&c);
        assert_eq!(c.balances.values().sum::<u64>() + a.balance() + b.balance(), 1000);
    }

    /// N=1 split: one input → two outputs, no dummies needed.
    #[test]
    fn test_split_n1() {
        let (mut c, mut a, mut b) = setup();
        c.fund("a", 1000);
        let (d, ak) = a.next_address();
        c.shield("a", 1000, &d, &ak, None, &a.ek_v, &a.ek_d).unwrap();
        a.scan(&c);
        let (db, akb) = b.next_address();
        let (da, aka) = a.next_address();
        c.transfer(&[a.notes[0].clone()], &db, &akb, 400, None, &b.ek_v, &b.ek_d, &da, &aka, 600, None, &a.ek_v, &a.ek_d).unwrap();
        a.spend(&[0]); a.scan(&c); b.scan(&c);
        assert_eq!(a.balance(), 600);
        assert_eq!(b.balance(), 400);
    }

    /// Unshield with change: spend 1 note, withdraw part, keep rest private.
    #[test]
    fn test_unshield_with_change() {
        let (mut c, mut a, _) = setup();
        c.fund("a", 1000);
        let (d, ak) = a.next_address();
        c.shield("a", 1000, &d, &ak, None, &a.ek_v, &a.ek_d).unwrap();
        a.scan(&c);
        let (dc, akc) = a.next_address();
        c.unshield(&[a.notes[0].clone()], 300, "a", Some((&dc, &akc, &a.ek_v, &a.ek_d))).unwrap();
        a.spend(&[0]); a.scan(&c);
        assert_eq!(c.balances["a"], 300);  // 300 withdrawn to public
        assert_eq!(a.balance(), 700);       // 700 kept private as change
    }

    /// Detection: Bob's detector doesn't flag Alice's notes.
    #[test]
    fn test_detection_filters() {
        let (mut c, mut a, mut b) = setup();
        c.fund("a", 100);
        let (d, ak) = a.next_address();
        c.shield("a", 100, &d, &ak, None, &a.ek_v, &a.ek_d).unwrap();
        b.scan(&c);
        assert_eq!(b.balance(), 0);
        a.scan(&c);
        assert_eq!(a.balance(), 100);
    }

    /// Nullifier is deterministic and changes with nk.
    #[test]
    fn test_nullifier_determinism() {
        let master = [0x42u8; 32];
        let acc = derive_account(&master);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let rseed = [1u8; 32];
        let rcm = derive_rcm(&rseed);
        let ak = [3u8; 32];
        let cm = commit(&d_j, 100, &rcm, &ak);
        // Same inputs → same nullifier.
        assert_eq!(nullifier(&acc.nk, &cm), nullifier(&acc.nk, &cm));
        // Different nk → different nullifier.
        assert_ne!(nullifier(&acc.nk, &cm), nullifier(&[0x99u8; 32], &cm));
    }

    /// Cross-implementation test: Rust produces the same nk, ak, d_j, cm, nf
    /// as the Cairo circuit for master_sk=0xA11CE, note_a (address index 0).
    /// Expected values from `scarb execute --executable-name step_testvec`.
    #[test]
    fn test_cross_implementation() {
        // master_sk = 0xA11CE as 32-byte LE felt252.
        let mut master_sk = ZERO;
        master_sk[0] = 0xCE; master_sk[1] = 0x11; master_sk[2] = 0x0A;

        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ak = derive_ak(&acc.ask_base, 0);
        // rseed = 0x1001 as felt252 LE.
        let mut rseed = ZERO;
        rseed[0] = 0x01; rseed[1] = 0x10;
        let rcm = derive_rcm(&rseed);
        let cm = commit(&d_j, 1000, &rcm, &ak);
        let nf = nullifier(&acc.nk, &cm);

        // Expected values from Cairo execution.
        let exp_nk: F = [0xb5, 0x37, 0x35, 0x11, 0x2c, 0x79, 0xf4, 0x69, 0xb4, 0x0c, 0xe0, 0x59, 0x07, 0xb2, 0xb9, 0xd2, 0xb4, 0x55, 0x10, 0xdc, 0x93, 0x26, 0x1b, 0x44, 0x35, 0x2e, 0x58, 0x5d, 0x7a, 0xf3, 0xec, 0x01];
        let exp_ak: F = [0x7e, 0x77, 0x4c, 0x6c, 0x75, 0x4e, 0x51, 0x9e, 0x27, 0x0c, 0x15, 0xf9, 0x90, 0x3e, 0x01, 0xf5, 0x6e, 0x03, 0x25, 0xf5, 0x31, 0x2f, 0xac, 0x4f, 0x7f, 0xae, 0x10, 0xa3, 0x25, 0x74, 0xf1, 0x00];
        let exp_dj: F = [0x58, 0x37, 0x57, 0x8d, 0xcb, 0x85, 0x82, 0xf8, 0xf7, 0x07, 0x86, 0x50, 0x03, 0x45, 0xf8, 0x4a, 0x27, 0x21, 0x0d, 0x04, 0xc0, 0x29, 0x17, 0x47, 0x9a, 0x13, 0x52, 0x77, 0x40, 0x6b, 0x60, 0x05];
        let exp_cm: F = [0x48, 0x6b, 0x42, 0x64, 0x32, 0xef, 0x26, 0xdb, 0x67, 0x27, 0x66, 0xd0, 0x62, 0x09, 0xa0, 0x21, 0xa0, 0x43, 0xf5, 0xe6, 0x31, 0xbf, 0x16, 0x98, 0xbe, 0xa0, 0x14, 0x3f, 0x6c, 0x35, 0xbe, 0x02];
        let exp_nf: F = [0xd8, 0xf1, 0xa5, 0x4b, 0xd0, 0x04, 0x3b, 0xa9, 0xc3, 0xcc, 0xb9, 0x2a, 0x7a, 0x22, 0xeb, 0x19, 0x7a, 0x44, 0xa8, 0xad, 0xc3, 0xe2, 0x37, 0xbe, 0x34, 0xbc, 0x75, 0x48, 0xca, 0x8e, 0x7c, 0x06];

        assert_eq!(acc.nk, exp_nk, "nk mismatch");
        assert_eq!(ak, exp_ak, "ak mismatch");
        assert_eq!(d_j, exp_dj, "d_j mismatch");
        assert_eq!(cm, exp_cm, "cm mismatch");
        assert_eq!(nf, exp_nf, "nf mismatch");
    }
}
