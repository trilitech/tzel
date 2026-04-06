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
/// - Commitment: `cm = H_commit(d_j, v, rcm, owner_tag)` — binds address + auth + nullifier keys
/// - Nullifier:  `nf = H_nf(nk_spend, H_nf(cm, pos))` — position-dependent, per-address
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

/// Derive per-address secret nullifier key: nk_spend_j = H_nksp(nk, d_j).
fn derive_nk_spend(nk: &F, d_j: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(nk);
    buf[32..].copy_from_slice(d_j);
    blake2s(b"nkspSP__", &buf)
}

/// Derive per-address public binding tag: nk_tag_j = H_nktg(nk_spend_j).
fn derive_nk_tag(nk_spend: &F) -> F {
    blake2s(b"nktgSP__", nk_spend)
}

/// Owner tag: fuses ak and nk_tag. H_owner(ak, nk_tag).
fn owner_tag(ak: &F, nk_tag: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(ak);
    buf[32..].copy_from_slice(nk_tag);
    blake2s(b"ownrSP__", &buf)
}

/// Note commitment: cm = H_commit(d_j, v, rcm, owner_tag_j).
fn commit(d_j: &F, v: u64, rcm: &F, otag: &F) -> F {
    let mut buf = [0u8; 128];
    buf[..32].copy_from_slice(d_j);
    buf[32..40].copy_from_slice(&v.to_le_bytes());
    buf[64..96].copy_from_slice(rcm);
    buf[96..128].copy_from_slice(otag);
    hash_commit_raw(&buf)
}

/// Position-dependent nullifier: nf = H_nf(nk_spend, H_nf(cm, pos)).
fn nullifier(nk_spend: &F, cm: &F, pos: u64) -> F {
    let mut buf1 = [0u8; 64];
    buf1[..32].copy_from_slice(cm);
    let mut pos_f = ZERO;
    pos_f[..8].copy_from_slice(&pos.to_le_bytes());
    buf1[32..].copy_from_slice(&pos_f);
    let cm_pos = blake2s(b"nulfSP__", &buf1);
    let mut buf2 = [0u8; 64];
    buf2[..32].copy_from_slice(nk_spend);
    buf2[32..].copy_from_slice(&cm_pos);
    blake2s(b"nulfSP__", &buf2)
}

/// Compute the memo ciphertext hash that the circuit commits to.
/// This is H_memo(ct_v || encrypted_data) — the portion the recipient decrypts.
/// Uses a dedicated personalization ("memoSP__") for domain separation.
/// Computed client-side, passed into the circuit as a public input, and
/// verified on-chain by the contract against the posted calldata.
/// This prevents a malicious relayer from swapping memo data.
fn memo_ct_hash(enc: &EncryptedNote) -> F {
    let mut buf = Vec::with_capacity(enc.ct_v.len() + enc.encrypted_data.len());
    buf.extend_from_slice(&enc.ct_v);
    buf.extend_from_slice(&enc.encrypted_data);
    blake2s(b"memoSP__", &buf)
}

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
    let Ok(ct) = ml_kem_768::Ciphertext::try_from(enc.ct_d.as_slice()) else { return false; };
    // ML-KEM implicit rejection: decapsulation always returns a shared secret,
    // but for non-matching ciphertexts it's pseudorandom (not the real one).
    let ss = dk_d.try_decapsulate(&ct).expect("ML-KEM decaps is infallible");
    let tag_hash = hash(ss.as_slice());
    let computed = u16::from_le_bytes([tag_hash[0], tag_hash[1]]) & ((1 << DETECT_K) - 1);
    computed == enc.tag
}

/// Decrypt a note: recover (v, rseed, user_memo) from ML-KEM + AEAD layers.
/// Returns None if decryption fails (wrong key or tampered ciphertext).
fn decrypt_memo(enc: &EncryptedNote, dk_v: &Dk) -> Option<(u64, F, Vec<u8>)> {
    let ct = ml_kem_768::Ciphertext::try_from(enc.ct_v.as_slice()).ok()?;
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
    // Reject if index had bits above DEPTH (mirrors merkle.cairo range check).
    assert_eq!(index, 0, "path_indices out of range");
    assert_eq!(&current, root, "merkle root mismatch");
}

// ═══════════════════════════════════════════════════════════════════════
// Wallet — three-stage scanning: detect → decrypt → match address
// ═══════════════════════════════════════════════════════════════════════

/// A private note with all its data.
#[derive(Clone)]
struct Note {
    nk_spend: F, // per-address secret nullifier key (given to prover)
    nk_tag: F,   // per-address public binding tag (in payment address)
    ak: F,       // authorization verifying key
    d_j: F,      // diversified address
    v: u64,      // amount
    rseed: F,    // per-note randomness
    cm: F,       // commitment
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

    /// Generate a new diversified address + authorization key + nk_tag.
    /// Returns (d_j, ak_j, nk_tag_j).
    fn next_address(&mut self) -> (F, F, F) {
        let j = self.addr_counter;
        let d_j = derive_address(&self.account.incoming_seed, j);
        let ak = derive_ak(&self.account.ask_base, j);
        let nk_sp = derive_nk_spend(&self.account.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        self.addr_counter += 1;
        (d_j, ak, nk_tg)
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

            // Stage 3: try each address to find which d_j + ak + nk_tag produces this cm.
            let rcm = derive_rcm(&rseed);
            for j in 0..self.addr_counter {
                let d_j = derive_address(&self.account.incoming_seed, j);
                let ak = derive_ak(&self.account.ask_base, j);
                let nk_sp = derive_nk_spend(&self.account.nk, &d_j);
                let nk_tg = derive_nk_tag(&nk_sp);
                let otag = owner_tag(&ak, &nk_tg);
                if &commit(&d_j, v, &rcm, &otag) == cm {
                    let index = chain.tree.leaves.iter().position(|l| l == cm).unwrap();
                    self.notes.push(Note { nk_spend: nk_sp, nk_tag: nk_tg, ak, d_j, v, rseed, cm: *cm, index });
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

    fn balance(&self) -> u128 { self.notes.iter().map(|n| n.v as u128).sum() }
}

// ═══════════════════════════════════════════════════════════════════════
// On-chain state
// ═══════════════════════════════════════════════════════════════════════

struct Chain {
    tree: MerkleTree,
    nullifiers: HashSet<F>,
    /// Maps commitment → memo_ct_hash (simulates on-chain verification).
    memo_hashes: HashMap<F, F>,
    balances: HashMap<String, u64>,
    valid_roots: HashSet<F>,
    memos: Vec<(F, EncryptedNote)>,
}

impl Chain {
    fn new() -> Self {
        let tree = MerkleTree::new();
        let mut roots = HashSet::new();
        roots.insert(tree.root());
        Self { tree, nullifiers: HashSet::new(), memo_hashes: HashMap::new(), balances: HashMap::new(), valid_roots: roots, memos: vec![] }
    }

    fn fund(&mut self, addr: &str, amount: u64) {
        *self.balances.entry(addr.into()).or_default() += amount;
    }

    fn snapshot_root(&mut self) { self.valid_roots.insert(self.tree.root()); }

    /// Post an encrypted note on-chain: store it and record its memo hash.
    /// In production, the contract verifies H(posted_calldata) == memo_ct_hash
    /// from the proof's public outputs. Here we simulate that by storing the
    /// hash and verifying it in `verify_memo`.
    fn post_note(&mut self, cm: F, enc: EncryptedNote) {
        let mh = memo_ct_hash(&enc);
        self.memo_hashes.insert(cm, mh);
        self.memos.push((cm, enc));
    }

    /// Contract-side memo verification: check that the posted memo data
    /// matches the hash committed in the proof's public outputs.
    fn verify_memo(&self, cm: &F) -> bool {
        if let Some(expected) = self.memo_hashes.get(cm) {
            if let Some((_, enc)) = self.memos.iter().find(|(c, _)| c == cm) {
                return memo_ct_hash(enc) == *expected;
            }
        }
        false
    }

    /// Shield: deposit public tokens into a private note.
    fn shield(&mut self, sender: &str, v: u64, d_j: &F, ak: &F, nk_tag: &F, memo: Option<&[u8]>, ek_v: &Ek, ek_d: &Ek) -> Result<(), String> {
        let bal = self.balances.get(sender).copied().unwrap_or(0);
        if bal < v { return Err("insufficient balance".into()); }
        let mut rng = rand::rng();
        let rseed: F = rng.random();
        let rcm = derive_rcm(&rseed);
        let otag = owner_tag(ak, nk_tag);
        let cm = commit(d_j, v, &rcm, &otag);
        *self.balances.get_mut(sender).unwrap() -= v;
        let index = self.tree.append(cm);
        self.snapshot_root();
        self.post_note(cm, encrypt_note(v, &rseed, memo, ek_v, ek_d));
        println!("    cm={} index={}", short(&cm), index);
        Ok(())
    }

    /// Unshield: spend N notes → public withdrawal + optional private change.
    /// Mirrors the Cairo N→change+withdrawal circuit.
    fn unshield(
        &mut self, inputs: &[Note], v_pub: u64, recipient: &str,
        change: Option<(&F, &F, &F, &Ek, &Ek)>, // (d_j, ak, nk_tag, ek_v, ek_d) for change output
    ) -> Result<(), String> {
        if inputs.is_empty() || inputs.len() > 16 { return Err("bad input count".into()); }
        let root = self.tree.root();

        // Verify all inputs, compute position-dependent nullifiers, sum values.
        let mut sum_in: u128 = 0;
        let mut nfs = vec![];
        for note in inputs {
            let (siblings, r) = self.tree.auth_path(note.index);
            if r != root { return Err("root mismatch across inputs".into()); }
            verify_merkle(&note.cm, &root, &siblings, note.index);
            let nf = nullifier(&note.nk_spend, &note.cm, note.index as u64);
            if self.nullifiers.contains(&nf) { return Err(format!("nf {} spent", short(&nf))); }
            nfs.push(nf);
            sum_in += note.v as u128;
        }
        if !self.valid_roots.contains(&root) { return Err("invalid root".into()); }

        // Pairwise nullifier distinctness.
        for i in 0..nfs.len() {
            for j in i+1..nfs.len() {
                if nfs[i] == nfs[j] { return Err("duplicate nullifier".into()); }
            }
        }

        // Balance: sum_in = v_pub + v_change
        if (v_pub as u128) > sum_in { return Err("withdrawal exceeds inputs".into()); }
        let v_change = sum_in - v_pub as u128;

        // Create change output if requested.
        if let Some((d_j, ak, nk_tag, ek_v, ek_d)) = change {
            if v_change > u64::MAX as u128 { return Err("change overflow".into()); }
            let mut rng = rand::rng();
            let rseed: F = rng.random();
            let rcm = derive_rcm(&rseed);
            let otag = owner_tag(ak, nk_tag);
            let cm = commit(d_j, v_change as u64, &rcm, &otag);
            let index = self.tree.append(cm);
            self.post_note(cm, encrypt_note(v_change as u64, &rseed, None, ek_v, ek_d));
            println!("    change cm={} v={} index={}", short(&cm), v_change, index);
        } else if v_change != 0 {
            return Err("no change output but value remains".into());
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
        d1: &F, ak1: &F, nkt1: &F, v1: u64, memo1: Option<&[u8]>, ev1: &Ek, ed1: &Ek,
        d2: &F, ak2: &F, nkt2: &F, v2: u64, memo2: Option<&[u8]>, ev2: &Ek, ed2: &Ek,
    ) -> Result<(), String> {
        if inputs.is_empty() || inputs.len() > 16 { return Err("bad input count".into()); }
        let root = self.tree.root();

        // Verify all inputs.
        let mut sum_in: u128 = 0;
        let mut nfs = vec![];
        for note in inputs {
            let (siblings, r) = self.tree.auth_path(note.index);
            if r != root { return Err("root mismatch".into()); }
            verify_merkle(&note.cm, &root, &siblings, note.index);
            let nf = nullifier(&note.nk_spend, &note.cm, note.index as u64);
            if self.nullifiers.contains(&nf) { return Err(format!("nf {} spent", short(&nf))); }
            nfs.push(nf);
            sum_in += note.v as u128;
        }
        if !self.valid_roots.contains(&root) { return Err("invalid root".into()); }

        // Pairwise nullifier distinctness.
        for i in 0..nfs.len() {
            for j in i+1..nfs.len() {
                if nfs[i] == nfs[j] { return Err("duplicate nullifier".into()); }
            }
        }

        // Balance conservation.
        let sum_out = v1 as u128 + v2 as u128;
        if sum_in != sum_out { return Err(format!("balance mismatch: in={} out={}", sum_in, sum_out)); }

        // Create two output notes.
        let mut rng = rand::rng();
        for (d, ak, nkt, v, memo, ev, ed) in [(d1,ak1,nkt1,v1,memo1,ev1,ed1),(d2,ak2,nkt2,v2,memo2,ev2,ed2)] {
            let rseed: F = rng.random();
            let rcm = derive_rcm(&rseed);
            let otag = owner_tag(ak, nkt);
            let cm = commit(d, v, &rcm, &otag);
            let index = self.tree.append(cm);
            self.post_note(cm, encrypt_note(v, &rseed, memo, ev, ed));
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
    let (da1, ak_a1, nkt_a1) = alice.next_address();
    let (da2, ak_a2, nkt_a2) = alice.next_address();
    println!("[2] Shield 1500");
    chain.shield("alice", 1500, &da1, &ak_a1, &nkt_a1, None, &alice.ek_v, &alice.ek_d).unwrap();
    println!("[3] Shield 500");
    chain.shield("alice", 500, &da2, &ak_a2, &nkt_a2, None, &alice.ek_v, &alice.ek_d).unwrap();

    // 4. Alice scans: detection → decryption → address matching.
    println!("[4] Alice scans:");
    alice.scan(&chain);
    println!("    public={} private={}", chain.balances["alice"], alice.balance());

    // 5. Transfer N=2: Alice(1500+500) → Bob(1200) + Alice(800 change).
    let (db1, ak_b1, nkt_b1) = bob.next_address();
    let (da3, ak_a3, nkt_a3) = alice.next_address();
    println!("[5] Transfer (N=2): alice(1500+500) -> bob(1200) + alice(800)");
    println!("    (with memo: 'Payment for mass relay parts')");
    let inputs: Vec<Note> = alice.notes.clone();
    chain.transfer(
        &inputs,
        &db1, &ak_b1, &nkt_b1, 1200, Some(b"Payment for mass relay parts"), &bob.ek_v, &bob.ek_d,
        &da3, &ak_a3, &nkt_a3, 800, None, &alice.ek_v, &alice.ek_d,
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
    let (dc1, ak_c1, nkt_c1) = carol.next_address();
    let (db2, ak_b2, nkt_b2) = bob.next_address();
    println!("[7] Split (N=1): bob(1200) -> carol(500) + bob(700)");
    chain.transfer(
        &[bob.notes[0].clone()], // N=1: single input
        &dc1, &ak_c1, &nkt_c1, 500, None, &carol.ek_v, &carol.ek_d,
        &db2, &ak_b2, &nkt_b2, 700, None, &bob.ek_v, &bob.ek_d,
    ).unwrap();
    bob.spend(&[0]);

    println!("[8] Scan:");
    bob.scan(&chain);
    carol.scan(&chain);
    println!("    bob={} carol={}", bob.balance(), carol.balance());

    // 9. Unshield N=1 with change: Carol withdraws 200, keeps 300 private.
    let (dc2, ak_c2, nkt_c2) = carol.next_address();
    println!("[9] Unshield (N=1 + change): carol withdraws 200, keeps 300");
    chain.unshield(
        &[carol.notes[0].clone()], 200, "carol",
        Some((&dc2, &ak_c2, &nkt_c2, &carol.ek_v, &carol.ek_d)),
    ).unwrap();
    carol.spend(&[0]);
    carol.scan(&chain);
    println!("    carol public={} private={}", chain.balances.get("carol").unwrap_or(&0), carol.balance());

    // 10. Double-spend rejected: try to re-spend Alice's notes (already spent in step 5).
    print!("[10] Double-spend (alice's notes from step 5): ");
    match chain.transfer(
        &inputs, // alice's notes, already spent in step 5
        &db1, &ak_b1, &nkt_b1, 1200, None, &bob.ek_v, &bob.ek_d,
        &da3, &ak_a3, &nkt_a3, 800, None, &alice.ek_v, &alice.ek_d,
    ) {
        Err(e) => println!("REJECTED ({})", e),
        Ok(()) => println!("BUG!"),
    }

    // Value conservation check.
    println!("\n=== Final State ===");
    let total: u128 = chain.balances.values().map(|&v| v as u128).sum::<u128>()
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
        let (d, ak, nkt) = a.next_address();
        c.shield("a", 1000, &d, &ak, &nkt, None, &a.ek_v, &a.ek_d).unwrap();
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
        let (d, ak, nkt) = a.next_address();
        c.shield("a", 500, &d, &ak, &nkt, None, &a.ek_v, &a.ek_d).unwrap();
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
        let (d1, ak1, nkt1) = a.next_address();
        let (d2, ak2, nkt2) = a.next_address();
        c.shield("a", 600, &d1, &ak1, &nkt1, None, &a.ek_v, &a.ek_d).unwrap();
        c.shield("a", 400, &d2, &ak2, &nkt2, None, &a.ek_v, &a.ek_d).unwrap();
        a.scan(&c);
        let (db, akb, nktb) = b.next_address();
        let (da, aka, nkta) = a.next_address();
        let inputs: Vec<Note> = a.notes.clone();
        c.transfer(&inputs, &db, &akb, &nktb, 700, None, &b.ek_v, &b.ek_d, &da, &aka, &nkta, 300, None, &a.ek_v, &a.ek_d).unwrap();
        a.spend(&[0, 1]); a.scan(&c); b.scan(&c);
        assert_eq!(c.balances.values().map(|&v| v as u128).sum::<u128>() + a.balance() + b.balance(), 1000);
    }

    /// N=1 split: one input → two outputs, no dummies needed.
    #[test]
    fn test_split_n1() {
        let (mut c, mut a, mut b) = setup();
        c.fund("a", 1000);
        let (d, ak, nkt) = a.next_address();
        c.shield("a", 1000, &d, &ak, &nkt, None, &a.ek_v, &a.ek_d).unwrap();
        a.scan(&c);
        let (db, akb, nktb) = b.next_address();
        let (da, aka, nkta) = a.next_address();
        c.transfer(&[a.notes[0].clone()], &db, &akb, &nktb, 400, None, &b.ek_v, &b.ek_d, &da, &aka, &nkta, 600, None, &a.ek_v, &a.ek_d).unwrap();
        a.spend(&[0]); a.scan(&c); b.scan(&c);
        assert_eq!(a.balance(), 600);
        assert_eq!(b.balance(), 400);
    }

    /// Unshield with change: spend 1 note, withdraw part, keep rest private.
    #[test]
    fn test_unshield_with_change() {
        let (mut c, mut a, _) = setup();
        c.fund("a", 1000);
        let (d, ak, nkt) = a.next_address();
        c.shield("a", 1000, &d, &ak, &nkt, None, &a.ek_v, &a.ek_d).unwrap();
        a.scan(&c);
        let (dc, akc, nktc) = a.next_address();
        c.unshield(&[a.notes[0].clone()], 300, "a", Some((&dc, &akc, &nktc, &a.ek_v, &a.ek_d))).unwrap();
        a.spend(&[0]); a.scan(&c);
        assert_eq!(c.balances["a"], 300);  // 300 withdrawn to public
        assert_eq!(a.balance(), 700);       // 700 kept private as change
    }

    /// Detection: Bob's detector doesn't flag Alice's notes.
    #[test]
    fn test_detection_filters() {
        let (mut c, mut a, mut b) = setup();
        c.fund("a", 100);
        let (d, ak, nkt) = a.next_address();
        c.shield("a", 100, &d, &ak, &nkt, None, &a.ek_v, &a.ek_d).unwrap();
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
        let ak = derive_ak(&acc.ask_base, 0);
        let rseed = [1u8; 32];
        let rcm = derive_rcm(&rseed);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&ak, &nk_tg);
        let cm = commit(&d_j, 100, &rcm, &otag);
        // Same inputs → same nullifier.
        assert_eq!(nullifier(&nk_sp, &cm, 0), nullifier(&nk_sp, &cm, 0));
        // Different nk_spend → different nullifier.
        assert_ne!(nullifier(&nk_sp, &cm, 0), nullifier(&[0x99u8; 32], &cm, 0));
        // Different position → different nullifier.
        assert_ne!(nullifier(&nk_sp, &cm, 0), nullifier(&nk_sp, &cm, 1));
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
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&ak, &nk_tg);
        // rseed = 0x1001 as felt252 LE.
        let mut rseed = ZERO;
        rseed[0] = 0x01; rseed[1] = 0x10;
        let rcm = derive_rcm(&rseed);
        let cm = commit(&d_j, 1000, &rcm, &otag);
        let nf = nullifier(&nk_sp, &cm, 0); // position 0

        // Expected values from Cairo execution (nk, ak, d_j unchanged from v2).
        let exp_nk: F = [0xb5, 0x37, 0x35, 0x11, 0x2c, 0x79, 0xf4, 0x69, 0xb4, 0x0c, 0xe0, 0x59, 0x07, 0xb2, 0xb9, 0xd2, 0xb4, 0x55, 0x10, 0xdc, 0x93, 0x26, 0x1b, 0x44, 0x35, 0x2e, 0x58, 0x5d, 0x7a, 0xf3, 0xec, 0x01];
        let exp_ak: F = [0x7e, 0x77, 0x4c, 0x6c, 0x75, 0x4e, 0x51, 0x9e, 0x27, 0x0c, 0x15, 0xf9, 0x90, 0x3e, 0x01, 0xf5, 0x6e, 0x03, 0x25, 0xf5, 0x31, 0x2f, 0xac, 0x4f, 0x7f, 0xae, 0x10, 0xa3, 0x25, 0x74, 0xf1, 0x00];
        let exp_dj: F = [0x58, 0x37, 0x57, 0x8d, 0xcb, 0x85, 0x82, 0xf8, 0xf7, 0x07, 0x86, 0x50, 0x03, 0x45, 0xf8, 0x4a, 0x27, 0x21, 0x0d, 0x04, 0xc0, 0x29, 0x17, 0x47, 0x9a, 0x13, 0x52, 0x77, 0x40, 0x6b, 0x60, 0x05];

        assert_eq!(acc.nk, exp_nk, "nk mismatch");
        assert_eq!(ak, exp_ak, "ak mismatch");
        assert_eq!(d_j, exp_dj, "d_j mismatch");

        // New expected values: commitment uses owner_tag, nullifier is position-dependent.
        let exp_nk_spend: F = [89, 19, 110, 41, 180, 183, 205, 41, 33, 134, 117, 152, 235, 7, 229, 229, 174, 217, 114, 252, 177, 224, 229, 91, 121, 80, 186, 245, 67, 249, 85, 3];
        let exp_nk_tag: F = [17, 89, 69, 49, 250, 242, 253, 209, 28, 237, 96, 154, 132, 8, 133, 43, 190, 121, 73, 113, 232, 18, 75, 149, 255, 222, 50, 80, 19, 210, 134, 1];
        let exp_cm: F = [241, 116, 8, 46, 91, 152, 152, 54, 44, 207, 95, 107, 157, 140, 1, 47, 26, 163, 128, 163, 85, 219, 249, 243, 60, 122, 214, 24, 101, 104, 231, 1];
        let exp_nf: F = [18, 119, 163, 62, 249, 45, 40, 118, 113, 139, 231, 234, 244, 251, 255, 149, 64, 73, 95, 179, 25, 8, 173, 155, 221, 146, 35, 139, 102, 121, 246, 4];

        assert_eq!(nk_sp, exp_nk_spend, "nk_spend mismatch");
        assert_eq!(nk_tg, exp_nk_tag, "nk_tag mismatch");
        assert_eq!(cm, exp_cm, "cm mismatch");
        assert_eq!(nf, exp_nf, "nf mismatch");
    }

    /// memo_ct_hash is recorded for every posted note and is deterministic.
    #[test]
    fn test_memo_ct_hash_recorded() {
        let (mut c, mut a, _) = setup();
        c.fund("a", 100);
        let (d, ak, nkt) = a.next_address();
        c.shield("a", 100, &d, &ak, &nkt, Some(b"test memo"), &a.ek_v, &a.ek_d).unwrap();
        // The chain should have recorded a memo hash for the commitment.
        let cm = c.tree.leaves[0];
        assert!(c.memo_hashes.contains_key(&cm), "memo hash not recorded");
        let mh = c.memo_hashes[&cm];
        assert_ne!(mh, ZERO, "memo hash should not be zero");
    }

    /// Tampering with the encrypted memo data is detected by the
    /// contract-side verify_memo check.
    #[test]
    fn test_memo_tamper_detected() {
        let (mut c, mut a, _) = setup();
        c.fund("a", 100);
        let (d, ak, nkt) = a.next_address();
        c.shield("a", 100, &d, &ak, &nkt, Some(b"real memo"), &a.ek_v, &a.ek_d).unwrap();
        let cm = c.tree.leaves[0];

        // Before tampering: memo verification passes.
        assert!(c.verify_memo(&cm), "memo should verify before tampering");

        // Simulate a relayer tampering with the encrypted data.
        c.memos[0].1.encrypted_data[0] ^= 0xFF;

        // After tampering: memo verification fails.
        assert!(!c.verify_memo(&cm), "tampered memo should fail verification");
    }
}
