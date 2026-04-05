/// StarkPrivacy demo — minimal ledger + wallet with delegated proving.
///
/// Demonstrates the full protocol without a blockchain or STARK proofs:
///   - Commitment tree T (append-only Merkle tree of note commitments)
///   - Nullifier set NF_set (prevents double-spend)
///   - Public balances (simulates the token contract's ledger)
///   - Encrypted memos (so recipients discover incoming notes)
///   - Shield / Transfer / Unshield with spend authorization
///
/// # Key hierarchy (Sapling-style, enables delegated proving)
///
/// ```text
///   master_sk                                     — root secret, never leaves the wallet
///   ├── nsk_i = H(H("nsk", master), i)            — nullifier key (given to prover)
///   │   └── pk_i = H(nsk_i)                       — paying key (public, given to senders)
///   └── ask_i = H(H("ask", master), i)            — authorization key (NEVER shared)
///       └── ak_i = H(ask_i)                       — verification key (public, in proof output)
/// ```
///
/// The prover receives (nsk, ak) — enough to generate the STARK proof.
/// The user keeps ask and signs the proof outputs afterward. The contract
/// verifies the signature against ak. No pre-registration needed.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// ═══════════════════════════════════════════════════════════════════════
// Hash primitives — mirrors blake_hash.cairo
// ═══════════════════════════════════════════════════════════════════════
//
// All protocol hashing uses BLAKE2s-256 truncated to 251 bits (matching
// Cairo's felt252 field). Domain separation is by message length:
//   hash(32 bytes)  — key derivation (pk = H(nsk), ak = H(ask))
//   hash(64 bytes)  — nullifiers H(nsk, rho), Merkle nodes H(L, R), owner key H(pk, ak)
//   hash(128 bytes) — commitments H(owner_key, v, rho, r)

/// A 256-bit value. Represents a field element (felt252) as 32 LE bytes.
/// The top 5 bits (bits 251-255) are always zero after hashing.
type F = [u8; 32];
const ZERO: F = [0u8; 32];

/// BLAKE2s-256 with optional personalization, truncated to 251 bits.
///
/// `personal` is an 8-byte personalization string. If empty, no
/// personalization (used for key derivation hash1).
///
/// The truncation (clearing bits 251-255) matches the Cairo circuit's
/// `u32x8_to_felt` with mask 0x07FFFFFF on word 7.
fn hash_with_personal(data: &[u8], personal: &[u8; 8]) -> F {
    use blake2::digest::consts::U32;
    use blake2::Blake2s;
    use blake2::digest::typenum::Unsigned;

    // Blake2sVar doesn't support personalization directly.
    // We use the low-level parameter API via Blake2sVar with params.
    // Actually, blake2 crate's Blake2sVar doesn't expose personalization.
    // So we compute the personalized IV manually and feed it through
    // the raw compression, matching what Cairo does.
    //
    // For simplicity, we implement BLAKE2s manually for the final block.
    // This mirrors the Cairo approach: compute personalized IV, then compress.

    // BLAKE2s IV
    let iv: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    // Parameter block
    let p0: u32 = 0x01010020; // digest=32, key=0, fanout=1, depth=1
    let p6 = u32::from_le_bytes([personal[0], personal[1], personal[2], personal[3]]);
    let p7 = u32::from_le_bytes([personal[4], personal[5], personal[6], personal[7]]);

    let mut h = [0u32; 8];
    for i in 0..8 { h[i] = iv[i]; }
    h[0] ^= p0;
    h[6] ^= p6;
    h[7] ^= p7;

    // We need to run BLAKE2s compression with this custom IV.
    // The blake2 crate doesn't expose this, so we use a standalone
    // BLAKE2s implementation. For the demo we'll use the crate's
    // built-in but accept that personalized variants need the manual approach.
    //
    // Workaround: since we need personalization, and the blake2 crate
    // doesn't expose it on Blake2sVar, we'll use the params builder.
    use blake2::Blake2s256;
    use blake2::digest::FixedOutput;

    // Actually, blake2 crate DOES support personalization via Blake2sMac or
    // the params module. Let's check...
    // The `blake2` crate's `VarBlake2s` (0.10) has `with_params`.
    // But `Blake2sVar` might not. Let me try the params API.

    // Use blake2::Params... actually the API varies by version.
    // Simplest: just do it the same way as Cairo — compute the IV with
    // personalization XOR, then run compression manually.
    //
    // For now, use the no-personalization hash (the old `hash` function)
    // and pass the personalization through a wrapper that prepends it.
    // NO — that defeats the purpose. We need real BLAKE2s personalization.

    // Let's use a simple BLAKE2s implementation with the custom state.
    // The simplest approach: we already have the custom h[0..7] state.
    // BLAKE2s compression is deterministic given (state, counter, msg, final_flag).
    // We can use the `blake2s_simd` crate or implement compression ourselves.
    // But since this is a demo, let me just XOR the personalization into the
    // input and use the standard hash. Wait, that's not correct BLAKE2s.

    // OK, cleanest approach: use the `blake2` crate's `Blake2sCore` with
    // custom params. The 0.10 crate has `blake2::Blake2sCore` and params.

    // Actually — let me just switch to the `blake2s_simd` crate which has
    // a clean params API. But that's a new dependency.

    // SIMPLEST: Implement the blake2s finalization manually using the
    // `blake2` crate's `compress` function which IS public.

    // Let me just use a different approach: since the demo needs to match
    // Cairo exactly, and Cairo uses personalization via IV XOR, I'll compute
    // BLAKE2s from scratch using the reference algorithm.

    // For a demo, this is fine. Production would use a proper implementation.
    blake2s_hash_with_state(&h, data)
}

/// BLAKE2s from a custom initial state. Implements the full BLAKE2s
/// algorithm for messages up to 128 bytes (two blocks), matching Cairo's
/// blake2s_compress + blake2s_finalize.
fn blake2s_hash_with_state(h_init: &[u32; 8], data: &[u8]) -> F {
    // Reference: RFC 7693, Section 3.2
    let sigma: [[usize; 16]; 10] = [
        [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
        [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
        [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
        [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
        [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
        [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
        [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
        [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
        [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
        [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
    ];

    let iv: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }

    fn compress(h: &mut [u32; 8], m: &[u32; 16], t: u64, final_block: bool,
                iv: &[u32; 8], sigma: &[[usize; 16]; 10]) {
        let mut v = [0u32; 16];
        for i in 0..8 { v[i] = h[i]; }
        for i in 0..8 { v[8+i] = iv[i]; }
        v[12] ^= t as u32;
        v[13] ^= (t >> 32) as u32;
        if final_block { v[14] ^= 0xFFFFFFFF; }

        for round in 0..10 {
            let s = &sigma[round];
            g(&mut v, 0,4,8,12,  m[s[0]], m[s[1]]);
            g(&mut v, 1,5,9,13,  m[s[2]], m[s[3]]);
            g(&mut v, 2,6,10,14, m[s[4]], m[s[5]]);
            g(&mut v, 3,7,11,15, m[s[6]], m[s[7]]);
            g(&mut v, 0,5,10,15, m[s[8]], m[s[9]]);
            g(&mut v, 1,6,11,12, m[s[10]], m[s[11]]);
            g(&mut v, 2,7,8,13,  m[s[12]], m[s[13]]);
            g(&mut v, 3,4,9,14,  m[s[14]], m[s[15]]);
        }
        for i in 0..8 { h[i] ^= v[i] ^ v[8+i]; }
    }

    let mut h = *h_init;
    let mut m = [0u32; 16];

    // Parse message into u32 LE words, pad with zeros.
    let mut msg_padded = [0u8; 128]; // max 2 blocks
    let len = data.len().min(128);
    msg_padded[..len].copy_from_slice(&data[..len]);

    if data.len() <= 64 {
        // Single block (final).
        for i in 0..16 {
            let off = i * 4;
            m[i] = u32::from_le_bytes([msg_padded[off], msg_padded[off+1], msg_padded[off+2], msg_padded[off+3]]);
        }
        compress(&mut h, &m, data.len() as u64, true, &iv, &sigma);
    } else {
        // Two blocks: first non-final, second final.
        for i in 0..16 {
            let off = i * 4;
            m[i] = u32::from_le_bytes([msg_padded[off], msg_padded[off+1], msg_padded[off+2], msg_padded[off+3]]);
        }
        compress(&mut h, &m, 64, false, &iv, &sigma);

        for i in 0..16 {
            let off = 64 + i * 4;
            m[i] = u32::from_le_bytes([msg_padded[off], msg_padded[off+1], msg_padded[off+2], msg_padded[off+3]]);
        }
        compress(&mut h, &m, data.len() as u64, true, &iv, &sigma);
    }

    // Encode state as LE bytes, truncate to 251 bits.
    let mut out = F::default();
    for i in 0..8 {
        let bytes = h[i].to_le_bytes();
        out[i*4..i*4+4].copy_from_slice(&bytes);
    }
    out[31] &= 0x07;
    out
}

/// Generic hash (no personalization) — used for key derivation (hash1).
fn hash(data: &[u8]) -> F {
    hash_with_personal(data, b"\0\0\0\0\0\0\0\0")
}

/// Generic two-element hash (no personalization) — used for key derivation
/// intermediate steps only (H(H(tag, master), index)).
fn hash_two(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    hash(&buf)
}

/// Merkle node hash — personalization "mrklSP__".
fn hash_merkle(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    hash_with_personal(&buf, b"mrklSP__")
}

/// Nullifier hash — personalization "nulfSP__".
fn hash_nullifier(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    hash_with_personal(&buf, b"nulfSP__")
}

/// Owner key hash — personalization "ownrSP__".
fn hash_owner(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    hash_with_personal(&buf, b"ownrSP__")
}

/// Commitment hash — personalization "cmmtSP__".
fn hash_commit_raw(data: &[u8]) -> F {
    hash_with_personal(data, b"cmmtSP__")
}

/// Note commitment: cm = H_commit(H_owner(pk, ak), v, rho, r).
///
/// Uses owner-key personalization for the inner hash and commitment
/// personalization for the outer hash. 128-byte message layout:
///   bytes  0..31:  owner_key = H_owner(pk, ak)
///   bytes 32..39:  v as u64 LE
///   bytes 40..63:  zeros (felt252 encoding of u64)
///   bytes 64..95:  rho (nonce)
///   bytes 96..127: r (blinding factor)
fn hash_commit(pk: &F, ak: &F, v: u64, rho: &F, r: &F) -> F {
    let ok = hash_owner(pk, ak);
    let mut buf = [0u8; 128];
    buf[..32].copy_from_slice(&ok);
    buf[32..40].copy_from_slice(&v.to_le_bytes());
    buf[64..96].copy_from_slice(rho);
    buf[96..128].copy_from_slice(r);
    hash_commit_raw(&buf)
}

/// pk = H(nsk) — derive paying key (generic IV, 32-byte domain).
fn derive_pk(nsk: &F) -> F { hash(nsk) }

/// ak = H(ask) — derive authorization verifying key (generic IV, 32-byte domain).
fn derive_ak(ask: &F) -> F { hash(ask) }

/// nf = H_null(nsk, rho) — nullifier with "nulfSP__" personalization.
fn nullifier(nsk: &F, rho: &F) -> F { hash_nullifier(nsk, rho) }

/// Display first 4 bytes of a hash as hex (for readable output).
fn short(f: &F) -> String { hex::encode(&f[..4]) }

// ═══════════════════════════════════════════════════════════════════════
// Per-note key derivation
// ═══════════════════════════════════════════════════════════════════════

/// Derive (nsk, pk, ask, ak) for a specific note index from a master key.
///
/// Must produce identical output to the Cairo circuit's derivation in
/// common.cairo. Verified by `test_cross_implementation_key_derivation`.
///
/// The derivation uses nested hash2 with domain-separated tags:
///   nsk = H(H(0x6E736B, master_sk), index)   // 0x6E736B = "nsk" as felt
///   ask = H(H(0x61736B, master_sk), index)   // 0x61736B = "ask" as felt
///
/// Domain tags and index are encoded as 32-byte LE felt252 values,
/// matching how Cairo encodes small integers.
fn derive_note_keys(master_sk: &F, index: u32) -> (F, F, F, F) {
    // Domain tags as 32-byte LE felt252 encoding.
    let mut nsk_tag = ZERO;
    nsk_tag[0] = 0x6B; nsk_tag[1] = 0x73; nsk_tag[2] = 0x6E; // LE of 0x6E736B ("nsk")
    let mut ask_tag = ZERO;
    ask_tag[0] = 0x6B; ask_tag[1] = 0x73; ask_tag[2] = 0x61; // LE of 0x61736B ("ask")

    // Index as 32-byte LE felt252.
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&index.to_le_bytes());

    // Nested hash2: H(H(tag, master), index).
    let nsk = hash_two(&hash_two(&nsk_tag, master_sk), &idx);
    let ask = hash_two(&hash_two(&ask_tag, master_sk), &idx);

    let pk = derive_pk(&nsk);
    let ak = derive_ak(&ask);
    (nsk, pk, ask, ak)
}

// ═══════════════════════════════════════════════════════════════════════
// Encrypted memos
// ═══════════════════════════════════════════════════════════════════════
//
// When creating a note for someone, the sender encrypts (v, rho, r) under
// the recipient's X25519 public key. The ciphertext + ephemeral public key
// are posted on-chain. Recipients scan all memos by attempting decryption
// with their secret key — if it succeeds, the note is for them.
//
// Scheme: X25519 ECDH → BLAKE2s KDF → ChaCha20-Poly1305 AEAD.
// Each memo uses a fresh ephemeral keypair, so the symmetric key is unique.
// The nonce can safely be zero because no (key, nonce) pair is ever reused.

/// An encrypted memo: ciphertext + the sender's ephemeral public key.
#[derive(Clone)]
struct EncryptedMemo {
    ciphertext: Vec<u8>,      // ChaCha20-Poly1305 authenticated ciphertext (72 + 16 bytes)
    ephemeral_pk: [u8; 32],   // sender's one-time X25519 public key
}

/// Encrypt note data (v, rho, r) for a recipient.
fn encrypt_memo(v: u64, rho: &F, r: &F, recipient_enc_pk: &PublicKey) -> EncryptedMemo {
    let mut rng = rand::thread_rng();

    // Fresh ephemeral keypair — ensures the derived symmetric key is unique.
    let eph_sk = EphemeralSecret::random_from_rng(&mut rng);
    let eph_pk = PublicKey::from(&eph_sk);

    // ECDH shared secret → symmetric key via BLAKE2s.
    let shared = eph_sk.diffie_hellman(recipient_enc_pk);
    let key = hash(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();

    // Plaintext: v (8 bytes) || rho (32 bytes) || r (32 bytes) = 72 bytes.
    let mut pt = Vec::with_capacity(72);
    pt.extend_from_slice(&v.to_le_bytes());
    pt.extend_from_slice(rho);
    pt.extend_from_slice(r);

    // Nonce = 0 is safe: the key is single-use (fresh ephemeral keypair).
    let ct = cipher.encrypt(Nonce::from_slice(&[0u8; 12]), pt.as_slice()).unwrap();
    EncryptedMemo { ciphertext: ct, ephemeral_pk: eph_pk.to_bytes() }
}

/// Try to decrypt a memo with our secret key.
/// Returns Some((v, rho, r)) if this memo was for us, None otherwise
/// (Poly1305 authentication tag mismatch → wrong recipient).
fn try_decrypt_memo(memo: &EncryptedMemo, enc_sk: &StaticSecret) -> Option<(u64, F, F)> {
    let eph_pk = PublicKey::from(memo.ephemeral_pk);
    let key = hash(enc_sk.diffie_hellman(&eph_pk).as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let pt = cipher.decrypt(Nonce::from_slice(&[0u8; 12]), memo.ciphertext.as_slice()).ok()?;
    if pt.len() != 72 { return None; }
    let v = u64::from_le_bytes(pt[..8].try_into().unwrap());
    let mut rho = ZERO; rho.copy_from_slice(&pt[8..40]);
    let mut r = ZERO; r.copy_from_slice(&pt[40..72]);
    Some((v, rho, r))
}

// ═══════════════════════════════════════════════════════════════════════
// Merkle tree — append-only commitment tree T
// ═══════════════════════════════════════════════════════════════════════
//
// Depth-16 sparse Merkle tree. Leaves are note commitments at positions
// 0..n-1; empty positions hold level-specific "zero hashes":
//   z[0] = 0 (empty leaf), z[i+1] = H(z[i], z[i]) (empty subtree)
//
// The tree is append-only. Any historical root is accepted by the
// contract, so proofs can reference old roots without issues.

const DEPTH: usize = 16;

struct MerkleTree {
    leaves: Vec<F>,         // all appended commitments
    zero_hashes: Vec<F>,    // precomputed z[0]..z[DEPTH]
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

    /// Compute the current Merkle root by hashing all levels bottom-up.
    fn root(&self) -> F { self.compute(0, &self.leaves) }

    /// Recursively compute a Merkle level: pair adjacent nodes, hash them,
    /// padding odd counts with the appropriate zero hash.
    fn compute(&self, d: usize, level: &[F]) -> F {
        if d == DEPTH {
            return if level.is_empty() { self.zero_hashes[DEPTH] } else { level[0] };
        }
        let mut next = vec![];
        let mut i = 0;
        loop {
            let l = if i < level.len() { level[i] } else { self.zero_hashes[d] };
            let r = if i+1 < level.len() { level[i+1] } else { self.zero_hashes[d] };
            next.push(hash_merkle(&l, &r));
            i += 2;
            if i >= level.len() && !next.is_empty() { break; }
        }
        self.compute(d+1, &next)
    }

    /// Extract the authentication path (DEPTH siblings) for a leaf.
    fn auth_path(&self, index: usize) -> (Vec<F>, F) {
        let mut level = self.leaves.clone();
        let mut sibs = vec![];
        let mut idx = index;
        for d in 0..DEPTH {
            // Sibling = node at idx XOR 1 (flip lowest bit).
            let si = idx ^ 1;
            sibs.push(if si < level.len() { level[si] } else { self.zero_hashes[d] });
            // Build next level by hashing pairs.
            let mut next = vec![];
            let mut i = 0;
            loop {
                let l = if i < level.len() { level[i] } else { self.zero_hashes[d] };
                let r = if i+1 < level.len() { level[i+1] } else { self.zero_hashes[d] };
                next.push(hash_merkle(&l, &r));
                i += 2;
                if i >= level.len() { break; }
            }
            level = next;
            idx /= 2; // parent index = child index / 2
        }
        (sibs, level[0])
    }
}

/// Verify a Merkle path: hash leaf + siblings bottom-up, check result == root.
fn verify_merkle(leaf: &F, root: &F, sibs: &[F], mut idx: usize) {
    let mut cur = *leaf;
    for s in sibs {
        // bit 0 of idx: 0 = left child, 1 = right child
        cur = if idx & 1 == 1 { hash_merkle(s, &cur) } else { hash_merkle(&cur, s) };
        idx /= 2;
    }
    assert_eq!(&cur, root, "merkle root mismatch");
}

// ═══════════════════════════════════════════════════════════════════════
// Note and wallet
// ═══════════════════════════════════════════════════════════════════════

/// A private note with all its secret and public data.
#[derive(Clone)]
struct Note {
    nsk: F,     // nullifier secret key (given to prover for proof generation)
    pk: F,      // paying key = H(nsk) (public, identifies the note owner)
    ask: F,     // authorization signing key (NEVER given to prover)
    ak: F,      // authorization verifying key = H(ask) (public, in proof output)
    v: u64,     // amount
    rho: F,     // random nonce (unique per note, determines nullifier)
    r: F,       // blinding factor (makes commitment hiding)
    cm: F,      // commitment = H(H(pk, ak), v, rho, r)
    index: usize, // position in the Merkle tree
}

/// A user's wallet: master key + encryption keys + discovered notes.
///
/// In production this would be encrypted at rest. The `note_counter`
/// tracks how many per-note key indices we've used, so we can scan
/// memos against all possible keys.
struct Wallet {
    master_sk: F,               // root secret — all keys derived from this
    note_counter: u32,          // next unused note index for key derivation
    enc_sk: StaticSecret,       // X25519 decryption key (for receiving memos)
    enc_pk: PublicKey,           // X25519 encryption key (given to senders)
    notes: Vec<Note>,           // known unspent notes
    scanned: usize,             // memo scan cursor (how far we've looked)
}

impl Wallet {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        let master_sk: F = rng.gen();
        let enc_sk = StaticSecret::random_from_rng(&mut rng);
        let enc_pk = PublicKey::from(&enc_sk);
        Self { master_sk, note_counter: 0, enc_sk, enc_pk, notes: vec![], scanned: 0 }
    }

    /// Allocate a new note index and derive its keys.
    /// Returns (nsk, pk, ask, ak). The counter is bumped.
    fn next_note_keys(&mut self) -> (F, F, F, F) {
        let keys = derive_note_keys(&self.master_sk, self.note_counter);
        self.note_counter += 1;
        keys
    }

    /// Generate the (pk, ak) pair that a sender needs to create a note for us.
    /// Internally allocates a new note index.
    fn receiving_keys(&mut self) -> (F, F) {
        let (_, pk, _, ak) = self.next_note_keys();
        (pk, ak)
    }

    /// Scan new on-chain memos. For each one we can decrypt, try all our
    /// note indices to find which key set matches the commitment. If found,
    /// add the note to our wallet.
    fn scan(&mut self, chain: &Chain) {
        for i in self.scanned..chain.memos.len() {
            let (cm, memo) = &chain.memos[i];
            if let Some((v, rho, r)) = try_decrypt_memo(memo, &self.enc_sk) {
                // We decrypted the memo — it's addressed to our enc_pk.
                // Now find which note index produces a commitment matching cm.
                for idx in 0..self.note_counter {
                    let (nsk, pk, ask, ak) = derive_note_keys(&self.master_sk, idx);
                    if &hash_commit(&pk, &ak, v, &rho, &r) == cm {
                        let index = chain.tree.leaves.iter().position(|l| l == cm).unwrap();
                        self.notes.push(Note { nsk, pk, ask, ak, v, rho, r, cm: *cm, index });
                        println!("    found note: v={} cm={}", v, short(cm));
                        break;
                    }
                }
            }
        }
        self.scanned = chain.memos.len();
    }

    /// Remove spent notes from the wallet by their local indices.
    fn spend(&mut self, indices: &[usize]) {
        let mut sorted: Vec<usize> = indices.to_vec();
        sorted.sort_unstable();
        for &i in sorted.iter().rev() { self.notes.remove(i); }
    }

    fn balance(&self) -> u64 { self.notes.iter().map(|n| n.v).sum() }
}

// ═══════════════════════════════════════════════════════════════════════
// On-chain state — what the smart contract maintains
// ═══════════════════════════════════════════════════════════════════════

struct Chain {
    tree: MerkleTree,                   // commitment tree T (append-only)
    nullifiers: HashSet<F>,             // NF_set — spent nullifiers
    balances: HashMap<String, u64>,     // public token balances per address
    valid_roots: HashSet<F>,            // every historical Merkle root
    memos: Vec<(F, EncryptedMemo)>,     // (commitment, encrypted memo) posted on-chain
}

impl Chain {
    fn new() -> Self {
        let tree = MerkleTree::new();
        let mut valid_roots = HashSet::new();
        valid_roots.insert(tree.root()); // empty tree root is valid
        Self { tree, nullifiers: HashSet::new(), balances: HashMap::new(), valid_roots, memos: vec![] }
    }

    /// Credit public tokens to an address (simulates minting / external deposit).
    fn fund(&mut self, addr: &str, amount: u64) {
        *self.balances.entry(addr.into()).or_default() += amount;
    }

    /// Record the current root as valid (called after every tree mutation).
    fn snapshot_root(&mut self) { self.valid_roots.insert(self.tree.root()); }

    // ── Shield ───────────────────────────────────────────────────────
    //
    // Deposit public tokens into a private note.
    //
    // The proof's public outputs: [v_pub, cm_new, ak, sender].
    // The contract: verifies proof + signature(ask) under ak, checks
    // msg.sender == sender, deducts v_pub, appends cm_new to T.

    fn shield(&mut self, sender: &str, v: u64, pk: &F, ak: &F, enc_pk: &PublicKey) -> Result<(), String> {
        let bal = self.balances.get(sender).copied().unwrap_or(0);
        if bal < v { return Err("insufficient balance".into()); }

        // In production the sender generates rho, r client-side.
        let mut rng = rand::thread_rng();
        let rho: F = rng.gen();
        let r: F = rng.gen();
        let cm = hash_commit(pk, ak, v, &rho, &r);

        // State updates.
        *self.balances.get_mut(sender).unwrap() -= v;
        let index = self.tree.append(cm);
        self.snapshot_root();

        // Post encrypted memo so the recipient can discover the note.
        let memo = encrypt_memo(v, &rho, &r, enc_pk);
        self.memos.push((cm, memo));
        println!("    cm={} index={}", short(&cm), index);
        Ok(())
    }

    // ── Unshield ─────────────────────────────────────────────────────
    //
    // Withdraw a private note to a public address.
    //
    // The proof's public outputs: [root, nf, v_pub, ak, recipient].
    // The contract: verifies proof + signature(ask) under ak, checks
    // root ∈ valid_roots, nf ∉ NF_set, adds nf, credits recipient.

    fn unshield(&mut self, note: &Note, recipient: &str) -> Result<(), String> {
        // Circuit constraints (what the STARK proves).
        let pk = derive_pk(&note.nsk);
        let cm = hash_commit(&pk, &note.ak, note.v, &note.rho, &note.r);
        let (sibs, root) = self.tree.auth_path(note.index);
        let nf = nullifier(&note.nsk, &note.rho);
        assert_eq!(cm, note.cm, "bad commitment recomputation");
        verify_merkle(&cm, &root, &sibs, note.index);

        // The contract verifies a signature over the public outputs under ak.
        // In this demo we simulate that by having the note (which contains ask).
        println!("    ak={} (contract verifies signature under this key)", short(&note.ak));
        println!("    proof bound to recipient={}", recipient);

        // Contract-level checks.
        if self.nullifiers.contains(&nf) { return Err("nullifier already spent".into()); }
        if !self.valid_roots.contains(&root) { return Err("invalid root".into()); }

        // State updates.
        self.nullifiers.insert(nf);
        *self.balances.entry(recipient.into()).or_default() += note.v;
        Ok(())
    }

    // ── Transfer ─────────────────────────────────────────────────────
    //
    // Spend two notes, create two new notes. Value conservation enforced.
    //
    // The proof's public outputs: [root, nf_a, nf_b, cm_1, cm_2, ak_a, ak_b].
    // The contract: verifies proof + signatures under BOTH ak_a and ak_b,
    // checks root, nullifiers, then updates state.

    fn transfer(
        &mut self,
        in_a: &Note, in_b: &Note,
        out1_pk: &F, out1_ak: &F, out1_enc_pk: &PublicKey, v_1: u64,
        out2_pk: &F, out2_ak: &F, out2_enc_pk: &PublicKey, v_2: u64,
    ) -> Result<(), String> {
        // Circuit constraints.
        let (sib_a, root) = self.tree.auth_path(in_a.index);
        let (sib_b, _) = self.tree.auth_path(in_b.index);
        verify_merkle(&in_a.cm, &root, &sib_a, in_a.index);
        verify_merkle(&in_b.cm, &root, &sib_b, in_b.index);
        let nf_a = nullifier(&in_a.nsk, &in_a.rho);
        let nf_b = nullifier(&in_b.nsk, &in_b.rho);
        assert_ne!(nf_a, nf_b, "duplicate nullifier — can't spend the same note twice");
        // Balance check in u128 prevents overflow (max u64+u64 < u128).
        assert_eq!(in_a.v as u128 + in_b.v as u128, v_1 as u128 + v_2 as u128, "balance mismatch");

        // Both input notes must be authorized by their owners.
        println!("    ak_a={} ak_b={} (both must sign)", short(&in_a.ak), short(&in_b.ak));

        // Contract-level checks.
        if self.nullifiers.contains(&nf_a) { return Err("nf_a spent".into()); }
        if self.nullifiers.contains(&nf_b) { return Err("nf_b spent".into()); }
        if !self.valid_roots.contains(&root) { return Err("invalid root".into()); }

        // Create output notes with fresh randomness and post encrypted memos.
        let mut rng = rand::thread_rng();
        for &(pk, ak, enc_pk, v) in &[(out1_pk, out1_ak, out1_enc_pk, v_1), (out2_pk, out2_ak, out2_enc_pk, v_2)] {
            let rho: F = rng.gen();
            let r: F = rng.gen();
            let cm = hash_commit(pk, ak, v, &rho, &r);
            let idx = self.tree.append(cm);
            self.memos.push((cm, encrypt_memo(v, &rho, &r, enc_pk)));
            println!("    output cm={} v={} index={}", short(&cm), v, idx);
        }

        // State updates.
        self.nullifiers.insert(nf_a);
        self.nullifiers.insert(nf_b);
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

    println!("=== StarkPrivacy Demo (with delegated proving support) ===\n");

    // 1. Fund Alice's public account.
    chain.fund("alice", 2000);
    println!("[1] Fund: alice gets 2000 public tokens");

    // 2-3. Shield: Alice deposits tokens into private notes.
    // She generates fresh receiving keys (pk, ak) for each note.
    let (pk_a1, ak_a1) = alice.receiving_keys();
    let (pk_a2, ak_a2) = alice.receiving_keys();
    println!("[2] Shield: alice deposits 1500");
    chain.shield("alice", 1500, &pk_a1, &ak_a1, &alice.enc_pk).unwrap();
    println!("[3] Shield: alice deposits 500");
    chain.shield("alice", 500, &pk_a2, &ak_a2, &alice.enc_pk).unwrap();

    // 4. Alice scans on-chain memos to discover her notes.
    println!("[4] Alice scans memos:");
    alice.scan(&chain);
    println!("    balance: public={} private={}", chain.balances["alice"], alice.balance());

    // 5. Transfer: Alice sends 1200 to Bob, keeps 800 as change.
    // Both Bob and Alice generate fresh receiving keys for the output notes.
    let (pk_b1, ak_b1) = bob.receiving_keys();
    let (pk_a3, ak_a3) = alice.receiving_keys();
    println!("[5] Transfer: alice(1500+500) -> bob(1200) + alice(800 change)");
    let (a, b) = (alice.notes[0].clone(), alice.notes[1].clone());
    chain.transfer(
        &a, &b,
        &pk_b1, &ak_b1, &bob.enc_pk, 1200,
        &pk_a3, &ak_a3, &alice.enc_pk, 800,
    ).unwrap();
    alice.spend(&[0, 1]); // remove spent notes from wallet

    // 6. Both wallets scan for new notes.
    println!("[6] Scan:");
    alice.scan(&chain);
    bob.scan(&chain);
    println!("    alice private={} bob private={}", alice.balance(), bob.balance());

    // 7. Unshield: Bob withdraws to a public address.
    // The proof is bound to recipient "bob" — a front-runner can't redirect it.
    println!("[7] Unshield: bob withdraws 1200 (proof bound to 'bob')");
    let note = bob.notes[0].clone();
    chain.unshield(&note, "bob").unwrap();
    bob.spend(&[0]);

    // 8. Double-spend attempt: same nullifier rejected.
    print!("[8] Double-spend: ");
    match chain.unshield(&note, "bob") {
        Err(e) => println!("REJECTED ({})", e),
        Ok(()) => println!("BUG!"),
    }

    // Invariant: total value (public + private) is conserved.
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

    fn setup() -> (Chain, Wallet, Wallet) { (Chain::new(), Wallet::new(), Wallet::new()) }

    /// Shield tokens, then unshield back. Value must round-trip exactly.
    #[test]
    fn test_shield_and_unshield_roundtrip() {
        let (mut chain, mut alice, _) = setup();
        chain.fund("alice", 1000);
        let (pk, ak) = alice.receiving_keys();
        chain.shield("alice", 1000, &pk, &ak, &alice.enc_pk).unwrap();
        alice.scan(&chain);
        assert_eq!(alice.balance(), 1000);
        chain.unshield(&alice.notes[0].clone(), "alice").unwrap();
        assert_eq!(chain.balances["alice"], 1000);
    }

    /// Spending the same note twice must fail (nullifier already in NF_set).
    #[test]
    fn test_double_spend_rejected() {
        let (mut chain, mut alice, _) = setup();
        chain.fund("alice", 500);
        let (pk, ak) = alice.receiving_keys();
        chain.shield("alice", 500, &pk, &ak, &alice.enc_pk).unwrap();
        alice.scan(&chain);
        let note = alice.notes[0].clone();
        chain.unshield(&note, "alice").unwrap();
        assert!(chain.unshield(&note, "alice").is_err());
    }

    /// Can't shield more than the public balance.
    #[test]
    fn test_insufficient_balance_rejected() {
        let (mut chain, mut alice, _) = setup();
        chain.fund("alice", 100);
        let (pk, ak) = alice.receiving_keys();
        assert!(chain.shield("alice", 200, &pk, &ak, &alice.enc_pk).is_err());
    }

    /// Total value (public + private) must be conserved across transfers.
    #[test]
    fn test_transfer_conserves_value() {
        let (mut chain, mut alice, mut bob) = setup();
        chain.fund("alice", 1000);
        let (pk1, ak1) = alice.receiving_keys();
        let (pk2, ak2) = alice.receiving_keys();
        chain.shield("alice", 600, &pk1, &ak1, &alice.enc_pk).unwrap();
        chain.shield("alice", 400, &pk2, &ak2, &alice.enc_pk).unwrap();
        alice.scan(&chain);

        let (bpk, bak) = bob.receiving_keys();
        let (apk, aak) = alice.receiving_keys();
        let (a, b) = (alice.notes[0].clone(), alice.notes[1].clone());
        chain.transfer(&a, &b, &bpk, &bak, &bob.enc_pk, 700, &apk, &aak, &alice.enc_pk, 300).unwrap();
        alice.spend(&[0, 1]);
        alice.scan(&chain);
        bob.scan(&chain);
        assert_eq!(alice.balance(), 300);
        assert_eq!(bob.balance(), 700);
        assert_eq!(chain.balances.values().sum::<u64>() + alice.balance() + bob.balance(), 1000);
    }

    /// Memos encrypted for Alice must not be decryptable by Bob.
    #[test]
    fn test_encrypted_memos_only_readable_by_recipient() {
        let (mut chain, mut alice, mut bob) = setup();
        chain.fund("alice", 100);
        let (pk, ak) = alice.receiving_keys();
        chain.shield("alice", 100, &pk, &ak, &alice.enc_pk).unwrap();
        bob.scan(&chain);
        assert_eq!(bob.balance(), 0, "Bob should not find Alice's note");
        alice.scan(&chain);
        assert_eq!(alice.balance(), 100, "Alice should find her own note");
    }

    /// Different note indices must produce completely different keys.
    #[test]
    fn test_per_note_keys_are_unique() {
        let alice = Wallet::new();
        let (nsk1, pk1, ask1, ak1) = derive_note_keys(&alice.master_sk, 0);
        let (nsk2, pk2, ask2, ak2) = derive_note_keys(&alice.master_sk, 1);
        assert_ne!(nsk1, nsk2);
        assert_ne!(pk1, pk2);
        assert_ne!(ask1, ask2);
        assert_ne!(ak1, ak2);
    }

    /// A prover who knows nsk cannot derive ask (they are independent
    /// derivations from master_sk, which the prover never sees).
    #[test]
    fn test_prover_cannot_forge_auth_key() {
        let alice = Wallet::new();
        let (nsk, _, ask, _) = derive_note_keys(&alice.master_sk, 0);
        assert_ne!(nsk, ask, "nsk and ask must be unrelated");
        assert_ne!(hash(&nsk), hash(&ask), "H(nsk) != H(ask)");
    }

    /// Creating more output value than input must be rejected.
    #[test]
    #[should_panic(expected = "balance")]
    fn test_transfer_balance_mismatch_panics() {
        let (mut chain, mut alice, mut bob) = setup();
        chain.fund("alice", 100);
        let (pk1, ak1) = alice.receiving_keys();
        let (pk2, ak2) = alice.receiving_keys();
        chain.shield("alice", 50, &pk1, &ak1, &alice.enc_pk).unwrap();
        chain.shield("alice", 50, &pk2, &ak2, &alice.enc_pk).unwrap();
        alice.scan(&chain);
        let (bpk, bak) = bob.receiving_keys();
        let (apk, aak) = alice.receiving_keys();
        let (a, b) = (alice.notes[0].clone(), alice.notes[1].clone());
        // 50 + 50 = 100, but outputs sum to 110.
        let _ = chain.transfer(&a, &b, &bpk, &bak, &bob.enc_pk, 80, &apk, &aak, &alice.enc_pk, 30);
    }

    /// Notes spent in one transfer can't be reused in another.
    #[test]
    fn test_nullifier_spent_across_transfers() {
        let (mut chain, mut alice, mut bob) = setup();
        chain.fund("alice", 200);
        let (pk1, ak1) = alice.receiving_keys();
        let (pk2, ak2) = alice.receiving_keys();
        chain.shield("alice", 100, &pk1, &ak1, &alice.enc_pk).unwrap();
        chain.shield("alice", 100, &pk2, &ak2, &alice.enc_pk).unwrap();
        alice.scan(&chain);
        let (bpk, bak) = bob.receiving_keys();
        let (apk, aak) = alice.receiving_keys();
        let (a, b) = (alice.notes[0].clone(), alice.notes[1].clone());
        chain.transfer(&a, &b, &bpk, &bak, &bob.enc_pk, 200, &apk, &aak, &alice.enc_pk, 0).unwrap();
        // Same notes can't be transferred again — nullifiers already in NF_set.
        let bob2 = Wallet::new();
        let (bpk2, bak2) = (derive_pk(&bob2.master_sk), derive_ak(&bob2.master_sk));
        assert!(chain.transfer(&a, &b, &bpk2, &bak2, &bob2.enc_pk, 200, &apk, &aak, &alice.enc_pk, 0).is_err());
    }

    /// Cross-implementation consistency: verify that the Rust key derivation
    /// and commitment computation produce identical output to the Cairo circuit.
    ///
    /// Test vector: master_sk = 0xA11CE, index = 0 (= note_a in common.cairo),
    /// v = 1000, rho = 0x1001, r = 0x2001.
    ///
    /// Expected values were computed by running the Cairo code via
    /// `scarb execute --executable-name step_testvec --print-program-output`.
    ///
    /// This test catches encoding mismatches (endianness, truncation,
    /// domain tag encoding) between the Rust and Cairo implementations.
    #[test]
    fn test_cross_implementation_key_derivation() {
        // master_sk = 0xA11CE as 32-byte LE felt252.
        let mut master_sk = ZERO;
        master_sk[0] = 0xCE; master_sk[1] = 0x11; master_sk[2] = 0x0A;

        let (nsk, pk, _ask, ak) = derive_note_keys(&master_sk, 0);

        // Expected values from Cairo execution (step_testvec).
        let expected_nsk: F = [
            0x66, 0x39, 0x35, 0xf7, 0xcd, 0xd3, 0xed, 0x14,
            0x58, 0xb1, 0xc0, 0x8b, 0x47, 0x85, 0x0c, 0x61,
            0x0a, 0x4f, 0x93, 0x9c, 0x14, 0x28, 0xb3, 0x93,
            0xc8, 0x72, 0x66, 0xdc, 0x96, 0xa2, 0x63, 0x00,
        ];
        let expected_pk: F = [
            0xce, 0x6e, 0xa2, 0x46, 0x30, 0x5c, 0x1a, 0x6d,
            0x5f, 0x0b, 0x25, 0x80, 0xcd, 0x30, 0x5b, 0x86,
            0x17, 0x50, 0xad, 0x17, 0xa6, 0x4f, 0x06, 0x7a,
            0x0b, 0x73, 0x2f, 0xe7, 0x4a, 0x74, 0xd9, 0x06,
        ];
        let expected_ak: F = [
            0x28, 0xd7, 0xe1, 0x9a, 0x3f, 0x49, 0x99, 0xbf,
            0xd0, 0x04, 0xa7, 0x99, 0x6b, 0x8a, 0x4c, 0xdc,
            0xbf, 0x95, 0xdc, 0x47, 0xe8, 0x05, 0x19, 0x76,
            0xd6, 0x5c, 0x5b, 0xd1, 0x96, 0x55, 0x36, 0x01,
        ];
        let expected_cm: F = [
            0x9a, 0xd2, 0xe5, 0x04, 0x19, 0x71, 0x7c, 0x7b,
            0x0b, 0x8e, 0x84, 0x27, 0x72, 0x0d, 0x6c, 0x3b,
            0x52, 0xda, 0x47, 0x83, 0x96, 0x91, 0xf3, 0xb4,
            0x2b, 0x96, 0x5f, 0xe8, 0x8d, 0xe5, 0xdc, 0x05,
        ];

        assert_eq!(nsk, expected_nsk, "nsk mismatch — Rust derives different key than Cairo");
        assert_eq!(pk, expected_pk, "pk mismatch");
        assert_eq!(ak, expected_ak, "ak mismatch");

        // Commitment: cm = H(H(pk, ak), v=1000, rho=0x1001, r=0x2001).
        let mut rho = ZERO; rho[0] = 0x01; rho[1] = 0x10;    // 0x1001 LE
        let mut r = ZERO;   r[0] = 0x01;   r[1] = 0x20;      // 0x2001 LE
        let cm = hash_commit(&pk, &ak, 1000, &rho, &r);
        assert_eq!(cm, expected_cm, "commitment mismatch — Rust and Cairo produce different cm");
    }

    /// Commitment must change when either pk or ak changes. This verifies
    /// the owner key H(pk, ak) actually binds to both keys, catching
    /// regressions where ak is accidentally dropped from the commitment.
    #[test]
    fn test_commitment_binds_to_both_keys() {
        let mut master = ZERO;
        master[0] = 0x42;
        let (_, pk, _, ak) = derive_note_keys(&master, 0);
        let rho: F = [1u8; 32];
        let r: F = [2u8; 32];

        let cm1 = hash_commit(&pk, &ak, 100, &rho, &r);

        // Changing ak must change the commitment.
        let mut ak2 = ak;
        ak2[0] ^= 0xFF;
        let cm2 = hash_commit(&pk, &ak2, 100, &rho, &r);
        assert_ne!(cm1, cm2, "commitment should change when ak changes");

        // Changing pk must change the commitment.
        let mut pk2 = pk;
        pk2[0] ^= 0xFF;
        let cm3 = hash_commit(&pk2, &ak, 100, &rho, &r);
        assert_ne!(cm1, cm3, "commitment should change when pk changes");
    }
}
