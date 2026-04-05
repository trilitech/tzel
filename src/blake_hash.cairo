/// BLAKE2s-256 hash primitives for StarkPrivacy.
///
/// Every hash in this protocol uses BLAKE2s-256 from Cairo's core library.
/// BLAKE2s is a built-in opcode in the Cairo VM's Stwo backend, making it
/// far cheaper to prove than algebraic hashes like Poseidon.
///
/// # Key hierarchy
///
/// The protocol splits key material to support delegated proving (where
/// a third-party prover generates the expensive STARK proof, but cannot
/// steal funds):
///
/// ```text
///   master_sk
///   ├── nsk_i = H(H("nsk", master_sk), i)   — nullifier secret key (per-note)
///   │   └── pk_i = H(nsk_i)                 — paying key (public, per-note)
///   └── ask_i = H(H("ask", master_sk), i)   — authorization signing key (per-note)
///       └── ak_i = H(ask_i)                 — authorization verifying key (public)
/// ```
///
/// The prover receives `nsk_i` and `ak_i` (but NOT `ask_i` or `master_sk`).
/// This is enough to generate the proof but not to authorize the spend.
/// The user signs the proof outputs with `ask_i` — the contract verifies
/// the signature against `ak_i` (which is a public output of the proof).
///
/// # Note commitments
///
/// A note commitment binds to BOTH the nullifier key and the authorization
/// key: `cm = H(H(pk, ak), v, rho, r)`. The inner `H(pk, ak)` fuses the
/// two key domains into a single "owner key" that the commitment is bound to.
///
/// # Domain separation
///
/// Different uses of the hash are domain-separated by BLAKE2s's byte counter:
///
///   - `hash1(a)`:       byte_count = 32  — key derivation (pk, ak)
///   - `hash2(a, b)`:    byte_count = 64  — nullifiers, Merkle nodes, owner key
///   - `hash4(a,b,c,d)`: byte_count = 128 — note commitments
///
/// # Output truncation
///
/// BLAKE2s produces 256-bit digests. We truncate to 251 bits so the result
/// fits in felt252. This costs ~5 bits of collision resistance (2^125.5
/// vs 2^128), well above the 96-bit STARK security level.

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxTrait;

// ── Arithmetic helpers for u128 → u32 word extraction ────────────────
const MASK32: u128 = 0xFFFFFFFF;
const POW32: u128 = 0x100000000;
const POW64: u128 = 0x10000000000000000;
const POW96: u128 = 0x1000000000000000000000000;

/// BLAKE2s IVs with domain-specific personalization.
///
/// Each hash use case gets a unique IV via BLAKE2s's personalization field
/// (parameter block P[6..7]). This prevents cross-domain collisions:
/// e.g., a nullifier H_null(nsk, rho) can never equal a Merkle node
/// H_mrkl(left, right) even if (nsk,rho) == (left,right), because they
/// use different compression states.
///
/// Base config: P[0] = 0x01010020 (digest=32, key=0, fanout=1, depth=1).
/// h[i] = IV[i] ^ P[i], with P[6..7] set per domain.

/// Generic IV (no personalization) — used for key derivation (hash1).
/// Already domain-separated from hash2/hash4 by message length (32 vs 64/128).
fn blake2s_iv() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ])
}

/// Merkle-node IV — personalization "mrklSP__".
fn blake2s_iv_merkle() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x73E8ABC6, 0x04BF9D4A,
    ])
}

/// Nullifier IV — personalization "nulfSP__".
fn blake2s_iv_nullifier() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x79EFACC5, 0x04BF9D4A,
    ])
}

/// Owner-key IV — personalization "ownrSP__".
fn blake2s_iv_owner() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x6DEDAEC4, 0x04BF9D4A,
    ])
}

/// Commitment IV — personalization "cmmtSP__".
fn blake2s_iv_commit() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x6BEEB4C8, 0x04BF9D4A,
    ])
}

/// Encode a felt252 as 8 little-endian u32 words (256 bits total, top 5 zero).
fn felt_to_u32x8(val: felt252) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    let v: u256 = val.into();
    let lo = v.low;
    let hi = v.high;
    (
        (lo & MASK32).try_into().unwrap(),
        ((lo / POW32) & MASK32).try_into().unwrap(),
        ((lo / POW64) & MASK32).try_into().unwrap(),
        ((lo / POW96) & MASK32).try_into().unwrap(),
        (hi & MASK32).try_into().unwrap(),
        ((hi / POW32) & MASK32).try_into().unwrap(),
        ((hi / POW64) & MASK32).try_into().unwrap(),
        ((hi / POW96) & MASK32).try_into().unwrap(),
    )
}

/// Decode 8 u32 words back to a felt252, truncating to 251 bits.
/// Clears bits 251-255 via mask 0x07FFFFFF = 2^27 - 1 on word 7.
fn u32x8_to_felt(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32, h5: u32, h6: u32, h7: u32) -> felt252 {
    let low: u128 = h0.into() + h1.into() * POW32 + h2.into() * POW64 + h3.into() * POW96;
    let h7_masked: u128 = h7.into() & 0x07FFFFFF;
    let high: u128 = h4.into() + h5.into() * POW32 + h6.into() * POW64 + h7_masked * POW96;
    let out = u256 { low, high };
    out.try_into().unwrap()
}

// ── Public hash functions ────────────────────────────────────────────

/// H(a) — single-element hash (32-byte message).
/// Used for: pk = H(nsk), ak = H(ask).
pub fn hash1(a: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0, 0]);
    let result = blake2s_finalize(blake2s_iv(), 32, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H(a, b) — generic two-element hash (no personalization).
/// Used for: key derivation intermediate steps only.
/// NOT for Merkle nodes, nullifiers, or owner keys (those use personalized variants).
pub fn hash2_generic(a: felt252, b: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv(), a, b)
}

/// H_merkle(a, b) — Merkle tree internal node hash.
/// Uses the "mrklSP__" personalized IV.
pub fn hash2(a: felt252, b: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_merkle(), a, b)
}

/// Internal: 64-byte hash with a caller-specified IV.
fn hash2_with_iv(iv: Box<[u32; 8]>, a: felt252, b: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let result = blake2s_finalize(iv, 64, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H_commit(a, b, c, d) — note commitment (128-byte, two blocks).
/// Uses the "cmmtSP__" personalized IV.
fn hash4(a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let (c0, c1, c2, c3, c4, c5, c6, c7) = felt_to_u32x8(c);
    let (d0, d1, d2, d3, d4, d5, d6, d7) = felt_to_u32x8(d);

    let block1 = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let state = blake2s_compress(blake2s_iv_commit(), 64, block1);

    let block2 = BoxTrait::new([c0, c1, c2, c3, c4, c5, c6, c7, d0, d1, d2, d3, d4, d5, d6, d7]);
    let result = blake2s_finalize(state, 128, block2);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

// ── Protocol-level functions ─────────────────────────────────────────

/// Derive the paying key from the nullifier secret key: pk = H(nsk).
///
/// pk is public — it's the "address" that senders use to create notes
/// payable to this owner. The one-wayness of BLAKE2s ensures pk reveals
/// nothing about nsk.
pub fn derive_pk(nsk: felt252) -> felt252 {
    hash1(nsk)
}

/// Derive the authorization verifying key: ak = H(ask).
///
/// ak is public — it's output by the circuit so the on-chain contract
/// can verify the user's spend authorization signature. The prover sees
/// ak but never ask, so they cannot forge signatures.
pub fn derive_ak(ask: felt252) -> felt252 {
    hash1(ask)
}

/// Compute the owner key: ok = H_owner(pk, ak).
///
/// Fuses the nullifier-derived paying key and the authorization key into
/// a single value that the commitment is bound to. Uses the "ownrSP__"
/// personalized IV, distinct from Merkle nodes and nullifiers.
pub fn owner_key(pk: felt252, ak: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_owner(), pk, ak)
}

/// Compute a note commitment: cm = H(H(pk, ak), v, rho, r).
///
/// The commitment binds to:
///   - The owner (via pk and ak, fused into the owner key)
///   - The amount v
///   - The nonce rho (unique per note)
///   - The blinding factor r (makes the commitment hiding)
pub fn commit(pk: felt252, ak: felt252, v: u64, rho: felt252, r: felt252) -> felt252 {
    let ok = owner_key(pk, ak);
    hash4(ok, v.into(), rho, r)
}

/// Compute a nullifier: nf = H_null(nsk, rho).
///
/// Uses the "nulfSP__" personalized IV, distinct from Merkle nodes and
/// owner keys. Only the note owner (who knows nsk) can compute the
/// nullifier. Deterministic: each note has exactly one valid nullifier.
pub fn nullifier(nsk: felt252, rho: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_nullifier(), nsk, rho)
}
