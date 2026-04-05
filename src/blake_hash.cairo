/// BLAKE2s-256 hash primitives for StarkPrivacy.
///
/// Every hash in this protocol — key derivation, note commitments, nullifiers,
/// and Merkle tree nodes — uses BLAKE2s-256 from Cairo's core library.
/// BLAKE2s is a built-in opcode in the Cairo VM's Stwo backend, making it
/// far cheaper to prove than algebraic hashes like Poseidon.
///
/// # Domain separation
///
/// Different uses of the hash must not collide. We achieve this through
/// BLAKE2s's byte counter, which is part of the compression state:
///
///   - `hash1(a)`:      byte_count = 32  — key derivation (pk = H(sk))
///   - `hash2(a, b)`:   byte_count = 64  — nullifiers, Merkle nodes
///   - `hash4(a,b,c,d)`:byte_count = 128 — note commitments
///
/// Since the byte counter feeds into the BLAKE2s compression function,
/// messages of different lengths produce unrelated outputs even if the
/// raw bytes overlap.
///
/// # Output truncation
///
/// BLAKE2s produces 256-bit digests. We truncate to 251 bits (clear bits
/// 251-255 of the top word) so the result fits in a felt252 (the Stark
/// prime field). This costs ~5 bits of collision resistance (2^125.5 vs
/// 2^128), which is well above the 96-bit STARK security level.

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxTrait;

// ── Arithmetic helpers for u128 → u32 word extraction ────────────────
const MASK32: u128 = 0xFFFFFFFF;
const POW32: u128 = 0x100000000;
const POW64: u128 = 0x10000000000000000;
const POW96: u128 = 0x1000000000000000000000000;

/// Standard BLAKE2s initialization vector, XORed with the parameter block
/// for a 32-byte, unkeyed, sequential hash:
///   P[0] = digest_length(32) | key_length(0)<<8 | fanout(1)<<16 | depth(1)<<24
///        = 0x01010020
///   h[0] = IV[0] ^ P[0] = 0x6A09E667 ^ 0x01010020 = 0x6B08E647
///   h[1..7] = IV[1..7]  (P[1..7] are zero for this parameter set)
fn blake2s_iv() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ])
}

/// Encode a felt252 as 8 little-endian u32 words (256 bits total, top 5 zero).
///
/// felt252 → u256 { low: u128, high: u128 }
/// Word 0 = low bits 0..31, Word 1 = bits 32..63, ..., Word 7 = high bits 96..127.
/// Since felt252 < 2^251, word 7 is at most 27 bits.
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
///
/// Clears the top 5 bits of word 7 with mask 0x07FFFFFF = 2^27 - 1.
/// This ensures the result is < 2^251 < P (the Stark prime), so the
/// conversion to felt252 never fails.
fn u32x8_to_felt(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32, h5: u32, h6: u32, h7: u32) -> felt252 {
    let low: u128 = h0.into() + h1.into() * POW32 + h2.into() * POW64 + h3.into() * POW96;
    let h7_masked: u128 = h7.into() & 0x07FFFFFF;
    let high: u128 = h4.into() + h5.into() * POW32 + h6.into() * POW64 + h7_masked * POW96;
    let out = u256 { low, high };
    out.try_into().unwrap()
}

// ── Public hash functions ────────────────────────────────────────────

/// H(a) — single-element hash (32-byte message), used for key derivation.
///
/// The 32-byte felt is placed in the first 8 words of the block; the
/// remaining 8 words are zero-padded. `byte_count = 32` tells BLAKE2s
/// this is a 32-byte message, domain-separating it from hash2 (64 bytes).
pub fn hash1(a: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0, 0]);
    let result = blake2s_finalize(blake2s_iv(), 32, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H(a, b) — two-element hash (64-byte message).
///
/// Used for nullifiers (H(sk, rho)) and Merkle tree internal nodes (H(left, right)).
/// Both felts fill the entire 64-byte block; `byte_count = 64`.
pub fn hash2(a: felt252, b: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let result = blake2s_finalize(blake2s_iv(), 64, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H(a, b, c, d) — four-element hash (128-byte message, two BLAKE2s blocks).
///
/// Used for note commitments: cm = H(pk, v, rho, r).
///
/// This is a proper two-block BLAKE2s computation, NOT a tree of hash2 calls:
///   Block 1: compress(IV, a||b, counter=64)      — non-final
///   Block 2: finalize(state, c||d, counter=128)   — final
///
/// The `byte_count = 128` domain-separates this from hash2 (`byte_count = 64`)
/// and hash1 (`byte_count = 32`), preventing structural collisions between
/// commitments and Merkle internal nodes.
pub fn hash4(a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let (c0, c1, c2, c3, c4, c5, c6, c7) = felt_to_u32x8(c);
    let (d0, d1, d2, d3, d4, d5, d6, d7) = felt_to_u32x8(d);

    // Block 1: a || b (64 bytes, non-final compression)
    let block1 = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let state = blake2s_compress(blake2s_iv(), 64, block1);

    // Block 2: c || d (64 bytes, final compression with total byte_count = 128)
    let block2 = BoxTrait::new([c0, c1, c2, c3, c4, c5, c6, c7, d0, d1, d2, d3, d4, d5, d6, d7]);
    let result = blake2s_finalize(state, 128, block2);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

// ── Protocol-level wrappers ──────────────────────────────────────────

/// Derive the paying key from a spending key: pk = H(sk).
///
/// Uses hash1 (32-byte domain). The one-wayness of BLAKE2s ensures that
/// pk reveals nothing about sk.
pub fn derive_pk(sk: felt252) -> felt252 {
    hash1(sk)
}

/// Compute a note commitment: cm = H(pk, v, rho, r).
///
/// Uses hash4 (128-byte domain). The blinding factor `r` makes the
/// commitment statistically hiding — without `r`, an adversary could
/// try all (pk, v, rho) combinations to find a match.
pub fn commit(pk: felt252, v: u64, rho: felt252, r: felt252) -> felt252 {
    hash4(pk, v.into(), rho, r)
}

/// Compute a nullifier: nf = H(sk, rho).
///
/// Uses hash2 (64-byte domain). Only the note owner (who knows sk) can
/// compute the nullifier for their note. The nullifier is deterministic:
/// each note has exactly one nullifier, preventing double-spend.
pub fn nullifier(sk: felt252, rho: felt252) -> felt252 {
    hash2(sk, rho)
}
