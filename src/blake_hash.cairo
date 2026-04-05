/// BLAKE2s-256 hash primitives (efficient under Stwo).
///
/// All hashing uses BLAKE2s with domain-separated inputs via different
/// message lengths, avoiding collisions between hash1/hash2/hash4.

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxTrait;

const MASK32: u128 = 0xFFFFFFFF;
const POW32: u128 = 0x100000000;
const POW64: u128 = 0x10000000000000000;
const POW96: u128 = 0x1000000000000000000000000;

/// BLAKE2s IV with parameter block: digest_length=32, key_length=0, fanout=1, depth=1.
/// h[0] = 0x6A09E667 ^ 0x01010020 = 0x6B08E647; h[1..7] = IV[1..7].
fn blake2s_iv() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ])
}

/// Split a felt252 into 8 little-endian u32 words.
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

/// Reassemble 8 u32 words into a felt252 (251-bit truncated).
fn u32x8_to_felt(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32, h5: u32, h6: u32, h7: u32) -> felt252 {
    let low: u128 = h0.into() + h1.into() * POW32 + h2.into() * POW64 + h3.into() * POW96;
    let h7_masked: u128 = h7.into() & 0x07FFFFFF;
    let high: u128 = h4.into() + h5.into() * POW32 + h6.into() * POW64 + h7_masked * POW96;
    let out = u256 { low, high };
    out.try_into().unwrap()
}

/// H(a) — single-element hash (32 bytes input), used for key derivation.
pub fn hash1(a: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0, 0]);
    let result = blake2s_finalize(blake2s_iv(), 32, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H(a, b) — two-element hash (64 bytes input), used for nullifiers and Merkle nodes.
pub fn hash2(a: felt252, b: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let result = blake2s_finalize(blake2s_iv(), 64, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H(a, b, c, d) — four-element hash, used for note commitments.
/// Proper 2-block BLAKE2s: compress(IV, a||b) then finalize(state, c||d, 128).
/// Domain-separated from hash2 (byte_count=64) by using byte_count=128.
pub fn hash4(a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let (c0, c1, c2, c3, c4, c5, c6, c7) = felt_to_u32x8(c);
    let (d0, d1, d2, d3, d4, d5, d6, d7) = felt_to_u32x8(d);

    // Block 1: a || b (64 bytes, non-final)
    let block1 = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let state = blake2s_compress(blake2s_iv(), 64, block1);

    // Block 2: c || d (64 bytes, final, total byte_count = 128)
    let block2 = BoxTrait::new([c0, c1, c2, c3, c4, c5, c6, c7, d0, d1, d2, d3, d4, d5, d6, d7]);
    let result = blake2s_finalize(state, 128, block2);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// Derive paying key from spending key: pk = H(sk).
pub fn derive_pk(sk: felt252) -> felt252 {
    hash1(sk)
}

/// Compute note commitment: cm = H(pk, v, rho, r).
pub fn commit(pk: felt252, v: u64, rho: felt252, r: felt252) -> felt252 {
    hash4(pk, v.into(), rho, r)
}

/// Compute nullifier: nf = H(sk, rho).
pub fn nullifier(sk: felt252, rho: felt252) -> felt252 {
    hash2(sk, rho)
}
