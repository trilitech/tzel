/// Minimal BLAKE2s primitives for benchmarking — matches production blake_hash.cairo.

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxTrait;

const MASK32: u128 = 0xFFFFFFFF;
const POW32: u128 = 0x100000000;
const POW64: u128 = 0x10000000000000000;
const POW96: u128 = 0x1000000000000000000000000;

fn blake2s_iv() -> Box<[u32; 8]> {
    BoxTrait::new([0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19])
}
fn blake2s_iv_merkle() -> Box<[u32; 8]> {
    BoxTrait::new([0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                   0x510E527F, 0x9B05688C, 0x73E8ABC6, 0x04BF9D4A])
}
fn blake2s_iv_nullifier() -> Box<[u32; 8]> {
    BoxTrait::new([0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                   0x510E527F, 0x9B05688C, 0x79EFACC5, 0x04BF9D4A])
}
fn blake2s_iv_commit() -> Box<[u32; 8]> {
    BoxTrait::new([0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                   0x510E527F, 0x9B05688C, 0x6BEEB4C8, 0x04BF9D4A])
}
fn blake2s_iv_nk_tag() -> Box<[u32; 8]> {
    BoxTrait::new([0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                   0x510E527F, 0x9B05688C, 0x78F7B2C5, 0x04BF9D4A])
}
fn blake2s_iv_owner() -> Box<[u32; 8]> {
    BoxTrait::new([0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                   0x510E527F, 0x9B05688C, 0x6DEDAEC4, 0x04BF9D4A])
}

pub fn felt_to_u32x8(x: felt252) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    let v: u256 = x.into();
    let lo: u128 = v.low; let hi: u128 = v.high;
    (
        (lo & MASK32).try_into().unwrap(), ((lo / POW32) & MASK32).try_into().unwrap(),
        ((lo / POW64) & MASK32).try_into().unwrap(), ((lo / POW96) & MASK32).try_into().unwrap(),
        (hi & MASK32).try_into().unwrap(), ((hi / POW32) & MASK32).try_into().unwrap(),
        ((hi / POW64) & MASK32).try_into().unwrap(), ((hi / POW96) & MASK32).try_into().unwrap(),
    )
}

pub fn u32x8_to_felt(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32, h5: u32, h6: u32, h7: u32) -> felt252 {
    let low: u128 = h0.into() + h1.into() * POW32 + h2.into() * POW64 + h3.into() * POW96;
    let h7m: u128 = h7.into() & 0x07FFFFFF;
    let high: u128 = h4.into() + h5.into() * POW32 + h6.into() * POW64 + h7m * POW96;
    let out = u256 { low, high };
    out.try_into().unwrap()
}

fn finalize(iv: Box<[u32; 8]>, len: u32, msg: Box<[u32; 16]>) -> felt252 {
    let result = blake2s_finalize(iv, len, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

fn make_msg1(a: felt252) -> Box<[u32; 16]> {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0, 0])
}

fn make_msg2(a: felt252, b: felt252) -> Box<[u32; 16]> {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7])
}

// ── Public hash functions ────────────────────────────────────────────

pub fn hash1(a: felt252) -> felt252 { finalize(blake2s_iv(), 32, make_msg1(a)) }
pub fn hash2(a: felt252, b: felt252) -> felt252 { finalize(blake2s_iv(), 64, make_msg2(a, b)) }
pub fn hash2_merkle(a: felt252, b: felt252) -> felt252 { finalize(blake2s_iv_merkle(), 64, make_msg2(a, b)) }

pub fn derive_rcm(rseed: felt252) -> felt252 { hash2(hash1(0x72636D), rseed) }
pub fn derive_nk_tag(nk_spend: felt252) -> felt252 { finalize(blake2s_iv_nk_tag(), 32, make_msg1(nk_spend)) }
pub fn owner_tag(auth_root: felt252, nk_tag: felt252) -> felt252 { finalize(blake2s_iv_owner(), 64, make_msg2(auth_root, nk_tag)) }

pub fn commit(d_j: felt252, v: u64, rcm: felt252, otag: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(d_j);
    let vlo: u32 = (v & 0xFFFFFFFF).try_into().unwrap();
    let vhi: u32 = ((v / 0x100000000) & 0xFFFFFFFF).try_into().unwrap();
    let block1 = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, vlo, vhi, 0, 0, 0, 0, 0, 0]);
    let state = blake2s_compress(blake2s_iv_commit(), 64, block1);
    let [s0, s1, s2, s3, s4, s5, s6, s7] = state.unbox();
    let (c0, c1, c2, c3, c4, c5, c6, c7) = felt_to_u32x8(rcm);
    let (d0, d1, d2, d3, d4, d5, d6, d7) = felt_to_u32x8(otag);
    let block2 = BoxTrait::new([c0, c1, c2, c3, c4, c5, c6, c7, d0, d1, d2, d3, d4, d5, d6, d7]);
    let result = blake2s_finalize(BoxTrait::new([s0, s1, s2, s3, s4, s5, s6, s7]), 128, block2);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

pub fn nullifier(nk_spend: felt252, cm: felt252, pos: u64) -> felt252 {
    let cm_pos = finalize(blake2s_iv_nullifier(), 64, make_msg2(cm, pos.into()));
    finalize(blake2s_iv_nullifier(), 64, make_msg2(nk_spend, cm_pos))
}

// ── Merkle verification ──────────────────────────────────────────────

#[cfg(feature: 'depth16')]
pub const TREE_DEPTH: u32 = 16;
#[cfg(feature: 'depth48')]
pub const TREE_DEPTH: u32 = 48;
pub const AUTH_DEPTH: u32 = 10;

pub fn verify_merkle(leaf: felt252, root: felt252, siblings: Span<felt252>, path_indices: u64) {
    let mut current = leaf;
    let mut idx = path_indices;
    let mut i: u32 = 0;
    while i < TREE_DEPTH {
        let sib = *siblings.at(i);
        let bit = idx & 1; idx = idx / 2;
        current = if bit == 1 { hash2_merkle(sib, current) } else { hash2_merkle(current, sib) };
        i += 1;
    };
    assert(idx == 0, 'path_idx range');
    assert(current == root, 'merkle root');
}

pub fn verify_auth(leaf: felt252, root: felt252, siblings: Span<felt252>, path_indices: u64) {
    let mut current = leaf;
    let mut idx = path_indices;
    let mut i: u32 = 0;
    while i < AUTH_DEPTH {
        let sib = *siblings.at(i);
        let bit = idx & 1; idx = idx / 2;
        current = if bit == 1 { hash2_merkle(sib, current) } else { hash2_merkle(current, sib) };
        i += 1;
    };
    assert(idx == 0, 'auth_idx range');
    assert(current == root, 'auth root');
}
