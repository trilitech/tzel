/// Poseidon2 hash primitives.
///
/// Uses Cairo's built-in Poseidon permutation (Hades construction over the
/// Stark field). Swap this module for a dedicated Poseidon2 implementation
/// when it lands in the stdlib.

use core::poseidon::PoseidonTrait;
use core::hash::{HashStateTrait, HashStateExTrait};

/// H(a) — single-element hash, used for key derivation.
pub fn hash1(a: felt252) -> felt252 {
    PoseidonTrait::new().update_with(a).finalize()
}

/// H(a, b) — two-element hash, used for nullifiers and Merkle nodes.
pub fn hash2(a: felt252, b: felt252) -> felt252 {
    PoseidonTrait::new().update_with(a).update_with(b).finalize()
}

/// H(a, b, c, d) — four-element hash, used for note commitments.
pub fn hash4(a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    PoseidonTrait::new()
        .update_with(a)
        .update_with(b)
        .update_with(c)
        .update_with(d)
        .finalize()
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
