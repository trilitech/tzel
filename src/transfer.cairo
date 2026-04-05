/// Transfer circuit: 2-in-2-out JoinSplit.
///
/// Public inputs:  root, nf_a, nf_b, cm_1, cm_2
/// Private inputs: two spent notes with Merkle paths, two new notes
///
/// Proves:
///   1. Both inputs are valid notes in T under root
///   2. Nullifiers are correctly derived
///   3. nf_a != nf_b
///   4. Output commitments are well-formed
///   5. v_a + v_b = v_1 + v_2
///   6. v_1 < 2^64, v_2 < 2^64 (implicit via u64 type)

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

pub fn verify(
    // --- public inputs ---
    root: felt252,
    nf_a: felt252,
    nf_b: felt252,
    cm_1: felt252,
    cm_2: felt252,
    // --- spent note A ---
    sk_a: felt252,
    v_a: u64,
    rho_a: felt252,
    r_a: felt252,
    siblings_a: Span<felt252>,
    path_indices_a: u64,
    // --- spent note B ---
    sk_b: felt252,
    v_b: u64,
    rho_b: felt252,
    r_b: felt252,
    siblings_b: Span<felt252>,
    path_indices_b: u64,
    // --- new note 1 ---
    pk_1: felt252,
    v_1: u64,
    rho_1: felt252,
    r_1: felt252,
    // --- new note 2 ---
    pk_2: felt252,
    v_2: u64,
    rho_2: felt252,
    r_2: felt252,
) -> Array<felt252> {
    // Input A: derive pk, recompute commitment, verify Merkle membership, check nullifier
    let pk_a = hash::derive_pk(sk_a);
    let cm_a = hash::commit(pk_a, v_a, rho_a, r_a);
    merkle::verify(cm_a, root, siblings_a, path_indices_a);
    assert(hash::nullifier(sk_a, rho_a) == nf_a, 'transfer: bad nf_a');

    // Input B: same
    let pk_b = hash::derive_pk(sk_b);
    let cm_b = hash::commit(pk_b, v_b, rho_b, r_b);
    merkle::verify(cm_b, root, siblings_b, path_indices_b);
    assert(hash::nullifier(sk_b, rho_b) == nf_b, 'transfer: bad nf_b');

    // Nullifier uniqueness (prevents same-note double spend in one tx)
    assert(nf_a != nf_b, 'transfer: duplicate nullifier');

    // Output commitments
    assert(hash::commit(pk_1, v_1, rho_1, r_1) == cm_1, 'transfer: bad cm_1');
    assert(hash::commit(pk_2, v_2, rho_2, r_2) == cm_2, 'transfer: bad cm_2');

    // Balance conservation (u128 arithmetic to avoid overflow)
    let sum_in: u128 = v_a.into() + v_b.into();
    let sum_out: u128 = v_1.into() + v_2.into();
    assert(sum_in == sum_out, 'transfer: balance mismatch');

    // Public outputs — the on-chain verifier reads these from the proof.
    array![root, nf_a, nf_b, cm_1, cm_2]
}
