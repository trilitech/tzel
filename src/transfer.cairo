/// Transfer circuit: 2-in-2-out JoinSplit.
///
/// # Public outputs
///   - `root`  — Merkle root of T
///   - `nf_a`  — nullifier of first spent note
///   - `nf_b`  — nullifier of second spent note
///   - `cm_1`  — first output commitment (appended to T)
///   - `cm_2`  — second output commitment (appended to T)
///   - `ak_a`  — authorization key for input note A
///   - `ak_b`  — authorization key for input note B
///
/// # Constraints
///   1. Both inputs: pk = H(nsk), cm = H(H(pk, ak), v, rho, r), Merkle membership
///   2. Nullifiers: nf = H(nsk, rho) for both inputs
///   3. nf_a != nf_b
///   4. Output commitments well-formed
///   5. v_a + v_b = v_1 + v_2
///   6. v_1, v_2 < 2^64
///
/// # Delegated proving
///
/// The prover receives (nsk_a, ak_a, nsk_b, ak_b, ...) for the inputs
/// and all output data. They generate the proof but cannot authorize it.
/// The user signs the outputs with (ask_a, ask_b). The contract verifies
/// signatures against (ak_a, ak_b) from the proof's public outputs.
///
/// Both input notes must be authorized — this prevents a prover who knows
/// one note's ask from spending a second note they were only asked to prove.

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

pub fn verify(
    // --- public inputs ---
    root: felt252,
    nf_a: felt252,
    nf_b: felt252,
    cm_1: felt252,
    cm_2: felt252,
    // --- spent note A (private witness given to prover) ---
    nsk_a: felt252,
    ak_a: felt252,
    v_a: u64,
    rho_a: felt252,
    r_a: felt252,
    siblings_a: Span<felt252>,
    path_indices_a: u64,
    // --- spent note B (private witness given to prover) ---
    nsk_b: felt252,
    ak_b: felt252,
    v_b: u64,
    rho_b: felt252,
    r_b: felt252,
    siblings_b: Span<felt252>,
    path_indices_b: u64,
    // --- new note 1 (private witness) ---
    pk_1: felt252,
    ak_1: felt252,
    v_1: u64,
    rho_1: felt252,
    r_1: felt252,
    // --- new note 2 (private witness) ---
    pk_2: felt252,
    ak_2: felt252,
    v_2: u64,
    rho_2: felt252,
    r_2: felt252,
) -> Array<felt252> {
    // ── Verify input note A ──────────────────────────────────────────
    let pk_a = hash::derive_pk(nsk_a);
    let cm_a = hash::commit(pk_a, ak_a, v_a, rho_a, r_a);
    merkle::verify(cm_a, root, siblings_a, path_indices_a);
    assert(hash::nullifier(nsk_a, rho_a) == nf_a, 'transfer: bad nf_a');

    // ── Verify input note B ──────────────────────────────────────────
    let pk_b = hash::derive_pk(nsk_b);
    let cm_b = hash::commit(pk_b, ak_b, v_b, rho_b, r_b);
    merkle::verify(cm_b, root, siblings_b, path_indices_b);
    assert(hash::nullifier(nsk_b, rho_b) == nf_b, 'transfer: bad nf_b');

    // ── Same-note double-spend prevention ────────────────────────────
    assert(nf_a != nf_b, 'transfer: duplicate nullifier');

    // ── Verify output commitments ────────────────────────────────────
    assert(hash::commit(pk_1, ak_1, v_1, rho_1, r_1) == cm_1, 'transfer: bad cm_1');
    assert(hash::commit(pk_2, ak_2, v_2, rho_2, r_2) == cm_2, 'transfer: bad cm_2');

    // ── Balance conservation (u128 to prevent overflow) ──────────────
    let sum_in: u128 = v_a.into() + v_b.into();
    let sum_out: u128 = v_1.into() + v_2.into();
    assert(sum_in == sum_out, 'transfer: balance mismatch');

    // Public outputs. ak_a and ak_b are included so the contract can
    // verify spend authorization signatures for BOTH input notes.
    array![root, nf_a, nf_b, cm_1, cm_2, ak_a, ak_b]
}
