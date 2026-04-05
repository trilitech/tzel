/// Transfer circuit: 2-in-2-out JoinSplit.
///
/// Consumes two private notes and creates two new private notes, with
/// total input value equal to total output value. This single circuit
/// covers all private-to-private operations:
///   - Transfer: Alice spends note A, creates note for Bob + change note for herself
///   - Join/merge: combine two notes into one (second output has v = 0)
///   - Split: break one note into two (second input is a zero-value dummy)
///
/// Zero-value dummy notes are used for unused slots. Each dummy note must
/// be a real commitment in the tree (created via Shield with v = 0), and
/// its nullifier is still consumed — so each dummy can only be used once.
///
/// # Public inputs (read from proof output by the on-chain verifier)
///   - `root`  — Merkle root of T
///   - `nf_a`  — nullifier of first spent note
///   - `nf_b`  — nullifier of second spent note
///   - `cm_1`  — first output commitment (appended to T)
///   - `cm_2`  — second output commitment (appended to T)
///
/// # Constraints
///   1. Both inputs are valid notes in T under root
///   2. Nullifiers are correctly derived: nf_x = H(sk_x, rho_x)
///   3. nf_a != nf_b (can't spend the same note twice in one tx)
///   4. Output commitments are well-formed: cm_x = H(pk_x, v_x, rho_x, r_x)
///   5. Value conservation: v_a + v_b = v_1 + v_2
///   6. Output range checks: v_1, v_2 < 2^64 (implicit via u64 type)
///
/// Note: The circuit does NOT need to know about the nullifier set — that
/// check happens on-chain. The proof just outputs the nullifiers and the
/// contract checks NF_set membership.

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

pub fn verify(
    // --- public inputs (will appear in proof output) ---
    root: felt252,
    nf_a: felt252,
    nf_b: felt252,
    cm_1: felt252,
    cm_2: felt252,
    // --- spent note A (private witness) ---
    sk_a: felt252,
    v_a: u64,
    rho_a: felt252,
    r_a: felt252,
    siblings_a: Span<felt252>,
    path_indices_a: u64,
    // --- spent note B (private witness) ---
    sk_b: felt252,
    v_b: u64,
    rho_b: felt252,
    r_b: felt252,
    siblings_b: Span<felt252>,
    path_indices_b: u64,
    // --- new note 1 (private witness) ---
    pk_1: felt252,
    v_1: u64,
    rho_1: felt252,
    r_1: felt252,
    // --- new note 2 (private witness) ---
    pk_2: felt252,
    v_2: u64,
    rho_2: felt252,
    r_2: felt252,
) -> Array<felt252> {
    // ── Verify input note A ──────────────────────────────────────────
    // Derive pk from sk, recompute commitment, check it's in the tree,
    // and verify the nullifier matches.
    let pk_a = hash::derive_pk(sk_a);
    let cm_a = hash::commit(pk_a, v_a, rho_a, r_a);
    merkle::verify(cm_a, root, siblings_a, path_indices_a);
    assert(hash::nullifier(sk_a, rho_a) == nf_a, 'transfer: bad nf_a');

    // ── Verify input note B (same checks) ────────────────────────────
    let pk_b = hash::derive_pk(sk_b);
    let cm_b = hash::commit(pk_b, v_b, rho_b, r_b);
    merkle::verify(cm_b, root, siblings_b, path_indices_b);
    assert(hash::nullifier(sk_b, rho_b) == nf_b, 'transfer: bad nf_b');

    // ── Prevent same-note double spend within this transaction ───────
    // Without this check, a prover could use the same note for both
    // inputs and double their money. Cross-transaction double-spend
    // is handled by the on-chain nullifier set.
    assert(nf_a != nf_b, 'transfer: duplicate nullifier');

    // ── Verify output commitments are well-formed ────────────────────
    // The prover chooses the recipients (pk_1, pk_2) — the circuit just
    // ensures the commitments match the claimed values.
    assert(hash::commit(pk_1, v_1, rho_1, r_1) == cm_1, 'transfer: bad cm_1');
    assert(hash::commit(pk_2, v_2, rho_2, r_2) == cm_2, 'transfer: bad cm_2');

    // ── Balance conservation ─────────────────────────────────────────
    // Sum in u128 to prevent overflow (max u64 + u64 = 2^65 - 2 < 2^128).
    // Output range checks (v_1, v_2 < 2^64) are implicit via the u64 type —
    // Cairo's range_check builtin enforces this at the VM level.
    let sum_in: u128 = v_a.into() + v_b.into();
    let sum_out: u128 = v_1.into() + v_2.into();
    assert(sum_in == sum_out, 'transfer: balance mismatch');

    // ── Public outputs ───────────────────────────────────────────────
    // The on-chain verifier reads these to update state:
    //   - Check root is a valid historical root
    //   - Check nf_a, nf_b are not in NF_set, then add them
    //   - Append cm_1, cm_2 to the commitment tree T
    array![root, nf_a, nf_b, cm_1, cm_2]
}
