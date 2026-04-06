/// Transfer circuit: N→2 JoinSplit (1 ≤ N ≤ 16).
///
/// Consumes N private notes and creates exactly 2 new private notes,
/// with total input value equal to total output value. This single
/// circuit handles all private-to-private operations:
///   - 1→2 split (one input, two outputs)
///   - 2→2 standard transfer (N=2)
///   - 5→2 consolidation (merge five notes into payment + change)
///
/// N is a runtime parameter, not a program parameter. The program hash
/// is the same regardless of N. N is NOT private — the number of
/// published nullifiers reveals the input count.
///
/// # Public outputs
///   [root, nf_0, ..., nf_{N-1}, cm_1, cm_2, ak_0, ..., ak_{N-1}]
///
/// # Constraints
///   For each input i (0..N):
///     rcm_i = H("rcm", rseed_i)
///     cm_i  = H_commit(d_j_i, v_i, rcm_i, ak_i)
///     cm_i is in T under root
///     nf_i  = H_null(nk_i, cm_i)
///   All nf_i are pairwise distinct
///   For both outputs:
///     cm = H_commit(d_j, v, rcm, ak)
///   sum(v_inputs) = v_1 + v_2

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

/// Maximum number of inputs. Cap at 16 for bounded worst-case prover time.
const MAX_INPUTS: u32 = 16;

pub fn verify(
    // --- public ---
    root: felt252,
    nf_list: Span<felt252>,      // N nullifiers (one per input)
    cm_1: felt252,               // output commitment 1
    cm_2: felt252,               // output commitment 2
    // --- per-input parallel arrays (all length N) ---
    nk_list: Span<felt252>,      // per-input nullifier key
    ak_in_list: Span<felt252>,   // per-input authorization key
    d_j_in_list: Span<felt252>,  // per-input diversified address
    v_in_list: Span<u64>,        // per-input value
    rseed_in_list: Span<felt252>,// per-input randomness
    siblings_flat: Span<felt252>,// N * TREE_DEPTH siblings, concatenated
    path_indices_list: Span<u64>,// per-input Merkle path index
    // --- output 1 ---
    d_j_1: felt252, v_1: u64, rseed_1: felt252, ak_1: felt252,
    // --- output 2 ---
    d_j_2: felt252, v_2: u64, rseed_2: felt252, ak_2: felt252,
) -> Array<felt252> {
    // Determine N from the nullifier list length.
    let n = nf_list.len();
    assert(n >= 1, 'transfer: need >= 1 input');
    assert(n <= MAX_INPUTS, 'transfer: too many inputs');

    // All parallel arrays must have the same length.
    assert(nk_list.len() == n, 'transfer: nk_list len');
    assert(ak_in_list.len() == n, 'transfer: ak_list len');
    assert(d_j_in_list.len() == n, 'transfer: d_j_list len');
    assert(v_in_list.len() == n, 'transfer: v_list len');
    assert(rseed_in_list.len() == n, 'transfer: rseed_list len');
    assert(path_indices_list.len() == n, 'transfer: path_list len');
    assert(siblings_flat.len() == n * merkle::TREE_DEPTH, 'transfer: siblings len');

    // ── Verify each input ────────────────────────────────────────────
    let mut sum_in: u128 = 0;
    let mut i: u32 = 0;
    while i < n {
        let nk = *nk_list.at(i);
        let ak = *ak_in_list.at(i);
        let d_j = *d_j_in_list.at(i);
        let v: u64 = *v_in_list.at(i);
        let rseed = *rseed_in_list.at(i);
        let path_idx = *path_indices_list.at(i);

        // Extract this input's siblings from the flat array.
        let sib_start = i * merkle::TREE_DEPTH;
        let siblings = siblings_flat.slice(sib_start, merkle::TREE_DEPTH);

        // Recompute commitment and verify.
        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, rcm, ak);
        merkle::verify(cm, root, siblings, path_idx);

        // Verify nullifier.
        let nf = hash::nullifier(nk, cm);
        assert(nf == *nf_list.at(i), 'transfer: bad nf');

        sum_in += v.into();
        i += 1;
    };

    // ── Pairwise nullifier distinctness ──────────────────────────────
    // O(N²) but N ≤ 16, so at most 120 comparisons — negligible.
    let mut a: u32 = 0;
    while a < n {
        let mut b: u32 = a + 1;
        while b < n {
            assert(*nf_list.at(a) != *nf_list.at(b), 'transfer: dup nullifier');
            b += 1;
        };
        a += 1;
    };

    // ── Verify output commitments ────────────────────────────────────
    let rcm_1 = hash::derive_rcm(rseed_1);
    assert(hash::commit(d_j_1, v_1, rcm_1, ak_1) == cm_1, 'transfer: bad cm_1');
    let rcm_2 = hash::derive_rcm(rseed_2);
    assert(hash::commit(d_j_2, v_2, rcm_2, ak_2) == cm_2, 'transfer: bad cm_2');

    // ── Balance conservation ─────────────────────────────────────────
    let sum_out: u128 = v_1.into() + v_2.into();
    assert(sum_in == sum_out, 'transfer: balance mismatch');

    // ── Build public outputs ─────────────────────────────────────────
    // Format: [root, nf_0..nf_{n-1}, cm_1, cm_2, ak_0..ak_{n-1}]
    let mut outputs: Array<felt252> = array![root];
    let mut j: u32 = 0;
    while j < n {
        outputs.append(*nf_list.at(j));
        j += 1;
    };
    outputs.append(cm_1);
    outputs.append(cm_2);
    let mut j: u32 = 0;
    while j < n {
        outputs.append(*ak_in_list.at(j));
        j += 1;
    };
    outputs
}
