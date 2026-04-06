/// Transfer circuit: N→2 JoinSplit (1 ≤ N ≤ 16).
///
/// # Public outputs
///   [root, nf_0..nf_{N-1}, cm_1, cm_2, ak_0..ak_{N-1}, memo_ct_hash_1, memo_ct_hash_2]
///
/// # Constraints per input
///   nk_tag_i = H_nktg(nk_spend_i)             — verify binding tag from secret key
///   owner_tag_i = H_owner(ak_i, nk_tag_i)
///   cm_i = H_commit(d_j_i, v_i, rcm_i, owner_tag_i)
///   cm_i in Merkle tree under root
///   nf_i = H_nf(nk_spend_i, cm_i, pos_i)      — position-dependent nullifier
///
/// # Constraints on outputs
///   owner_tag = H_owner(ak, nk_tag)
///   cm = H_commit(d_j, v, rcm, owner_tag)
///
/// # Balance
///   sum(v_inputs) = v_1 + v_2

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

const MAX_INPUTS: u32 = 16;

pub fn verify(
    // --- public ---
    root: felt252,
    nf_list: Span<felt252>,
    cm_1: felt252,
    cm_2: felt252,
    // --- per-input parallel arrays ---
    nk_spend_list: Span<felt252>,  // per-input secret nullifier key
    ak_in_list: Span<felt252>,
    d_j_in_list: Span<felt252>,
    v_in_list: Span<u64>,
    rseed_in_list: Span<felt252>,
    siblings_flat: Span<felt252>,
    path_indices_list: Span<u64>,  // also serves as pos for nullifier
    // --- output 1 ---
    d_j_1: felt252, v_1: u64, rseed_1: felt252, ak_1: felt252, nk_tag_1: felt252, memo_ct_hash_1: felt252,
    // --- output 2 ---
    d_j_2: felt252, v_2: u64, rseed_2: felt252, ak_2: felt252, nk_tag_2: felt252, memo_ct_hash_2: felt252,
) -> Array<felt252> {
    let n = nf_list.len();
    assert(n >= 1, 'transfer: need >= 1 input');
    assert(n <= MAX_INPUTS, 'transfer: too many inputs');
    assert(nk_spend_list.len() == n, 'transfer: nk_spend len');
    assert(ak_in_list.len() == n, 'transfer: ak len');
    assert(d_j_in_list.len() == n, 'transfer: d_j len');
    assert(v_in_list.len() == n, 'transfer: v len');
    assert(rseed_in_list.len() == n, 'transfer: rseed len');
    assert(path_indices_list.len() == n, 'transfer: path len');
    assert(siblings_flat.len() == n * merkle::TREE_DEPTH, 'transfer: siblings len');

    // ── Verify each input ────────────────────────────────────────────
    let mut sum_in: u128 = 0;
    let mut i: u32 = 0;
    while i < n {
        let nk_spend = *nk_spend_list.at(i);
        let ak = *ak_in_list.at(i);
        let d_j = *d_j_in_list.at(i);
        let v: u64 = *v_in_list.at(i);
        let rseed = *rseed_in_list.at(i);
        let path_idx = *path_indices_list.at(i);

        // Verify nk_tag derives from nk_spend (binding check).
        let nk_tag = hash::derive_nk_tag(nk_spend);
        let otag = hash::owner_tag(ak, nk_tag);

        // Recompute commitment.
        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, rcm, otag);

        // Merkle membership.
        let sib_start = i * merkle::TREE_DEPTH;
        let siblings = siblings_flat.slice(sib_start, merkle::TREE_DEPTH);
        merkle::verify(cm, root, siblings, path_idx);

        // Position-dependent nullifier: H_nf(nk_spend, cm, pos).
        // pos = path_idx (the leaf index in the Merkle tree).
        let nf = hash::nullifier(nk_spend, cm, path_idx);
        assert(nf == *nf_list.at(i), 'transfer: bad nf');

        sum_in += v.into();
        i += 1;
    };

    // ── Pairwise nullifier distinctness ──────────────────────────────
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
    let otag_1 = hash::owner_tag(ak_1, nk_tag_1);
    assert(hash::commit(d_j_1, v_1, rcm_1, otag_1) == cm_1, 'transfer: bad cm_1');

    let rcm_2 = hash::derive_rcm(rseed_2);
    let otag_2 = hash::owner_tag(ak_2, nk_tag_2);
    assert(hash::commit(d_j_2, v_2, rcm_2, otag_2) == cm_2, 'transfer: bad cm_2');

    // ── Balance conservation ─────────────────────────────────────────
    let sum_out: u128 = v_1.into() + v_2.into();
    assert(sum_in == sum_out, 'transfer: balance mismatch');

    // ── Public outputs ───────────────────────────────────────────────
    let mut outputs: Array<felt252> = array![root];
    let mut j: u32 = 0;
    while j < n { outputs.append(*nf_list.at(j)); j += 1; };
    outputs.append(cm_1);
    outputs.append(cm_2);
    let mut j: u32 = 0;
    while j < n { outputs.append(*ak_in_list.at(j)); j += 1; };
    outputs.append(memo_ct_hash_1);
    outputs.append(memo_ct_hash_2);
    outputs
}
