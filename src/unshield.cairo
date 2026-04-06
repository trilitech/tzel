/// Unshield circuit: N→withdrawal + optional change (1 ≤ N ≤ 16).
///
/// # Public outputs
///   [root, nf_0..nf_{N-1}, v_pub, ak_0..ak_{N-1}, recipient, cm_change, memo_ct_hash_change]
///
/// # Constraints (per input)
///   nk_tag_i = H_nktg(nk_spend_i)
///   owner_tag_i = H_owner(ak_i, nk_tag_i)
///   cm_i = H_commit(d_j_i, v_i, rcm_i, owner_tag_i)
///   Merkle membership, obtaining pos_i
///   nf_i = H_nf(nk_spend_i, cm_i, pos_i)
///
/// # Change output
///   If has_change: cm_change = H_commit(d_j_c, v_change, rcm_c, H_owner(ak_c, nk_tag_c))
///   If !has_change: v_change = 0, cm_change = 0, memo_ct_hash_change = 0
///
/// # Balance: sum(v_inputs) = v_pub + v_change

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

const MAX_INPUTS: u32 = 16;

pub fn verify(
    // --- public ---
    root: felt252,
    nf_list: Span<felt252>,
    v_pub: u64,
    recipient: felt252,
    // --- per-input parallel arrays ---
    nk_spend_list: Span<felt252>,
    ak_in_list: Span<felt252>,
    d_j_in_list: Span<felt252>,
    v_in_list: Span<u64>,
    rseed_in_list: Span<felt252>,
    siblings_flat: Span<felt252>,
    path_indices_list: Span<u64>,
    // --- optional change output ---
    has_change: bool,
    d_j_change: felt252,
    v_change: u64,
    rseed_change: felt252,
    ak_change: felt252,
    nk_tag_change: felt252,
    memo_ct_hash_change: felt252,
) -> Array<felt252> {
    let n = nf_list.len();
    assert(n >= 1, 'unshield: need >= 1 input');
    assert(n <= MAX_INPUTS, 'unshield: too many inputs');
    assert(nk_spend_list.len() == n, 'unshield: nk_spend len');
    assert(ak_in_list.len() == n, 'unshield: ak len');
    assert(d_j_in_list.len() == n, 'unshield: d_j len');
    assert(v_in_list.len() == n, 'unshield: v len');
    assert(rseed_in_list.len() == n, 'unshield: rseed len');
    assert(path_indices_list.len() == n, 'unshield: path len');
    assert(siblings_flat.len() == n * merkle::TREE_DEPTH, 'unshield: siblings len');

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

        // Verify binding: nk_tag derives from nk_spend.
        let nk_tag = hash::derive_nk_tag(nk_spend);
        let otag = hash::owner_tag(ak, nk_tag);

        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, rcm, otag);

        let sib_start = i * merkle::TREE_DEPTH;
        let siblings = siblings_flat.slice(sib_start, merkle::TREE_DEPTH);
        merkle::verify(cm, root, siblings, path_idx);

        // Position-dependent nullifier.
        let nf = hash::nullifier(nk_spend, cm, path_idx);
        assert(nf == *nf_list.at(i), 'unshield: bad nf');

        sum_in += v.into();
        i += 1;
    };

    // ── Pairwise nullifier distinctness ──────────────────────────────
    let mut a: u32 = 0;
    while a < n {
        let mut b: u32 = a + 1;
        while b < n {
            assert(*nf_list.at(a) != *nf_list.at(b), 'unshield: dup nf');
            b += 1;
        };
        a += 1;
    };

    // ── Change output (optional) ─────────────────────────────────────
    let cm_change = if has_change {
        let rcm_c = hash::derive_rcm(rseed_change);
        let otag_c = hash::owner_tag(ak_change, nk_tag_change);
        hash::commit(d_j_change, v_change, rcm_c, otag_c)
    } else {
        assert(v_change == 0, 'unshield: no change but v!=0');
        assert(memo_ct_hash_change == 0, 'unshield: mh!=0 but no change');
        0
    };

    // ── Balance conservation ─────────────────────────────────────────
    let sum_out: u128 = v_pub.into() + v_change.into();
    assert(sum_in == sum_out, 'unshield: balance mismatch');

    // ── Public outputs ───────────────────────────────────────────────
    let mut outputs: Array<felt252> = array![root];
    let mut j: u32 = 0;
    while j < n { outputs.append(*nf_list.at(j)); j += 1; };
    outputs.append(v_pub.into());
    let mut j: u32 = 0;
    while j < n { outputs.append(*ak_in_list.at(j)); j += 1; };
    outputs.append(recipient);
    outputs.append(cm_change);
    outputs.append(memo_ct_hash_change);
    outputs
}
