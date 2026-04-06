/// Unshield circuit: N→withdrawal + optional change (1 ≤ N ≤ 16).
///
/// Consumes N private notes, releases `v_pub` to a public address,
/// and optionally creates one private change note.
///
/// # Public outputs
///   [root, nf_0, ..., nf_{N-1}, v_pub, ak_0, ..., ak_{N-1}, recipient, cm_change]
///   (cm_change = 0 if no change output)
///
/// # Constraints
///   Same per-input verification as Transfer (Merkle, nullifier, commitment)
///   If has_change: cm_change = H_commit(d_j_c, v_change, rcm_c, ak_c)
///   sum(v_inputs) = v_pub + v_change

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
    nk_list: Span<felt252>,
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
) -> Array<felt252> {
    let n = nf_list.len();
    assert(n >= 1, 'unshield: need >= 1 input');
    assert(n <= MAX_INPUTS, 'unshield: too many inputs');
    assert(nk_list.len() == n, 'unshield: nk len');
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
        let nk = *nk_list.at(i);
        let ak = *ak_in_list.at(i);
        let d_j = *d_j_in_list.at(i);
        let v: u64 = *v_in_list.at(i);
        let rseed = *rseed_in_list.at(i);
        let path_idx = *path_indices_list.at(i);

        let sib_start = i * merkle::TREE_DEPTH;
        let siblings = siblings_flat.slice(sib_start, merkle::TREE_DEPTH);

        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, rcm, ak);
        merkle::verify(cm, root, siblings, path_idx);

        let nf = hash::nullifier(nk, cm);
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
        hash::commit(d_j_change, v_change, rcm_c, ak_change)
    } else {
        assert(v_change == 0, 'unshield: no change but v!=0');
        0
    };

    // ── Balance conservation ─────────────────────────────────────────
    let sum_out: u128 = v_pub.into() + v_change.into();
    assert(sum_in == sum_out, 'unshield: balance mismatch');

    // ── Public outputs ───────────────────────────────────────────────
    let mut outputs: Array<felt252> = array![root];
    let mut j: u32 = 0;
    while j < n {
        outputs.append(*nf_list.at(j));
        j += 1;
    };
    outputs.append(v_pub.into());
    let mut j: u32 = 0;
    while j < n {
        outputs.append(*ak_in_list.at(j));
        j += 1;
    };
    outputs.append(recipient);
    outputs.append(cm_change);
    outputs
}
