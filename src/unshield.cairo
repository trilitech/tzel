/// Unshield circuit: N→withdrawal + optional change (1 ≤ N ≤ 16).
///
/// # Public outputs
///   [auth_domain, root, nf_0..nf_{N-1}, v_pub, recipient, cm_change, memo_ct_hash_change]
///
/// # Spend authorization
///   WOTS+ w=4 signature verification inside the STARK, bound to the sighash.

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

const MAX_INPUTS: u32 = 16;
const WOTS_W: u32 = 4;
const WOTS_CHAINS: u32 = 133;

pub fn verify(
    // --- public ---
    auth_domain: felt252,
    root: felt252,
    nf_list: Span<felt252>,
    v_pub: u64,
    recipient: felt252,
    // --- per-input parallel arrays ---
    nk_spend_list: Span<felt252>,
    auth_root_list: Span<felt252>,
    wots_sig_flat: Span<felt252>,
    wots_pk_flat: Span<felt252>,
    auth_siblings_flat: Span<felt252>,
    auth_index_list: Span<u64>,
    d_j_in_list: Span<felt252>,
    v_in_list: Span<u64>,
    rseed_in_list: Span<felt252>,
    cm_siblings_flat: Span<felt252>,
    cm_path_indices_list: Span<u64>,
    // --- optional change output ---
    has_change: bool,
    d_j_change: felt252,
    v_change: u64,
    rseed_change: felt252,
    auth_root_change: felt252,
    nk_tag_change: felt252,
    memo_ct_hash_change: felt252,
) -> Array<felt252> {
    let n = nf_list.len();
    assert(n >= 1, 'unshield: need >= 1 input');
    assert(n <= MAX_INPUTS, 'unshield: too many inputs');
    assert(nk_spend_list.len() == n, 'unshield: nk_spend len');
    assert(auth_root_list.len() == n, 'unshield: auth_root len');
    assert(wots_sig_flat.len() == n * WOTS_CHAINS, 'unshield: wots_sig len');
    assert(wots_pk_flat.len() == n * WOTS_CHAINS, 'unshield: wots_pk len');
    assert(auth_siblings_flat.len() == n * merkle::AUTH_DEPTH, 'unshield: auth_sibs len');
    assert(auth_index_list.len() == n, 'unshield: auth_idx len');
    assert(d_j_in_list.len() == n, 'unshield: d_j len');
    assert(v_in_list.len() == n, 'unshield: v len');
    assert(rseed_in_list.len() == n, 'unshield: rseed len');
    assert(cm_path_indices_list.len() == n, 'unshield: path len');
    assert(cm_siblings_flat.len() == n * merkle::TREE_DEPTH, 'unshield: cm_sibs len');

    // ── Compute sighash from public outputs ─────────────────────────
    // Circuit-type tag 0x02 prevents cross-circuit replay.
    let mut sighash = hash::sighash_fold(0x02, auth_domain);
    sighash = hash::sighash_fold(sighash, root);
    let mut si: u32 = 0;
    while si < n {
        sighash = hash::sighash_fold(sighash, *nf_list.at(si));
        si += 1;
    };
    sighash = hash::sighash_fold(sighash, v_pub.into());
    sighash = hash::sighash_fold(sighash, recipient);
    // Include change cm and memo hash (both 0 if no change — still bound)
    let cm_change_val = if has_change {
        let rcm_c = hash::derive_rcm(rseed_change);
        let otag_c = hash::owner_tag(auth_root_change, nk_tag_change);
        hash::commit(d_j_change, v_change, rcm_c, otag_c)
    } else {
        assert(v_change == 0, 'unshield: no change but v!=0');
        assert(memo_ct_hash_change == 0, 'unshield: mh!=0 but no change');
        assert(d_j_change == 0, 'unshield: d_j!=0 but no change');
        assert(rseed_change == 0, 'unshield: rseed!=0 no change');
        assert(auth_root_change == 0, 'unshield: ar!=0 but no change');
        assert(nk_tag_change == 0, 'unshield: nkt!=0 but no change');
        0
    };
    sighash = hash::sighash_fold(sighash, cm_change_val);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_change);

    let sighash_digits = hash::sighash_to_wots_digits(sighash);

    // ── Verify each input ────────────────────────────────────────────
    let mut sum_in: u128 = 0;
    let mut i: u32 = 0;
    while i < n {
        let nk_spend = *nk_spend_list.at(i);
        let auth_root = *auth_root_list.at(i);
        let auth_idx = *auth_index_list.at(i);
        let d_j = *d_j_in_list.at(i);
        let v: u64 = *v_in_list.at(i);
        let rseed = *rseed_in_list.at(i);
        let cm_path_idx = *cm_path_indices_list.at(i);

        let nk_tag = hash::derive_nk_tag(nk_spend);
        let otag = hash::owner_tag(auth_root, nk_tag);
        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, rcm, otag);

        let cm_sib_start = i * merkle::TREE_DEPTH;
        let cm_siblings = cm_siblings_flat.slice(cm_sib_start, merkle::TREE_DEPTH);
        merkle::verify(cm, root, cm_siblings, cm_path_idx);

        // WOTS+ w=4 signature verification (digits from sighash).
        let wots_start = i * WOTS_CHAINS;
        let mut j: u32 = 0;
        while j < WOTS_CHAINS {
            let idx = wots_start + j;
            let digit = *sighash_digits.at(j);
            let remaining = WOTS_W - 1 - digit;
            let mut current = *wots_sig_flat.at(idx);
            let mut k: u32 = 0;
            while k < remaining { current = hash::hash1_wots(current); k += 1; };
            assert(current == *wots_pk_flat.at(idx), 'wots chain mismatch');
            j += 1;
        };

        let mut leaf = *wots_pk_flat.at(wots_start);
        let mut j: u32 = 1;
        while j < WOTS_CHAINS {
            leaf = hash::hash2_pkfold(leaf, *wots_pk_flat.at(wots_start + j));
            j += 1;
        };

        let auth_sib_start = i * merkle::AUTH_DEPTH;
        let auth_siblings = auth_siblings_flat.slice(auth_sib_start, merkle::AUTH_DEPTH);
        merkle::verify_auth(leaf, auth_root, auth_siblings, auth_idx);

        let nf = hash::nullifier(nk_spend, cm, cm_path_idx);
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

    // ── Balance conservation ─────────────────────────────────────────
    let sum_out: u128 = v_pub.into() + v_change.into();
    assert(sum_in == sum_out, 'unshield: balance mismatch');

    // ── Public outputs ───────────────────────────────────────────────
    let mut outputs: Array<felt252> = array![auth_domain, root];
    let mut j: u32 = 0;
    while j < n { outputs.append(*nf_list.at(j)); j += 1; };
    outputs.append(v_pub.into());
    outputs.append(recipient);
    outputs.append(cm_change_val);
    outputs.append(memo_ct_hash_change);
    outputs
}
