/// Unshield circuit: N→withdrawal + optional change (1 ≤ N ≤ 16).
///
/// # Public outputs
///   [auth_domain, root, nf_0..nf_{N-1}, v_pub, recipient_id, cm_change, memo_ct_hash_change]
///
/// # Spend authorization
///   XMSS-style WOTS+ w=4 signature verification inside the STARK, bound to the sighash.

use tzel::blake_hash as hash;
use tzel::merkle;
use tzel::xmss_common;

const MAX_INPUTS: u32 = 16;

pub fn verify(
    auth_domain: felt252,
    root: felt252,
    nf_list: Span<felt252>,
    v_pub: u64,
    recipient: felt252,
    nk_spend_list: Span<felt252>,
    auth_root_list: Span<felt252>,
    auth_pub_seed_list: Span<felt252>,
    wots_sig_flat: Span<felt252>,
    auth_siblings_flat: Span<felt252>,
    auth_index_list: Span<u64>,
    d_j_in_list: Span<felt252>,
    v_in_list: Span<u64>,
    rseed_in_list: Span<felt252>,
    cm_siblings_flat: Span<felt252>,
    cm_path_indices_list: Span<u64>,
    has_change: bool,
    d_j_change: felt252,
    v_change: u64,
    rseed_change: felt252,
    auth_root_change: felt252,
    auth_pub_seed_change: felt252,
    nk_tag_change: felt252,
    memo_ct_hash_change: felt252,
) -> Array<felt252> {
    let n = nf_list.len();
    assert(n >= 1, 'unshield: need >= 1 input');
    assert(n <= MAX_INPUTS, 'unshield: too many inputs');
    assert(nk_spend_list.len() == n, 'unshield: nk_spend len');
    assert(auth_root_list.len() == n, 'unshield: auth_root len');
    assert(auth_pub_seed_list.len() == n, 'unshield: auth_pub_seed len');
    assert(wots_sig_flat.len() == n * xmss_common::WOTS_CHAINS, 'unshield: wots_sig len');
    assert(auth_siblings_flat.len() == n * merkle::AUTH_DEPTH, 'unshield: auth_sibs len');
    assert(auth_index_list.len() == n, 'unshield: auth_idx len');
    assert(d_j_in_list.len() == n, 'unshield: d_j len');
    assert(v_in_list.len() == n, 'unshield: v len');
    assert(rseed_in_list.len() == n, 'unshield: rseed len');
    assert(cm_path_indices_list.len() == n, 'unshield: path len');
    assert(cm_siblings_flat.len() == n * merkle::TREE_DEPTH, 'unshield: cm_sibs len');

    let mut sighash = hash::sighash_fold(0x02, auth_domain);
    sighash = hash::sighash_fold(sighash, root);
    let mut si: u32 = 0;
    while si < n {
        sighash = hash::sighash_fold(sighash, *nf_list.at(si));
        si += 1;
    };
    sighash = hash::sighash_fold(sighash, v_pub.into());
    sighash = hash::sighash_fold(sighash, recipient);
    let cm_change_val = if has_change {
        let rcm_c = hash::derive_rcm(rseed_change);
        let otag_c = hash::owner_tag(auth_root_change, auth_pub_seed_change, nk_tag_change);
        hash::commit(d_j_change, v_change, rcm_c, otag_c)
    } else {
        assert(v_change == 0, 'unshield: no change but v!=0');
        assert(memo_ct_hash_change == 0, 'unshield: mh!=0 but no change');
        assert(d_j_change == 0, 'unshield: d_j!=0 but no change');
        assert(rseed_change == 0, 'unshield: rseed!=0 no change');
        assert(auth_root_change == 0, 'unshield: ar!=0 but no change');
        assert(auth_pub_seed_change == 0, 'unshield: ps!=0 but no change');
        assert(nk_tag_change == 0, 'unshield: nkt!=0 but no change');
        0
    };
    sighash = hash::sighash_fold(sighash, cm_change_val);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_change);

    let mut sum_in: u128 = 0;
    let mut i: u32 = 0;
    while i < n {
        let nk_spend = *nk_spend_list.at(i);
        let auth_root = *auth_root_list.at(i);
        let auth_pub_seed = *auth_pub_seed_list.at(i);
        let auth_idx: u32 = (*auth_index_list.at(i)).try_into().unwrap();
        let d_j = *d_j_in_list.at(i);
        let v: u64 = *v_in_list.at(i);
        let rseed = *rseed_in_list.at(i);
        let cm_path_idx = *cm_path_indices_list.at(i);

        let nk_tag = hash::derive_nk_tag(nk_spend);
        let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, rcm, otag);

        let cm_sib_start = i * merkle::TREE_DEPTH;
        let cm_siblings = cm_siblings_flat.slice(cm_sib_start, merkle::TREE_DEPTH);
        merkle::verify(cm, root, cm_siblings, cm_path_idx);

        let wots_start = i * xmss_common::WOTS_CHAINS;
        let recovered_pk = xmss_common::xmss_recover_pk(
            sighash,
            auth_pub_seed,
            auth_idx,
            wots_sig_flat.slice(wots_start, xmss_common::WOTS_CHAINS),
        );
        let leaf = xmss_common::xmss_ltree(auth_pub_seed, auth_idx, recovered_pk.span());

        let auth_sib_start = i * merkle::AUTH_DEPTH;
        let auth_siblings = auth_siblings_flat.slice(auth_sib_start, merkle::AUTH_DEPTH);
        xmss_common::xmss_verify_auth(leaf, auth_root, auth_pub_seed, auth_idx, auth_siblings);

        let nf = hash::nullifier(nk_spend, cm, cm_path_idx);
        assert(nf == *nf_list.at(i), 'unshield: bad nf');

        sum_in += v.into();
        i += 1;
    };

    let mut a: u32 = 0;
    while a < n {
        let mut b: u32 = a + 1;
        while b < n {
            assert(*nf_list.at(a) != *nf_list.at(b), 'unshield: dup nf');
            b += 1;
        };
        a += 1;
    };

    let sum_out: u128 = v_pub.into() + v_change.into();
    assert(sum_in == sum_out, 'unshield: balance mismatch');

    let mut outputs: Array<felt252> = array![auth_domain, root];
    let mut j: u32 = 0;
    while j < n { outputs.append(*nf_list.at(j)); j += 1; };
    outputs.append(v_pub.into());
    outputs.append(recipient);
    outputs.append(cm_change_val);
    outputs.append(memo_ct_hash_change);
    outputs
}
