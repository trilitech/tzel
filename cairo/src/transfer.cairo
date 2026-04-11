/// Transfer circuit: N→2 JoinSplit (1 ≤ N ≤ 16).
///
/// # Public outputs
///   [auth_domain, root, nf_0..nf_{N-1}, cm_1, cm_2, memo_ct_hash_1, memo_ct_hash_2]
///
/// # Spend authorization
///   XMSS-style WOTS+ w=4 signature verification inside the STARK.
///   The circuit recovers the 133 WOTS public-key endpoints from the signature,
///   compresses them with an XMSS L-tree, and authenticates that exact leaf under
///   the witness `(auth_root, auth_pub_seed)` public key.

use tzel::blake_hash as hash;
use tzel::merkle;
use tzel::xmss_common;

const MAX_INPUTS: u32 = 16;

pub fn verify(
    auth_domain: felt252,
    root: felt252,
    nf_list: Span<felt252>,
    cm_1: felt252,
    cm_2: felt252,
    nk_spend_list: Span<felt252>,
    auth_root_list: Span<felt252>,
    auth_pub_seed_list: Span<felt252>,
    auth_index_list: Span<u64>,
    d_j_in_list: Span<felt252>,
    v_in_list: Span<u64>,
    rseed_in_list: Span<felt252>,
    cm_siblings_flat: Span<felt252>,
    auth_siblings_flat: Span<felt252>,
    cm_path_indices_list: Span<u64>,
    wots_sig_flat: Span<felt252>,
    d_j_1: felt252, v_1: u64, rseed_1: felt252, auth_root_1: felt252, auth_pub_seed_1: felt252, nk_tag_1: felt252, memo_ct_hash_1: felt252,
    d_j_2: felt252, v_2: u64, rseed_2: felt252, auth_root_2: felt252, auth_pub_seed_2: felt252, nk_tag_2: felt252, memo_ct_hash_2: felt252,
) -> Array<felt252> {
    let n = nf_list.len();
    assert(n >= 1, 'transfer: need >= 1 input');
    assert(n <= MAX_INPUTS, 'transfer: too many inputs');
    assert(nk_spend_list.len() == n, 'transfer: nk_spend len');
    assert(auth_root_list.len() == n, 'transfer: auth_root len');
    assert(auth_pub_seed_list.len() == n, 'transfer: auth_pub_seed len');
    assert(auth_index_list.len() == n, 'transfer: auth_idx len');
    assert(d_j_in_list.len() == n, 'transfer: d_j len');
    assert(v_in_list.len() == n, 'transfer: v len');
    assert(rseed_in_list.len() == n, 'transfer: rseed len');
    assert(cm_path_indices_list.len() == n, 'transfer: path len');
    assert(cm_siblings_flat.len() == n * merkle::TREE_DEPTH, 'transfer: cm_sibs len');
    assert(auth_siblings_flat.len() == n * merkle::AUTH_DEPTH, 'transfer: auth_sibs len');
    assert(wots_sig_flat.len() == n * xmss_common::WOTS_CHAINS, 'transfer: wots sig len');

    let mut sighash = hash::sighash_fold(0x01, auth_domain);
    sighash = hash::sighash_fold(sighash, root);
    let mut si: u32 = 0;
    while si < n {
        sighash = hash::sighash_fold(sighash, *nf_list.at(si));
        si += 1;
    };
    sighash = hash::sighash_fold(sighash, cm_1);
    sighash = hash::sighash_fold(sighash, cm_2);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_1);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_2);

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
        merkle::verify(
            cm,
            root,
            cm_siblings_flat.slice(cm_sib_start, merkle::TREE_DEPTH),
            cm_path_idx,
        );

        let wots_start = i * xmss_common::WOTS_CHAINS;
        let recovered_pk = xmss_common::xmss_recover_pk(
            sighash,
            auth_pub_seed,
            auth_idx,
            wots_sig_flat.slice(wots_start, xmss_common::WOTS_CHAINS),
        );
        let leaf = xmss_common::xmss_ltree(auth_pub_seed, auth_idx, recovered_pk.span());
        let auth_sib_start = i * merkle::AUTH_DEPTH;
        xmss_common::xmss_verify_auth(
            leaf,
            auth_root,
            auth_pub_seed,
            auth_idx,
            auth_siblings_flat.slice(auth_sib_start, merkle::AUTH_DEPTH),
        );

        let nf = hash::nullifier(nk_spend, cm, cm_path_idx);
        assert(nf == *nf_list.at(i), 'transfer: bad nf');
        sum_in += v.into();
        i += 1;
    };

    let mut a: u32 = 0;
    while a < n {
        let mut b: u32 = a + 1;
        while b < n {
            assert(*nf_list.at(a) != *nf_list.at(b), 'transfer: dup nf');
            b += 1;
        };
        a += 1;
    };

    let rcm_1 = hash::derive_rcm(rseed_1);
    let otag_1 = hash::owner_tag(auth_root_1, auth_pub_seed_1, nk_tag_1);
    assert(hash::commit(d_j_1, v_1, rcm_1, otag_1) == cm_1, 'transfer: bad cm_1');

    let rcm_2 = hash::derive_rcm(rseed_2);
    let otag_2 = hash::owner_tag(auth_root_2, auth_pub_seed_2, nk_tag_2);
    assert(hash::commit(d_j_2, v_2, rcm_2, otag_2) == cm_2, 'transfer: bad cm_2');

    let sum_out: u128 = v_1.into() + v_2.into();
    assert(sum_in == sum_out, 'transfer: balance mismatch');

    let mut outputs: Array<felt252> = array![auth_domain, root];
    let mut j: u32 = 0;
    while j < n { outputs.append(*nf_list.at(j)); j += 1; };
    outputs.append(cm_1);
    outputs.append(cm_2);
    outputs.append(memo_ct_hash_1);
    outputs.append(memo_ct_hash_2);
    outputs
}
