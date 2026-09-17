/// Parameterized transfer executable — takes all witness data as input.
///
/// Argument layout (flattened felt252 array):
///   [0]  N
///   [1]  auth_domain
///   [2]  root
///   [3]  fee
///   Then per input (N times):
///     nf, nk_spend, auth_root, auth_pub_seed, auth_index,
///     d_j, v, rseed, cm_path_idx
///   Then per input (N times): TREE_DEPTH cm siblings
///   Then per input (N times): AUTH_DEPTH auth siblings
///   Then per input (N times): WOTS_CHAINS sig values
///   Then per input (N times): asset_i (multiasset Phase B)
///   Then output 1 (recipient): cm_1, d_j_1, v_1, rseed_1, auth_root_1,
///        auth_pub_seed_1, nk_tag_1, memo_ct_hash_1, asset_1
///   Then output 2 (change_1): cm_2, d_j_2, v_2, rseed_2, auth_root_2,
///        auth_pub_seed_2, nk_tag_2, memo_ct_hash_2, asset_2
///   Then output 3 (change_2): cm_3, d_j_3, v_3, rseed_3, auth_root_3,
///        auth_pub_seed_3, nk_tag_3, memo_ct_hash_3, asset_3
///   Then output 4 (producer fee): cm_4, d_j_4, v_4, rseed_4, auth_root_4,
///        auth_pub_seed_4, nk_tag_4, memo_ct_hash_4, asset_4
///   Then: primary_non_tez_asset (multiasset Phase B 2-accumulator witness)

use tzel::merkle;
use tzel::{transfer, xmss_common};

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    let mut pos: u32 = 0;

    let n: u32 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let auth_domain = *args.at(pos);
    pos += 1;
    let root = *args.at(pos);
    pos += 1;
    let fee: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;

    let mut nf_list: Array<felt252> = array![];
    let mut nk_spend_list: Array<felt252> = array![];
    let mut auth_root_list: Array<felt252> = array![];
    let mut auth_pub_seed_list: Array<felt252> = array![];
    let mut auth_idx_list: Array<u32> = array![];
    let mut d_j_list: Array<felt252> = array![];
    let mut v_list: Array<u64> = array![];
    let mut rseed_list: Array<felt252> = array![];
    let mut path_idx_list: Array<u64> = array![];

    let mut i: u32 = 0;
    while i < n {
        nf_list.append(*args.at(pos));
        pos += 1;
        nk_spend_list.append(*args.at(pos));
        pos += 1;
        auth_root_list.append(*args.at(pos));
        pos += 1;
        auth_pub_seed_list.append(*args.at(pos));
        pos += 1;
        auth_idx_list.append((*args.at(pos)).try_into().unwrap());
        pos += 1;
        d_j_list.append(*args.at(pos));
        pos += 1;
        v_list.append((*args.at(pos)).try_into().unwrap());
        pos += 1;
        rseed_list.append(*args.at(pos));
        pos += 1;
        path_idx_list.append((*args.at(pos)).try_into().unwrap());
        pos += 1;
        i += 1;
    }

    let mut cm_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * merkle::TREE_DEPTH {
        cm_sibs.append(*args.at(pos));
        pos += 1;
        i += 1;
    }

    let mut auth_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * merkle::AUTH_DEPTH {
        auth_sibs.append(*args.at(pos));
        pos += 1;
        i += 1;
    }

    let mut wots_sig: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * xmss_common::WOTS_CHAINS {
        wots_sig.append(*args.at(pos));
        pos += 1;
        i += 1;
    }

    // Multiasset Phase B: per-input asset tags.
    let mut input_asset_list: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n {
        input_asset_list.append(*args.at(pos));
        pos += 1;
        i += 1;
    }

    let cm_1 = *args.at(pos);
    pos += 1;
    let d_j_1 = *args.at(pos);
    pos += 1;
    let v_1: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let rseed_1 = *args.at(pos);
    pos += 1;
    let auth_root_1 = *args.at(pos);
    pos += 1;
    let auth_pub_seed_1 = *args.at(pos);
    pos += 1;
    let nk_tag_1 = *args.at(pos);
    pos += 1;
    let mh_1 = *args.at(pos);
    pos += 1;
    let asset_1 = *args.at(pos);
    pos += 1;

    let cm_2 = *args.at(pos);
    pos += 1;
    let d_j_2 = *args.at(pos);
    pos += 1;
    let v_2: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let rseed_2 = *args.at(pos);
    pos += 1;
    let auth_root_2 = *args.at(pos);
    pos += 1;
    let auth_pub_seed_2 = *args.at(pos);
    pos += 1;
    let nk_tag_2 = *args.at(pos);
    pos += 1;
    let mh_2 = *args.at(pos);
    pos += 1;
    let asset_2 = *args.at(pos);
    pos += 1;

    let cm_3 = *args.at(pos);
    pos += 1;
    let d_j_3 = *args.at(pos);
    pos += 1;
    let v_3: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let rseed_3 = *args.at(pos);
    pos += 1;
    let auth_root_3 = *args.at(pos);
    pos += 1;
    let auth_pub_seed_3 = *args.at(pos);
    pos += 1;
    let nk_tag_3 = *args.at(pos);
    pos += 1;
    let mh_3 = *args.at(pos);
    pos += 1;
    let asset_3 = *args.at(pos);
    pos += 1;

    let cm_4 = *args.at(pos);
    pos += 1;
    let d_j_4 = *args.at(pos);
    pos += 1;
    let v_4: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let rseed_4 = *args.at(pos);
    pos += 1;
    let auth_root_4 = *args.at(pos);
    pos += 1;
    let auth_pub_seed_4 = *args.at(pos);
    pos += 1;
    let nk_tag_4 = *args.at(pos);
    pos += 1;
    let mh_4 = *args.at(pos);
    pos += 1;
    let asset_4 = *args.at(pos);
    pos += 1;

    let primary_non_tez_asset = *args.at(pos);
    pos += 1;

    assert(pos == args.len(), 'unexpected trailing args');

    transfer::verify(
        auth_domain,
        root,
        nf_list.span(),
        fee,
        cm_1,
        cm_2,
        cm_3,
        cm_4,
        nk_spend_list.span(),
        auth_root_list.span(),
        auth_pub_seed_list.span(),
        auth_idx_list.span(),
        d_j_list.span(),
        v_list.span(),
        rseed_list.span(),
        cm_sibs.span(),
        auth_sibs.span(),
        path_idx_list.span(),
        wots_sig.span(),
        input_asset_list.span(),
        d_j_1,
        v_1,
        rseed_1,
        auth_root_1,
        auth_pub_seed_1,
        nk_tag_1,
        mh_1,
        asset_1,
        d_j_2,
        v_2,
        rseed_2,
        auth_root_2,
        auth_pub_seed_2,
        nk_tag_2,
        mh_2,
        asset_2,
        d_j_3,
        v_3,
        rseed_3,
        auth_root_3,
        auth_pub_seed_3,
        nk_tag_3,
        mh_3,
        asset_3,
        d_j_4,
        v_4,
        rseed_4,
        auth_root_4,
        auth_pub_seed_4,
        nk_tag_4,
        mh_4,
        asset_4,
        primary_non_tez_asset,
    )
}
