/// Parameterized unshield executable — takes all witness data as input.
///
/// Public outputs (`2 + N + 10` felts, in order):
///   [auth_domain, root, nf_0..nf_{N-1}, v_pub, asset_pub, fee,
///    recipient_id, cm_change, memo_ct_hash_change,
///    cm_change_2, memo_ct_hash_change_2, cm_fee, memo_ct_hash_fee]
///
/// Argument layout (flattened felt252 array):
///   [0]  N
///   [1]  auth_domain
///   [2]  root
///   [3]  v_pub
///   [4]  fee
///   [5]  recipient
///   Then per input (N times):
///     nf, nk_spend, auth_root, auth_pub_seed, auth_index,
///     d_j, v, rseed, cm_path_idx
///   Then per input (N times): TREE_DEPTH cm siblings
///   Then per input (N times): AUTH_DEPTH auth siblings
///   Then per input (N times): WOTS_CHAINS sig values
///   Then per input (N times): asset_i (multiasset Phase B)
///   Then change_1 slot: has_change, d_j, v, rseed, auth_root,
///        auth_pub_seed, nk_tag, memo_ct_hash, asset_change
///   Then change_2 slot (Phase C, the second per-asset change note):
///        has_change_2, d_j_change_2, v_change_2, rseed_change_2,
///        auth_root_change_2, auth_pub_seed_change_2, nk_tag_change_2,
///        memo_ct_hash_change_2, asset_change_2
///   Then producer fee note: d_j, v, rseed, auth_root, auth_pub_seed,
///        nk_tag, memo_ct_hash, asset_fee
///   Then: asset_pub, primary_non_tez_asset (multiasset Phase B)

use tzel::merkle;
use tzel::{unshield, xmss_common};

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    let mut pos: u32 = 0;

    let n: u32 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let auth_domain = *args.at(pos);
    pos += 1;
    let root = *args.at(pos);
    pos += 1;
    let v_pub: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let fee: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let recipient = *args.at(pos);
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

    let has_change_felt: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    assert(has_change_felt <= 1, 'has_change must be 0 or 1');
    let has_change = has_change_felt != 0;
    let d_j_change = *args.at(pos);
    pos += 1;
    let v_change: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let rseed_change = *args.at(pos);
    pos += 1;
    let auth_root_change = *args.at(pos);
    pos += 1;
    let auth_pub_seed_change = *args.at(pos);
    pos += 1;
    let nk_tag_change = *args.at(pos);
    pos += 1;
    let mh_change = *args.at(pos);
    pos += 1;
    let asset_change = *args.at(pos);
    pos += 1;

    // Phase C: change_2 slot (8 felts + 1 asset = 9 fields).
    let has_change_2_felt: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    assert(has_change_2_felt <= 1, 'has_change_2 must be 0 or 1');
    let has_change_2 = has_change_2_felt != 0;
    let d_j_change_2 = *args.at(pos);
    pos += 1;
    let v_change_2: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let rseed_change_2 = *args.at(pos);
    pos += 1;
    let auth_root_change_2 = *args.at(pos);
    pos += 1;
    let auth_pub_seed_change_2 = *args.at(pos);
    pos += 1;
    let nk_tag_change_2 = *args.at(pos);
    pos += 1;
    let mh_change_2 = *args.at(pos);
    pos += 1;
    let asset_change_2 = *args.at(pos);
    pos += 1;

    let d_j_fee = *args.at(pos);
    pos += 1;
    let v_fee: u64 = (*args.at(pos)).try_into().unwrap();
    pos += 1;
    let rseed_fee = *args.at(pos);
    pos += 1;
    let auth_root_fee = *args.at(pos);
    pos += 1;
    let auth_pub_seed_fee = *args.at(pos);
    pos += 1;
    let nk_tag_fee = *args.at(pos);
    pos += 1;
    let mh_fee = *args.at(pos);
    pos += 1;
    let asset_fee = *args.at(pos);
    pos += 1;

    let asset_pub = *args.at(pos);
    pos += 1;
    let primary_non_tez_asset = *args.at(pos);
    pos += 1;

    assert(pos == args.len(), 'unexpected trailing args');

    unshield::verify(
        auth_domain,
        root,
        nf_list.span(),
        v_pub,
        fee,
        recipient,
        nk_spend_list.span(),
        auth_root_list.span(),
        auth_pub_seed_list.span(),
        wots_sig.span(),
        auth_sibs.span(),
        auth_idx_list.span(),
        d_j_list.span(),
        v_list.span(),
        rseed_list.span(),
        cm_sibs.span(),
        path_idx_list.span(),
        has_change,
        d_j_change,
        v_change,
        rseed_change,
        auth_root_change,
        auth_pub_seed_change,
        nk_tag_change,
        mh_change,
        has_change_2,
        d_j_change_2,
        v_change_2,
        rseed_change_2,
        auth_root_change_2,
        auth_pub_seed_change_2,
        nk_tag_change_2,
        mh_change_2,
        d_j_fee,
        v_fee,
        rseed_fee,
        auth_root_fee,
        auth_pub_seed_fee,
        nk_tag_fee,
        mh_fee,
        input_asset_list.span(),
        asset_change,
        asset_change_2,
        asset_fee,
        asset_pub,
        primary_non_tez_asset,
    )
}
