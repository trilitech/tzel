/// Parameterized unshield executable — takes all witness data as input.
///
/// Argument layout (flattened felt252 array):
///   [0]  N
///   [1]  auth_domain
///   [2]  root
///   [3]  v_pub
///   [4]  recipient
///   Then per input (N times):
///     nf, nk_spend, auth_root, auth_index,
///     d_j, v, rseed, cm_path_idx
///   Then per input (N times): TREE_DEPTH cm siblings
///   Then per input (N times): AUTH_DEPTH auth siblings
///   Then per input (N times): WOTS_CHAINS sig values
///   Then per input (N times): WOTS_CHAINS pk values
///   Then change: has_change, d_j, v, rseed, auth_root, nk_tag, memo_ct_hash

use starkprivacy::unshield;
use starkprivacy::merkle;

const WOTS_CHAINS: u32 = 133;

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    let mut pos: u32 = 0;

    let n: u32 = (*args.at(pos)).try_into().unwrap(); pos += 1;
    let auth_domain = *args.at(pos); pos += 1;
    let root = *args.at(pos); pos += 1;
    let v_pub: u64 = (*args.at(pos)).try_into().unwrap(); pos += 1;
    let recipient = *args.at(pos); pos += 1;

    let mut nf_list: Array<felt252> = array![];
    let mut nk_spend_list: Array<felt252> = array![];
    let mut auth_root_list: Array<felt252> = array![];
    let mut auth_idx_list: Array<u64> = array![];
    let mut d_j_list: Array<felt252> = array![];
    let mut v_list: Array<u64> = array![];
    let mut rseed_list: Array<felt252> = array![];
    let mut path_idx_list: Array<u64> = array![];

    let mut i: u32 = 0;
    while i < n {
        nf_list.append(*args.at(pos)); pos += 1;
        nk_spend_list.append(*args.at(pos)); pos += 1;
        auth_root_list.append(*args.at(pos)); pos += 1;
        auth_idx_list.append((*args.at(pos)).try_into().unwrap()); pos += 1;
        d_j_list.append(*args.at(pos)); pos += 1;
        v_list.append((*args.at(pos)).try_into().unwrap()); pos += 1;
        rseed_list.append(*args.at(pos)); pos += 1;
        path_idx_list.append((*args.at(pos)).try_into().unwrap()); pos += 1;
        i += 1;
    };

    let mut cm_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * merkle::TREE_DEPTH { cm_sibs.append(*args.at(pos)); pos += 1; i += 1; };

    let mut auth_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * merkle::AUTH_DEPTH { auth_sibs.append(*args.at(pos)); pos += 1; i += 1; };

    let mut wots_sig: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * WOTS_CHAINS { wots_sig.append(*args.at(pos)); pos += 1; i += 1; };

    let mut wots_pk: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * WOTS_CHAINS { wots_pk.append(*args.at(pos)); pos += 1; i += 1; };

    // Change output
    let has_change_felt: u64 = (*args.at(pos)).try_into().unwrap(); pos += 1;
    assert(has_change_felt <= 1, 'has_change must be 0 or 1');
    let has_change = has_change_felt != 0;
    let d_j_change = *args.at(pos); pos += 1;
    let v_change: u64 = (*args.at(pos)).try_into().unwrap(); pos += 1;
    let rseed_change = *args.at(pos); pos += 1;
    let auth_root_change = *args.at(pos); pos += 1;
    let nk_tag_change = *args.at(pos); pos += 1;
    let mh_change = *args.at(pos); pos += 1;

    assert(pos == args.len(), 'unexpected trailing args');

    unshield::verify(
        auth_domain,
        root,
        nf_list.span(),
        v_pub,
        recipient,
        nk_spend_list.span(),
        auth_root_list.span(),
        wots_sig.span(),
        wots_pk.span(),
        auth_sibs.span(),
        auth_idx_list.span(),
        d_j_list.span(),
        v_list.span(),
        rseed_list.span(),
        cm_sibs.span(),
        path_idx_list.span(),
        has_change,
        d_j_change, v_change, rseed_change,
        auth_root_change, nk_tag_change, mh_change,
    )
}
