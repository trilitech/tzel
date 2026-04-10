/// Parameterized transfer executable — takes all witness data as input.
///
/// Argument layout (flattened felt252 array):
///   [0]  N
///   [1]  auth_domain
///   [2]  root
///   Then per input (N times):
///     nf, nk_spend, auth_root, auth_index,
///     d_j, v, rseed, cm_path_idx
///   Then per input (N times): TREE_DEPTH cm siblings
///   Then per input (N times): AUTH_DEPTH auth siblings
///   Then per input (N times): WOTS_CHAINS sig values
///   Then per input (N times): WOTS_CHAINS pk values
///   (digits are computed by the circuit from the sighash — not in args)
///   Then output 1: cm_1, d_j_1, v_1, rseed_1, auth_root_1, nk_tag_1, memo_ct_hash_1
///   Then output 2: cm_2, d_j_2, v_2, rseed_2, auth_root_2, nk_tag_2, memo_ct_hash_2

use tzel::transfer;
use tzel::merkle;

const WOTS_CHAINS: u32 = 133;

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    let mut pos: u32 = 0;

    let n: u32 = (*args.at(pos)).try_into().unwrap(); pos += 1;
    let auth_domain = *args.at(pos); pos += 1;
    let root = *args.at(pos); pos += 1;

    // Per-input scalar fields
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

    // Commitment tree siblings (N * TREE_DEPTH)
    let mut cm_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * merkle::TREE_DEPTH { cm_sibs.append(*args.at(pos)); pos += 1; i += 1; };

    // Auth tree siblings (N * AUTH_DEPTH)
    let mut auth_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * merkle::AUTH_DEPTH { auth_sibs.append(*args.at(pos)); pos += 1; i += 1; };

    // WOTS+ signature chains (N * WOTS_CHAINS)
    let mut wots_sig: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * WOTS_CHAINS { wots_sig.append(*args.at(pos)); pos += 1; i += 1; };

    // WOTS+ public key chains (N * WOTS_CHAINS)
    let mut wots_pk: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < n * WOTS_CHAINS { wots_pk.append(*args.at(pos)); pos += 1; i += 1; };

    // Output 1
    let cm_1 = *args.at(pos); pos += 1;
    let d_j_1 = *args.at(pos); pos += 1;
    let v_1: u64 = (*args.at(pos)).try_into().unwrap(); pos += 1;
    let rseed_1 = *args.at(pos); pos += 1;
    let auth_root_1 = *args.at(pos); pos += 1;
    let nk_tag_1 = *args.at(pos); pos += 1;
    let mh_1 = *args.at(pos); pos += 1;

    // Output 2
    let cm_2 = *args.at(pos); pos += 1;
    let d_j_2 = *args.at(pos); pos += 1;
    let v_2: u64 = (*args.at(pos)).try_into().unwrap(); pos += 1;
    let rseed_2 = *args.at(pos); pos += 1;
    let auth_root_2 = *args.at(pos); pos += 1;
    let nk_tag_2 = *args.at(pos); pos += 1;
    let mh_2 = *args.at(pos); pos += 1;

    assert(pos == args.len(), 'unexpected trailing args');

    transfer::verify(
        auth_domain,
        root,
        nf_list.span(),
        cm_1, cm_2,
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
        d_j_1, v_1, rseed_1, auth_root_1, nk_tag_1, mh_1,
        d_j_2, v_2, rseed_2, auth_root_2, nk_tag_2, mh_2,
    )
}
