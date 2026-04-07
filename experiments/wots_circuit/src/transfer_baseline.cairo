/// Baseline N=1 transfer: no WOTS+ signature verification.
/// Same logic as the production run_transfer with N=1.
/// Args: [root, nf, nk_spend, auth_root, auth_leaf, auth_idx, d_j, v, rseed, cm_path_idx,
///        cm_siblings(TREE_DEPTH), auth_siblings(AUTH_DEPTH),
///        cm_1, d_j_1, v_1, rseed_1, auth_root_1, nk_tag_1,
///        cm_2, d_j_2, v_2, rseed_2, auth_root_2, nk_tag_2]

use wots_circuit_bench::hash;

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    let mut p: u32 = 0;
    let root = *args.at(p); p += 1;
    let nf_expected = *args.at(p); p += 1;
    let nk_spend = *args.at(p); p += 1;
    let auth_root = *args.at(p); p += 1;
    let auth_leaf = *args.at(p); p += 1;
    let auth_idx: u64 = (*args.at(p)).try_into().unwrap(); p += 1;
    let d_j = *args.at(p); p += 1;
    let v: u64 = (*args.at(p)).try_into().unwrap(); p += 1;
    let rseed = *args.at(p); p += 1;
    let cm_path_idx: u64 = (*args.at(p)).try_into().unwrap(); p += 1;

    let mut cm_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < hash::TREE_DEPTH { cm_sibs.append(*args.at(p)); p += 1; i += 1; };

    let mut auth_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < hash::AUTH_DEPTH { auth_sibs.append(*args.at(p)); p += 1; i += 1; };

    // Output 1
    let cm_1 = *args.at(p); p += 1;
    let d_j_1 = *args.at(p); p += 1;
    let v_1: u64 = (*args.at(p)).try_into().unwrap(); p += 1;
    let rseed_1 = *args.at(p); p += 1;
    let auth_root_1 = *args.at(p); p += 1;
    let nk_tag_1 = *args.at(p); p += 1;

    // Output 2
    let cm_2 = *args.at(p); p += 1;
    let d_j_2 = *args.at(p); p += 1;
    let v_2: u64 = (*args.at(p)).try_into().unwrap(); p += 1;
    let rseed_2 = *args.at(p); p += 1;
    let auth_root_2 = *args.at(p); p += 1;
    let nk_tag_2 = *args.at(p); p += 1;

    assert(p == args.len(), 'trailing args');

    // ── Input verification ──────────────────────────────────────────
    let nk_tag = hash::derive_nk_tag(nk_spend);
    let otag = hash::owner_tag(auth_root, nk_tag);
    let rcm = hash::derive_rcm(rseed);
    let cm = hash::commit(d_j, v, rcm, otag);
    hash::verify_merkle(cm, root, cm_sibs.span(), cm_path_idx);
    hash::verify_auth(auth_leaf, auth_root, auth_sibs.span(), auth_idx);
    let nf = hash::nullifier(nk_spend, cm, cm_path_idx);
    assert(nf == nf_expected, 'bad nf');

    // ── Output verification ─────────────────────────────────────────
    let rcm_1 = hash::derive_rcm(rseed_1);
    let otag_1 = hash::owner_tag(auth_root_1, nk_tag_1);
    assert(hash::commit(d_j_1, v_1, rcm_1, otag_1) == cm_1, 'bad cm_1');

    let rcm_2 = hash::derive_rcm(rseed_2);
    let otag_2 = hash::owner_tag(auth_root_2, nk_tag_2);
    assert(hash::commit(d_j_2, v_2, rcm_2, otag_2) == cm_2, 'bad cm_2');

    // ── Balance ─────────────────────────────────────────────────────
    let sum_in: u128 = v.into();
    let sum_out: u128 = v_1.into() + v_2.into();
    assert(sum_in == sum_out, 'balance');

    array![root, nf, cm_1, cm_2, auth_leaf]
}
