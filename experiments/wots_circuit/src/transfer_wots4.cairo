/// N=1 transfer + WOTS+ w=4 signature verification inside the STARK.
/// Same as baseline but adds: 133 chain verifications + pk→leaf hash.
/// Extra args after auth_siblings: sig_chains(133), pk_chains(133), digits(133)

use wots_circuit_bench::hash;

const W: u32 = 4;
const CHAINS: u32 = 133;

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    let mut p: u32 = 0;
    let root = *args.at(p); p += 1;
    let nf_expected = *args.at(p); p += 1;
    let nk_spend = *args.at(p); p += 1;
    let auth_root = *args.at(p); p += 1;
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

    // WOTS+ signature data
    let mut sig: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < CHAINS { sig.append(*args.at(p)); p += 1; i += 1; };

    let mut pk: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < CHAINS { pk.append(*args.at(p)); p += 1; i += 1; };

    let mut digits: Array<u32> = array![];
    let mut i: u32 = 0;
    while i < CHAINS { digits.append((*args.at(p)).try_into().unwrap()); p += 1; i += 1; };

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

    // ── WOTS+ w=4 verification ──────────────────────────────────────
    let mut i: u32 = 0;
    while i < CHAINS {
        let d = *digits.at(i);
        let remaining = W - 1 - d;
        let mut current = *sig.at(i);
        let mut j: u32 = 0;
        while j < remaining { current = hash::hash1(current); j += 1; };
        assert(current == *pk.at(i), 'wots chain');
        i += 1;
    };

    // PK → leaf: fold all pk values
    let mut leaf = *pk.at(0);
    let mut i: u32 = 1;
    while i < CHAINS { leaf = hash::hash2(leaf, *pk.at(i)); i += 1; };

    // Auth tree verification
    hash::verify_auth(leaf, auth_root, auth_sibs.span(), auth_idx);

    let nf = hash::nullifier(nk_spend, cm, cm_path_idx);
    assert(nf == nf_expected, 'bad nf');

    // ── Outputs ─────────────────────────────────────────────────────
    let rcm_1 = hash::derive_rcm(rseed_1);
    let otag_1 = hash::owner_tag(auth_root_1, nk_tag_1);
    assert(hash::commit(d_j_1, v_1, rcm_1, otag_1) == cm_1, 'bad cm_1');

    let rcm_2 = hash::derive_rcm(rseed_2);
    let otag_2 = hash::owner_tag(auth_root_2, nk_tag_2);
    assert(hash::commit(d_j_2, v_2, rcm_2, otag_2) == cm_2, 'bad cm_2');

    let si: u128 = v.into(); let so: u128 = v_1.into() + v_2.into();
    assert(si == so, 'balance');

    array![root, nf, cm_1, cm_2, leaf]
}
