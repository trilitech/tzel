/// N=1 transfer + Lamport signature verification inside the STARK.
/// 256 revealed values, each hashed once and checked against pk.

use wots_circuit_bench::hash;

const BITS: u32 = 256;

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

    // Lamport: revealed values (256), pk_0 halves (256), pk_1 halves (256), msg_hash bits
    let mut revealed: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < BITS { revealed.append(*args.at(p)); p += 1; i += 1; };

    let mut pk0: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < BITS { pk0.append(*args.at(p)); p += 1; i += 1; };

    let mut pk1: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < BITS { pk1.append(*args.at(p)); p += 1; i += 1; };

    // Message hash (the sighash, 256 bits as felt252)
    let msg_hash = *args.at(p); p += 1;

    let cm_1 = *args.at(p); p += 1;
    let d_j_1 = *args.at(p); p += 1;
    let v_1: u64 = (*args.at(p)).try_into().unwrap(); p += 1;
    let rseed_1 = *args.at(p); p += 1;
    let auth_root_1 = *args.at(p); p += 1;
    let nk_tag_1 = *args.at(p); p += 1;
    let cm_2 = *args.at(p); p += 1;
    let d_j_2 = *args.at(p); p += 1;
    let v_2: u64 = (*args.at(p)).try_into().unwrap(); p += 1;
    let rseed_2 = *args.at(p); p += 1;
    let auth_root_2 = *args.at(p); p += 1;
    let nk_tag_2 = *args.at(p); p += 1;

    assert(p == args.len(), 'trailing args');

    let nk_tag = hash::derive_nk_tag(nk_spend);
    let otag = hash::owner_tag(auth_root, nk_tag);
    let rcm = hash::derive_rcm(rseed);
    let cm = hash::commit(d_j, v, rcm, otag);
    hash::verify_merkle(cm, root, cm_sibs.span(), cm_path_idx);

    // Lamport verification: hash each revealed value, compare against correct pk half
    let (b0, b1, b2, b3, b4, b5, b6, b7) = hash::felt_to_u32x8(msg_hash);
    let msg_words: [u32; 8] = [b0, b1, b2, b3, b4, b5, b6, b7];
    let mut i: u32 = 0;
    while i < BITS {
        let h = hash::hash1(*revealed.at(i));
        let word_idx: u32 = i / 32;
        let bit_idx: u32 = i % 32;
        // Extract bit from msg_hash
        let word = *msg_words.span().at(word_idx);
        let bit: u32 = (word / pow2(bit_idx)) % 2;
        let expected = if bit == 0 { *pk0.at(i) } else { *pk1.at(i) };
        assert(h == expected, 'lamport bit');
        i += 1;
    };

    // PK → leaf: hash all 512 pk values together
    let mut leaf = *pk0.at(0);
    let mut i: u32 = 0;
    while i < BITS {
        leaf = hash::hash2(leaf, *pk0.at(i));
        leaf = hash::hash2(leaf, *pk1.at(i));
        i += 1;
    };

    hash::verify_auth(leaf, auth_root, auth_sibs.span(), auth_idx);

    let nf = hash::nullifier(nk_spend, cm, cm_path_idx);
    assert(nf == nf_expected, 'bad nf');

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

fn pow2(n: u32) -> u32 {
    let mut r: u32 = 1;
    let mut i: u32 = 0;
    while i < n { r = r * 2; i += 1; };
    r
}
