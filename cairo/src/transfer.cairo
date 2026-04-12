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
use tzel::{merkle, xmss_common};

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
    d_j_1: felt252,
    v_1: u64,
    rseed_1: felt252,
    auth_root_1: felt252,
    auth_pub_seed_1: felt252,
    nk_tag_1: felt252,
    memo_ct_hash_1: felt252,
    d_j_2: felt252,
    v_2: u64,
    rseed_2: felt252,
    auth_root_2: felt252,
    auth_pub_seed_2: felt252,
    nk_tag_2: felt252,
    memo_ct_hash_2: felt252,
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
    }
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
            cm, root, cm_siblings_flat.slice(cm_sib_start, merkle::TREE_DEPTH), cm_path_idx,
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
    }

    let mut a: u32 = 0;
    while a < n {
        let mut b: u32 = a + 1;
        while b < n {
            assert(*nf_list.at(a) != *nf_list.at(b), 'transfer: dup nf');
            b += 1;
        }
        a += 1;
    }

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
    while j < n {
        outputs.append(*nf_list.at(j));
        j += 1;
    }
    outputs.append(cm_1);
    outputs.append(cm_2);
    outputs.append(memo_ct_hash_1);
    outputs.append(memo_ct_hash_2);
    outputs
}

#[cfg(test)]
mod tests {
    use tzel::{blake_hash as hash, merkle, xmss_common};
    use super::verify;

    const TAG_XMSS_TREE_TEST: felt252 = 0x72742D73736D78;

    #[derive(Drop)]
    struct TransferFixture {
        auth_domain: felt252,
        root: felt252,
        nf_list: Array<felt252>,
        nk_spend_list: Array<felt252>,
        auth_root_list: Array<felt252>,
        auth_pub_seed_list: Array<felt252>,
        auth_index_list: Array<u64>,
        d_j_in_list: Array<felt252>,
        v_in_list: Array<u64>,
        rseed_in_list: Array<felt252>,
        cm_siblings_flat: Array<felt252>,
        auth_siblings_flat: Array<felt252>,
        cm_path_indices_list: Array<u64>,
        wots_sig_flat: Array<felt252>,
        cm_1: felt252,
        d_j_1: felt252,
        v_1: u64,
        rseed_1: felt252,
        auth_root_1: felt252,
        auth_pub_seed_1: felt252,
        nk_tag_1: felt252,
        memo_ct_hash_1: felt252,
        cm_2: felt252,
        d_j_2: felt252,
        v_2: u64,
        rseed_2: felt252,
        auth_root_2: felt252,
        auth_pub_seed_2: felt252,
        nk_tag_2: felt252,
        memo_ct_hash_2: felt252,
    }

    fn copy_and_mutate(values: Span<felt252>, target: u32) -> Array<felt252> {
        let mut mutated: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < values.len() {
            mutated.append(if i == target {
                *values.at(i) + 1
            } else {
                *values.at(i)
            });
            i += 1;
        }
        mutated
    }

    fn merkle_root_from_path(leaf: felt252, siblings: Span<felt252>, mut path_idx: u64) -> felt252 {
        let mut current = leaf;
        let mut level: u32 = 0;
        while level < merkle::TREE_DEPTH {
            let sibling = *siblings.at(level);
            current =
                if path_idx & 1 == 1 {
                    hash::hash2(sibling, current)
                } else {
                    hash::hash2(current, sibling)
                };
            path_idx /= 2;
            level += 1;
        }
        current
    }

    fn auth_root_from_leaf(
        leaf: felt252, pub_seed: felt252, mut key_idx: u32, siblings: Span<felt252>,
    ) -> felt252 {
        let mut current = leaf;
        let mut level: u32 = 0;
        while level < merkle::AUTH_DEPTH {
            let sibling = *siblings.at(level);
            let node_idx = key_idx / 2;
            current =
                if key_idx & 1 == 1 {
                    xmss_common::xmss_node_hash(
                        pub_seed, TAG_XMSS_TREE_TEST, 0, level, node_idx, sibling, current,
                    )
                } else {
                    xmss_common::xmss_node_hash(
                        pub_seed, TAG_XMSS_TREE_TEST, 0, level, node_idx, current, sibling,
                    )
                };
            key_idx /= 2;
            level += 1;
        }
        current
    }

    fn chain_advance(
        mut current: felt252, pub_seed: felt252, key_idx: u32, chain_idx: u32, steps: u32,
    ) -> felt252 {
        let mut step: u32 = 0;
        while step < steps {
            current = xmss_common::xmss_chain_step(current, pub_seed, key_idx, chain_idx, step);
            step += 1;
        }
        current
    }

    fn output_commitment(
        d_j: felt252,
        v: u64,
        rseed: felt252,
        auth_root: felt252,
        auth_pub_seed: felt252,
        nk_tag: felt252,
    ) -> felt252 {
        let rcm = hash::derive_rcm(rseed);
        let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
        hash::commit(d_j, v, rcm, otag)
    }

    fn transfer_sighash(
        auth_domain: felt252,
        root: felt252,
        nf_list: Span<felt252>,
        cm_1: felt252,
        cm_2: felt252,
        memo_ct_hash_1: felt252,
        memo_ct_hash_2: felt252,
    ) -> felt252 {
        let mut sighash = hash::sighash_fold(0x01, auth_domain);
        sighash = hash::sighash_fold(sighash, root);
        let mut i: u32 = 0;
        while i < nf_list.len() {
            sighash = hash::sighash_fold(sighash, *nf_list.at(i));
            i += 1;
        }
        sighash = hash::sighash_fold(sighash, cm_1);
        sighash = hash::sighash_fold(sighash, cm_2);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_1);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_2);
        sighash
    }

    fn sign_transfer_input(
        sighash: felt252, auth_pub_seed: felt252, auth_idx: u32, key_material_base: felt252,
    ) -> Array<felt252> {
        let digits = hash::sighash_to_wots_digits(sighash);
        let mut wots_sig_flat: Array<felt252> = array![];
        let mut j: u32 = 0;
        while j < xmss_common::WOTS_CHAINS {
            let start = hash::hash1(j.into() + key_material_base);
            wots_sig_flat.append(chain_advance(start, auth_pub_seed, auth_idx, j, *digits.at(j)));
            j += 1;
        }
        wots_sig_flat
    }

    fn sign_transfer_statement(
        auth_domain: felt252,
        root: felt252,
        nf: felt252,
        cm_1: felt252,
        cm_2: felt252,
        memo_ct_hash_1: felt252,
        memo_ct_hash_2: felt252,
        auth_pub_seed: felt252,
        auth_idx: u32,
    ) -> Array<felt252> {
        let sighash = transfer_sighash(
            auth_domain,
            root,
            array![nf].span(),
            cm_1,
            cm_2,
            memo_ct_hash_1,
            memo_ct_hash_2,
        );
        sign_transfer_input(sighash, auth_pub_seed, auth_idx, 0x7500)
    }

    fn build_fixture_with_values(v_in: u64, v_1: u64, v_2: u64) -> TransferFixture {
        let auth_domain = 0x7001;
        let nk_spend = 0x7101;
        let auth_pub_seed = 0x7201;
        let auth_idx = 5_u32;
        let d_j_in = 0x7301;
        let rseed_in = 0x7401;
        let cm_path_idx = 9_u64;

        let mut wots_endpoints: Array<felt252> = array![];
        let mut chain_idx: u32 = 0;
        while chain_idx < xmss_common::WOTS_CHAINS {
            let start = hash::hash1(chain_idx.into() + 0x7500);
            wots_endpoints
                .append(
                    chain_advance(
                        start, auth_pub_seed, auth_idx, chain_idx, xmss_common::WOTS_W - 1,
                    ),
                );
            chain_idx += 1;
        }

        let mut auth_siblings_flat: Array<felt252> = array![];
        let mut level: u32 = 0;
        while level < merkle::AUTH_DEPTH {
            auth_siblings_flat.append(hash::hash1(level.into() + 0x7600));
            level += 1;
        }
        let leaf = xmss_common::xmss_ltree(auth_pub_seed, auth_idx, wots_endpoints.span());
        let auth_root = auth_root_from_leaf(
            leaf, auth_pub_seed, auth_idx, auth_siblings_flat.span(),
        );

        let nk_tag_in = hash::derive_nk_tag(nk_spend);
        let cm_in = output_commitment(d_j_in, v_in, rseed_in, auth_root, auth_pub_seed, nk_tag_in);

        let mut cm_siblings_flat: Array<felt252> = array![];
        let mut tree_level: u32 = 0;
        while tree_level < merkle::TREE_DEPTH {
            cm_siblings_flat.append(hash::hash1(tree_level.into() + 0x7700));
            tree_level += 1;
        }
        let root = merkle_root_from_path(cm_in, cm_siblings_flat.span(), cm_path_idx);
        let nf = hash::nullifier(nk_spend, cm_in, cm_path_idx);

        let d_j_1 = 0x7801;
        let rseed_1 = 0x7802;
        let auth_root_1 = 0x7803;
        let auth_pub_seed_1 = 0x7804;
        let nk_tag_1 = 0x7805;
        let memo_ct_hash_1 = 0x7806;
        let cm_1 = output_commitment(d_j_1, v_1, rseed_1, auth_root_1, auth_pub_seed_1, nk_tag_1);

        let d_j_2 = 0x7901;
        let rseed_2 = 0x7902;
        let auth_root_2 = 0x7903;
        let auth_pub_seed_2 = 0x7904;
        let nk_tag_2 = 0x7905;
        let memo_ct_hash_2 = 0x7906;
        let cm_2 = output_commitment(d_j_2, v_2, rseed_2, auth_root_2, auth_pub_seed_2, nk_tag_2);

        let wots_sig_flat = sign_transfer_statement(
            auth_domain,
            root,
            nf,
            cm_1,
            cm_2,
            memo_ct_hash_1,
            memo_ct_hash_2,
            auth_pub_seed,
            auth_idx,
        );

        TransferFixture {
            auth_domain,
            root,
            nf_list: array![nf],
            nk_spend_list: array![nk_spend],
            auth_root_list: array![auth_root],
            auth_pub_seed_list: array![auth_pub_seed],
            auth_index_list: array![auth_idx.into()],
            d_j_in_list: array![d_j_in],
            v_in_list: array![v_in],
            rseed_in_list: array![rseed_in],
            cm_siblings_flat,
            auth_siblings_flat,
            cm_path_indices_list: array![cm_path_idx],
            wots_sig_flat,
            cm_1,
            d_j_1,
            v_1,
            rseed_1,
            auth_root_1,
            auth_pub_seed_1,
            nk_tag_1,
            memo_ct_hash_1,
            cm_2,
            d_j_2,
            v_2,
            rseed_2,
            auth_root_2,
            auth_pub_seed_2,
            nk_tag_2,
            memo_ct_hash_2,
        }
    }

    fn build_fixture() -> TransferFixture {
        build_fixture_with_values(70_u64, 45_u64, 25_u64)
    }

    fn build_two_input_fixture() -> TransferFixture {
        let auth_domain = 0x8801;
        let auth_pub_seed = 0x8802;

        let auth_idx_0 = 0_u32;
        let auth_idx_1 = 1_u32;
        let key_base_0 = 0x8900;
        let key_base_1 = 0x8A00;

        let mut endpoints_0: Array<felt252> = array![];
        let mut endpoints_1: Array<felt252> = array![];
        let mut chain_idx: u32 = 0;
        while chain_idx < xmss_common::WOTS_CHAINS {
            let start_0 = hash::hash1(chain_idx.into() + key_base_0);
            let start_1 = hash::hash1(chain_idx.into() + key_base_1);
            endpoints_0.append(
                chain_advance(start_0, auth_pub_seed, auth_idx_0, chain_idx, xmss_common::WOTS_W - 1),
            );
            endpoints_1.append(
                chain_advance(start_1, auth_pub_seed, auth_idx_1, chain_idx, xmss_common::WOTS_W - 1),
            );
            chain_idx += 1;
        }

        let leaf_0 = xmss_common::xmss_ltree(auth_pub_seed, auth_idx_0, endpoints_0.span());
        let leaf_1 = xmss_common::xmss_ltree(auth_pub_seed, auth_idx_1, endpoints_1.span());

        let mut upper_auth_siblings: Array<felt252> = array![];
        let mut auth_level: u32 = 1;
        while auth_level < merkle::AUTH_DEPTH {
            upper_auth_siblings.append(hash::hash1(auth_level.into() + 0x8B00));
            auth_level += 1;
        }
        let mut auth_siblings_0: Array<felt252> = array![leaf_1];
        let mut auth_siblings_1: Array<felt252> = array![leaf_0];
        let mut i: u32 = 0;
        while i < upper_auth_siblings.len() {
            auth_siblings_0.append(*upper_auth_siblings.at(i));
            auth_siblings_1.append(*upper_auth_siblings.at(i));
            i += 1;
        }
        let auth_root = auth_root_from_leaf(leaf_0, auth_pub_seed, auth_idx_0, auth_siblings_0.span());

        let nk_spend_0 = 0x8C01;
        let nk_spend_1 = 0x8C02;
        let d_j_in_0 = 0x8C03;
        let d_j_in_1 = 0x8C04;
        let v_in_0 = 40_u64;
        let v_in_1 = 30_u64;
        let rseed_in_0 = 0x8C05;
        let rseed_in_1 = 0x8C06;

        let cm_0 = output_commitment(
            d_j_in_0,
            v_in_0,
            rseed_in_0,
            auth_root,
            auth_pub_seed,
            hash::derive_nk_tag(nk_spend_0),
        );
        let cm_1_in = output_commitment(
            d_j_in_1,
            v_in_1,
            rseed_in_1,
            auth_root,
            auth_pub_seed,
            hash::derive_nk_tag(nk_spend_1),
        );

        let mut upper_cm_siblings: Array<felt252> = array![];
        let mut tree_level: u32 = 1;
        while tree_level < merkle::TREE_DEPTH {
            upper_cm_siblings.append(hash::hash1(tree_level.into() + 0x8D00));
            tree_level += 1;
        }
        let mut cm_siblings_0: Array<felt252> = array![cm_1_in];
        let mut cm_siblings_1: Array<felt252> = array![cm_0];
        let mut j: u32 = 0;
        while j < upper_cm_siblings.len() {
            cm_siblings_0.append(*upper_cm_siblings.at(j));
            cm_siblings_1.append(*upper_cm_siblings.at(j));
            j += 1;
        }

        let root = merkle_root_from_path(cm_0, cm_siblings_0.span(), 0);
        let nf_0 = hash::nullifier(nk_spend_0, cm_0, 0);
        let nf_1 = hash::nullifier(nk_spend_1, cm_1_in, 1);

        let d_j_1 = 0x8E01;
        let v_1 = 35_u64;
        let rseed_1 = 0x8E02;
        let auth_root_1 = 0x8E03;
        let auth_pub_seed_1 = 0x8E04;
        let nk_tag_1 = 0x8E05;
        let memo_ct_hash_1 = 0x8E06;
        let cm_1 = output_commitment(d_j_1, v_1, rseed_1, auth_root_1, auth_pub_seed_1, nk_tag_1);

        let d_j_2 = 0x8F01;
        let v_2 = 35_u64;
        let rseed_2 = 0x8F02;
        let auth_root_2 = 0x8F03;
        let auth_pub_seed_2 = 0x8F04;
        let nk_tag_2 = 0x8F05;
        let memo_ct_hash_2 = 0x8F06;
        let cm_2 = output_commitment(d_j_2, v_2, rseed_2, auth_root_2, auth_pub_seed_2, nk_tag_2);

        let nf_list: Array<felt252> = array![nf_0, nf_1];
        let sighash = transfer_sighash(
            auth_domain,
            root,
            nf_list.span(),
            cm_1,
            cm_2,
            memo_ct_hash_1,
            memo_ct_hash_2,
        );

        let sig_0 = sign_transfer_input(sighash, auth_pub_seed, auth_idx_0, key_base_0);
        let sig_1 = sign_transfer_input(sighash, auth_pub_seed, auth_idx_1, key_base_1);
        let mut wots_sig_flat: Array<felt252> = array![];
        let mut k: u32 = 0;
        while k < sig_0.len() {
            wots_sig_flat.append(*sig_0.at(k));
            k += 1;
        }
        let mut m: u32 = 0;
        while m < sig_1.len() {
            wots_sig_flat.append(*sig_1.at(m));
            m += 1;
        }

        let mut cm_siblings_flat: Array<felt252> = array![];
        let mut p: u32 = 0;
        while p < cm_siblings_0.len() {
            cm_siblings_flat.append(*cm_siblings_0.at(p));
            p += 1;
        }
        let mut q: u32 = 0;
        while q < cm_siblings_1.len() {
            cm_siblings_flat.append(*cm_siblings_1.at(q));
            q += 1;
        }

        let mut auth_siblings_flat: Array<felt252> = array![];
        let mut r: u32 = 0;
        while r < auth_siblings_0.len() {
            auth_siblings_flat.append(*auth_siblings_0.at(r));
            r += 1;
        }
        let mut s: u32 = 0;
        while s < auth_siblings_1.len() {
            auth_siblings_flat.append(*auth_siblings_1.at(s));
            s += 1;
        }

        TransferFixture {
            auth_domain,
            root,
            nf_list,
            nk_spend_list: array![nk_spend_0, nk_spend_1],
            auth_root_list: array![auth_root, auth_root],
            auth_pub_seed_list: array![auth_pub_seed, auth_pub_seed],
            auth_index_list: array![auth_idx_0.into(), auth_idx_1.into()],
            d_j_in_list: array![d_j_in_0, d_j_in_1],
            v_in_list: array![v_in_0, v_in_1],
            rseed_in_list: array![rseed_in_0, rseed_in_1],
            cm_siblings_flat,
            auth_siblings_flat,
            cm_path_indices_list: array![0_u64, 1_u64],
            wots_sig_flat,
            cm_1,
            d_j_1,
            v_1,
            rseed_1,
            auth_root_1,
            auth_pub_seed_1,
            nk_tag_1,
            memo_ct_hash_1,
            cm_2,
            d_j_2,
            v_2,
            rseed_2,
            auth_root_2,
            auth_pub_seed_2,
            nk_tag_2,
            memo_ct_hash_2,
        }
    }

    fn build_duplicate_nf_fixture() -> TransferFixture {
        let base = build_fixture_with_values(70_u64, 80_u64, 60_u64);
        let sighash = transfer_sighash(
            base.auth_domain,
            base.root,
            array![*base.nf_list.at(0), *base.nf_list.at(0)].span(),
            base.cm_1,
            base.cm_2,
            base.memo_ct_hash_1,
            base.memo_ct_hash_2,
        );
        let sig = sign_transfer_input(
            sighash,
            *base.auth_pub_seed_list.at(0),
            (*base.auth_index_list.at(0)).try_into().unwrap(),
            0x7500,
        );
        let mut wots_sig_flat: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < sig.len() {
            wots_sig_flat.append(*sig.at(i));
            i += 1;
        }
        let mut j: u32 = 0;
        while j < sig.len() {
            wots_sig_flat.append(*sig.at(j));
            j += 1;
        }

        let mut cm_siblings_flat: Array<felt252> = array![];
        let mut k: u32 = 0;
        while k < base.cm_siblings_flat.len() {
            cm_siblings_flat.append(*base.cm_siblings_flat.at(k));
            k += 1;
        }
        let mut m: u32 = 0;
        while m < base.cm_siblings_flat.len() {
            cm_siblings_flat.append(*base.cm_siblings_flat.at(m));
            m += 1;
        }

        let mut auth_siblings_flat: Array<felt252> = array![];
        let mut p: u32 = 0;
        while p < base.auth_siblings_flat.len() {
            auth_siblings_flat.append(*base.auth_siblings_flat.at(p));
            p += 1;
        }
        let mut q: u32 = 0;
        while q < base.auth_siblings_flat.len() {
            auth_siblings_flat.append(*base.auth_siblings_flat.at(q));
            q += 1;
        }

        TransferFixture {
            auth_domain: base.auth_domain,
            root: base.root,
            nf_list: array![*base.nf_list.at(0), *base.nf_list.at(0)],
            nk_spend_list: array![*base.nk_spend_list.at(0), *base.nk_spend_list.at(0)],
            auth_root_list: array![*base.auth_root_list.at(0), *base.auth_root_list.at(0)],
            auth_pub_seed_list: array![*base.auth_pub_seed_list.at(0), *base.auth_pub_seed_list.at(0)],
            auth_index_list: array![*base.auth_index_list.at(0), *base.auth_index_list.at(0)],
            d_j_in_list: array![*base.d_j_in_list.at(0), *base.d_j_in_list.at(0)],
            v_in_list: array![*base.v_in_list.at(0), *base.v_in_list.at(0)],
            rseed_in_list: array![*base.rseed_in_list.at(0), *base.rseed_in_list.at(0)],
            cm_siblings_flat,
            auth_siblings_flat,
            cm_path_indices_list: array![
                *base.cm_path_indices_list.at(0), *base.cm_path_indices_list.at(0),
            ],
            wots_sig_flat,
            cm_1: base.cm_1,
            d_j_1: base.d_j_1,
            v_1: base.v_1,
            rseed_1: base.rseed_1,
            auth_root_1: base.auth_root_1,
            auth_pub_seed_1: base.auth_pub_seed_1,
            nk_tag_1: base.nk_tag_1,
            memo_ct_hash_1: base.memo_ct_hash_1,
            cm_2: base.cm_2,
            d_j_2: base.d_j_2,
            v_2: base.v_2,
            rseed_2: base.rseed_2,
            auth_root_2: base.auth_root_2,
            auth_pub_seed_2: base.auth_pub_seed_2,
            nk_tag_2: base.nk_tag_2,
            memo_ct_hash_2: base.memo_ct_hash_2,
        }
    }

    fn run_verify(fixture: @TransferFixture) -> Array<felt252> {
        verify(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.cm_1,
            fixture.cm_2,
            fixture.nk_spend_list.span(),
            fixture.auth_root_list.span(),
            fixture.auth_pub_seed_list.span(),
            fixture.auth_index_list.span(),
            fixture.d_j_in_list.span(),
            fixture.v_in_list.span(),
            fixture.rseed_in_list.span(),
            fixture.cm_siblings_flat.span(),
            fixture.auth_siblings_flat.span(),
            fixture.cm_path_indices_list.span(),
            fixture.wots_sig_flat.span(),
            fixture.d_j_1,
            fixture.v_1,
            fixture.rseed_1,
            fixture.auth_root_1,
            fixture.auth_pub_seed_1,
            fixture.nk_tag_1,
            fixture.memo_ct_hash_1,
            fixture.d_j_2,
            fixture.v_2,
            fixture.rseed_2,
            fixture.auth_root_2,
            fixture.auth_pub_seed_2,
            fixture.nk_tag_2,
            fixture.memo_ct_hash_2,
        )
    }

    #[test]
    fn test_transfer_accepts_valid_statement() {
        let fixture = build_fixture();
        let outputs = run_verify(@fixture);
        assert(outputs.len() == 7, 'transfer outputs len');
        assert(*outputs.at(0) == fixture.auth_domain, 'transfer out domain');
        assert(*outputs.at(1) == fixture.root, 'transfer out root');
        assert(*outputs.at(2) == *fixture.nf_list.at(0), 'transfer out nf');
        assert(*outputs.at(3) == fixture.cm_1, 'transfer out cm1');
        assert(*outputs.at(4) == fixture.cm_2, 'transfer out cm2');
        assert(*outputs.at(5) == fixture.memo_ct_hash_1, 'transfer out memo1');
        assert(*outputs.at(6) == fixture.memo_ct_hash_2, 'transfer out memo2');
    }

    #[test]
    fn test_transfer_accepts_valid_two_input_statement() {
        let fixture = build_two_input_fixture();
        let outputs = run_verify(@fixture);
        assert(outputs.len() == 8, 'transfer outputs len two input');
        assert(*outputs.at(0) == fixture.auth_domain, 'transfer2 out domain');
        assert(*outputs.at(1) == fixture.root, 'transfer2 out root');
        assert(*outputs.at(2) == *fixture.nf_list.at(0), 'transfer2 out nf0');
        assert(*outputs.at(3) == *fixture.nf_list.at(1), 'transfer2 out nf1');
        assert(*outputs.at(4) == fixture.cm_1, 'transfer2 out cm1');
        assert(*outputs.at(5) == fixture.cm_2, 'transfer2 out cm2');
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_transfer_rejects_public_nullifier_mutation_via_signature_binding() {
        let mut fixture = build_fixture();
        fixture.nf_list = array![*fixture.nf_list.at(0) + 1];
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('transfer: bad nf',))]
    fn test_transfer_rejects_private_nullifier_preimage_mutation() {
        let mut fixture = build_fixture();
        fixture.nf_list = array![*fixture.nf_list.at(0) + 1];
        fixture
            .wots_sig_flat =
                sign_transfer_statement(
                    fixture.auth_domain,
                    fixture.root,
                    *fixture.nf_list.at(0),
                    fixture.cm_1,
                    fixture.cm_2,
                    fixture.memo_ct_hash_1,
                    fixture.memo_ct_hash_2,
                    *fixture.auth_pub_seed_list.at(0),
                    (*fixture.auth_index_list.at(0)).try_into().unwrap(),
                );
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('merkle root mismatch',))]
    fn test_transfer_rejects_mutated_merkle_path() {
        let mut fixture = build_fixture();
        fixture.cm_siblings_flat = copy_and_mutate(fixture.cm_siblings_flat.span(), 0);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_transfer_rejects_mutated_wots_signature() {
        let mut fixture = build_fixture();
        fixture.wots_sig_flat = copy_and_mutate(fixture.wots_sig_flat.span(), 7);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_transfer_rejects_mutated_auth_path() {
        let mut fixture = build_fixture();
        fixture.auth_siblings_flat = copy_and_mutate(fixture.auth_siblings_flat.span(), 3);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_transfer_rejects_public_output_commitment_mutation_via_signature_binding() {
        let mut fixture = build_fixture();
        fixture.cm_1 += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('transfer: bad cm_1',))]
    fn test_transfer_rejects_private_output_commitment_preimage_mutation() {
        let mut fixture = build_fixture();
        fixture.d_j_1 += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('transfer: balance mismatch',))]
    fn test_transfer_rejects_balance_mismatch_even_with_consistent_output_commitment() {
        let fixture = build_fixture_with_values(70_u64, 45_u64, 24_u64);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_transfer_rejects_second_input_auth_path_mutation() {
        let mut fixture = build_two_input_fixture();
        fixture.auth_siblings_flat = copy_and_mutate(fixture.auth_siblings_flat.span(), merkle::AUTH_DEPTH + 2);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('transfer: dup nf',))]
    fn test_transfer_rejects_duplicate_nullifiers_after_all_other_checks() {
        let fixture = build_duplicate_nf_fixture();
        run_verify(@fixture);
    }
}
