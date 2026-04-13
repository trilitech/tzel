/// Unshield circuit: N→withdrawal + optional change (1 ≤ N ≤ 7).
///
/// # Public outputs
///   [auth_domain, root, nf_0..nf_{N-1}, v_pub, recipient_id, cm_change, memo_ct_hash_change]
///
/// # Spend authorization
///   XMSS-style WOTS+ w=4 signature verification inside the STARK, bound to the sighash.

use tzel::blake_hash as hash;
use tzel::{merkle, xmss_common};

const MAX_INPUTS: u32 = 7;

fn change_commitment_or_zero(
    has_change: bool,
    d_j_change: felt252,
    v_change: u64,
    rseed_change: felt252,
    auth_root_change: felt252,
    auth_pub_seed_change: felt252,
    nk_tag_change: felt252,
    memo_ct_hash_change: felt252,
) -> felt252 {
    if has_change {
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
    }
}

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
    }
    sighash = hash::sighash_fold(sighash, v_pub.into());
    sighash = hash::sighash_fold(sighash, recipient);
    let cm_change_val = change_commitment_or_zero(
        has_change,
        d_j_change,
        v_change,
        rseed_change,
        auth_root_change,
        auth_pub_seed_change,
        nk_tag_change,
        memo_ct_hash_change,
    );
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
    }

    let mut a: u32 = 0;
    while a < n {
        let mut b: u32 = a + 1;
        while b < n {
            assert(*nf_list.at(a) != *nf_list.at(b), 'unshield: dup nf');
            b += 1;
        }
        a += 1;
    }

    let sum_out: u128 = v_pub.into() + v_change.into();
    assert(sum_in == sum_out, 'unshield: balance mismatch');

    let mut outputs: Array<felt252> = array![auth_domain, root];
    let mut j: u32 = 0;
    while j < n {
        outputs.append(*nf_list.at(j));
        j += 1;
    }
    outputs.append(v_pub.into());
    outputs.append(recipient);
    outputs.append(cm_change_val);
    outputs.append(memo_ct_hash_change);
    outputs
}

#[cfg(test)]
mod tests {
    use tzel::{blake_hash as hash, merkle, xmss_common};
    use super::{change_commitment_or_zero, verify};

    const TAG_XMSS_TREE_TEST: felt252 = 0x72742D73736D78;

    #[derive(Drop)]
    struct UnshieldFixture {
        auth_domain: felt252,
        root: felt252,
        nf_list: Array<felt252>,
        v_pub: u64,
        recipient: felt252,
        nk_spend_list: Array<felt252>,
        auth_root_list: Array<felt252>,
        auth_pub_seed_list: Array<felt252>,
        wots_sig_flat: Array<felt252>,
        auth_siblings_flat: Array<felt252>,
        auth_index_list: Array<u64>,
        d_j_in_list: Array<felt252>,
        v_in_list: Array<u64>,
        rseed_in_list: Array<felt252>,
        cm_siblings_flat: Array<felt252>,
        cm_path_indices_list: Array<u64>,
        has_change: bool,
        d_j_change: felt252,
        v_change: u64,
        rseed_change: felt252,
        auth_root_change: felt252,
        auth_pub_seed_change: felt252,
        nk_tag_change: felt252,
        memo_ct_hash_change: felt252,
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

    fn note_commitment(
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

    fn unshield_sighash(
        auth_domain: felt252,
        root: felt252,
        nf_list: Span<felt252>,
        v_pub: u64,
        recipient: felt252,
        cm_change: felt252,
        memo_ct_hash_change: felt252,
    ) -> felt252 {
        let mut sighash = hash::sighash_fold(0x02, auth_domain);
        sighash = hash::sighash_fold(sighash, root);
        let mut i: u32 = 0;
        while i < nf_list.len() {
            sighash = hash::sighash_fold(sighash, *nf_list.at(i));
            i += 1;
        }
        sighash = hash::sighash_fold(sighash, v_pub.into());
        sighash = hash::sighash_fold(sighash, recipient);
        sighash = hash::sighash_fold(sighash, cm_change);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_change);
        sighash
    }

    fn sign_unshield_input(
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

    fn sign_unshield_statement(
        auth_domain: felt252,
        root: felt252,
        nf: felt252,
        v_pub: u64,
        recipient: felt252,
        cm_change: felt252,
        memo_ct_hash_change: felt252,
        auth_pub_seed: felt252,
        auth_idx: u32,
    ) -> Array<felt252> {
        let sighash = unshield_sighash(
            auth_domain, root, array![nf].span(), v_pub, recipient, cm_change, memo_ct_hash_change,
        );
        sign_unshield_input(sighash, auth_pub_seed, auth_idx, 0x8200)
    }

    fn build_fixture_with_values(v_in: u64, v_pub: u64, v_change: u64) -> UnshieldFixture {
        let auth_domain = 0x8101;
        let nk_spend = 0x8102;
        let auth_pub_seed = 0x8103;
        let auth_idx = 6_u32;
        let d_j_in = 0x8104;
        let rseed_in = 0x8105;
        let cm_path_idx = 7_u64;

        let mut wots_endpoints: Array<felt252> = array![];
        let mut chain_idx: u32 = 0;
        while chain_idx < xmss_common::WOTS_CHAINS {
            let start = hash::hash1(chain_idx.into() + 0x8200);
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
            auth_siblings_flat.append(hash::hash1(level.into() + 0x8300));
            level += 1;
        }
        let leaf = xmss_common::xmss_ltree(auth_pub_seed, auth_idx, wots_endpoints.span());
        let auth_root = auth_root_from_leaf(
            leaf, auth_pub_seed, auth_idx, auth_siblings_flat.span(),
        );

        let nk_tag_in = hash::derive_nk_tag(nk_spend);
        let cm_in = note_commitment(d_j_in, v_in, rseed_in, auth_root, auth_pub_seed, nk_tag_in);

        let mut cm_siblings_flat: Array<felt252> = array![];
        let mut tree_level: u32 = 0;
        while tree_level < merkle::TREE_DEPTH {
            cm_siblings_flat.append(hash::hash1(tree_level.into() + 0x8400));
            tree_level += 1;
        }
        let root = merkle_root_from_path(cm_in, cm_siblings_flat.span(), cm_path_idx);
        let nf = hash::nullifier(nk_spend, cm_in, cm_path_idx);

        let recipient = 0x8501;
        let has_change = true;
        let d_j_change = 0x8502;
        let rseed_change = 0x8503;
        let auth_root_change = 0x8504;
        let auth_pub_seed_change = 0x8505;
        let nk_tag_change = 0x8506;
        let memo_ct_hash_change = 0x8507;
        let cm_change = change_commitment_or_zero(
            has_change,
            d_j_change,
            v_change,
            rseed_change,
            auth_root_change,
            auth_pub_seed_change,
            nk_tag_change,
            memo_ct_hash_change,
        );

        let wots_sig_flat = sign_unshield_statement(
            auth_domain,
            root,
            nf,
            v_pub,
            recipient,
            cm_change,
            memo_ct_hash_change,
            auth_pub_seed,
            auth_idx,
        );

        UnshieldFixture {
            auth_domain,
            root,
            nf_list: array![nf],
            v_pub,
            recipient,
            nk_spend_list: array![nk_spend],
            auth_root_list: array![auth_root],
            auth_pub_seed_list: array![auth_pub_seed],
            wots_sig_flat,
            auth_siblings_flat,
            auth_index_list: array![auth_idx.into()],
            d_j_in_list: array![d_j_in],
            v_in_list: array![v_in],
            rseed_in_list: array![rseed_in],
            cm_siblings_flat,
            cm_path_indices_list: array![cm_path_idx],
            has_change,
            d_j_change,
            v_change,
            rseed_change,
            auth_root_change,
            auth_pub_seed_change,
            nk_tag_change,
            memo_ct_hash_change,
        }
    }

    fn build_fixture() -> UnshieldFixture {
        build_fixture_with_values(80_u64, 50_u64, 30_u64)
    }

    fn build_two_input_fixture() -> UnshieldFixture {
        let auth_domain = 0x9101;
        let auth_pub_seed = 0x9102;

        let auth_idx_0 = 0_u32;
        let auth_idx_1 = 1_u32;
        let key_base_0 = 0x9200;
        let key_base_1 = 0x9300;

        let mut endpoints_0: Array<felt252> = array![];
        let mut endpoints_1: Array<felt252> = array![];
        let mut chain_idx: u32 = 0;
        while chain_idx < xmss_common::WOTS_CHAINS {
            let start_0 = hash::hash1(chain_idx.into() + key_base_0);
            let start_1 = hash::hash1(chain_idx.into() + key_base_1);
            endpoints_0
                .append(
                    chain_advance(
                        start_0, auth_pub_seed, auth_idx_0, chain_idx, xmss_common::WOTS_W - 1,
                    ),
                );
            endpoints_1
                .append(
                    chain_advance(
                        start_1, auth_pub_seed, auth_idx_1, chain_idx, xmss_common::WOTS_W - 1,
                    ),
                );
            chain_idx += 1;
        }

        let leaf_0 = xmss_common::xmss_ltree(auth_pub_seed, auth_idx_0, endpoints_0.span());
        let leaf_1 = xmss_common::xmss_ltree(auth_pub_seed, auth_idx_1, endpoints_1.span());

        let mut upper_auth_siblings: Array<felt252> = array![];
        let mut auth_level: u32 = 1;
        while auth_level < merkle::AUTH_DEPTH {
            upper_auth_siblings.append(hash::hash1(auth_level.into() + 0x9400));
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
        let auth_root = auth_root_from_leaf(
            leaf_0, auth_pub_seed, auth_idx_0, auth_siblings_0.span(),
        );

        let nk_spend_0 = 0x9501;
        let nk_spend_1 = 0x9502;
        let d_j_in_0 = 0x9503;
        let d_j_in_1 = 0x9504;
        let v_in_0 = 45_u64;
        let v_in_1 = 35_u64;
        let rseed_in_0 = 0x9505;
        let rseed_in_1 = 0x9506;

        let cm_0 = note_commitment(
            d_j_in_0, v_in_0, rseed_in_0, auth_root, auth_pub_seed, hash::derive_nk_tag(nk_spend_0),
        );
        let cm_1_in = note_commitment(
            d_j_in_1, v_in_1, rseed_in_1, auth_root, auth_pub_seed, hash::derive_nk_tag(nk_spend_1),
        );

        let mut upper_cm_siblings: Array<felt252> = array![];
        let mut tree_level: u32 = 1;
        while tree_level < merkle::TREE_DEPTH {
            upper_cm_siblings.append(hash::hash1(tree_level.into() + 0x9600));
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

        let v_pub = 50_u64;
        let recipient = 0x9701;
        let has_change = true;
        let d_j_change = 0x9702;
        let v_change = 30_u64;
        let rseed_change = 0x9703;
        let auth_root_change = 0x9704;
        let auth_pub_seed_change = 0x9705;
        let nk_tag_change = 0x9706;
        let memo_ct_hash_change = 0x9707;
        let cm_change = change_commitment_or_zero(
            has_change,
            d_j_change,
            v_change,
            rseed_change,
            auth_root_change,
            auth_pub_seed_change,
            nk_tag_change,
            memo_ct_hash_change,
        );

        let nf_list: Array<felt252> = array![nf_0, nf_1];
        let sighash = unshield_sighash(
            auth_domain, root, nf_list.span(), v_pub, recipient, cm_change, memo_ct_hash_change,
        );

        let sig_0 = sign_unshield_input(sighash, auth_pub_seed, auth_idx_0, key_base_0);
        let sig_1 = sign_unshield_input(sighash, auth_pub_seed, auth_idx_1, key_base_1);
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

        UnshieldFixture {
            auth_domain,
            root,
            nf_list,
            v_pub,
            recipient,
            nk_spend_list: array![nk_spend_0, nk_spend_1],
            auth_root_list: array![auth_root, auth_root],
            auth_pub_seed_list: array![auth_pub_seed, auth_pub_seed],
            wots_sig_flat,
            auth_siblings_flat,
            auth_index_list: array![auth_idx_0.into(), auth_idx_1.into()],
            d_j_in_list: array![d_j_in_0, d_j_in_1],
            v_in_list: array![v_in_0, v_in_1],
            rseed_in_list: array![rseed_in_0, rseed_in_1],
            cm_siblings_flat,
            cm_path_indices_list: array![0_u64, 1_u64],
            has_change,
            d_j_change,
            v_change,
            rseed_change,
            auth_root_change,
            auth_pub_seed_change,
            nk_tag_change,
            memo_ct_hash_change,
        }
    }

    fn build_duplicate_nf_fixture() -> UnshieldFixture {
        let base = build_fixture_with_values(80_u64, 90_u64, 70_u64);
        let cm_change = change_commitment_or_zero(
            base.has_change,
            base.d_j_change,
            base.v_change,
            base.rseed_change,
            base.auth_root_change,
            base.auth_pub_seed_change,
            base.nk_tag_change,
            base.memo_ct_hash_change,
        );
        let sighash = unshield_sighash(
            base.auth_domain,
            base.root,
            array![*base.nf_list.at(0), *base.nf_list.at(0)].span(),
            base.v_pub,
            base.recipient,
            cm_change,
            base.memo_ct_hash_change,
        );
        let sig = sign_unshield_input(
            sighash,
            *base.auth_pub_seed_list.at(0),
            (*base.auth_index_list.at(0)).try_into().unwrap(),
            0x8200,
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

        UnshieldFixture {
            auth_domain: base.auth_domain,
            root: base.root,
            nf_list: array![*base.nf_list.at(0), *base.nf_list.at(0)],
            v_pub: base.v_pub,
            recipient: base.recipient,
            nk_spend_list: array![*base.nk_spend_list.at(0), *base.nk_spend_list.at(0)],
            auth_root_list: array![*base.auth_root_list.at(0), *base.auth_root_list.at(0)],
            auth_pub_seed_list: array![
                *base.auth_pub_seed_list.at(0), *base.auth_pub_seed_list.at(0),
            ],
            wots_sig_flat,
            auth_siblings_flat,
            auth_index_list: array![*base.auth_index_list.at(0), *base.auth_index_list.at(0)],
            d_j_in_list: array![*base.d_j_in_list.at(0), *base.d_j_in_list.at(0)],
            v_in_list: array![*base.v_in_list.at(0), *base.v_in_list.at(0)],
            rseed_in_list: array![*base.rseed_in_list.at(0), *base.rseed_in_list.at(0)],
            cm_siblings_flat,
            cm_path_indices_list: array![
                *base.cm_path_indices_list.at(0), *base.cm_path_indices_list.at(0),
            ],
            has_change: base.has_change,
            d_j_change: base.d_j_change,
            v_change: base.v_change,
            rseed_change: base.rseed_change,
            auth_root_change: base.auth_root_change,
            auth_pub_seed_change: base.auth_pub_seed_change,
            nk_tag_change: base.nk_tag_change,
            memo_ct_hash_change: base.memo_ct_hash_change,
        }
    }

    fn run_verify(fixture: @UnshieldFixture) -> Array<felt252> {
        verify(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.v_pub,
            fixture.recipient,
            fixture.nk_spend_list.span(),
            fixture.auth_root_list.span(),
            fixture.auth_pub_seed_list.span(),
            fixture.wots_sig_flat.span(),
            fixture.auth_siblings_flat.span(),
            fixture.auth_index_list.span(),
            fixture.d_j_in_list.span(),
            fixture.v_in_list.span(),
            fixture.rseed_in_list.span(),
            fixture.cm_siblings_flat.span(),
            fixture.cm_path_indices_list.span(),
            fixture.has_change,
            fixture.d_j_change,
            fixture.v_change,
            fixture.rseed_change,
            fixture.auth_root_change,
            fixture.auth_pub_seed_change,
            fixture.nk_tag_change,
            fixture.memo_ct_hash_change,
        )
    }

    #[test]
    fn test_change_commitment_or_zero_accepts_all_zero_no_change() {
        assert(change_commitment_or_zero(false, 0, 0, 0, 0, 0, 0, 0) == 0, 'zero ok');
    }

    #[test]
    fn test_change_commitment_or_zero_matches_commit_when_present() {
        let d_j = 0x11;
        let v = 37_u64;
        let rseed = 0x22;
        let auth_root = 0x33;
        let auth_pub_seed = 0x44;
        let nk_tag = 0x55;
        let memo_ct_hash = 0x66;

        let rcm = hash::derive_rcm(rseed);
        let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
        let expected = hash::commit(d_j, v, rcm, otag);

        assert(
            change_commitment_or_zero(
                true, d_j, v, rseed, auth_root, auth_pub_seed, nk_tag, memo_ct_hash,
            ) == expected,
            'change cm',
        );
    }

    #[test]
    #[should_panic(expected: ('unshield: no change but v!=0',))]
    fn test_change_commitment_or_zero_rejects_nonzero_value_without_change() {
        change_commitment_or_zero(false, 0, 1_u64, 0, 0, 0, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: mh!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_memo_without_change() {
        change_commitment_or_zero(false, 0, 0, 0, 0, 0, 0, 1);
    }

    #[test]
    #[should_panic(expected: ('unshield: d_j!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_dj_without_change() {
        change_commitment_or_zero(false, 1, 0, 0, 0, 0, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: rseed!=0 no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_rseed_without_change() {
        change_commitment_or_zero(false, 0, 0, 1, 0, 0, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: ar!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_auth_root_without_change() {
        change_commitment_or_zero(false, 0, 0, 0, 1, 0, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: ps!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_pub_seed_without_change() {
        change_commitment_or_zero(false, 0, 0, 0, 0, 1, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: nkt!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_nk_tag_without_change() {
        change_commitment_or_zero(false, 0, 0, 0, 0, 0, 1, 0);
    }

    #[test]
    fn test_unshield_accepts_valid_statement() {
        let fixture = build_fixture();
        let outputs = run_verify(@fixture);
        let cm_change = change_commitment_or_zero(
            fixture.has_change,
            fixture.d_j_change,
            fixture.v_change,
            fixture.rseed_change,
            fixture.auth_root_change,
            fixture.auth_pub_seed_change,
            fixture.nk_tag_change,
            fixture.memo_ct_hash_change,
        );
        assert(outputs.len() == 7, 'unshield outputs len');
        assert(*outputs.at(0) == fixture.auth_domain, 'unshield out domain');
        assert(*outputs.at(1) == fixture.root, 'unshield out root');
        assert(*outputs.at(2) == *fixture.nf_list.at(0), 'unshield out nf');
        assert(*outputs.at(3) == fixture.v_pub.into(), 'unshield out vpub');
        assert(*outputs.at(4) == fixture.recipient, 'unshield out recipient');
        assert(*outputs.at(5) == cm_change, 'unshield out change');
        assert(*outputs.at(6) == fixture.memo_ct_hash_change, 'unshield out memo');
    }

    #[test]
    fn test_unshield_accepts_valid_two_input_statement() {
        let fixture = build_two_input_fixture();
        let outputs = run_verify(@fixture);
        assert(outputs.len() == 8, 'unshield outputs len two input');
        assert(*outputs.at(0) == fixture.auth_domain, 'unshield2 out domain');
        assert(*outputs.at(1) == fixture.root, 'unshield2 out root');
        assert(*outputs.at(2) == *fixture.nf_list.at(0), 'unshield2 out nf0');
        assert(*outputs.at(3) == *fixture.nf_list.at(1), 'unshield2 out nf1');
        assert(*outputs.at(4) == fixture.v_pub.into(), 'unshield2 out vpub');
        assert(*outputs.at(5) == fixture.recipient, 'unshield2 out recipient');
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_unshield_rejects_public_nullifier_mutation_via_signature_binding() {
        let mut fixture = build_fixture();
        fixture.nf_list = array![*fixture.nf_list.at(0) + 1];
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('unshield: bad nf',))]
    fn test_unshield_rejects_private_nullifier_preimage_mutation() {
        let mut fixture = build_fixture();
        fixture.nf_list = array![*fixture.nf_list.at(0) + 1];
        let cm_change = change_commitment_or_zero(
            fixture.has_change,
            fixture.d_j_change,
            fixture.v_change,
            fixture.rseed_change,
            fixture.auth_root_change,
            fixture.auth_pub_seed_change,
            fixture.nk_tag_change,
            fixture.memo_ct_hash_change,
        );
        fixture
            .wots_sig_flat =
                sign_unshield_statement(
                    fixture.auth_domain,
                    fixture.root,
                    *fixture.nf_list.at(0),
                    fixture.v_pub,
                    fixture.recipient,
                    cm_change,
                    fixture.memo_ct_hash_change,
                    *fixture.auth_pub_seed_list.at(0),
                    (*fixture.auth_index_list.at(0)).try_into().unwrap(),
                );
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('merkle root mismatch',))]
    fn test_unshield_rejects_mutated_merkle_path() {
        let mut fixture = build_fixture();
        fixture.cm_siblings_flat = copy_and_mutate(fixture.cm_siblings_flat.span(), 0);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_unshield_rejects_mutated_wots_signature() {
        let mut fixture = build_fixture();
        fixture.wots_sig_flat = copy_and_mutate(fixture.wots_sig_flat.span(), 12);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_unshield_rejects_mutated_recipient() {
        let mut fixture = build_fixture();
        fixture.recipient += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_unshield_rejects_mutated_change_memo_hash() {
        let mut fixture = build_fixture();
        fixture.memo_ct_hash_change += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('unshield: balance mismatch',))]
    fn test_unshield_rejects_balance_mismatch_even_with_consistent_change_commitment() {
        let fixture = build_fixture_with_values(80_u64, 50_u64, 29_u64);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_unshield_rejects_second_input_auth_path_mutation() {
        let mut fixture = build_two_input_fixture();
        fixture
            .auth_siblings_flat =
                copy_and_mutate(fixture.auth_siblings_flat.span(), merkle::AUTH_DEPTH + 2);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('unshield: dup nf',))]
    fn test_unshield_rejects_duplicate_nullifiers_after_all_other_checks() {
        let fixture = build_duplicate_nf_fixture();
        run_verify(@fixture);
    }
}
