/// Unshield circuit: N→withdrawal + up to two change notes + producer fee
/// (1 ≤ N ≤ 7).
///
/// Phase C / multiasset output layout: a public exit of `v_pub` units of
/// `asset_pub` to a canonical Tezos recipient (the L1 burn dispatches via
/// the bridge ticketer registered for `asset_pub`), plus up to two
/// change notes (one per asset under the 2-accumulator design) plus a
/// producer-fee note (permanently tez).
///
/// # Public outputs
///   [auth_domain, root, nf_0..nf_{N-1}, v_pub, asset_pub, fee, recipient_id,
///    cm_change, memo_ct_hash_change, cm_change_2, memo_ct_hash_change_2,
///    cm_fee, memo_ct_hash_fee]
///
/// Length is `2 + N + 10` felts (auth_domain + root + N nullifiers +
/// v_pub + asset_pub + fee + recipient_id + 2×(cm,mh) for changes +
/// 1×(cm,mh) for the producer fee).
///
/// # Multiasset constraints
///   The witness declares one primary non-tez asset `A`; every input and
///   every output (including the two optional change slots and the
///   `asset_pub` exit asset) is constrained to lie in {ASSET_TEZ, A}.
///   Two accumulators close the per-asset balance:
///     tez_in     = tez_out     + [asset_pub == ASSET_TEZ] * v_pub + v_fee + fee
///     primary_in = primary_out + [asset_pub == A]         * v_pub
///   The producer-fee note is permanently tez (`asset_fee = ASSET_TEZ`).
///
///   Phase E.5 bug #1 (commit 2003bf5): an earlier version
///   unconditionally added `v_pub` to `tez_out` regardless of
///   `asset_pub`. That bug let a tez-only input set mint FA2 tokens on
///   L1; the fix routes `v_pub` to the right accumulator based on
///   `asset_pub`.
///
/// # Spend authorization
///   XMSS-style WOTS+ w=4 signature verification inside the STARK, bound to the sighash.
///   `asset_pub` IS folded directly into the sighash (it's a
///   public-output discriminator chosen by the user at sign time).

use tzel::blake_hash as hash;
use tzel::{merkle, xmss_common};
use tzel::ASSET_TEZ;

const MAX_INPUTS: u32 = 7;

fn change_commitment_or_zero(
    has_change: bool,
    d_j_change: felt252,
    v_change: u64,
    asset_change: felt252,
    rseed_change: felt252,
    auth_root_change: felt252,
    auth_pub_seed_change: felt252,
    nk_tag_change: felt252,
    memo_ct_hash_change: felt252,
) -> felt252 {
    if has_change {
        let rcm_c = hash::derive_rcm(rseed_change);
        let otag_c = hash::owner_tag(auth_root_change, auth_pub_seed_change, nk_tag_change);
        hash::commit(d_j_change, v_change, asset_change, rcm_c, otag_c)
    } else {
        assert(v_change == 0, 'unshield: no change but v!=0');
        assert(memo_ct_hash_change == 0, 'unshield: mh!=0 but no change');
        assert(d_j_change == 0, 'unshield: d_j!=0 but no change');
        assert(rseed_change == 0, 'unshield: rseed!=0 no change');
        assert(auth_root_change == 0, 'unshield: ar!=0 but no change');
        assert(auth_pub_seed_change == 0, 'unshield: ps!=0 but no change');
        assert(nk_tag_change == 0, 'unshield: nkt!=0 but no change');
        assert(asset_change == 0, 'unshield: asset!=0 no change');
        0
    }
}

pub fn verify(
    auth_domain: felt252,
    root: felt252,
    nf_list: Span<felt252>,
    v_pub: u64,
    fee: u64,
    recipient: felt252,
    nk_spend_list: Span<felt252>,
    auth_root_list: Span<felt252>,
    auth_pub_seed_list: Span<felt252>,
    wots_sig_flat: Span<felt252>,
    auth_siblings_flat: Span<felt252>,
    auth_index_list: Span<u32>,
    d_j_in_list: Span<felt252>,
    v_in_list: Span<u64>,
    rseed_in_list: Span<felt252>,
    cm_siblings_flat: Span<felt252>,
    cm_path_indices_list: Span<u64>,
    // Phase C: change_1 slot (renamed from "change").
    has_change: bool,
    d_j_change: felt252,
    v_change: u64,
    rseed_change: felt252,
    auth_root_change: felt252,
    auth_pub_seed_change: felt252,
    nk_tag_change: felt252,
    memo_ct_hash_change: felt252,
    // Phase C: change_2 slot (new). Same has_change_2/optional-zero
    // semantics as change_1.
    has_change_2: bool,
    d_j_change_2: felt252,
    v_change_2: u64,
    rseed_change_2: felt252,
    auth_root_change_2: felt252,
    auth_pub_seed_change_2: felt252,
    nk_tag_change_2: felt252,
    memo_ct_hash_change_2: felt252,
    d_j_fee: felt252,
    v_fee: u64,
    rseed_fee: felt252,
    auth_root_fee: felt252,
    auth_pub_seed_fee: felt252,
    nk_tag_fee: felt252,
    memo_ct_hash_fee: felt252,
    // Multiasset (Phase B). asset_pub is the L1 exit asset (pinned to
    // ASSET_TEZ in v1: only the tez bridge exists for exits). asset_change_1
    // and asset_change_2 are private-output assets; the producer fee is
    // pinned to ASSET_TEZ permanently by the liquidity argument. Either
    // change slot may hold tez or the witness-declared primary non-tez
    // asset.
    input_asset_list: Span<felt252>,
    asset_change: felt252,
    asset_change_2: felt252,
    asset_fee: felt252,
    asset_pub: felt252,
    primary_non_tez_asset: felt252,
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
    assert(input_asset_list.len() == n, 'unshield: asset list len');

    // Phase E.3: the v1 `asset_pub == ASSET_TEZ` pin moved to the
    // kernel-side registry check (the kernel rejects exits to
    // unregistered ticketers / unknown asset_ids). The circuit only
    // verifies the per-asset balance and the producer-fee pin below.
    //
    // Permanent: producer fee must be tez.
    assert(asset_fee == ASSET_TEZ, 'unshield: producer must be tez');

    let mut sighash = hash::sighash_fold(0x02, auth_domain);
    sighash = hash::sighash_fold(sighash, root);
    let mut si: u32 = 0;
    while si < n {
        sighash = hash::sighash_fold(sighash, *nf_list.at(si));
        si += 1;
    }
    sighash = hash::sighash_fold(sighash, v_pub.into());
    sighash = hash::sighash_fold(sighash, asset_pub);
    sighash = hash::sighash_fold(sighash, fee.into());
    sighash = hash::sighash_fold(sighash, recipient);
    let cm_change_val = change_commitment_or_zero(
        has_change,
        d_j_change,
        v_change,
        asset_change,
        rseed_change,
        auth_root_change,
        auth_pub_seed_change,
        nk_tag_change,
        memo_ct_hash_change,
    );
    let cm_change_2_val = change_commitment_or_zero(
        has_change_2,
        d_j_change_2,
        v_change_2,
        asset_change_2,
        rseed_change_2,
        auth_root_change_2,
        auth_pub_seed_change_2,
        nk_tag_change_2,
        memo_ct_hash_change_2,
    );
    sighash = hash::sighash_fold(sighash, cm_change_val);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_change);
    sighash = hash::sighash_fold(sighash, cm_change_2_val);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_change_2);
    let rcm_fee = hash::derive_rcm(rseed_fee);
    let otag_fee = hash::owner_tag(auth_root_fee, auth_pub_seed_fee, nk_tag_fee);
    let cm_fee = hash::commit(d_j_fee, v_fee, asset_fee, rcm_fee, otag_fee);
    sighash = hash::sighash_fold(sighash, cm_fee);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_fee);

    // Both change slots must be in {tez, primary_non_tez_asset}.  If a
    // slot has has_change=false, change_commitment_or_zero forces
    // its asset to zero, and ASSET_TEZ = 0 so it satisfies the tez
    // branch trivially.
    assert(
        asset_change == ASSET_TEZ || asset_change == primary_non_tez_asset,
        'unshield: bad asset_change',
    );
    assert(
        asset_change_2 == ASSET_TEZ || asset_change_2 == primary_non_tez_asset,
        'unshield: bad asset_change_2',
    );

    // 2-accumulator per-asset balance.
    let mut tez_in: u128 = 0;
    let mut primary_in: u128 = 0;
    let mut i: u32 = 0;
    while i < n {
        let nk_spend = *nk_spend_list.at(i);
        let auth_root = *auth_root_list.at(i);
        let auth_pub_seed = *auth_pub_seed_list.at(i);
        let auth_idx: u32 = *auth_index_list.at(i);
        let d_j = *d_j_in_list.at(i);
        let v: u64 = *v_in_list.at(i);
        let rseed = *rseed_in_list.at(i);
        let cm_path_idx = *cm_path_indices_list.at(i);
        let asset_i = *input_asset_list.at(i);

        assert(
            asset_i == ASSET_TEZ || asset_i == primary_non_tez_asset,
            'unshield: bad input asset',
        );

        let nk_tag = hash::derive_nk_tag(nk_spend);
        let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, asset_i, rcm, otag);

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

        if asset_i == ASSET_TEZ {
            tez_in += v.into();
        } else {
            primary_in += v.into();
        }
        i += 1;
    }

    assert(v_fee > 0_u64, 'unshield prod fee');

    // Tally outputs into the per-asset accumulators. asset_fee is
    // pinned to ASSET_TEZ (asserted above); the two change slots
    // and the public exit each route based on their declared
    // witness asset.
    let mut tez_out: u128 = v_fee.into(); // producer fee pinned to tez
    let mut primary_out: u128 = 0;
    if asset_change == ASSET_TEZ {
        tez_out += v_change.into();
    } else {
        primary_out += v_change.into();
    }
    if asset_change_2 == ASSET_TEZ {
        tez_out += v_change_2.into();
    } else {
        primary_out += v_change_2.into();
    }

    // asset_pub MUST be in the same {tez, primary} pair every other
    // asset is constrained to. Without this, a prover could mint a
    // non-tez asset on L1 by spending only tez inputs: the kernel
    // reads asset_pub from the proof's public outputs and routes
    // the outbox burn to its registered ticketer, so a v_pub credited
    // to the wrong lane lets an attacker mint a token they never
    // deposited. The earlier Phase E.3 lift of the tez pin on
    // asset_pub silently broke the balance accounting because the
    // unconditional `tez_out += v_pub` here pre-dated the per-asset
    // constraint.
    assert(
        asset_pub == ASSET_TEZ || asset_pub == primary_non_tez_asset,
        'unshield: bad asset_pub',
    );
    if asset_pub == ASSET_TEZ {
        tez_out += v_pub.into();
    } else {
        primary_out += v_pub.into();
    }

    // Per-asset balance.
    assert(tez_in == tez_out + fee.into(), 'unshield: tez balance');
    assert(primary_in == primary_out, 'unshield: primary balance');

    let mut outputs: Array<felt252> = array![auth_domain, root];
    let mut j: u32 = 0;
    while j < n {
        outputs.append(*nf_list.at(j));
        j += 1;
    }
    outputs.append(v_pub.into());
    outputs.append(asset_pub);
    outputs.append(fee.into());
    outputs.append(recipient);
    outputs.append(cm_change_val);
    outputs.append(memo_ct_hash_change);
    outputs.append(cm_change_2_val);
    outputs.append(memo_ct_hash_change_2);
    outputs.append(cm_fee);
    outputs.append(memo_ct_hash_fee);
    outputs
}

#[cfg(test)]
mod tests {
    use tzel::{blake_hash as hash, merkle, xmss_common};
    use tzel::ASSET_TEZ;
    use super::{change_commitment_or_zero, verify};

    const TAG_XMSS_TREE_TEST: felt252 = 0x72742D73736D78;

    #[derive(Drop)]
    struct UnshieldFixture {
        auth_domain: felt252,
        root: felt252,
        nf_list: Array<felt252>,
        v_pub: u64,
        fee: u64,
        recipient: felt252,
        nk_spend_list: Array<felt252>,
        auth_root_list: Array<felt252>,
        auth_pub_seed_list: Array<felt252>,
        wots_sig_flat: Array<felt252>,
        auth_siblings_flat: Array<felt252>,
        auth_index_list: Array<u32>,
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
        d_j_fee: felt252,
        v_fee: u64,
        rseed_fee: felt252,
        auth_root_fee: felt252,
        auth_pub_seed_fee: felt252,
        nk_tag_fee: felt252,
        memo_ct_hash_fee: felt252,
        // Phase C: second change slot.
        has_change_2: bool,
        d_j_change_2: felt252,
        v_change_2: u64,
        rseed_change_2: felt252,
        auth_root_change_2: felt252,
        auth_pub_seed_change_2: felt252,
        nk_tag_change_2: felt252,
        memo_ct_hash_change_2: felt252,
        // Multiasset Phase B
        input_asset_list: Array<felt252>,
        asset_change: felt252,
        asset_change_2: felt252,
        asset_fee: felt252,
        asset_pub: felt252,
        primary_non_tez_asset: felt252,
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
        hash::commit(d_j, v, ASSET_TEZ, rcm, otag)
    }

    fn unshield_sighash(
        auth_domain: felt252,
        root: felt252,
        nf_list: Span<felt252>,
        v_pub: u64,
        asset_pub: felt252,
        fee: u64,
        recipient: felt252,
        cm_change: felt252,
        memo_ct_hash_change: felt252,
        cm_change_2: felt252,
        memo_ct_hash_change_2: felt252,
        cm_fee: felt252,
        memo_ct_hash_fee: felt252,
    ) -> felt252 {
        let mut sighash = hash::sighash_fold(0x02, auth_domain);
        sighash = hash::sighash_fold(sighash, root);
        let mut i: u32 = 0;
        while i < nf_list.len() {
            sighash = hash::sighash_fold(sighash, *nf_list.at(i));
            i += 1;
        }
        sighash = hash::sighash_fold(sighash, v_pub.into());
        sighash = hash::sighash_fold(sighash, asset_pub);
        sighash = hash::sighash_fold(sighash, fee.into());
        sighash = hash::sighash_fold(sighash, recipient);
        sighash = hash::sighash_fold(sighash, cm_change);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_change);
        sighash = hash::sighash_fold(sighash, cm_change_2);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_change_2);
        sighash = hash::sighash_fold(sighash, cm_fee);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_fee);
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
        fee: u64,
        recipient: felt252,
        cm_change: felt252,
        memo_ct_hash_change: felt252,
        cm_fee: felt252,
        memo_ct_hash_fee: felt252,
        auth_pub_seed: felt252,
        auth_idx: u32,
    ) -> Array<felt252> {
        let sighash = unshield_sighash(
            auth_domain,
            root,
            array![nf].span(),
            v_pub,
            ASSET_TEZ,
            fee,
            recipient,
            cm_change,
            memo_ct_hash_change,
            0, // cm_change_2 = zero (has_change_2 = false)
            0, // memo_ct_hash_change_2
            cm_fee,
            memo_ct_hash_fee,
        );
        sign_unshield_input(sighash, auth_pub_seed, auth_idx, 0x8200)
    }

    fn build_fixture_with_values_and_fee(
        v_in: u64, v_pub: u64, v_change: u64, v_fee: u64, fee: u64,
    ) -> UnshieldFixture {
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
            ASSET_TEZ,
            rseed_change,
            auth_root_change,
            auth_pub_seed_change,
            nk_tag_change,
            memo_ct_hash_change
        );

        let d_j_fee = 0x8512;
        let rseed_fee = 0x8513;
        let auth_root_fee = 0x8514;
        let auth_pub_seed_fee = 0x8515;
        let nk_tag_fee = 0x8516;
        let memo_ct_hash_fee = 0x8517;
        let cm_fee = note_commitment(
            d_j_fee, v_fee, rseed_fee, auth_root_fee, auth_pub_seed_fee, nk_tag_fee,
        );

        let wots_sig_flat = sign_unshield_statement(
            auth_domain,
            root,
            nf,
            v_pub,
            fee,
            recipient,
            cm_change,
            memo_ct_hash_change,
            cm_fee,
            memo_ct_hash_fee,
            auth_pub_seed,
            auth_idx,
        );

        UnshieldFixture {
            auth_domain,
            root,
            nf_list: array![nf],
            v_pub,
            fee,
            recipient,
            nk_spend_list: array![nk_spend],
            auth_root_list: array![auth_root],
            auth_pub_seed_list: array![auth_pub_seed],
            wots_sig_flat,
            auth_siblings_flat,
            auth_index_list: array![auth_idx],
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
            d_j_fee,
            v_fee,
            rseed_fee,
            auth_root_fee,
            auth_pub_seed_fee,
            nk_tag_fee,
            memo_ct_hash_fee,
            // Multiasset Phase B: pure-tez single-input fixture.
            input_asset_list: array![ASSET_TEZ],
            asset_change: ASSET_TEZ,
            asset_change_2: ASSET_TEZ,
            asset_fee: ASSET_TEZ,
            asset_pub: ASSET_TEZ,
            primary_non_tez_asset: ASSET_TEZ,
            // Phase C: change_2 slot zeroed (has_change_2=false in all
            // pre-existing test scenarios).
            has_change_2: false,
            d_j_change_2: 0,
            v_change_2: 0,
            rseed_change_2: 0,
            auth_root_change_2: 0,
            auth_pub_seed_change_2: 0,
            nk_tag_change_2: 0,
            memo_ct_hash_change_2: 0,
        }
    }

    fn build_fixture_with_values(
        v_in: u64, v_pub: u64, v_change: u64, v_fee: u64,
    ) -> UnshieldFixture {
        let fee = v_in - v_pub - v_change - v_fee;
        build_fixture_with_values_and_fee(v_in, v_pub, v_change, v_fee, fee)
    }

    fn build_fixture() -> UnshieldFixture {
        build_fixture_with_values(80_u64, 47_u64, 25_u64, 3_u64)
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

        let v_pub = 47_u64;
        let fee = 5_u64;
        let v_fee = 3_u64;
        let recipient = 0x9701;
        let has_change = true;
        let d_j_change = 0x9702;
        let v_change = 25_u64;
        let rseed_change = 0x9703;
        let auth_root_change = 0x9704;
        let auth_pub_seed_change = 0x9705;
        let nk_tag_change = 0x9706;
        let memo_ct_hash_change = 0x9707;
        let cm_change = change_commitment_or_zero(
            has_change,
            d_j_change,
            v_change,
            ASSET_TEZ,
            rseed_change,
            auth_root_change,
            auth_pub_seed_change,
            nk_tag_change,
            memo_ct_hash_change
        );

        let d_j_fee = 0x9712;
        let rseed_fee = 0x9713;
        let auth_root_fee = 0x9714;
        let auth_pub_seed_fee = 0x9715;
        let nk_tag_fee = 0x9716;
        let memo_ct_hash_fee = 0x9717;
        let cm_fee = note_commitment(
            d_j_fee, v_fee, rseed_fee, auth_root_fee, auth_pub_seed_fee, nk_tag_fee,
        );

        let nf_list: Array<felt252> = array![nf_0, nf_1];
        let sighash = unshield_sighash(
            auth_domain,
            root,
            nf_list.span(),
            v_pub,
            ASSET_TEZ,
            fee,
            recipient,
            cm_change,
            memo_ct_hash_change,
            0, // cm_change_2 = zero (has_change_2 = false)
            0, // memo_ct_hash_change_2
            cm_fee,
            memo_ct_hash_fee,
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
            fee,
            recipient,
            nk_spend_list: array![nk_spend_0, nk_spend_1],
            auth_root_list: array![auth_root, auth_root],
            auth_pub_seed_list: array![auth_pub_seed, auth_pub_seed],
            wots_sig_flat,
            auth_siblings_flat,
            auth_index_list: array![auth_idx_0, auth_idx_1],
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
            d_j_fee,
            v_fee,
            rseed_fee,
            auth_root_fee,
            auth_pub_seed_fee,
            nk_tag_fee,
            memo_ct_hash_fee,
            // Multiasset Phase B: pure-tez two-input fixture.
            input_asset_list: array![ASSET_TEZ, ASSET_TEZ],
            asset_change: ASSET_TEZ,
            asset_change_2: ASSET_TEZ,
            asset_fee: ASSET_TEZ,
            asset_pub: ASSET_TEZ,
            primary_non_tez_asset: ASSET_TEZ,
            // Phase C: change_2 slot zeroed (has_change_2=false in all
            // pre-existing test scenarios).
            has_change_2: false,
            d_j_change_2: 0,
            v_change_2: 0,
            rseed_change_2: 0,
            auth_root_change_2: 0,
            auth_pub_seed_change_2: 0,
            nk_tag_change_2: 0,
            memo_ct_hash_change_2: 0,
        }
    }

    fn build_duplicate_nf_fixture() -> UnshieldFixture {
        let base = build_fixture_with_values_and_fee(80_u64, 100_u64, 52_u64, 3_u64, 5_u64);
        let cm_change = change_commitment_or_zero(
            base.has_change,
            base.d_j_change,
            base.v_change,
            ASSET_TEZ,
            base.rseed_change,
            base.auth_root_change,
            base.auth_pub_seed_change,
            base.nk_tag_change,
            base.memo_ct_hash_change
        );
        let sighash = unshield_sighash(
            base.auth_domain,
            base.root,
            array![*base.nf_list.at(0), *base.nf_list.at(0)].span(),
            base.v_pub,
            ASSET_TEZ,
            base.fee,
            base.recipient,
            cm_change,
            base.memo_ct_hash_change,
            0, // cm_change_2 = zero (has_change_2 = false)
            0, // memo_ct_hash_change_2
            note_commitment(
                base.d_j_fee,
                base.v_fee,
                base.rseed_fee,
                base.auth_root_fee,
                base.auth_pub_seed_fee,
                base.nk_tag_fee,
            ),
            base.memo_ct_hash_fee,
        );
        let sig = sign_unshield_input(
            sighash,
            *base.auth_pub_seed_list.at(0),
            *base.auth_index_list.at(0),
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
            fee: base.fee,
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
            d_j_fee: base.d_j_fee,
            v_fee: base.v_fee,
            rseed_fee: base.rseed_fee,
            auth_root_fee: base.auth_root_fee,
            auth_pub_seed_fee: base.auth_pub_seed_fee,
            nk_tag_fee: base.nk_tag_fee,
            memo_ct_hash_fee: base.memo_ct_hash_fee,
            // Multiasset Phase B: pure-tez duplicate-nf fixture (2 inputs).
            input_asset_list: array![ASSET_TEZ, ASSET_TEZ],
            asset_change: ASSET_TEZ,
            asset_change_2: ASSET_TEZ,
            asset_fee: ASSET_TEZ,
            asset_pub: ASSET_TEZ,
            primary_non_tez_asset: ASSET_TEZ,
            // Phase C: change_2 slot zeroed (has_change_2=false in all
            // pre-existing test scenarios).
            has_change_2: false,
            d_j_change_2: 0,
            v_change_2: 0,
            rseed_change_2: 0,
            auth_root_change_2: 0,
            auth_pub_seed_change_2: 0,
            nk_tag_change_2: 0,
            memo_ct_hash_change_2: 0,
        }
    }

    fn run_verify(fixture: @UnshieldFixture) -> Array<felt252> {
        verify(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.v_pub,
            fixture.fee,
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
            fixture.has_change_2,
            fixture.d_j_change_2,
            fixture.v_change_2,
            fixture.rseed_change_2,
            fixture.auth_root_change_2,
            fixture.auth_pub_seed_change_2,
            fixture.nk_tag_change_2,
            fixture.memo_ct_hash_change_2,
            fixture.d_j_fee,
            fixture.v_fee,
            fixture.rseed_fee,
            fixture.auth_root_fee,
            fixture.auth_pub_seed_fee,
            fixture.nk_tag_fee,
            fixture.memo_ct_hash_fee,
            fixture.input_asset_list.span(),
            fixture.asset_change,
            fixture.asset_change_2,
            fixture.asset_fee,
            fixture.asset_pub,
            fixture.primary_non_tez_asset,
        )
    }

    #[test]
    fn test_change_commitment_or_zero_accepts_all_zero_no_change() {
        assert(change_commitment_or_zero(false, 0, 0, ASSET_TEZ, 0, 0, 0, 0, 0) == 0, 'zero ok');
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
        let expected = hash::commit(d_j, v, ASSET_TEZ, rcm, otag);

        assert(
            change_commitment_or_zero(
                true, d_j, v, ASSET_TEZ, rseed, auth_root, auth_pub_seed, nk_tag, memo_ct_hash
            ) == expected,
            'change cm',
        );
    }

    #[test]
    #[should_panic(expected: ('unshield: no change but v!=0',))]
    fn test_change_commitment_or_zero_rejects_nonzero_value_without_change() {
        change_commitment_or_zero(false, 0, 1_u64, ASSET_TEZ, 0, 0, 0, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: mh!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_memo_without_change() {
        change_commitment_or_zero(false, 0, 0, ASSET_TEZ, 0, 0, 0, 0, 1);
    }

    #[test]
    #[should_panic(expected: ('unshield: d_j!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_dj_without_change() {
        change_commitment_or_zero(false, 1, 0, ASSET_TEZ, 0, 0, 0, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: rseed!=0 no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_rseed_without_change() {
        change_commitment_or_zero(false, 0, 0, ASSET_TEZ, 1, 0, 0, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: ar!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_auth_root_without_change() {
        change_commitment_or_zero(false, 0, 0, ASSET_TEZ, 0, 1, 0, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: ps!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_pub_seed_without_change() {
        change_commitment_or_zero(false, 0, 0, ASSET_TEZ, 0, 0, 1, 0, 0);
    }

    #[test]
    #[should_panic(expected: ('unshield: nkt!=0 but no change',))]
    fn test_change_commitment_or_zero_rejects_nonzero_nk_tag_without_change() {
        change_commitment_or_zero(false, 0, 0, ASSET_TEZ, 0, 0, 0, 1, 0);
    }

    #[test]
    fn test_unshield_accepts_valid_statement() {
        let fixture = build_fixture();
        let outputs = run_verify(@fixture);
        let cm_change = change_commitment_or_zero(
            fixture.has_change,
            fixture.d_j_change,
            fixture.v_change,
            ASSET_TEZ,
            fixture.rseed_change,
            fixture.auth_root_change,
            fixture.auth_pub_seed_change,
            fixture.nk_tag_change,
            fixture.memo_ct_hash_change
        );
        let cm_fee = note_commitment(
            fixture.d_j_fee,
            fixture.v_fee,
            fixture.rseed_fee,
            fixture.auth_root_fee,
            fixture.auth_pub_seed_fee,
            fixture.nk_tag_fee,
        );
        // Phase C: outputs include cm_change_2 + memo_change_2 (+2 vs Phase B).
        assert(outputs.len() == 13, 'unshield outputs len');
        assert(*outputs.at(0) == fixture.auth_domain, 'unshield out domain');
        assert(*outputs.at(1) == fixture.root, 'unshield out root');
        assert(*outputs.at(2) == *fixture.nf_list.at(0), 'unshield out nf');
        assert(*outputs.at(3) == fixture.v_pub.into(), 'unshield out vpub');
        assert(*outputs.at(4) == fixture.asset_pub, 'unshield out asset_pub');
        assert(*outputs.at(5) == fixture.fee.into(), 'unshield out fee');
        assert(*outputs.at(6) == fixture.recipient, 'unshield out recipient');
        assert(*outputs.at(7) == cm_change, 'unshield out change');
        assert(*outputs.at(8) == fixture.memo_ct_hash_change, 'unshield out memo');
        // outputs.at(9) = cm_change_2 = 0 (has_change_2 = false)
        // outputs.at(10) = memo_ct_hash_change_2 = 0
        assert(*outputs.at(11) == cm_fee, 'unshield out fee cm');
        assert(*outputs.at(12) == fixture.memo_ct_hash_fee, 'unshield out fee memo');
    }

    #[test]
    fn test_unshield_accepts_valid_two_input_statement() {
        let fixture = build_two_input_fixture();
        let outputs = run_verify(@fixture);
        // Phase C: +2 for change_2.
        assert(outputs.len() == 14, 'unshield outputs len two input');
        assert(*outputs.at(0) == fixture.auth_domain, 'unshield2 out domain');
        assert(*outputs.at(1) == fixture.root, 'unshield2 out root');
        assert(*outputs.at(2) == *fixture.nf_list.at(0), 'unshield2 out nf0');
        assert(*outputs.at(3) == *fixture.nf_list.at(1), 'unshield2 out nf1');
        assert(*outputs.at(4) == fixture.v_pub.into(), 'unshield2 out vpub');
        assert(*outputs.at(5) == fixture.asset_pub, 'unshield2 out asset_pub');
        assert(*outputs.at(6) == fixture.fee.into(), 'unshield2 out fee');
        assert(*outputs.at(7) == fixture.recipient, 'unshield2 out recipient');
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
            ASSET_TEZ,
            fixture.rseed_change,
            fixture.auth_root_change,
            fixture.auth_pub_seed_change,
            fixture.nk_tag_change,
            fixture.memo_ct_hash_change
        );
        fixture
            .wots_sig_flat =
                sign_unshield_statement(
                    fixture.auth_domain,
                    fixture.root,
                    *fixture.nf_list.at(0),
                    fixture.v_pub,
                    fixture.fee,
                    fixture.recipient,
                    cm_change,
                    fixture.memo_ct_hash_change,
                    note_commitment(
                        fixture.d_j_fee,
                        fixture.v_fee,
                        fixture.rseed_fee,
                        fixture.auth_root_fee,
                        fixture.auth_pub_seed_fee,
                        fixture.nk_tag_fee,
                    ),
                    fixture.memo_ct_hash_fee,
                    *fixture.auth_pub_seed_list.at(0),
                    *fixture.auth_index_list.at(0),
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
    #[should_panic(expected: ('unshield: tez balance',))]
    fn test_unshield_rejects_balance_mismatch_even_with_consistent_change_commitment() {
        let fixture = build_fixture_with_values_and_fee(80_u64, 47_u64, 24_u64, 3_u64, 5_u64);
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
    fn test_unshield_leaves_duplicate_nullifier_rejection_to_consensus() {
        let fixture = build_duplicate_nf_fixture();
        run_verify(@fixture);
    }

    // ═══════════════════════════════════════════════════════════════
    // Multiasset Phase B/C mutation tests
    // ═══════════════════════════════════════════════════════════════

    /// Phase E.3: the Cairo `asset_pub == ASSET_TEZ` pin was lifted —
    /// the kernel enforces "asset_pub ∈ registered" against the
    /// kernel-binary registry. Mutating just `asset_pub` after the
    /// fact still breaks the WOTS sighash: asset_pub is folded into
    /// the unshield sighash, so a fixture that signed for ASSET_TEZ
    /// fails the auth-tree recover when asset_pub is swapped for
    /// 0xDEADBEEF. The kernel-side registry check is exercised by the
    /// Rust apply_unshield tests.
    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_unshield_rejects_asset_pub_mutation_via_sighash_binding() {
        let mut fixture = build_fixture();
        fixture.asset_pub = 0xDEADBEEF;
        run_verify(@fixture);
    }

    /// CRITICAL: a prover MUST NOT be able to mint a non-tez asset
    /// on L1 by spending only tez inputs. This was a real bug in
    /// Phase E.3: when the `asset_pub == ASSET_TEZ` pin was lifted
    /// for the multi-bridge upgrade, the balance accounting still
    /// added v_pub unconditionally to tez_out. So a fixture with
    /// all-tez inputs and asset_pub = non-tez balanced fine on the
    /// tez lane (because v_pub went there) while the primary lane
    /// trivially balanced at 0 == 0 — letting the kernel emit an
    /// outbox burn for v_pub units of a token the prover never
    /// deposited.
    ///
    /// The fix routes v_pub through whichever accumulator its
    /// asset_pub belongs to AND asserts asset_pub ∈ {tez, primary}.
    /// This test constructs the original exploit (all-tez inputs,
    /// non-tez asset_pub, primary_non_tez_asset = asset_pub) with a
    /// fresh signature so the WOTS sighash check passes — meaning
    /// the failure can only come from the per-asset balance
    /// constraint we just added.
    ///
    /// In this fixture's specific configuration the tez side fails
    /// first: the original two-input fixture had v_in = v_change +
    /// v_fee + fee + v_pub (i.e. v_pub was funded by tez inputs).
    /// Once we re-route v_pub off the tez lane, tez_in stays at 80
    /// but tez_out drops by 47 (the v_pub amount), so the tez
    /// balance assertion catches it before the primary lane is
    /// even checked. Either failure proves the attack is rejected
    /// — both are part of the same per-asset-balance invariant.
    #[test]
    #[should_panic(expected: ('unshield: tez balance',))]
    fn test_unshield_rejects_non_tez_v_pub_with_only_tez_inputs() {
        // Start from the pure-tez two-input fixture (all inputs +
        // change + fee in tez). Repoint asset_pub at a synthetic
        // primary asset and set primary_non_tez_asset to the same
        // value so the in-pair check on asset_pub passes. Then
        // re-sign so WOTS verifies. With the fix in place, the
        // per-asset balance assertion catches the attempted mint:
        // primary_in = 0 (no primary inputs) but primary_out =
        // v_pub > 0 (v_pub got routed to the primary lane).
        let primary = 0xFA2B1A5E;
        let mut fixture = build_two_input_fixture();
        fixture.asset_pub = primary;
        fixture.primary_non_tez_asset = primary;
        // v_change_2 was zero in the base fixture; everything else
        // stays as-is so tez_in == tez_out + fee remains true on
        // the tez lane.
        let new_sighash = unshield_sighash(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.v_pub,
            fixture.asset_pub,
            fixture.fee,
            fixture.recipient,
            change_commitment_or_zero(
                fixture.has_change,
                fixture.d_j_change,
                fixture.v_change,
                fixture.asset_change,
                fixture.rseed_change,
                fixture.auth_root_change,
                fixture.auth_pub_seed_change,
                fixture.nk_tag_change,
                fixture.memo_ct_hash_change,
            ),
            fixture.memo_ct_hash_change,
            0,
            0,
            note_commitment(
                fixture.d_j_fee,
                fixture.v_fee,
                fixture.rseed_fee,
                fixture.auth_root_fee,
                fixture.auth_pub_seed_fee,
                fixture.nk_tag_fee,
            ),
            fixture.memo_ct_hash_fee,
        );
        let sig_0 = sign_unshield_input(new_sighash, 0x9102, 0_u32, 0x9200);
        let sig_1 = sign_unshield_input(new_sighash, 0x9102, 1_u32, 0x9300);
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
        fixture.wots_sig_flat = wots_sig_flat;
        run_verify(@fixture);
    }

    /// Closely-related: if asset_pub is set to a third asset
    /// (neither tez nor primary_non_tez_asset), the in-pair check
    /// rejects it BEFORE the balance accountant gets a chance.
    /// Without this layer, a prover could create a synthetic
    /// "rogue" asset_pub that's not in the registered FA2 set at
    /// the kernel layer; the kernel would catch it in
    /// `ticketer_for_asset`, but having defense-in-depth at the
    /// Cairo layer means the proof itself is rejected, never even
    /// reaching the kernel.
    #[test]
    #[should_panic(expected: ('unshield: bad asset_pub',))]
    fn test_unshield_rejects_third_asset_in_asset_pub() {
        let primary = 0xFA2B1A5E;
        let rogue = 0xC0FFEE;
        let mut fixture = build_two_input_fixture();
        fixture.primary_non_tez_asset = primary;
        fixture.asset_pub = rogue;
        let new_sighash = unshield_sighash(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.v_pub,
            fixture.asset_pub,
            fixture.fee,
            fixture.recipient,
            change_commitment_or_zero(
                fixture.has_change,
                fixture.d_j_change,
                fixture.v_change,
                fixture.asset_change,
                fixture.rseed_change,
                fixture.auth_root_change,
                fixture.auth_pub_seed_change,
                fixture.nk_tag_change,
                fixture.memo_ct_hash_change,
            ),
            fixture.memo_ct_hash_change,
            0,
            0,
            note_commitment(
                fixture.d_j_fee,
                fixture.v_fee,
                fixture.rseed_fee,
                fixture.auth_root_fee,
                fixture.auth_pub_seed_fee,
                fixture.nk_tag_fee,
            ),
            fixture.memo_ct_hash_fee,
        );
        let sig_0 = sign_unshield_input(new_sighash, 0x9102, 0_u32, 0x9200);
        let sig_1 = sign_unshield_input(new_sighash, 0x9102, 1_u32, 0x9300);
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
        fixture.wots_sig_flat = wots_sig_flat;
        run_verify(@fixture);
    }

    /// asset_fee (producer) must be ASSET_TEZ — permanent constraint.
    #[test]
    #[should_panic(expected: ('unshield: producer must be tez',))]
    fn test_unshield_rejects_non_tez_producer_asset() {
        let mut fixture = build_fixture();
        fixture.asset_fee = 0xCAFEBABE;
        run_verify(@fixture);
    }

    /// asset_change (slot 1) must be in {tez, primary}.
    #[test]
    #[should_panic(expected: ('unshield: bad asset_change',))]
    fn test_unshield_rejects_change_1_asset_outside_pair() {
        let mut fixture = build_fixture();
        // Force has_change = true so the slot has a real asset to check.
        fixture.has_change = true;
        fixture.primary_non_tez_asset = 0xA;
        fixture.asset_change = 0xB;
        run_verify(@fixture);
    }

    /// asset_change_2 (slot 2) must be in {tez, primary}.
    #[test]
    #[should_panic(expected: ('unshield: bad asset_change_2',))]
    fn test_unshield_rejects_change_2_asset_outside_pair() {
        let mut fixture = build_fixture();
        fixture.has_change_2 = true;
        fixture.primary_non_tez_asset = 0xA;
        fixture.asset_change_2 = 0xC;
        run_verify(@fixture);
    }

    /// Per-input asset must be in {tez, primary}.
    #[test]
    #[should_panic(expected: ('unshield: bad input asset',))]
    fn test_unshield_rejects_input_asset_outside_pair() {
        let mut fixture = build_fixture();
        fixture.primary_non_tez_asset = 0xA;
        fixture.input_asset_list = array![0xB];
        run_verify(@fixture);
    }

    // Multiasset Phase B positive coverage. Same reasoning as
    // transfer.cairo's mixed-asset block: the negative tests above only
    // confirm rejections; without these positive cases the
    // 2-accumulator per-asset balance could be silently bypassed and
    // the suite would still go green.
    //
    // Layout: input 0 carries tez (covers fee + producer + tez public
    // exit + tez change), input 1 carries primary (refunded in
    // change_1). Public exit is pinned to tez by the v1 single-bridge
    // constraint so the only legal way to spend primary in an unshield
    // is via the change slots.
    fn build_mixed_asset_two_input_fixture(primary: felt252) -> UnshieldFixture {
        let auth_domain = 0xB101;
        let auth_pub_seed = 0xB102;

        let auth_idx_0 = 0_u32;
        let auth_idx_1 = 1_u32;
        let key_base_0 = 0xB200;
        let key_base_1 = 0xB300;

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
            upper_auth_siblings.append(hash::hash1(auth_level.into() + 0xB400));
            auth_level += 1;
        }
        let mut auth_siblings_0: Array<felt252> = array![leaf_1];
        let mut auth_siblings_1: Array<felt252> = array![leaf_0];
        let mut ai: u32 = 0;
        while ai < upper_auth_siblings.len() {
            auth_siblings_0.append(*upper_auth_siblings.at(ai));
            auth_siblings_1.append(*upper_auth_siblings.at(ai));
            ai += 1;
        }
        let auth_root = auth_root_from_leaf(
            leaf_0, auth_pub_seed, auth_idx_0, auth_siblings_0.span(),
        );

        let nk_spend_0 = 0xB501;
        let nk_spend_1 = 0xB502;
        let d_j_in_0 = 0xB503;
        let d_j_in_1 = 0xB504;
        let v_in_0 = 45_u64;
        let v_in_1 = 35_u64;
        let rseed_in_0 = 0xB505;
        let rseed_in_1 = 0xB506;

        // Input 0: tez. Input 1: primary.
        let rcm_in_0 = hash::derive_rcm(rseed_in_0);
        let otag_in_0 = hash::owner_tag(
            auth_root, auth_pub_seed, hash::derive_nk_tag(nk_spend_0),
        );
        let cm_0 = hash::commit(d_j_in_0, v_in_0, ASSET_TEZ, rcm_in_0, otag_in_0);

        let rcm_in_1 = hash::derive_rcm(rseed_in_1);
        let otag_in_1 = hash::owner_tag(
            auth_root, auth_pub_seed, hash::derive_nk_tag(nk_spend_1),
        );
        let cm_1_in = hash::commit(d_j_in_1, v_in_1, primary, rcm_in_1, otag_in_1);

        let mut upper_cm_siblings: Array<felt252> = array![];
        let mut tree_level: u32 = 1;
        while tree_level < merkle::TREE_DEPTH {
            upper_cm_siblings.append(hash::hash1(tree_level.into() + 0xB600));
            tree_level += 1;
        }
        let mut cm_siblings_0: Array<felt252> = array![cm_1_in];
        let mut cm_siblings_1: Array<felt252> = array![cm_0];
        let mut cs: u32 = 0;
        while cs < upper_cm_siblings.len() {
            cm_siblings_0.append(*upper_cm_siblings.at(cs));
            cm_siblings_1.append(*upper_cm_siblings.at(cs));
            cs += 1;
        }

        let root = merkle_root_from_path(cm_0, cm_siblings_0.span(), 0);
        let nf_0 = hash::nullifier(nk_spend_0, cm_0, 0);
        let nf_1 = hash::nullifier(nk_spend_1, cm_1_in, 1);

        // Balance:
        //   tez_in     = 45
        //   tez_out    = v_fee (3) + v_pub (10) + v_change_2 (27 tez) = 40
        //                (change_1 is primary so excluded from tez lane)
        //   fee        = 5; 45 == 40 + 5 ✓
        //   primary_in = 35
        //   primary_out = v_change (35 primary) = 35 ✓
        let v_pub = 10_u64;
        let fee = 5_u64;
        let v_fee = 3_u64;
        let recipient = 0xB701;

        // change_1: asset = primary, value = 35 (refund of input 1).
        let has_change = true;
        let d_j_change = 0xB702;
        let v_change = 35_u64;
        let rseed_change = 0xB703;
        let auth_root_change = 0xB704;
        let auth_pub_seed_change = 0xB705;
        let nk_tag_change = 0xB706;
        let memo_ct_hash_change = 0xB707;
        let cm_change = change_commitment_or_zero(
            has_change,
            d_j_change,
            v_change,
            primary,
            rseed_change,
            auth_root_change,
            auth_pub_seed_change,
            nk_tag_change,
            memo_ct_hash_change,
        );

        // change_2: asset = tez, value = 27 (leftover tez after exit + fees).
        let has_change_2 = true;
        let d_j_change_2 = 0xB712;
        let v_change_2 = 27_u64;
        let rseed_change_2 = 0xB713;
        let auth_root_change_2 = 0xB714;
        let auth_pub_seed_change_2 = 0xB715;
        let nk_tag_change_2 = 0xB716;
        let memo_ct_hash_change_2 = 0xB717;
        let cm_change_2 = change_commitment_or_zero(
            has_change_2,
            d_j_change_2,
            v_change_2,
            ASSET_TEZ,
            rseed_change_2,
            auth_root_change_2,
            auth_pub_seed_change_2,
            nk_tag_change_2,
            memo_ct_hash_change_2,
        );

        let d_j_fee = 0xB722;
        let rseed_fee = 0xB723;
        let auth_root_fee = 0xB724;
        let auth_pub_seed_fee = 0xB725;
        let nk_tag_fee = 0xB726;
        let memo_ct_hash_fee = 0xB727;
        let cm_fee = note_commitment(
            d_j_fee, v_fee, rseed_fee, auth_root_fee, auth_pub_seed_fee, nk_tag_fee,
        );

        let nf_list: Array<felt252> = array![nf_0, nf_1];
        let sighash = unshield_sighash(
            auth_domain,
            root,
            nf_list.span(),
            v_pub,
            ASSET_TEZ,
            fee,
            recipient,
            cm_change,
            memo_ct_hash_change,
            cm_change_2,
            memo_ct_hash_change_2,
            cm_fee,
            memo_ct_hash_fee,
        );

        let sig_0 = sign_unshield_input(sighash, auth_pub_seed, auth_idx_0, key_base_0);
        let sig_1 = sign_unshield_input(sighash, auth_pub_seed, auth_idx_1, key_base_1);
        let mut wots_sig_flat: Array<felt252> = array![];
        let mut sk: u32 = 0;
        while sk < sig_0.len() {
            wots_sig_flat.append(*sig_0.at(sk));
            sk += 1;
        }
        let mut sl: u32 = 0;
        while sl < sig_1.len() {
            wots_sig_flat.append(*sig_1.at(sl));
            sl += 1;
        }

        let mut cm_siblings_flat: Array<felt252> = array![];
        let mut cp: u32 = 0;
        while cp < cm_siblings_0.len() {
            cm_siblings_flat.append(*cm_siblings_0.at(cp));
            cp += 1;
        }
        let mut cq: u32 = 0;
        while cq < cm_siblings_1.len() {
            cm_siblings_flat.append(*cm_siblings_1.at(cq));
            cq += 1;
        }

        let mut auth_siblings_flat: Array<felt252> = array![];
        let mut ar: u32 = 0;
        while ar < auth_siblings_0.len() {
            auth_siblings_flat.append(*auth_siblings_0.at(ar));
            ar += 1;
        }
        let mut at: u32 = 0;
        while at < auth_siblings_1.len() {
            auth_siblings_flat.append(*auth_siblings_1.at(at));
            at += 1;
        }

        UnshieldFixture {
            auth_domain,
            root,
            nf_list,
            v_pub,
            fee,
            recipient,
            nk_spend_list: array![nk_spend_0, nk_spend_1],
            auth_root_list: array![auth_root, auth_root],
            auth_pub_seed_list: array![auth_pub_seed, auth_pub_seed],
            wots_sig_flat,
            auth_siblings_flat,
            auth_index_list: array![auth_idx_0, auth_idx_1],
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
            d_j_fee,
            v_fee,
            rseed_fee,
            auth_root_fee,
            auth_pub_seed_fee,
            nk_tag_fee,
            memo_ct_hash_fee,
            has_change_2,
            d_j_change_2,
            v_change_2,
            rseed_change_2,
            auth_root_change_2,
            auth_pub_seed_change_2,
            nk_tag_change_2,
            memo_ct_hash_change_2,
            input_asset_list: array![ASSET_TEZ, primary],
            asset_change: primary,
            asset_change_2: ASSET_TEZ,
            asset_fee: ASSET_TEZ,
            asset_pub: ASSET_TEZ,
            primary_non_tez_asset: primary,
        }
    }

    /// Positive: mixed-asset unshield. Primary refunded via change_1,
    /// tez leftover via change_2, asset_pub pinned to tez. Both
    /// accumulators carry non-zero balances.
    #[test]
    fn test_unshield_accepts_mixed_assets_primary_refund_via_change_1() {
        let primary = 0xFA2F0001;
        let fixture = build_mixed_asset_two_input_fixture(primary);
        let outputs = run_verify(@fixture);
        // Public output layout: auth_domain, root, nf_0, nf_1, v_pub,
        // asset_pub, fee, recipient, cm_change, mh_change,
        // cm_change_2, mh_change_2, cm_fee, mh_fee → 14 entries for n=2.
        assert(outputs.len() == 14, 'unshield mixed outputs len');
        assert(*outputs.at(5) == fixture.asset_pub, 'unshield mixed out asset_pub');
        assert(*outputs.at(4) == fixture.v_pub.into(), 'unshield mixed out v_pub');
    }

    /// Positive: swap which change slot carries the primary refund.
    /// change_1 becomes tez and change_2 becomes primary. The
    /// 2-accumulator constraint should accept the mirrored layout.
    #[test]
    fn test_unshield_accepts_primary_refund_via_change_2() {
        let primary = 0xFA2F0002;
        let mut fixture = build_mixed_asset_two_input_fixture(primary);
        // Swap the asset+value of the two change slots, then rebuild
        // both commitments and re-sign.
        let v_c1 = fixture.v_change;
        let v_c2 = fixture.v_change_2;
        fixture.v_change = v_c2;
        fixture.v_change_2 = v_c1;
        fixture.asset_change = ASSET_TEZ;
        fixture.asset_change_2 = primary;

        let new_cm_change = change_commitment_or_zero(
            fixture.has_change,
            fixture.d_j_change,
            fixture.v_change,
            fixture.asset_change,
            fixture.rseed_change,
            fixture.auth_root_change,
            fixture.auth_pub_seed_change,
            fixture.nk_tag_change,
            fixture.memo_ct_hash_change,
        );
        let new_cm_change_2 = change_commitment_or_zero(
            fixture.has_change_2,
            fixture.d_j_change_2,
            fixture.v_change_2,
            fixture.asset_change_2,
            fixture.rseed_change_2,
            fixture.auth_root_change_2,
            fixture.auth_pub_seed_change_2,
            fixture.nk_tag_change_2,
            fixture.memo_ct_hash_change_2,
        );
        let cm_fee = note_commitment(
            fixture.d_j_fee,
            fixture.v_fee,
            fixture.rseed_fee,
            fixture.auth_root_fee,
            fixture.auth_pub_seed_fee,
            fixture.nk_tag_fee,
        );
        let new_sighash = unshield_sighash(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.v_pub,
            fixture.asset_pub,
            fixture.fee,
            fixture.recipient,
            new_cm_change,
            fixture.memo_ct_hash_change,
            new_cm_change_2,
            fixture.memo_ct_hash_change_2,
            cm_fee,
            fixture.memo_ct_hash_fee,
        );
        let sig_0 = sign_unshield_input(new_sighash, 0xB102, 0_u32, 0xB200);
        let sig_1 = sign_unshield_input(new_sighash, 0xB102, 1_u32, 0xB300);
        let mut wots_sig_flat: Array<felt252> = array![];
        let mut sk: u32 = 0;
        while sk < sig_0.len() {
            wots_sig_flat.append(*sig_0.at(sk));
            sk += 1;
        }
        let mut sl: u32 = 0;
        while sl < sig_1.len() {
            wots_sig_flat.append(*sig_1.at(sl));
            sl += 1;
        }
        fixture.wots_sig_flat = wots_sig_flat;
        run_verify(@fixture);
    }

    /// Positive: degenerate case where primary_non_tez_asset ==
    /// ASSET_TEZ. The two accumulators merge into the single tez lane.
    /// Same regime the pure-tez tests already cover, asserted here
    /// explicitly so a refactor cannot silently disable the
    /// `primary_in == primary_out` check by short-circuiting when the
    /// two assets are equal.
    #[test]
    fn test_unshield_accepts_degenerate_primary_equals_tez() {
        let fixture = build_two_input_fixture();
        let _outputs = run_verify(@fixture);
    }

    /// Positive: primary_non_tez_asset is non-tez but no input or
    /// output uses it. Both primary accumulators stay at zero and the
    /// proof verifies. Guards against a regression that would require
    /// primary_in or primary_out to be strictly positive once primary
    /// differs from tez.
    #[test]
    fn test_unshield_accepts_unused_primary_asset() {
        let mut fixture = build_two_input_fixture();
        fixture.primary_non_tez_asset = 0xFEEDFACE;
        run_verify(@fixture);
    }

    /// Negative: flip change_1's asset tag to tez without recomputing
    /// the commitment (cm_change was committed to primary). The
    /// change_commitment_or_zero recompute uses fixture.asset_change so
    /// the cm we recompute won't match what the sighash bound. The
    /// fastest-firing check is the WOTS signature recovery (sighash
    /// changes, recovered key won't match the leaf).
    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_unshield_rejects_change_1_asset_flipped() {
        let primary = 0xFA2F0003;
        let mut fixture = build_mixed_asset_two_input_fixture(primary);
        fixture.asset_change = ASSET_TEZ;
        run_verify(@fixture);
    }

    /// Negative: flip the input asset tag at position 1 from primary
    /// to tez. The per-input loop recomputes commit(d_j, v, tez, …)
    /// which won't match the committed leaf in the cm-tree.
    #[test]
    #[should_panic(expected: ('merkle root mismatch',))]
    fn test_unshield_rejects_input_asset_tag_flipped() {
        let primary = 0xFA2F0004;
        let mut fixture = build_mixed_asset_two_input_fixture(primary);
        fixture.input_asset_list = array![ASSET_TEZ, ASSET_TEZ];
        run_verify(@fixture);
    }

    /// Negative: drop the public exit to 0 and keep the rest. The tez
    /// lane now has 45 in vs 40 - 10 + 0 = 30 out + 5 fee → 35.
    /// 45 ≠ 35 so the tez balance constraint fires.
    #[test]
    #[should_panic(expected: ('unshield: tez balance',))]
    fn test_unshield_rejects_silent_v_pub_drop() {
        let primary = 0xFA2F0005;
        let mut fixture = build_mixed_asset_two_input_fixture(primary);
        fixture.v_pub = 0_u64;
        // Re-sign so the WOTS check passes and we hit the balance
        // assertion specifically.
        let cm_change = change_commitment_or_zero(
            fixture.has_change,
            fixture.d_j_change,
            fixture.v_change,
            fixture.asset_change,
            fixture.rseed_change,
            fixture.auth_root_change,
            fixture.auth_pub_seed_change,
            fixture.nk_tag_change,
            fixture.memo_ct_hash_change,
        );
        let cm_change_2 = change_commitment_or_zero(
            fixture.has_change_2,
            fixture.d_j_change_2,
            fixture.v_change_2,
            fixture.asset_change_2,
            fixture.rseed_change_2,
            fixture.auth_root_change_2,
            fixture.auth_pub_seed_change_2,
            fixture.nk_tag_change_2,
            fixture.memo_ct_hash_change_2,
        );
        let cm_fee = note_commitment(
            fixture.d_j_fee,
            fixture.v_fee,
            fixture.rseed_fee,
            fixture.auth_root_fee,
            fixture.auth_pub_seed_fee,
            fixture.nk_tag_fee,
        );
        let new_sighash = unshield_sighash(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.v_pub,
            fixture.asset_pub,
            fixture.fee,
            fixture.recipient,
            cm_change,
            fixture.memo_ct_hash_change,
            cm_change_2,
            fixture.memo_ct_hash_change_2,
            cm_fee,
            fixture.memo_ct_hash_fee,
        );
        let sig_0 = sign_unshield_input(new_sighash, 0xB102, 0_u32, 0xB200);
        let sig_1 = sign_unshield_input(new_sighash, 0xB102, 1_u32, 0xB300);
        let mut wots_sig_flat: Array<felt252> = array![];
        let mut sk: u32 = 0;
        while sk < sig_0.len() {
            wots_sig_flat.append(*sig_0.at(sk));
            sk += 1;
        }
        let mut sl: u32 = 0;
        while sl < sig_1.len() {
            wots_sig_flat.append(*sig_1.at(sl));
            sl += 1;
        }
        fixture.wots_sig_flat = wots_sig_flat;
        run_verify(@fixture);
    }
}
