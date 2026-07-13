/// Transfer circuit: N→4 JoinSplit (1 ≤ N ≤ 7).
///
/// Phase C output layout — four output slots:
///   slot 1 (cm_1): recipient note, asset = `asset_recipient` (witness-chosen
///                  from {ASSET_TEZ, primary_non_tez_asset})
///   slot 2 (cm_2): change_1 (same asset as recipient, or pure-tez refund)
///   slot 3 (cm_3): change_2 (the OTHER asset under the 2-accumulator design;
///                  zero-value placeholder for single-asset transfers)
///   slot 4 (cm_4): producer-fee note (asset MUST equal ASSET_TEZ — see
///                  Multiasset rationale in specs/rationale.md)
///
/// # Public outputs
///   [auth_domain, root, nf_0..nf_{N-1}, fee, cm_1, cm_2, cm_3, cm_4,
///    memo_ct_hash_1, memo_ct_hash_2, memo_ct_hash_3, memo_ct_hash_4]
///
/// Length is `2 + N + 9` felts (auth_domain + root + N nullifiers + fee +
/// 4 cms + 4 memo hashes).
///
/// # Multiasset constraints
///   Every input and every output carries an asset tag in the commitment
///   preimage. The witness declares one primary non-tez asset `A`; each
///   input/output asset is constrained to lie in {ASSET_TEZ, A}. Two
///   accumulators (`tez_in/tez_out`, `primary_in/primary_out`) close the
///   per-asset balance; only the burned `fee` enters `tez_out` directly.
///
/// # Spend authorization
///   XMSS-style WOTS+ w=4 signature verification inside the STARK.
///   The circuit recovers the 133 WOTS public-key endpoints from the signature,
///   compresses them with an XMSS L-tree, and authenticates that exact leaf under
///   the witness `(auth_root, auth_pub_seed)` public key. Asset binding to
///   the sighash is transitive via `cm_k` (which commits to asset_k);
///   `asset_k` itself is NOT public, only the commitments are.

use tzel::blake_hash as hash;
use tzel::{merkle, xmss_common};
use tzel::ASSET_TEZ;

const MAX_INPUTS: u32 = 7;

pub fn verify(
    auth_domain: felt252,
    root: felt252,
    nf_list: Span<felt252>,
    fee: u64,
    // Phase C: N→4 layout. Output positions: 1=recipient,
    // 2=change_1, 3=change_2, 4=producer-fee. The producer fee is
    // pinned to ASSET_TEZ and must be > 0. The two change slots are
    // free-form (any asset in {ASSET_TEZ, primary_non_tez_asset}).
    cm_1: felt252,
    cm_2: felt252,
    cm_3: felt252,
    cm_4: felt252,
    nk_spend_list: Span<felt252>,
    auth_root_list: Span<felt252>,
    auth_pub_seed_list: Span<felt252>,
    auth_index_list: Span<u32>,
    d_j_in_list: Span<felt252>,
    v_in_list: Span<u64>,
    rseed_in_list: Span<felt252>,
    cm_siblings_flat: Span<felt252>,
    auth_siblings_flat: Span<felt252>,
    cm_path_indices_list: Span<u64>,
    wots_sig_flat: Span<felt252>,
    // Multiasset (Phase B): per-input asset tag; each input is required
    // to be either tez or a single witness-supplied non-tez asset.
    input_asset_list: Span<felt252>,
    d_j_1: felt252,
    v_1: u64,
    rseed_1: felt252,
    auth_root_1: felt252,
    auth_pub_seed_1: felt252,
    nk_tag_1: felt252,
    memo_ct_hash_1: felt252,
    asset_1: felt252,
    d_j_2: felt252,
    v_2: u64,
    rseed_2: felt252,
    auth_root_2: felt252,
    auth_pub_seed_2: felt252,
    nk_tag_2: felt252,
    memo_ct_hash_2: felt252,
    asset_2: felt252,
    d_j_3: felt252,
    v_3: u64,
    rseed_3: felt252,
    auth_root_3: felt252,
    auth_pub_seed_3: felt252,
    nk_tag_3: felt252,
    memo_ct_hash_3: felt252,
    asset_3: felt252,
    d_j_4: felt252,
    v_4: u64,
    rseed_4: felt252,
    auth_root_4: felt252,
    auth_pub_seed_4: felt252,
    nk_tag_4: felt252,
    memo_ct_hash_4: felt252,
    asset_4: felt252,
    // 2-accumulator multiasset balance witness: every input and output
    // asset must be in {ASSET_TEZ, primary_non_tez_asset}. For pure-tez
    // transactions, primary_non_tez_asset may be any value (no constraint
    // will reference it because no input/output asset will match it
    // unless it equals ASSET_TEZ, in which case the constraint is
    // trivially satisfied).
    primary_non_tez_asset: felt252,
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
    assert(input_asset_list.len() == n, 'transfer: asset list len');
    assert(cm_siblings_flat.len() == n * merkle::TREE_DEPTH, 'transfer: cm_sibs len');
    assert(auth_siblings_flat.len() == n * merkle::AUTH_DEPTH, 'transfer: auth_sibs len');
    assert(wots_sig_flat.len() == n * xmss_common::WOTS_CHAINS, 'transfer: wots sig len');
    // Phase C: producer-fee output is now slot 4. It must be tez so the
    // DAL slot publisher can monetize it regardless of the transfer's
    // primary asset. Permanent (not v1-only).
    assert(asset_4 == ASSET_TEZ, 'transfer: producer must be tez');

    let mut sighash = hash::sighash_fold(0x01, auth_domain);
    sighash = hash::sighash_fold(sighash, root);
    let mut si: u32 = 0;
    while si < n {
        sighash = hash::sighash_fold(sighash, *nf_list.at(si));
        si += 1;
    }
    sighash = hash::sighash_fold(sighash, fee.into());
    sighash = hash::sighash_fold(sighash, cm_1);
    sighash = hash::sighash_fold(sighash, cm_2);
    sighash = hash::sighash_fold(sighash, cm_3);
    sighash = hash::sighash_fold(sighash, cm_4);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_1);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_2);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_3);
    sighash = hash::sighash_fold(sighash, memo_ct_hash_4);

    // 2-accumulator per-asset balance: tez_in / tez_out accumulate
    // contributions whose asset == ASSET_TEZ; primary_in / primary_out
    // accumulate contributions whose asset == primary_non_tez_asset.
    // Every input/output asset must be in {ASSET_TEZ, primary_non_tez_asset}.
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

        // Asset must be either tez or the single witness-declared
        // non-tez asset. This is the 2-accumulator constraint that
        // implements the spec's per-asset balance.
        assert(
            asset_i == ASSET_TEZ || asset_i == primary_non_tez_asset,
            'transfer: bad input asset',
        );

        let nk_tag = hash::derive_nk_tag(nk_spend);
        let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
        let rcm = hash::derive_rcm(rseed);
        let cm = hash::commit(d_j, v, asset_i, rcm, otag);

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
        if asset_i == ASSET_TEZ {
            tez_in += v.into();
        } else {
            primary_in += v.into();
        }
        i += 1;
    }

    // Output 1 (recipient): asset must be in {tez, primary}.
    assert(
        asset_1 == ASSET_TEZ || asset_1 == primary_non_tez_asset,
        'transfer: bad asset_1',
    );
    let rcm_1 = hash::derive_rcm(rseed_1);
    let otag_1 = hash::owner_tag(auth_root_1, auth_pub_seed_1, nk_tag_1);
    assert(
        hash::commit(d_j_1, v_1, asset_1, rcm_1, otag_1) == cm_1,
        'transfer: bad cm_1',
    );

    // Output 2 (change): asset must be in {tez, primary}.
    assert(
        asset_2 == ASSET_TEZ || asset_2 == primary_non_tez_asset,
        'transfer: bad asset_2',
    );
    let rcm_2 = hash::derive_rcm(rseed_2);
    let otag_2 = hash::owner_tag(auth_root_2, auth_pub_seed_2, nk_tag_2);
    assert(
        hash::commit(d_j_2, v_2, asset_2, rcm_2, otag_2) == cm_2,
        'transfer: bad cm_2',
    );

    // Output 3 (change_2): asset must be in {tez, primary}.
    assert(
        asset_3 == ASSET_TEZ || asset_3 == primary_non_tez_asset,
        'transfer: bad asset_3',
    );
    let rcm_3 = hash::derive_rcm(rseed_3);
    let otag_3 = hash::owner_tag(auth_root_3, auth_pub_seed_3, nk_tag_3);
    assert(
        hash::commit(d_j_3, v_3, asset_3, rcm_3, otag_3) == cm_3,
        'transfer: bad cm_3',
    );

    // Output 4 (producer fee): asset pinned to tez above; reconstruct cm.
    let rcm_4 = hash::derive_rcm(rseed_4);
    let otag_4 = hash::owner_tag(auth_root_4, auth_pub_seed_4, nk_tag_4);
    assert(
        hash::commit(d_j_4, v_4, asset_4, rcm_4, otag_4) == cm_4,
        'transfer: bad cm_4',
    );

    assert(v_4 > 0_u64, 'transfer prod fee');

    // Tally outputs into the per-asset accumulators.
    let mut tez_out: u128 = v_4.into(); // asset_4 == ASSET_TEZ (producer)
    let mut primary_out: u128 = 0;
    if asset_1 == ASSET_TEZ {
        tez_out += v_1.into();
    } else {
        primary_out += v_1.into();
    }
    if asset_2 == ASSET_TEZ {
        tez_out += v_2.into();
    } else {
        primary_out += v_2.into();
    }
    if asset_3 == ASSET_TEZ {
        tez_out += v_3.into();
    } else {
        primary_out += v_3.into();
    }

    // Per-asset balance: tez accumulator covers the public fee, the
    // primary non-tez accumulator must balance exactly (no public fee
    // possible in a non-tez asset — the L1 ledger only knows mutez).
    assert(tez_in == tez_out + fee.into(), 'transfer: tez balance');
    assert(primary_in == primary_out, 'transfer: primary balance');

    let mut outputs: Array<felt252> = array![auth_domain, root];
    let mut j: u32 = 0;
    while j < n {
        outputs.append(*nf_list.at(j));
        j += 1;
    }
    outputs.append(fee.into());
    outputs.append(cm_1);
    outputs.append(cm_2);
    outputs.append(cm_3);
    outputs.append(cm_4);
    outputs.append(memo_ct_hash_1);
    outputs.append(memo_ct_hash_2);
    outputs.append(memo_ct_hash_3);
    outputs.append(memo_ct_hash_4);
    outputs
}

#[cfg(test)]
mod tests {
    use tzel::{blake_hash as hash, merkle, xmss_common};
    use tzel::ASSET_TEZ;
    use super::verify;

    const TAG_XMSS_TREE_TEST: felt252 = 0x72742D73736D78;

    #[derive(Drop)]
    struct TransferFixture {
        auth_domain: felt252,
        root: felt252,
        nf_list: Array<felt252>,
        fee: u64,
        nk_spend_list: Array<felt252>,
        auth_root_list: Array<felt252>,
        auth_pub_seed_list: Array<felt252>,
        auth_index_list: Array<u32>,
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
        cm_3: felt252,
        d_j_3: felt252,
        v_3: u64,
        rseed_3: felt252,
        auth_root_3: felt252,
        auth_pub_seed_3: felt252,
        nk_tag_3: felt252,
        memo_ct_hash_3: felt252,
        // Phase C: 4th output (producer fee).
        cm_4: felt252,
        d_j_4: felt252,
        v_4: u64,
        rseed_4: felt252,
        auth_root_4: felt252,
        auth_pub_seed_4: felt252,
        nk_tag_4: felt252,
        memo_ct_hash_4: felt252,
        // Multiasset Phase B
        input_asset_list: Array<felt252>,
        asset_1: felt252,
        asset_2: felt252,
        asset_3: felt252,
        asset_4: felt252,
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
        hash::commit(d_j, v, ASSET_TEZ, rcm, otag)
    }

    fn transfer_sighash(
        auth_domain: felt252,
        root: felt252,
        nf_list: Span<felt252>,
        fee: u64,
        cm_1: felt252,
        cm_2: felt252,
        cm_3: felt252,
        cm_4: felt252,
        memo_ct_hash_1: felt252,
        memo_ct_hash_2: felt252,
        memo_ct_hash_3: felt252,
        memo_ct_hash_4: felt252,
    ) -> felt252 {
        let mut sighash = hash::sighash_fold(0x01, auth_domain);
        sighash = hash::sighash_fold(sighash, root);
        let mut i: u32 = 0;
        while i < nf_list.len() {
            sighash = hash::sighash_fold(sighash, *nf_list.at(i));
            i += 1;
        }
        sighash = hash::sighash_fold(sighash, fee.into());
        sighash = hash::sighash_fold(sighash, cm_1);
        sighash = hash::sighash_fold(sighash, cm_2);
        sighash = hash::sighash_fold(sighash, cm_3);
        sighash = hash::sighash_fold(sighash, cm_4);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_1);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_2);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_3);
        sighash = hash::sighash_fold(sighash, memo_ct_hash_4);
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
        fee: u64,
        cm_1: felt252,
        cm_2: felt252,
        cm_3: felt252,
        cm_4: felt252,
        memo_ct_hash_1: felt252,
        memo_ct_hash_2: felt252,
        memo_ct_hash_3: felt252,
        memo_ct_hash_4: felt252,
        auth_pub_seed: felt252,
        auth_idx: u32,
    ) -> Array<felt252> {
        let sighash = transfer_sighash(
            auth_domain,
            root,
            array![nf].span(),
            fee,
            cm_1,
            cm_2,
            cm_3,
            cm_4,
            memo_ct_hash_1,
            memo_ct_hash_2,
            memo_ct_hash_3,
            memo_ct_hash_4,
        );
        sign_transfer_input(sighash, auth_pub_seed, auth_idx, 0x7500)
    }

    // Phase C: function still accepts (v_in, v_1, v_2, v_3, fee) where v_3
    // is the producer-fee amount (now at output slot 4). The new change_2
    // slot at output position 3 is hardcoded to a zero-value note
    // (asset = tez), keeping the existing test invariants intact while
    // the layout changes to N→4.
    fn build_fixture_with_values_and_fee(
        v_in: u64, v_1: u64, v_2: u64, v_3: u64, fee: u64,
    ) -> TransferFixture {
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

        // Phase C: cm_3 is now change_2 (zero-value pure-tez note).
        let d_j_3 = 0x7AC1;
        let rseed_3 = 0x7AC2;
        let auth_root_3 = 0x7AC3;
        let auth_pub_seed_3 = 0x7AC4;
        let nk_tag_3 = 0x7AC5;
        let memo_ct_hash_3 = 0x7AC6;
        let v_3_change_2: u64 = 0;
        let cm_3 = output_commitment(
            d_j_3, v_3_change_2, rseed_3, auth_root_3, auth_pub_seed_3, nk_tag_3,
        );

        // cm_4 is the producer-fee note (formerly cm_3). The producer-fee
        // amount is the original `v_3` parameter.
        let d_j_4 = 0x7A01;
        let rseed_4 = 0x7A02;
        let auth_root_4 = 0x7A03;
        let auth_pub_seed_4 = 0x7A04;
        let nk_tag_4 = 0x7A05;
        let memo_ct_hash_4 = 0x7A06;
        let cm_4 = output_commitment(d_j_4, v_3, rseed_4, auth_root_4, auth_pub_seed_4, nk_tag_4);

        let wots_sig_flat = sign_transfer_statement(
            auth_domain,
            root,
            nf,
            fee,
            cm_1,
            cm_2,
            cm_3,
            cm_4,
            memo_ct_hash_1,
            memo_ct_hash_2,
            memo_ct_hash_3,
            memo_ct_hash_4,
            auth_pub_seed,
            auth_idx,
        );

        TransferFixture {
            auth_domain,
            root,
            nf_list: array![nf],
            fee,
            nk_spend_list: array![nk_spend],
            auth_root_list: array![auth_root],
            auth_pub_seed_list: array![auth_pub_seed],
            auth_index_list: array![auth_idx],
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
            cm_3,
            d_j_3,
            v_3: v_3_change_2,
            rseed_3,
            auth_root_3,
            auth_pub_seed_3,
            nk_tag_3,
            memo_ct_hash_3,
            // Phase C: 4th output (producer fee, v_3 from param).
            cm_4,
            d_j_4,
            v_4: v_3,
            rseed_4,
            auth_root_4,
            auth_pub_seed_4,
            nk_tag_4,
            memo_ct_hash_4,
            // Multiasset Phase B: pure-tez fixture.
            input_asset_list: array![ASSET_TEZ],
            asset_1: ASSET_TEZ,
            asset_2: ASSET_TEZ,
            asset_3: ASSET_TEZ,
            asset_4: ASSET_TEZ,
            primary_non_tez_asset: ASSET_TEZ,
        }
    }

    fn build_fixture_with_values(v_in: u64, v_1: u64, v_2: u64, v_3: u64) -> TransferFixture {
        let fee = v_in - v_1 - v_2 - v_3;
        build_fixture_with_values_and_fee(v_in, v_1, v_2, v_3, fee)
    }

    fn build_fixture() -> TransferFixture {
        build_fixture_with_values(70_u64, 42_u64, 20_u64, 3_u64)
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
        let auth_root = auth_root_from_leaf(
            leaf_0, auth_pub_seed, auth_idx_0, auth_siblings_0.span(),
        );

        let nk_spend_0 = 0x8C01;
        let nk_spend_1 = 0x8C02;
        let d_j_in_0 = 0x8C03;
        let d_j_in_1 = 0x8C04;
        let v_in_0 = 40_u64;
        let v_in_1 = 30_u64;
        let rseed_in_0 = 0x8C05;
        let rseed_in_1 = 0x8C06;

        let cm_0 = output_commitment(
            d_j_in_0, v_in_0, rseed_in_0, auth_root, auth_pub_seed, hash::derive_nk_tag(nk_spend_0),
        );
        let cm_1_in = output_commitment(
            d_j_in_1, v_in_1, rseed_in_1, auth_root, auth_pub_seed, hash::derive_nk_tag(nk_spend_1),
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
        let fee = 5_u64;
        let v_3 = 3_u64;
        let v_1 = 35_u64;
        let rseed_1 = 0x8E02;
        let auth_root_1 = 0x8E03;
        let auth_pub_seed_1 = 0x8E04;
        let nk_tag_1 = 0x8E05;
        let memo_ct_hash_1 = 0x8E06;
        let cm_1 = output_commitment(d_j_1, v_1, rseed_1, auth_root_1, auth_pub_seed_1, nk_tag_1);

        let d_j_2 = 0x8F01;
        let v_2 = 27_u64;
        let rseed_2 = 0x8F02;
        let auth_root_2 = 0x8F03;
        let auth_pub_seed_2 = 0x8F04;
        let nk_tag_2 = 0x8F05;
        let memo_ct_hash_2 = 0x8F06;
        let cm_2 = output_commitment(d_j_2, v_2, rseed_2, auth_root_2, auth_pub_seed_2, nk_tag_2);

        // Phase C: cm_3 = change_2 (zero-value tez), cm_4 = producer fee.
        let d_j_3 = 0x90C1;
        let rseed_3 = 0x90C2;
        let auth_root_3 = 0x90C3;
        let auth_pub_seed_3 = 0x90C4;
        let nk_tag_3 = 0x90C5;
        let memo_ct_hash_3 = 0x90C6;
        let v_3_change_2: u64 = 0;
        let cm_3 = output_commitment(
            d_j_3, v_3_change_2, rseed_3, auth_root_3, auth_pub_seed_3, nk_tag_3,
        );

        let d_j_4 = 0x9001;
        let rseed_4 = 0x9002;
        let auth_root_4 = 0x9003;
        let auth_pub_seed_4 = 0x9004;
        let nk_tag_4 = 0x9005;
        let memo_ct_hash_4 = 0x9006;
        let cm_4 = output_commitment(d_j_4, v_3, rseed_4, auth_root_4, auth_pub_seed_4, nk_tag_4);

        let nf_list: Array<felt252> = array![nf_0, nf_1];
        let sighash = transfer_sighash(
            auth_domain,
            root,
            nf_list.span(),
            fee,
            cm_1,
            cm_2,
            cm_3,
            cm_4,
            memo_ct_hash_1,
            memo_ct_hash_2,
            memo_ct_hash_3,
            memo_ct_hash_4,
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
            fee,
            nk_spend_list: array![nk_spend_0, nk_spend_1],
            auth_root_list: array![auth_root, auth_root],
            auth_pub_seed_list: array![auth_pub_seed, auth_pub_seed],
            auth_index_list: array![auth_idx_0, auth_idx_1],
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
            cm_3,
            d_j_3,
            v_3: v_3_change_2,
            rseed_3,
            auth_root_3,
            auth_pub_seed_3,
            nk_tag_3,
            memo_ct_hash_3,
            cm_4,
            d_j_4,
            v_4: v_3,
            rseed_4,
            auth_root_4,
            auth_pub_seed_4,
            nk_tag_4,
            memo_ct_hash_4,
            // Multiasset Phase B: pure-tez 2-input fixture.
            input_asset_list: array![ASSET_TEZ, ASSET_TEZ],
            asset_1: ASSET_TEZ,
            asset_2: ASSET_TEZ,
            asset_3: ASSET_TEZ,
            asset_4: ASSET_TEZ,
            primary_non_tez_asset: ASSET_TEZ,
        }
    }

    fn copy_span(values: Span<felt252>) -> Array<felt252> {
        let mut copied: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < values.len() {
            copied.append(*values.at(i));
            i += 1;
        }
        copied
    }

    fn merkle_nodes_at_level(leaves: Span<felt252>, target_level: u32) -> Array<felt252> {
        let mut current = copy_span(leaves);
        let mut level: u32 = 0;
        while level < target_level {
            let mut next: Array<felt252> = array![];
            let mut pair_idx: u32 = 0;
            while pair_idx < current.len() / 2_u32 {
                let left = *current.at(pair_idx * 2_u32);
                let right = *current.at(pair_idx * 2_u32 + 1_u32);
                next.append(hash::hash2(left, right));
                pair_idx += 1;
            }
            current = next;
            level += 1;
        }
        current
    }

    fn auth_nodes_at_level(
        leaves: Span<felt252>, pub_seed: felt252, target_level: u32,
    ) -> Array<felt252> {
        let mut current = copy_span(leaves);
        let mut level: u32 = 0;
        while level < target_level {
            let mut next: Array<felt252> = array![];
            let mut pair_idx: u32 = 0;
            while pair_idx < current.len() / 2_u32 {
                let left = *current.at(pair_idx * 2_u32);
                let right = *current.at(pair_idx * 2_u32 + 1_u32);
                next
                    .append(
                        xmss_common::xmss_node_hash(
                            pub_seed, TAG_XMSS_TREE_TEST, 0, level, pair_idx, left, right,
                        ),
                    );
                pair_idx += 1;
            }
            current = next;
            level += 1;
        }
        current
    }

    fn build_left_aligned_merkle_root_and_paths(
        leaves: Span<felt252>, upper_seed: felt252,
    ) -> (felt252, Array<felt252>) {
        let leaf_count = leaves.len();
        assert(leaf_count != 0, 'transfer test empty leaves');

        let mut width = leaf_count;
        let mut subtree_levels: u32 = 0;
        while width > 1_u32 {
            assert(width % 2_u32 == 0, 'transfer test width odd');
            width /= 2_u32;
            subtree_levels += 1;
        }

        let subtree_root = *merkle_nodes_at_level(leaves, subtree_levels).at(0);
        let mut root = subtree_root;
        let mut level = subtree_levels;
        while level < merkle::TREE_DEPTH {
            let sibling = hash::hash1(level.into() + upper_seed);
            root = hash::hash2(root, sibling);
            level += 1;
        }

        let mut siblings_flat: Array<felt252> = array![];
        let mut leaf_idx: u32 = 0;
        while leaf_idx < leaf_count {
            let mut idx = leaf_idx;
            let mut path_level: u32 = 0;
            while path_level < subtree_levels {
                let nodes = merkle_nodes_at_level(leaves, path_level);
                let sibling_idx = if idx & 1_u32 == 0 {
                    idx + 1_u32
                } else {
                    idx - 1_u32
                };
                siblings_flat.append(*nodes.at(sibling_idx));
                idx /= 2_u32;
                path_level += 1;
            }
            while path_level < merkle::TREE_DEPTH {
                siblings_flat.append(hash::hash1(path_level.into() + upper_seed));
                path_level += 1;
            }
            leaf_idx += 1;
        }

        (root, siblings_flat)
    }

    fn build_left_aligned_auth_root_and_paths(
        leaves: Span<felt252>, pub_seed: felt252, upper_seed: felt252,
    ) -> (felt252, Array<felt252>) {
        let leaf_count = leaves.len();
        assert(leaf_count != 0, 'transfer test empty auth leaves');

        let mut width = leaf_count;
        let mut subtree_levels: u32 = 0;
        while width > 1_u32 {
            assert(width % 2_u32 == 0, 'transfer test auth width odd');
            width /= 2_u32;
            subtree_levels += 1;
        }

        let subtree_root = *auth_nodes_at_level(leaves, pub_seed, subtree_levels).at(0);
        let mut root = subtree_root;
        let mut level = subtree_levels;
        while level < merkle::AUTH_DEPTH {
            let sibling = hash::hash1(level.into() + upper_seed);
            root =
                xmss_common::xmss_node_hash(
                    pub_seed, TAG_XMSS_TREE_TEST, 0, level, 0, root, sibling,
                );
            level += 1;
        }

        let mut siblings_flat: Array<felt252> = array![];
        let mut leaf_idx: u32 = 0;
        while leaf_idx < leaf_count {
            let mut idx = leaf_idx;
            let mut path_level: u32 = 0;
            while path_level < subtree_levels {
                let nodes = auth_nodes_at_level(leaves, pub_seed, path_level);
                let sibling_idx = if idx & 1_u32 == 0 {
                    idx + 1_u32
                } else {
                    idx - 1_u32
                };
                siblings_flat.append(*nodes.at(sibling_idx));
                idx /= 2_u32;
                path_level += 1;
            }
            while path_level < merkle::AUTH_DEPTH {
                siblings_flat.append(hash::hash1(path_level.into() + upper_seed));
                path_level += 1;
            }
            leaf_idx += 1;
        }

        (root, siblings_flat)
    }

    fn next_power_of_two(mut n: u32) -> u32 {
        assert(n != 0, 'transfer test next_pow2 zero');
        let mut width = 1_u32;
        while width < n {
            width *= 2_u32;
        }
        width
    }

    fn take_prefix(values: Span<felt252>, count: u32) -> Array<felt252> {
        let mut out: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < count {
            out.append(*values.at(i));
            i += 1;
        }
        out
    }

    fn build_multi_input_fixture(n_inputs: u32) -> TransferFixture {
        assert(n_inputs != 0, 'transfer test n=0');

        let auth_domain = 0xA001;
        let auth_pub_seed = 0xA002;
        let auth_upper_seed = 0xA100;
        let cm_upper_seed = 0xA200;

        let mut auth_leaves: Array<felt252> = array![];
        let mut nk_spend_list: Array<felt252> = array![];
        let mut auth_index_list: Array<u32> = array![];
        let mut d_j_in_list: Array<felt252> = array![];
        let mut v_in_list: Array<u64> = array![];
        let mut rseed_in_list: Array<felt252> = array![];

        let mut input_idx: u32 = 0;
        while input_idx < n_inputs {
            let key_base = 0xA300 + input_idx.into() * 0x100;
            let mut endpoints: Array<felt252> = array![];
            let mut chain_idx: u32 = 0;
            while chain_idx < xmss_common::WOTS_CHAINS {
                let start = hash::hash1(key_base + chain_idx.into());
                endpoints
                    .append(
                        chain_advance(
                            start, auth_pub_seed, input_idx, chain_idx, xmss_common::WOTS_W - 1,
                        ),
                    );
                chain_idx += 1;
            }
            auth_leaves.append(xmss_common::xmss_ltree(auth_pub_seed, input_idx, endpoints.span()));
            nk_spend_list.append(0xA400 + input_idx.into());
            auth_index_list.append(input_idx);
            d_j_in_list.append(0xA500 + input_idx.into());
            v_in_list.append(20_u64 + input_idx.into());
            rseed_in_list.append(0xA600 + input_idx.into());
            input_idx += 1;
        }

        let padded_inputs = next_power_of_two(n_inputs);
        while auth_leaves.len() < padded_inputs {
            let pad_idx = auth_leaves.len();
            let key_base = 0xAF00 + pad_idx.into() * 0x100;
            let mut endpoints: Array<felt252> = array![];
            let mut chain_idx: u32 = 0;
            while chain_idx < xmss_common::WOTS_CHAINS {
                let start = hash::hash1(key_base + chain_idx.into());
                endpoints
                    .append(
                        chain_advance(
                            start, auth_pub_seed, pad_idx, chain_idx, xmss_common::WOTS_W - 1,
                        ),
                    );
                chain_idx += 1;
            }
            auth_leaves.append(xmss_common::xmss_ltree(auth_pub_seed, pad_idx, endpoints.span()));
        }

        let (auth_root, auth_siblings_full) = build_left_aligned_auth_root_and_paths(
            auth_leaves.span(), auth_pub_seed, auth_upper_seed,
        );
        let auth_siblings_flat = take_prefix(
            auth_siblings_full.span(), n_inputs * merkle::AUTH_DEPTH,
        );

        let mut cm_leaves: Array<felt252> = array![];
        let mut auth_root_list: Array<felt252> = array![];
        let mut auth_pub_seed_list: Array<felt252> = array![];
        let mut cm_path_indices_list: Array<u64> = array![];
        let mut nf_list: Array<felt252> = array![];
        let mut total_in: u64 = 0;
        let mut j: u32 = 0;
        while j < n_inputs {
            let nk_spend = *nk_spend_list.at(j);
            let d_j_in = *d_j_in_list.at(j);
            let v_in = *v_in_list.at(j);
            let rseed_in = *rseed_in_list.at(j);
            let cm_leaf = output_commitment(
                d_j_in, v_in, rseed_in, auth_root, auth_pub_seed, hash::derive_nk_tag(nk_spend),
            );
            cm_leaves.append(cm_leaf);
            auth_root_list.append(auth_root);
            auth_pub_seed_list.append(auth_pub_seed);
            cm_path_indices_list.append(j.into());
            total_in += v_in;
            j += 1;
        }

        while cm_leaves.len() < padded_inputs {
            let pad_idx = cm_leaves.len();
            cm_leaves.append(hash::hash1(cm_upper_seed + 0x5000 + pad_idx.into()));
        }

        let (root, cm_siblings_full) = build_left_aligned_merkle_root_and_paths(
            cm_leaves.span(), cm_upper_seed,
        );
        let cm_siblings_flat = take_prefix(cm_siblings_full.span(), n_inputs * merkle::TREE_DEPTH);

        let mut k: u32 = 0;
        while k < n_inputs {
            nf_list.append(hash::nullifier(*nk_spend_list.at(k), *cm_leaves.at(k), k.into()));
            k += 1;
        }

        let fee = 5_u64;
        let v_3 = 3_u64;
        let v_1 = total_in / 2_u64;
        let v_2 = total_in - v_1 - fee - v_3;

        let d_j_1 = 0xA701;
        let rseed_1 = 0xA702;
        let auth_root_1 = 0xA703;
        let auth_pub_seed_1 = 0xA704;
        let nk_tag_1 = 0xA705;
        let memo_ct_hash_1 = 0xA706;
        let cm_1 = output_commitment(d_j_1, v_1, rseed_1, auth_root_1, auth_pub_seed_1, nk_tag_1);

        let d_j_2 = 0xA801;
        let rseed_2 = 0xA802;
        let auth_root_2 = 0xA803;
        let auth_pub_seed_2 = 0xA804;
        let nk_tag_2 = 0xA805;
        let memo_ct_hash_2 = 0xA806;
        let cm_2 = output_commitment(d_j_2, v_2, rseed_2, auth_root_2, auth_pub_seed_2, nk_tag_2);

        // Phase C: cm_3 = zero-value tez change_2, cm_4 = producer fee.
        let d_j_3 = 0xA9C1;
        let rseed_3 = 0xA9C2;
        let auth_root_3 = 0xA9C3;
        let auth_pub_seed_3 = 0xA9C4;
        let nk_tag_3 = 0xA9C5;
        let memo_ct_hash_3 = 0xA9C6;
        let v_3_change_2: u64 = 0;
        let cm_3 = output_commitment(
            d_j_3, v_3_change_2, rseed_3, auth_root_3, auth_pub_seed_3, nk_tag_3,
        );

        let d_j_4 = 0xA901;
        let rseed_4 = 0xA902;
        let auth_root_4 = 0xA903;
        let auth_pub_seed_4 = 0xA904;
        let nk_tag_4 = 0xA905;
        let memo_ct_hash_4 = 0xA906;
        let cm_4 = output_commitment(d_j_4, v_3, rseed_4, auth_root_4, auth_pub_seed_4, nk_tag_4);

        let sighash = transfer_sighash(
            auth_domain,
            root,
            nf_list.span(),
            fee,
            cm_1,
            cm_2,
            cm_3,
            cm_4,
            memo_ct_hash_1,
            memo_ct_hash_2,
            memo_ct_hash_3,
            memo_ct_hash_4,
        );
        let mut wots_sig_flat: Array<felt252> = array![];
        let mut m: u32 = 0;
        while m < n_inputs {
            let key_base = 0xA300 + m.into() * 0x100;
            let sig = sign_transfer_input(sighash, auth_pub_seed, m, key_base);
            let mut s: u32 = 0;
            while s < sig.len() {
                wots_sig_flat.append(*sig.at(s));
                s += 1;
            }
            m += 1;
        }

        // Multiasset Phase B: pure-tez asset list (length n_inputs).
        let mut input_asset_list: Array<felt252> = array![];
        let mut q: u32 = 0;
        while q < n_inputs {
            input_asset_list.append(ASSET_TEZ);
            q += 1;
        }

        TransferFixture {
            auth_domain,
            root,
            nf_list,
            fee,
            nk_spend_list,
            auth_root_list,
            auth_pub_seed_list,
            auth_index_list,
            d_j_in_list,
            v_in_list,
            rseed_in_list,
            cm_siblings_flat,
            auth_siblings_flat,
            cm_path_indices_list,
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
            cm_3,
            d_j_3,
            v_3: v_3_change_2,
            rseed_3,
            auth_root_3,
            auth_pub_seed_3,
            nk_tag_3,
            memo_ct_hash_3,
            cm_4,
            d_j_4,
            v_4: v_3,
            rseed_4,
            auth_root_4,
            auth_pub_seed_4,
            nk_tag_4,
            memo_ct_hash_4,
            input_asset_list,
            asset_1: ASSET_TEZ,
            asset_2: ASSET_TEZ,
            asset_3: ASSET_TEZ,
            asset_4: ASSET_TEZ,
            primary_non_tez_asset: ASSET_TEZ,
        }
    }

    fn build_duplicate_nf_fixture() -> TransferFixture {
        let base = build_fixture_with_values_and_fee(70_u64, 80_u64, 52_u64, 3_u64, 5_u64);
        let sighash = transfer_sighash(
            base.auth_domain,
            base.root,
            array![*base.nf_list.at(0), *base.nf_list.at(0)].span(),
            base.fee,
            base.cm_1,
            base.cm_2,
            base.cm_3,
            base.cm_4,
            base.memo_ct_hash_1,
            base.memo_ct_hash_2,
            base.memo_ct_hash_3,
            base.memo_ct_hash_4,
        );
        let sig = sign_transfer_input(
            sighash,
            *base.auth_pub_seed_list.at(0),
            *base.auth_index_list.at(0),
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
            fee: base.fee,
            nk_spend_list: array![*base.nk_spend_list.at(0), *base.nk_spend_list.at(0)],
            auth_root_list: array![*base.auth_root_list.at(0), *base.auth_root_list.at(0)],
            auth_pub_seed_list: array![
                *base.auth_pub_seed_list.at(0), *base.auth_pub_seed_list.at(0),
            ],
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
            cm_3: base.cm_3,
            d_j_3: base.d_j_3,
            v_3: base.v_3,
            rseed_3: base.rseed_3,
            auth_root_3: base.auth_root_3,
            auth_pub_seed_3: base.auth_pub_seed_3,
            nk_tag_3: base.nk_tag_3,
            memo_ct_hash_3: base.memo_ct_hash_3,
            cm_4: base.cm_4,
            d_j_4: base.d_j_4,
            v_4: base.v_4,
            rseed_4: base.rseed_4,
            auth_root_4: base.auth_root_4,
            auth_pub_seed_4: base.auth_pub_seed_4,
            nk_tag_4: base.nk_tag_4,
            memo_ct_hash_4: base.memo_ct_hash_4,
            // Multiasset Phase B: pure-tez duplicate-nf fixture (2 inputs).
            input_asset_list: array![ASSET_TEZ, ASSET_TEZ],
            asset_1: ASSET_TEZ,
            asset_2: ASSET_TEZ,
            asset_3: ASSET_TEZ,
            asset_4: ASSET_TEZ,
            primary_non_tez_asset: ASSET_TEZ,
        }
    }

    fn run_verify(fixture: @TransferFixture) -> Array<felt252> {
        verify(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.fee,
            fixture.cm_1,
            fixture.cm_2,
            fixture.cm_3,
            fixture.cm_4,
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
            fixture.input_asset_list.span(),
            fixture.d_j_1,
            fixture.v_1,
            fixture.rseed_1,
            fixture.auth_root_1,
            fixture.auth_pub_seed_1,
            fixture.nk_tag_1,
            fixture.memo_ct_hash_1,
            fixture.asset_1,
            fixture.d_j_2,
            fixture.v_2,
            fixture.rseed_2,
            fixture.auth_root_2,
            fixture.auth_pub_seed_2,
            fixture.nk_tag_2,
            fixture.memo_ct_hash_2,
            fixture.asset_2,
            fixture.d_j_3,
            fixture.v_3,
            fixture.rseed_3,
            fixture.auth_root_3,
            fixture.auth_pub_seed_3,
            fixture.nk_tag_3,
            fixture.memo_ct_hash_3,
            fixture.asset_3,
            fixture.d_j_4,
            fixture.v_4,
            fixture.rseed_4,
            fixture.auth_root_4,
            fixture.auth_pub_seed_4,
            fixture.nk_tag_4,
            fixture.memo_ct_hash_4,
            fixture.asset_4,
            fixture.primary_non_tez_asset,
        )
    }

    #[test]
    fn test_transfer_accepts_valid_statement() {
        let fixture = build_fixture();
        let outputs = run_verify(@fixture);
        // Phase C: outputs now have 4 cm's + 4 memos = +2 vs prior layout.
        assert(outputs.len() == 12, 'transfer outputs len');
        assert(*outputs.at(0) == fixture.auth_domain, 'transfer out domain');
        assert(*outputs.at(1) == fixture.root, 'transfer out root');
        assert(*outputs.at(2) == *fixture.nf_list.at(0), 'transfer out nf');
        assert(*outputs.at(3) == fixture.fee.into(), 'transfer out fee');
        assert(*outputs.at(4) == fixture.cm_1, 'transfer out cm1');
        assert(*outputs.at(5) == fixture.cm_2, 'transfer out cm2');
        assert(*outputs.at(6) == fixture.cm_3, 'transfer out cm3');
        assert(*outputs.at(7) == fixture.cm_4, 'transfer out cm4');
        assert(*outputs.at(8) == fixture.memo_ct_hash_1, 'transfer out memo1');
        assert(*outputs.at(9) == fixture.memo_ct_hash_2, 'transfer out memo2');
        assert(*outputs.at(10) == fixture.memo_ct_hash_3, 'transfer out memo3');
        assert(*outputs.at(11) == fixture.memo_ct_hash_4, 'transfer out memo4');
    }

    #[test]
    fn test_transfer_accepts_valid_two_input_statement() {
        let fixture = build_two_input_fixture();
        let outputs = run_verify(@fixture);
        // Phase C: +2 vs prior layout (4 cms + 4 memos).
        assert(outputs.len() == 13, 'transfer outputs len two input');
        assert(*outputs.at(0) == fixture.auth_domain, 'transfer2 out domain');
        assert(*outputs.at(1) == fixture.root, 'transfer2 out root');
        assert(*outputs.at(2) == *fixture.nf_list.at(0), 'transfer2 out nf0');
        assert(*outputs.at(3) == *fixture.nf_list.at(1), 'transfer2 out nf1');
        assert(*outputs.at(4) == fixture.fee.into(), 'transfer2 out fee');
        assert(*outputs.at(5) == fixture.cm_1, 'transfer2 out cm1');
        assert(*outputs.at(6) == fixture.cm_2, 'transfer2 out cm2');
        assert(*outputs.at(7) == fixture.cm_3, 'transfer2 out cm3');
        assert(*outputs.at(8) == fixture.cm_4, 'transfer2 out cm4');
    }

    fn assert_transfer_accepts_multi_input_statement(n_inputs: u32) {
        let fixture = build_multi_input_fixture(n_inputs);
        let outputs = run_verify(@fixture);
        // Phase C: N nf + 1 (fee) + 4 cm + 4 memo + 2 (auth_domain, root)
        // = N + 11. Old was N + 9.
        assert(outputs.len() == n_inputs + 11_u32, 'transfer outputs len multi');
        assert(*outputs.at(0) == fixture.auth_domain, 'transfer multi out domain');
        assert(*outputs.at(1) == fixture.root, 'transfer multi out root');
        assert(*outputs.at(2) == *fixture.nf_list.at(0), 'transfer multi out nf0');
        assert(
            *outputs.at(1_u32 + n_inputs) == *fixture.nf_list.at(n_inputs - 1_u32),
            'transfer multi out last nf',
        );
        assert(*outputs.at(2_u32 + n_inputs) == fixture.fee.into(), 'transfer multi out fee');
        assert(*outputs.at(3_u32 + n_inputs) == fixture.cm_1, 'transfer multi out cm1');
        assert(*outputs.at(4_u32 + n_inputs) == fixture.cm_2, 'transfer multi out cm2');
        assert(*outputs.at(5_u32 + n_inputs) == fixture.cm_3, 'transfer multi out cm3');
        assert(*outputs.at(6_u32 + n_inputs) == fixture.cm_4, 'transfer multi out cm4');
    }

    #[test]
    fn test_transfer_accepts_multi_input_statement_sizes() {
        assert_transfer_accepts_multi_input_statement(4_u32);
        assert_transfer_accepts_multi_input_statement(7_u32);
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
                    fixture.fee,
                    fixture.cm_1,
                    fixture.cm_2,
                    fixture.cm_3,
                    fixture.cm_4,
                    fixture.memo_ct_hash_1,
                    fixture.memo_ct_hash_2,
                    fixture.memo_ct_hash_3,
                    fixture.memo_ct_hash_4,
                    *fixture.auth_pub_seed_list.at(0),
                    *fixture.auth_index_list.at(0),
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
    #[should_panic(expected: ('transfer: tez balance',))]
    fn test_transfer_rejects_balance_mismatch_even_with_consistent_output_commitment() {
        let fixture = build_fixture_with_values_and_fee(70_u64, 45_u64, 21_u64, 3_u64, 5_u64);
        run_verify(@fixture);
    }

    // ═══════════════════════════════════════════════════════════════
    // Multiasset Phase B/C mutation tests
    // ═══════════════════════════════════════════════════════════════

    /// asset_4 must be ASSET_TEZ — pinning the producer fee to tez is a
    /// permanent constraint (DAL slot publishers need liquid revenue).
    #[test]
    #[should_panic(expected: ('transfer: producer must be tez',))]
    fn test_transfer_rejects_producer_with_non_tez_asset() {
        let mut fixture = build_fixture();
        fixture.asset_4 = 0xDEADBEEF;
        run_verify(@fixture);
    }

    /// asset_1 must be in {ASSET_TEZ, primary_non_tez_asset}.
    /// A "rogue" 3rd asset class is rejected.
    #[test]
    #[should_panic(expected: ('transfer: bad asset_1',))]
    fn test_transfer_rejects_recipient_asset_outside_pair() {
        let mut fixture = build_fixture();
        // Set primary asset to A. Recipient asset = B (different).
        fixture.primary_non_tez_asset = 0xA;
        fixture.asset_1 = 0xB;
        run_verify(@fixture);
    }

    /// asset_2 (change_1) must be in {tez, primary}.
    #[test]
    #[should_panic(expected: ('transfer: bad asset_2',))]
    fn test_transfer_rejects_change_1_asset_outside_pair() {
        let mut fixture = build_fixture();
        fixture.primary_non_tez_asset = 0xA;
        fixture.asset_2 = 0xC;
        run_verify(@fixture);
    }

    /// asset_3 (change_2) must be in {tez, primary}.
    #[test]
    #[should_panic(expected: ('transfer: bad asset_3',))]
    fn test_transfer_rejects_change_2_asset_outside_pair() {
        let mut fixture = build_fixture();
        fixture.primary_non_tez_asset = 0xA;
        fixture.asset_3 = 0xD;
        run_verify(@fixture);
    }

    /// Per-input asset must be in {tez, primary}.
    /// Substituting a 3rd asset for the input is rejected.
    #[test]
    #[should_panic(expected: ('transfer: bad input asset',))]
    fn test_transfer_rejects_input_asset_outside_pair() {
        let mut fixture = build_fixture();
        fixture.primary_non_tez_asset = 0xA;
        fixture.input_asset_list = array![0xB];
        run_verify(@fixture);
    }

    /// Producer fee v_4 > 0.
    /// A zero-value producer fee is rejected.
    #[test]
    #[should_panic(expected: ('transfer prod fee',))]
    fn test_transfer_rejects_zero_producer_fee() {
        let fixture = build_fixture_with_values(70_u64, 42_u64, 23_u64, 0_u64);
        run_verify(@fixture);
    }

    /// asset_4 substitution that ALSO satisfies the in-set constraint
    /// (= primary_non_tez_asset) is still rejected by the producer-tez
    /// pin. This proves the producer pin is independent of the
    /// in-set check.
    #[test]
    #[should_panic(expected: ('transfer: producer must be tez',))]
    fn test_transfer_rejects_non_tez_producer_even_if_in_pair() {
        let mut fixture = build_fixture();
        fixture.primary_non_tez_asset = 0xA;
        fixture.asset_4 = 0xA; // would satisfy in-set, but producer must be tez
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_transfer_rejects_second_input_auth_path_mutation() {
        let mut fixture = build_two_input_fixture();
        fixture
            .auth_siblings_flat =
                copy_and_mutate(fixture.auth_siblings_flat.span(), merkle::AUTH_DEPTH + 2);
        run_verify(@fixture);
    }

    #[test]
    fn test_transfer_leaves_duplicate_nullifier_rejection_to_consensus() {
        let fixture = build_duplicate_nf_fixture();
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_transfer_rejects_last_input_auth_path_mutation_at_max_inputs() {
        let mut fixture = build_multi_input_fixture(7_u32);
        let target = 6_u32 * merkle::AUTH_DEPTH + 3_u32;
        fixture.auth_siblings_flat = copy_and_mutate(fixture.auth_siblings_flat.span(), target);
        run_verify(@fixture);
    }

    // Multiasset Phase B positive coverage.
    //
    // The negative tests above all set primary_non_tez_asset to a
    // distinct felt and confirm rogue / mispinned assets get rejected.
    // Below we exercise the *happy* path: build fixtures where the
    // primary asset actually carries a non-zero balance, and assert the
    // 2-accumulator constraint accepts it. Without these, all of the
    // mixed-asset semantics could silently degenerate to a no-op (e.g.
    // an accidental `asset == ASSET_TEZ` guard elsewhere in the circuit)
    // and the negative tests would still pass, because their balances
    // never actually move on the primary lane.
    //
    // Convention: input 0 carries tez (funds fee + producer + tez
    // change), input 1 carries the primary asset (funds recipient or
    // primary change). Both halves of the 2-accumulator constraint are
    // therefore strictly positive on both lanes.
    fn build_mixed_asset_two_input_fixture(primary: felt252) -> TransferFixture {
        let auth_domain = 0xA101;
        let auth_pub_seed = 0xA102;

        let auth_idx_0 = 0_u32;
        let auth_idx_1 = 1_u32;
        let key_base_0 = 0xA900;
        let key_base_1 = 0xAA00;

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
            upper_auth_siblings.append(hash::hash1(auth_level.into() + 0xAB00));
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

        let nk_spend_0 = 0xAC01;
        let nk_spend_1 = 0xAC02;
        let d_j_in_0 = 0xAC03;
        let d_j_in_1 = 0xAC04;
        let v_in_0 = 40_u64;
        let v_in_1 = 30_u64;
        let rseed_in_0 = 0xAC05;
        let rseed_in_1 = 0xAC06;

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
            upper_cm_siblings.append(hash::hash1(tree_level.into() + 0xAD00));
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
        //   tez_in     = 40
        //   tez_out    = v_2 (change_1 tez) + v_3 (change_2, v=0)
        //              + v_4 (producer tez) = 32 + 0 + 3 = 35
        //   fee        = 5; 40 == 35 + 5     ✓
        //   primary_in = 30
        //   primary_out = v_1 (recipient primary) = 30 ✓
        let fee = 5_u64;
        let v_1 = 30_u64; // recipient (primary)
        let v_2 = 32_u64; // change_1 (tez)
        let v_3 = 0_u64;  // change_2 placeholder (tez)
        let v_4 = 3_u64;  // producer (tez)

        // Recipient: asset = primary, value = 30.
        let d_j_1 = 0xAE01;
        let rseed_1 = 0xAE02;
        let auth_root_1 = 0xAE03;
        let auth_pub_seed_1 = 0xAE04;
        let nk_tag_1 = 0xAE05;
        let memo_ct_hash_1 = 0xAE06;
        let rcm_1 = hash::derive_rcm(rseed_1);
        let otag_1 = hash::owner_tag(auth_root_1, auth_pub_seed_1, nk_tag_1);
        let cm_1 = hash::commit(d_j_1, v_1, primary, rcm_1, otag_1);

        // change_1: asset = tez, value = 32.
        let d_j_2 = 0xAF01;
        let rseed_2 = 0xAF02;
        let auth_root_2 = 0xAF03;
        let auth_pub_seed_2 = 0xAF04;
        let nk_tag_2 = 0xAF05;
        let memo_ct_hash_2 = 0xAF06;
        let cm_2 = output_commitment(
            d_j_2, v_2, rseed_2, auth_root_2, auth_pub_seed_2, nk_tag_2,
        );

        // change_2 placeholder: asset = tez, value = 0.
        let d_j_3 = 0xB001;
        let rseed_3 = 0xB002;
        let auth_root_3 = 0xB003;
        let auth_pub_seed_3 = 0xB004;
        let nk_tag_3 = 0xB005;
        let memo_ct_hash_3 = 0xB006;
        let cm_3 = output_commitment(
            d_j_3, v_3, rseed_3, auth_root_3, auth_pub_seed_3, nk_tag_3,
        );

        // Producer: asset = tez, value = 3.
        let d_j_4 = 0xB101;
        let rseed_4 = 0xB102;
        let auth_root_4 = 0xB103;
        let auth_pub_seed_4 = 0xB104;
        let nk_tag_4 = 0xB105;
        let memo_ct_hash_4 = 0xB106;
        let cm_4 = output_commitment(
            d_j_4, v_4, rseed_4, auth_root_4, auth_pub_seed_4, nk_tag_4,
        );

        let nf_list: Array<felt252> = array![nf_0, nf_1];
        let sighash = transfer_sighash(
            auth_domain,
            root,
            nf_list.span(),
            fee,
            cm_1,
            cm_2,
            cm_3,
            cm_4,
            memo_ct_hash_1,
            memo_ct_hash_2,
            memo_ct_hash_3,
            memo_ct_hash_4,
        );

        let sig_0 = sign_transfer_input(sighash, auth_pub_seed, auth_idx_0, key_base_0);
        let sig_1 = sign_transfer_input(sighash, auth_pub_seed, auth_idx_1, key_base_1);
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

        TransferFixture {
            auth_domain,
            root,
            nf_list,
            fee,
            nk_spend_list: array![nk_spend_0, nk_spend_1],
            auth_root_list: array![auth_root, auth_root],
            auth_pub_seed_list: array![auth_pub_seed, auth_pub_seed],
            auth_index_list: array![auth_idx_0, auth_idx_1],
            d_j_in_list: array![d_j_in_0, d_j_in_1],
            v_in_list: array![v_in_0, v_in_1],
            rseed_in_list: array![rseed_in_0, rseed_in_1],
            cm_siblings_flat,
            auth_siblings_flat,
            cm_path_indices_list: array![0_u64, 1_u64],
            wots_sig_flat,
            cm_1, d_j_1, v_1, rseed_1, auth_root_1, auth_pub_seed_1, nk_tag_1, memo_ct_hash_1,
            cm_2, d_j_2, v_2, rseed_2, auth_root_2, auth_pub_seed_2, nk_tag_2, memo_ct_hash_2,
            cm_3, d_j_3, v_3, rseed_3, auth_root_3, auth_pub_seed_3, nk_tag_3, memo_ct_hash_3,
            cm_4, d_j_4, v_4, rseed_4, auth_root_4, auth_pub_seed_4, nk_tag_4, memo_ct_hash_4,
            // Multiasset Phase B: explicit per-asset tagging.
            input_asset_list: array![ASSET_TEZ, primary],
            asset_1: primary,
            asset_2: ASSET_TEZ,
            asset_3: ASSET_TEZ,
            asset_4: ASSET_TEZ,
            primary_non_tez_asset: primary,
        }
    }

    /// Positive: mixed-asset transfer where input 1 = primary and the
    /// recipient takes the full primary balance. tez_in funds change_1
    /// + producer + fee. Both per-asset accumulators are strictly
    /// positive, so this is the first test that actually exercises the
    /// `primary_in == primary_out` constraint with a non-zero RHS.
    #[test]
    fn test_transfer_accepts_mixed_assets_recipient_takes_primary() {
        let primary = 0xFA2A55E7;
        let fixture = build_mixed_asset_two_input_fixture(primary);
        let outputs = run_verify(@fixture);
        // Phase C: 2 + 2 nfs + 1 fee + 4 cm + 4 memo = 13 fields.
        assert(outputs.len() == 13, 'mixed-asset outputs len');
        assert(*outputs.at(5) == fixture.cm_1, 'mixed-asset out cm1');
        assert(*outputs.at(8) == fixture.cm_4, 'mixed-asset out cm4');
    }

    /// Positive: the 2-accumulator constraint is symmetric across the
    /// two change slots — swap which slot carries the (zero-value)
    /// placeholder vs. the real tez change and the proof still
    /// verifies. Without this, an accidental hard-pin on change_1
    /// would silently force all tez change into slot 2.
    #[test]
    fn test_transfer_accepts_tez_change_in_slot_2_with_primary_recipient() {
        let primary = 0xFA2B5550;
        let mut fixture = build_mixed_asset_two_input_fixture(primary);
        // Re-route the tez change: change_1 becomes the v=0 placeholder
        // and change_2 carries the 32-tez balance. Both slots stay
        // tez-typed, so the per-asset balance is unchanged.
        let old_v_2 = fixture.v_2;
        let old_v_3 = fixture.v_3;
        fixture.v_2 = old_v_3;
        fixture.v_3 = old_v_2;
        // Recompute commitments for the swapped values.
        fixture
            .cm_2 =
                output_commitment(
                    fixture.d_j_2,
                    fixture.v_2,
                    fixture.rseed_2,
                    fixture.auth_root_2,
                    fixture.auth_pub_seed_2,
                    fixture.nk_tag_2,
                );
        fixture
            .cm_3 =
                output_commitment(
                    fixture.d_j_3,
                    fixture.v_3,
                    fixture.rseed_3,
                    fixture.auth_root_3,
                    fixture.auth_pub_seed_3,
                    fixture.nk_tag_3,
                );
        // Re-sign the new sighash (cm_2 and cm_3 changed).
        let new_sighash = transfer_sighash(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.fee,
            fixture.cm_1,
            fixture.cm_2,
            fixture.cm_3,
            fixture.cm_4,
            fixture.memo_ct_hash_1,
            fixture.memo_ct_hash_2,
            fixture.memo_ct_hash_3,
            fixture.memo_ct_hash_4,
        );
        let sig_0 = sign_transfer_input(new_sighash, 0xA102, 0_u32, 0xA900);
        let sig_1 = sign_transfer_input(new_sighash, 0xA102, 1_u32, 0xAA00);
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

    /// Positive: swap the recipient asset to tez — recipient now takes
    /// the full tez change, and the primary lane refunds 30 back to the
    /// sender via change_1 (asset = primary, v = 30). Confirms the
    /// 2-accumulator constraint is symmetric: nothing forces the
    /// recipient slot to carry the primary asset specifically.
    #[test]
    fn test_transfer_accepts_primary_refunded_to_change_slot() {
        let primary = 0xFA2C5550;
        let mut fixture = build_mixed_asset_two_input_fixture(primary);
        // Re-route: recipient (asset_1) becomes tez carrying the 32 tez
        // change; change_1 (asset_2) becomes the primary refund of 30.
        // Producer + fee unchanged. v_3 stays 0. Balance:
        //   tez_in 40 == tez_out (32 recipient + 0 + 3 producer) + 5 fee ✓
        //   primary_in 30 == primary_out (30 change_1) ✓
        fixture.asset_1 = ASSET_TEZ;
        fixture.v_1 = 32_u64;
        fixture
            .cm_1 =
                output_commitment(
                    fixture.d_j_1,
                    fixture.v_1,
                    fixture.rseed_1,
                    fixture.auth_root_1,
                    fixture.auth_pub_seed_1,
                    fixture.nk_tag_1,
                );
        fixture.asset_2 = primary;
        fixture.v_2 = 30_u64;
        let rcm_2 = hash::derive_rcm(fixture.rseed_2);
        let otag_2 = hash::owner_tag(
            fixture.auth_root_2, fixture.auth_pub_seed_2, fixture.nk_tag_2,
        );
        fixture.cm_2 = hash::commit(fixture.d_j_2, fixture.v_2, primary, rcm_2, otag_2);

        let new_sighash = transfer_sighash(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.fee,
            fixture.cm_1,
            fixture.cm_2,
            fixture.cm_3,
            fixture.cm_4,
            fixture.memo_ct_hash_1,
            fixture.memo_ct_hash_2,
            fixture.memo_ct_hash_3,
            fixture.memo_ct_hash_4,
        );
        let sig_0 = sign_transfer_input(new_sighash, 0xA102, 0_u32, 0xA900);
        let sig_1 = sign_transfer_input(new_sighash, 0xA102, 1_u32, 0xAA00);
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

    /// Positive: the degenerate case where primary_non_tez_asset ==
    /// ASSET_TEZ. The two accumulators collapse into one (every input
    /// and output lands in tez_in/tez_out, and the
    /// primary_in == primary_out constraint becomes 0 == 0). This is
    /// exactly the regime the existing pure-tez tests run in, but the
    /// invariant must hold *because* the constraint is satisfied, not
    /// because primary lookups are skipped. Asserting it explicitly
    /// here catches a refactor that would gate the per-asset
    /// accumulation on `primary != tez`.
    #[test]
    fn test_transfer_accepts_degenerate_primary_equals_tez() {
        // Reuse the pure-tez two-input fixture, which already sets
        // primary_non_tez_asset = ASSET_TEZ. Running it through
        // run_verify still exercises the 2-accumulator code path.
        let fixture = build_two_input_fixture();
        let _outputs = run_verify(@fixture);
    }

    /// Positive: when primary_non_tez_asset is set to a non-tez value
    /// but no input/output actually uses it, the primary accumulators
    /// stay at zero on both sides and the proof verifies. This guards
    /// against a refactor that would force primary_in or primary_out
    /// to be strictly positive when primary_non_tez_asset != tez.
    #[test]
    fn test_transfer_accepts_unused_primary_asset() {
        let mut fixture = build_two_input_fixture();
        fixture.primary_non_tez_asset = 0xC0FFEE;
        // input_asset_list, asset_1..asset_4 all stay tez; balance
        // still holds on the tez lane, primary lane is 0 == 0.
        run_verify(@fixture);
    }

    /// Negative: starting from the mixed-asset positive fixture, flip
    /// asset_1 (recipient) to tez. The recipient still claims v_1 = 30
    /// but now as tez, so the tez lane overshoots (40 in, 65 out + 5
    /// fee) and the per-asset balance constraint fires.
    #[test]
    #[should_panic(expected: ('transfer: tez balance',))]
    fn test_transfer_rejects_recipient_asset_flipped() {
        let primary = 0xFA2D5550;
        let mut fixture = build_mixed_asset_two_input_fixture(primary);
        // Recipient now claims tez but cm_1 is committed to primary.
        // The asset-mismatch panics first on the commit recompute,
        // before we even hit the balance check. Actually: the
        // commitment is computed from fixture.asset_1, so we also
        // need to refresh cm_1 to reflect the new asset and let the
        // balance check fire.
        fixture.asset_1 = ASSET_TEZ;
        let rcm_1 = hash::derive_rcm(fixture.rseed_1);
        let otag_1 = hash::owner_tag(
            fixture.auth_root_1, fixture.auth_pub_seed_1, fixture.nk_tag_1,
        );
        fixture.cm_1 = hash::commit(fixture.d_j_1, fixture.v_1, ASSET_TEZ, rcm_1, otag_1);
        // Re-sign so the WOTS check is OK and the balance check is the
        // one that fires.
        let new_sighash = transfer_sighash(
            fixture.auth_domain,
            fixture.root,
            fixture.nf_list.span(),
            fixture.fee,
            fixture.cm_1,
            fixture.cm_2,
            fixture.cm_3,
            fixture.cm_4,
            fixture.memo_ct_hash_1,
            fixture.memo_ct_hash_2,
            fixture.memo_ct_hash_3,
            fixture.memo_ct_hash_4,
        );
        let sig_0 = sign_transfer_input(new_sighash, 0xA102, 0_u32, 0xA900);
        let sig_1 = sign_transfer_input(new_sighash, 0xA102, 1_u32, 0xAA00);
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

    /// Negative: starting from the mixed-asset positive fixture, flip
    /// the input_asset_list tag at position 1 from primary to tez.
    /// cm_1_in was committed to primary so the per-input loop will
    /// recompute commit(d_j, v, tez, …) which won't match the leaf
    /// in the cm-tree — merkle root verification fires first.
    #[test]
    #[should_panic(expected: ('merkle root mismatch',))]
    fn test_transfer_rejects_input_asset_tag_flipped() {
        let primary = 0xFA2E5550;
        let mut fixture = build_mixed_asset_two_input_fixture(primary);
        fixture.input_asset_list = array![ASSET_TEZ, ASSET_TEZ];
        run_verify(@fixture);
    }
}
