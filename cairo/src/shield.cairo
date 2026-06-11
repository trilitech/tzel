/// Shield circuit (post deposit-pool / pubkey_hash redesign + multiasset).
///
/// # Public outputs (10 felts)
///   [auth_domain, pubkey_hash, v_note, fee, producer_fee,
///    cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash,
///    asset_new]
///
/// `asset_new` is the recipient note's L2 asset_id (ASSET_TEZ or
/// `derive_asset_id(ticketer_kt1)` for an FA2). The producer-fee
/// note's asset is implicit (always ASSET_TEZ, asserted in-circuit by
/// the producer-commitment recomputation below).
///
/// # Spend authorization
///   In-circuit XMSS-style WOTS+ signature verification under the
///   recipient's auth tree, mirroring the transfer / unshield circuits.
///   The signature signs the shield sighash:
///     fold(0x03, auth_domain, pubkey_hash, v_note, fee, producer_fee,
///          cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash,
///          asset_new, asset_producer)
///   so a delegated prover holding the witness still cannot redirect funds,
///   change values, swap recipients, or change the asset without the
///   wallet's signing key. `asset_producer` is folded directly into the
///   sighash even though it's pinned to ASSET_TEZ in-circuit, to keep the
///   sighash structure identical to a hypothetical future variant that
///   relaxes that pin.
///
/// # Constraints
///   owner_tag = H_owner(auth_root, auth_pub_seed, nk_tag)
///   cm_new   = H_commit(d_j, v_note, asset_new, H(rseed), owner_tag)
///   producer_owner_tag = H_owner(producer_auth_root, producer_auth_pub_seed,
///                                producer_nk_tag)
///   cm_producer = H_commit(producer_d_j, producer_fee, ASSET_TEZ,
///                          H(producer_rseed), producer_owner_tag)
///   producer_fee > 0
///   asset_producer == ASSET_TEZ   (DAL liquidity argument; see whitepaper §Multiasset)
///   pubkey_hash = fold(0x04, auth_domain, auth_root, auth_pub_seed, blind)
///   WOTS+(sighash, auth_root, auth_pub_seed, auth_idx, wots_sig, auth_siblings)
///
///   Note: `asset_new` is NOT asserted to equal ASSET_TEZ — Phase E.3
///   lifted that pin. The kernel re-checks `asset_new` against its
///   registered-asset list. An attempt to shield against an
///   unregistered asset reaches the circuit and produces a valid
///   proof, but the kernel rejects the resulting Shield request.

use tzel::blake_hash as hash;
use tzel::{merkle, xmss_common};
use tzel::ASSET_TEZ;

pub fn verify(
    auth_domain: felt252,
    pubkey_hash: felt252,
    v_note: u64,
    fee: u64,
    producer_fee: u64,
    cm_new: felt252,
    cm_producer: felt252,
    memo_ct_hash: felt252,
    producer_memo_ct_hash: felt252,
    // private inputs (recipient note witness + auth tree)
    auth_root: felt252,
    auth_pub_seed: felt252,
    nk_tag: felt252,
    d_j: felt252,
    rseed: felt252,
    blind: felt252,
    // WOTS+ signature material. `auth_idx` is the position of the
    // recipient's WOTS+ key within their auth tree (0..2^AUTH_DEPTH);
    // u32 is plenty (AUTH_DEPTH = 16 today) and the signature on the
    // sighash binds it via the chain-step ADRS, so the kernel never
    // needs to see this value.
    auth_idx: u32,
    wots_sig_flat: Span<felt252>,
    auth_siblings_flat: Span<felt252>,
    // private inputs (producer-fee note witness)
    producer_auth_root: felt252,
    producer_auth_pub_seed: felt252,
    producer_nk_tag: felt252,
    producer_d_j: felt252,
    producer_rseed: felt252,
    // Multiasset (Phase B). asset_new is the recipient note's asset
    // (pinned to ASSET_TEZ in v1 — the only deployed bridge);
    // asset_producer is the producer-fee note's asset (always
    // ASSET_TEZ regardless of bridges, by the liquidity argument).
    // Both are public side-bound via the sighash because the
    // L1 ticket reveals the asset anyway.
    asset_new: felt252,
    asset_producer: felt252,
) -> Array<felt252> {
    assert(wots_sig_flat.len() == xmss_common::WOTS_CHAINS, 'shield: wots sig len');
    assert(auth_siblings_flat.len() == merkle::AUTH_DEPTH, 'shield: auth sib len');

    // Phase E.3: asset_new is exposed in the public outputs (last
    // entry) so the kernel can validate it against the registered
    // bridge ticketers. The circuit no longer pins asset_new ==
    // ASSET_TEZ; that check lives at the kernel boundary.
    //
    // Permanent constraint: DAL slot publisher fee must be tez.
    assert(asset_producer == ASSET_TEZ, 'shield: producer must be tez');

    // Recipient commitment.
    let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
    let rcm = hash::derive_rcm(rseed);
    assert(
        hash::commit(d_j, v_note, asset_new, rcm, otag) == cm_new,
        'shield: bad commitment',
    );

    // Producer-fee commitment.
    let producer_otag =
        hash::owner_tag(producer_auth_root, producer_auth_pub_seed, producer_nk_tag);
    let producer_rcm = hash::derive_rcm(producer_rseed);
    assert(
        hash::commit(producer_d_j, producer_fee, asset_producer, producer_rcm, producer_otag)
            == cm_producer,
        'shield: bad producer cm',
    );
    assert(producer_fee > 0_u64, 'shield: producer fee zero');

    // pubkey_hash = fold(0x04, auth_domain, auth_root, auth_pub_seed, blind).
    let mut pkh = hash::sighash_fold(0x04, auth_domain);
    pkh = hash::sighash_fold(pkh, auth_root);
    pkh = hash::sighash_fold(pkh, auth_pub_seed);
    pkh = hash::sighash_fold(pkh, blind);
    assert(pkh == pubkey_hash, 'shield: bad pubkey_hash');

    // sighash = fold(0x03, auth_domain, pubkey_hash, v_note, fee,
    //                producer_fee, asset_new, asset_producer, cm_new,
    //                cm_producer, memo_ct_hash, producer_memo_ct_hash).
    // The asset fields are included because they are public at the
    // L1 bridge boundary.
    let mut sighash = hash::sighash_fold(0x03, auth_domain);
    sighash = hash::sighash_fold(sighash, pubkey_hash);
    sighash = hash::sighash_fold(sighash, v_note.into());
    sighash = hash::sighash_fold(sighash, fee.into());
    sighash = hash::sighash_fold(sighash, producer_fee.into());
    sighash = hash::sighash_fold(sighash, asset_new);
    sighash = hash::sighash_fold(sighash, asset_producer);
    sighash = hash::sighash_fold(sighash, cm_new);
    sighash = hash::sighash_fold(sighash, cm_producer);
    sighash = hash::sighash_fold(sighash, memo_ct_hash);
    sighash = hash::sighash_fold(sighash, producer_memo_ct_hash);

    // In-circuit WOTS+ verify under the recipient's auth tree.
    let recovered_pk = xmss_common::xmss_recover_pk(
        sighash,
        auth_pub_seed,
        auth_idx,
        wots_sig_flat,
    );
    let leaf = xmss_common::xmss_ltree(auth_pub_seed, auth_idx, recovered_pk.span());
    xmss_common::xmss_verify_auth(
        leaf,
        auth_root,
        auth_pub_seed,
        auth_idx,
        auth_siblings_flat,
    );

    array![
        auth_domain,
        pubkey_hash,
        v_note.into(),
        fee.into(),
        producer_fee.into(),
        cm_new,
        cm_producer,
        memo_ct_hash,
        producer_memo_ct_hash,
        // Phase E.3: expose the recipient note's asset so the kernel
        // can route the shield to the right (asset_id, pubkey_hash)
        // deposit pool. asset_producer stays implicit since it's
        // pinned to ASSET_TEZ above.
        asset_new,
    ]
}

#[cfg(test)]
mod tests {
    use tzel::{blake_hash as hash, merkle, xmss_common};
    use tzel::ASSET_TEZ;
    use super::verify;

    const TAG_XMSS_TREE_TEST: felt252 = 0x72742D73736D78;

    #[derive(Drop)]
    struct ShieldFixture {
        auth_domain: felt252,
        pubkey_hash: felt252,
        v_note: u64,
        fee: u64,
        producer_fee: u64,
        cm_new: felt252,
        cm_producer: felt252,
        memo_ct_hash: felt252,
        producer_memo_ct_hash: felt252,
        auth_root: felt252,
        auth_pub_seed: felt252,
        nk_tag: felt252,
        d_j: felt252,
        rseed: felt252,
        blind: felt252,
        auth_idx: u32,
        wots_sig: Array<felt252>,
        auth_siblings: Array<felt252>,
        producer_auth_root: felt252,
        producer_auth_pub_seed: felt252,
        producer_nk_tag: felt252,
        producer_d_j: felt252,
        producer_rseed: felt252,
        // Multiasset Phase B
        asset_new: felt252,
        asset_producer: felt252,
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

    fn deposit_pubkey_hash(
        auth_domain: felt252, auth_root: felt252, auth_pub_seed: felt252, blind: felt252,
    ) -> felt252 {
        let mut pkh = hash::sighash_fold(0x04, auth_domain);
        pkh = hash::sighash_fold(pkh, auth_root);
        pkh = hash::sighash_fold(pkh, auth_pub_seed);
        pkh = hash::sighash_fold(pkh, blind);
        pkh
    }

    fn shield_sighash(
        auth_domain: felt252,
        pubkey_hash: felt252,
        v_note: u64,
        fee: u64,
        producer_fee: u64,
        cm_new: felt252,
        cm_producer: felt252,
        memo_ct_hash: felt252,
        producer_memo_ct_hash: felt252,
        asset_new: felt252,
        asset_producer: felt252,
    ) -> felt252 {
        let mut sighash = hash::sighash_fold(0x03, auth_domain);
        sighash = hash::sighash_fold(sighash, pubkey_hash);
        sighash = hash::sighash_fold(sighash, v_note.into());
        sighash = hash::sighash_fold(sighash, fee.into());
        sighash = hash::sighash_fold(sighash, producer_fee.into());
        sighash = hash::sighash_fold(sighash, asset_new);
        sighash = hash::sighash_fold(sighash, asset_producer);
        sighash = hash::sighash_fold(sighash, cm_new);
        sighash = hash::sighash_fold(sighash, cm_producer);
        sighash = hash::sighash_fold(sighash, memo_ct_hash);
        sighash = hash::sighash_fold(sighash, producer_memo_ct_hash);
        sighash
    }

    // Cross-impl conformance for the FULL shield sighash field set (the
    // non-malleability binding). This pins the helper -- which the passing
    // fixture tests prove equals production verify's INLINE sighash -- to
    // the OCaml port's Transaction.shield_sighash. It is the regression
    // guard for the multiasset asset-field binding: the port had silently
    // OMITTED asset_new/asset_producer (dead code, never exercised by the
    // function differential); had this test existed, it would have failed.
    // Inputs: auth_domain=1 pubkey_hash=2 v=10 fee=3 producer_fee=4
    // asset_new=5 asset_producer=0 cm_new=6 cm_producer=7 memo=8 pmemo=9.
    #[test]
    fn test_shield_sighash_field_set_conforms_to_port() {
        let sh = shield_sighash(1, 2, 10_u64, 3_u64, 4_u64, 6, 7, 8, 9, 5, 0);
        assert(sh == 0x0391e90c832477cc8e2fc07481a22be92fc15cf044a33fe7d994e286e92ad4bc, 'shield sighash field-set');
    }

    fn sign_shield(
        sighash: felt252,
        auth_pub_seed: felt252,
        auth_idx: u32,
        key_material_base: felt252,
    ) -> Array<felt252> {
        let digits = hash::sighash_to_wots_digits(sighash);
        let mut wots_sig: Array<felt252> = array![];
        let mut j: u32 = 0;
        while j < xmss_common::WOTS_CHAINS {
            let start = hash::hash1(j.into() + key_material_base);
            wots_sig.append(chain_advance(start, auth_pub_seed, auth_idx, j, *digits.at(j)));
            j += 1;
        }
        wots_sig
    }

    fn build_recipient_keytree(
        auth_pub_seed: felt252,
        auth_idx: u32,
        key_material_base: felt252,
        auth_seed_offset: felt252,
    ) -> (felt252, Array<felt252>) {
        let mut endpoints: Array<felt252> = array![];
        let mut chain_idx: u32 = 0;
        while chain_idx < xmss_common::WOTS_CHAINS {
            let start = hash::hash1(chain_idx.into() + key_material_base);
            endpoints
                .append(
                    chain_advance(
                        start, auth_pub_seed, auth_idx, chain_idx, xmss_common::WOTS_W - 1,
                    ),
                );
            chain_idx += 1;
        }

        let mut auth_siblings: Array<felt252> = array![];
        let mut level: u32 = 0;
        while level < merkle::AUTH_DEPTH {
            auth_siblings.append(hash::hash1(level.into() + auth_seed_offset));
            level += 1;
        }
        let leaf = xmss_common::xmss_ltree(auth_pub_seed, auth_idx, endpoints.span());
        let auth_root = auth_root_from_leaf(leaf, auth_pub_seed, auth_idx, auth_siblings.span());
        (auth_root, auth_siblings)
    }

    fn build_fixture_with(
        v_note: u64, fee: u64, producer_fee: u64,
    ) -> ShieldFixture {
        let auth_domain = 0xC001;
        let auth_pub_seed = 0xC002;
        let auth_idx = 5_u32;
        let nk_tag = 0xC003;
        let d_j = 0xC004;
        let rseed = 0xC005;
        let blind = 0xC006;
        let memo_ct_hash = 0xC007;

        let (auth_root, auth_siblings) = build_recipient_keytree(
            auth_pub_seed, auth_idx, 0xC100, 0xC200,
        );

        let pubkey_hash = deposit_pubkey_hash(auth_domain, auth_root, auth_pub_seed, blind);
        let cm_new = output_commitment(d_j, v_note, rseed, auth_root, auth_pub_seed, nk_tag);

        // Producer note has its own independent owner tree witness. The
        // shield circuit only checks the producer commitment opens to
        // the witness; it doesn't require any signature under the
        // producer's tree.
        let producer_auth_root = 0xD001;
        let producer_auth_pub_seed = 0xD002;
        let producer_nk_tag = 0xD003;
        let producer_d_j = 0xD004;
        let producer_rseed = 0xD005;
        let producer_memo_ct_hash = 0xD006;
        let cm_producer = output_commitment(
            producer_d_j,
            producer_fee,
            producer_rseed,
            producer_auth_root,
            producer_auth_pub_seed,
            producer_nk_tag,
        );

        let sighash = shield_sighash(
            auth_domain,
            pubkey_hash,
            v_note,
            fee,
            producer_fee,
            cm_new,
            cm_producer,
            memo_ct_hash,
            producer_memo_ct_hash,
            ASSET_TEZ,
            ASSET_TEZ,
        );
        let wots_sig = sign_shield(sighash, auth_pub_seed, auth_idx, 0xC100);

        ShieldFixture {
            auth_domain,
            pubkey_hash,
            v_note,
            fee,
            producer_fee,
            cm_new,
            cm_producer,
            memo_ct_hash,
            producer_memo_ct_hash,
            auth_root,
            auth_pub_seed,
            nk_tag,
            d_j,
            rseed,
            blind,
            auth_idx,
            wots_sig,
            auth_siblings,
            producer_auth_root,
            producer_auth_pub_seed,
            producer_nk_tag,
            producer_d_j,
            producer_rseed,
            asset_new: ASSET_TEZ,
            asset_producer: ASSET_TEZ,
        }
    }

    fn build_fixture() -> ShieldFixture {
        build_fixture_with(100_u64, 5_u64, 1_u64)
    }

    fn run_verify(f: @ShieldFixture) -> Array<felt252> {
        verify(
            f.auth_domain,
            f.pubkey_hash,
            f.v_note,
            f.fee,
            f.producer_fee,
            f.cm_new,
            f.cm_producer,
            f.memo_ct_hash,
            f.producer_memo_ct_hash,
            f.auth_root,
            f.auth_pub_seed,
            f.nk_tag,
            f.d_j,
            f.rseed,
            f.blind,
            f.auth_idx,
            f.wots_sig.span(),
            f.auth_siblings.span(),
            f.producer_auth_root,
            f.producer_auth_pub_seed,
            f.producer_nk_tag,
            f.producer_d_j,
            f.producer_rseed,
            f.asset_new,
            f.asset_producer,
        )
    }

    #[test]
    fn test_shield_accepts_valid_statement() {
        let fixture = build_fixture();
        let outputs = run_verify(@fixture);
        // Phase E.3: +1 trailing slot for asset_new.
        assert(outputs.len() == 10, 'shield outputs len');
        assert(*outputs.at(0) == fixture.auth_domain, 'shield out domain');
        assert(*outputs.at(1) == fixture.pubkey_hash, 'shield out pkh');
        assert(*outputs.at(2) == fixture.v_note.into(), 'shield out v');
        assert(*outputs.at(3) == fixture.fee.into(), 'shield out fee');
        assert(*outputs.at(4) == fixture.producer_fee.into(), 'shield out prod fee');
        assert(*outputs.at(5) == fixture.cm_new, 'shield out cm new');
        assert(*outputs.at(6) == fixture.cm_producer, 'shield out cm prod');
        assert(*outputs.at(7) == fixture.memo_ct_hash, 'shield out mh');
        assert(*outputs.at(8) == fixture.producer_memo_ct_hash, 'shield out prod mh');
        assert(*outputs.at(9) == fixture.asset_new, 'shield out asset new');
    }

    #[test]
    fn test_shield_accepts_zero_value_recipient_note() {
        // A zero-value recipient note is allowed: the user effectively
        // donates the entire pool to the producer-fee + tx-fee. The
        // circuit doesn't bake in `v_note > 0`, only `producer_fee > 0`.
        let fixture = build_fixture_with(0_u64, 5_u64, 1_u64);
        run_verify(@fixture);
    }

    #[test]
    fn test_shield_accepts_zero_tx_fee() {
        // The circuit doesn't enforce a minimum tx fee; the kernel does
        // (by rejecting fee < required_tx_fee at request validation).
        let fixture = build_fixture_with(50_u64, 0_u64, 1_u64);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: producer fee zero',))]
    fn test_shield_rejects_zero_producer_fee() {
        let fixture = build_fixture_with(100_u64, 5_u64, 0_u64);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_recipient_d_j_witness_mutation() {
        let mut fixture = build_fixture();
        fixture.d_j += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_recipient_rseed_witness_mutation() {
        let mut fixture = build_fixture();
        fixture.rseed += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_recipient_nk_tag_witness_mutation() {
        let mut fixture = build_fixture();
        fixture.nk_tag += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad producer cm',))]
    fn test_shield_rejects_producer_d_j_witness_mutation() {
        let mut fixture = build_fixture();
        fixture.producer_d_j += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad producer cm',))]
    fn test_shield_rejects_producer_rseed_witness_mutation() {
        let mut fixture = build_fixture();
        fixture.producer_rseed += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad producer cm',))]
    fn test_shield_rejects_producer_auth_root_witness_mutation() {
        let mut fixture = build_fixture();
        fixture.producer_auth_root += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad pubkey_hash',))]
    fn test_shield_rejects_blind_mismatch() {
        let mut fixture = build_fixture();
        fixture.blind += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad pubkey_hash',))]
    fn test_shield_rejects_pubkey_hash_public_mutation() {
        // Public pubkey_hash mutated. The recomputed pubkey_hash from
        // (auth_domain, auth_root, auth_pub_seed, blind) won't match.
        let mut fixture = build_fixture();
        fixture.pubkey_hash += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_recipient_auth_root_witness_mutation() {
        // Mutating auth_root in the witness breaks the commitment first
        // (cm_new was built with the original auth_root via owner_tag).
        let mut fixture = build_fixture();
        fixture.auth_root += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_shield_rejects_mutated_wots_signature() {
        let mut fixture = build_fixture();
        fixture.wots_sig = copy_and_mutate(fixture.wots_sig.span(), 7);
        run_verify(@fixture);
    }

    #[test]
    fn test_shield_binds_every_wots_chain_into_authenticated_root() {
        let fixture = build_fixture();
        let mut j: u32 = 0;
        while j < xmss_common::WOTS_CHAINS {
            let mutated_wots = copy_and_mutate(fixture.wots_sig.span(), j);
            let recovered_pk = xmss_common::xmss_recover_pk(
                shield_sighash(
                    fixture.auth_domain,
                    fixture.pubkey_hash,
                    fixture.v_note,
                    fixture.fee,
                    fixture.producer_fee,
                    fixture.cm_new,
                    fixture.cm_producer,
                    fixture.memo_ct_hash,
                    fixture.producer_memo_ct_hash,
                    fixture.asset_new,
                    fixture.asset_producer,
                ),
                fixture.auth_pub_seed,
                fixture.auth_idx,
                mutated_wots.span(),
            );
            let leaf = xmss_common::xmss_ltree(
                fixture.auth_pub_seed, fixture.auth_idx, recovered_pk.span(),
            );
            let mutated_root = auth_root_from_leaf(
                leaf, fixture.auth_pub_seed, fixture.auth_idx, fixture.auth_siblings.span(),
            );
            assert(mutated_root != fixture.auth_root, 'wots mutation escaped');
            j += 1;
        }
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_shield_rejects_mutated_auth_siblings() {
        let mut fixture = build_fixture();
        fixture.auth_siblings = copy_and_mutate(fixture.auth_siblings.span(), 3);
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_shield_rejects_public_memo_hash_mutation_via_signature_binding() {
        // memo_ct_hash is folded into the sighash, so changing it in
        // the public output without re-signing breaks WOTS+ verify.
        let mut fixture = build_fixture();
        fixture.memo_ct_hash += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_shield_rejects_public_producer_memo_hash_mutation_via_signature_binding() {
        let mut fixture = build_fixture();
        fixture.producer_memo_ct_hash += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_v_note_public_mutation() {
        // Mutating v_note breaks cm_new immediately (commitment is
        // computed from v_note in-circuit).
        let mut fixture = build_fixture();
        fixture.v_note += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: bad producer cm',))]
    fn test_shield_rejects_producer_fee_public_mutation() {
        // Same: producer_fee feeds into cm_producer.
        let mut fixture = build_fixture();
        fixture.producer_fee += 1;
        run_verify(@fixture);
    }

    // ═══════════════════════════════════════════════════════════════
    // Multiasset Phase B mutation tests
    // ═══════════════════════════════════════════════════════════════

    /// Phase E.3: the Cairo `asset_new == ASSET_TEZ` pin was lifted —
    /// the kernel now enforces "asset_new ∈ registered" at apply time
    /// against the kernel-binary registry. The circuit only checks
    /// that `cm_new = commit(d_j, v, asset_new, …)` is consistent with
    /// whatever asset_new the prover claims, and that the WOTS sig
    /// covers it via the sighash. Mutating just `asset_new` after the
    /// fact still breaks the commitment recompute (fixture.cm_new was
    /// built against asset = ASSET_TEZ) — the 'shield: bad commitment'
    /// assertion fires before sighash recovery.
    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_asset_new_mutation_via_commitment_binding() {
        let mut fixture = build_fixture();
        fixture.asset_new = 0xFEEDFACE;
        run_verify(@fixture);
    }

    /// asset_producer must be ASSET_TEZ — permanent constraint
    /// (liquidity argument for DAL inclusion).
    #[test]
    #[should_panic(expected: ('shield: producer must be tez',))]
    fn test_shield_rejects_non_tez_producer_asset() {
        let mut fixture = build_fixture();
        fixture.asset_producer = 0xBADBEEF;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_shield_rejects_fee_public_mutation_via_signature_binding() {
        // fee is in the sighash but not in any commitment, so a fee
        // mutation only fails through the WOTS+ binding.
        let mut fixture = build_fixture();
        fixture.fee += 1;
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_shield_rejects_auth_domain_mutation_via_signature_binding() {
        // auth_domain doesn't appear in cm_new (so the recipient-commit
        // check passes), but it does feed pubkey_hash AND the sighash.
        // We have to keep pubkey_hash consistent with auth_domain or
        // the pubkey_hash check fires first; the cleanest mutation is
        // to flip both auth_domain and pubkey_hash in lockstep so we
        // exercise the sighash binding cleanly.
        let mut fixture = build_fixture();
        fixture.auth_domain += 1;
        fixture.pubkey_hash =
            deposit_pubkey_hash(
                fixture.auth_domain, fixture.auth_root, fixture.auth_pub_seed, fixture.blind,
            );
        run_verify(@fixture);
    }

    #[test]
    #[should_panic(expected: ('shield: wots sig len',))]
    fn test_shield_rejects_short_wots_signature() {
        let fixture = build_fixture();
        let mut short_sig: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < xmss_common::WOTS_CHAINS - 1 {
            short_sig.append(*fixture.wots_sig.at(i));
            i += 1;
        }
        verify(
            fixture.auth_domain,
            fixture.pubkey_hash,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
            fixture.blind,
            fixture.auth_idx,
            short_sig.span(),
            fixture.auth_siblings.span(),
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
            fixture.asset_new,
            fixture.asset_producer,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: auth sib len',))]
    fn test_shield_rejects_short_auth_siblings() {
        let fixture = build_fixture();
        let mut short_siblings: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < merkle::AUTH_DEPTH - 1 {
            short_siblings.append(*fixture.auth_siblings.at(i));
            i += 1;
        }
        verify(
            fixture.auth_domain,
            fixture.pubkey_hash,
            fixture.v_note,
            fixture.fee,
            fixture.producer_fee,
            fixture.cm_new,
            fixture.cm_producer,
            fixture.memo_ct_hash,
            fixture.producer_memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
            fixture.blind,
            fixture.auth_idx,
            fixture.wots_sig.span(),
            short_siblings.span(),
            fixture.producer_auth_root,
            fixture.producer_auth_pub_seed,
            fixture.producer_nk_tag,
            fixture.producer_d_j,
            fixture.producer_rseed,
            fixture.asset_new,
            fixture.asset_producer,
        );
    }
}
