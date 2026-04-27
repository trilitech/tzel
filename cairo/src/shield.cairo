/// Shield circuit (post deposit-pool / pubkey_hash redesign).
///
/// # Public outputs
///   [auth_domain, pubkey_hash, v_note, fee, producer_fee,
///    cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash]
///
/// # Spend authorization
///   In-circuit XMSS-style WOTS+ signature verification under the
///   recipient's auth tree, mirroring the transfer / unshield circuits.
///   The signature signs the shield sighash:
///     fold(0x03, auth_domain, pubkey_hash, v_note, fee, producer_fee,
///          cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash)
///   so a delegated prover holding the witness still cannot redirect funds,
///   change values, or swap recipients without the wallet's signing key.
///
/// # Constraints
///   owner_tag = H_owner(auth_root, auth_pub_seed, nk_tag)
///   cm_new   = H_commit(d_j, v_note, H(rseed), owner_tag)
///   producer_owner_tag = H_owner(producer_auth_root, producer_auth_pub_seed,
///                                producer_nk_tag)
///   cm_producer = H_commit(producer_d_j, producer_fee, H(producer_rseed),
///                          producer_owner_tag)
///   producer_fee > 0
///   pubkey_hash = fold(0x04, auth_domain, auth_root, auth_pub_seed, blind)
///   WOTS+(sighash, auth_root, auth_pub_seed, auth_idx, wots_sig, auth_siblings)

use tzel::blake_hash as hash;
use tzel::{merkle, xmss_common};

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
    // WOTS+ signature material
    auth_idx: u64,
    wots_sig_flat: Span<felt252>,
    auth_siblings_flat: Span<felt252>,
    // private inputs (producer-fee note witness)
    producer_auth_root: felt252,
    producer_auth_pub_seed: felt252,
    producer_nk_tag: felt252,
    producer_d_j: felt252,
    producer_rseed: felt252,
) -> Array<felt252> {
    assert(wots_sig_flat.len() == xmss_common::WOTS_CHAINS, 'shield: wots sig len');
    assert(auth_siblings_flat.len() == merkle::AUTH_DEPTH, 'shield: auth sib len');

    // Recipient commitment.
    let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
    let rcm = hash::derive_rcm(rseed);
    assert(hash::commit(d_j, v_note, rcm, otag) == cm_new, 'shield: bad commitment');

    // Producer-fee commitment.
    let producer_otag =
        hash::owner_tag(producer_auth_root, producer_auth_pub_seed, producer_nk_tag);
    let producer_rcm = hash::derive_rcm(producer_rseed);
    assert(
        hash::commit(producer_d_j, producer_fee, producer_rcm, producer_otag) == cm_producer,
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
    //                producer_fee, cm_new, cm_producer, memo_ct_hash,
    //                producer_memo_ct_hash).
    let mut sighash = hash::sighash_fold(0x03, auth_domain);
    sighash = hash::sighash_fold(sighash, pubkey_hash);
    sighash = hash::sighash_fold(sighash, v_note.into());
    sighash = hash::sighash_fold(sighash, fee.into());
    sighash = hash::sighash_fold(sighash, producer_fee.into());
    sighash = hash::sighash_fold(sighash, cm_new);
    sighash = hash::sighash_fold(sighash, cm_producer);
    sighash = hash::sighash_fold(sighash, memo_ct_hash);
    sighash = hash::sighash_fold(sighash, producer_memo_ct_hash);

    // In-circuit WOTS+ verify under the recipient's auth tree.
    let auth_idx_u32: u32 = auth_idx.try_into().unwrap();
    let recovered_pk = xmss_common::xmss_recover_pk(
        sighash,
        auth_pub_seed,
        auth_idx_u32,
        wots_sig_flat,
    );
    let leaf = xmss_common::xmss_ltree(auth_pub_seed, auth_idx_u32, recovered_pk.span());
    xmss_common::xmss_verify_auth(
        leaf,
        auth_root,
        auth_pub_seed,
        auth_idx_u32,
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
    ]
}

#[cfg(test)]
mod tests {
    use tzel::{blake_hash as hash, merkle, xmss_common};
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
        auth_idx: u64,
        wots_sig: Array<felt252>,
        auth_siblings: Array<felt252>,
        producer_auth_root: felt252,
        producer_auth_pub_seed: felt252,
        producer_nk_tag: felt252,
        producer_d_j: felt252,
        producer_rseed: felt252,
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
        hash::commit(d_j, v, rcm, otag)
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
    ) -> felt252 {
        let mut sighash = hash::sighash_fold(0x03, auth_domain);
        sighash = hash::sighash_fold(sighash, pubkey_hash);
        sighash = hash::sighash_fold(sighash, v_note.into());
        sighash = hash::sighash_fold(sighash, fee.into());
        sighash = hash::sighash_fold(sighash, producer_fee.into());
        sighash = hash::sighash_fold(sighash, cm_new);
        sighash = hash::sighash_fold(sighash, cm_producer);
        sighash = hash::sighash_fold(sighash, memo_ct_hash);
        sighash = hash::sighash_fold(sighash, producer_memo_ct_hash);
        sighash
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
            auth_idx: auth_idx.into(),
            wots_sig,
            auth_siblings,
            producer_auth_root,
            producer_auth_pub_seed,
            producer_nk_tag,
            producer_d_j,
            producer_rseed,
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
        )
    }

    #[test]
    fn test_shield_accepts_valid_statement() {
        let fixture = build_fixture();
        let outputs = run_verify(@fixture);
        assert(outputs.len() == 9, 'shield outputs len');
        assert(*outputs.at(0) == fixture.auth_domain, 'shield out domain');
        assert(*outputs.at(1) == fixture.pubkey_hash, 'shield out pkh');
        assert(*outputs.at(2) == fixture.v_note.into(), 'shield out v');
        assert(*outputs.at(3) == fixture.fee.into(), 'shield out fee');
        assert(*outputs.at(4) == fixture.producer_fee.into(), 'shield out prod fee');
        assert(*outputs.at(5) == fixture.cm_new, 'shield out cm new');
        assert(*outputs.at(6) == fixture.cm_producer, 'shield out cm prod');
        assert(*outputs.at(7) == fixture.memo_ct_hash, 'shield out mh');
        assert(*outputs.at(8) == fixture.producer_memo_ct_hash, 'shield out prod mh');
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
            let auth_idx_u32: u32 = fixture.auth_idx.try_into().unwrap();
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
                ),
                fixture.auth_pub_seed,
                auth_idx_u32,
                mutated_wots.span(),
            );
            let leaf = xmss_common::xmss_ltree(
                fixture.auth_pub_seed, auth_idx_u32, recovered_pk.span(),
            );
            let mutated_root = auth_root_from_leaf(
                leaf, fixture.auth_pub_seed, auth_idx_u32, fixture.auth_siblings.span(),
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
        );
    }
}
