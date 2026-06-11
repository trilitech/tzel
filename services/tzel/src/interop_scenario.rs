use crate::*;
use ml_kem::{ml_kem_768, KeyExport};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropShieldStep {
    pub sender: String,
    pub v: u64,
    pub fee: u64,
    pub producer_fee: u64,
    pub address: PaymentAddress,
    #[serde(with = "hex_f")]
    pub cm: F,
    pub enc: EncryptedNote,
    #[serde(with = "hex_f")]
    pub memo_ct_hash: F,
    #[serde(with = "hex_f")]
    pub producer_cm: F,
    pub producer_enc: EncryptedNote,
    #[serde(with = "hex_f")]
    pub producer_memo_ct_hash: F,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropTransferStep {
    #[serde(with = "hex_f")]
    pub root: F,
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
    pub fee: u64,
    // Multiasset 4-slot layout: 1 = recipient/change, 2 = recipient/change,
    // 3 = change_2 (empty in this tez-only scenario), 4 = producer-fee.
    #[serde(with = "hex_f")]
    pub cm_1: F,
    #[serde(with = "hex_f")]
    pub cm_2: F,
    #[serde(with = "hex_f")]
    pub cm_3: F,
    #[serde(with = "hex_f")]
    pub cm_4: F,
    pub enc_1: EncryptedNote,
    pub enc_2: EncryptedNote,
    pub enc_3: EncryptedNote,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_1: F,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_2: F,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_3: F,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_4: F,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropUnshieldStep {
    #[serde(with = "hex_f")]
    pub root: F,
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
    pub v_pub: u64,
    #[serde(with = "hex_f")]
    pub asset_pub: F,
    pub fee: u64,
    pub recipient: String,
    #[serde(with = "hex_f")]
    pub cm_change: F,
    pub enc_change: Option<EncryptedNote>,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_change: F,
    #[serde(with = "hex_f")]
    pub cm_change_2: F,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_change_2: F,
    #[serde(with = "hex_f")]
    pub cm_fee: F,
    pub enc_fee: EncryptedNote,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_fee: F,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropExpected {
    pub withdrawals: Vec<WithdrawalRecord>,
    pub tree_size: usize,
    pub nullifier_count: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropScenario {
    #[serde(with = "hex_f")]
    pub auth_domain: F,
    pub initial_alice_balance: u64,
    pub shield: InteropShieldStep,
    pub transfer: InteropTransferStep,
    pub unshield: InteropUnshieldStep,
    pub expected: InteropExpected,
}

struct DerivedScenarioAddress {
    payment: PaymentAddress,
    nk_spend: F,
}

fn interop_auth_root(d_j: &F, auth_pub_seed: &F) -> F {
    hash_two(&felt_tag(b"interop-auth"), &hash_two(d_j, auth_pub_seed))
}

fn fixed_felt(seed: u8) -> F {
    let mut out = ZERO;
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out[31] &= 0x07;
    out
}

fn fixed_ephemeral(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

const INTEROP_L1_RECIPIENT: &str = "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx";

fn derive_scenario_address(acc: &Account, j: u32) -> DerivedScenarioAddress {
    let d_j = derive_address(&acc.incoming_seed, j);
    let ask_j = derive_ask(&acc.ask_base, j);
    let auth_pub_seed = derive_auth_pub_seed(&ask_j);
    let auth_root = interop_auth_root(&d_j, &auth_pub_seed);
    let nk_spend = derive_nk_spend(&acc.nk, &d_j);
    let nk_tag = derive_nk_tag(&nk_spend);
    let (ek_v, _, ek_d, _) = derive_kem_keys(&acc.incoming_seed, j);
    DerivedScenarioAddress {
        payment: PaymentAddress {
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        },
        nk_spend,
    }
}

fn commit_for_address(address: &PaymentAddress, v: u64, rseed: &F) -> F {
    let rcm = derive_rcm(rseed);
    let otag = owner_tag(&address.auth_root, &address.auth_pub_seed, &address.nk_tag);
    commit(&address.d_j, v, &ASSET_TEZ, &rcm, &otag)
}

fn deterministic_note(
    address: &PaymentAddress,
    v: u64,
    rseed: &F,
    memo: &[u8],
    detect_seed: u8,
    view_seed: u8,
) -> (F, EncryptedNote, F) {
    let ek_v = ml_kem_768::EncapsulationKey::new(address.ek_v.as_slice().try_into().unwrap())
        .expect("valid ek_v");
    let ek_d = ml_kem_768::EncapsulationKey::new(address.ek_d.as_slice().try_into().unwrap())
        .expect("valid ek_d");
    let enc = encrypt_note_deterministic(
        v,
        rseed,
        Some(memo),
        &ek_v,
        &ek_d,
        &fixed_ephemeral(detect_seed),
        &fixed_ephemeral(view_seed),
    );
    let cm = commit_for_address(address, v, rseed);
    let mh = memo_ct_hash(&enc);
    (cm, enc, mh)
}

pub fn generate_interop_scenario() -> InteropScenario {
    let auth_domain = default_auth_domain();
    let initial_alice_balance = 500_001;

    let alice_acc = derive_account(&fixed_felt(0x11));
    let bob_acc = derive_account(&fixed_felt(0x55));
    let producer_acc = derive_account(&fixed_felt(0x77));

    let alice_addr0 = derive_scenario_address(&alice_acc, 0);
    let alice_addr1 = derive_scenario_address(&alice_acc, 1);
    let bob_addr0 = derive_scenario_address(&bob_acc, 0);
    let producer_addr0 = derive_scenario_address(&producer_acc, 0);

    let shield_rseed = fixed_felt(0x21);
    let (shield_cm, shield_enc, shield_mh) = deterministic_note(
        &alice_addr0.payment,
        400_000,
        &shield_rseed,
        b"interop-shield",
        0x31,
        0x41,
    );
    let shield_producer_rseed = fixed_felt(0x24);
    let (shield_producer_cm, shield_producer_enc, shield_producer_mh) = deterministic_note(
        &producer_addr0.payment,
        1,
        &shield_producer_rseed,
        b"interop-dal-shield",
        0x34,
        0x44,
    );

    let mut tree = MerkleTree::new();
    tree.append(shield_cm);
    tree.append(shield_producer_cm);
    let root_after_shield = tree.root();

    let shield_nf = nullifier(&alice_addr0.nk_spend, &shield_cm, 0);

    let transfer_rseed_1 = fixed_felt(0x22);
    let transfer_rseed_2 = fixed_felt(0x23);
    let transfer_rseed_3 = fixed_felt(0x25);
    let (transfer_cm_1, transfer_enc_1, transfer_mh_1) = deterministic_note(
        &alice_addr1.payment,
        99_999,
        &transfer_rseed_1,
        b"interop-change",
        0x32,
        0x42,
    );
    let (transfer_cm_2, transfer_enc_2, transfer_mh_2) = deterministic_note(
        &bob_addr0.payment,
        200_000,
        &transfer_rseed_2,
        b"interop-bob",
        0x33,
        0x43,
    );
    let (transfer_cm_3, transfer_enc_3, transfer_mh_3) = deterministic_note(
        &producer_addr0.payment,
        1,
        &transfer_rseed_3,
        b"interop-dal-transfer",
        0x35,
        0x45,
    );

    tree.append(transfer_cm_1);
    tree.append(transfer_cm_2);
    tree.append(transfer_cm_3);
    let root_after_transfer = tree.root();

    let bob_nf = nullifier(&bob_addr0.nk_spend, &transfer_cm_2, 3);
    let unshield_fee_rseed = fixed_felt(0x26);
    let (unshield_fee_cm, unshield_fee_enc, unshield_fee_mh) = deterministic_note(
        &producer_addr0.payment,
        1,
        &unshield_fee_rseed,
        b"interop-dal-unshield",
        0x36,
        0x46,
    );

    InteropScenario {
        auth_domain,
        initial_alice_balance,
        shield: InteropShieldStep {
            sender: "alice".into(),
            v: 400_000,
            fee: MIN_TX_FEE,
            producer_fee: 1,
            address: alice_addr0.payment,
            cm: shield_cm,
            enc: shield_enc,
            memo_ct_hash: shield_mh,
            producer_cm: shield_producer_cm,
            producer_enc: shield_producer_enc,
            producer_memo_ct_hash: shield_producer_mh,
        },
        transfer: InteropTransferStep {
            root: root_after_shield,
            nullifiers: vec![shield_nf],
            fee: MIN_TX_FEE,
            // slot 3 (change_2) empty; producer-fee in slot 4
            cm_1: transfer_cm_1,
            cm_2: transfer_cm_2,
            cm_3: ZERO,
            cm_4: transfer_cm_3,
            enc_1: transfer_enc_1,
            enc_2: transfer_enc_2,
            enc_3: transfer_enc_3,
            memo_ct_hash_1: transfer_mh_1,
            memo_ct_hash_2: transfer_mh_2,
            memo_ct_hash_3: ZERO,
            memo_ct_hash_4: transfer_mh_3,
        },
        unshield: InteropUnshieldStep {
            root: root_after_transfer,
            nullifiers: vec![bob_nf],
            v_pub: 99_999,
            asset_pub: ASSET_TEZ,
            fee: MIN_TX_FEE,
            recipient: INTEROP_L1_RECIPIENT.into(),
            cm_change: ZERO,
            enc_change: None,
            memo_ct_hash_change: ZERO,
            cm_change_2: ZERO,
            memo_ct_hash_change_2: ZERO,
            cm_fee: unshield_fee_cm,
            enc_fee: unshield_fee_enc,
            memo_ct_hash_fee: unshield_fee_mh,
        },
        expected: InteropExpected {
            withdrawals: vec![WithdrawalRecord {
                asset_id: ASSET_TEZ,
                recipient: INTEROP_L1_RECIPIENT.into(),
                amount: 99_999,
            }],
            tree_size: 6,
            nullifier_count: 2,
        },
    }
}

pub fn generate_interop_scenario_json() -> String {
    serde_json::to_string_pretty(&generate_interop_scenario()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generated_interop_scenario_is_self_consistent() {
        let scenario = generate_interop_scenario();
        let alice_acc = derive_account(&fixed_felt(0x11));
        let bob_acc = derive_account(&fixed_felt(0x55));
        let producer_acc = derive_account(&fixed_felt(0x77));
        let alice_addr0 = derive_scenario_address(&alice_acc, 0);
        let alice_addr1 = derive_scenario_address(&alice_acc, 1);
        let bob_addr0 = derive_scenario_address(&bob_acc, 0);
        let producer_addr0 = derive_scenario_address(&producer_acc, 0);

        assert_eq!(scenario.auth_domain, default_auth_domain());
        assert_eq!(scenario.initial_alice_balance, 500_001);
        assert_eq!(scenario.shield.address.d_j, alice_addr0.payment.d_j);
        assert_eq!(
            scenario.transfer.cm_1,
            commit_for_address(&alice_addr1.payment, 99_999, &fixed_felt(0x22))
        );
        assert_eq!(
            scenario.transfer.cm_2,
            commit_for_address(&bob_addr0.payment, 200_000, &fixed_felt(0x23))
        );
        assert_eq!(scenario.transfer.cm_3, ZERO);
        assert_eq!(
            scenario.transfer.cm_4,
            commit_for_address(&producer_addr0.payment, 1, &fixed_felt(0x25))
        );

        let (shield_cm, _shield_enc, shield_mh) = deterministic_note(
            &alice_addr0.payment,
            400_000,
            &fixed_felt(0x21),
            b"interop-shield",
            0x31,
            0x41,
        );
        assert_eq!(scenario.shield.fee, MIN_TX_FEE);
        assert_eq!(scenario.shield.producer_fee, 1);
        assert_eq!(scenario.shield.cm, shield_cm);
        assert_eq!(scenario.shield.memo_ct_hash, shield_mh);
        assert_eq!(
            scenario.shield.producer_cm,
            commit_for_address(&producer_addr0.payment, 1, &fixed_felt(0x24))
        );

        let mut tree = MerkleTree::new();
        tree.append(scenario.shield.cm);
        tree.append(scenario.shield.producer_cm);
        assert_eq!(scenario.transfer.root, tree.root());
        assert_eq!(
            scenario.transfer.nullifiers,
            vec![nullifier(&alice_addr0.nk_spend, &scenario.shield.cm, 0)]
        );

        assert_eq!(scenario.transfer.fee, MIN_TX_FEE);
        tree.append(scenario.transfer.cm_1);
        tree.append(scenario.transfer.cm_2);
        // slot 3 (change_2) is empty; producer-fee is slot 4
        tree.append(scenario.transfer.cm_4);
        assert_eq!(scenario.unshield.root, tree.root());
        assert_eq!(
            scenario.unshield.nullifiers,
            vec![nullifier(&bob_addr0.nk_spend, &scenario.transfer.cm_2, 3)]
        );

        assert_eq!(scenario.unshield.v_pub, 99_999);
        assert_eq!(scenario.unshield.fee, MIN_TX_FEE);
        assert_eq!(scenario.unshield.recipient, INTEROP_L1_RECIPIENT);
        assert_eq!(scenario.unshield.cm_change, ZERO);
        assert!(scenario.unshield.enc_change.is_none());
        assert_eq!(scenario.unshield.memo_ct_hash_change, ZERO);
        assert_eq!(
            scenario.unshield.cm_fee,
            commit_for_address(&producer_addr0.payment, 1, &fixed_felt(0x26))
        );
        tree.append(scenario.unshield.cm_fee);

        assert_eq!(
            scenario.expected.withdrawals,
            vec![WithdrawalRecord {
                asset_id: ASSET_TEZ,
                recipient: INTEROP_L1_RECIPIENT.into(),
                amount: 99_999,
            }]
        );
        assert_eq!(scenario.expected.tree_size, tree.leaves.len());
        assert_eq!(scenario.expected.nullifier_count, 2);
    }

    #[test]
    fn test_deterministic_note_is_stable_and_binds_commitment() {
        let acc = derive_account(&fixed_felt(0x44));
        let addr = derive_scenario_address(&acc, 3);
        let rseed = fixed_felt(0x66);
        let (cm1, enc1, mh1) =
            deterministic_note(&addr.payment, 77, &rseed, b"interop-note", 0x12, 0x34);
        let (cm2, enc2, mh2) =
            deterministic_note(&addr.payment, 77, &rseed, b"interop-note", 0x12, 0x34);

        assert_eq!(cm1, cm2);
        assert_eq!(mh1, mh2);
        assert_eq!(enc1.tag, enc2.tag);
        assert_eq!(enc1.encrypted_data, enc2.encrypted_data);
        assert_eq!(cm1, commit_for_address(&addr.payment, 77, &rseed));
        assert_eq!(mh1, memo_ct_hash(&enc1));
    }

    #[test]
    fn test_generate_interop_scenario_json_roundtrip() {
        let json = generate_interop_scenario_json();
        let reparsed: InteropScenario =
            serde_json::from_str(&json).expect("interop scenario json should parse");

        assert_eq!(reparsed.shield.sender, "alice");
        assert_eq!(reparsed.unshield.recipient, INTEROP_L1_RECIPIENT);
        assert_eq!(
            reparsed.expected.withdrawals,
            vec![WithdrawalRecord {
                asset_id: ASSET_TEZ,
                recipient: INTEROP_L1_RECIPIENT.into(),
                amount: 99_999,
            }]
        );
        assert_eq!(reparsed.expected.tree_size, 6);
        assert_eq!(reparsed.expected.nullifier_count, 2);
    }

    // Golden per-flow sighash values on fixed inputs.  These are the
    // SHARED cross-impl reference: ocaml/test/test_main.ml pins
    // Transaction.{shield,transfer,unshield}_sighash to the SAME three
    // constants, so the OCaml port's sighash field-sets/order stay
    // byte-identical to the kernel's core::*_sighash.  If either side's
    // sighash drifts (a dropped or reordered field — exactly the
    // multiasset regression this fixes), its test fails.  Inputs:
    // shield  (auth=1, pkh=2, v=10, fee=3, pfee=4, cm_r=5, cm_p=6, mh_r=7,
    //          mh_p=8, asset_r=0, asset_p=0)
    // transfer(auth=1, root=2, nf=[3], fee=4, cm1=5, cm2=6, cm3=0, cm4=7,
    //          mh1=8, mh2=9, mh3=0, mh4=10)
    // unshield(auth=1, root=2, nf=[3], v=10, asset_pub=0, fee=4, recip=5,
    //          cm_change=6, mh_change=7, cm_change2=0, mh_change2=0,
    //          cm_fee=8, mh_fee=9)
    #[test]
    fn test_sighash_golden_matches_core() {
        let f = |n: u64| u64_to_felt(n);
        assert_eq!(
            hex::encode(shield_sighash(
                &f(1), &f(2), 10, 3, 4, &f(5), &f(6), &f(7), &f(8), &f(0), &f(0)
            )),
            "fbd968dd9f9d00603a75c08046c200d3d8d6fb7e7119187c84e37837585f4b04"
        );
        assert_eq!(
            hex::encode(transfer_sighash(
                &f(1), &f(2), &[f(3)], 4, &f(5), &f(6), &f(0), &f(7), &f(8), &f(9), &f(0), &f(10)
            )),
            "cb2f332c6f6047f457a611cab39719e3378f864124504d6334ae70536a2f0401"
        );
        assert_eq!(
            hex::encode(unshield_sighash(
                &f(1), &f(2), &[f(3)], 10, &f(0), 4, &f(5), &f(6), &f(7), &f(0), &f(0), &f(8), &f(9)
            )),
            "360b52a6051b21dbe78b12baf6a933f769b9a4b081481e9186c78aeaa07ca507"
        );
        // Multiasset: a shield whose recipient note carries a real FA2
        // asset_id (asset_producer stays ASSET_TEZ). Pins the nonzero
        // asset_recipient fold so the OCaml port's FA2 shield sighash is
        // verified byte-identical (mirror in ocaml test_main.ml).
        let fa2 = derive_asset_id("KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc");
        assert_eq!(
            hex::encode(shield_sighash(
                &f(1), &f(2), 10, 3, 4, &f(5), &f(6), &f(7), &f(8), &fa2, &ZERO
            )),
            "bcc633ff2b15f460d810b0e307a6ab6e0001521645bc7c404eb1071a5e75b603"
        );
        // Multiasset: a note commitment binding a nonzero FA2 asset tag.
        // The tez protocol vectors only exercise asset = ASSET_TEZ (zero);
        // this pins the FA2 (nonzero asset) commitment so the OCaml port's
        // hash_commit is verified byte-identical for FA2 notes too.
        assert_eq!(
            hex::encode(commit(&f(1), 10, &fa2, &f(2), &f(3))),
            "fce43f618a4cb4dfcabb5a7d1b472125d025f98899c4c2a350b0c7c8a65b3807"
        );
    }

}
