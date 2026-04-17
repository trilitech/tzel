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
    #[serde(with = "hex_f")]
    pub cm_1: F,
    #[serde(with = "hex_f")]
    pub cm_2: F,
    #[serde(with = "hex_f")]
    pub cm_3: F,
    pub enc_1: EncryptedNote,
    pub enc_2: EncryptedNote,
    pub enc_3: EncryptedNote,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_1: F,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_2: F,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_3: F,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropUnshieldStep {
    #[serde(with = "hex_f")]
    pub root: F,
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
    pub v_pub: u64,
    pub fee: u64,
    pub recipient: String,
    #[serde(with = "hex_f")]
    pub cm_change: F,
    pub enc_change: Option<EncryptedNote>,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_change: F,
    #[serde(with = "hex_f")]
    pub cm_fee: F,
    pub enc_fee: EncryptedNote,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_fee: F,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropExpected {
    pub alice_public_balance: u64,
    pub bob_public_balance: u64,
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
    commit(&address.d_j, v, &rcm, &otag)
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
            cm_1: transfer_cm_1,
            cm_2: transfer_cm_2,
            cm_3: transfer_cm_3,
            enc_1: transfer_enc_1,
            enc_2: transfer_enc_2,
            enc_3: transfer_enc_3,
            memo_ct_hash_1: transfer_mh_1,
            memo_ct_hash_2: transfer_mh_2,
            memo_ct_hash_3: transfer_mh_3,
        },
        unshield: InteropUnshieldStep {
            root: root_after_transfer,
            nullifiers: vec![bob_nf],
            v_pub: 99_999,
            fee: MIN_TX_FEE,
            recipient: "bob".into(),
            cm_change: ZERO,
            enc_change: None,
            memo_ct_hash_change: ZERO,
            cm_fee: unshield_fee_cm,
            enc_fee: unshield_fee_enc,
            memo_ct_hash_fee: unshield_fee_mh,
        },
        expected: InteropExpected {
            alice_public_balance: 0,
            bob_public_balance: 99_999,
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
        assert_eq!(
            scenario.transfer.cm_3,
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
        tree.append(scenario.transfer.cm_3);
        assert_eq!(scenario.unshield.root, tree.root());
        assert_eq!(
            scenario.unshield.nullifiers,
            vec![nullifier(&bob_addr0.nk_spend, &scenario.transfer.cm_2, 3)]
        );

        assert_eq!(scenario.unshield.v_pub, 99_999);
        assert_eq!(scenario.unshield.fee, MIN_TX_FEE);
        assert_eq!(scenario.unshield.recipient, "bob");
        assert_eq!(scenario.unshield.cm_change, ZERO);
        assert!(scenario.unshield.enc_change.is_none());
        assert_eq!(scenario.unshield.memo_ct_hash_change, ZERO);
        assert_eq!(
            scenario.unshield.cm_fee,
            commit_for_address(&producer_addr0.payment, 1, &fixed_felt(0x26))
        );
        tree.append(scenario.unshield.cm_fee);

        assert_eq!(scenario.expected.alice_public_balance, 0);
        assert_eq!(scenario.expected.bob_public_balance, 99_999);
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
        assert_eq!(reparsed.unshield.recipient, "bob");
        assert_eq!(reparsed.expected.tree_size, 6);
        assert_eq!(reparsed.expected.nullifier_count, 2);
    }
}
