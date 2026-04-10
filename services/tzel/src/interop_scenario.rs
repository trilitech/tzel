use crate::*;
use ml_kem::{ml_kem_768, KeyExport};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropShieldStep {
    pub sender: String,
    pub v: u64,
    pub address: PaymentAddress,
    #[serde(with = "hex_f")]
    pub cm: F,
    pub enc: EncryptedNote,
    #[serde(with = "hex_f")]
    pub memo_ct_hash: F,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropTransferStep {
    #[serde(with = "hex_f")]
    pub root: F,
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
    #[serde(with = "hex_f")]
    pub cm_1: F,
    #[serde(with = "hex_f")]
    pub cm_2: F,
    pub enc_1: EncryptedNote,
    pub enc_2: EncryptedNote,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_1: F,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_2: F,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropUnshieldStep {
    #[serde(with = "hex_f")]
    pub root: F,
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
    pub v_pub: u64,
    pub recipient: String,
    #[serde(with = "hex_f")]
    pub cm_change: F,
    pub enc_change: Option<EncryptedNote>,
    #[serde(with = "hex_f")]
    pub memo_ct_hash_change: F,
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
    let (auth_root, _) = build_auth_tree(&ask_j);
    let nk_spend = derive_nk_spend(&acc.nk, &d_j);
    let nk_tag = derive_nk_tag(&nk_spend);
    let (ek_v, _, ek_d, _) = derive_kem_keys(&acc.incoming_seed, j);
    DerivedScenarioAddress {
        payment: PaymentAddress {
            d_j,
            auth_root,
            nk_tag,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        },
        nk_spend,
    }
}

fn commit_for_address(address: &PaymentAddress, v: u64, rseed: &F) -> F {
    let rcm = derive_rcm(rseed);
    let otag = owner_tag(&address.auth_root, &address.nk_tag);
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
    let initial_alice_balance = 100;

    let alice_acc = derive_account(&fixed_felt(0x11));
    let bob_acc = derive_account(&fixed_felt(0x55));

    let alice_addr0 = derive_scenario_address(&alice_acc, 0);
    let alice_addr1 = derive_scenario_address(&alice_acc, 1);
    let bob_addr0 = derive_scenario_address(&bob_acc, 0);

    let shield_rseed = fixed_felt(0x21);
    let (shield_cm, shield_enc, shield_mh) = deterministic_note(
        &alice_addr0.payment,
        100,
        &shield_rseed,
        b"interop-shield",
        0x31,
        0x41,
    );

    let mut tree = MerkleTree::new();
    tree.append(shield_cm);
    let root_after_shield = tree.root();

    let shield_nf = nullifier(&alice_addr0.nk_spend, &shield_cm, 0);

    let transfer_rseed_1 = fixed_felt(0x22);
    let transfer_rseed_2 = fixed_felt(0x23);
    let (transfer_cm_1, transfer_enc_1, transfer_mh_1) = deterministic_note(
        &alice_addr1.payment,
        60,
        &transfer_rseed_1,
        b"interop-change",
        0x32,
        0x42,
    );
    let (transfer_cm_2, transfer_enc_2, transfer_mh_2) = deterministic_note(
        &bob_addr0.payment,
        40,
        &transfer_rseed_2,
        b"interop-bob",
        0x33,
        0x43,
    );

    tree.append(transfer_cm_1);
    tree.append(transfer_cm_2);
    let root_after_transfer = tree.root();

    let bob_nf = nullifier(&bob_addr0.nk_spend, &transfer_cm_2, 2);

    InteropScenario {
        auth_domain,
        initial_alice_balance,
        shield: InteropShieldStep {
            sender: "alice".into(),
            v: 100,
            address: alice_addr0.payment,
            cm: shield_cm,
            enc: shield_enc,
            memo_ct_hash: shield_mh,
        },
        transfer: InteropTransferStep {
            root: root_after_shield,
            nullifiers: vec![shield_nf],
            cm_1: transfer_cm_1,
            cm_2: transfer_cm_2,
            enc_1: transfer_enc_1,
            enc_2: transfer_enc_2,
            memo_ct_hash_1: transfer_mh_1,
            memo_ct_hash_2: transfer_mh_2,
        },
        unshield: InteropUnshieldStep {
            root: root_after_transfer,
            nullifiers: vec![bob_nf],
            v_pub: 40,
            recipient: "bob".into(),
            cm_change: ZERO,
            enc_change: None,
            memo_ct_hash_change: ZERO,
        },
        expected: InteropExpected {
            alice_public_balance: 0,
            bob_public_balance: 40,
            tree_size: 3,
            nullifier_count: 2,
        },
    }
}

pub fn generate_interop_scenario_json() -> String {
    serde_json::to_string_pretty(&generate_interop_scenario()).unwrap()
}
