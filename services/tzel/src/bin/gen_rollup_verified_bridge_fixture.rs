use ml_kem::{ml_kem_768, KeyExport};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tzel_services::*;
use tzel_verifier::{
    encode_verify_meta, load_program_hashes, DirectProofVerifier, ProofBundle as VerifyProofBundle,
};

const PROVER_TOOLCHAIN: &str = "+nightly-2025-07-14";
const FIXTURE_PATH: &str = "tezos/rollup-kernel/testdata/verified_bridge_flow.json";
const BRIDGE_TICKETER: &str = "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc";
const WITHDRAWAL_RECIPIENT: &str = "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx";
const DAL_PRODUCER_FEE: u64 = 1;
const SHIELD_AMOUNT: u64 = 400_000;
const TRANSFER_CHANGE_AMOUNT: u64 = 99_999;
const TRANSFER_RECIPIENT_AMOUNT: u64 = 200_000;
const UNSHIELD_AMOUNT: u64 = 99_999;

#[derive(Serialize)]
struct VerifiedBridgeFixture {
    #[serde(with = "hex_f")]
    auth_domain: F,
    program_hashes: ProgramHashes,
    bridge_ticketer: String,
    withdrawal_recipient: String,
    shield: ShieldReq,
    transfer: TransferReq,
    unshield: UnshieldReq,
}

struct DerivedAddress {
    payment: PaymentAddress,
    ask_j: F,
    nk_spend: F,
    auth_path_0: Vec<F>,
}

#[derive(Deserialize)]
struct FixtureWallet {
    #[serde(with = "hex_f")]
    master_sk: F,
    addresses: Vec<FixtureAddressState>,
}

#[derive(Deserialize)]
struct FixtureAddressState {
    index: u32,
    #[serde(with = "hex_f")]
    d_j: F,
    #[serde(with = "hex_f")]
    auth_root: F,
    #[serde(with = "hex_f")]
    auth_pub_seed: F,
    #[serde(with = "hex_f")]
    nk_tag: F,
    bds: FixtureBdsState,
}

#[derive(Deserialize)]
struct FixtureBdsState {
    next_index: u32,
    #[serde(with = "hex_f_vec")]
    auth_path: Vec<F>,
}

fn main() -> Result<(), String> {
    let fixture = build_fixture()?;
    let output_path = workspace_root().join(FIXTURE_PATH);
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create fixture dir: {}", e))?;
    }
    let json =
        serde_json::to_string_pretty(&fixture).map_err(|e| format!("encode fixture: {}", e))?;
    std::fs::write(&output_path, json).map_err(|e| format!("write fixture: {}", e))?;
    println!("{}", output_path.display());
    Ok(())
}

fn build_fixture() -> Result<VerifiedBridgeFixture, String> {
    let auth_domain = default_auth_domain();
    let program_hashes = load_program_hashes(executables_dir().to_str().unwrap())?;
    let wallet = load_base_wallet_fixture()?;

    let alice_addr_0 = fixture_address(&wallet, 0)?;
    let alice_addr_1 = fixture_address(&wallet, 1)?;
    let bob_addr_0 = fixture_address(&wallet, 2)?;

    let shield_rseed = fixed_felt(0x21);
    let shield_enc = deterministic_note(
        &alice_addr_0.payment,
        SHIELD_AMOUNT,
        &shield_rseed,
        b"verified-bridge-shield",
        0x31,
        0x41,
    )?;
    let shield_cm = note_commitment(&alice_addr_0.payment, SHIELD_AMOUNT, &shield_rseed);
    let shield_producer_rseed = fixed_felt(0x24);
    let shield_producer_enc = deterministic_note(
        &alice_addr_1.payment,
        DAL_PRODUCER_FEE,
        &shield_producer_rseed,
        b"verified-bridge-dal-shield",
        0x34,
        0x44,
    )?;
    let shield_producer_cm = note_commitment(
        &alice_addr_1.payment,
        DAL_PRODUCER_FEE,
        &shield_producer_rseed,
    );
    let shield_proof = generate_shield_proof(
        &program_hashes,
        "alice",
        SHIELD_AMOUNT,
        MIN_TX_FEE,
        DAL_PRODUCER_FEE,
        &alice_addr_0.payment,
        &shield_rseed,
        &shield_enc,
        shield_cm,
        &alice_addr_1.payment,
        &shield_producer_rseed,
        &shield_producer_enc,
        shield_producer_cm,
    )?;

    let mut tree = MerkleTree::new();
    tree.append(shield_cm);
    tree.append(shield_producer_cm);
    let root_after_shield = tree.root();
    let shield_nf = nullifier(&alice_addr_0.nk_spend, &shield_cm, 0);

    let transfer_rseed_change = fixed_felt(0x22);
    let transfer_rseed_bob = fixed_felt(0x23);
    let transfer_rseed_producer = fixed_felt(0x25);
    let transfer_enc_change = deterministic_note(
        &alice_addr_1.payment,
        TRANSFER_CHANGE_AMOUNT,
        &transfer_rseed_change,
        b"verified-bridge-change",
        0x32,
        0x42,
    )?;
    let transfer_cm_change = note_commitment(
        &alice_addr_1.payment,
        TRANSFER_CHANGE_AMOUNT,
        &transfer_rseed_change,
    );
    let transfer_enc_bob = deterministic_note(
        &bob_addr_0.payment,
        TRANSFER_RECIPIENT_AMOUNT,
        &transfer_rseed_bob,
        b"verified-bridge-bob",
        0x33,
        0x43,
    )?;
    let transfer_cm_bob = note_commitment(
        &bob_addr_0.payment,
        TRANSFER_RECIPIENT_AMOUNT,
        &transfer_rseed_bob,
    );
    let transfer_enc_producer = deterministic_note(
        &alice_addr_1.payment,
        DAL_PRODUCER_FEE,
        &transfer_rseed_producer,
        b"verified-bridge-dal-transfer",
        0x35,
        0x45,
    )?;
    let transfer_cm_producer = note_commitment(
        &alice_addr_1.payment,
        DAL_PRODUCER_FEE,
        &transfer_rseed_producer,
    );
    let transfer_proof = generate_transfer_proof(
        auth_domain,
        &program_hashes,
        root_after_shield,
        shield_nf,
        &alice_addr_0,
        shield_cm,
        SHIELD_AMOUNT,
        &shield_rseed,
        MIN_TX_FEE,
        transfer_cm_change,
        &alice_addr_1.payment,
        TRANSFER_CHANGE_AMOUNT,
        &transfer_rseed_change,
        &transfer_enc_change,
        transfer_cm_bob,
        &bob_addr_0.payment,
        TRANSFER_RECIPIENT_AMOUNT,
        &transfer_rseed_bob,
        &transfer_enc_bob,
        transfer_cm_producer,
        &alice_addr_1.payment,
        DAL_PRODUCER_FEE,
        &transfer_rseed_producer,
        &transfer_enc_producer,
        &tree,
    )?;

    tree.append(transfer_cm_change);
    tree.append(transfer_cm_bob);
    tree.append(transfer_cm_producer);
    let root_after_transfer = tree.root();
    let bob_nf = nullifier(&bob_addr_0.nk_spend, &transfer_cm_bob, 3);
    let unshield_fee_rseed = fixed_felt(0x26);
    let unshield_fee_enc = deterministic_note(
        &alice_addr_1.payment,
        DAL_PRODUCER_FEE,
        &unshield_fee_rseed,
        b"verified-bridge-dal-unshield",
        0x36,
        0x46,
    )?;
    let unshield_fee_cm =
        note_commitment(&alice_addr_1.payment, DAL_PRODUCER_FEE, &unshield_fee_rseed);
    let unshield_proof = generate_unshield_proof(
        auth_domain,
        &program_hashes,
        root_after_transfer,
        bob_nf,
        &bob_addr_0,
        transfer_cm_bob,
        TRANSFER_RECIPIENT_AMOUNT,
        &transfer_rseed_bob,
        UNSHIELD_AMOUNT,
        MIN_TX_FEE,
        "bob",
        &alice_addr_1.payment,
        DAL_PRODUCER_FEE,
        &unshield_fee_rseed,
        &unshield_fee_enc,
        &tree,
    )?;

    Ok(VerifiedBridgeFixture {
        auth_domain,
        program_hashes,
        bridge_ticketer: BRIDGE_TICKETER.into(),
        withdrawal_recipient: WITHDRAWAL_RECIPIENT.into(),
        shield: ShieldReq {
            sender: "alice".into(),
            v: SHIELD_AMOUNT,
            fee: MIN_TX_FEE,
            producer_fee: DAL_PRODUCER_FEE,
            address: alice_addr_0.payment,
            memo: Some("verified-bridge-shield".into()),
            proof: shield_proof,
            client_cm: shield_cm,
            client_enc: Some(shield_enc),
            producer_cm: shield_producer_cm,
            producer_enc: Some(shield_producer_enc),
        },
        transfer: TransferReq {
            root: root_after_shield,
            nullifiers: vec![shield_nf],
            fee: MIN_TX_FEE,
            cm_1: transfer_cm_change,
            cm_2: transfer_cm_bob,
            cm_3: transfer_cm_producer,
            enc_1: transfer_enc_change,
            enc_2: transfer_enc_bob,
            enc_3: transfer_enc_producer,
            proof: transfer_proof,
        },
        unshield: UnshieldReq {
            root: root_after_transfer,
            nullifiers: vec![bob_nf],
            v_pub: UNSHIELD_AMOUNT,
            fee: MIN_TX_FEE,
            recipient: "bob".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee: unshield_fee_cm,
            enc_fee: unshield_fee_enc,
            proof: unshield_proof,
        },
    })
}

fn generate_shield_proof(
    program_hashes: &ProgramHashes,
    sender: &str,
    amount: u64,
    fee: u64,
    producer_fee: u64,
    address: &PaymentAddress,
    rseed: &F,
    enc: &EncryptedNote,
    cm: F,
    producer_address: &PaymentAddress,
    producer_rseed: &F,
    producer_enc: &EncryptedNote,
    producer_cm: F,
) -> Result<Proof, String> {
    let args = vec![
        felt_u64_to_hex(18),
        felt_u64_to_hex(amount),
        felt_u64_to_hex(fee),
        felt_u64_to_hex(producer_fee),
        felt_to_hex(&cm),
        felt_to_hex(&producer_cm),
        felt_to_hex(&hash(sender.as_bytes())),
        felt_to_hex(&memo_ct_hash(enc)),
        felt_to_hex(&memo_ct_hash(producer_enc)),
        felt_to_hex(&address.auth_root),
        felt_to_hex(&address.auth_pub_seed),
        felt_to_hex(&address.nk_tag),
        felt_to_hex(&address.d_j),
        felt_to_hex(rseed),
        felt_to_hex(&producer_address.auth_root),
        felt_to_hex(&producer_address.auth_pub_seed),
        felt_to_hex(&producer_address.nk_tag),
        felt_to_hex(&producer_address.d_j),
        felt_to_hex(producer_rseed),
    ];
    let proof = proof_from_bundle(generate_stark_bundle("run_shield.executable.json", &args)?);
    DirectProofVerifier::verified(false, program_hashes.clone())
        .validate(&proof, CircuitKind::Shield)?;
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
fn generate_transfer_proof(
    auth_domain: F,
    program_hashes: &ProgramHashes,
    root: F,
    nf: F,
    input_addr: &DerivedAddress,
    input_cm: F,
    input_value: u64,
    input_rseed: &F,
    fee: u64,
    cm_1: F,
    output_1: &PaymentAddress,
    v_1: u64,
    rseed_1: &F,
    enc_1: &EncryptedNote,
    cm_2: F,
    output_2: &PaymentAddress,
    v_2: u64,
    rseed_2: &F,
    enc_2: &EncryptedNote,
    cm_3: F,
    output_3: &PaymentAddress,
    v_3: u64,
    rseed_3: &F,
    enc_3: &EncryptedNote,
    tree: &MerkleTree,
) -> Result<Proof, String> {
    let (cm_path, path_root) = tree.auth_path(0);
    if path_root != root {
        return Err("transfer input path root mismatch".into());
    }

    let nullifiers = vec![nf];
    let mh_1 = memo_ct_hash(enc_1);
    let mh_2 = memo_ct_hash(enc_2);
    let mh_3 = memo_ct_hash(enc_3);
    let sighash = transfer_sighash(
        &auth_domain,
        &root,
        &nullifiers,
        fee,
        &cm_1,
        &cm_2,
        &cm_3,
        &mh_1,
        &mh_2,
        &mh_3,
    );
    let (sig, _, _) = wots_sign(&input_addr.ask_j, 0, &sighash);

    let total_fields = 4 + 9 + DEPTH + AUTH_DEPTH + WOTS_CHAINS + 24;
    let mut args = vec![
        felt_u64_to_hex(total_fields as u64),
        felt_u64_to_hex(1),
        felt_to_hex(&auth_domain),
        felt_to_hex(&root),
        felt_u64_to_hex(fee),
        felt_to_hex(&nf),
        felt_to_hex(&input_addr.nk_spend),
        felt_to_hex(&input_addr.payment.auth_root),
        felt_to_hex(&input_addr.payment.auth_pub_seed),
        felt_u64_to_hex(0),
        felt_to_hex(&input_addr.payment.d_j),
        felt_u64_to_hex(input_value),
        felt_to_hex(input_rseed),
        felt_u64_to_hex(0),
    ];

    for sibling in &cm_path {
        args.push(felt_to_hex(sibling));
    }
    for sibling in &input_addr.auth_path_0 {
        args.push(felt_to_hex(sibling));
    }
    for felt in &sig {
        args.push(felt_to_hex(felt));
    }

    args.extend([
        felt_to_hex(&cm_1),
        felt_to_hex(&output_1.d_j),
        felt_u64_to_hex(v_1),
        felt_to_hex(rseed_1),
        felt_to_hex(&output_1.auth_root),
        felt_to_hex(&output_1.auth_pub_seed),
        felt_to_hex(&output_1.nk_tag),
        felt_to_hex(&mh_1),
        felt_to_hex(&cm_2),
        felt_to_hex(&output_2.d_j),
        felt_u64_to_hex(v_2),
        felt_to_hex(rseed_2),
        felt_to_hex(&output_2.auth_root),
        felt_to_hex(&output_2.auth_pub_seed),
        felt_to_hex(&output_2.nk_tag),
        felt_to_hex(&mh_2),
        felt_to_hex(&cm_3),
        felt_to_hex(&output_3.d_j),
        felt_u64_to_hex(v_3),
        felt_to_hex(rseed_3),
        felt_to_hex(&output_3.auth_root),
        felt_to_hex(&output_3.auth_pub_seed),
        felt_to_hex(&output_3.nk_tag),
        felt_to_hex(&mh_3),
    ]);

    if note_commitment(&input_addr.payment, input_value, input_rseed) != input_cm {
        return Err("transfer input commitment mismatch".into());
    }

    let proof = proof_from_bundle(generate_stark_bundle(
        "run_transfer.executable.json",
        &args,
    )?);
    DirectProofVerifier::verified(false, program_hashes.clone())
        .validate(&proof, CircuitKind::Transfer)?;
    Ok(proof)
}

fn generate_unshield_proof(
    auth_domain: F,
    program_hashes: &ProgramHashes,
    root: F,
    nf: F,
    input_addr: &DerivedAddress,
    input_cm: F,
    input_value: u64,
    input_rseed: &F,
    v_pub: u64,
    fee: u64,
    recipient: &str,
    fee_address: &PaymentAddress,
    fee_amount: u64,
    fee_rseed: &F,
    fee_enc: &EncryptedNote,
    tree: &MerkleTree,
) -> Result<Proof, String> {
    let (cm_path, path_root) = tree.auth_path(3);
    if path_root != root {
        return Err("unshield input path root mismatch".into());
    }

    let nullifiers = vec![nf];
    let recipient_f = hash(recipient.as_bytes());
    let fee_cm = note_commitment(fee_address, fee_amount, fee_rseed);
    let fee_mh = memo_ct_hash(fee_enc);
    let sighash = unshield_sighash(
        &auth_domain,
        &root,
        &nullifiers,
        v_pub,
        fee,
        &recipient_f,
        &ZERO,
        &ZERO,
        &fee_cm,
        &fee_mh,
    );
    let (sig, _, _) = wots_sign(&input_addr.ask_j, 0, &sighash);

    let total_fields = 6 + 9 + DEPTH + AUTH_DEPTH + WOTS_CHAINS + 15;
    let mut args = vec![
        felt_u64_to_hex(total_fields as u64),
        felt_u64_to_hex(1),
        felt_to_hex(&auth_domain),
        felt_to_hex(&root),
        felt_u64_to_hex(v_pub),
        felt_u64_to_hex(fee),
        felt_to_hex(&recipient_f),
        felt_to_hex(&nf),
        felt_to_hex(&input_addr.nk_spend),
        felt_to_hex(&input_addr.payment.auth_root),
        felt_to_hex(&input_addr.payment.auth_pub_seed),
        felt_u64_to_hex(0),
        felt_to_hex(&input_addr.payment.d_j),
        felt_u64_to_hex(input_value),
        felt_to_hex(input_rseed),
        felt_u64_to_hex(3),
    ];

    for sibling in &cm_path {
        args.push(felt_to_hex(sibling));
    }
    for sibling in &input_addr.auth_path_0 {
        args.push(felt_to_hex(sibling));
    }
    for felt in &sig {
        args.push(felt_to_hex(felt));
    }

    args.extend([
        felt_u64_to_hex(0),
        "0x0".into(),
        "0x0".into(),
        "0x0".into(),
        "0x0".into(),
        "0x0".into(),
        "0x0".into(),
        "0x0".into(),
        felt_to_hex(&fee_address.d_j),
        felt_u64_to_hex(fee_amount),
        felt_to_hex(fee_rseed),
        felt_to_hex(&fee_address.auth_root),
        felt_to_hex(&fee_address.auth_pub_seed),
        felt_to_hex(&fee_address.nk_tag),
        felt_to_hex(&fee_mh),
    ]);

    if note_commitment(&input_addr.payment, input_value, input_rseed) != input_cm {
        return Err("unshield input commitment mismatch".into());
    }

    let proof = proof_from_bundle(generate_stark_bundle(
        "run_unshield.executable.json",
        &args,
    )?);
    DirectProofVerifier::verified(false, program_hashes.clone())
        .validate(&proof, CircuitKind::Unshield)?;
    Ok(proof)
}

fn proof_from_bundle(bundle: VerifyProofBundle) -> Proof {
    Proof::Stark {
        proof_bytes: bundle.proof_bytes,
        output_preimage: bundle.output_preimage,
        verify_meta: bundle
            .verify_meta
            .map(|meta| encode_verify_meta(&meta))
            .transpose()
            .expect("verify_meta should encode"),
    }
}

fn generate_stark_bundle(
    executable_filename: &str,
    args: &[String],
) -> Result<VerifyProofBundle, String> {
    let executable = executables_dir().join(executable_filename);
    if !executable.exists() {
        return Err(format!("missing executable {}", executable.display()));
    }

    let args_file = tempfile::NamedTempFile::new().map_err(|e| format!("tempfile: {}", e))?;
    std::fs::write(
        args_file.path(),
        serde_json::to_string(args).map_err(|e| format!("encode args: {}", e))?,
    )
    .map_err(|e| format!("write args: {}", e))?;
    let proof_file = tempfile::NamedTempFile::new().map_err(|e| format!("tempfile: {}", e))?;

    let output = Command::new(build_reprove_bin())
        .arg(&executable)
        .arg("--arguments-file")
        .arg(args_file.path())
        .arg("--output")
        .arg(proof_file.path())
        .output()
        .map_err(|e| format!("failed to run reprove: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "reprove failed for {}:\nstdout:\n{}\nstderr:\n{}",
            executable_filename,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let bundle_json =
        std::fs::read_to_string(proof_file.path()).map_err(|e| format!("read proof: {}", e))?;
    serde_json::from_str(&bundle_json).map_err(|e| format!("parse proof bundle: {}", e))
}

fn build_reprove_bin() -> PathBuf {
    let path = workspace_root().join("apps/prover/target/release/reprove");
    if path.exists() {
        return path;
    }

    let output = Command::new("cargo")
        .current_dir(workspace_root().join("apps/prover"))
        .args([PROVER_TOOLCHAIN, "build", "--release", "--bin", "reprove"])
        .output()
        .expect("failed to build reprove");
    assert!(
        output.status.success(),
        "failed to build reprove:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn executables_dir() -> PathBuf {
    workspace_root().join("cairo/target/dev")
}

fn base_wallet_fixture_path() -> PathBuf {
    workspace_root().join("apps/wallet/testdata/base_wallet_bds.json")
}

fn load_base_wallet_fixture() -> Result<FixtureWallet, String> {
    let fixture_json = std::fs::read_to_string(base_wallet_fixture_path())
        .map_err(|e| format!("read base wallet fixture: {}", e))?;
    serde_json::from_str(&fixture_json).map_err(|e| format!("parse base wallet fixture: {}", e))
}

fn fixture_address(wallet: &FixtureWallet, index: usize) -> Result<DerivedAddress, String> {
    let address = wallet
        .addresses
        .get(index)
        .ok_or_else(|| format!("missing wallet fixture address {}", index))?;
    if address.bds.next_index != 0 {
        return Err(format!(
            "fixture address {} expected next_index 0, got {}",
            index, address.bds.next_index
        ));
    }

    let account = derive_account(&wallet.master_sk);
    let ask_j = derive_ask(&account.ask_base, address.index);
    let nk_spend = derive_nk_spend(&account.nk, &address.d_j);
    let (ek_v, _, ek_d, _) = derive_kem_keys(&account.incoming_seed, address.index);
    Ok(DerivedAddress {
        payment: PaymentAddress {
            d_j: address.d_j,
            auth_root: address.auth_root,
            auth_pub_seed: address.auth_pub_seed,
            nk_tag: address.nk_tag,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        },
        ask_j,
        nk_spend,
        auth_path_0: address.bds.auth_path.clone(),
    })
}

fn deterministic_note(
    address: &PaymentAddress,
    value: u64,
    rseed: &F,
    memo: &[u8],
    detect_seed: u8,
    view_seed: u8,
) -> Result<EncryptedNote, String> {
    let ek_v = ml_kem_768::EncapsulationKey::new(address.ek_v.as_slice().try_into().unwrap())
        .map_err(|_| "invalid ek_v".to_string())?;
    let ek_d = ml_kem_768::EncapsulationKey::new(address.ek_d.as_slice().try_into().unwrap())
        .map_err(|_| "invalid ek_d".to_string())?;
    Ok(encrypt_note_deterministic(
        value,
        rseed,
        Some(memo),
        &ek_v,
        &ek_d,
        &fixed_ephemeral(detect_seed),
        &fixed_ephemeral(view_seed),
    ))
}

fn note_commitment(address: &PaymentAddress, value: u64, rseed: &F) -> F {
    commit(
        &address.d_j,
        value,
        &derive_rcm(rseed),
        &owner_tag(&address.auth_root, &address.auth_pub_seed, &address.nk_tag),
    )
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

fn felt_to_hex(f: &F) -> String {
    let mut be = [0u8; 32];
    for (dst, src) in be.iter_mut().zip(f.iter().rev()) {
        *dst = *src;
    }
    let hex_str = hex::encode(be);
    let trimmed = hex_str.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_string()
    } else {
        format!("0x{}", trimmed)
    }
}

fn felt_u64_to_hex(v: u64) -> String {
    format!("0x{:x}", v)
}
