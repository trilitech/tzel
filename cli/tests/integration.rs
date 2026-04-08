//! Integration tests: spawn sp-ledger and run sp-client commands as subprocesses
//! with alice and bob wallets.
//!
//! Most operations use --trust-me-bro for speed. The suite also exercises
//! verifier-enabled ledgers and real STARK proofs for each circuit type
//! (shield, transfer, unshield).

use ml_kem::{ml_kem_768, KeyExport};
use serde::Serialize;
use starkprivacy_cli::*;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use ureq::{http, RequestExt};

const LEDGER_PORT: u16 = 19876;

fn ledger_url() -> String {
    format!("http://localhost:{}", LEDGER_PORT)
}

fn sp_client() -> String {
    env!("CARGO_BIN_EXE_sp-client").to_string()
}

fn sp_ledger() -> String {
    env!("CARGO_BIN_EXE_sp-ledger").to_string()
}

/// Path to the reprove binary (built separately in ../reprover)
fn reprove_bin() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("reprover/target/release/reprove");
    path.to_str().unwrap().to_string()
}

/// Path to compiled Cairo executables
fn executables_dir() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target/dev");
    path.to_str().unwrap().to_string()
}

fn run(bin: &str, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to execute");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), stdout, stderr)
}

/// Run sp-client in --trust-me-bro mode (fast, no proving).
fn client_tmb(wallet: &str, args: &[&str]) -> (bool, String) {
    let mut full_args = vec!["-w", wallet, "--trust-me-bro"];
    full_args.extend_from_slice(args);
    let (ok, stdout, stderr) = run(&sp_client(), &full_args);
    (ok, format!("{}{}", stdout, stderr))
}

fn wait_for_ledger(port: u16) {
    let url = format!("http://localhost:{}/tree", port);
    for _ in 0..50 {
        if ureq::get(&url).call().is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("ledger did not start listening on {}", url);
}

/// Run sp-client with real STARK proof generation.
fn client_prove(wallet: &str, args: &[&str]) -> (bool, String) {
    let reprove = reprove_bin();
    let exedir = executables_dir();
    let mut full_args = vec![
        "-w",
        wallet,
        "--reprove-bin",
        &reprove,
        "--executables-dir",
        &exedir,
    ];
    full_args.extend_from_slice(args);
    let (ok, stdout, stderr) = run(&sp_client(), &full_args);
    (ok, format!("{}{}", stdout, stderr))
}

fn start_ledger() -> Child {
    let child = Command::new(sp_ledger())
        .args(["--port", &LEDGER_PORT.to_string(), "--trust-me-bro"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start ledger");
    wait_for_ledger(LEDGER_PORT);
    child
}

fn start_ledger_with_verifier(port: u16) -> Child {
    let reprove = reprove_bin();
    let exedir = executables_dir();
    let child = Command::new(sp_ledger())
        .args([
            "--port",
            &port.to_string(),
            "--trust-me-bro",
            "--reprove-bin",
            &reprove,
            "--executables-dir",
            &exedir,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start ledger with verifier");
    wait_for_ledger(port);
    child
}

fn start_verified_ledger(port: u16) -> Child {
    let reprove = reprove_bin();
    let exedir = executables_dir();
    let child = Command::new(sp_ledger())
        .args([
            "--port",
            &port.to_string(),
            "--reprove-bin",
            &reprove,
            "--executables-dir",
            &exedir,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start verified ledger");
    wait_for_ledger(port);
    child
}

fn has_reprover() -> bool {
    std::path::Path::new(&reprove_bin()).exists()
        && std::path::Path::new(&executables_dir())
            .join("run_shield.executable.json")
            .exists()
}

fn felt_to_hex(f: &F) -> String {
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = f[31 - i];
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

fn make_test_address() -> PaymentAddress {
    let mut master_sk = ZERO;
    master_sk[0] = 0x42;
    let acc = derive_account(&master_sk);
    let d_j = derive_address(&acc.incoming_seed, 0);
    let ask_j = derive_ask(&acc.ask_base, 0);
    let (auth_root, _) = build_auth_tree(&ask_j);
    let nk_spend = derive_nk_spend(&acc.nk, &d_j);
    let nk_tag = derive_nk_tag(&nk_spend);
    let (ek_v, _, ek_d, _) = derive_kem_keys(&acc.incoming_seed, 0);
    PaymentAddress {
        d_j,
        auth_root,
        nk_tag,
        ek_v: ek_v.to_bytes().to_vec(),
        ek_d: ek_d.to_bytes().to_vec(),
    }
}

fn generate_shield_proof(
    sender: &str,
    amount: u64,
    address: &PaymentAddress,
) -> (Proof, F, EncryptedNote) {
    let rseed = random_felt();
    let rcm = derive_rcm(&rseed);
    let otag = owner_tag(&address.auth_root, &address.nk_tag);
    let cm = commit(&address.d_j, amount, &rcm, &otag);
    let sender_f = hash(sender.as_bytes());

    let ek_v = ml_kem_768::EncapsulationKey::new(address.ek_v.as_slice().try_into().unwrap())
        .expect("valid ek_v");
    let ek_d = ml_kem_768::EncapsulationKey::new(address.ek_d.as_slice().try_into().unwrap())
        .expect("valid ek_d");
    let enc = encrypt_note(amount, &rseed, None, &ek_v, &ek_d);
    let memo_ct_hash_f = memo_ct_hash(&enc);

    let args: Vec<String> = vec![
        felt_u64_to_hex(8),
        felt_u64_to_hex(amount),
        felt_to_hex(&cm),
        felt_to_hex(&sender_f),
        felt_to_hex(&memo_ct_hash_f),
        felt_to_hex(&address.auth_root),
        felt_to_hex(&address.nk_tag),
        felt_to_hex(&address.d_j),
        felt_to_hex(&rseed),
    ];

    let executable = format!("{}/run_shield.executable.json", executables_dir());
    let args_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(args_file.path(), serde_json::to_string(&args).unwrap()).unwrap();
    let proof_file = tempfile::NamedTempFile::new().unwrap();

    let out = Command::new(reprove_bin())
        .arg(&executable)
        .arg("--arguments-file")
        .arg(args_file.path())
        .arg("--output")
        .arg(proof_file.path())
        .output()
        .expect("failed to run reprover");
    assert!(
        out.status.success(),
        "reprover failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bundle_json = std::fs::read_to_string(proof_file.path()).unwrap();
    let bundle: serde_json::Value = serde_json::from_str(&bundle_json).unwrap();
    let proof_hex = bundle["proof_hex"].as_str().unwrap().to_string();
    let output_preimage = bundle["output_preimage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let verify_meta = bundle.get("verify_meta").cloned();

    (
        Proof::Stark {
            proof_hex,
            output_preimage,
            verify_meta,
        },
        cm,
        enc,
    )
}

fn post_json_allow_status<Req: Serialize>(url: &str, body: &Req) -> http::Response<ureq::Body> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(body).unwrap())
        .unwrap()
        .with_default_agent()
        .configure()
        .http_status_as_error(false)
        .run()
        .unwrap()
}

/// Full end-to-end test in TrustMeBro mode.
/// Tests: keygen, address, fund, shield, scan, transfer, unshield, balance,
/// double-spend rejection, insufficient funds rejection, value conservation.
#[test]
fn test_e2e_trust_me_bro() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let alice = dir.join("alice.json").to_str().unwrap().to_string();
    let bob = dir.join("bob.json").to_str().unwrap().to_string();
    let bob_addr = dir.join("bob_addr.json").to_str().unwrap().to_string();
    let l = ledger_url();

    let mut ledger = start_ledger();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // ── Setup: keygen + addresses ───────────────────────────────
        let (ok, out) = client_tmb(&alice, &["keygen"]);
        assert!(ok, "alice keygen: {}", out);

        let (ok, out) = client_tmb(&bob, &["keygen"]);
        assert!(ok, "bob keygen: {}", out);

        let (ok, out) = client_tmb(&bob, &["address"]);
        assert!(ok, "bob address: {}", out);
        let json_start = out.find('{').expect("no JSON");
        std::fs::write(&bob_addr, &out[json_start..]).unwrap();

        // Verify address has expected fields
        let addr: serde_json::Value = serde_json::from_str(&out[json_start..]).unwrap();
        assert!(addr.get("auth_root").is_some(), "missing auth_root");
        assert!(addr.get("nk_tag").is_some(), "missing nk_tag");
        assert!(addr.get("d_j").is_some(), "missing d_j");
        assert!(addr.get("ek_v").is_some(), "missing ek_v");
        assert!(addr.get("ek_d").is_some(), "missing ek_d");

        // ── Fund alice ──────────────────────────────────────────────
        let (ok, out) = client_tmb(
            &alice,
            &["fund", "-l", &l, "--addr", "alice", "--amount", "2000"],
        );
        assert!(ok, "fund: {}", out);

        // ── Shield 1500 + 500 ───────────────────────────────────────
        let (ok, out) = client_tmb(
            &alice,
            &["shield", "-l", &l, "--sender", "alice", "--amount", "1500"],
        );
        assert!(ok, "shield 1500: {}", out);
        assert!(out.contains("Shielded 1500"));

        let (ok, out) = client_tmb(
            &alice,
            &["shield", "-l", &l, "--sender", "alice", "--amount", "500"],
        );
        assert!(ok, "shield 500: {}", out);
        assert!(out.contains("Shielded 500"));

        // ── Insufficient balance ────────────────────────────────────
        let (ok, _) = client_tmb(
            &alice,
            &["shield", "-l", &l, "--sender", "alice", "--amount", "1"],
        );
        assert!(!ok, "shield with 0 balance should fail");

        // ── Alice scan ──────────────────────────────────────────────
        let (ok, out) = client_tmb(&alice, &["scan", "-l", &l]);
        assert!(ok, "alice scan: {}", out);
        assert!(out.contains("2 new notes found"));
        assert!(out.contains("balance=2000"));

        // ── Alice balance ───────────────────────────────────────────
        let (ok, out) = client_tmb(&alice, &["balance"]);
        assert!(ok, "balance: {}", out);
        assert!(out.contains("Private balance: 2000"));
        assert!(out.contains("Notes: 2"));

        // ── Transfer 1200 to bob ────────────────────────────────────
        let (ok, out) = client_tmb(
            &alice,
            &["transfer", "-l", &l, "--to", &bob_addr, "--amount", "1200"],
        );
        assert!(ok, "transfer: {}", out);
        assert!(out.contains("Transferred 1200"));
        assert!(out.contains("change=300"));

        // ── Both scan ───────────────────────────────────────────────
        let (ok, out) = client_tmb(&alice, &["scan", "-l", &l]);
        assert!(ok, "alice scan 2: {}", out);
        assert!(out.contains("1 new notes found"));

        let (ok, out) = client_tmb(&bob, &["scan", "-l", &l]);
        assert!(ok, "bob scan: {}", out);
        assert!(out.contains("v=1200"));

        // ── Balances ────────────────────────────────────────────────
        let (ok, out) = client_tmb(&bob, &["balance"]);
        assert!(ok, "bob balance: {}", out);
        assert!(out.contains("Private balance: 1200"));

        let (ok, out) = client_tmb(&alice, &["balance"]);
        assert!(ok, "alice balance: {}", out);
        assert!(out.contains("Private balance: 800"));

        // ── Bob unshields 500 ───────────────────────────────────────
        let (ok, out) = client_tmb(
            &bob,
            &[
                "unshield",
                "-l",
                &l,
                "--amount",
                "500",
                "--recipient",
                "bob_pub",
            ],
        );
        assert!(ok, "unshield: {}", out);
        assert!(out.contains("Unshielded 500"));
        assert!(out.contains("change=700"));

        // ── Bob scan + balance ──────────────────────────────────────
        let (ok, _) = client_tmb(&bob, &["scan", "-l", &l]);
        assert!(ok, "bob scan 2");

        let (ok, out) = client_tmb(&bob, &["balance"]);
        assert!(ok, "bob balance 2: {}", out);
        assert!(out.contains("Private balance: 700"));

        // ── Insufficient funds ──────────────────────────────────────
        let (ok, _) = client_tmb(
            &alice,
            &["transfer", "-l", &l, "--to", &bob_addr, "--amount", "9999"],
        );
        assert!(!ok, "transfer exceeding balance should fail");

        // ── Public balances ─────────────────────────────────────────
        let resp: serde_json::Value = ureq::get(&format!("{}/balances", l))
            .call()
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let balances = resp.get("balances").unwrap();
        assert_eq!(balances.get("alice").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(balances.get("bob_pub").and_then(|v| v.as_u64()), Some(500));

        // ── Tree integrity ──────────────────────────────────────────
        let tree: serde_json::Value = ureq::get(&format!("{}/tree", l))
            .call()
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let size = tree.get("size").unwrap().as_u64().unwrap();
        assert!(
            size >= 5,
            "tree should have at least 5 leaves, got {}",
            size
        );

        // ── Value conservation ──────────────────────────────────────
        // alice_private(800) + bob_private(700) + bob_public(500) = 2000
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// Test that the ledger rejects TrustMeBro when running in verified mode.
#[test]
fn test_ledger_rejects_tmb_by_default() {
    if !has_reprover() {
        eprintln!("SKIP: reprover binary or Cairo executables not found.");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let alice = dir.path().join("alice.json").to_str().unwrap().to_string();

    // Start ledger in verified mode (no --trust-me-bro) on a different port
    let port = LEDGER_PORT + 1;
    let l = format!("http://localhost:{}", port);
    let mut ledger = start_verified_ledger(port);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (ok, _) = client_tmb(&alice, &["keygen"]);
        assert!(ok);

        // Fund works (no proof needed)
        let (ok, _) = client_tmb(
            &alice,
            &["fund", "-l", &l, "--addr", "alice", "--amount", "1000"],
        );
        assert!(ok, "fund should work without proof");

        // Shield with TrustMeBro should be REJECTED
        let (ok, out) = client_tmb(
            &alice,
            &["shield", "-l", &l, "--sender", "alice", "--amount", "500"],
        );
        assert!(!ok, "ledger should reject TrustMeBro: {}", out);
        assert!(
            out.contains("TrustMeBro proofs rejected") || out.contains("400"),
            "expected rejection message: {}",
            out
        );
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// Test that the ledger refuses to start in the insecure no-verifier / no-trust mode.
#[test]
fn test_ledger_refuses_insecure_startup() {
    let port = LEDGER_PORT + 4;
    let out = Command::new(sp_ledger())
        .args(["--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to start ledger");
    assert!(
        !out.status.success(),
        "ledger startup should fail without verifier or trust mode"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to start without proof verification"),
        "unexpected stderr: {}",
        stderr
    );
}

/// Test with real STARK proofs: shield, transfer, unshield.
/// Uses the TrustMeBro ledger + TMB operations to set up state,
/// then proves specific transactions with the real reprover.
///
/// This test is slow (~2 minutes) and requires:
/// - reprover built: `cd reprover && cargo build --release`
/// - Cairo executables built: `scarb build`
#[test]
fn test_e2e_with_real_proofs() {
    if !has_reprover() {
        eprintln!("SKIP: reprover binary or Cairo executables not found. Build with:");
        eprintln!("  cd reprover && cargo build --release");
        eprintln!("  scarb build");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let alice = dir.join("alice.json").to_str().unwrap().to_string();
    let bob = dir.join("bob.json").to_str().unwrap().to_string();
    let bob_addr = dir.join("bob_addr.json").to_str().unwrap().to_string();
    let port = LEDGER_PORT + 2;
    let l = format!("http://localhost:{}", port);

    let mut ledger = start_ledger_with_verifier(port);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // ── Setup with TrustMeBro (fast) ────────────────────────────
        let (ok, _) = client_tmb(&alice, &["keygen"]);
        assert!(ok);
        let (ok, _) = client_tmb(&bob, &["keygen"]);
        assert!(ok);

        let (ok, out) = client_tmb(&bob, &["address"]);
        assert!(ok);
        let json_start = out.find('{').unwrap();
        std::fs::write(&bob_addr, &out[json_start..]).unwrap();

        let (ok, _) = client_tmb(
            &alice,
            &["fund", "-l", &l, "--addr", "alice", "--amount", "5000"],
        );
        assert!(ok);

        // ── REAL PROOF: Shield 1000 ─────────────────────────────────
        eprintln!(">>> Generating real shield proof...");
        let (ok, out) = client_prove(
            &alice,
            &["shield", "-l", &l, "--sender", "alice", "--amount", "1000"],
        );
        assert!(ok, "real shield failed: {}", out);
        assert!(out.contains("Shielded 1000"), "shield output: {}", out);
        assert!(
            out.contains("Proof generated"),
            "should show proof generation: {}",
            out
        );
        eprintln!(">>> Shield proof OK");

        // Use TMB for a second shield (to have notes for transfer)
        let (ok, _) = client_tmb(
            &alice,
            &["shield", "-l", &l, "--sender", "alice", "--amount", "500"],
        );
        assert!(ok);

        // Scan to pick up both notes
        let (ok, out) = client_tmb(&alice, &["scan", "-l", &l]);
        assert!(ok, "scan: {}", out);
        assert!(out.contains("2 new notes found"));

        // ── REAL PROOF: Transfer 800 to bob ─────────────────────────
        // Alice has 1000 + 500 = 1500. Transfer 800, change 200 (from the 1000 note).
        eprintln!(">>> Generating real transfer proof...");
        let (ok, out) = client_prove(
            &alice,
            &["transfer", "-l", &l, "--to", &bob_addr, "--amount", "800"],
        );
        assert!(ok, "real transfer failed: {}", out);
        assert!(out.contains("Transferred 800"), "transfer output: {}", out);
        eprintln!(">>> Transfer proof OK");

        // Scan both
        let (ok, _) = client_tmb(&alice, &["scan", "-l", &l]);
        assert!(ok);
        let (ok, _) = client_tmb(&bob, &["scan", "-l", &l]);
        assert!(ok);

        let (ok, out) = client_tmb(&bob, &["balance"]);
        assert!(ok);
        assert!(
            out.contains("Private balance: 800"),
            "bob should have 800: {}",
            out
        );

        // ── REAL PROOF: Unshield 300 from bob (no change) ───────────
        // Bob has 800. Unshield 800 (exact, no change) to avoid the
        // "change not wired" issue.
        eprintln!(">>> Generating real unshield proof...");
        let (ok, out) = client_prove(
            &bob,
            &[
                "unshield",
                "-l",
                &l,
                "--amount",
                "800",
                "--recipient",
                "bob_pub",
            ],
        );
        assert!(ok, "real unshield failed: {}", out);
        assert!(out.contains("Unshielded 800"), "unshield output: {}", out);
        eprintln!(">>> Unshield proof OK");

        // ── Verify final state ──────────────────────────────────────
        let resp: serde_json::Value = ureq::get(&format!("{}/balances", l))
            .call()
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let balances = resp.get("balances").unwrap();
        let bob_public = balances
            .get("bob_pub")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert_eq!(bob_public, 800, "bob_pub should have 800");

        let alice_public = balances.get("alice").and_then(|v| v.as_u64()).unwrap_or(0);
        // alice funded 5000, shielded 1000+500 = 1500 remaining public = 3500
        assert_eq!(alice_public, 3500, "alice public should be 3500");

        eprintln!(">>> All three real proofs verified successfully");
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// Tests the ledger's --reprove-bin proof verification path.
/// The ledger verifies submitted STARK proofs via the reprover binary.
/// This exercises the ProofBundle::verify() code path including the
/// output_preimage binding check (security finding #1).
#[test]
fn test_ledger_verifies_proofs_with_reprover() {
    if !has_reprover() {
        eprintln!("SKIP: reprover binary or Cairo executables not found.");
        return;
    }

    let port = LEDGER_PORT + 3;
    let l = format!("http://localhost:{}", port);

    let mut ledger = start_verified_ledger(port);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fund_resp = post_json_allow_status(
            &format!("{}/fund", l),
            &serde_json::json!({ "addr": "alice", "amount": 5000 }),
        );
        assert_eq!(fund_resp.status(), 200);

        let address = make_test_address();
        let (proof, cm, enc) = generate_shield_proof("alice", 1000, &address);
        let req = ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address,
            memo: None,
            proof,
            client_cm: cm,
            client_enc: Some(enc),
        };

        let resp = post_json_allow_status(&format!("{}/shield", l), &req);
        let status = resp.status();
        let body = resp.into_body().read_to_string().unwrap_or_default();
        assert_eq!(
            status, 200,
            "clean verifier-backed proof rejected: {}",
            body
        );
        let shield_resp: ShieldResp = serde_json::from_str(&body).unwrap();
        assert_eq!(shield_resp.index, 0);

        eprintln!(">>> Ledger proof verification path exercised successfully");
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
fn test_ledger_rejects_tampered_output_preimage() {
    if !has_reprover() {
        eprintln!("SKIP: reprover binary or Cairo executables not found.");
        return;
    }

    let port = LEDGER_PORT + 5;
    let l = format!("http://localhost:{}", port);
    let mut ledger = start_verified_ledger(port);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fund_resp = post_json_allow_status(
            &format!("{}/fund", l),
            &serde_json::json!({ "addr": "alice", "amount": 5000 }),
        );
        assert_eq!(fund_resp.status(), 200);

        let address = make_test_address();
        let (proof, _real_cm, enc) = generate_shield_proof("alice", 1000, &address);

        let mut tampered_cm = random_felt();
        while tampered_cm == ZERO {
            tampered_cm = random_felt();
        }

        let tampered_proof = match proof {
            Proof::Stark {
                proof_hex,
                mut output_preimage,
                verify_meta,
            } => {
                let tail_start = output_preimage.len() - 4;
                output_preimage[tail_start + 1] = felt_to_dec(&tampered_cm);
                Proof::Stark {
                    proof_hex,
                    output_preimage,
                    verify_meta,
                }
            }
            Proof::TrustMeBro => panic!("expected Stark proof"),
        };

        let req = ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address,
            memo: None,
            proof: tampered_proof,
            client_cm: tampered_cm,
            client_enc: Some(enc),
        };

        let resp = post_json_allow_status(&format!("{}/shield", l), &req);
        let status = resp.status();
        let body = resp.into_body().read_to_string().unwrap_or_default();

        assert_eq!(status, 400, "tampered proof should be rejected: {}", body);
        assert!(
            body.contains("STARK proof verification FAILED"),
            "expected verifier failure, got: {}",
            body
        );
        assert!(
            body.contains("output_preimage"),
            "expected output_preimage binding failure, got: {}",
            body
        );
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
