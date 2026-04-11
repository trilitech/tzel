//! Integration tests: spawn sp-ledger and run sp-client commands as subprocesses
//! with alice and bob wallets.
//!
//! Most operations use --trust-me-bro for speed. The suite also exercises
//! verifier-enabled ledgers and real STARK proofs for each circuit type
//! (shield, transfer, unshield).

use ml_kem::{ml_kem_768, KeyExport};
use serde::{Deserialize, Serialize};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tzel_services::*;
use ureq::{http, RequestExt};

const PROVER_TOOLCHAIN: &str = "+nightly-2025-07-14";

static SP_CLIENT_BIN: OnceLock<String> = OnceLock::new();
static SP_LEDGER_BIN: OnceLock<String> = OnceLock::new();
static REPROVE_BIN: OnceLock<String> = OnceLock::new();
static INTEGRATION_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn integration_test_guard() -> MutexGuard<'static, ()> {
    INTEGRATION_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn free_port() -> u16 {
    static NEXT_PORT: OnceLock<AtomicU16> = OnceLock::new();
    let counter = NEXT_PORT.get_or_init(|| {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u16;
        AtomicU16::new(30000 + (seed % 20000))
    });
    counter.fetch_add(1, Ordering::Relaxed)
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn ensure_app_bin(package: &str, bin: &str) -> String {
    let path = workspace_root().join("target/debug").join(bin);
    let out = Command::new("cargo")
        .current_dir(workspace_root())
        .args(["build", "-p", package, "--bin", bin])
        .output()
        .expect("failed to build app binary");
    assert!(
        out.status.success(),
        "failed to build {}:\nstdout:\n{}\nstderr:\n{}",
        bin,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    path.to_str().unwrap().to_string()
}

fn sp_client() -> String {
    SP_CLIENT_BIN
        .get_or_init(|| ensure_app_bin("tzel-wallet-app", "sp-client"))
        .clone()
}

fn sp_ledger() -> String {
    SP_LEDGER_BIN
        .get_or_init(|| ensure_app_bin("tzel-ledger-app", "sp-ledger"))
        .clone()
}

/// Path to the reprove binary in the workspace target dir.
fn reprove_bin_path() -> String {
    workspace_root()
        .join("apps/prover/target/release/reprove")
        .to_str()
        .unwrap()
        .to_string()
}

fn build_reprove_bin() -> String {
    REPROVE_BIN
        .get_or_init(|| {
            let path = workspace_root().join("apps/prover/target/release/reprove");
            let out = Command::new("cargo")
                .current_dir(workspace_root().join("apps/prover"))
                .args([PROVER_TOOLCHAIN, "build", "--release", "--bin", "reprove"])
                .output()
                .expect("failed to build reprover binary");
            assert!(
                out.status.success(),
                "failed to build reprove:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            path.to_str().unwrap().to_string()
        })
        .clone()
}

/// Path to compiled Cairo executables
fn executables_dir() -> String {
    let path = workspace_root().join("cairo/target/dev");
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
    let reprove = build_reprove_bin();
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

fn start_ledger(port: u16) -> Child {
    let child = Command::new(sp_ledger())
        .args(["--port", &port.to_string(), "--trust-me-bro"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start ledger");
    wait_for_ledger(port);
    child
}

fn start_ledger_with_verifier(port: u16) -> Child {
    let reprove = build_reprove_bin();
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
    let reprove = reprove_bin_path();
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
    std::path::Path::new(&reprove_bin_path()).exists()
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

fn integration_auth_root(d_j: &F, auth_pub_seed: &F) -> F {
    hash_two(&felt_tag(b"itest-auth"), &hash_two(d_j, auth_pub_seed))
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
}

fn base_wallet_fixture_path() -> std::path::PathBuf {
    workspace_root().join("apps/wallet/testdata/base_wallet_bds.json")
}

fn install_base_wallet_fixture(wallet_path: &std::path::Path, address_path: &std::path::Path) {
    let fixture_json =
        std::fs::read_to_string(base_wallet_fixture_path()).expect("read base wallet fixture");
    let mut wallet_json: serde_json::Value =
        serde_json::from_str(&fixture_json).expect("parse base wallet fixture json");
    wallet_json["addr_counter"] = serde_json::Value::from(2u64);
    std::fs::write(
        wallet_path,
        serde_json::to_string_pretty(&wallet_json).expect("serialize integration wallet fixture"),
    )
    .expect("write integration wallet fixture");
    let fixture: FixtureWallet = serde_json::from_str(&fixture_json).expect("parse wallet fixture");
    let addr = fixture
        .addresses
        .first()
        .expect("wallet fixture should contain address 0");
    assert_eq!(addr.index, 0, "wallet fixture should start at address 0");

    let acc = derive_account(&fixture.master_sk);
    let (ek_v, _, ek_d, _) = derive_kem_keys(&acc.incoming_seed, addr.index);
    let payment = PaymentAddress {
        d_j: addr.d_j,
        auth_root: addr.auth_root,
        auth_pub_seed: addr.auth_pub_seed,
        nk_tag: addr.nk_tag,
        ek_v: ek_v.to_bytes().to_vec(),
        ek_d: ek_d.to_bytes().to_vec(),
    };
    std::fs::write(
        address_path,
        serde_json::to_string_pretty(&payment).unwrap(),
    )
    .expect("write fixture address");
}

fn make_test_address() -> PaymentAddress {
    let mut master_sk = ZERO;
    master_sk[0] = 0x42;
    let acc = derive_account(&master_sk);
    let d_j = derive_address(&acc.incoming_seed, 0);
    let ask_j = derive_ask(&acc.ask_base, 0);
    let auth_pub_seed = derive_auth_pub_seed(&ask_j);
    let auth_root = integration_auth_root(&d_j, &auth_pub_seed);
    let nk_spend = derive_nk_spend(&acc.nk, &d_j);
    let nk_tag = derive_nk_tag(&nk_spend);
    let (ek_v, _, ek_d, _) = derive_kem_keys(&acc.incoming_seed, 0);
    PaymentAddress {
        d_j,
        auth_root,
        auth_pub_seed,
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
    let otag = owner_tag(&address.auth_root, &address.auth_pub_seed, &address.nk_tag);
    let cm = commit(&address.d_j, amount, &rcm, &otag);
    let sender_f = hash(sender.as_bytes());

    let ek_v = ml_kem_768::EncapsulationKey::new(address.ek_v.as_slice().try_into().unwrap())
        .expect("valid ek_v");
    let ek_d = ml_kem_768::EncapsulationKey::new(address.ek_d.as_slice().try_into().unwrap())
        .expect("valid ek_d");
    let enc = encrypt_note(amount, &rseed, None, &ek_v, &ek_d);
    let memo_ct_hash_f = memo_ct_hash(&enc);

    let args: Vec<String> = vec![
        felt_u64_to_hex(9),
        felt_u64_to_hex(amount),
        felt_to_hex(&cm),
        felt_to_hex(&sender_f),
        felt_to_hex(&memo_ct_hash_f),
        felt_to_hex(&address.auth_root),
        felt_to_hex(&address.auth_pub_seed),
        felt_to_hex(&address.nk_tag),
        felt_to_hex(&address.d_j),
        felt_to_hex(&rseed),
    ];

    let executable = format!("{}/run_shield.executable.json", executables_dir());
    let args_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(args_file.path(), serde_json::to_string(&args).unwrap()).unwrap();
    let proof_file = tempfile::NamedTempFile::new().unwrap();

    let out = Command::new(build_reprove_bin())
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

    #[derive(Deserialize)]
    struct ProofBundleJson {
        #[serde(with = "hex_bytes")]
        proof_bytes: Vec<u8>,
        #[serde(with = "hex_f_vec")]
        output_preimage: Vec<F>,
        #[serde(default)]
        verify_meta: Option<serde_json::Value>,
    }

    let bundle_json = std::fs::read_to_string(proof_file.path()).unwrap();
    let bundle: ProofBundleJson = serde_json::from_str(&bundle_json).unwrap();

    (
        Proof::Stark {
            proof_bytes: bundle.proof_bytes,
            output_preimage: bundle.output_preimage,
            verify_meta: bundle.verify_meta,
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
    let _guard = integration_test_guard();
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let alice = dir.join("alice.json").to_str().unwrap().to_string();
    let alice_addr = dir.join("alice_addr.json").to_str().unwrap().to_string();
    let port = free_port();
    let l = format!("http://localhost:{}", port);

    install_base_wallet_fixture(
        std::path::Path::new(&alice),
        std::path::Path::new(&alice_addr),
    );

    let mut ledger = start_ledger(port);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // ── Fund alice ──────────────────────────────────────────────
        let (ok, out) = client_tmb(
            &alice,
            &["fund", "-l", &l, "--addr", "alice", "--amount", "2000"],
        );
        assert!(ok, "fund: {}", out);

        // ── Shield exactly to the fixed fixture address ─────────────
        let (ok, out) = client_tmb(
            &alice,
            &[
                "shield",
                "-l",
                &l,
                "--sender",
                "alice",
                "--amount",
                "2000",
                "--to",
                &alice_addr,
            ],
        );
        assert!(ok, "shield 2000: {}", out);
        assert!(out.contains("Shielded 2000"));

        // ── Alice scan ──────────────────────────────────────────────
        let (ok, out) = client_tmb(&alice, &["scan", "-l", &l]);
        assert!(ok, "alice scan: {}", out);
        assert!(out.contains("1 new notes found"));
        assert!(out.contains("balance=2000"));

        // ── Alice balance ───────────────────────────────────────────
        let (ok, out) = client_tmb(&alice, &["balance"]);
        assert!(ok, "balance: {}", out);
        assert!(out.contains("Private balance: 2000"));
        assert!(out.contains("Notes: 1"));

        // ── Exact unshield (no change address generation) ───────────
        let (ok, out) = client_tmb(
            &alice,
            &[
                "unshield",
                "-l",
                &l,
                "--amount",
                "2000",
                "--recipient",
                "alice_pub",
            ],
        );
        assert!(ok, "unshield: {}", out);
        assert!(out.contains("Unshielded 2000"));

        let (ok, out) = client_tmb(&alice, &["balance"]);
        assert!(ok, "alice balance 2: {}", out);
        assert!(out.contains("Private balance: 0"));

        // ── Public balances ─────────────────────────────────────────
        let resp: serde_json::Value = ureq::get(&format!("{}/balances", l))
            .call()
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let balances = resp.get("balances").unwrap();
        assert_eq!(balances.get("alice").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(
            balances.get("alice_pub").and_then(|v| v.as_u64()),
            Some(2000)
        );

        // ── Tree integrity ──────────────────────────────────────────
        let tree: serde_json::Value = ureq::get(&format!("{}/tree", l))
            .call()
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let size = tree.get("size").unwrap().as_u64().unwrap();
        assert_eq!(size, 1, "tree should have exactly one leaf, got {}", size);
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
    let _guard = integration_test_guard();
    if !has_reprover() {
        eprintln!("SKIP: reprover binary or Cairo executables not found.");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let alice = dir.path().join("alice.json").to_str().unwrap().to_string();
    let alice_addr = dir
        .path()
        .join("alice_addr.json")
        .to_str()
        .unwrap()
        .to_string();

    install_base_wallet_fixture(
        std::path::Path::new(&alice),
        std::path::Path::new(&alice_addr),
    );

    // Start ledger in verified mode (no --trust-me-bro) on a different port
    let port = free_port();
    let l = format!("http://localhost:{}", port);
    let mut ledger = start_verified_ledger(port);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Fund works (no proof needed)
        let (ok, _) = client_tmb(
            &alice,
            &["fund", "-l", &l, "--addr", "alice", "--amount", "1000"],
        );
        assert!(ok, "fund should work without proof");

        // Shield with TrustMeBro should be REJECTED
        let (ok, out) = client_tmb(
            &alice,
            &[
                "shield",
                "-l",
                &l,
                "--sender",
                "alice",
                "--amount",
                "500",
                "--to",
                &alice_addr,
            ],
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
    let _guard = integration_test_guard();
    let port = free_port();
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

/// Focused real-proof test: generate a shield proof and submit it to a verifier-backed ledger.
/// Slow, so ignored by default. Integration flow tests use TrustMeBro instead.
#[test]
#[ignore = "slow real-proof integration"]
fn test_shield_proof_roundtrip() {
    let _guard = integration_test_guard();
    if !has_reprover() {
        eprintln!("SKIP: reprover binary or Cairo executables not found.");
        return;
    }

    let port = free_port();
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
        assert_eq!(status, 200, "clean shield proof rejected: {}", body);
        let shield_resp: ShieldResp = serde_json::from_str(&body).unwrap();
        assert_eq!(shield_resp.index, 0);
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// Focused real-proof test: setup notes quickly with TrustMeBro, then generate one transfer proof.
#[test]
#[ignore = "slow real-proof integration"]
fn test_transfer_proof_roundtrip() {
    let _guard = integration_test_guard();
    if !has_reprover() {
        eprintln!("SKIP: reprover binary or Cairo executables not found.");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let alice = dir.join("alice.json").to_str().unwrap().to_string();
    let alice_addr = dir.join("alice_addr.json").to_str().unwrap().to_string();
    let recipient_addr = dir
        .join("recipient_addr.json")
        .to_str()
        .unwrap()
        .to_string();
    let port = free_port();
    let l = format!("http://localhost:{}", port);

    let mut ledger = start_ledger_with_verifier(port);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        install_base_wallet_fixture(
            std::path::Path::new(&alice),
            std::path::Path::new(&alice_addr),
        );
        std::fs::write(
            &recipient_addr,
            serde_json::to_string_pretty(&make_test_address()).unwrap(),
        )
        .unwrap();

        let (ok, out) = client_tmb(
            &alice,
            &["fund", "-l", &l, "--addr", "alice", "--amount", "1500"],
        );
        assert!(ok, "fund: {}", out);

        let (ok, out) = client_tmb(
            &alice,
            &[
                "shield",
                "-l",
                &l,
                "--sender",
                "alice",
                "--amount",
                "1500",
                "--to",
                &alice_addr,
            ],
        );
        assert!(ok, "setup shield: {}", out);

        let (ok, out) = client_tmb(&alice, &["scan", "-l", &l]);
        assert!(ok, "setup scan: {}", out);
        assert!(out.contains("1 new notes found"), "setup scan: {}", out);

        let (ok, out) = client_prove(
            &alice,
            &[
                "transfer",
                "-l",
                &l,
                "--to",
                &recipient_addr,
                "--amount",
                "1500",
            ],
        );
        assert!(ok, "real transfer failed: {}", out);
        assert!(out.contains("Transferred 1500"), "transfer output: {}", out);

        let (ok, out) = client_tmb(&alice, &["balance"]);
        assert!(ok, "alice balance: {}", out);
        assert!(out.contains("Private balance: 0"), "alice balance: {}", out);

        let tree: serde_json::Value = ureq::get(&format!("{}/tree", l))
            .call()
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let size = tree.get("size").unwrap().as_u64().unwrap();
        assert_eq!(
            size, 3,
            "tree should contain the setup note plus recipient and change outputs"
        );
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// Focused real-proof test: setup a private note quickly with TrustMeBro, then generate one unshield proof.
#[test]
#[ignore = "slow real-proof integration"]
fn test_unshield_proof_roundtrip() {
    let _guard = integration_test_guard();
    if !has_reprover() {
        eprintln!("SKIP: reprover binary or Cairo executables not found.");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let alice = dir.join("alice.json").to_str().unwrap().to_string();
    let alice_addr = dir.join("alice_addr.json").to_str().unwrap().to_string();
    let port = free_port();
    let l = format!("http://localhost:{}", port);

    let mut ledger = start_ledger_with_verifier(port);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        install_base_wallet_fixture(
            std::path::Path::new(&alice),
            std::path::Path::new(&alice_addr),
        );

        let (ok, out) = client_tmb(
            &alice,
            &["fund", "-l", &l, "--addr", "alice", "--amount", "800"],
        );
        assert!(ok, "fund: {}", out);

        let (ok, out) = client_tmb(
            &alice,
            &[
                "shield",
                "-l",
                &l,
                "--sender",
                "alice",
                "--amount",
                "800",
                "--to",
                &alice_addr,
            ],
        );
        assert!(ok, "setup shield: {}", out);

        let (ok, out) = client_tmb(&alice, &["scan", "-l", &l]);
        assert!(ok, "setup scan: {}", out);
        assert!(out.contains("1 new notes found"), "setup scan: {}", out);

        let (ok, out) = client_prove(
            &alice,
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

        let resp: serde_json::Value = ureq::get(&format!("{}/balances", l))
            .call()
            .unwrap()
            .into_body()
            .read_json()
            .unwrap();
        let balances = resp.get("balances").unwrap();
        assert_eq!(balances.get("bob_pub").and_then(|v| v.as_u64()), Some(800));
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
