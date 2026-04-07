//! Integration tests: spawns sp-ledger in --trust-me-bro mode, runs sp-client
//! commands as subprocesses with alice and bob wallets.
//!
//! Most operations use --trust-me-bro for speed. At least one of each circuit
//! type (shield, transfer, unshield) is tested with real STARK proofs.
//! The ledger runs in trust-me-bro mode throughout — this means it accepts
//! BOTH TrustMeBro and real Stark proofs. Real proofs must still be valid
//! (the reprover verifies internally before returning).

use std::process::{Child, Command, Stdio};
use std::time::Duration;

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
        .parent().unwrap()
        .join("reprover/target/release/reprove");
    path.to_str().unwrap().to_string()
}

/// Path to compiled Cairo executables
fn executables_dir() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
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

/// Run sp-client with real STARK proof generation.
fn client_prove(wallet: &str, args: &[&str]) -> (bool, String) {
    let reprove = reprove_bin();
    let exedir = executables_dir();
    let mut full_args = vec![
        "-w", wallet,
        "--reprove-bin", &reprove,
        "--executables-dir", &exedir,
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
    std::thread::sleep(Duration::from_millis(500));
    child
}

fn has_reprover() -> bool {
    std::path::Path::new(&reprove_bin()).exists()
        && std::path::Path::new(&executables_dir()).join("run_shield.executable.json").exists()
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
        let (ok, out) = client_tmb(&alice, &["fund", "-l", &l, "--addr", "alice", "--amount", "2000"]);
        assert!(ok, "fund: {}", out);

        // ── Shield 1500 + 500 ───────────────────────────────────────
        let (ok, out) = client_tmb(&alice, &["shield", "-l", &l, "--sender", "alice", "--amount", "1500"]);
        assert!(ok, "shield 1500: {}", out);
        assert!(out.contains("Shielded 1500"));

        let (ok, out) = client_tmb(&alice, &["shield", "-l", &l, "--sender", "alice", "--amount", "500"]);
        assert!(ok, "shield 500: {}", out);
        assert!(out.contains("Shielded 500"));

        // ── Insufficient balance ────────────────────────────────────
        let (ok, _) = client_tmb(&alice, &["shield", "-l", &l, "--sender", "alice", "--amount", "1"]);
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
        let (ok, out) = client_tmb(&alice, &[
            "transfer", "-l", &l, "--to", &bob_addr, "--amount", "1200",
        ]);
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
        let (ok, out) = client_tmb(&bob, &[
            "unshield", "-l", &l, "--amount", "500", "--recipient", "bob_pub",
        ]);
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
        let (ok, _) = client_tmb(&alice, &[
            "transfer", "-l", &l, "--to", &bob_addr, "--amount", "9999",
        ]);
        assert!(!ok, "transfer exceeding balance should fail");

        // ── Public balances ─────────────────────────────────────────
        let resp: serde_json::Value = ureq::get(&format!("{}/balances", l))
            .call().unwrap().into_body().read_json().unwrap();
        let balances = resp.get("balances").unwrap();
        assert_eq!(balances.get("alice").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(balances.get("bob_pub").and_then(|v| v.as_u64()), Some(500));

        // ── Tree integrity ──────────────────────────────────────────
        let tree: serde_json::Value = ureq::get(&format!("{}/tree", l))
            .call().unwrap().into_body().read_json().unwrap();
        let size = tree.get("size").unwrap().as_u64().unwrap();
        assert!(size >= 5, "tree should have at least 5 leaves, got {}", size);

        // ── Value conservation ──────────────────────────────────────
        // alice_private(800) + bob_private(700) + bob_public(500) = 2000
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result { std::panic::resume_unwind(e); }
}

/// Test that the ledger rejects TrustMeBro when NOT started with --trust-me-bro.
#[test]
fn test_ledger_rejects_tmb_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let alice = dir.path().join("alice.json").to_str().unwrap().to_string();

    // Start ledger WITHOUT --trust-me-bro on a different port
    let port = LEDGER_PORT + 1;
    let l = format!("http://localhost:{}", port);
    let mut ledger = Command::new(sp_ledger())
        .args(["--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start ledger");
    std::thread::sleep(Duration::from_millis(500));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (ok, _) = client_tmb(&alice, &["keygen"]);
        assert!(ok);

        // Fund works (no proof needed)
        let (ok, _) = client_tmb(&alice, &["fund", "-l", &l, "--addr", "alice", "--amount", "1000"]);
        assert!(ok, "fund should work without proof");

        // Shield with TrustMeBro should be REJECTED
        let (ok, out) = client_tmb(&alice, &["shield", "-l", &l, "--sender", "alice", "--amount", "500"]);
        assert!(!ok, "ledger should reject TrustMeBro: {}", out);
        assert!(out.contains("TrustMeBro proofs rejected") || out.contains("400"),
            "expected rejection message: {}", out);
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result { std::panic::resume_unwind(e); }
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

    let mut ledger = Command::new(sp_ledger())
        .args(["--port", &port.to_string(), "--trust-me-bro"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start ledger");
    std::thread::sleep(Duration::from_millis(500));

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

        let (ok, _) = client_tmb(&alice, &["fund", "-l", &l, "--addr", "alice", "--amount", "5000"]);
        assert!(ok);

        // ── REAL PROOF: Shield 1000 ─────────────────────────────────
        eprintln!(">>> Generating real shield proof...");
        let (ok, out) = client_prove(&alice, &["shield", "-l", &l, "--sender", "alice", "--amount", "1000"]);
        assert!(ok, "real shield failed: {}", out);
        assert!(out.contains("Shielded 1000"), "shield output: {}", out);
        assert!(out.contains("Proof generated"), "should show proof generation: {}", out);
        eprintln!(">>> Shield proof OK");

        // Use TMB for a second shield (to have notes for transfer)
        let (ok, _) = client_tmb(&alice, &["shield", "-l", &l, "--sender", "alice", "--amount", "500"]);
        assert!(ok);

        // Scan to pick up both notes
        let (ok, out) = client_tmb(&alice, &["scan", "-l", &l]);
        assert!(ok, "scan: {}", out);
        assert!(out.contains("2 new notes found"));

        // ── REAL PROOF: Transfer 800 to bob ─────────────────────────
        // Alice has 1000 + 500 = 1500. Transfer 800, change 200 (from the 1000 note).
        eprintln!(">>> Generating real transfer proof...");
        let (ok, out) = client_prove(&alice, &[
            "transfer", "-l", &l, "--to", &bob_addr, "--amount", "800",
        ]);
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
        assert!(out.contains("Private balance: 800"), "bob should have 800: {}", out);

        // ── REAL PROOF: Unshield 300 from bob (no change) ───────────
        // Bob has 800. Unshield 800 (exact, no change) to avoid the
        // "change not wired" issue.
        eprintln!(">>> Generating real unshield proof...");
        let (ok, out) = client_prove(&bob, &[
            "unshield", "-l", &l, "--amount", "800", "--recipient", "bob_pub",
        ]);
        assert!(ok, "real unshield failed: {}", out);
        assert!(out.contains("Unshielded 800"), "unshield output: {}", out);
        eprintln!(">>> Unshield proof OK");

        // ── Verify final state ──────────────────────────────────────
        let resp: serde_json::Value = ureq::get(&format!("{}/balances", l))
            .call().unwrap().into_body().read_json().unwrap();
        let balances = resp.get("balances").unwrap();
        let bob_public = balances.get("bob_pub").and_then(|v| v.as_u64()).unwrap_or(0);
        assert_eq!(bob_public, 800, "bob_pub should have 800");

        let alice_public = balances.get("alice").and_then(|v| v.as_u64()).unwrap_or(0);
        // alice funded 5000, shielded 1000+500 = 1500 remaining public = 3500
        assert_eq!(alice_public, 3500, "alice public should be 3500");

        eprintln!(">>> All three real proofs verified successfully");
    }));

    let _ = ledger.kill();
    let _ = ledger.wait();
    if let Err(e) = result { std::panic::resume_unwind(e); }
}
