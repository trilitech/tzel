//! Integration tests covering the bootloader output-preimage shape and
//! the slow N=7 transfer real-proof guard. End-to-end demo-ledger flows
//! moved out when `cmd_shield` was deleted; the kernel-side equivalents
//! now live in `tezos/rollup-kernel/tests/bridge_flow.rs`.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tzel_services::*;
use tzel_verifier::{DirectProofVerifier, ProofBundle as VerifyProofBundle};

const PROVER_TOOLCHAIN: &str = "+nightly-2025-07-14";

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

fn has_reprover() -> bool {
    std::path::Path::new(&reprove_bin_path()).exists()
        && std::path::Path::new(&executables_dir())
            .join("run_shield.executable.json")
            .exists()
}

fn generate_stark_bundle(executable_filename: &str, args: &[String]) -> VerifyProofBundle {
    let executable = format!("{}/{}", executables_dir(), executable_filename);
    let args_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(args_file.path(), serde_json::to_string(args).unwrap()).unwrap();
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

    let bundle_json = std::fs::read_to_string(proof_file.path()).unwrap();
    serde_json::from_str(&bundle_json).unwrap()
}

fn bootloader_cairo_array_public_outputs(output_preimage: &[F]) -> &[F] {
    let parsed = parse_single_task_output_preimage(output_preimage)
        .expect("bootloader output preimage should parse");
    let (declared_len_felt, public_outputs) = parsed
        .public_outputs
        .split_first()
        .expect("bootloader task output should contain a Cairo array length");
    let declared_len = felt_to_usize(declared_len_felt)
        .expect("Cairo public-output array length should fit usize");
    assert_eq!(
        declared_len,
        public_outputs.len(),
        "Cairo public-output array length prefix must match stripped output length",
    );
    public_outputs
}

#[test]
fn bootloader_public_outputs_strip_cairo_array_length_prefix() {
    let expected_public_outputs = vec![u64_to_felt(11), u64_to_felt(22), u64_to_felt(33)];
    let mut output_preimage = vec![
        u64_to_felt(1),
        u64_to_felt((expected_public_outputs.len() + 3) as u64),
        u64_to_felt(12345),
        u64_to_felt(expected_public_outputs.len() as u64),
    ];
    output_preimage.extend(expected_public_outputs.iter().copied());

    assert_eq!(
        bootloader_cairo_array_public_outputs(&output_preimage),
        expected_public_outputs.as_slice(),
    );
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

/// Slow, ignored by default: prove a max-input transfer witness directly.
/// This is the explicit guard against N=7 trace-budget or tail-slicing failures.
#[test]
#[ignore = "slow real-proof max-input proof"]
fn test_transfer_7_inputs_proof_roundtrip() {
    let _guard = integration_test_guard();
    if !has_reprover() {
        eprintln!("SKIP: reprover binary or Cairo executables not found.");
        return;
    }

    let witness = proof_bench::build_transfer_bench_witness(7);
    let bundle = generate_stark_bundle("run_transfer.executable.json", &witness.args);
    let public_outputs = bootloader_cairo_array_public_outputs(&bundle.output_preimage);

    assert_eq!(
        public_outputs,
        witness.expected_public_outputs.as_slice(),
        "n=7 transfer proof public outputs must match the witness, including the final nullifier",
    );
    assert!(
        !bundle.proof_bytes.is_empty(),
        "proof bytes should be nonempty"
    );
    let proof = Proof::Stark {
        proof_bytes: bundle.proof_bytes,
        output_preimage: bundle.output_preimage,
    };
    DirectProofVerifier::from_executables_dir(false, &executables_dir())
        .expect("test executables should provide program hashes")
        .validate(&proof, CircuitKind::Transfer)
        .expect("n=7 transfer proof should verify with canonical metadata");
}

