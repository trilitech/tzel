use std::path::PathBuf;
use std::process::Command;

/// Sandbox-level integration test for the TzEL orchestrator (Mode A).
///
/// Originates the orchestrator contract on a local Octez sandbox next to a
/// real smart rollup running the TzEL kernel, calls `%shield` with a
/// wire-valid stub body, and asserts (through the rollup node durable
/// storage) that the kernel received the internal `Transfer<MichelsonBytes>`
/// inbox entry and dispatched it through `apply_kernel_message` — the
/// deterministic rejection "proof verifier is not configured" lands in
/// `/tzel/v1/state/last_result.bin`.
#[test]
#[ignore = "requires installed Octez binaries plus local sandbox networking"]
fn octez_sandbox_orchestrator_shield_dispatch() {
    if std::env::var_os("TZEL_RUN_ORCHESTRATOR_SANDBOX").is_none()
        && std::env::var_os("TZEL_RUN_OCTEZ_ROLLUP_SANDBOX").is_none()
    {
        eprintln!(
            "skipping: set TZEL_RUN_ORCHESTRATOR_SANDBOX=1 (or TZEL_RUN_OCTEZ_ROLLUP_SANDBOX=1) to run"
        );
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace layout")
        .to_path_buf();
    let script = repo_root.join("scripts/octez_orchestrator_sandbox_smoke.sh");

    let status = Command::new(&script)
        .current_dir(&repo_root)
        .status()
        .expect("failed to launch Octez orchestrator sandbox smoke script");

    assert!(status.success(), "Octez orchestrator sandbox smoke script failed");
}
