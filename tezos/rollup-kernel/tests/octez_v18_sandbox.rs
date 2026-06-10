use std::path::PathBuf;
use std::process::Command;

/// Sandbox-level integration test for the v18 DAL-free submission protocol
/// (`docs/SNARK-SUBMISSION-DESIGN.md`): `StageChunk`, `SubmitOps`, and
/// `SubmitStagedConfig`, injected as external Targetted smart-rollup inbox
/// messages on a local Octez sandbox.
///
/// The kernel WASM is built with `TZEL_INSECURE_SANDBOX=1` so the
/// `kernel-test-skip-verify` Groth16 token fires in-rollup, bypassing ONLY the
/// proof-side Groth16 tree walk + program-hash binding. The kernel's CORE
/// output-binding still runs and is satisfied by the fixture's real
/// `output_preimage`, so the assertions below prove APPLY (durable state
/// change), not just parse:
///
///   1. SubmitStagedConfig (gap #1): a signed ConfigureVerifier envelope is
///      staged across 2 `StageChunk`s, then `SubmitStagedConfig` applies it —
///      asserted by `KernelResult::Configured` (tag 0) plus a populated
///      `/tzel/v1/state/verifier_config.bin` durable key.
///   2. StageChunk → SubmitOps shield: the two shield notes are staged (the
///      client note split across 2 chunks), then a single-op `SubmitOps`
///      applies the shield — asserted by `KernelResult::Submitted` (tag 6),
///      the deposit pool draining to 0, and the note tree size reaching 2 (the
///      two shield commitments). The drain + insertion are only reachable if
///      the staged notes are SEALED and CONSUMED, so this also covers the
///      staged-note lifecycle.
///
/// REPRO:
///   TZEL_RUN_V18_SANDBOX=1 \
///     cargo test -p tzel-rollup-kernel --test octez_v18_sandbox \
///     -- --ignored --nocapture
/// or run the harness directly:
///   scripts/octez_v18_sandbox_smoke.sh
///
/// Like `octez_orchestrator_sandbox.rs`, this needs installed Octez binaries
/// (octez-node / octez-client / octez-smart-rollup-node / smart-rollup-installer)
/// plus local sandbox networking. It needs NO DAL node and NO `ligo`.
///
/// KNOWN BLOCKER (kernel storage layer, not this harness): on the real Octez
/// rollup runtime the kernel's `WasmHost::read_store`/`write_store`
/// (`src/lib.rs` ~2760) do a SINGLE raw `store_read`/`store_write`, capped by
/// the PVM at `MAX_FILE_CHUNK_SIZE = 2048` bytes/call. `apply_stage_chunk`
/// writes each chunk's `bytes` (≈3.4 KiB per encrypted note, ≈4.9 KiB per
/// signed config envelope) in one `write_store`, so the write silently fails
/// and seal-time reassembly reports `staging entry N chunk K is missing`. The
/// in-process `bridge_flow.rs` tests miss this because `TestHost` is a HashMap
/// with no per-call size cap. The fix is in kernel src (loop both helpers over
/// `MAX_FILE_CHUNK_SIZE`, or use the SDK `store_*_all` helpers) and is out of
/// scope for the harness. Until it lands, every scenario below reaches the
/// kernel and dispatches correctly but cannot SEAL a multi-KiB chunk on real
/// Octez, so this test currently fails at the first StageChunk seal.
#[test]
#[ignore = "requires installed Octez binaries plus local sandbox networking"]
fn octez_sandbox_v18_submission_protocol() {
    if std::env::var_os("TZEL_RUN_V18_SANDBOX").is_none()
        && std::env::var_os("TZEL_RUN_OCTEZ_ROLLUP_SANDBOX").is_none()
    {
        eprintln!("skipping: set TZEL_RUN_V18_SANDBOX=1 (or TZEL_RUN_OCTEZ_ROLLUP_SANDBOX=1) to run");
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace layout")
        .to_path_buf();
    let script = repo_root.join("scripts/octez_v18_sandbox_smoke.sh");

    let status = Command::new(&script)
        .current_dir(&repo_root)
        .status()
        .expect("failed to launch Octez v18 sandbox smoke script");

    assert!(status.success(), "Octez v18 sandbox smoke script failed");
}
