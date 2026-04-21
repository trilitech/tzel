use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "requires installed Octez and DAL binaries plus local sandbox networking"]
fn octez_sandbox_configure_bridge_roundtrip() {
    if std::env::var_os("TZEL_RUN_OCTEZ_ROLLUP_SANDBOX").is_none() {
        eprintln!("skipping: set TZEL_RUN_OCTEZ_ROLLUP_SANDBOX=1 to run");
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace layout")
        .to_path_buf();
    let script = repo_root.join("scripts/octez_rollup_sandbox_smoke.sh");

    let status = Command::new(&script)
        .current_dir(&repo_root)
        .status()
        .expect("failed to launch Octez sandbox smoke script");

    assert!(status.success(), "Octez sandbox smoke script failed");
}
