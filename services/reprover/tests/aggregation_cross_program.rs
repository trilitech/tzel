//! Cross-program aggregation test: 2× shield + 2× transfer → 1 root proof.
//!
//! Tests whether the multiverifier can aggregate leaves from *different*
//! TZEL programs (sharing the same Cairo AIR topology but with different
//! per-component log_sizes). Per the G4 sanity check (`g4_cross_program_check`):
//!   - shield and transfer have IDENTICAL `enable_bits` (the bootloader
//!     normalizes them);
//!   - their `component_log_sizes` differ — but log_sizes are public inputs,
//!     not topology metadata, so the circuit_verifier topology is identical.
//!
//! If this test passes, the bootloader's normalization is sufficient for
//! cross-program aggregation across the current TZEL program family, and the
//! G4 "enable_bits canonical prologue" is not needed.
//!
//! Heavy (~4 min). `#[ignore]`.

use std::path::PathBuf;

use tzel_reprover::aggregate::{
    AggregationContext, AggregationNode, AggregationShape, aggregate_tree,
};
use tzel_reprover::custom_circuit::{LeafArtifacts, produce_leaf_artifacts};
use tzel_reprover::run_privacy_bootloader;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("cairo/target/dev")
        .join(name)
}

fn args_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn one_leaf(exe: &str, args: &str) -> LeafArtifacts {
    let exe_path = fixture(exe);
    let args_path = args_fixture(args);
    let (prover_input, output_preimage) =
        run_privacy_bootloader(&exe_path, None, Some(args_path)).expect("bootloader");
    produce_leaf_artifacts(prover_input, output_preimage).expect("leaf")
}

#[test]
#[ignore]
fn aggregate_two_shields_two_transfers() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    eprintln!("[XPROG] === generating 2 shield + 2 transfer leaves ===");
    let t = std::time::Instant::now();
    let leaves: Vec<LeafArtifacts> = vec![
        ("shield-A", "run_shield.executable.json", "run_shield_args.json"),
        ("shield-B", "run_shield.executable.json", "run_shield_args.json"),
        (
            "transfer-A",
            "run_transfer.executable.json",
            "run_transfer_args.json",
        ),
        (
            "transfer-B",
            "run_transfer.executable.json",
            "run_transfer_args.json",
        ),
    ]
    .into_iter()
    .map(|(label, exe, args)| {
        let t = std::time::Instant::now();
        let leaf = one_leaf(exe, args);
        eprintln!(
            "[XPROG]   {} produced in {:?} (cairo {}ms, circuit {}ms)",
            label,
            t.elapsed(),
            leaf.cairo_prove_ms,
            leaf.circuit_prove_ms,
        );
        leaf
    })
    .collect();
    eprintln!("[XPROG] all 4 leaves produced in {:?}", t.elapsed());

    let leaf_preprocessed = leaves[0].preprocessed_circuit.clone();
    let leaf_pcs_config = leaves[0].circuit_pcs_config;
    let ctx = AggregationContext::new(leaf_preprocessed, leaf_pcs_config).expect("ctx");

    let nodes: Vec<AggregationNode> = leaves
        .into_iter()
        .map(|l| AggregationNode {
            proof: l.circuit_proof,
            shape: AggregationShape::Leaf,
        })
        .collect();

    eprintln!("[XPROG] === aggregating 4 → 1 ===");
    let t_agg = std::time::Instant::now();
    let root = aggregate_tree(&ctx, nodes).expect("aggregate_tree");
    eprintln!("[XPROG] root produced in {:?}", t_agg.elapsed());

    assert_eq!(root.shape, AggregationShape::Internal);
    eprintln!(
        "[XPROG] ✓ cross-program aggregation: 2 shield + 2 transfer → 1 root proof"
    );
}
