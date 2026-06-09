//! Export a multiverifier root proof as a chip fixture.
//!
//! Produces 4 shield/transfer leaves, aggregates them to a single mv_to_mv
//! root proof, then serializes the root via `CircuitSerialize` into
//! `/tmp/tzel-mv-fixture/mv_root_proof.bin` — the drop-in input format for
//! stwo-gnark-tzel's witness pipeline (same byte layout as `l2_proof.bin`).
//!
//! Run with `TZEL_DUMP_LOG_SIZES=1` to also capture the per-component
//! log_sizes + preprocessed roots the gnark BenchCircuit hardcodes.
//!
//! Heavy (~3 min). `#[ignore]`.

use std::path::PathBuf;

use circuit_prover::prover::prepare_circuit_proof_for_circuit_verifier;
use circuit_serialize::serialize::CircuitSerialize;
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
fn export_mv_root_fixture() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let out_dir = PathBuf::from("/tmp/tzel-mv-fixture");
    std::fs::create_dir_all(&out_dir).expect("mkdir out_dir");

    eprintln!("[EXPORT-MV] generating 2 shield + 2 transfer leaves …");
    let t0 = std::time::Instant::now();
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
        eprintln!("[EXPORT-MV]   {} in {:?}", label, t.elapsed());
        leaf
    })
    .collect();
    eprintln!("[EXPORT-MV] 4 leaves in {:?}", t0.elapsed());

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

    eprintln!("[EXPORT-MV] aggregating 4 → 1 …");
    let t_agg = std::time::Instant::now();
    let root = aggregate_tree(&ctx, nodes).expect("aggregate_tree");
    eprintln!("[EXPORT-MV] root in {:?}", t_agg.elapsed());
    assert_eq!(root.shape, AggregationShape::Internal);

    // ── Serialize the root proof via CircuitSerialize ─────────────────
    // Same path as custom_circuit's run_leaf_pipeline_serialized: prepare
    // → serialize. The internal_shared_config's proof_config describes the
    // mv shape the root proof has.
    eprintln!("[EXPORT-MV] pcs_config = {:?}", root.proof.pcs_config);
    eprintln!(
        "[EXPORT-MV] root output_values = {:?}",
        root.proof.claim.output_values
    );
    eprintln!(
        "[EXPORT-MV] root channel_salt = {}, interaction_pow_nonce = {}",
        root.proof.channel_salt, root.proof.interaction_pow_nonce
    );

    let (proof_qm31s, public_data) = prepare_circuit_proof_for_circuit_verifier(
        root.proof,
        &ctx.internal_shared_config.proof_config,
    );
    eprintln!(
        "[EXPORT-MV] public_data.output_values = {:?}",
        public_data.output_values
    );

    let mut bytes: Vec<u8> = vec![];
    proof_qm31s.serialize(&mut bytes);
    let out_path = out_dir.join("mv_root_proof.bin");
    std::fs::write(&out_path, &bytes).expect("write mv_root_proof.bin");
    eprintln!(
        "[EXPORT-MV] wrote {} bytes to {}",
        bytes.len(),
        out_path.display()
    );

    eprintln!("[EXPORT-MV] total wall {:?}", t0.elapsed());
}
