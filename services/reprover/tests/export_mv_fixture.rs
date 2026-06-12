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
// Shape-sidecar deps (mirror witness-extractor/src/main.rs).
use circuit_verifier::statement::{
    INTERACTION_POW_BITS as L2_INTERACTION_POW_BITS, all_circuit_components,
};
use circuits::blake::HashValue;
use circuits_stark_verifier::proof::ProofConfig;
use stwo::core::fields::qm31::QM31;
use tzel_reprover::aggregate::{
    AggregationContext, AggregationNode, AggregationShape, aggregate_tree,
};
use tzel_reprover::custom_circuit::{LeafArtifacts, produce_leaf_artifacts};
use tzel_reprover::run_privacy_bootloader;

/// Metadata sidecar mirroring the Go `ProofShape` struct
/// (stwo-gnark-tzel/variables/multiverifier_proof.go). The length-prefix-free
/// binary proof carries no shape info; every read in the Go deserializer is
/// driven by these fields. Field names below are the serde/json tags.
///
/// Ported from witness-extractor/src/main.rs (the single-leaf emitter),
/// adapted to the mv-root proof. `preprocessed_column_registry` entries are
/// `(String, u32)` tuples so serde renders them as 2-element JSON arrays
/// `["name", logsize]`, matching the Go `PreprocessedColumnEntry`.
#[derive(serde::Serialize)]
struct ProofShape {
    n_traces: usize,
    n_composition_columns: usize,
    extension_degree: usize,
    n_pow_bits: u32,
    n_interaction_pow_bits: u32,
    n_components: usize,
    n_preprocessed_columns: usize,
    n_trace_columns: usize,
    n_interaction_columns: usize,
    cumulative_sum_columns: Vec<bool>,
    enabled_bits: Vec<bool>,
    n_columns_per_trace: Vec<usize>,
    log_trace_size: usize,
    log_blowup_factor: usize,
    n_queries: usize,
    log_n_last_layer_coefs: usize,
    fold_step: usize,
    log_evaluation_domain_size: usize,
    all_fold_steps: Vec<usize>,
    l2_preprocessed_root_hex: String,
    component_log_sizes: Vec<u32>,
    preprocessed_column_registry: Vec<(String, u32)>,
    output_values_qm31s: Vec<[u32; 4]>,
}

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
            component_log_sizes: None,
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

    // ── Capture everything the shape sidecar needs from `root.proof`
    //    BEFORE it is moved into prepare_circuit_proof_for_circuit_verifier.
    //    Rebuild the ProofConfig from the proof's ACTUAL PcsConfig (the
    //    prover mutates lifting_log_size at prove time, so the input config
    //    in internal_shared_config may not match). This mirrors the
    //    reference emitter (witness-extractor/src/main.rs ~395-495).
    let mv_actual_pcs_config = root.proof.stark_proof.proof.config;
    let mv_components = all_circuit_components::<QM31>();
    let mv_n_preprocessed_cols = ctx
        .mv_to_mv_preprocessed
        .preprocessed_trace
        .n_columns();
    let mv_proof_config = ProofConfig::new(
        &mv_components,
        vec![true; mv_components.len()],
        mv_n_preprocessed_cols,
        &mv_actual_pcs_config,
        L2_INTERACTION_POW_BITS,
    );

    // L2 prover's actual claim.output_values — the real tzel mv-root outputs
    // (NOT L1's public_data.output_values, which differ; the prover mixes its
    // own claim values into the channel before the interaction PoW).
    let captured_output_values: Vec<[u32; 4]> = root
        .proof
        .claim
        .output_values
        .iter()
        .map(|q| q.to_m31_array().map(|m| m.0))
        .collect();

    // Preprocessed root: commitments.0[0] → HashValue<QM31> → 8 LE M31 words
    // (32 bytes), hex-encoded. Same recipe as the reference + the in-crate
    // debug_dump_component_log_sizes.
    let l2_preprocessed_root_hex = {
        let a = root.proof.stark_proof.proof.commitments.0[0];
        let hv: HashValue<QM31> = a.into();
        let mut h = Vec::with_capacity(32);
        for c in hv.0.to_m31_array().iter().chain(hv.1.to_m31_array().iter()) {
            h.extend_from_slice(&c.0.to_le_bytes());
        }
        hex::encode(&h)
    };

    // Per-component log_sizes — captured during aggregation (the final
    // aggregate_pair populated this on the root node when TZEL_DUMP_LOG_SIZES=1).
    let component_log_sizes = root
        .component_log_sizes
        .clone()
        .expect("component_log_sizes missing — run with TZEL_DUMP_LOG_SIZES=1");

    // Preprocessed-column registry: must correspond to the SAME preprocessed
    // trace whose Merkle root we emit as `l2_preprocessed_root_hex`. The
    // mv-root proof commits the `mv_to_mv_preprocessed` tree at commitments[0],
    // so the registry comes from that preprocessed circuit (in OODS commit
    // order = log-size-sorted). NOTE: `ctx.leaf_preprocessed` (the Cairo
    // verifier leaf) is a DIFFERENT shape and would not match the root.
    let preprocessed_column_registry: Vec<(String, u32)> = ctx
        .mv_to_mv_preprocessed
        .preprocessed_trace
        .log_sizes()
        .iter()
        .map(|(id, log_size)| (id.id.clone(), *log_size))
        .collect();

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

    // ── Shape sidecar — drives every read in the Go ReadMultiverifierProof.
    let n_columns_per_trace = mv_proof_config.n_columns_per_trace().to_vec();
    let n_interaction_columns = n_columns_per_trace[2];

    let log_trace_size = mv_proof_config.fri.log_trace_size;
    let log_blowup_factor = mv_proof_config.fri.log_blowup_factor;
    let log_n_last_layer_coefs = mv_proof_config.fri.log_n_last_layer_coefs;
    let fold_step = mv_proof_config.fri.fold_step;
    let n_queries = mv_proof_config.fri.n_queries;
    let log_evaluation_domain_size = log_trace_size + log_blowup_factor;

    // all_fold_steps: fold_step per FRI layer, last layer holds the remainder.
    // Same computation as the reference emitter.
    let all_fold_steps = {
        let degree_log_ratio = log_trace_size - log_n_last_layer_coefs;
        let n_folds = degree_log_ratio.div_ceil(fold_step);
        let rem = degree_log_ratio % fold_step;
        let mut v = vec![fold_step; n_folds];
        if rem != 0 {
            *v.last_mut().unwrap() = rem;
        }
        v
    };

    let shape = ProofShape {
        // Constants (the Go side may also hardcode these).
        n_traces: 4,
        n_composition_columns: 8,
        extension_degree: 4,
        // From the rebuilt ProofConfig.
        n_pow_bits: mv_proof_config.n_pow_bits,
        n_interaction_pow_bits: mv_proof_config.n_interaction_pow_bits,
        n_components: mv_proof_config.n_components(),
        n_preprocessed_columns: mv_proof_config.n_preprocessed_columns,
        n_trace_columns: mv_proof_config.n_trace_columns,
        n_interaction_columns,
        cumulative_sum_columns: mv_proof_config.cumulative_sum_columns.clone(),
        enabled_bits: mv_proof_config.enabled_bits.clone(),
        n_columns_per_trace,
        log_trace_size,
        log_blowup_factor,
        n_queries,
        log_n_last_layer_coefs,
        fold_step,
        log_evaluation_domain_size,
        all_fold_steps,
        l2_preprocessed_root_hex,
        component_log_sizes,
        preprocessed_column_registry,
        output_values_qm31s: captured_output_values,
    };
    let shape_json = serde_json::to_string_pretty(&shape).expect("serialize ProofShape");
    let shape_path = out_dir.join("mv_root_proof.shape.json");
    std::fs::write(&shape_path, shape_json.as_bytes()).expect("write shape.json");
    eprintln!(
        "[EXPORT-MV] wrote shape {} bytes to {}",
        shape_json.len(),
        shape_path.display()
    );
    eprintln!(
        "[EXPORT-MV] component_log_sizes = {:?}",
        shape.component_log_sizes
    );

    eprintln!("[EXPORT-MV] total wall {:?}", t0.elapsed());
}
