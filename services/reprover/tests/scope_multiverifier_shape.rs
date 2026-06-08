//! Scope helper for the multiverifier-target chip rebuild.
//!
//! Produces ONE shield leaf (~30s) just to feed AggregationContext::new(),
//! then dumps everything BenchCircuit / multiverifier_proof.go would need to
//! hardcode for the multiverifier-shape chip:
//!
//!   - leaf_to_mv preprocessed shape (level 0 → 1)
//!   - mv_to_mv preprocessed shape    (level ≥ 1, reused across the tree)
//!
//! Heavy (~30-60s). `#[ignore]`.

use std::path::PathBuf;

use tzel_reprover::aggregate::AggregationContext;
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

#[test]
#[ignore]
fn dump_multiverifier_shape() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    eprintln!("[SCOPE-MV] producing 1 shield leaf for topology …");
    let exe = fixture("run_shield.executable.json");
    let args = args_fixture("run_shield_args.json");
    let (prover_input, output_preimage) =
        run_privacy_bootloader(&exe, None, Some(args)).expect("bootloader");
    let leaf: LeafArtifacts = produce_leaf_artifacts(prover_input, output_preimage).expect("leaf");
    eprintln!("[SCOPE-MV] leaf produced");

    let leaf_pp = leaf.preprocessed_circuit.clone();
    let leaf_cfg = leaf.circuit_pcs_config;

    eprintln!(
        "[SCOPE-MV] leaf preprocessed: trace_log_size={}, n_columns={}",
        leaf_pp.params.trace_log_size,
        leaf_pp.preprocessed_trace.n_columns()
    );
    let leaf_log_sizes = leaf_pp.preprocessed_trace.log_sizes();
    eprintln!(
        "[SCOPE-MV] leaf preprocessed: {} entries in log_sizes() map",
        leaf_log_sizes.len()
    );

    let ctx = AggregationContext::new(leaf_pp, leaf_cfg).expect("ctx");

    eprintln!("\n[SCOPE-MV] ── leaf_to_mv preprocessed (level 0 → 1) ──");
    let l2mv = &ctx.leaf_to_mv_preprocessed;
    eprintln!(
        "[SCOPE-MV]   trace_log_size = {}",
        l2mv.params.trace_log_size
    );
    eprintln!(
        "[SCOPE-MV]   preprocessed n_columns = {}",
        l2mv.preprocessed_trace.n_columns()
    );
    let l2mv_log_sizes = l2mv.preprocessed_trace.log_sizes();
    eprintln!(
        "[SCOPE-MV]   preprocessed log_sizes() n_entries = {}",
        l2mv_log_sizes.len()
    );
    for (i, (id, log_size)) in l2mv_log_sizes.iter().enumerate() {
        eprintln!("[SCOPE-MV]     [{:>3}] log_size={:>2} id={:?}", i, log_size, id);
    }

    eprintln!("\n[SCOPE-MV] ── mv_to_mv preprocessed (level ≥ 1, root candidate) ──");
    let mv2mv = &ctx.mv_to_mv_preprocessed;
    eprintln!(
        "[SCOPE-MV]   trace_log_size = {}",
        mv2mv.params.trace_log_size
    );
    eprintln!(
        "[SCOPE-MV]   preprocessed n_columns = {}",
        mv2mv.preprocessed_trace.n_columns()
    );
    let mv2mv_log_sizes = mv2mv.preprocessed_trace.log_sizes();
    eprintln!(
        "[SCOPE-MV]   preprocessed log_sizes() n_entries = {}",
        mv2mv_log_sizes.len()
    );
    for (i, (id, log_size)) in mv2mv_log_sizes.iter().enumerate() {
        eprintln!("[SCOPE-MV]     [{:>3}] log_size={:>2} id={:?}", i, log_size, id);
    }

    eprintln!("\n[SCOPE-MV] ── SharedConfig snapshots ──");
    eprintln!(
        "[SCOPE-MV]   leaf_shared_config.pcs_config = {:?}",
        ctx.leaf_shared_config.pcs_config
    );
    eprintln!(
        "[SCOPE-MV]   internal_shared_config.pcs_config = {:?}",
        ctx.internal_shared_config.pcs_config
    );
    eprintln!(
        "[SCOPE-MV]   internal proof_config n_columns_per_trace = {:?}",
        ctx.internal_shared_config.proof_config.n_columns_per_trace()
    );
    eprintln!(
        "[SCOPE-MV]   internal proof_config n_components = {}",
        ctx.internal_shared_config.proof_config.n_components()
    );
    eprintln!(
        "[SCOPE-MV]   internal proof_config n_preprocessed_columns = {}",
        ctx.internal_shared_config.proof_config.n_preprocessed_columns
    );
    eprintln!(
        "[SCOPE-MV]   internal proof_config n_trace_columns = {}",
        ctx.internal_shared_config.proof_config.n_trace_columns
    );
}
