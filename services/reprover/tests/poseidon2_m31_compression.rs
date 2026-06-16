//! COMPRESSION SPIKE — does the Poseidon2-M31 recursion ladder shrink, or grow
//! to a fixed point?
//!
//! Two parts:
//!  (1) REAL Layer 1 measurement: a Poseidon2-M31 node verifying two real
//!      leaf_to_mv (mv-root) proofs. Record its full DA shape (FRI layers,
//!      decommit hash counts, size_breakdown bytes) + prove time @96-bit.
//!  (2) SHAPE-LADDER iteration (cheap, no proving): starting from the real
//!      leaf_to_mv node preprocessed, iterate "the multiverifier node that
//!      verifies a proof of the previous level's shape" and record
//!      trace_log_size + n_columns at each level. This directly answers: does
//!      the node-that-verifies-shape-S have shape S (fixed point, no growth), or
//!      does each level grow? And if it converges, at what shape?
//!
//! Run:
//! ```bash
//! TZEL_SEC=96 TZEL_DUMP_LOG_SIZES=1 RAYON_NUM_THREADS=22 \
//!   cargo test --release --test poseidon2_m31_compression -- --ignored --nocapture
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use circuit_common::preprocessed::PreprocessedCircuit;
use stwo::core::pcs::PcsConfig;

const RESULT_FILE: &str = "/tmp/p2m31_compression_result.txt";

macro_rules! logln {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        let _ = std::io::stderr().flush();
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true).append(true).open(RESULT_FILE) {
            let _ = writeln!(f, $($arg)*);
            let _ = f.flush();
        }
    }};
}

use stwo::core::vcs_lifted::poseidon2_m31_merkle::{
    Poseidon2M31MerkleChannel, Poseidon2M31MerkleHasher,
};
use tzel_reprover::aggregate::{
    AggregationContext, AggregationNode, AggregationShape, aggregate_pair,
    aggregate_pair_outer_with_channel, stwo_verify_outer,
};
use tzel_reprover::custom_circuit::{LeafArtifacts, produce_leaf_artifacts};
use tzel_reprover::run_privacy_bootloader;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().parent().unwrap()
        .join("cairo/target/dev").join(name)
}
fn args_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}
fn one_shield_leaf() -> LeafArtifacts {
    let exe = fixture("run_shield.executable.json");
    let args = args_fixture("run_shield_args.json");
    assert!(exe.exists(), "missing fixture {}", exe.display());
    let (pi, op) = run_privacy_bootloader(&exe, None, Some(args)).expect("bootloader");
    produce_leaf_artifacts(pi, op).expect("leaf")
}

fn base_internal_pcs() -> PcsConfig {
    if std::env::var("TZEL_SEC").as_deref() == Ok("96") {
        PcsConfig {
            pow_bits: 26,
            fri_config: stwo::core::fri::FriConfig {
                log_blowup_factor: 2, log_last_layer_degree_bound: 0,
                n_queries: 35, fold_step: 1,
            },
            lifting_log_size: None,
        }
    } else {
        PcsConfig {
            pow_bits: 10,
            fri_config: stwo::core::fri::FriConfig {
                log_blowup_factor: 1, log_last_layer_degree_bound: 0,
                n_queries: 23, fold_step: 1,
            },
            lifting_log_size: None,
        }
    }
}

/// Report the full DA / decommit shape of an outer Poseidon2-M31 proof.
fn report_shape(
    label: &str,
    proof: &circuit_verifier::circuit_proof::CircuitProof<Poseidon2M31MerkleHasher>,
) {
    let sp = &proof.stark_proof.proof;
    let cs = &sp.0;
    let n_commit = cs.commitments.0.len();
    let n_fri_inner = cs.fri_proof.inner_layers.len();
    let trace_decommit_hashes: Vec<usize> =
        cs.decommitments.0.iter().map(|d| d.hash_witness.len()).collect();
    let fri_first_hashes = cs.fri_proof.first_layer.decommitment.hash_witness.len();
    let fri_inner_hashes: Vec<usize> =
        cs.fri_proof.inner_layers.iter().map(|l| l.decommitment.hash_witness.len()).collect();
    let total_trace_hashes: usize = trace_decommit_hashes.iter().sum();
    let total_fri_inner_hashes: usize = fri_inner_hashes.iter().sum();
    let total_merkle_hashes = total_trace_hashes + fri_first_hashes + total_fri_inner_hashes;
    let bd = sp.size_breakdown_estimate();
    let total = sp.size_estimate();

    logln!("──────── {label} ────────");
    logln!("  pcs_config                     = {:?}", proof.pcs_config);
    logln!("  n trace trees (decommit sites) = {n_commit}");
    logln!("  FRI inner layers               = {n_fri_inner}");
    logln!("  total decommit sites           = {} (= {n_commit} trace + 1 FRI-first + {n_fri_inner} FRI-inner)", n_commit + 1 + n_fri_inner);
    logln!("  trace decommit hash-witness    = {trace_decommit_hashes:?}");
    logln!("  FRI first-layer decommit hashes= {fri_first_hashes}");
    logln!("  FRI inner-layer decommit hashes= {fri_inner_hashes:?}");
    logln!("  TOTAL Merkle-path hashes       = {total_merkle_hashes} (trace {total_trace_hashes} + FRI-first {fri_first_hashes} + FRI-inner {total_fri_inner_hashes})");
    logln!("  DA size_estimate (bytes)       = {total}");
    logln!("    oods_samples         = {}", bd.oods_samples);
    logln!("    queries_values       = {}", bd.queries_values);
    logln!("    fri_samples          = {}", bd.fri_samples);
    logln!("    fri_decommitments    = {}", bd.fri_decommitments);
    logln!("    trace_decommitments  = {}", bd.trace_decommitments);
}

fn shape(pp: &PreprocessedCircuit) -> (u32, usize) {
    (pp.params.trace_log_size, pp.preprocessed_trace.n_columns())
}

#[test]
#[ignore]
fn poseidon2_m31_compression_ladder() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
    let _ = std::fs::write(RESULT_FILE, b"");
    let t_all = Instant::now();
    let sec = std::env::var("TZEL_SEC").unwrap_or_else(|_| "33".into());
    logln!("[CMP] security target = {sec}-bit");

    // ── 4 leaves -> 2 leaf_to_mv (real mv-root) for the REAL Layer-1 measure.
    logln!("[CMP] producing 4 shield leaves ...");
    let t = Instant::now();
    let leaves: Vec<LeafArtifacts> = (0..4).map(|_| one_shield_leaf()).collect();
    logln!("[CMP] 4 leaves in {:?}", t.elapsed());

    let leaf_pp = leaves[0].preprocessed_circuit.clone();
    let leaf_cfg = leaves[0].circuit_pcs_config;
    let ctx = AggregationContext::new(leaf_pp, leaf_cfg).expect("ctx");

    let mut it = leaves.into_iter();
    let mk = |l: LeafArtifacts| AggregationNode {
        proof: l.circuit_proof, shape: AggregationShape::Leaf, component_log_sizes: None,
    };
    let m0 = aggregate_pair(&ctx, mk(it.next().unwrap()), mk(it.next().unwrap())).expect("m0");
    let m1 = aggregate_pair(&ctx, mk(it.next().unwrap()), mk(it.next().unwrap())).expect("m1");

    // ── REAL LAYER 1: outer Poseidon2-M31 over two leaf_to_mv proofs.
    logln!("[CMP] LAYER 1 (real): outer Poseidon2-M31 over (leaf_to_mv, leaf_to_mv) ...");
    let t = Instant::now();
    let (layer1, _v1) = aggregate_pair_outer_with_channel::<Poseidon2M31MerkleChannel>(
        &ctx, m0.proof, m1.proof,
    ).expect("layer1 prove");
    let layer1_ms = t.elapsed();
    logln!("[CMP] LAYER 1 PROVE @{sec}-bit: {:?}", layer1_ms);
    report_shape("LAYER 1 (Poseidon2-M31, verifies leaf_to_mv)", &layer1);
    let t = Instant::now();
    stwo_verify_outer::<Poseidon2M31MerkleChannel>(layer1, &ctx.mv_to_mv_preprocessed)
        .expect("layer1 verify");
    logln!("[CMP] LAYER 1 verify in {:?}", t.elapsed());

    // ── SHAPE LADDER (cheap, no proving): iterate the node-verifying-previous-shape.
    //    Seed = leaf_to_mv node preprocessed. Each step builds the multiverifier
    //    node that verifies a proof of the previous node's shape.
    logln!("[CMP] ── recursion shape ladder @{sec}-bit (no proving) ──");
    let base = base_internal_pcs();
    let (l0t, l0c) = shape(&ctx.leaf_to_mv_preprocessed);
    logln!("[CMP] level 1  leaf_to_mv      : trace_log_size={l0t}  n_preproc_cols={l0c}");

    let mut inner_pp: Arc<PreprocessedCircuit> = ctx.leaf_to_mv_preprocessed.clone();
    let mut prev = shape(&inner_pp);
    let mut converged_at = None;
    for level in 2..=8u32 {
        let (_cfg, node_pp) =
            AggregationContext::mv_node_for_inner_shape(&inner_pp, base).expect("ladder step");
        let cur = shape(&node_pp);
        logln!(
            "[CMP] level {level}  node-verifies-prev: trace_log_size={}  n_preproc_cols={}  (prev was {:?})",
            cur.0, cur.1, prev
        );
        if cur == prev {
            converged_at = Some((level, cur));
            logln!("[CMP] >>> FIXED POINT reached at level {level}: shape {cur:?} (node-verifying-S has shape S)");
            break;
        }
        prev = cur;
        inner_pp = node_pp;
    }
    if converged_at.is_none() {
        logln!("[CMP] >>> NO fixed point within 8 levels — ladder still growing (last shape {prev:?})");
    }

    logln!("[CMP] DONE @{sec}-bit — total wall {:?}", t_all.elapsed());
}
