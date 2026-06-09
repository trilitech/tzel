//! Dump multiverifier proof empirical data — produces 1 leaf, aggregates with
//! itself, then dumps the resulting mv proof's shape data needed for the chip
//! rebuild.
//!
//! Two passes:
//!   - leaf_to_mv = aggregate_pair(leaf, leaf_copy) → mv proof at "internal" shape
//!   - mv_to_mv = aggregate_pair(leaf_to_mv, leaf_to_mv_copy) → mv proof at "internal" shape
//!
//! We DUMP the mv_to_mv proof since that's the canonical "root" shape the
//! chip would target.
//!
//! Heavy (~3-4 min). `#[ignore]`.

use std::path::PathBuf;

use tzel_reprover::aggregate::{
    AggregationContext, AggregationNode, AggregationShape, aggregate_pair,
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

#[test]
#[ignore]
fn dump_mv_proof_shape() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    eprintln!("[DUMP-MV] producing 1 shield leaf …");
    let t0 = std::time::Instant::now();
    let exe = fixture("run_shield.executable.json");
    let args = args_fixture("run_shield_args.json");
    let (prover_input, output_preimage) =
        run_privacy_bootloader(&exe, None, Some(args)).expect("bootloader");
    let leaf_a: LeafArtifacts = produce_leaf_artifacts(prover_input, output_preimage).expect("leaf a");
    eprintln!("[DUMP-MV] leaf #1 done in {:?}", t0.elapsed());

    // Second leaf — we need a DIFFERENT proof object (can't reuse one, the
    // aggregate_pair consumes it). Re-prove from the same fixture.
    let t1 = std::time::Instant::now();
    eprintln!("[DUMP-MV] producing 2nd shield leaf …");
    let exe = fixture("run_shield.executable.json");
    let args = args_fixture("run_shield_args.json");
    let (prover_input, output_preimage) =
        run_privacy_bootloader(&exe, None, Some(args)).expect("bootloader");
    let leaf_b: LeafArtifacts = produce_leaf_artifacts(prover_input, output_preimage).expect("leaf b");
    eprintln!("[DUMP-MV] leaf #2 done in {:?}", t1.elapsed());

    let leaf_pp = leaf_a.preprocessed_circuit.clone();
    let leaf_cfg = leaf_a.circuit_pcs_config;
    let ctx = AggregationContext::new(leaf_pp, leaf_cfg).expect("ctx");
    eprintln!("[DUMP-MV] AggregationContext ready");

    let nodes = vec![
        AggregationNode { proof: leaf_a.circuit_proof, shape: AggregationShape::Leaf },
        AggregationNode { proof: leaf_b.circuit_proof, shape: AggregationShape::Leaf },
    ];

    // First level: 2 leaves → 1 leaf_to_mv proof
    let t_agg = std::time::Instant::now();
    eprintln!("[DUMP-MV] aggregate (leaf, leaf) → leaf_to_mv …");
    let mut it = nodes.into_iter();
    let l = it.next().unwrap();
    let r = it.next().unwrap();
    let mv_l = aggregate_pair(&ctx, l, r).expect("aggregate level 1");
    eprintln!("[DUMP-MV] leaf_to_mv done in {:?}", t_agg.elapsed());

    eprintln!("\n[DUMP-MV] ── leaf_to_mv proof shape ──");
    dump_proof(&mv_l.proof, "leaf_to_mv");

    eprintln!("\n[DUMP-MV] total wall time = {:?}", t0.elapsed());
    eprintln!("[DUMP-MV] (mv_to_mv proof requires 4 leaves — see aggregation_e2e test for that)");
}

fn dump_proof(
    proof: &circuit_verifier::circuit_proof::CircuitProof<
        stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher,
    >,
    label: &str,
) {
    eprintln!("[DUMP-MV] {} proof:", label);
    eprintln!("[DUMP-MV]   pcs_config = {:?}", proof.pcs_config);
    eprintln!(
        "[DUMP-MV]   claim.output_values.len() = {}",
        proof.claim.output_values.len()
    );
    eprintln!(
        "[DUMP-MV]   claim.output_values = {:?}",
        proof.claim.output_values
    );
    eprintln!(
        "[DUMP-MV]   interaction_pow_nonce = {}",
        proof.interaction_pow_nonce
    );
    eprintln!("[DUMP-MV]   channel_salt = {}", proof.channel_salt);
    // stark_proof.proof has the commitment roots + queries data
    let sp = &proof.stark_proof.proof;
    eprintln!(
        "[DUMP-MV]   stark_proof.commitments[0..n] = {} entries",
        sp.commitments.0.len()
    );
    eprintln!(
        "[DUMP-MV]   stark_proof.sampled_values trees = {}",
        sp.sampled_values.0.len()
    );
    for (i, tree) in sp.sampled_values.0.iter().enumerate() {
        eprintln!(
            "[DUMP-MV]     tree[{}] has {} columns",
            i,
            tree.len()
        );
    }
}
