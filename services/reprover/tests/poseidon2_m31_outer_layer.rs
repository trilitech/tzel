//! SPIKE (item-b) — REAL Poseidon2-M31 recursion layer over a real tzel mv-root.
//!
//! Clone of `bn254_outer_layer.rs`, swapping the OUTER Merkle channel from
//! `Poseidon2Bn254MerkleChannel` to `Poseidon2M31MerkleChannel` (the
//! node-class-fast fast-field hash). Pipeline:
//!   1. 4 real shield leaf proofs (Blake2sM31 Cairo-verifier leaves).
//!   2. `aggregate_pair(leaf,leaf)` x2 -> two real `Internal`-shape mv inner
//!      proofs (the real tzel mv-root, still Blake2sM31).
//!   3. OUTER recursion layer: multiverifier AIR verifying the two real mv
//!      inner proofs, PROVED + COMMITTED over `Poseidon2M31MerkleChannel`.
//!   4. VERIFY the outer Poseidon2-M31 proof round-trip via the stwo verifier.
//!
//! Security: set `TZEL_SEC=96` for the production 96-bit outer FRI config.
//!
//! Run:
//! ```bash
//! cd services/reprover
//! TZEL_SEC=96 RAYON_NUM_THREADS=22 cargo test --release \
//!   --test poseidon2_m31_outer_layer -- --ignored --nocapture
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

const RESULT_FILE: &str = "/tmp/p2m31_spike_result.txt";

macro_rules! logln {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        let _ = std::io::stderr().flush();
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(RESULT_FILE)
        {
            let _ = writeln!(f, $($arg)*);
            let _ = f.flush();
        }
    }};
}

use stwo::core::vcs_lifted::poseidon2_m31_merkle::Poseidon2M31MerkleChannel;
use tzel_reprover::aggregate::{
    AggregationContext, AggregationNode, AggregationShape, aggregate_pair,
    aggregate_pair_outer_with_channel, stwo_verify_outer,
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

fn one_shield_leaf() -> LeafArtifacts {
    let exe = fixture("run_shield.executable.json");
    let args = args_fixture("run_shield_args.json");
    assert!(exe.exists(), "missing fixture {}", exe.display());
    let (prover_input, output_preimage) =
        run_privacy_bootloader(&exe, None, Some(args)).expect("bootloader");
    produce_leaf_artifacts(prover_input, output_preimage).expect("leaf")
}

#[test]
#[ignore]
fn poseidon2_m31_outer_layer_over_real_mv_root() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let _ = std::fs::write(RESULT_FILE, b"");
    let t_all = Instant::now();

    let sec = std::env::var("TZEL_SEC").unwrap_or_else(|_| "33".into());
    logln!("[P2M31] OUTER security target = {sec}-bit");

    // 4 real leaf proofs.
    logln!("[P2M31] producing 4 shield leaves ...");
    let t = Instant::now();
    let leaves: Vec<LeafArtifacts> = (0..4).map(|_| one_shield_leaf()).collect();
    logln!("[P2M31] 4 leaves in {:?}", t.elapsed());

    let leaf_pp = leaves[0].preprocessed_circuit.clone();
    let leaf_cfg = leaves[0].circuit_pcs_config;
    let ctx = AggregationContext::new(leaf_pp, leaf_cfg).expect("ctx");

    let mut it = leaves.into_iter();
    let mk_node = |l: LeafArtifacts| AggregationNode {
        proof: l.circuit_proof,
        shape: AggregationShape::Leaf,
        component_log_sizes: None,
    };

    // 2 real mv inner proofs.
    logln!("[P2M31] aggregate (leaf,leaf) -> mv inner #1 ...");
    let t = Instant::now();
    let mv_a = aggregate_pair(&ctx, mk_node(it.next().unwrap()), mk_node(it.next().unwrap()))
        .expect("mv inner #1");
    logln!("[P2M31] mv inner #1 in {:?}", t.elapsed());
    assert_eq!(mv_a.shape, AggregationShape::Internal);

    logln!("[P2M31] aggregate (leaf,leaf) -> mv inner #2 ...");
    let t = Instant::now();
    let mv_b = aggregate_pair(&ctx, mk_node(it.next().unwrap()), mk_node(it.next().unwrap()))
        .expect("mv inner #2");
    logln!("[P2M31] mv inner #2 in {:?}", t.elapsed());
    assert_eq!(mv_b.shape, AggregationShape::Internal);

    // OUTER recursion layer over Poseidon2-M31.
    logln!("[P2M31] proving OUTER multiverifier layer over Poseidon2-M31 channel ...");
    let t = Instant::now();
    let (outer_proof, _outer_values) =
        aggregate_pair_outer_with_channel::<Poseidon2M31MerkleChannel>(
            &ctx, mv_a.proof, mv_b.proof,
        )
        .expect("outer Poseidon2-M31 prove");
    let outer_prove = t.elapsed();
    logln!("[P2M31] OUTER Poseidon2-M31 PROVE wall-clock: {:?}", outer_prove);

    let sp = &outer_proof.stark_proof.proof;
    logln!(
        "[P2M31] outer proof: {} commitments, {} sampled trees, pcs_config = {:?}",
        sp.commitments.0.len(),
        sp.sampled_values.0.len(),
        outer_proof.pcs_config,
    );

    // VERIFY round-trip.
    logln!("[P2M31] verifying OUTER Poseidon2-M31 proof via stwo verifier ...");
    let t = Instant::now();
    stwo_verify_outer::<Poseidon2M31MerkleChannel>(outer_proof, &ctx.mv_to_mv_preprocessed)
        .expect("outer Poseidon2-M31 verify");
    logln!("[P2M31] OUTER Poseidon2-M31 verify in {:?}", t.elapsed());

    logln!(
        "[P2M31] PASS - real multiverifier AIR over real mv-root, OUTER proof \
         committed+transcripted over Poseidon2-M31 @{sec}-bit, verified round-trip. \
         (outer prove {:?}, total wall {:?})",
        outer_prove,
        t_all.elapsed()
    );
}
