//! SPIKE (item-d) — first REAL BN254-native recursion layer.
//!
//! Pipeline:
//!   1. Produce 2 real shield leaf proofs (Blake2sM31-committed circuit_verifier
//!      / Cairo-verifier leaves).
//!   2. `aggregate_pair(leaf, leaf)` → a REAL `leaf_to_mv` multiverifier proof
//!      (still Blake2sM31-committed). Do this TWICE so we have two distinct
//!      `Internal`-shape inner proofs — the genuine "mv-root" inner proofs the
//!      outer layer will verify.
//!   3. OUTER recursion layer: build the multiverifier AIR that VERIFIES those
//!      two real mv inner proofs, but PROVE + COMMIT the outer proof with
//!      `Poseidon2Bn254MerkleChannel` + `Bn254Channel` (the inner proofs stay
//!      Blake2sM31). This is the real field-change step.
//!   4. VERIFY the outer BN254 proof end-to-end via the stwo STARK verifier
//!      over the BN254 channel (round-trip).
//!
//! This is the real `circuit_verifier`/multiverifier AIR over a REAL inner
//! proof — NOT the arbitrary-M31-trace PoC of step 4. Heavy (~4 leaf proves +
//! 2 inner mv proves + 1 outer prove). `#[ignore]`.
//!
//! Run:
//! ```bash
//! cd services/reprover
//! cargo test --release --test bn254_outer_layer -- --ignored --nocapture
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

/// Print + flush stderr so progress survives even if the process is killed
/// mid-run (eprintln alone can sit in a buffer).
const RESULT_FILE: &str = "/tmp/bn254_spike_result.txt";

/// Print + flush stderr AND append to a durable result file, so progress
/// survives even if the process is killed mid-run (eprintln alone can sit in a
/// buffer; the result file is the source of truth).
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

use stwo::core::vcs_lifted::poseidon2_bn254_merkle::Poseidon2Bn254MerkleChannel;
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
fn bn254_outer_layer_over_real_mv_root() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let _ = std::fs::write(RESULT_FILE, b""); // truncate result file
    let t_all = Instant::now();

    // ── 4 real leaf proofs (Blake2sM31). ─────────────────────────────────
    logln!("[BN254] producing 4 shield leaves …");
    let t = Instant::now();
    let leaves: Vec<LeafArtifacts> = (0..4).map(|_| one_shield_leaf()).collect();
    logln!("[BN254] 4 leaves in {:?}", t.elapsed());

    let leaf_pp = leaves[0].preprocessed_circuit.clone();
    let leaf_cfg = leaves[0].circuit_pcs_config;
    let ctx = AggregationContext::new(leaf_pp, leaf_cfg).expect("ctx");

    let mut it = leaves.into_iter();
    let mk_node = |l: LeafArtifacts| AggregationNode {
        proof: l.circuit_proof,
        shape: AggregationShape::Leaf,
        component_log_sizes: None,
    };

    // ── 2 real mv inner proofs (leaf_to_mv, still Blake2sM31). ────────────
    logln!("[BN254] aggregate (leaf,leaf) → mv inner #1 …");
    let t = Instant::now();
    let mv_a = aggregate_pair(&ctx, mk_node(it.next().unwrap()), mk_node(it.next().unwrap()))
        .expect("mv inner #1");
    logln!("[BN254] mv inner #1 in {:?}", t.elapsed());
    assert_eq!(mv_a.shape, AggregationShape::Internal);

    logln!("[BN254] aggregate (leaf,leaf) → mv inner #2 …");
    let t = Instant::now();
    let mv_b = aggregate_pair(&ctx, mk_node(it.next().unwrap()), mk_node(it.next().unwrap()))
        .expect("mv inner #2");
    logln!("[BN254] mv inner #2 in {:?}", t.elapsed());
    assert_eq!(mv_b.shape, AggregationShape::Internal);

    // ── OUTER recursion layer: verify the 2 real mv inner proofs inside a
    //    multiverifier AIR, but commit/transcript the OUTER proof over BN254.
    logln!("[BN254] proving OUTER multiverifier layer over BN254 channel …");
    let t = Instant::now();
    let (outer_proof, _outer_values) =
        aggregate_pair_outer_with_channel::<Poseidon2Bn254MerkleChannel>(
            &ctx, mv_a.proof, mv_b.proof,
        )
        .expect("outer BN254 prove");
    let outer_prove_ms = t.elapsed();
    logln!("[BN254] OUTER BN254 proof produced in {:?}", outer_prove_ms);

    // Rough size of the outer BN254 proof (serialize the stark_proof via bincode-ish
    // debug fallback: use the serialized circuit proof bytes if available; here we
    // approximate via the number of commitments / sampled trees, and the FRI layers).
    let sp = &outer_proof.stark_proof.proof;
    logln!(
        "[BN254] outer proof: {} commitments, {} sampled trees, pcs_config = {:?}",
        sp.commitments.0.len(),
        sp.sampled_values.0.len(),
        outer_proof.pcs_config,
    );

    // ── VERIFY the outer BN254 proof (round-trip). ───────────────────────
    logln!("[BN254] verifying OUTER BN254 proof via stwo STARK verifier …");
    let t = Instant::now();
    stwo_verify_outer::<Poseidon2Bn254MerkleChannel>(outer_proof, &ctx.mv_to_mv_preprocessed)
        .expect("outer BN254 verify");
    logln!("[BN254] OUTER BN254 verify in {:?}", t.elapsed());

    logln!(
        "[BN254] ✓ PASS — real multiverifier AIR over real mv-root, OUTER proof \
         committed+transcripted over Poseidon2-BN254, verified round-trip. \
         (outer prove {:?}, total wall {:?})",
        outer_prove_ms,
        t_all.elapsed()
    );
}
