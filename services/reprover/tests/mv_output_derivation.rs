//! Golden-vector capture + off-circuit validation of the multiverifier
//! `output_values` derivation (Option E mv-mode, kernel-side binding).
//!
//! Upstream (stwo-circuits rev 2bf051f,
//! `crates/circuit_multiverifier/src/verify.rs:64-96`), every mv node's 2
//! reserved outputs are:
//!
//! ```text
//! parent.output_values = blake_qm31(
//!     [rootL.0, rootL.1, ovL.0, ovL.1, rootR.0, rootR.1, ovR.0, ovR.1],
//!     16 * 8,                                  // 128 bytes, full QM31 chunks
//! )
//! ```
//!
//! where `rootX` is the child's preprocessed root (`HashValue<QM31>`) and
//! `ovX` its 2 claim output values, each QM31 framed as 4 u32 LE lanes
//! (`crates/circuits/src/blake.rs:47-54` `to_bytes`), the digest being
//! standard blake2s-256 reduced lane-wise to M31
//! (`blake.rs:67-85` `blake_qm31` + stwo `core/vcs/blake2_hash.rs:111`).
//!
//! This test rebuilds the exact 4-leaf tree of `export_mv_fixture.rs`
//! (2 shield + 2 transfer), and at EVERY aggregation pair (2× leaf_to_mv +
//! 1× mv_to_mv root) asserts the off-circuit re-derivation above equals the
//! parent proof's `claim.output_values`. It then dumps the captured publics
//! to `/tmp/tzel-mv-fixture/mv_root_children.json` — the golden data the
//! kernel-side `tzel-verifier` checks into `verifier/testdata/`.
//!
//! Heavy (~6 min). `#[ignore]`. Run from `services/reprover`:
//! `cargo test --release --test mv_output_derivation -- --ignored --nocapture`

use std::path::PathBuf;

use circuits::blake::{HashValue, blake_qm31};
use serde_json::json;
use stwo::core::fields::qm31::QM31;
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

fn one_leaf(exe: &str, args: &str) -> LeafArtifacts {
    let exe_path = fixture(exe);
    let args_path = args_fixture(args);
    let (prover_input, output_preimage) =
        run_privacy_bootloader(&exe_path, None, Some(args_path)).expect("bootloader");
    produce_leaf_artifacts(prover_input, output_preimage).expect("leaf")
}

/// The public data of an aggregation node that enters its PARENT's
/// output hash: preprocessed root (first commitment) + claim outputs.
#[derive(Clone, Debug)]
struct NodePublics {
    preprocessed_root: HashValue<QM31>,
    output_values: [QM31; 2],
}

fn node_publics(node: &AggregationNode) -> NodePublics {
    let preprocessed_root: HashValue<QM31> =
        node.proof.stark_proof.proof.commitments.0[0].into();
    let output_values: [QM31; 2] = node
        .proof
        .claim
        .output_values
        .as_slice()
        .try_into()
        .expect("aggregation node must have exactly 2 claim output values");
    NodePublics {
        preprocessed_root,
        output_values,
    }
}

fn qm31_lanes(q: &QM31) -> [u32; 4] {
    q.to_m31_array().map(|m| m.0)
}

fn lanes8(root: &HashValue<QM31>) -> [u32; 8] {
    let a = qm31_lanes(&root.0);
    let b = qm31_lanes(&root.1);
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

fn ov_lanes8(ov: &[QM31; 2]) -> [u32; 8] {
    let a = qm31_lanes(&ov[0]);
    let b = qm31_lanes(&ov[1]);
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

/// Off-circuit re-derivation of `circuit_multiverifier`'s output hash:
/// blake_qm31 over [rootL ‖ ovL ‖ rootR ‖ ovR] (8 QM31s, 128 bytes).
fn derive_parent_output_values(left: &NodePublics, right: &NodePublics) -> [QM31; 2] {
    let mut preimage: Vec<QM31> = Vec::with_capacity(8);
    for child in [left, right] {
        preimage.push(child.preprocessed_root.0);
        preimage.push(child.preprocessed_root.1);
        preimage.extend_from_slice(&child.output_values);
    }
    assert_eq!(preimage.len(), 8);
    let h = blake_qm31(&preimage, 16 * preimage.len());
    [h.0, h.1]
}

fn check_and_capture(
    label: &str,
    left: &NodePublics,
    right: &NodePublics,
    parent: &NodePublics,
) -> serde_json::Value {
    let derived = derive_parent_output_values(left, right);
    assert_eq!(
        derived, parent.output_values,
        "[{label}] off-circuit blake_qm31(rootL ‖ ovL ‖ rootR ‖ ovR) must equal \
         the parent's claim.output_values"
    );
    eprintln!(
        "[MV-DERIVE] {label}: derivation CONFIRMED, parent ov lanes = {:?}",
        ov_lanes8(&parent.output_values)
    );
    json!({
        "label": label,
        "left": {
            "preprocessed_root_lanes": lanes8(&left.preprocessed_root),
            "output_lanes": ov_lanes8(&left.output_values),
        },
        "right": {
            "preprocessed_root_lanes": lanes8(&right.preprocessed_root),
            "output_lanes": ov_lanes8(&right.output_values),
        },
        "parent_preprocessed_root_lanes": lanes8(&parent.preprocessed_root),
        "parent_output_lanes": ov_lanes8(&parent.output_values),
    })
}

#[test]
#[ignore]
fn mv_output_values_derive_from_children() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let out_dir = PathBuf::from("/tmp/tzel-mv-fixture");
    std::fs::create_dir_all(&out_dir).expect("mkdir out_dir");

    // Same 4 leaves as export_mv_fixture.rs — the tree whose root the
    // 2026-06-10 gnark mv-target proof (verifier/testdata/proof.bin) wraps.
    eprintln!("[MV-DERIVE] generating 2 shield + 2 transfer leaves …");
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
        eprintln!("[MV-DERIVE]   {} in {:?}", label, t.elapsed());
        leaf
    })
    .collect();
    eprintln!("[MV-DERIVE] 4 leaves in {:?}", t0.elapsed());

    let leaf_preprocessed = leaves[0].preprocessed_circuit.clone();
    let leaf_pcs_config = leaves[0].circuit_pcs_config;
    let ctx = AggregationContext::new(leaf_preprocessed, leaf_pcs_config).expect("ctx");

    let mut nodes: Vec<AggregationNode> = leaves
        .into_iter()
        .map(|l| AggregationNode {
            proof: l.circuit_proof,
            shape: AggregationShape::Leaf,
        })
        .collect();

    // Level 0 → 1 (leaf_to_mv ×2), capturing publics before consumption.
    let leaf_publics: Vec<NodePublics> = nodes.iter().map(node_publics).collect();
    let mut it = nodes.drain(..);
    let (l0, l1, l2, l3) = (
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
    );
    drop(it);

    eprintln!("[MV-DERIVE] aggregating level 0 → 1 …");
    let mv0 = aggregate_pair(&ctx, l0, l1).expect("leaf_to_mv pair 0");
    let mv1 = aggregate_pair(&ctx, l2, l3).expect("leaf_to_mv pair 1");
    let mv0_publics = node_publics(&mv0);
    let mv1_publics = node_publics(&mv1);

    let node0_json =
        check_and_capture("leaf_to_mv_0", &leaf_publics[0], &leaf_publics[1], &mv0_publics);
    let node1_json =
        check_and_capture("leaf_to_mv_1", &leaf_publics[2], &leaf_publics[3], &mv1_publics);

    // Level 1 → root (mv_to_mv) — the node the gnark chip wraps.
    eprintln!("[MV-DERIVE] aggregating level 1 → root …");
    let root = aggregate_pair(&ctx, mv0, mv1).expect("mv_to_mv root");
    assert_eq!(root.shape, AggregationShape::Internal);
    let root_publics = node_publics(&root);

    let root_json =
        check_and_capture("mv_to_mv_root", &mv0_publics, &mv1_publics, &root_publics);

    // Dump the golden vectors (kernel-side tzel-verifier checks the root
    // node's entry into verifier/testdata/mv_root_children.json).
    let doc = json!({
        "comment": "Captured by services/reprover/tests/mv_output_derivation.rs on the \
                    export_mv_fixture tree (2 shield + 2 transfer leaves). Every node's \
                    parent_output_lanes == blake_qm31(left.root ‖ left.ov ‖ right.root ‖ \
                    right.ov) was asserted off-circuit during capture.",
        "nodes": [node0_json, node1_json, root_json],
    });
    let out_path = out_dir.join("mv_root_children.json");
    std::fs::write(&out_path, serde_json::to_string_pretty(&doc).unwrap())
        .expect("write mv_root_children.json");
    eprintln!("[MV-DERIVE] wrote {}", out_path.display());
    eprintln!("[MV-DERIVE] total wall {:?}", t0.elapsed());
}
