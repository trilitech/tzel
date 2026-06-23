//! item-D binding-fixture capture: the OUTER bn254 statement's two children
//! publics + the 4 shield-leaf preimages.
//!
//! The `/tmp/wrap-ceremony` gnark wrap (and `verifier/testdata/proof.bin`)
//! wraps the OUTER multiverifier layer of the `l2_proof_bn254` fixture:
//!
//! ```text
//! 4 shield leaves → 2 leaf_to_mv inner proofs (mv_a, mv_b) → OUTER (mv_to_mv)
//! ```
//!
//! This harness rebuilds EXACTLY that tree (same 4 shield leaves as
//! `export_bn254_fixture.rs`), captures:
//!   * the 4 leaf publics + their bootloader `output_preimage`s,
//!   * the leaf circuit preprocessed root,
//!   * the 2 leaf_to_mv (mv_a, mv_b) publics — the OUTER's two children,
//!   * the leaf_to_mv preprocessed root (level-1 internal root),
//! and asserts at every level that
//! `blake_qm31(rootL ‖ ovL ‖ rootR ‖ ovR) == parent.output_values`
//! (off-circuit `circuit_multiverifier` derivation).
//!
//! Crucially, it cross-checks the OUTER node's derived `output_values`
//! against the GROUND-TRUTH `output_values_qm31s` in
//! `l2_proof_bn254.shape.json` (the values the proven OUTER claim — and thus
//! the gnark wrap's Poseidon2 OutHash — was built from). The leaf_to_mv
//! children are Blake2sM31 inner proofs (NOT the heavy BN254 OUTER prove), so
//! this is the ~6-min-per-pair derivation path, not the >1h OUTER prove.
//!
//! Dumps `/tmp/tzel-bn254-fixture/{mv_root_children.json, leaf_junction.json}`
//! — the item-D analogues of `verifier/testdata/{mv_root_children,
//! leaf_junction}.json`, to be checked into `tzel/verifier/testdata/`.
//!
//! `#[ignore]`. Run from `services/reprover`:
//! `cargo test --release --test export_bn254_children -- --ignored --nocapture`

use std::path::PathBuf;

use circuits::blake::{HashValue, blake_qm31};
use serde_json::json;
use starknet_types_core::felt::Felt;
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

/// One shield leaf + its bootloader output preimage (the leaf↔mv junction
/// input the kernel re-derives publics from).
fn one_shield_leaf() -> (LeafArtifacts, Vec<Felt>) {
    let exe = fixture("run_shield.executable.json");
    let args = args_fixture("run_shield_args.json");
    let (prover_input, output_preimage) =
        run_privacy_bootloader(&exe, None, Some(args)).expect("bootloader");
    let preimage = output_preimage.clone();
    let leaf = produce_leaf_artifacts(prover_input, output_preimage).expect("leaf");
    (leaf, preimage)
}

#[derive(Clone, Debug)]
struct NodePublics {
    preprocessed_root: HashValue<QM31>,
    output_values: [QM31; 2],
}

fn node_publics(node: &AggregationNode) -> NodePublics {
    let preprocessed_root: HashValue<QM31> = node.proof.stark_proof.proof.commitments.0[0].into();
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

fn derive_parent_output_values(left: &NodePublics, right: &NodePublics) -> [QM31; 2] {
    let mut preimage: Vec<QM31> = Vec::with_capacity(8);
    for child in [left, right] {
        preimage.push(child.preprocessed_root.0);
        preimage.push(child.preprocessed_root.1);
        preimage.extend_from_slice(&child.output_values);
    }
    let h = blake_qm31(&preimage, 16 * preimage.len());
    [h.0, h.1]
}

fn check_capture(
    label: &str,
    left: &NodePublics,
    right: &NodePublics,
    parent: &NodePublics,
) -> serde_json::Value {
    let derived = derive_parent_output_values(left, right);
    assert_eq!(
        derived, parent.output_values,
        "[{label}] blake_qm31(rootL ‖ ovL ‖ rootR ‖ ovR) must equal parent.output_values"
    );
    eprintln!("[EXPORT-CH] {label}: fold CONFIRMED, parent ov = {:?}", ov_lanes8(&parent.output_values));
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
fn export_bn254_children() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let out_dir = PathBuf::from("/tmp/tzel-bn254-fixture");
    std::fs::create_dir_all(&out_dir).expect("mkdir out_dir");
    let t0 = std::time::Instant::now();

    // The OUTER `output_values_qm31s` ground truth (from the shape sidecar).
    // Hardcoded from l2_proof_bn254.shape.json so the harness is self-checking.
    let outer_ground_truth_ov: [[u32; 4]; 2] = [
        [1482205925, 1224080734, 422000347, 770043551],
        [1470588146, 716900524, 273334556, 347170781],
    ];

    eprintln!("[EXPORT-CH] producing 4 shield leaves …");
    let mut leaf_artifacts = Vec::new();
    let mut leaf_preimages: Vec<Vec<Felt>> = Vec::new();
    for i in 0..4 {
        let t = std::time::Instant::now();
        let (leaf, preimage) = one_shield_leaf();
        eprintln!("[EXPORT-CH]   shield leaf {i} in {:?}", t.elapsed());
        leaf_artifacts.push(leaf);
        leaf_preimages.push(preimage);
    }

    let leaf_preprocessed = leaf_artifacts[0].preprocessed_circuit.clone();
    let leaf_pcs_config = leaf_artifacts[0].circuit_pcs_config;
    let ctx = AggregationContext::new(leaf_preprocessed, leaf_pcs_config).expect("ctx");

    let nodes: Vec<AggregationNode> = leaf_artifacts
        .into_iter()
        .map(|l| AggregationNode {
            proof: l.circuit_proof,
            shape: AggregationShape::Leaf,
            component_log_sizes: None,
        })
        .collect();
    let leaf_publics: Vec<NodePublics> = nodes.iter().map(node_publics).collect();

    let mut it = nodes.into_iter();
    let (l0, l1, l2, l3) = (
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
    );

    eprintln!("[EXPORT-CH] aggregating leaf_to_mv pair 0 (mv_a) …");
    let mv_a = aggregate_pair(&ctx, l0, l1).expect("leaf_to_mv pair 0");
    eprintln!("[EXPORT-CH] aggregating leaf_to_mv pair 1 (mv_b) …");
    let mv_b = aggregate_pair(&ctx, l2, l3).expect("leaf_to_mv pair 1");
    let mv_a_publics = node_publics(&mv_a);
    let mv_b_publics = node_publics(&mv_b);

    let node0_json = check_capture("leaf_to_mv_0", &leaf_publics[0], &leaf_publics[1], &mv_a_publics);
    let node1_json = check_capture("leaf_to_mv_1", &leaf_publics[2], &leaf_publics[3], &mv_b_publics);

    // OUTER fold (off-circuit): the OUTER claim.output_values is
    // blake_qm31(mv_a ‖ mv_b). Cross-check against the proven OUTER ground
    // truth from the shape sidecar — this is what the gnark Poseidon2 OutHash
    // was built from.
    let outer_derived = derive_parent_output_values(&mv_a_publics, &mv_b_publics);
    let outer_derived_lanes = ov_lanes8(&outer_derived);
    let gt_lanes: [u32; 8] = {
        let mut a = [0u32; 8];
        a[..4].copy_from_slice(&outer_ground_truth_ov[0]);
        a[4..].copy_from_slice(&outer_ground_truth_ov[1]);
        a
    };
    eprintln!("[EXPORT-CH] OUTER derived ov = {:?}", outer_derived_lanes);
    eprintln!("[EXPORT-CH] OUTER ground-truth = {:?}", gt_lanes);
    assert_eq!(
        outer_derived_lanes, gt_lanes,
        "OUTER blake fold of (mv_a, mv_b) must equal the shape's output_values_qm31s — \
         this is the proof's bound claim outputs"
    );
    eprintln!("[EXPORT-CH] *** OUTER binding cross-check PASSED ***");

    // mv_root_children.json: the OUTER root's two children (mv_a, mv_b) and
    // the OUTER's own publics. parent_preprocessed_root_lanes is the OUTER
    // (bn254) preprocessed root — NOT captured here (it requires the heavy
    // OUTER bn254 prove); the kernel binds it from TreeRoots[0] of the proof.
    // We store the OUTER derived output_lanes (== ground truth) as
    // parent_output_lanes.
    let root_json = json!({
        "label": "mv_to_mv_root",
        "left": {
            "preprocessed_root_lanes": lanes8(&mv_a_publics.preprocessed_root),
            "output_lanes": ov_lanes8(&mv_a_publics.output_values),
        },
        "right": {
            "preprocessed_root_lanes": lanes8(&mv_b_publics.preprocessed_root),
            "output_lanes": ov_lanes8(&mv_b_publics.output_values),
        },
        "parent_output_lanes": gt_lanes,
        "note": "parent_preprocessed_root_lanes intentionally absent: the OUTER bn254 \
                 preprocessed root is bound from the gnark proof's TreeRoots[0], not captured here.",
    });

    let children_doc = json!({
        "comment": "item-D: OUTER bn254 statement = 4 shield leaves → 2 leaf_to_mv (mv_a, mv_b) \
                    → OUTER. leaf_to_mv children are Blake2sM31 inner proofs. \
                    parent_output_lanes of mv_to_mv_root == output_values_qm31s of \
                    l2_proof_bn254.shape.json (asserted in-harness against the proven OUTER claim).",
        "nodes": [node0_json, node1_json, root_json],
    });
    let p = out_dir.join("mv_root_children.json");
    std::fs::write(&p, serde_json::to_string_pretty(&children_doc).unwrap()).expect("write children");
    eprintln!("[EXPORT-CH] wrote {}", p.display());

    // leaf_junction.json: each shield leaf's bootloader preimage (hex felts)
    // + the leaf's claim output lanes. The 4 leaves are identical shields, so
    // we emit ONE "shield" entry (the tree is [shield ×4]).
    let leaf_doc = json!({
        "comment": "item-D OUTER tree leaves: 4 identical shield leaves. Each leaf's \
                    output_preimage re-derives expected_leaf_output_lanes via the kernel \
                    junction chain (compute_leaf_output_lanes).",
        "leaves": [
            {
                "label": "shield",
                "output_preimage_hex": leaf_preimages[0]
                    .iter()
                    .map(|f| format!("{:#x}", f))
                    .collect::<Vec<_>>(),
                "expected_leaf_output_lanes": ov_lanes8(&leaf_publics[0].output_values),
            },
        ],
    });
    let p = out_dir.join("leaf_junction.json");
    std::fs::write(&p, serde_json::to_string_pretty(&leaf_doc).unwrap()).expect("write leaf_junction");
    eprintln!("[EXPORT-CH] wrote {}", p.display());
    eprintln!("[EXPORT-CH] DONE in {:?}", t0.elapsed());

    // Sanity: all 4 leaves identical (same shield exe+args) → same publics.
    for i in 1..4 {
        assert_eq!(
            ov_lanes8(&leaf_publics[i].output_values),
            ov_lanes8(&leaf_publics[0].output_values),
            "all 4 shield leaves must share output lanes"
        );
        assert_eq!(
            lanes8(&leaf_publics[i].preprocessed_root),
            lanes8(&leaf_publics[0].preprocessed_root),
            "all 4 shield leaves must share the leaf circuit root"
        );
    }
}
