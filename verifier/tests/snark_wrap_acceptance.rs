//! Acceptance tests for the Groth16 wrap verifier on the **mv-target**
//! artifacts (2026-06-10 cloud Setup+Prove cycle on the TzEL multiverifier
//! root proof — the production chip shape).
//!
//! Fixtures (`verifier/testdata/`):
//! * `proof.bin` / `vk.bin` — the real mv-target gnark artifacts (388 B /
//!   9680 B; gnark's own `groth16.Verify` PASSED on them, see
//!   gs://tezosx-snark-artifacts/2026-06-10-mv-target-setup/). The wrapped
//!   statement is a real TzEL multiverifier root proof aggregating
//!   2 shield + 2 transfer leaves. `vk.bin` is byte-identical to the
//!   embedded `src/wrap_vk.bin`.
//! * `wrap_public_witness.txt` — the 136 public inputs (128 TreeRoots
//!   bytes + 8 OutHash M31 lanes) dumped via gnark
//!   `frontend.NewWitness(..., PublicOnly())` from the mv fixture
//!   (stwo-gnark-tzel `TestDumpPublicWitness` helper).
//!
//! * `mv_root_children.json` — the mv root's two children (preprocessed
//!   root + claim output lanes each), captured during a deterministic
//!   re-run of the fixture aggregation by
//!   `services/reprover/tests/mv_output_derivation.rs` (which also asserts
//!   the off-circuit blake derivation at every tree node). These drive the
//!   POSITIVE `verify_snark_mv` happy path below: Groth16 PASS on the real
//!   proof **and** OutHash binding PASS through the mv derivation chain.
//! * `leaf_junction.json` — the leaf↔mv junction golden vectors (track W3,
//!   `docs/SNARK-SUBMISSION-DESIGN.md`): the REAL fixture leaves'
//!   bootloader `output_preimage`s + the leaf proofs' `claim.output_values`
//!   lanes, captured by `services/reprover/tests/leaf_junction_capture.rs`.
//!   These drive the junction golden tests and the POSITIVE
//!   `verify_snark_tree` happy path: declared leaves' preimages → tree walk
//!   → root publics → OutHash binding → Groth16, all against the real
//!   mv-target proof. The fixture aggregation tree is
//!   `[shield, shield, transfer, transfer]` (each leaf duplicated), depth 2.
//!
//! NOTE: the *leaf-mode* `verify_snark` happy path is still not exercised
//! here — the wrapped statement is an mv root, so there is no consistent
//! bootloader `output_preimage` for it; leaf mode stays pinned by golden
//! vectors in `src/snark.rs`. Its negative direction (valid Groth16, wrong
//! preimage -> reject at the binding step) IS exercised below.

use tzel_verifier::groth16::{
    parse_gnark_vk, verify_groth16_wrap, verify_groth16_wrap_with_vk, VerifyError, N_PUBLIC_INPUTS,
    WRAP_VK_BYTES,
};
use tzel_verifier::snark::{
    compute_leaf_output_lanes, derive_mv_root_publics, root_lanes_to_bytes, verify_snark,
    verify_snark_mv, verify_snark_tree, MvLeafSlot, MvNodePublics,
};

const PROOF_BIN: &[u8] = include_bytes!("../testdata/proof.bin");
const VK_BIN: &[u8] = include_bytes!("../testdata/vk.bin");
const PUBLIC_WITNESS_TXT: &str = include_str!("../testdata/wrap_public_witness.txt");
const MV_ROOT_CHILDREN_JSON: &str = include_str!("../testdata/mv_root_children.json");
const LEAF_JUNCTION_JSON: &str = include_str!("../testdata/leaf_junction.json");

fn lanes8(v: &serde_json::Value) -> [u32; 8] {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| u32::try_from(x.as_u64().unwrap()).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn mv_node(doc: &serde_json::Value, label: &str) -> serde_json::Value {
    doc["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["label"] == label)
        .unwrap_or_else(|| panic!("{label} node in mv_root_children.json"))
        .clone()
}

/// Parse the captured mv-root golden data: the root's two children plus the
/// root's expected `output_values` lanes.
fn fixture_mv_children() -> (MvNodePublics, MvNodePublics, [u32; 8]) {
    let doc: serde_json::Value = serde_json::from_str(MV_ROOT_CHILDREN_JSON).unwrap();
    let root_node = mv_node(&doc, "mv_to_mv_root");
    let child = |v: &serde_json::Value| MvNodePublics {
        preprocessed_root_lanes: lanes8(&v["preprocessed_root_lanes"]),
        output_lanes: lanes8(&v["output_lanes"]),
    };
    (
        child(&root_node["left"]),
        child(&root_node["right"]),
        lanes8(&root_node["parent_output_lanes"]),
    )
}

/// One captured leaf of `leaf_junction.json`: the op's bootloader
/// `output_preimage` (raw 32-byte LE felts, the kernel wire form) and the
/// REAL leaf proof's `claim.output_values` lanes.
struct JunctionLeaf {
    label: String,
    preimage_raw: Vec<[u8; 32]>,
    expected_lanes: [u32; 8],
}

fn fixture_junction_leaves() -> Vec<JunctionLeaf> {
    let doc: serde_json::Value = serde_json::from_str(LEAF_JUNCTION_JSON).unwrap();
    doc["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|leaf| JunctionLeaf {
            label: leaf["label"].as_str().unwrap().to_string(),
            preimage_raw: leaf["output_preimage_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    starknet_types_core::felt::Felt::from_hex(h.as_str().unwrap())
                        .expect("valid felt hex")
                        .to_bytes_le()
                })
                .collect(),
            expected_lanes: lanes8(&leaf["expected_leaf_output_lanes"]),
        })
        .collect()
}

/// The full fixture aggregation tree constants + golden root publics
/// (`mv_root_children.json`): leaf-circuit preprocessed root, per-level
/// internal preprocessed roots (bottom-up), and the root's expected publics.
struct FixtureTree {
    leaf_root_lanes: [u32; 8],
    internal_root_lanes: [[u32; 8]; 2],
    expected_root: MvNodePublics,
}

fn fixture_tree() -> FixtureTree {
    let doc: serde_json::Value = serde_json::from_str(MV_ROOT_CHILDREN_JSON).unwrap();
    let level1 = mv_node(&doc, "leaf_to_mv_0");
    let root = mv_node(&doc, "mv_to_mv_root");
    FixtureTree {
        leaf_root_lanes: lanes8(&level1["left"]["preprocessed_root_lanes"]),
        internal_root_lanes: [
            lanes8(&level1["parent_preprocessed_root_lanes"]),
            lanes8(&root["parent_preprocessed_root_lanes"]),
        ],
        expected_root: MvNodePublics {
            preprocessed_root_lanes: lanes8(&root["parent_preprocessed_root_lanes"]),
            output_lanes: lanes8(&root["parent_output_lanes"]),
        },
    }
}

/// The fixture tree's leaf slots, all DECLARED: `[shield, shield, transfer,
/// transfer]` (the aggregation duplicated each op, see
/// `mv_root_children.json` leaf_to_mv_0/_1 left == right).
fn all_declared_slots(leaves: &[JunctionLeaf]) -> Vec<MvLeafSlot<'_>> {
    let shield = leaves.iter().find(|l| l.label == "shield").unwrap();
    let transfer = leaves.iter().find(|l| l.label == "transfer").unwrap();
    vec![
        MvLeafSlot::Declared {
            output_preimage: &shield.preimage_raw,
        },
        MvLeafSlot::Declared {
            output_preimage: &shield.preimage_raw,
        },
        MvLeafSlot::Declared {
            output_preimage: &transfer.preimage_raw,
        },
        MvLeafSlot::Declared {
            output_preimage: &transfer.preimage_raw,
        },
    ]
}

/// Parse the dumped public witness (`<index> <decimal>` lines) into the
/// wrap circuit's (tree_roots, out_hash_lanes) public inputs.
fn fixture_publics() -> ([[u8; 32]; 4], [u32; 8]) {
    let vals: Vec<u64> = PUBLIC_WITNESS_TXT
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            l.split_whitespace()
                .nth(1)
                .expect("`<idx> <dec>` line")
                .parse()
                .expect("decimal")
        })
        .collect();
    assert_eq!(vals.len(), N_PUBLIC_INPUTS);

    let mut tree_roots = [[0u8; 32]; 4];
    for t in 0..4 {
        for b in 0..32 {
            let v = vals[t * 32 + b];
            assert!(v < 256, "TreeRoots entry must be a byte");
            tree_roots[t][b] = v as u8;
        }
    }
    let mut out_hash_lanes = [0u32; 8];
    for (i, lane) in out_hash_lanes.iter_mut().enumerate() {
        let v = vals[128 + i];
        assert!(v < (1 << 31), "OutHash lane must be M31");
        *lane = v as u32;
    }
    (tree_roots, out_hash_lanes)
}

/// Build the `verify_snark` wire envelope:
/// `tree_roots (4×32) ‖ out_hash lanes (8×u32 LE) ‖ gnark proof bytes`.
fn fixture_envelope(proof_tail: &[u8]) -> Vec<u8> {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    let mut bytes = Vec::with_capacity(160 + proof_tail.len());
    for root in &tree_roots {
        bytes.extend_from_slice(root);
    }
    for lane in &out_hash_lanes {
        bytes.extend_from_slice(&lane.to_le_bytes());
    }
    bytes.extend_from_slice(proof_tail);
    bytes
}

#[test]
fn embedded_vk_matches_testdata_vk() {
    // The embedded VK (mv-target, 2026-06-10 Setup) must be byte-identical
    // to the testdata VK.
    assert_eq!(WRAP_VK_BYTES, VK_BIN);
    parse_gnark_vk(WRAP_VK_BYTES).expect("embedded VK parses");
}

#[test]
fn accepts_real_mv_proof() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    verify_groth16_wrap(PROOF_BIN, &tree_roots, &out_hash_lanes)
        .expect("real mv-target proof must verify against the embedded VK");
}

#[test]
fn accepts_real_mv_proof_with_explicit_vk() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    verify_groth16_wrap_with_vk(PROOF_BIN, &tree_roots, &out_hash_lanes, VK_BIN)
        .expect("real mv-target proof must verify");
}

#[test]
fn rejects_bit_flipped_proof() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    let mut proof = PROOF_BIN.to_vec();
    // Flip a low bit of Ar.Y (offset 63 = last byte of Y_BE): the point
    // either falls off the curve (InvalidPoint) or breaks the pairing.
    proof[63] ^= 0x01;
    match verify_groth16_wrap(&proof, &tree_roots, &out_hash_lanes) {
        Err(_) => {}
        Ok(()) => panic!("bit-flipped proof must not verify"),
    }
}

#[test]
fn rejects_tampered_commitment() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    let mut proof = PROOF_BIN.to_vec();
    // Commitment starts after Ar(64) + Bs(128) + Krs(64) + u32 len(4) = 260.
    proof[260 + 63] ^= 0x01;
    match verify_groth16_wrap(&proof, &tree_roots, &out_hash_lanes) {
        Err(_) => {}
        Ok(()) => panic!("tampered commitment must not verify"),
    }
}

#[test]
fn rejects_tampered_pok() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    let mut proof = PROOF_BIN.to_vec();
    // PoK is the last 64 bytes (offset 324).
    proof[324 + 63] ^= 0x01;
    match verify_groth16_wrap(&proof, &tree_roots, &out_hash_lanes) {
        Err(VerifyError::PokCheckFailed) | Err(VerifyError::InvalidPoint { .. }) => {}
        other => panic!("tampered PoK must fail the PoK check, got {other:?}"),
    }
}

#[test]
fn rejects_wrong_tree_root_byte() {
    let (mut tree_roots, out_hash_lanes) = fixture_publics();
    tree_roots[0][0] ^= 0x01;
    match verify_groth16_wrap(PROOF_BIN, &tree_roots, &out_hash_lanes) {
        Err(VerifyError::ProofRejected) => {}
        other => panic!("wrong tree root must reject the pairing, got {other:?}"),
    }
}

#[test]
fn rejects_wrong_out_hash_lane() {
    let (tree_roots, mut out_hash_lanes) = fixture_publics();
    out_hash_lanes[7] ^= 0x01;
    match verify_groth16_wrap(PROOF_BIN, &tree_roots, &out_hash_lanes) {
        Err(VerifyError::ProofRejected) => {}
        other => panic!("wrong OutHash lane must reject the pairing, got {other:?}"),
    }
}

#[test]
fn rejects_truncated_proof_tail() {
    let (tree_roots, out_hash_lanes) = fixture_publics();
    match verify_groth16_wrap(&PROOF_BIN[..PROOF_BIN.len() - 1], &tree_roots, &out_hash_lanes) {
        Err(VerifyError::Truncated { .. }) => {}
        other => panic!("truncated proof must fail to parse, got {other:?}"),
    }
}

/// `verify_snark` full path against the real proof: step (a) (Groth16 on the
/// envelope publics) PASSES, then step (c) (OutHash binding) must REJECT a
/// preimage that does not re-derive the proof's OutHash — there is no
/// consistent `output_preimage` for the leaf fixture, so any preimage must
/// be rejected at the binding step, never accepted.
#[test]
fn verify_snark_rejects_mismatched_output_preimage() {
    let envelope = fixture_envelope(PROOF_BIN);
    // Shape-valid single-task preimage: [n_tasks=1, size=4, hash, out, out].
    let f = |v: u64| {
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&v.to_le_bytes());
        raw
    };
    let preimage = vec![f(1), f(4), f(0xdead), f(99), f(100)];
    let err = verify_snark(&envelope, &preimage).unwrap_err();
    assert!(
        err.contains("does not match proof OutHash"),
        "must fail at the OutHash binding step (Groth16 already passed), got: {err}"
    );
}

/// POSITIVE happy path, mv mode: the real Groth16 proof verifies (step a)
/// AND the OutHash binding passes (steps b+c) when fed the REAL children of
/// the wrapped mv root (captured from a deterministic re-run of the fixture
/// aggregation). Exercises the full envelope → Groth16 → mv derivation →
/// binding chain against the embedded production VK.
#[test]
fn verify_snark_mv_accepts_real_proof_with_real_children() {
    let envelope = fixture_envelope(PROOF_BIN);
    let (left, right, expected_root_ov) = fixture_mv_children();
    let root_ov = verify_snark_mv(&envelope, &left, &right)
        .expect("full mv-mode happy path: Groth16 PASS + OutHash binding PASS");
    assert_eq!(
        root_ov, expected_root_ov,
        "returned root output lanes must equal the captured mv root claim outputs"
    );
}

/// mv-mode binding negative: a single flipped child output lane must be
/// rejected at the binding step (Groth16 already passed).
#[test]
fn verify_snark_mv_rejects_tampered_child_outputs() {
    let envelope = fixture_envelope(PROOF_BIN);
    let (left, mut right, _) = fixture_mv_children();
    right.output_lanes[3] ^= 0x01;
    let err = verify_snark_mv(&envelope, &left, &right).unwrap_err();
    assert!(
        err.contains("mv children do not match proof OutHash"),
        "must fail at the OutHash binding step, got: {err}"
    );
}

/// mv-mode binding negative: a flipped child preprocessed-root lane is
/// equally rejected — the children's ROOTS are part of the hashed chain,
/// so a proof cannot be re-bound to a different child circuit shape.
#[test]
fn verify_snark_mv_rejects_tampered_child_root() {
    let envelope = fixture_envelope(PROOF_BIN);
    let (mut left, right, _) = fixture_mv_children();
    left.preprocessed_root_lanes[0] ^= 0x01;
    let err = verify_snark_mv(&envelope, &left, &right).unwrap_err();
    assert!(
        err.contains("mv children do not match proof OutHash"),
        "must fail at the OutHash binding step, got: {err}"
    );
}

/// mv-mode input validation: non-M31 child lanes are rejected up front.
#[test]
fn verify_snark_mv_rejects_non_m31_child_lane() {
    let envelope = fixture_envelope(PROOF_BIN);
    let (left, mut right, _) = fixture_mv_children();
    right.output_lanes[0] = u32::MAX;
    let err = verify_snark_mv(&envelope, &left, &right).unwrap_err();
    assert!(err.contains("not an M31 value"), "{err}");
}

// ---------------------------------------------------------------------------
// Track W3 — the leaf↔mv junction + full-tree verification walk
// ---------------------------------------------------------------------------

/// THE JUNCTION GOLDEN VECTORS: each REAL fixture leaf's bootloader
/// `output_preimage` must re-derive, through the kernel-side junction chain
/// (`Blake2Felt252` → 28 M31 limbs → `pack_into_qm31s` → `blake_m31`),
/// the leaf proof's `claim.output_values` lanes — captured from the real
/// proofs during the fixture aggregation. This is the leaf↔mv missing link:
/// the lanes ARE what each leaf's mv parent hashes as `ovX`.
#[test]
fn leaf_junction_rederives_real_claim_outputs() {
    let leaves = fixture_junction_leaves();
    assert_eq!(leaves.len(), 2, "shield + transfer");
    for leaf in &leaves {
        let felts: Vec<starknet_types_core::felt::Felt> = leaf
            .preimage_raw
            .iter()
            .map(starknet_types_core::felt::Felt::from_bytes_le)
            .collect();
        assert_eq!(
            compute_leaf_output_lanes(&felts),
            leaf.expected_lanes,
            "[{}] junction derivation must equal the real leaf claim.output_values",
            leaf.label
        );
    }
}

/// Fixture cross-link: the junction fixture's expected lanes must BE the
/// leaf `output_lanes` of the mv tree capture (same real proofs, two
/// independent capture runs) — guards against the two JSONs drifting apart.
#[test]
fn leaf_junction_lanes_match_mv_tree_capture() {
    let leaves = fixture_junction_leaves();
    let doc: serde_json::Value = serde_json::from_str(MV_ROOT_CHILDREN_JSON).unwrap();
    for (label, node) in [("shield", "leaf_to_mv_0"), ("transfer", "leaf_to_mv_1")] {
        let expected = leaves.iter().find(|l| l.label == label).unwrap().expected_lanes;
        let node = mv_node(&doc, node);
        assert_eq!(lanes8(&node["left"]["output_lanes"]), expected, "{label} left");
        assert_eq!(lanes8(&node["right"]["output_lanes"]), expected, "{label} right");
    }
}

/// THE TREE WALK GOLDEN VECTOR: junction-derive all 4 declared leaves from
/// their bootloader preimages alone and fold up — the derived ROOT publics
/// must equal the real aggregation's root (preprocessed root AND claim
/// outputs), and the root's preprocessed root must be the wrap proof's
/// `TreeRoots[0]`.
#[test]
fn tree_walk_rederives_real_mv_root_from_preimages() {
    let leaves = fixture_junction_leaves();
    let tree = fixture_tree();
    let root = derive_mv_root_publics(
        tree.leaf_root_lanes,
        &tree.internal_root_lanes,
        &all_declared_slots(&leaves),
    )
    .expect("tree walk");
    assert_eq!(root, tree.expected_root, "derived root publics");

    let (tree_roots, _) = fixture_publics();
    assert_eq!(
        root_lanes_to_bytes(&root.preprocessed_root_lanes),
        tree_roots[0],
        "derived root preprocessed_root must be the wrap proof's TreeRoots[0]"
    );
}

/// POSITIVE happy path, tree mode (the full SNARK-SUBMISSION-DESIGN walk):
/// real Groth16 proof + 4 declared leaves' bootloader preimages → Groth16
/// PASS, tree walk, circuit-identity check, OutHash binding — all green.
#[test]
fn verify_snark_tree_accepts_real_proof_all_declared() {
    let envelope = fixture_envelope(PROOF_BIN);
    let leaves = fixture_junction_leaves();
    let tree = fixture_tree();
    let root_ov = verify_snark_tree(
        &envelope,
        tree.leaf_root_lanes,
        &tree.internal_root_lanes,
        &all_declared_slots(&leaves),
    )
    .expect("full tree-mode happy path");
    assert_eq!(root_ov, tree.expected_root.output_lanes);
}

/// POSITIVE, kernel wiring shape (W2b): the same tree-mode happy path but
/// with the PINNED per-release circuit-identity constants
/// (`LEAF_CIRCUIT_ROOT_LANES` + `pinned_internal_root_lanes`) instead of
/// fixture-loaded ones — exactly the constants the rollup kernel's
/// `verify_submit_ops_tree` passes. Proves the pinned constants accept
/// the real mv-target proof end to end.
#[test]
fn verify_snark_tree_accepts_real_proof_with_pinned_constants() {
    use tzel_verifier::snark::{
        pinned_internal_root_lanes, LEAF_CIRCUIT_ROOT_LANES,
    };
    let envelope = fixture_envelope(PROOF_BIN);
    let leaves = fixture_junction_leaves();
    let tree = fixture_tree();
    let internal = pinned_internal_root_lanes(2).expect("depth 2");
    let root_ov = verify_snark_tree(
        &envelope,
        LEAF_CIRCUIT_ROOT_LANES,
        &internal,
        &all_declared_slots(&leaves),
    )
    .expect("pinned-constant tree-mode happy path");
    assert_eq!(root_ov, tree.expected_root.output_lanes);
}

/// POSITIVE, single-op style: declare each op once and pad its duplicate
/// slot as `Opaque` (junction lanes supplied as-is) — the design's
/// "batch of 1" submission shape.
#[test]
fn verify_snark_tree_accepts_opaque_padding() {
    let envelope = fixture_envelope(PROOF_BIN);
    let leaves = fixture_junction_leaves();
    let tree = fixture_tree();
    let shield = leaves.iter().find(|l| l.label == "shield").unwrap();
    let transfer = leaves.iter().find(|l| l.label == "transfer").unwrap();
    let opaque = |l: &JunctionLeaf| {
        MvLeafSlot::Opaque(MvNodePublics {
            preprocessed_root_lanes: tree.leaf_root_lanes,
            output_lanes: l.expected_lanes,
        })
    };
    let slots = vec![
        MvLeafSlot::Declared {
            output_preimage: &shield.preimage_raw,
        },
        opaque(shield),
        MvLeafSlot::Declared {
            output_preimage: &transfer.preimage_raw,
        },
        opaque(transfer),
    ];
    let root_ov = verify_snark_tree(
        &envelope,
        tree.leaf_root_lanes,
        &tree.internal_root_lanes,
        &slots,
    )
    .expect("declared + opaque mix must verify");
    assert_eq!(root_ov, tree.expected_root.output_lanes);
}

/// Tree-mode binding negative: tampering ONE felt of ONE declared leaf's
/// preimage breaks the blake chain → rejected at the OutHash binding.
#[test]
fn verify_snark_tree_rejects_tampered_declared_preimage() {
    let envelope = fixture_envelope(PROOF_BIN);
    let mut leaves = fixture_junction_leaves();
    let tree = fixture_tree();
    leaves[0].preimage_raw[2][0] ^= 0x01;
    let err = verify_snark_tree(
        &envelope,
        tree.leaf_root_lanes,
        &tree.internal_root_lanes,
        &all_declared_slots(&leaves),
    )
    .unwrap_err();
    assert!(err.contains("does not match proof OutHash"), "{err}");
}

/// Tree-mode binding negative: a flipped OPAQUE slot lane is equally
/// rejected — opaque siblings are part of the hashed chain.
#[test]
fn verify_snark_tree_rejects_tampered_opaque_lane() {
    let envelope = fixture_envelope(PROOF_BIN);
    let leaves = fixture_junction_leaves();
    let tree = fixture_tree();
    let shield = leaves.iter().find(|l| l.label == "shield").unwrap();
    let transfer = leaves.iter().find(|l| l.label == "transfer").unwrap();
    let mut tampered_lanes = shield.expected_lanes;
    tampered_lanes[5] ^= 0x01;
    let slots = vec![
        MvLeafSlot::Declared {
            output_preimage: &shield.preimage_raw,
        },
        MvLeafSlot::Opaque(MvNodePublics {
            preprocessed_root_lanes: tree.leaf_root_lanes,
            output_lanes: tampered_lanes,
        }),
        MvLeafSlot::Declared {
            output_preimage: &transfer.preimage_raw,
        },
        MvLeafSlot::Declared {
            output_preimage: &transfer.preimage_raw,
        },
    ];
    let err = verify_snark_tree(
        &envelope,
        tree.leaf_root_lanes,
        &tree.internal_root_lanes,
        &slots,
    )
    .unwrap_err();
    assert!(err.contains("does not match proof OutHash"), "{err}");
}

/// Tree-mode negative: a wrong LEAF-circuit constant (the protocol-pinned
/// leaf preprocessed root) changes every fold → OutHash binding reject. An
/// attacker cannot re-bind the proof to a different leaf circuit.
#[test]
fn verify_snark_tree_rejects_wrong_leaf_circuit_constant() {
    let envelope = fixture_envelope(PROOF_BIN);
    let leaves = fixture_junction_leaves();
    let mut tree = fixture_tree();
    tree.leaf_root_lanes[0] ^= 0x01;
    let err = verify_snark_tree(
        &envelope,
        tree.leaf_root_lanes,
        &tree.internal_root_lanes,
        &all_declared_slots(&leaves),
    )
    .unwrap_err();
    assert!(err.contains("does not match proof OutHash"), "{err}");
}

/// Tree-mode negative: a wrong ROOT-level circuit constant is caught by the
/// circuit-identity check (step c) — the derived root preprocessed root no
/// longer matches the proof's `TreeRoots[0]`.
#[test]
fn verify_snark_tree_rejects_wrong_root_circuit_constant() {
    let envelope = fixture_envelope(PROOF_BIN);
    let leaves = fixture_junction_leaves();
    let mut tree = fixture_tree();
    tree.internal_root_lanes[1][0] ^= 0x01;
    let err = verify_snark_tree(
        &envelope,
        tree.leaf_root_lanes,
        &tree.internal_root_lanes,
        &all_declared_slots(&leaves),
    )
    .unwrap_err();
    assert!(err.contains("does not match proof TreeRoots[0]"), "{err}");
}

/// Tree-mode step (a) negative: a tampered gnark proof inside the envelope
/// is rejected before any tree work.
#[test]
fn verify_snark_tree_rejects_tampered_groth16_proof() {
    let mut tampered = PROOF_BIN.to_vec();
    tampered[63] ^= 0x01;
    let envelope = fixture_envelope(&tampered);
    let leaves = fixture_junction_leaves();
    let tree = fixture_tree();
    let err = verify_snark_tree(
        &envelope,
        tree.leaf_root_lanes,
        &tree.internal_root_lanes,
        &all_declared_slots(&leaves),
    )
    .unwrap_err();
    assert!(err.contains("groth16 wrap verification failed"), "{err}");
}

/// Tree-walk input validation: slot count must be exactly `2^depth`, depth
/// must be ≥ 1, and opaque lanes must be M31.
#[test]
fn derive_mv_root_publics_validates_inputs() {
    let leaves = fixture_junction_leaves();
    let tree = fixture_tree();

    // Wrong slot count for depth 2.
    let two_slots = &all_declared_slots(&leaves)[..2];
    let err = derive_mv_root_publics(tree.leaf_root_lanes, &tree.internal_root_lanes, two_slots)
        .unwrap_err();
    assert!(err.contains("needs 4 leaf slots"), "{err}");

    // Depth 0.
    let err =
        derive_mv_root_publics(tree.leaf_root_lanes, &[], &all_declared_slots(&leaves)[..1])
            .unwrap_err();
    assert!(err.contains("depth must be in 1..32"), "{err}");

    // Non-M31 opaque lane.
    let bad = MvLeafSlot::Opaque(MvNodePublics {
        preprocessed_root_lanes: tree.leaf_root_lanes,
        output_lanes: [u32::MAX; 8],
    });
    let shield = leaves.iter().find(|l| l.label == "shield").unwrap();
    let slots = vec![
        MvLeafSlot::Declared {
            output_preimage: &shield.preimage_raw,
        },
        bad,
    ];
    let err = derive_mv_root_publics(
        tree.leaf_root_lanes,
        &tree.internal_root_lanes[..1],
        &slots,
    )
    .unwrap_err();
    assert!(err.contains("not an M31 value"), "{err}");
}

/// `verify_snark` step (a) failure: tampering the gnark proof inside the
/// envelope is rejected before the binding step.
#[test]
fn verify_snark_rejects_tampered_envelope_proof() {
    let mut tampered = PROOF_BIN.to_vec();
    tampered[63] ^= 0x01;
    let envelope = fixture_envelope(&tampered);
    let f = |v: u64| {
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&v.to_le_bytes());
        raw
    };
    let preimage = vec![f(1), f(4), f(0xdead), f(99), f(100)];
    let err = verify_snark(&envelope, &preimage).unwrap_err();
    assert!(
        err.contains("groth16 wrap verification failed"),
        "must fail at the Groth16 step, got: {err}"
    );
}
