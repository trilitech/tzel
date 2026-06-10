//! Golden-vector capture of the **leaf↔mv junction** (track W3 of
//! `docs/SNARK-SUBMISSION-DESIGN.md`): a leaf's claim `output_values` — the
//! 2 QM31s its mv PARENT hashes — derive from the leaf op's bootloader
//! `output_preimage` alone:
//!
//! ```text
//! limbs        = Felt252(Blake2Felt252(output_preimage)).get_limbs()  // 28 M31s
//! output_qm31s = pack_into_qm31s(limbs)                               // 7 QM31s
//! claim.ov     = blake_qm31(output_qm31s, 7 * 16)                     // 2 QM31s
//! ```
//!
//! Upstream ground truth (stwo-circuits rev 2bf051f,
//! `crates/cairo_verifier/src/statement.rs:355-357`):
//! `output_hash = blake(ctx, packed_outputs, …); set_outputs(&[output_hash.0,
//! output_hash.1])` — the CairoStatement leaf has exactly 2 claim outputs
//! (`u` is enforced via the public logup sum, not listed).
//!
//! This test re-runs ONLY the privacy bootloader (no proving — seconds, not
//! minutes) for the same shield/transfer fixtures as `export_mv_fixture.rs`,
//! re-derives the lanes above, and asserts them against the leaf
//! `output_lanes` captured from the REAL proofs by `mv_output_derivation.rs`
//! (`verifier/testdata/mv_root_children.json`, nodes leaf_to_mv_0/_1). It
//! then dumps `/tmp/tzel-mv-fixture/leaf_junction.json` — preimages +
//! expected lanes — for the kernel-side `tzel-verifier` golden tests.
//!
//! Run from `services/reprover`:
//! `cargo test --release --test leaf_junction_capture -- --ignored --nocapture`

use std::path::PathBuf;

use circuits::blake::blake_qm31;
use privacy_circuit_verify::compute_privacy_bootloader_output;
use serde_json::json;
use starknet_types_core::felt::Felt;
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

/// Bootloader-only run: returns the op's `output_preimage` felts.
fn preimage_of(exe: &str, args: &str) -> Vec<Felt> {
    let (_prover_input, output_preimage) =
        run_privacy_bootloader(&fixture(exe), None, Some(args_fixture(args)))
            .expect("bootloader run");
    output_preimage
}

/// The junction derivation under test (mirrors tzel-verifier's
/// `compute_output_hash_values` and upstream `CairoStatement::claims_to_mix`).
fn leaf_output_lanes(output_preimage: &[Felt]) -> [u32; 8] {
    use circuits_stark_verifier::proof_from_stark_proof::pack_into_qm31s;
    let limbs = compute_privacy_bootloader_output(output_preimage);
    let qm31s = pack_into_qm31s(limbs.into_iter());
    let h = blake_qm31(&qm31s, qm31s.len() * 16);
    let a = h.0.to_m31_array().map(|m| m.0);
    let b = h.1.to_m31_array().map(|m| m.0);
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

/// Leaf `output_lanes` of `verifier/testdata/mv_root_children.json`
/// (captured from the REAL leaf proofs' `claim.output_values` by
/// `mv_output_derivation.rs` on the export_mv_fixture tree).
const SHIELD_LEAF_LANES: [u32; 8] = [
    978423824, 1296894678, 337981983, 1090493975, 1318990943, 34913325, 2019415546, 380174573,
];
const TRANSFER_LEAF_LANES: [u32; 8] = [
    2073000406, 1409692151, 1297781539, 851970458, 866671971, 1790092888, 1205592385, 1316010105,
];

#[test]
#[ignore]
fn leaf_output_values_derive_from_bootloader_preimage() {
    let out_dir = PathBuf::from("/tmp/tzel-mv-fixture");
    std::fs::create_dir_all(&out_dir).expect("mkdir out_dir");

    let mut entries = vec![];
    for (label, exe, args, expected) in [
        (
            "shield",
            "run_shield.executable.json",
            "run_shield_args.json",
            SHIELD_LEAF_LANES,
        ),
        (
            "transfer",
            "run_transfer.executable.json",
            "run_transfer_args.json",
            TRANSFER_LEAF_LANES,
        ),
    ] {
        let t = std::time::Instant::now();
        let preimage = preimage_of(exe, args);
        let lanes = leaf_output_lanes(&preimage);
        eprintln!(
            "[LEAF-JUNCTION] {label}: {} preimage felts in {:?}, lanes = {:?}",
            preimage.len(),
            t.elapsed(),
            lanes
        );
        assert_eq!(
            lanes, expected,
            "[{label}] junction derivation must equal the leaf claim.output_values \
             lanes captured from the real proof (mv_root_children.json)"
        );
        entries.push(json!({
            "label": label,
            "output_preimage_hex": preimage.iter().map(|f| format!("{f:#x}")).collect::<Vec<_>>(),
            "expected_leaf_output_lanes": expected,
        }));
    }

    let doc = json!({
        "comment": "Captured by services/reprover/tests/leaf_junction_capture.rs (bootloader-only \
                    re-run of the export_mv_fixture leaves). expected_leaf_output_lanes are the \
                    REAL leaf proofs' claim.output_values (mv_root_children.json); the junction \
                    derivation pack_into_qm31s(Blake2Felt252-limbs) -> blake_qm31 was asserted \
                    equal during capture.",
        "leaves": entries,
    });
    let out_path = out_dir.join("leaf_junction.json");
    std::fs::write(&out_path, serde_json::to_string_pretty(&doc).unwrap())
        .expect("write leaf_junction.json");
    eprintln!("[LEAF-JUNCTION] wrote {}", out_path.display());
}
