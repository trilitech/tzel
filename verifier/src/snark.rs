//! `verify_snark` — the Option E kernel precompile primitive
//! (`stwo-gnark-tzel/E2E-INTEGRATION-PLAN.md`, "program_hash binding").
//!
//! ```text
//! verify_snark(proof_bytes, output_preimage)
//!     -> Result<(program_hash, public_outputs)>
//! ```
//!
//! Steps:
//! (a) verify the Groth16 wrap proof on its public inputs
//!     (`TreeRoots`, `OutHash`), all extracted from `proof_bytes`;
//! (b) re-derive `expected_OutHash` from `output_preimage`
//!     (see [`compute_expected_out_hash`]);
//! (c) assert `expected_OutHash == OutHash` — this binds the STARK-side
//!     `output_preimage` to the SNARK proof (forging a preimage for a given
//!     `OutHash` is a blake2s second-preimage attack);
//! (d) parse `(program_hash, public_outputs)` via the existing
//!     `tzel_core::parse_single_task_output_preimage`.
//!
//! # `proof_bytes` wire envelope
//!
//! The chip's public inputs travel alongside the raw gnark proof in a flat,
//! length-checked envelope (offsets in bytes):
//!
//! ```text
//! [0   .. 128)  TreeRoots[0..4]   — 4 × 32 raw bytes (tree order:
//!               preprocessed, trace, interaction, composition)
//! [128 .. 160)  OutHash lanes     — 8 × u32 LE (OutHash[0].(a.0,a.1,b.0,b.1),
//!               then OutHash[1] likewise; each lane < 2^31-1)
//! [160 ..  · )  gnark proof       — `Proof.WriteRawTo` bytes (388 bytes for
//!               the 1-commitment wrap shape; parsed and length-checked by
//!               `groth16::parse_gnark_proof`)
//! ```
//!
//! # `expected_OutHash` derivation — byte layout
//!
//! Matches the chip's `outputHash`
//! (`stwo-gnark-tzel/verifier/circuit_verifier_chip.go:119-150`, called at
//! `:672-676` on `TreeRoots[preprocessed]` + the L2 claim's output values),
//! which itself mirrors upstream `circuit_verifier::verify::
//! build_verification_circuit` (stwo-circuits rev 2bf051f,
//! `crates/circuit_verifier/src/verify.rs:67-74`):
//!
//! ```text
//! output_felt   = Blake2Felt252::encode_felt252_data_and_calc_blake_hash(output_preimage)
//! limbs         = Felt252(output_felt).get_limbs()          // 28 × 9-bit M31 limbs
//! output_qm31s  = pack_into_qm31s(limbs)                    // 7 QM31s
//! output_hash   = blake_m31(output_qm31s)                   // 2 QM31s (8 lanes)
//! output_values = [output_hash.0, output_hash.1, U_VALUE]   // U_VALUE = (0,0,1,0)
//! preimage      = TreeRoots[0] (32 raw bytes)
//!              ‖ output_values as QM31 bytes (per QM31: 4 lanes × u32 LE)
//!               = 80 bytes total
//! OutHash       = blake_m31(preimage)                       // 8 lanes
//! ```
//!
//! where `blake_m31(x) = reduce_to_m31(blake2s-256(x))` — **standard**
//! blake2s-256, then each of the 8 LE u32 lanes of the digest reduced mod
//! `P = 2^31 - 1` (the chip's `ChannelLifted.ReduceDigestM31`,
//! `stwo-gnark-tzel/channel/channel_lifted.go:69-101`; upstream
//! `circuits::blake::blake_qm31`, stwo-circuits
//! `crates/circuits/src/blake.rs:67-87` + stwo
//! `core/vcs/blake2_hash.rs:111` `reduce_to_m31`).
//!
//! The first stage (`output_felt → output_hash`) reuses the host crate's
//! `bundle::compute_output_hash_values`, which delegates to the same
//! upstream crates (`starknet_types_core::hash::Blake2Felt252`,
//! `circuits_stark_verifier::pack_into_qm31s`, `circuits::ivalue::IValue::
//! blake`) used by `proving-utils/crates/privacy_circuit_verify`
//! (`compute_privacy_bootloader_output`, `src/lib.rs:168-171` +
//! `verify_recursive_circuit`, `src/lib.rs:108-114`).
//!
//! ## mv-target assumption (output_values shape)
//!
//! `output_values = [output_hash.0, output_hash.1, U_VALUE]` is the
//! **mv-target / privacy-recursion** shape (`CIRCUIT_OUTPUT_ADDRESSES =
//! [3, 4, 2]` in `privacy_circuit_verify/src/consts.rs`; `U_VALUE` is the
//! logup anchor output at address 2, stwo-circuits
//! `crates/circuits/src/context.rs:20`). The sprint 3.4b **leaf** fixture
//! predates this and carries only 2 output values, so the full
//! `verify_snark` happy path cannot be exercised until the Track A mv
//! artifacts exist; [`compute_expected_out_hash`] is pinned instead by an
//! independently-derived golden vector (see tests).

use starknet_types_core::felt::Felt;
use stwo::core::fields::qm31::QM31;
use tzel_core::{parse_single_task_output_preimage, BootloaderTaskOutput, F as RawF};

use crate::bundle::compute_output_hash_values;
use crate::groth16::{verify_groth16_wrap_with_vk, N_TREES, OUT_HASH_LANES, WRAP_VK_BYTES};

/// Byte length of the `TreeRoots` segment of the proof envelope.
const TREE_ROOTS_BYTES: usize = N_TREES * 32;
/// Byte length of the `OutHash` segment of the proof envelope.
const OUT_HASH_BYTES: usize = OUT_HASH_LANES * 4;
/// Total header (public inputs) length before the raw gnark proof.
const ENVELOPE_HEADER_BYTES: usize = TREE_ROOTS_BYTES + OUT_HASH_BYTES;

/// `U_VALUE` — the logup anchor constant output by `finalize_constants` at
/// wire address 2 (stwo-circuits rev 2bf051f
/// `crates/circuits/src/context.rs:20`): `QM31(0, 0, 1, 0)`.
const U_VALUE_LANES: [u32; 4] = [0, 0, 1, 0];

/// Decoded `proof_bytes` envelope (public inputs + raw gnark proof).
#[derive(Debug)]
pub struct SnarkProofEnvelope<'a> {
    pub tree_roots: [[u8; 32]; N_TREES],
    pub out_hash_lanes: [u32; OUT_HASH_LANES],
    pub gnark_proof_bytes: &'a [u8],
}

/// Parse and length-check the `proof_bytes` envelope (layout in the module
/// docs). The OutHash lanes are range-checked against M31 (`< 2^31 - 1`);
/// the gnark proof tail is only checked non-empty here (fully parsed by
/// the Groth16 layer).
pub fn parse_snark_proof_envelope(proof_bytes: &[u8]) -> Result<SnarkProofEnvelope<'_>, String> {
    if proof_bytes.len() <= ENVELOPE_HEADER_BYTES {
        return Err(format!(
            "snark proof envelope too short: {} <= {} header bytes",
            proof_bytes.len(),
            ENVELOPE_HEADER_BYTES
        ));
    }

    let mut tree_roots = [[0u8; 32]; N_TREES];
    for (t, root) in tree_roots.iter_mut().enumerate() {
        root.copy_from_slice(&proof_bytes[t * 32..(t + 1) * 32]);
    }

    let mut out_hash_lanes = [0u32; OUT_HASH_LANES];
    for (i, lane) in out_hash_lanes.iter_mut().enumerate() {
        let off = TREE_ROOTS_BYTES + i * 4;
        *lane = u32::from_le_bytes(proof_bytes[off..off + 4].try_into().unwrap());
        if *lane >= (1 << 31) - 1 {
            return Err(format!("OutHash lane {} not an M31 value: {}", i, lane));
        }
    }

    Ok(SnarkProofEnvelope {
        tree_roots,
        out_hash_lanes,
        gnark_proof_bytes: &proof_bytes[ENVELOPE_HEADER_BYTES..],
    })
}

/// Re-derive the wrap circuit's `OutHash` public output from the privacy
/// bootloader `output_preimage` and the proof's preprocessed root
/// (`TreeRoots[0]`, 32 raw bytes). Byte layout documented in the module
/// docs; mv-target output shape `[output_hash.0, output_hash.1, U_VALUE]`.
pub fn compute_expected_out_hash(
    preprocessed_root: &[u8; 32],
    output_preimage: &[Felt],
) -> [u32; OUT_HASH_LANES] {
    // Stage 1 — output_hash = blake_m31(pack(limbs(Blake2Felt252(preimage)))),
    // 8 M31 lanes. Same chain as proving-utils
    // `compute_privacy_bootloader_output` + `verify_recursive_circuit`.
    let output_hash_lanes = compute_output_hash_values(output_preimage);
    debug_assert_eq!(output_hash_lanes.len(), OUT_HASH_LANES);

    // Stage 2 — the wrap circuit's outputHash over
    // root_bytes ‖ output_values (each QM31 = 4 lanes × u32 LE) = 80 bytes.
    let mut preimage = [0u8; 32 + 3 * 16];
    preimage[..32].copy_from_slice(preprocessed_root);
    for (i, lane) in output_hash_lanes
        .iter()
        .chain(U_VALUE_LANES.iter())
        .enumerate()
    {
        preimage[32 + i * 4..32 + (i + 1) * 4].copy_from_slice(&lane.to_le_bytes());
    }
    blake_m31_lanes(&preimage)
}

/// `reduce_to_m31(blake2s-256(data))` as 8 u32 lanes — the
/// "Blake2sM31" digest used throughout the lifted chip/channel.
///
/// Implemented via the upstream `circuits::ivalue::IValue::blake`
/// (= `circuits::blake::blake_qm31`: standard `Blake2s256` + stwo
/// `reduce_to_m31`) so the kernel stays byte-identical with the proving
/// stack. The 80-byte preimage is QM31-aligned (5 × 16 bytes), so feeding
/// it as 5 QM31s of LE u32 lanes is exactly the chip's byte stream
/// (`circuit_verifier_chip.go:123-127`: 32 root bytes + 16 bytes per
/// output QM31).
fn blake_m31_lanes(data: &[u8]) -> [u32; OUT_HASH_LANES] {
    use circuits::blake::qm31_from_bytes;
    use circuits::ivalue::IValue;

    debug_assert_eq!(data.len() % 16, 0);
    let qm31s: Vec<QM31> = data
        .chunks_exact(16)
        .map(|c| qm31_from_bytes(c.try_into().unwrap()))
        .collect();
    let hash = QM31::blake(&qm31s, data.len());
    [
        hash.0 .0 .0 .0,
        hash.0 .0 .1 .0,
        hash.0 .1 .0 .0,
        hash.0 .1 .1 .0,
        hash.1 .0 .0 .0,
        hash.1 .0 .1 .0,
        hash.1 .1 .0 .0,
        hash.1 .1 .1 .0,
    ]
}

/// The Option E precompile: verify a Groth16-wrapped TzEL proof and bind it
/// to `output_preimage`, returning the parsed
/// `(program_hash, public_outputs)`.
///
/// See the module docs for the envelope format and the binding derivation.
pub fn verify_snark<'a>(
    proof_bytes: &[u8],
    output_preimage: &'a [RawF],
) -> Result<BootloaderTaskOutput<'a>, String> {
    verify_snark_with_vk(proof_bytes, output_preimage, WRAP_VK_BYTES)
}

/// [`verify_snark`] with an explicit gnark VK (testing / VK rotation).
pub fn verify_snark_with_vk<'a>(
    proof_bytes: &[u8],
    output_preimage: &'a [RawF],
    vk_bytes: &[u8],
) -> Result<BootloaderTaskOutput<'a>, String> {
    let envelope = parse_snark_proof_envelope(proof_bytes)?;

    // (a) Groth16 verification on the chip's public inputs.
    verify_groth16_wrap_with_vk(
        envelope.gnark_proof_bytes,
        &envelope.tree_roots,
        &envelope.out_hash_lanes,
        vk_bytes,
    )
    .map_err(|e| format!("groth16 wrap verification failed: {e}"))?;

    // (b) + (c) OutHash binding: the preimage must re-derive the proof's
    // OutHash. TreeRoots[0] is the preprocessed root the chip hashed.
    let preimage_felts: Vec<Felt> = output_preimage
        .iter()
        .map(|raw| Felt::from_bytes_le(raw))
        .collect();
    let expected = compute_expected_out_hash(&envelope.tree_roots[0], &preimage_felts);
    if expected != envelope.out_hash_lanes {
        return Err(format!(
            "output_preimage does not match proof OutHash: expected lanes {:?}, proof carries {:?}",
            expected, envelope.out_hash_lanes
        ));
    }

    // (d) Parse (program_hash, public_outputs).
    parse_single_task_output_preimage(output_preimage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::qm31::QM31;

    /// Leaf-fixture cross-check of the **outer** OutHash stage (stage 2):
    /// the sprint 3.4b leaf shape sidecar
    /// (`l2_proof.shape.json.leaf-backup`) carries
    /// `l2_preprocessed_root_hex` + 2 `output_values_qm31s`, and the gnark
    /// public witness dump pins the resulting OutHash lanes (indices
    /// 128..136 of `testdata/sprint34b_public_witness.txt`). This validates
    /// the `root_bytes ‖ QM31-LE-lanes → blake2s → M31-reduce` layout
    /// against chip-validated data (the leaf shape has 2 output values,
    /// no U_VALUE — hence testing `blake_m31_lanes` directly).
    #[test]
    fn out_hash_layout_matches_leaf_fixture() {
        let root =
            hex::decode("ae20985c63c835435d346b78c87f8d61d8afe270ba30ab3e906f21456dc5e433")
                .unwrap();
        let output_values: [[u32; 4]; 2] = [
            [1001097638, 999176661, 173075864, 1536773375],
            [1599342717, 1876184159, 922490163, 607398914],
        ];
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&root);
        for q in &output_values {
            for lane in q {
                preimage.extend_from_slice(&lane.to_le_bytes());
            }
        }
        let lanes = blake_m31_lanes(&preimage);
        assert_eq!(
            lanes,
            [
                755157659, 477502738, 595910405, 364866566, 669724106, 877210065, 761932097,
                1096864836
            ],
            "must match OutHash lanes of the dumped sprint34b public witness"
        );
    }

    /// Golden vector for the full mv-target derivation, generated by an
    /// independent Python implementation (hashlib.blake2s + manual felt
    /// encoding per starknet-types-core `blake2s.rs:62-130` + 9-bit limb
    /// split per stwo-cairo `cpu.rs:450-485`). Guards every stage:
    /// felt encoding, inner blake, limb split, QM31 packing, U_VALUE
    /// placement, outer blake, M31 lane reduction.
    #[test]
    fn compute_expected_out_hash_golden_vector() {
        let mut root = [0u8; 32];
        root.copy_from_slice(
            &hex::decode("ae20985c63c835435d346b78c87f8d61d8afe270ba30ab3e906f21456dc5e433")
                .unwrap(),
        );
        let preimage: Vec<Felt> = [
            Felt::from(1u64),
            Felt::from(4u64),
            Felt::from_hex_unchecked(
                "0x07d0b1aafa1b3f57a0d4c84712d23ff70fb55fbcb1f81e2452cf6c4e74e7c508",
            ),
            Felt::from(99u64),
            Felt::from(100u64),
        ]
        .to_vec();
        assert_eq!(
            compute_expected_out_hash(&root, &preimage),
            [
                1327368715, 167547655, 34084859, 358180399, 458755360, 675324717, 638057561,
                2067345823
            ],
        );
    }

    /// The intermediate output_hash lanes of the golden vector, pinning
    /// stage 1 (`Blake2Felt252` + limb split + `pack_into_qm31s` +
    /// `QM31::blake`) separately for easier debugging.
    #[test]
    fn output_hash_values_golden_vector() {
        let preimage: Vec<Felt> = [
            Felt::from(1u64),
            Felt::from(4u64),
            Felt::from_hex_unchecked(
                "0x07d0b1aafa1b3f57a0d4c84712d23ff70fb55fbcb1f81e2452cf6c4e74e7c508",
            ),
            Felt::from(99u64),
            Felt::from(100u64),
        ]
        .to_vec();
        assert_eq!(
            compute_output_hash_values(&preimage),
            vec![
                1582265401, 1538535622, 2135620025, 1601248341, 1791917009, 204480096, 808409381,
                1431869092
            ],
        );
    }

    #[test]
    fn envelope_rejects_short_input() {
        let err = parse_snark_proof_envelope(&[0u8; ENVELOPE_HEADER_BYTES]).unwrap_err();
        assert!(err.contains("envelope too short"), "{err}");
    }

    #[test]
    fn envelope_rejects_non_m31_lane() {
        let mut bytes = vec![0u8; ENVELOPE_HEADER_BYTES + 1];
        bytes[TREE_ROOTS_BYTES..TREE_ROOTS_BYTES + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        let err = parse_snark_proof_envelope(&bytes).unwrap_err();
        assert!(err.contains("not an M31 value"), "{err}");
    }

    #[test]
    fn envelope_roundtrips_fields() {
        let mut bytes = Vec::new();
        for t in 0..4u8 {
            bytes.extend_from_slice(&[t; 32]);
        }
        for lane in 0..8u32 {
            bytes.extend_from_slice(&(lane + 100).to_le_bytes());
        }
        bytes.extend_from_slice(b"gnark-proof-tail");
        let env = parse_snark_proof_envelope(&bytes).unwrap();
        assert_eq!(env.tree_roots[2], [2u8; 32]);
        assert_eq!(env.out_hash_lanes[7], 107);
        assert_eq!(env.gnark_proof_bytes, b"gnark-proof-tail");
    }

    /// Sanity: QM31 lane accessor order in `blake_m31_lanes` matches
    /// `circuits::blake::qm31_from_bytes` (LE lane order a.0, a.1, b.0, b.1).
    #[test]
    fn qm31_lane_order_roundtrip() {
        use circuits::blake::qm31_from_bytes;
        let mut bytes = [0u8; 16];
        for (i, lane) in [11u32, 22, 33, 44].iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&lane.to_le_bytes());
        }
        let q: QM31 = qm31_from_bytes(&bytes);
        assert_eq!(
            [q.0 .0 .0, q.0 .1 .0, q.1 .0 .0, q.1 .1 .0],
            [11, 22, 33, 44]
        );
    }
}
