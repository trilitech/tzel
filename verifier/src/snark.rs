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
//! // Stage 1 (blake2s) — unchanged:
//! output_felt   = Blake2Felt252::encode_felt252_data_and_calc_blake_hash(output_preimage)
//! limbs         = Felt252(output_felt).get_limbs()          // 28 × 9-bit M31 limbs
//! output_qm31s  = pack_into_qm31s(limbs)                    // 7 QM31s
//! output_hash   = blake_m31(output_qm31s)                   // 2 QM31s (8 lanes)
//! output_values = [output_hash.0, output_hash.1]            // Claim.OutputValues, len=N_RESERVED=2 (NO U_VALUE)
//! // Stage 2 (Poseidon2-BN254, item-D ABI):
//! sponge        = Poseidon2-BN254 t=3 rate-1: state=[0,0,0];
//!                 absorb Fr(TreeRoots[0]); for each output_value:
//!                   absorb its 4 M31 limbs as Fr (each: state[0]+=x; permute);
//!                 digestFr = state[0]
//! OutHash       = frToM31Lanes(digestFr)                    // 8 lanes
//! ```
//!
//! Stage 1 still uses `blake_m31(x) = reduce_to_m31(blake2s-256(x))` — standard
//! blake2s-256 reduced mod `P = 2^31 - 1`. Stage 2 changed from blake2s to the
//! Poseidon2-BN254 sponge to match the wrap chip's item-D ABI
//! (`fri.Poseidon2Bn254Hasher.HashLeafQM31Lanes`); `frToM31Lanes` takes 254
//! canonical LE bits of the digest Fr, regroups into 8 × 32-bit words (last
//! clamped to the 254-bit span), each reduced mod `P`.
//!
//! The first stage (`output_felt → output_hash`) reuses the host crate's
//! `bundle::compute_output_hash_values`, which delegates to the same
//! upstream crates (`starknet_types_core::hash::Blake2Felt252`,
//! `circuits_stark_verifier::pack_into_qm31s`, `circuits::ivalue::IValue::
//! blake`) used by `proving-utils/crates/privacy_circuit_verify`
//! (`compute_privacy_bootloader_output`, `src/lib.rs:168-171` +
//! `verify_recursive_circuit`, `src/lib.rs:108-114`).
//!
//! ## Leaf mode vs mv mode (output_values shape)
//!
//! Two derivations of `expected_OutHash` exist, depending on WHAT the wrap
//! circuit verified:
//!
//! **Leaf mode** ([`compute_expected_out_hash`]) — the wrap verifies a
//! recursion *leaf* statement whose `output_values = [output_hash.0,
//! output_hash.1]` (2 QM31s), where `output_hash` derives from the Cairo
//! bootloader `output_preimage`. The `u` logup anchor (wire 2, stwo-circuits
//! `crates/circuits/src/context.rs:20`) is NOT an explicit output value here:
//! it is enforced through the public logup sum, matching the Go chip's
//! `Claim.OutputValues` (length `N_RESERVED = 2`) and the `CairoStatement`
//! `set_outputs(&[output_hash.0, output_hash.1])` (stwo-circuits 2bf051f
//! `crates/cairo_verifier/src/statement.rs:355-357`).
//!
//! NOTE: prior to the item-D ABI change, Stage 2 was blake2s over
//! `[output_hash.0, output_hash.1, U_VALUE]` (the standalone
//! `privacy_circuit_verify` 3-output shape, `CIRCUIT_OUTPUT_ADDRESSES =
//! [3,4,2]`). The Poseidon2-BN254 `outputHash` gadget
//! (`circuit_verifier_chip.go`) absorbs only the 2 claim output_values, so the
//! `U_VALUE` term is dropped. If the leaf wrap is ever re-pointed at the
//! standalone 3-output `privacy_circuit_verify` statement (rather than the
//! circuit_verifier/Cairo-leaf chip), this Stage-2 must absorb 3 values again.
//!
//! **mv mode** ([`compute_expected_out_hash_mv`]) — the production shape:
//! the wrap verifies a `circuit_multiverifier` *root* proof aggregating a
//! binary tree of statements. mv claims have exactly `N_RESERVED = 2`
//! output values (stwo-circuits `crates/circuit_common/src/lib.rs:8`;
//! `crates/circuit_multiverifier/src/verify.rs:96`
//! `set_outputs(&[output_hash.0, output_hash.1])`) and `U_VALUE` does NOT
//! appear among them — for `CircuitStatement`-built circuits the `u` wire
//! is enforced through the public logup sum instead
//! (`crates/circuit_verifier/src/statement.rs:120-127` appends the pair
//! `(U_VAR_IDX, u)`; `crates/circuit_verifier/src/verify.rs` step-3 note
//! "this is fine for soundness because `u` is checked as part of the
//! logup sum"). Each mv node's 2 outputs are
//!
//! ```text
//! parent.output_values = blake_m31(
//!     childL.preprocessed_root ‖ childL.output_values
//!   ‖ childR.preprocessed_root ‖ childR.output_values )   // 8 QM31s = 128 B
//! ```
//!
//! (`crates/circuit_multiverifier/src/verify.rs:64-96`: preimage build at
//! :79-88, `blake(.., 16 * len)` at :90-94), each QM31 framed as 4 u32 LE
//! lanes (`crates/circuits/src/blake.rs:47-54` `to_bytes`, mirrored by the
//! witness `blake_qm31` at `blake.rs:67-85`). These tree-fold blake2s steps
//! ([`compute_mv_output_values`]) are UNCHANGED by item-D.
//!
//! The chip then computes the FINAL `OutHash` over `TreeRoots[preprocessed] ‖
//! Claim.OutputValues` with the item-D **Poseidon2-BN254** `outputHash` gadget
//! (the SAME single gadget used for the leaf path —
//! `stwo-gnark-tzel/verifier/circuit_verifier_chip.go` `outputHash`, mv-root
//! call site `:912-915`): the t=3 rate-1 sponge absorbs `Fr(root)` then the 2
//! output values' M31 limbs, then `frToM31Lanes(digest)`. See
//! [`compute_expected_out_hash_mv`].
//!
//! Both modes' Poseidon2 final-OutHash derivation is pinned by golden vectors
//! validated byte-exact against the Go reference `offcircuit.OutHashPoseidon2`.
//! NOTE: the real 2026-06-10 `proof.bin` fixture is blake2s-era (its pinned
//! OutHash predates item-D), so the real-proof *binding* acceptance tests are
//! `#[ignore]`d pending an item-D Poseidon2 mv wrap fixture (see
//! `tests/snark_wrap_acceptance.rs` module docs).
//!
//! ## The leaf↔mv junction (aggregation-tree leaves)
//!
//! When a privacy op is a LEAF of an aggregation tree (the production
//! submission path, `docs/SNARK-SUBMISSION-DESIGN.md` track W3), its publics
//! as seen by its mv PARENT derive from the op's bootloader
//! `output_preimage` alone:
//!
//! ```text
//! limbs        = Felt252(Blake2Felt252(output_preimage)).get_limbs() // 28 M31s
//! output_qm31s = pack_into_qm31s(limbs)                              // 7 QM31s
//! leaf.output_values = blake_m31(output_qm31s)                       // 2 QM31s
//! leaf.preprocessed_root = protocol constant (leaf circuit identity)
//! ```
//!
//! i.e. EXACTLY stage 1 of the leaf-mode derivation
//! ([`compute_leaf_output_lanes`]) — the `CairoStatement` leaf circuit sets
//! exactly these 2 claim outputs (stwo-circuits 2bf051f
//! `crates/cairo_verifier/src/statement.rs:355-357`: `output_hash =
//! blake(ctx, packed_outputs, …); set_outputs(&[output_hash.0,
//! output_hash.1])`; the `u` anchor is enforced via the public logup sum,
//! not listed — unlike the standalone 3-output leaf shape of
//! `privacy_circuit_verify`). Pinned by `testdata/leaf_junction.json`:
//! the REAL fixture leaves' bootloader preimages re-derive the leaf
//! `claim.output_values` captured from the real proofs
//! (`testdata/mv_root_children.json`, nodes `leaf_to_mv_*`).
//!
//! [`derive_mv_root_publics`] walks a whole binding tree
//! ([`MvLeafSlot`] leaves → pairwise [`compute_mv_output_values`] folds),
//! and [`verify_snark_tree`] is the end-to-end kernel check: declared
//! leaves' preimages → tree walk → root publics → wrap OutHash equation →
//! Groth16.

use starknet_types_core::felt::Felt;
use stwo::core::fields::qm31::QM31;
use tzel_core::{parse_single_task_output_preimage, BootloaderTaskOutput, F as RawF};

use crate::out_hash::compute_output_hash_values;
use crate::groth16::{verify_groth16_wrap_with_vk, N_TREES, OUT_HASH_LANES, WRAP_VK_BYTES};

/// Byte length of the `TreeRoots` segment of the proof envelope.
const TREE_ROOTS_BYTES: usize = N_TREES * 32;
/// Byte length of the `OutHash` segment of the proof envelope.
const OUT_HASH_BYTES: usize = OUT_HASH_LANES * 4;
/// Total header (public inputs) length before the raw gnark proof.
const ENVELOPE_HEADER_BYTES: usize = TREE_ROOTS_BYTES + OUT_HASH_BYTES;

// ── Pinned circuit-identity constants (per-TzEL-release) ────────────────
//
// The aggregation-tree verification walk (`verify_snark_tree`) needs the
// preprocessed roots of the circuits at each tree level — protocol
// constants pinned per TzEL release, exactly like the embedded wrap VK
// (`src/wrap_vk.bin`): they change together whenever the circuit stack is
// regenerated (`docs/SNARK-SUBMISSION-DESIGN.md`, "Open points").
//
// Values captured from the REAL fixture aggregation tree
// (`testdata/mv_root_children.json`, 2026-06-10 mv-target cycle) and
// pinned against it by `pinned_circuit_roots_match_golden_fixture`. The
// leaf root is identical across op kinds (shield and transfer leaves in
// the fixture carry the same root: the leaf circuit verifies the privacy
// bootloader, whatever Cairo task it ran).

/// Preprocessed root of the LEAF circuit (`HashValue<QM31>` as 8 M31
/// lanes) — the identity every `MvLeafSlot::Declared` leaf is bound to.
pub const LEAF_CIRCUIT_ROOT_LANES: [u32; 8] = [
    260776853, 1309242768, 1145090100, 1598670544, 369006849, 883527537, 842476743, 1550035524,
];

/// Preprocessed root of the level-1 multiverifier circuit (`leaf_to_mv`,
/// verifies two leaf proofs). FRI-config-dependent (preprocessed LDE Merkle
/// root) — captured at the PRODUCTION config TZEL_SEC=96 TZEL_FOLD=2.
pub const LEAF_TO_MV_CIRCUIT_ROOT_LANES: [u32; 8] = [
    327071585, 1981680103, 733719417, 886400460, 805003444, 384535660, 1686938097, 1077085843,
];

/// Preprocessed root of the level-≥2 multiverifier circuit (`mv_to_mv`,
/// verifies two mv proofs). FRI-config-dependent — captured at TZEL_SEC=96
/// TZEL_FOLD=2.
pub const MV_TO_MV_CIRCUIT_ROOT_LANES: [u32; 8] = [
    595696919, 1910171649, 2139503746, 1553759560, 1553561027, 1362531168, 719029369, 85600087,
];

/// The pinned per-level internal preprocessed roots for a tree of `depth`
/// levels, bottom-up — the `internal_preprocessed_root_lanes` argument of
/// [`verify_snark_tree`] / [`derive_mv_root_publics`]: `leaf_to_mv` at
/// level 1, `mv_to_mv` at every level ≥ 2
/// (`docs/SNARK-SUBMISSION-DESIGN.md`, verification walk step 3).
///
/// NOTE: depth 2 is golden-validated end to end
/// (`mv_root_children.json`); the uniform `mv_to_mv` root at levels ≥ 3
/// follows from the mv circuit verifying two mv proofs regardless of
/// level, per the design doc — re-pin against a deeper fixture when one
/// is captured.
pub fn pinned_internal_root_lanes(depth: u8) -> Result<Vec<[u32; 8]>, String> {
    if depth == 0 || depth >= 32 {
        return Err(format!("mv tree depth must be in 1..32, got {depth}"));
    }
    Ok((1..=depth)
        .map(|level| {
            if level == 1 {
                LEAF_TO_MV_CIRCUIT_ROOT_LANES
            } else {
                MV_TO_MV_CIRCUIT_ROOT_LANES
            }
        })
        .collect())
}

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

    // Stage 2 — the wrap circuit's `outputHash` (item-D ABI: Poseidon2-BN254).
    //
    // Absorbs the preprocessed root (`TreeRoots[0]` as a BN254 Fr) then the
    // claim's `output_values` 4-M31-limb-each, through a t=3 rate-1 Poseidon2
    // sponge, then maps the digest Fr to 8 M31 lanes. This is the EXACT gadget
    // `CircuitVerifierChipLifted.outputHash` (verifier/circuit_verifier_chip.go)
    // / off-circuit `offcircuit.OutHashPoseidon2`.
    //
    // `Claim.OutputValues` has length `N_RESERVED = 2` (the multiverifier root's
    // emitted outputs == Stage-1 `output_hash` = these 8 lanes). U_VALUE is NOT
    // absorbed here — it only appears in `derivePublicLogupSum`, a distinct
    // computation, never in `outputHash`. (Resolves the prior 2-vs-3 question:
    // the blake2s Stage-2 appended U_VALUE as a 3rd QM31; the Poseidon2 ABI does
    // not — it absorbs exactly the 2 claim output_values.)
    crate::poseidon2_bn254::out_hash_poseidon2(preprocessed_root, &output_hash_lanes)
}

/// Public data of one aggregation-tree node as seen by its PARENT
/// multiverifier: the node's preprocessed root (`HashValue<QM31>`, 8 M31
/// lanes) and its 2 claim output values (8 M31 lanes). Lane order is the
/// upstream QM31 LE framing `a.0, a.1, b.0, b.1` per QM31 (stwo-circuits
/// 2bf051f `crates/circuits/src/blake.rs:47-54`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MvNodePublics {
    pub preprocessed_root_lanes: [u32; 8],
    pub output_lanes: [u32; 8],
}

impl MvNodePublics {
    fn check_m31(&self) -> Result<(), String> {
        for (what, lanes) in [
            ("preprocessed_root", &self.preprocessed_root_lanes),
            ("output_values", &self.output_lanes),
        ] {
            if let Some(lane) = lanes.iter().find(|l| **l >= (1 << 31) - 1) {
                return Err(format!("mv child {what} lane not an M31 value: {lane}"));
            }
        }
        Ok(())
    }
}

/// One multiverifier tree level: re-derive a parent mv node's 2 claim
/// output values (as 8 M31 lanes) from its two children's publics.
///
/// Mirrors `build_multiverifier_circuit` (stwo-circuits 2bf051f
/// `crates/circuit_multiverifier/src/verify.rs:64-96`):
/// `blake_m31([rootL.0, rootL.1, ovL.0, ovL.1, rootR.0, rootR.1, ovR.0,
/// ovR.1], n_bytes = 16 × 8)` — 128 bytes of u32-LE lanes, standard
/// blake2s-256, digest lanes reduced to M31. Validated off-circuit against
/// real aggregation runs by
/// `services/reprover/tests/mv_output_derivation.rs` and pinned by the
/// `testdata/mv_root_children.json` golden vectors.
pub fn compute_mv_output_values(left: &MvNodePublics, right: &MvNodePublics) -> [u32; 8] {
    let mut preimage = [0u8; 2 * 2 * 8 * 4]; // 2 children × (root + ov) × 8 lanes × 4 B
    for (c, child) in [left, right].into_iter().enumerate() {
        for (i, lane) in child
            .preprocessed_root_lanes
            .iter()
            .chain(child.output_lanes.iter())
            .enumerate()
        {
            let off = c * 64 + i * 4;
            preimage[off..off + 4].copy_from_slice(&lane.to_le_bytes());
        }
    }
    blake_m31_lanes(&preimage)
}

/// The leaf↔mv junction, stage 1 of the leaf derivation: a leaf statement's
/// 2 claim output values (8 M31 lanes) from its bootloader
/// `output_preimage` — what the leaf's mv PARENT hashes as `ovX` (see the
/// module docs, "The leaf↔mv junction"). Same chain as the first stage of
/// [`compute_expected_out_hash`].
pub fn compute_leaf_output_lanes(output_preimage: &[Felt]) -> [u32; 8] {
    let lanes = compute_output_hash_values(output_preimage);
    lanes
        .as_slice()
        .try_into()
        .expect("compute_output_hash_values yields exactly 8 lanes")
}

/// A leaf's full mv-visible publics: junction-derived output lanes + the
/// leaf circuit's preprocessed root (a per-release protocol constant — the
/// leaf circuit's identity, NOT attacker-controlled).
pub fn leaf_mv_publics(
    leaf_preprocessed_root_lanes: [u32; 8],
    output_preimage: &[Felt],
) -> MvNodePublics {
    MvNodePublics {
        preprocessed_root_lanes: leaf_preprocessed_root_lanes,
        output_lanes: compute_leaf_output_lanes(output_preimage),
    }
}

/// [`leaf_mv_publics`] taking the raw 32-byte LE felts the kernel wire
/// carries (`&[RawF]`), converting exactly as [`derive_mv_root_publics`]
/// does for a `Declared` slot. Lets producers (wallet/operator) derive a
/// leaf's mv publics without depending on `starknet-types-core` directly —
/// e.g. to fill an `Opaque` padding slot that duplicates a declared leaf.
pub fn leaf_mv_publics_raw(
    leaf_preprocessed_root_lanes: [u32; 8],
    output_preimage: &[RawF],
) -> MvNodePublics {
    let felts: Vec<Felt> = output_preimage
        .iter()
        .map(|raw| Felt::from_bytes_le(raw))
        .collect();
    leaf_mv_publics(leaf_preprocessed_root_lanes, &felts)
}

/// One leaf slot of an aggregation-tree binding
/// (`docs/SNARK-SUBMISSION-DESIGN.md`, `TreeBinding`).
#[derive(Debug)]
pub enum MvLeafSlot<'a> {
    /// Leaf backed by a declared op: its publics are RE-DERIVED from the
    /// op's bootloader `output_preimage` (raw 32-byte LE felts, as carried
    /// on the wire) — the leaf↔mv junction.
    Declared { output_preimage: &'a [RawF] },
    /// Padding / sibling leaf: lanes supplied as-is (M31 range-checked,
    /// never applied as an op).
    Opaque(MvNodePublics),
}

/// Recursive aggregation-tree walk: fold `2^depth` leaf slots pairwise up
/// to the ROOT's publics.
///
/// * `leaf_preprocessed_root_lanes` — the leaf circuit's preprocessed root
///   (protocol constant), used for every `Declared` slot.
/// * `internal_preprocessed_root_lanes` — one constant per internal level,
///   bottom-up: `[0]` = the leaf_to_mv circuit root (level 1), last = the
///   tree's ROOT circuit root (mv_to_mv for depth ≥ 2). `depth =
///   internal_preprocessed_root_lanes.len()`, so `slots.len()` must be
///   `2^depth` (≥ 2 slots).
///
/// Every fold is [`compute_mv_output_values`] (`parent.ov = blake_m31(rootL
/// ‖ ovL ‖ rootR ‖ ovR)`); all supplied lanes are M31 range-checked. The
/// returned root publics chain into [`compute_expected_out_hash_mv`] /
/// [`verify_snark_tree`].
pub fn derive_mv_root_publics(
    leaf_preprocessed_root_lanes: [u32; 8],
    internal_preprocessed_root_lanes: &[[u32; 8]],
    slots: &[MvLeafSlot<'_>],
) -> Result<MvNodePublics, String> {
    let depth = internal_preprocessed_root_lanes.len();
    if depth == 0 || depth >= 32 {
        return Err(format!("mv tree depth must be in 1..32, got {depth}"));
    }
    if slots.len() != 1usize << depth {
        return Err(format!(
            "mv tree of depth {depth} needs {} leaf slots, got {}",
            1usize << depth,
            slots.len()
        ));
    }

    let mut level: Vec<MvNodePublics> = Vec::with_capacity(slots.len());
    for slot in slots {
        let node = match slot {
            MvLeafSlot::Declared { output_preimage } => {
                let felts: Vec<Felt> = output_preimage
                    .iter()
                    .map(|raw| Felt::from_bytes_le(raw))
                    .collect();
                leaf_mv_publics(leaf_preprocessed_root_lanes, &felts)
            }
            MvLeafSlot::Opaque(publics) => *publics,
        };
        node.check_m31()?;
        level.push(node);
    }

    for parent_root_lanes in internal_preprocessed_root_lanes {
        if let Some(lane) = parent_root_lanes.iter().find(|l| **l >= (1 << 31) - 1) {
            return Err(format!(
                "internal preprocessed_root lane not an M31 value: {lane}"
            ));
        }
        level = level
            .chunks_exact(2)
            .map(|pair| MvNodePublics {
                preprocessed_root_lanes: *parent_root_lanes,
                output_lanes: compute_mv_output_values(&pair[0], &pair[1]),
            })
            .collect();
    }
    debug_assert_eq!(level.len(), 1);
    Ok(level[0])
}

/// Encode 8 M31 root lanes as the 32 raw bytes the chip carries in
/// `TreeRoots` (each lane u32 LE — the byte form of `HashValue<QM31>`).
pub fn root_lanes_to_bytes(lanes: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, lane) in lanes.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&lane.to_le_bytes());
    }
    bytes
}

/// Re-derive the wrap circuit's `OutHash` for an **mv root** proof from the
/// root's preprocessed root (`TreeRoots[0]`, 32 raw bytes) and its 2 claim
/// output values (8 M31 lanes, e.g. from [`compute_mv_output_values`]).
///
/// This is the FINAL OutHash-over-root. The item-D chip computes it with the
/// SAME single `outputHash` gadget it uses for the leaf path — Poseidon2-BN254
/// (`stwo-gnark-tzel/verifier/circuit_verifier_chip.go` `outputHash`, the only
/// OutHash gadget, called at the mv-root level `:912-915` on
/// `inputs.TreeRoots[Preprocessed]` + `inputs.Claim.OutputValues`). So the
/// final OutHash uses Poseidon2, IDENTICAL to [`compute_expected_out_hash`].
///
/// IMPORTANT: only this FINAL hash is Poseidon2. The tree-fold steps that build
/// the mv root's `output_values` (`parent.output_values = blake_m31(childL.root
/// ‖ childL.ov ‖ childR.root ‖ childR.ov)`, see [`compute_mv_output_values`])
/// STAY blake2s — they are upstream `circuit_multiverifier` `set_outputs` and
/// are unchanged by item-D.
///
/// The mv claim has exactly 2 output values and NO trailing `U_VALUE`
/// (see module docs) — the sponge absorbs `Fr(root) ‖ 8 M31 lanes`.
pub fn compute_expected_out_hash_mv(
    preprocessed_root: &[u8; 32],
    root_output_lanes: &[u32; 8],
) -> [u32; OUT_HASH_LANES] {
    crate::poseidon2_bn254::out_hash_poseidon2(preprocessed_root, root_output_lanes)
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

/// The Option E precompile, **mv mode**: verify a Groth16-wrapped TzEL
/// multiverifier ROOT proof and bind it to the root's two children
/// (their preprocessed roots + claim outputs).
///
/// Steps (a) and (c) are as in [`verify_snark`]; step (b) re-derives
/// `OutHash` through the aggregation-tree chain
/// ([`compute_mv_output_values`] one level up from the children, then
/// [`compute_expected_out_hash_mv`] with `TreeRoots[0]`). On success
/// returns the validated root `output_values` lanes — the binding anchor
/// for walking further down the tree (children-of-children → … → per-leaf
/// `(program_hash, public_outputs)`; that walk is pure
/// [`compute_mv_output_values`] recursion plus the leaf-mode stage-1
/// derivation and needs no further SNARK material).
pub fn verify_snark_mv(
    proof_bytes: &[u8],
    left_child: &MvNodePublics,
    right_child: &MvNodePublics,
) -> Result<[u32; 8], String> {
    verify_snark_mv_with_vk(proof_bytes, left_child, right_child, WRAP_VK_BYTES)
}

/// [`verify_snark_mv`] with an explicit gnark VK (testing / VK rotation).
pub fn verify_snark_mv_with_vk(
    proof_bytes: &[u8],
    left_child: &MvNodePublics,
    right_child: &MvNodePublics,
    vk_bytes: &[u8],
) -> Result<[u32; 8], String> {
    let envelope = parse_snark_proof_envelope(proof_bytes)?;
    left_child.check_m31()?;
    right_child.check_m31()?;

    // (a) Groth16 verification on the chip's public inputs.
    verify_groth16_wrap_with_vk(
        envelope.gnark_proof_bytes,
        &envelope.tree_roots,
        &envelope.out_hash_lanes,
        vk_bytes,
    )
    .map_err(|e| format!("groth16 wrap verification failed: {e}"))?;

    // (b) + (c) OutHash binding through the mv derivation chain.
    let root_output_lanes = compute_mv_output_values(left_child, right_child);
    let expected = compute_expected_out_hash_mv(&envelope.tree_roots[0], &root_output_lanes);
    if expected != envelope.out_hash_lanes {
        return Err(format!(
            "mv children do not match proof OutHash: expected lanes {:?}, proof carries {:?}",
            expected, envelope.out_hash_lanes
        ));
    }

    Ok(root_output_lanes)
}

/// The Option E precompile, **tree mode** — the full
/// `docs/SNARK-SUBMISSION-DESIGN.md` verification walk: bind a
/// Groth16-wrapped mv ROOT proof all the way down to the declared leaves'
/// bootloader `output_preimage`s.
///
/// Steps:
/// (a) Groth16 verification on the envelope publics;
/// (b) tree walk ([`derive_mv_root_publics`]): junction-derive every
///     `Declared` leaf from its preimage, take `Opaque` lanes as-is,
///     fold pairwise to the root;
/// (c) circuit-identity check: the derived root's preprocessed root must
///     BE the proof's `TreeRoots[0]` — the wrapped statement is the
///     expected mv circuit, not some other circuit with colliding outputs;
/// (d) OutHash binding: `blake_m31(TreeRoots[0] ‖ root.output_values)`
///     must equal the proof's `OutHash`.
///
/// On success returns the validated root output lanes. Any change to a
/// declared leaf's preimage, an opaque slot, or a tree constant breaks
/// (c)/(d) or the Groth16 publics.
pub fn verify_snark_tree(
    proof_bytes: &[u8],
    leaf_preprocessed_root_lanes: [u32; 8],
    internal_preprocessed_root_lanes: &[[u32; 8]],
    slots: &[MvLeafSlot<'_>],
) -> Result<[u32; 8], String> {
    verify_snark_tree_with_vk(
        proof_bytes,
        leaf_preprocessed_root_lanes,
        internal_preprocessed_root_lanes,
        slots,
        WRAP_VK_BYTES,
    )
}

/// [`verify_snark_tree`] with an explicit gnark VK (testing / VK rotation).
pub fn verify_snark_tree_with_vk(
    proof_bytes: &[u8],
    leaf_preprocessed_root_lanes: [u32; 8],
    internal_preprocessed_root_lanes: &[[u32; 8]],
    slots: &[MvLeafSlot<'_>],
    vk_bytes: &[u8],
) -> Result<[u32; 8], String> {
    let envelope = parse_snark_proof_envelope(proof_bytes)?;

    // (a) Groth16 verification on the chip's public inputs.
    verify_groth16_wrap_with_vk(
        envelope.gnark_proof_bytes,
        &envelope.tree_roots,
        &envelope.out_hash_lanes,
        vk_bytes,
    )
    .map_err(|e| format!("groth16 wrap verification failed: {e}"))?;

    // (b) Tree walk: leaves (junction-derived or opaque) → root publics.
    let root = derive_mv_root_publics(
        leaf_preprocessed_root_lanes,
        internal_preprocessed_root_lanes,
        slots,
    )?;

    // (c) Circuit identity: the derived root must be the proof's TreeRoots[0].
    if root_lanes_to_bytes(&root.preprocessed_root_lanes) != envelope.tree_roots[0] {
        return Err(
            "mv tree root preprocessed_root does not match proof TreeRoots[0]".to_string(),
        );
    }

    // (d) OutHash binding.
    let expected = compute_expected_out_hash_mv(&envelope.tree_roots[0], &root.output_lanes);
    if expected != envelope.out_hash_lanes {
        return Err(format!(
            "mv tree does not match proof OutHash: expected lanes {:?}, proof carries {:?}",
            expected, envelope.out_hash_lanes
        ));
    }

    Ok(root.output_lanes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::qm31::QM31;

    /// The pinned circuit-identity constants must stay byte-identical to
    /// the golden fixture tree (`testdata/mv_root_children.json`) — when
    /// the circuit stack is regenerated and the fixture re-captured, this
    /// test forces the constants (and the TzEL release pin) to follow.
    #[test]
    fn pinned_circuit_roots_match_golden_fixture() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/mv_root_children.json")).unwrap();
        let lanes8 = |v: &serde_json::Value| -> [u32; 8] {
            v.as_array()
                .unwrap()
                .iter()
                .map(|x| u32::try_from(x.as_u64().unwrap()).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        };
        let node = |label: &str| -> serde_json::Value {
            doc["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["label"] == label)
                .unwrap_or_else(|| panic!("{label} node in mv_root_children.json"))
                .clone()
        };

        // Leaf circuit identity: identical for shield (leaf_to_mv_0) and
        // transfer (leaf_to_mv_1) leaves, left and right.
        for label in ["leaf_to_mv_0", "leaf_to_mv_1"] {
            let n = node(label);
            for side in ["left", "right"] {
                assert_eq!(
                    lanes8(&n[side]["preprocessed_root_lanes"]),
                    LEAF_CIRCUIT_ROOT_LANES,
                    "{label}.{side} leaf circuit root"
                );
            }
        }
        assert_eq!(
            lanes8(&node("leaf_to_mv_0")["parent_preprocessed_root_lanes"]),
            LEAF_TO_MV_CIRCUIT_ROOT_LANES,
        );
        assert_eq!(
            lanes8(&node("mv_to_mv_root")["parent_preprocessed_root_lanes"]),
            MV_TO_MV_CIRCUIT_ROOT_LANES,
        );
    }

    #[test]
    fn pinned_internal_root_lanes_levels() {
        assert!(pinned_internal_root_lanes(0).is_err());
        assert_eq!(
            pinned_internal_root_lanes(1).unwrap(),
            vec![LEAF_TO_MV_CIRCUIT_ROOT_LANES]
        );
        assert_eq!(
            pinned_internal_root_lanes(4).unwrap(),
            vec![
                LEAF_TO_MV_CIRCUIT_ROOT_LANES,
                MV_TO_MV_CIRCUIT_ROOT_LANES,
                MV_TO_MV_CIRCUIT_ROOT_LANES,
                MV_TO_MV_CIRCUIT_ROOT_LANES
            ]
        );
    }

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

    /// Golden vector for the full two-stage mv-target derivation. Stage 1
    /// (blake2s: felt encoding, inner blake, 9-bit limb split, QM31 packing,
    /// M31 lane reduction) is unchanged. Stage 2 is the item-D Poseidon2-BN254
    /// `outputHash` (root Fr ‖ 2 output_values' M31 limbs → t=3 rate-1 sponge →
    /// frToM31Lanes); NO U_VALUE.
    ///
    /// The expected 8 lanes are the Go off-circuit `offcircuit.OutHashPoseidon2`
    /// for `root = ae20…e433` (big-endian, reduced mod r) + the Stage-1 lanes
    /// from `output_hash_values_golden_vector`. Regenerate via the Go harness
    /// `channel/offcircuit/outhash_golden_print_test.go` (case "snarkrs").
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
                1272457859, 1685065576, 251687680, 707557363, 1129927841, 850660069, 2022909033,
                22565545
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

    /// mv-mode FINAL OutHash (item-D Poseidon2-BN254) pinned by the REAL
    /// 2026-06-10 mv-target wrap fixture inputs: `TreeRoots[0]` (the fixture's
    /// preprocessed root) + the mv root proof's tree-folded `claim.output_values`
    /// (8 lanes, blake2s tree-fold, observed during the fixture export run
    /// `services/reprover/tests/export_mv_fixture.rs`, re-captured by
    /// `mv_output_derivation.rs`).
    ///
    /// The INPUTS (root + folded output lanes) are unchanged real ground truth.
    /// The expected OutHash is the **Poseidon2** result for those inputs,
    /// regenerated from the authoritative Go reference `offcircuit.OutHashPoseidon2`
    /// (harness `channel/offcircuit/outhash_golden_print_test.go`, case "mvwrap").
    ///
    /// NOTE: the fixture's own dumped `OutHash` public witness
    /// (`testdata/wrap_public_witness.txt`) is BLAKE2S-era (pre-item-D) and no
    /// longer matches this Poseidon2 derivation — that is expected. There is no
    /// item-D Poseidon2 mv wrap fixture available (the 2026-06-21 e2e-derisk
    /// proof ran with `SkipOutputHash`, so it carries no Poseidon2 OutHash), so
    /// this golden is pinned against the Go gadget, not a real item-D proof.
    #[test]
    fn mv_out_hash_matches_wrap_fixture() {
        let mut root = [0u8; 32];
        root.copy_from_slice(
            &hex::decode("0b38551b4456ef029086970a2f0ee7415a7e052ab5c5f526344ad2439942fc51")
                .unwrap(),
        );
        let root_output_lanes: [u32; 8] = [
            802081382, 416909726, 1859869728, 63892159, 106802067, 1890177931, 1827850667,
            1829696004,
        ];
        assert_eq!(
            compute_expected_out_hash_mv(&root, &root_output_lanes),
            [
                1497266488, 325154675, 946505096, 1208787576, 1466909141, 414348525, 1258147338,
                98023563
            ],
            "must match Go offcircuit.OutHashPoseidon2 for the mv wrap fixture inputs"
        );
    }

    /// mv-mode stage 1 (one multiverifier tree level) pinned by the
    /// captured golden vectors of the fixture aggregation
    /// (`testdata/mv_root_children.json`, root node — asserted off-circuit
    /// against the real `claim.output_values` during capture by
    /// `services/reprover/tests/mv_output_derivation.rs`). The expected
    /// lanes are the mv root's claim outputs, which chain into
    /// [`compute_expected_out_hash_mv`] (see
    /// `mv_out_hash_matches_wrap_fixture`).
    #[test]
    fn mv_output_values_golden_vector() {
        let left = MvNodePublics {
            preprocessed_root_lanes: [
                1329128718, 79407594, 317031791, 1097889202, 829834258, 737675984, 793553350,
                583776393,
            ],
            output_lanes: [
                1632211865, 503564493, 2081962125, 385989669, 2023033939, 827547523, 562925084,
                1455057832,
            ],
        };
        let right = MvNodePublics {
            preprocessed_root_lanes: left.preprocessed_root_lanes,
            output_lanes: [
                1405712821, 543965878, 942313946, 142366770, 1542713610, 901705420, 1935673009,
                587138056,
            ],
        };
        assert_eq!(
            compute_mv_output_values(&left, &right),
            [
                802081382, 416909726, 1859869728, 63892159, 106802067, 1890177931, 1827850667,
                1829696004
            ],
            "must match the mv root proof's claim.output_values"
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
