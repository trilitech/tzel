//! Commitment-aware Groth16 BN254 verifier for **gnark** proofs (Track B
//! phase 2 — TzEL kernel precompile primitive).
//!
//! Port of the phase-1 PoC (`stwo-gnark-tzel/tools/groth16-verifier-poc`)
//! with the `gnark-arkworks-adapter` conversion code inlined. The byte
//! formats and the verification algorithm are documented inline against
//! gnark v0.14.0 / gnark-crypto sources.
//!
//! # Why plain `ark_groth16::verify` is not enough
//!
//! The TzEL wrap circuit uses gnark's `frontend.Commit` (BSB22 commitments),
//! so its proofs carry extra elements (`Commitments []G1`, `CommitmentPok G1`)
//! and its VK carries Pedersen `CommitmentKeys` + the
//! `PublicAndCommitmentCommitted` index table. gnark's `Verify`
//! (gnark@v0.14.0 `backend/groth16/bn254/verify.go:38-137`) augments the
//! public-input vector with one hash-derived scalar per commitment and folds
//! the commitment points into the `Σ x_i·K_i` term of the pairing equation:
//!
//! 1. `nbPublicVars = len(vk.G1.K) - len(vk.PublicAndCommitmentCommitted)`;
//!    the caller-supplied public witness must have `nbPublicVars - 1`
//!    elements (the constant ONE wire is implicit). (verify.go:47-51)
//! 2. For each commitment `i` (verify.go:77-95, "solveCommitmentWire"):
//!    `prehash = proof.Commitments[i].Marshal()` (uncompressed
//!    `X_BE_32 || Y_BE_32`, 64 bytes) followed by the 32-byte BE `Marshal()`
//!    of each committed *public* wire in `PublicAndCommitmentCommitted[i]`;
//!    `res = fr.Hash(prehash, "bsb22-commitment", 1)` (RFC 9380
//!    `expand_message_xmd` over SHA-256, `L = 48`, big-endian reduce mod r);
//!    `publicWitness.append(res)`.
//! 3. Proof-of-knowledge check (verify.go:96-104): with
//!    `challenge = fr.Hash(res_0.Marshal() || ..., "G16-BSB22", 1)`, run
//!    gnark-crypto `pedersen.BatchVerifyMultiVk` (`pedersen.go:226-276`).
//! 4. Pairing equation (verify.go:106-133):
//!    `kSum = K[0] + Σ publicWitness[i]·K[i+1] + Σ Commitments[i]`,
//!    then check `e(Ar, Bs) · e(Krs, -δ) · e(kSum, -γ) == e(α, β)`.
//!
//! # Public input layout of the TzEL wrap circuit (item-D ABI)
//!
//! The wrap circuit (`stwo-gnark-tzel/cmd/measure_circuit_verifier/main.go`,
//! `BenchCircuit`, populated by `BuildBenchCircuitBn254`) declares exactly
//! two public fields, in this order:
//!
//! ```text
//! TreeRoots [4]fri.Bn254Element  `gnark:",public"`   // first declared field
//! ...all-secret fields...
//! OutHash   [2]m31.QM31          `gnark:",public"`   // last declared field
//! ```
//!
//! `fri.Bn254Element = frontend.Variable` (a single BN254 scalar) and
//! `m31.QM31 = {AReal, AImag, BReal, BImag}` (4 M31 lanes). gnark orders the
//! public witness by struct-field declaration order (depth-first), so the 12
//! public scalars are:
//!
//! * indices `0..4`: `TreeRoots[t]` for `t in 0..4` — each Merkle root is a
//!   single BN254 `Fr` scalar (tree order: 0=preprocessed, 1=trace,
//!   2=interaction, 3=composition);
//! * indices `4..12`: the 8 M31 lanes of `OutHash[0]`, `OutHash[1]`
//!   (per QM31: `AReal, AImag, BReal, BImag`).
//!
//! With the 1-commitment BSB22 wrap, the VK therefore has
//! `1 (ONE) + 12 (publics) + 1 (commitment) = 14` K-points.
//!
//! ## item-D change (was: 136-input blake2s ABI)
//!
//! Prior to item-D the wrap circuit declared `TreeRoots [4][32]uints.U8`
//! (`TreeRoots[t][b]` = one field element per root BYTE → 128 scalars) and a
//! blake2s `OutHash`, for `128 + 8 = 136` public scalars and a 138-K-point VK.
//! The item-D wrap changed `TreeRoots[t]` to a single BN254 `Fr` (4 scalars)
//! and `OutHash` to the Poseidon2-BN254 gadget. This module's public-witness
//! construction follows: each `TreeRoots[t]` is fed as ONE `Fr` scalar
//! (`Fr::from_be_bytes_mod_order` of the 32 big-endian root bytes — the gnark
//! `fr.Element.SetBytes` wire encoding), not 32 byte-scalars. The `tree_roots`
//! API/envelope still carries the 32 big-endian bytes of each root Fr; that is
//! also exactly what the Poseidon2 `outputHash` derivation absorbs
//! (`poseidon2_bn254::out_hash_poseidon2`), so the OutHash binding path is
//! unchanged.
//!
//! This ordering was confirmed against the dumped gnark public witness of the
//! item-D `BuildBenchCircuitBn254` wrap (`testdata/wrap_public_witness.txt`,
//! 12 lines): the first 4 values are the `Fr` roots, the last 8 the OutHash
//! lanes — the EXACT public witness the `/tmp/wrap-ceremony` sound proof was
//! proven for.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use sha2::{Digest, Sha256};

/// The embedded gnark verifying key for the TzEL wrap circuit
/// (`VerifyingKey.WriteRawTo` bytes).
///
/// This is the **item-D** Poseidon2-BN254 wrap VK (`/tmp/wrap-ceremony/vk.bin`,
/// 1744 bytes, 14 K points = `1 (ONE) + 12 public scalars + 1 commitment`),
/// matching the `BuildBenchCircuitBn254` public ABI (4 `TreeRoots` Fr scalars
/// + 8 `OutHash` lanes). The pinned `/tmp/wrap-ceremony` proof verifies in
/// gnark against this VK (skips=false, `TestMpcCeremonyProveVerify`).
pub const WRAP_VK_BYTES: &[u8] = include_bytes!("wrap_vk.bin");

/// Number of lifted Merkle trees committed by the wrap circuit
/// (preprocessed, trace, interaction, composition).
pub const N_TREES: usize = 4;
/// Number of M31 lanes in the wrap circuit's `OutHash` public output
/// (2 QM31s × 4 lanes).
pub const OUT_HASH_LANES: usize = 8;
/// Total number of gnark public scalars (item-D ABI): 4 `TreeRoots` Fr
/// scalars + 8 `OutHash` lanes = 12.
pub const N_PUBLIC_INPUTS: usize = N_TREES + OUT_HASH_LANES;

/// Domain separation tag used by gnark to hash a BSB22 commitment into a
/// public-input scalar (`constraint.CommitmentDst`,
/// gnark `constraint/commitment.go:7`).
const COMMITMENT_DST: &[u8] = b"bsb22-commitment";

/// Domain separation tag used by gnark to derive the PoK folding challenge
/// (gnark `backend/groth16/bn254/verify.go:97`).
const POK_FOLD_DST: &[u8] = b"G16-BSB22";

/// `L` parameter of RFC 9380 hash-to-field for BN254 Fr at 128-bit security:
/// `L = ceil((ceil(log2(r)) + k) / 8) = 16 + 32 = 48`
/// (gnark-crypto `ecc/bn254/fr/element.go:722` `fr.Hash`).
const HASH_TO_FIELD_L: usize = 48;

/// Errors of the gnark byte-format parser and the Groth16 verifier.
///
/// Hand-rolled `Display` (no `thiserror`) to stay kernel/wasm-friendly and
/// match the host crate's `String`-based error convention at the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Input shorter than the structured decode expects.
    Truncated { needed: usize, have: usize },
    /// A point did not carry gnark's uncompressed flag (top bits 0b00).
    NotUncompressed { got: u8 },
    /// A parsed point is not a valid BN254 group element.
    InvalidPoint { where_: &'static str },
    /// Trailing bytes after a structured decode.
    TrailingBytes { where_: &'static str, extra: usize },
    /// A u32 length field overflows the remaining buffer.
    LengthOverflow { len: u32, remaining: usize },
    /// Public witness size does not match the VK.
    PublicWitnessSize { got: usize, expected: usize },
    /// Proof/VK commitment counts disagree.
    CommitmentCountMismatch { proof: usize, vk: usize },
    /// Proof carries commitments but no proof of knowledge.
    MissingPok,
    /// A committed public wire index is out of range.
    CommittedIndexOutOfRange { index: u64, len: usize },
    /// Commitment keys use different G2 generators (unsupported fold).
    MismatchedCommitmentG2,
    /// The Pedersen proof-of-knowledge pairing check failed.
    PokCheckFailed,
    /// The final Groth16 pairing equation does not hold.
    ProofRejected,
    /// arkworks synthesis error (malformed prepared inputs).
    Synthesis,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { needed, have } => {
                write!(f, "input truncated: needed {needed} bytes, have {have}")
            }
            Self::NotUncompressed { got } => {
                write!(f, "expected gnark uncompressed-point flag, got 0b{got:02b}")
            }
            Self::InvalidPoint { where_ } => {
                write!(f, "invalid BN254 group element in {where_}")
            }
            Self::TrailingBytes { where_, extra } => {
                write!(f, "trailing bytes ({extra}) after decoding {where_}")
            }
            Self::LengthOverflow { len, remaining } => {
                write!(f, "length field {len} overflows remaining buffer ({remaining})")
            }
            Self::PublicWitnessSize { got, expected } => {
                write!(f, "public witness size {got}, expected {expected}")
            }
            Self::CommitmentCountMismatch { proof, vk } => {
                write!(f, "commitment count mismatch: proof {proof}, vk {vk}")
            }
            Self::MissingPok => write!(f, "proof carries commitments but no proof of knowledge"),
            Self::CommittedIndexOutOfRange { index, len } => {
                write!(f, "committed public wire index {index} out of range (len {len})")
            }
            Self::MismatchedCommitmentG2 => {
                write!(f, "commitment keys use different G2 generators")
            }
            Self::PokCheckFailed => write!(f, "Pedersen proof-of-knowledge check failed"),
            Self::ProofRejected => write!(f, "Groth16 pairing equation does not hold"),
            Self::Synthesis => write!(f, "Groth16 synthesis error"),
        }
    }
}

// ----------------------------------------------------------------------------
// gnark wire format → arkworks types (inlined gnark-arkworks-adapter)
// ----------------------------------------------------------------------------
//
// * gnark stores `Fq` coordinates **big-endian**; arkworks expects LE.
// * gnark encodes flag bits in the top 2 bits of the **first** byte of X;
//   `WriteRawTo` always uses mUncompressed (0b00).
// * G2 limb order is `[X.A1, X.A0, Y.A1, Y.A0]` in gnark vs c0-first in
//   arkworks.
//
// References: gnark-crypto `ecc/bn254/marshal.go:554` (`encodeRaw`), `:771`
// (`G1Affine.RawBytes`), `:1023` (`G2Affine.RawBytes`).

const FQ_BYTES: usize = 32;
const G1_UNCOMPRESSED: usize = 2 * FQ_BYTES;
const G2_UNCOMPRESSED: usize = 4 * FQ_BYTES;

const GNARK_MASK_BITS: u8 = 0b1100_0000;
const GNARK_M_UNCOMPRESSED: u8 = 0b00 << 6;
const GNARK_M_COMPRESSED_INFINITY: u8 = 0b01 << 6;

/// Full content of a gnark `groth16/bn254` proof, including the BSB22
/// Pedersen commitments and their (folded) proof of knowledge.
#[derive(Clone, Debug)]
pub struct GnarkProof {
    pub proof: Proof<Bn254>,
    pub commitments: Vec<G1Affine>,
    pub commitment_pok: Option<G1Affine>,
}

/// One gnark `pedersen.VerifyingKey`: `G` and `GSigmaNeg = -σ·G`
/// (serialized in this order by `pedersen.VerifyingKey.writeTo`,
/// gnark-crypto `fr/pedersen/pedersen.go:323`).
#[derive(Clone, Debug)]
pub struct PedersenVerifyingKey {
    pub g: G2Affine,
    pub g_sigma_neg: G2Affine,
}

/// Full content of a gnark `groth16/bn254` verifying key.
#[derive(Clone, Debug)]
pub struct GnarkVerifyingKey {
    pub vk: VerifyingKey<Bn254>,
    pub public_and_commitment_committed: Vec<Vec<u64>>,
    pub commitment_keys: Vec<PedersenVerifyingKey>,
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
    fn read(&mut self, n: usize) -> Result<&'a [u8], VerifyError> {
        if self.remaining() < n {
            return Err(VerifyError::Truncated {
                needed: n,
                have: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn read_u32_be(&mut self) -> Result<u32, VerifyError> {
        let b = self.read(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

fn reverse_into(src: &[u8], dst: &mut [u8; FQ_BYTES]) {
    for (i, b) in src.iter().rev().enumerate() {
        dst[i] = *b;
    }
}

/// Convert one gnark-uncompressed G1 (64 bytes, `X_BE_32 || Y_BE_32`) into an
/// arkworks `G1Affine`, with on-curve + subgroup checks (matching gnark's
/// `proof.isValid()` semantics).
fn read_g1(cur: &mut Cursor<'_>, where_: &'static str) -> Result<G1Affine, VerifyError> {
    let buf = cur.read(G1_UNCOMPRESSED)?;
    let flag = buf[0] & GNARK_MASK_BITS;
    if flag != GNARK_M_UNCOMPRESSED {
        if flag == GNARK_M_COMPRESSED_INFINITY {
            return Ok(G1Affine::identity());
        }
        return Err(VerifyError::NotUncompressed { got: flag >> 6 });
    }

    let mut x_be = [0u8; FQ_BYTES];
    x_be.copy_from_slice(&buf[..FQ_BYTES]);
    x_be[0] &= !GNARK_MASK_BITS;
    let mut x_le = [0u8; FQ_BYTES];
    let mut y_le = [0u8; FQ_BYTES];
    reverse_into(&x_be, &mut x_le);
    reverse_into(&buf[FQ_BYTES..G1_UNCOMPRESSED], &mut y_le);

    let x = Fq::from_le_bytes_mod_order(&x_le);
    let y = Fq::from_le_bytes_mod_order(&y_le);

    // gnark RawBytes encodes infinity as all-zero coordinates.
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::identity());
    }

    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VerifyError::InvalidPoint { where_ });
    }
    Ok(p)
}

/// Convert one gnark-uncompressed G2 (128 bytes,
/// `X.A1_BE || X.A0_BE || Y.A1_BE || Y.A0_BE`) into an arkworks `G2Affine`.
fn read_g2(cur: &mut Cursor<'_>, where_: &'static str) -> Result<G2Affine, VerifyError> {
    let buf = cur.read(G2_UNCOMPRESSED)?;
    let flag = buf[0] & GNARK_MASK_BITS;
    if flag != GNARK_M_UNCOMPRESSED {
        if flag == GNARK_M_COMPRESSED_INFINITY {
            return Ok(G2Affine::identity());
        }
        return Err(VerifyError::NotUncompressed { got: flag >> 6 });
    }

    let mut x_a1_be = [0u8; FQ_BYTES];
    x_a1_be.copy_from_slice(&buf[0..FQ_BYTES]);
    x_a1_be[0] &= !GNARK_MASK_BITS;

    let mut x_a1_le = [0u8; FQ_BYTES];
    let mut x_a0_le = [0u8; FQ_BYTES];
    let mut y_a1_le = [0u8; FQ_BYTES];
    let mut y_a0_le = [0u8; FQ_BYTES];
    reverse_into(&x_a1_be, &mut x_a1_le);
    reverse_into(&buf[FQ_BYTES..2 * FQ_BYTES], &mut x_a0_le);
    reverse_into(&buf[2 * FQ_BYTES..3 * FQ_BYTES], &mut y_a1_le);
    reverse_into(&buf[3 * FQ_BYTES..4 * FQ_BYTES], &mut y_a0_le);

    let x_c0 = Fq::from_le_bytes_mod_order(&x_a0_le);
    let x_c1 = Fq::from_le_bytes_mod_order(&x_a1_le);
    let y_c0 = Fq::from_le_bytes_mod_order(&y_a0_le);
    let y_c1 = Fq::from_le_bytes_mod_order(&y_a1_le);

    if x_c0.is_zero() && x_c1.is_zero() && y_c0.is_zero() && y_c1.is_zero() {
        return Ok(G2Affine::identity());
    }

    let p = G2Affine::new_unchecked(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1));
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VerifyError::InvalidPoint { where_ });
    }
    Ok(p)
}

/// Parse gnark `groth16/bn254.Proof.WriteRawTo` bytes:
/// `Ar:G1 || Bs:G2 || Krs:G1 || u32_BE(n) || Commitments:[n]G1 || CommitmentPok:G1`.
pub fn parse_gnark_proof(gnark_bytes: &[u8]) -> Result<GnarkProof, VerifyError> {
    let mut cur = Cursor::new(gnark_bytes);
    let ar = read_g1(&mut cur, "proof.Ar")?;
    let bs = read_g2(&mut cur, "proof.Bs")?;
    let krs = read_g1(&mut cur, "proof.Krs")?;
    let n_commitments = cur.read_u32_be()?;
    if (n_commitments as usize)
        .checked_mul(G1_UNCOMPRESSED)
        .is_none_or(|n| n > cur.remaining())
    {
        return Err(VerifyError::LengthOverflow {
            len: n_commitments,
            remaining: cur.remaining(),
        });
    }
    let mut commitments = Vec::with_capacity(n_commitments as usize);
    for _ in 0..n_commitments {
        commitments.push(read_g1(&mut cur, "proof.Commitments[i]")?);
    }
    let commitment_pok = if n_commitments > 0 {
        Some(read_g1(&mut cur, "proof.CommitmentPok")?)
    } else {
        None
    };
    if !cur.is_empty() {
        return Err(VerifyError::TrailingBytes {
            where_: "proof",
            extra: cur.remaining(),
        });
    }
    Ok(GnarkProof {
        proof: Proof { a: ar, b: bs, c: krs },
        commitments,
        commitment_pok,
    })
}

/// Parse gnark `groth16/bn254.VerifyingKey.WriteRawTo` bytes:
/// `G1.Alpha || G1.Beta || G2.Beta || G2.Gamma || G1.Delta || G2.Delta ||
///  u32_BE(k) || K:[k]G1 || u32_BE(outer)(u32_BE(inner)[inner]u64_BE)* ||
///  u32_BE(n_keys) || (G2 || G2)*n_keys`.
pub fn parse_gnark_vk(gnark_bytes: &[u8]) -> Result<GnarkVerifyingKey, VerifyError> {
    let mut cur = Cursor::new(gnark_bytes);
    let alpha_g1 = read_g1(&mut cur, "vk.G1.Alpha")?;
    let _g1_beta = read_g1(&mut cur, "vk.G1.Beta")?; // unused on arkworks
    let beta_g2 = read_g2(&mut cur, "vk.G2.Beta")?;
    let gamma_g2 = read_g2(&mut cur, "vk.G2.Gamma")?;
    let _g1_delta = read_g1(&mut cur, "vk.G1.Delta")?; // unused on arkworks
    let delta_g2 = read_g2(&mut cur, "vk.G2.Delta")?;

    let k_len = cur.read_u32_be()?;
    if (k_len as usize)
        .checked_mul(G1_UNCOMPRESSED)
        .is_none_or(|n| n > cur.remaining())
    {
        return Err(VerifyError::LengthOverflow {
            len: k_len,
            remaining: cur.remaining(),
        });
    }
    let mut gamma_abc_g1 = Vec::with_capacity(k_len as usize);
    for _ in 0..k_len {
        gamma_abc_g1.push(read_g1(&mut cur, "vk.G1.K[i]")?);
    }

    // PublicAndCommitmentCommitted: [u32 outer]([u32 inner][u64 BE]*)*.
    let outer = cur.read_u32_be()?;
    let mut public_and_commitment_committed = Vec::with_capacity(outer as usize);
    for _ in 0..outer {
        let inner = cur.read_u32_be()?;
        if (inner as usize)
            .checked_mul(8)
            .is_none_or(|n| n > cur.remaining())
        {
            return Err(VerifyError::LengthOverflow {
                len: inner,
                remaining: cur.remaining(),
            });
        }
        let mut indices = Vec::with_capacity(inner as usize);
        for _ in 0..inner {
            let b = cur.read(8)?;
            indices.push(u64::from_be_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]));
        }
        public_and_commitment_committed.push(indices);
    }

    // CommitmentKeys: u32 n_keys, then (G, GSigmaNeg) per key.
    let n_keys = cur.read_u32_be()?;
    let mut commitment_keys = Vec::with_capacity(n_keys as usize);
    for _ in 0..n_keys {
        let g = read_g2(&mut cur, "vk.CommitmentKeys[i].G")?;
        let g_sigma_neg = read_g2(&mut cur, "vk.CommitmentKeys[i].GSigmaNeg")?;
        commitment_keys.push(PedersenVerifyingKey { g, g_sigma_neg });
    }

    if !cur.is_empty() {
        return Err(VerifyError::TrailingBytes {
            where_: "vk",
            extra: cur.remaining(),
        });
    }

    Ok(GnarkVerifyingKey {
        vk: VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        },
        public_and_commitment_committed,
        commitment_keys,
    })
}

// ----------------------------------------------------------------------------
// gnark commitment-aware Groth16 verification
// ----------------------------------------------------------------------------

/// Verify a gnark Groth16 BN254 proof (possibly carrying BSB22 commitments)
/// against its gnark VK and the public inputs, replicating gnark's
/// `groth16.Verify` (gnark@v0.14.0 `backend/groth16/bn254/verify.go`).
///
/// `public_inputs` is the public witness in gnark order (struct-field
/// declaration order, depth first), **without** the constant ONE wire and
/// **without** the commitment wire(s).
pub fn verify_gnark_proof(
    proof: &GnarkProof,
    vk: &GnarkVerifyingKey,
    public_inputs: &[Fr],
) -> Result<(), VerifyError> {
    // verify.go:47-51 — witness size check. One K point per public wire
    // (incl. ONE) plus one per commitment.
    let nb_public_vars = vk
        .vk
        .gamma_abc_g1
        .len()
        .saturating_sub(vk.public_and_commitment_committed.len());
    let expected = nb_public_vars.saturating_sub(1);
    if public_inputs.len() != expected {
        return Err(VerifyError::PublicWitnessSize {
            got: public_inputs.len(),
            expected,
        });
    }
    if proof.commitments.len() != vk.commitment_keys.len()
        || proof.commitments.len() != vk.public_and_commitment_committed.len()
    {
        return Err(VerifyError::CommitmentCountMismatch {
            proof: proof.commitments.len(),
            vk: vk.commitment_keys.len(),
        });
    }

    // verify.go:71-95 — solveCommitmentWire: fold each commitment into one
    // extra public-input scalar via hash-to-field.
    let mut public_witness: Vec<Fr> = public_inputs.to_vec();
    let mut commitments_serialized: Vec<u8> =
        Vec::with_capacity(32 * vk.public_and_commitment_committed.len());
    for (i, committed) in vk.public_and_commitment_committed.iter().enumerate() {
        let mut prehash = gnark_marshal_g1_uncompressed(&proof.commitments[i]).to_vec();
        for &j in committed {
            // gnark indexes committed public wires 1-based (ONE wire = 0).
            let idx = (j as usize)
                .checked_sub(1)
                .filter(|&k| k < public_witness.len())
                .ok_or(VerifyError::CommittedIndexOutOfRange {
                    index: j,
                    len: public_witness.len(),
                })?;
            prehash.extend_from_slice(&fr_to_be_bytes(&public_witness[idx]));
        }
        let res = hash_to_fr(&prehash, COMMITMENT_DST);
        public_witness.push(res);
        commitments_serialized.extend_from_slice(&fr_to_be_bytes(&res));
    }

    // verify.go:96-104 — Pedersen proof-of-knowledge (BatchVerifyMultiVk).
    if !vk.commitment_keys.is_empty() {
        let challenge = hash_to_fr(&commitments_serialized, POK_FOLD_DST);
        let pok = proof.commitment_pok.ok_or(VerifyError::MissingPok)?;
        verify_pok(vk, &proof.commitments, &pok, challenge)?;
    }

    // verify.go:106-133 — augmented pairing equation. `prepare_inputs`
    // computes K[0] + Σ publicWitness[i]·K[i+1]; we then add the commitment
    // points (verify.go:113-115) before the final check
    // e(Ar,Bs)·e(Krs,-δ)·e(kSum,-γ) == e(α,β).
    let pvk = ark_groth16::prepare_verifying_key(&vk.vk);
    let mut prepared: G1Projective = Groth16::<Bn254>::prepare_inputs(&pvk, &public_witness)
        .map_err(|_| VerifyError::Synthesis)?;
    for c in &proof.commitments {
        prepared += c;
    }
    match Groth16::<Bn254>::verify_proof_with_prepared_inputs(&pvk, &proof.proof, &prepared) {
        Ok(true) => Ok(()),
        Ok(false) => Err(VerifyError::ProofRejected),
        Err(_) => Err(VerifyError::Synthesis),
    }
}

/// Verify a gnark wrap-circuit proof against the **embedded** wrap VK
/// ([`WRAP_VK_BYTES`]) and the wrap circuit's public inputs:
///
/// * `gnark_proof_bytes` — raw `Proof.WriteRawTo` bytes;
/// * `tree_roots` — the 4 lifted Merkle roots (32 raw bytes each), tree
///   order `preprocessed, trace, interaction, composition`;
/// * `out_hash_lanes` — the 8 M31 lanes of `OutHash[0..2]`
///   (per QM31: `AReal, AImag, BReal, BImag`).
///
/// Builds the 12 public scalars in the gnark declaration order documented
/// at the top of this module (4 `TreeRoots` Fr scalars, then the 8 OutHash
/// lanes) and runs the commitment-aware verification.
pub fn verify_groth16_wrap(
    gnark_proof_bytes: &[u8],
    tree_roots: &[[u8; 32]; N_TREES],
    out_hash_lanes: &[u32; OUT_HASH_LANES],
) -> Result<(), VerifyError> {
    verify_groth16_wrap_with_vk(gnark_proof_bytes, tree_roots, out_hash_lanes, WRAP_VK_BYTES)
}

/// [`verify_groth16_wrap`] with an explicit VK (testing / future VK rotation).
pub fn verify_groth16_wrap_with_vk(
    gnark_proof_bytes: &[u8],
    tree_roots: &[[u8; 32]; N_TREES],
    out_hash_lanes: &[u32; OUT_HASH_LANES],
    vk_bytes: &[u8],
) -> Result<(), VerifyError> {
    let proof = parse_gnark_proof(gnark_proof_bytes)?;
    let vk = parse_gnark_vk(vk_bytes)?;

    let mut publics: Vec<Fr> = Vec::with_capacity(N_PUBLIC_INPUTS);
    // item-D ABI: each TreeRoots[t] is ONE BN254 Fr scalar. The 32 root bytes
    // are its big-endian wire encoding (gnark `fr.Element.SetBytes`), so we
    // reduce them mod r — identical to how `out_hash_poseidon2` absorbs the
    // root, keeping the public witness and the OutHash derivation consistent.
    for root in tree_roots {
        publics.push(Fr::from_be_bytes_mod_order(root));
    }
    for &lane in out_hash_lanes {
        publics.push(Fr::from(lane as u64));
    }

    verify_gnark_proof(&proof, &vk, &publics)
}

/// gnark-crypto `pedersen.BatchVerifyMultiVk`
/// (`ecc/bn254/fr/pedersen/pedersen.go:226-276`) with a single folded PoK:
///
/// `e(C_0, -σ_0 G) · e(r·C_1, -σ_1 G) · ... · e(foldedPok, G) == 1`
///
/// where `r = challenge` and `foldedPok = Σ r^i · pok_i` — gnark proofs ship
/// one already-folded PoK, so `foldedPok = pok`.
fn verify_pok(
    vk: &GnarkVerifyingKey,
    commitments: &[G1Affine],
    pok: &G1Affine,
    challenge: Fr,
) -> Result<(), VerifyError> {
    let n = vk.commitment_keys.len();
    // All keys must share the same G2 generator (pedersen.go:238-240).
    if !vk
        .commitment_keys
        .iter()
        .all(|k| k.g == vk.commitment_keys[0].g)
    {
        return Err(VerifyError::MismatchedCommitmentG2);
    }

    let mut g1s: Vec<G1Affine> = Vec::with_capacity(n + 1);
    let mut g2s = Vec::with_capacity(n + 1);
    let mut r = Fr::one();
    for (i, c) in commitments.iter().enumerate() {
        if i == 0 {
            g1s.push(*c);
        } else {
            r *= challenge; // r = challenge^i  (pedersen.go:250-261)
            g1s.push((c.into_group() * r).into_affine());
        }
        g2s.push(vk.commitment_keys[i].g_sigma_neg);
    }
    g1s.push(*pok);
    g2s.push(vk.commitment_keys[0].g);

    // PairingCheck == 1 in GT ⇔ additive identity of PairingOutput.
    let out = Bn254::multi_pairing(g1s.iter().map(|p| p.into_group()), g2s);
    if out.is_zero() {
        Ok(())
    } else {
        Err(VerifyError::PokCheckFailed)
    }
}

/// gnark-crypto `G1Affine.Marshal()` = `RawBytes()` (uncompressed):
/// `X_BE_32 || Y_BE_32`, flag bits `0b00` (naturally 0 for BN254 Fq).
/// Infinity encodes as 64 zero bytes.
fn gnark_marshal_g1_uncompressed(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some((x, y)) = p.xy() {
        out[..32].copy_from_slice(&x.into_bigint().to_bytes_be());
        out[32..].copy_from_slice(&y.into_bigint().to_bytes_be());
    }
    out
}

/// 32-byte big-endian encoding of an Fr element
/// (gnark-crypto `fr.Element.Marshal`, `ecc/bn254/fr/element.go:878`).
fn fr_to_be_bytes(e: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&e.into_bigint().to_bytes_be());
    out
}

/// gnark-crypto `fr.Hash(msg, dst, 1)` (`ecc/bn254/fr/element.go:722`):
/// RFC 9380 `expand_message_xmd` over SHA-256 producing `L = 48` bytes,
/// interpreted as a big-endian integer reduced mod r.
fn hash_to_fr(msg: &[u8], dst: &[u8]) -> Fr {
    let bytes = expand_msg_xmd_sha256(msg, dst, HASH_TO_FIELD_L);
    Fr::from_be_bytes_mod_order(&bytes)
}

/// RFC 9380 §5.3.1 `expand_message_xmd` with SHA-256, mirroring gnark-crypto
/// `field/hash/hashutils.go` `ExpandMsgXmd`. Panics on `len_in_bytes` or DST
/// out of spec (we only call it with in-spec constants).
fn expand_msg_xmd_sha256(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 32; // SHA-256 output
    const R_IN_BYTES: usize = 64; // SHA-256 block size
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    assert!(
        ell <= 255 && dst.len() <= 255,
        "expand_msg_xmd params out of spec"
    );

    // b0 = H(Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update([0u8; R_IN_BYTES]);
    h.update(msg);
    h.update([(len_in_bytes >> 8) as u8, len_in_bytes as u8, 0u8]);
    h.update(dst);
    h.update([dst.len() as u8]);
    let b0 = h.finalize();

    // b1 = H(b0 || I2OSP(1, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update(b0);
    h.update([1u8]);
    h.update(dst);
    h.update([dst.len() as u8]);
    let mut bi = h.finalize();

    let mut out = Vec::with_capacity(ell * B_IN_BYTES);
    out.extend_from_slice(&bi);
    for i in 2..=ell {
        // b_i = H((b0 ^ b_{i-1}) || I2OSP(i, 1) || DST_prime)
        let mut h = Sha256::new();
        let xored: Vec<u8> = b0.iter().zip(bi.iter()).map(|(a, b)| a ^ b).collect();
        h.update(&xored);
        h.update([i as u8]);
        h.update(dst);
        h.update([dst.len() as u8]);
        bi = h.finalize();
        out.extend_from_slice(&bi);
    }
    out.truncate(len_in_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9380 appendix K.1 (expand_message_xmd, SHA-256) test vectors.
    #[test]
    fn expand_msg_xmd_rfc9380_vector() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let out = expand_msg_xmd_sha256(b"", dst, 0x20);
        assert_eq!(
            hex::encode(&out),
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"
        );
        // len = 0x80 exercises the b_i chaining (ell = 4).
        let out = expand_msg_xmd_sha256(b"", dst, 0x80);
        assert!(hex::encode(&out).starts_with("af84c27ccfd45d41914fdff5df25293e"));
        let out = expand_msg_xmd_sha256(b"abc", dst, 0x20);
        assert_eq!(
            hex::encode(&out),
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
        );
    }

    /// The embedded VK must parse and carry the expected item-D wrap-circuit
    /// shape: K = 1 (ONE) + 12 public scalars + 1 commitment wire = 14 points,
    /// 1 Pedersen commitment key.
    #[test]
    fn embedded_wrap_vk_parses_with_expected_shape() {
        let vk = parse_gnark_vk(WRAP_VK_BYTES).expect("embedded wrap VK must parse");
        assert_eq!(vk.vk.gamma_abc_g1.len(), 1 + N_PUBLIC_INPUTS + 1);
        assert_eq!(vk.vk.gamma_abc_g1.len(), 14, "item-D 14-K-point VK");
        assert_eq!(vk.commitment_keys.len(), 1);
        assert_eq!(vk.public_and_commitment_committed.len(), 1);
    }
}
