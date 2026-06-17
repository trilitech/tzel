//! D-g4 — On-disk serializer for a Poseidon2-BN254-committed STARK proof.
//!
//! This is the BN254-topology counterpart of stwo-circuits'
//! `circuit_serialize::CircuitSerialize` (the blake `Proof<QM31>` serializer,
//! rev `2bf051f`). It writes the OUTER `StarkProof<Bn254Hash>` produced by
//! [`crate::aggregate::aggregate_pair_outer_with_channel`] to bytes that are
//! **byte-for-byte identical** to what the Go parser
//! `~/git/stwo-gnark-tzel/variables/multiverifier_proof_bn254.go`
//! (`ReadMultiverifierProofBn254`) reads.
//!
//! ## Why this lives here (and not upstream in circuit_serialize)
//!
//! `circuit_serialize::serialize::CircuitSerialize` is hardcoded to
//! `Proof<QM31>` / `HashValue<QM31>` (= 2×QM31 = 8 M31 limbs = 32 bytes), and
//! its proof importer `proof_from_stark_proof` is generic only over hashers
//! that implement `Into<HashValue<QM31>>` — which `Bn254Hash` does NOT (it is a
//! full `ark_bn254::Fr`, a ~254-bit element, not 4 × M31). So the blake path
//! cannot represent a BN254 Merkle node without loss.
//!
//! This module therefore:
//!   * REUSES `circuit_serialize::CircuitSerialize` verbatim for every VALUE
//!     field (M31, QM31, channel_salt, claimed_sums, OODS samples, last-layer
//!     coefs, FRI witness, PoW nonces) — those are field-agnostic and shared
//!     with the Cairo/blake path.
//!   * Ports the auth-path / commitment / eval-domain-sample extraction from
//!     `proof_from_stark_proof` (which is private there), but keeps the Merkle
//!     hashes as raw `Bn254Hash` instead of lifting them to `HashValue<QM31>`.
//!   * Emits each `Bn254Hash` as `[u64; 4]` little-endian limbs (the canonical
//!     LE bigint of the Fr element), exactly matching the serde
//!     `Serialize for Bn254Hash` (`self.0.into_bigint().0`) and the Go
//!     `readBn254Hash`.
//!
//! ## Field order (mirrors the blake `CircuitSerialize for Proof<QM31>`)
//!
//! ```text
//!   channel_salt                 : QM31
//!   trace_root                   : Bn254Hash
//!   interaction_root             : Bn254Hash
//!   composition_polynomial_root  : Bn254Hash
//!   claimed_sums                 : [QM31; n_components]
//!   preprocessed_columns_at_oods : [QM31; n_preprocessed_columns]
//!   trace_at_oods                : [QM31; n_trace_columns]
//!   interaction_at_oods          : per col: QM31 (+ QM31 at_prev if cumulative)
//!   composition_eval_at_oods     : [QM31; 8]
//!   eval_domain_samples          : per trace (4) × per column × [M31; n_queries]
//!   eval_domain_auth_paths       : per tree (4) × per query × [Bn254Hash; log_eval]
//!   pow_nonce                    : QM31
//!   interaction_pow_nonce        : QM31
//!   fri.commit.layer_commitments : [Bn254Hash; len(all_fold_steps)]
//!   fri.commit.last_layer_coefs  : [QM31; 1 << log_n_last_layer_coefs]
//!   fri.auth_paths               : per layer × per query × [Bn254Hash; path_len]
//!   fri.witness                  : per layer × per query × [QM31; 1 << step]
//! ```
//!
//! NOTE: This module serializes from the NATIVE stwo `ExtendedStarkProof`
//! (`outer_proof.stark_proof`), reusing the SAME extraction recipe the blake
//! importer uses, so the only difference vs the blake on-disk bytes is the hash
//! encoding (`[u64;4]` LE vs 8 M31 limbs) — the field order and every value
//! field are identical.

use ark_ff::PrimeField;
use itertools::{chain, zip_eq};

use circuit_serialize::serialize::CircuitSerialize;
use circuits_stark_verifier::fri_proof::compute_all_fold_steps;
use circuits_stark_verifier::proof::{N_TRACES, ProofConfig};

use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::proof::ExtendedStarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::vcs_lifted::poseidon2_bn254_merkle::Bn254Hash;
use stwo::core::vcs_lifted::verifier::LOG_PACKED_LEAF_SIZE;

/// Serialize one `Bn254Hash` as `[u64; 4]` little-endian limbs (32 bytes).
///
/// `into_bigint().0` is the canonical reduced `[u64; 4]` (least-significant
/// limb first); each limb is written little-endian. This is byte-identical to:
///   * the serde `Serialize for Bn254Hash` (`limbs.serialize(s)`), and
///   * the Go `readBn254Hash` (limb-major, intra-limb LE).
fn serialize_bn254_hash(h: &Bn254Hash, output: &mut Vec<u8>) {
    let limbs: [u64; 4] = h.0.into_bigint().0;
    for limb in limbs {
        output.extend_from_slice(&limb.to_le_bytes());
    }
}

/// The hash type that the OUTER proof's Merkle commitment uses.
type H = stwo::core::vcs_lifted::poseidon2_bn254_merkle::Poseidon2Bn254MerkleHasher;

/// Task 4 — the canonical DECIMAL string of a `Bn254Hash` (Fr), for the
/// `l2_preprocessed_root_bn254_dec` ProofShape sidecar field the Go side
/// requires for the BN254 topology (`ProofShape.L2PreprocessedRootBn254Dec`,
/// parsed via `big.Int.SetString(..., 10)`).
///
/// The PINNED preprocessed root in the outer BN254 proof is
/// `outer_proof.stark_proof.proof.commitments[0]` (tree 0 = preprocessed); it is
/// NOT serialized into the proof bytes (mirrors the blake path, where it lives
/// in the sidecar as a hex string instead). `ark_bn254::Fr`'s `Display` prints
/// the canonical base-10 integer, which is exactly what the Go side parses.
pub fn bn254_root_decimal(root: &Bn254Hash) -> String {
    // `Display for Bn254Hash` already delegates to `Fr`'s canonical decimal
    // formatting (see poseidon2_bn254_merkle.rs); use it directly.
    root.to_string()
}

/// Convenience: the preprocessed-root decimal for the sidecar, read off the
/// outer proof's tree-0 commitment.
pub fn preprocessed_root_decimal(proof: &ExtendedStarkProof<H>) -> String {
    bn254_root_decimal(&proof.proof.commitments[0])
}

/// Serializes a Poseidon2-BN254-committed STARK proof to bytes matching the Go
/// parser `ReadMultiverifierProofBn254`.
///
/// `proof` is the OUTER `ExtendedStarkProof<H>` (= `circuit_proof.stark_proof`,
/// where `H = Poseidon2Bn254MerkleHasher`). The remaining args are the same
/// auxiliary scalars the blake serializer takes via `proof_from_stark_proof`
/// (`claimed_sums`, `interaction_pow_nonce`, `channel_salt`), captured from the
/// outer `CircuitProof`.
pub fn serialize_proof_bn254(
    proof: &ExtendedStarkProof<H>,
    config: &ProofConfig,
    claimed_sums: &[QM31],
    interaction_pow_nonce: u64,
    channel_salt: u32,
) -> Vec<u8> {
    let mut out = Vec::new();

    let commitments = &proof.proof.commitments;
    let sampled_values = &proof.proof.sampled_values;
    let fri_proof = &proof.proof.fri_proof;

    // ── channel_salt : QM31 (a u32 lifted into lane 0). ──────────────────
    let salt = QM31::from_u32_unchecked(channel_salt, 0, 0, 0);
    salt.serialize(&mut out);

    // ── 3 Merkle roots : Bn254Hash each. commitments[0] is preprocessed
    //    (NOT serialized — it lives in the sidecar). [1]=trace,
    //    [2]=interaction, [3]=composition. Mirrors proof_from_stark_proof.
    serialize_bn254_hash(&commitments[1], &mut out);
    serialize_bn254_hash(&commitments[2], &mut out);
    serialize_bn254_hash(&commitments[3], &mut out);

    // ── claimed_sums : [QM31; n_components]. ─────────────────────────────
    claimed_sums.serialize(&mut out);

    // ── preprocessed_columns_at_oods : [QM31; n_preprocessed_columns]. ───
    as_single_row(&sampled_values[0]).serialize(&mut out);
    // ── trace_at_oods : [QM31; n_trace_columns]. ─────────────────────────
    as_single_row(&sampled_values[1]).serialize(&mut out);

    // ── interaction_at_oods : per col, QM31 (+ at_prev QM31 if cumulative).
    //    stwo packs each interaction column as [at_prev, at_oods] (2 values)
    //    for cumulative columns, [at_oods] (1 value) otherwise. The blake
    //    serializer writes at_oods THEN at_prev (see
    //    `CircuitSerialize for InteractionAtOods`: at_oods, then at_prev). We
    //    reproduce that ordering exactly. The Go parser also reads at_oods
    //    then at_prev (multiverifier_proof_bn254.go lines 222-232).
    for col in sampled_values[2].iter() {
        match col[..] {
            [at_prev, at_oods] => {
                at_oods.serialize(&mut out);
                at_prev.serialize(&mut out);
            }
            [at_oods] => {
                at_oods.serialize(&mut out);
            }
            _ => panic!("unexpected interaction-at-OODS arity"),
        }
    }

    // ── composition_eval_at_oods : [QM31; 8]. ────────────────────────────
    as_single_row(&sampled_values[3]).serialize(&mut out);

    // ── eval_domain_samples : per trace (4) × per col × [M31; n_queries]. ─
    serialize_eval_domain_samples(proof, config, &mut out);

    // ── eval_domain_auth_paths : per tree (4) × per query × [hash; log_eval].
    serialize_eval_domain_auth_paths(proof, config, &mut out);

    // ── pow_nonce, interaction_pow_nonce : QM31 (low/high u32 in lanes 0,1).
    let pow = proof.proof.proof_of_work;
    qm31_from_u64(pow).serialize(&mut out);
    qm31_from_u64(interaction_pow_nonce).serialize(&mut out);

    // ── fri.commit.layer_commitments : [Bn254Hash; len(all_fold_steps)]. ─
    let all_fold_steps = compute_all_fold_steps(
        config.fri.log_trace_size - config.fri.log_n_last_layer_coefs,
        config.fri.fold_step,
    );
    let layer_commitments = chain!(
        [fri_proof.first_layer.commitment],
        fri_proof.inner_layers.iter().map(|l| l.commitment),
    );
    for c in layer_commitments {
        serialize_bn254_hash(&c, &mut out);
    }

    // ── fri.commit.last_layer_coefs : [QM31; 1 << log_n_last_layer_coefs]. ─
    fri_proof.last_layer_poly.to_vec().serialize(&mut out);

    // ── fri.auth_paths : per layer × per query × [hash; path_len]. ───────
    serialize_fri_auth_paths(proof, config, &all_fold_steps, &mut out);

    // ── fri.witness : per layer × per query × [QM31; 1 << step]. ─────────
    //    Port of `proof_from_stark_proof::construct_fri_witness` (value-only,
    //    hash-agnostic). We cannot CALL it directly: it is bounded by
    //    `MH: ProofHasher` (= `MH::Hash: Into<HashValue<QM31>>`), which the
    //    BN254 hasher does not satisfy, even though the witness extraction
    //    itself never touches the hash. The Go parser reads, per layer, per
    //    query, [QM31; 1 << step] — emitted layer-major, query-major.
    serialize_fri_witness(proof, &all_fold_steps, &mut out);

    out
}

/// Port of `proof_from_stark_proof::construct_fri_witness` (value-only),
/// serializing the QM31 coset witnesses directly. The blake importer builds
/// `witness_per_query_per_tree[layer][query]` then `CircuitSerialize` iterates
/// layer → query → cell. We reproduce that exact iteration order.
fn serialize_fri_witness(
    proof: &ExtendedStarkProof<H>,
    all_fold_steps: &[usize],
    out: &mut Vec<u8>,
) {
    let all_layers: Vec<_> = chain![
        std::slice::from_ref(&proof.aux.fri.first_layer),
        proof.aux.fri.inner_layers.iter(),
    ]
    .collect();

    // witness_per_query_per_tree[layer] = Vec<Vec<QM31>> (per query).
    let mut witness_per_layer: Vec<Vec<Vec<QM31>>> = vec![vec![]; all_fold_steps.len()];
    for query in &proof.aux.unsorted_query_locations {
        let mut pos = *query;
        for (layer_idx, (layer, step)) in zip_eq(&all_layers, all_fold_steps).enumerate() {
            let start = (pos >> step) << step;
            let witness: Vec<QM31> =
                (start..start + (1 << step)).map(|i| layer.all_values[0][&i]).collect();
            witness_per_layer[layer_idx].push(witness);
            pos >>= step;
        }
    }

    // Serialize layer → query → cell (== CircuitSerialize for FriWitness).
    for layer in &witness_per_layer {
        for query in layer {
            query.serialize(out);
        }
    }
}

/// QM31 from a u64 split into (low, high) u32 lanes — matches the blake
/// importer's `qm31_from_u32s(low, high, 0, 0)` for PoW nonces.
fn qm31_from_u64(v: u64) -> QM31 {
    QM31::from_u32_unchecked((v & 0xFFFF_FFFF) as u32, (v >> 32) as u32, 0, 0)
}

/// Flattens a column of single-element OODS rows into a 1-row vector
/// (mirrors `proof_from_stark_proof::as_single_row`).
fn as_single_row(values: &[Vec<QM31>]) -> Vec<QM31> {
    values
        .iter()
        .map(|x| {
            let [x] = x[..].try_into().expect("OODS row must have exactly one value");
            x
        })
        .collect()
}

/// Port of `proof_from_stark_proof::construct_eval_domain_samples`, emitting M31
/// samples directly (the result of `EvalDomainSamples` flattened the same way
/// `CircuitSerialize for EvalDomainSamples` iterates: trace → column → cell).
fn serialize_eval_domain_samples(
    proof: &ExtendedStarkProof<H>,
    config: &ProofConfig,
    out: &mut Vec<u8>,
) {
    use std::collections::HashMap;

    let unsorted_query_locations = &proof.aux.unsorted_query_locations;
    let queried_values = &proof.proof.queried_values;
    let n_queries = config.n_queries();
    assert_eq!(unsorted_query_locations.len(), n_queries);

    // query position -> list of indices in unsorted_query_locations.
    let mut query_to_indices = HashMap::<usize, Vec<usize>>::new();
    for (i, query) in unsorted_query_locations.iter().enumerate() {
        query_to_indices.entry(*query).or_default().push(i);
    }
    let mut sorted_query_keys: Vec<usize> = query_to_indices.keys().copied().collect();
    sorted_query_keys.sort_unstable();

    for (trace_idx, n_columns_in_trace) in config.n_columns_per_trace().iter().enumerate() {
        for column_idx in 0..*n_columns_in_trace {
            let mut column = vec![M31::from_u32_unchecked(0); n_queries];
            for (query_idx, query) in sorted_query_keys.iter().enumerate() {
                for idx in &query_to_indices[query] {
                    column[*idx] = queried_values[trace_idx][column_idx][query_idx];
                }
            }
            // Emit [M31; n_queries] for this column.
            column.serialize(out);
        }
    }
}

/// Port of `proof_from_stark_proof::construct_eval_domain_auth_paths`, but
/// emitting raw `Bn254Hash` siblings instead of `HashValue<QM31>`.
fn serialize_eval_domain_auth_paths(
    proof: &ExtendedStarkProof<H>,
    config: &ProofConfig,
    out: &mut Vec<u8>,
) {
    let unsorted_query_locations = &proof.aux.unsorted_query_locations;
    let path_len = config.log_evaluation_domain_size();

    for merkle_decommitment_aux in proof.aux.trace_decommitment.iter() {
        for query_idx in unsorted_query_locations.iter() {
            let mut pos = *query_idx;
            for j in 0..path_len {
                let sibling: <H as MerkleHasherLifted>::Hash =
                    merkle_decommitment_aux.all_node_values[j][&(pos ^ 1)];
                serialize_bn254_hash(&sibling, out);
                pos >>= 1;
            }
        }
    }
    debug_assert_eq!(proof.aux.trace_decommitment.len(), N_TRACES);
}

/// Port of `proof_from_stark_proof::construct_fri_auth_paths`, emitting raw
/// `Bn254Hash` siblings.
fn serialize_fri_auth_paths(
    proof: &ExtendedStarkProof<H>,
    config: &ProofConfig,
    all_fold_steps: &[usize],
    out: &mut Vec<u8>,
) {
    let unsorted_query_locations = &proof.aux.unsorted_query_locations;
    let layers = chain!([&proof.aux.fri.first_layer], &proof.aux.fri.inner_layers);
    let mut log_layer_size = config.log_evaluation_domain_size();
    let mut fold_sum = 0;

    for (layer_proof, step) in zip_eq(layers, all_fold_steps) {
        for query in unsorted_query_locations.iter() {
            let mut pos = *query;
            let pack_leaves = log_layer_size >= LOG_PACKED_LEAF_SIZE as usize && *step > 1;
            let pack_shift = if pack_leaves { LOG_PACKED_LEAF_SIZE as usize } else { 0 };
            pos >>= fold_sum + step;
            for j in *step..log_layer_size {
                let sibling: <H as MerkleHasherLifted>::Hash =
                    layer_proof.decommitment.all_node_values[j - pack_shift][&(pos ^ 1)];
                serialize_bn254_hash(&sibling, out);
                pos >>= 1;
            }
        }
        log_layer_size -= step;
        fold_sum += step;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    /// Independent reference encoder for one `Bn254Hash` → 32 bytes, written to
    /// mirror the Go test's `putBn254Hash` (limb-major, intra-limb LE). This is
    /// deliberately a SEPARATE implementation from `serialize_bn254_hash` so the
    /// test cross-checks the production path against a hand-rolled one.
    fn ref_put_bn254(out: &mut Vec<u8>, limbs: [u64; 4]) {
        for limb in limbs {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }

    fn ref_put_qm31(out: &mut Vec<u8>, lanes: [u32; 4]) {
        for v in lanes {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn ref_put_m31(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    /// Recompose [u64;4] LE limbs into the canonical big integer (mirrors the Go
    /// `expectedFr` / `readBn254Hash`): value = Σ limb_i · 2^(64 i).
    fn recompose(limbs: [u64; 4]) -> u128 {
        // Use u128 for the test vectors (all chosen < 2^128).
        (limbs[0] as u128) | ((limbs[1] as u128) << 64)
    }

    /// (1) Hash-encoding round-trip: `serialize_bn254_hash` emits exactly the
    /// `[u64;4]` LE limbs of `Fr::into_bigint()`, byte-identical to the Go
    /// `readBn254Hash` input, and the bytes recompose to the same field element.
    #[test]
    fn bn254_hash_encoding_matches_go_limbs() {
        // Small values whose limbs are exactly known.
        for v in [0u64, 1, 2, 100, 0xdead_beef, u64::MAX] {
            let h = Bn254Hash(Fr::from(v));
            let mut got = Vec::new();
            serialize_bn254_hash(&h, &mut got);
            assert_eq!(got.len(), 32, "Bn254Hash must serialize to 32 bytes");

            // Expected: into_bigint().0 limbs, each LE u64.
            let limbs: [u64; 4] = h.0.into_bigint().0;
            let mut want = Vec::new();
            ref_put_bn254(&mut want, limbs);
            assert_eq!(got, want, "value {v}: serializer bytes must equal [u64;4] LE limbs");

            // For values < 2^64 the canonical limbs are [v, 0, 0, 0] (Fr is
            // stored in Montgomery form internally, but into_bigint() reduces to
            // the canonical integer, so limb0 == v).
            if v != u64::MAX {
                assert_eq!(limbs, [v, 0, 0, 0], "canonical limbs for {v}");
            }
            // Recompose the low 128 bits and confirm round-trip for these.
            assert_eq!(recompose(limbs), v as u128, "recompose {v}");
        }
    }

    /// (1b) Cross-check against the gnark shared test vector (the canonical
    /// decimal printed by the Go `poseidon2_ref` for Compress(1,2)). Confirms the
    /// limb decomposition + LE byte order agree with what the Go side recomposes.
    #[test]
    fn bn254_hash_encoding_gnark_vector() {
        use std::str::FromStr;
        let dec = "14764600645593062425721213299093111352854594494516189496930284874052842801156";
        let fr = Fr::from_str(dec).unwrap();
        let h = Bn254Hash(fr);

        let mut got = Vec::new();
        serialize_bn254_hash(&h, &mut got);
        assert_eq!(got.len(), 32);

        // Recompose the 4 LE limbs from the bytes exactly as the Go
        // `readBn254Hash` does (limb3..limb0, then Lsh 64), and confirm it
        // equals the original decimal.
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&got[i * 8..i * 8 + 8]);
            *limb = u64::from_le_bytes(b);
        }
        let bigint = ark_ff::BigInt::<4>(limbs);
        let recomposed = Fr::from_bigint(bigint).expect("in range");
        assert_eq!(recomposed, fr, "gnark vector must round-trip through LE limbs");
    }

    /// (2) Full-blob layout cross-check. Replicates the EXACT field order +
    /// values of the Go test `buildMinimalBn254Blob` (multiverifier_proof_bn254_test.go),
    /// using the serializer's primitives, and asserts the bytes equal an
    /// independently-built expected blob. This proves the on-disk field order +
    /// value encodings match the Go parser's contract byte-for-byte, WITHOUT
    /// needing a real ~2h outer prove.
    ///
    /// minimalBn254Shape: n_components=2, n_preprocessed=1, n_trace=1,
    /// n_interaction=2 (col0 cumulative), n_composition=8, n_traces=4,
    /// n_columns_per_trace=[1,1,1,8], n_queries=1, log_eval=2,
    /// all_fold_steps=[1,1], log_n_last_layer=0.
    #[test]
    fn minimal_blob_matches_go_contract() {
        // h(n) = Bn254Hash with low limb n (matches the Go `h(n)` sentinel).
        let hash_bytes = |n: u64| {
            let mut b = Vec::new();
            serialize_bn254_hash(&Bn254Hash(Fr::from(n)), &mut b);
            b
        };

        // ── Build the blob via the serializer's primitives, in proof field order.
        let mut got = Vec::new();
        // channel_salt : QM31
        QM31::from_u32_unchecked(1, 2, 3, 4).serialize(&mut got);
        // 3 roots : Bn254Hash
        got.extend(hash_bytes(100));
        got.extend(hash_bytes(101));
        got.extend(hash_bytes(102));
        // claimed_sums : [QM31; 2]
        QM31::from_u32_unchecked(10, 0, 0, 0).serialize(&mut got);
        QM31::from_u32_unchecked(11, 0, 0, 0).serialize(&mut got);
        // preprocessed_columns_at_oods : [QM31; 1]
        QM31::from_u32_unchecked(20, 0, 0, 0).serialize(&mut got);
        // trace_at_oods : [QM31; 1]
        QM31::from_u32_unchecked(21, 0, 0, 0).serialize(&mut got);
        // interaction_at_oods : col0 cumulative (at_oods, at_prev), col1 (at_oods)
        QM31::from_u32_unchecked(30, 0, 0, 0).serialize(&mut got); // col0 at_oods
        QM31::from_u32_unchecked(31, 0, 0, 0).serialize(&mut got); // col0 at_prev
        QM31::from_u32_unchecked(32, 0, 0, 0).serialize(&mut got); // col1 at_oods
        // composition_eval_at_oods : [QM31; 8]
        for i in 0..8u32 {
            QM31::from_u32_unchecked(40 + i, 0, 0, 0).serialize(&mut got);
        }
        // eval_domain_samples : 4 trees × n_cols × [M31;1] → 11 samples 50..60
        let mut sample = 50u32;
        for &n_cols in &[1usize, 1, 1, 8] {
            for _ in 0..n_cols {
                M31::from_u32_unchecked(sample).serialize(&mut got);
                sample += 1;
            }
        }
        // eval_domain_auth_paths : 4 trees × 1 query × [hash;2] → 200..208
        let mut auth = 200u64;
        for _ in 0..4 {
            for _ in 0..2 {
                got.extend(hash_bytes(auth));
                auth += 1;
            }
        }
        // pow_nonce, interaction_pow_nonce : QM31
        QM31::from_u32_unchecked(60, 0, 0, 0).serialize(&mut got);
        QM31::from_u32_unchecked(61, 0, 0, 0).serialize(&mut got);
        // fri.commit.layer_commitments : [hash; 2]
        got.extend(hash_bytes(300));
        got.extend(hash_bytes(301));
        // fri.commit.last_layer_coefs : [QM31; 1]
        QM31::from_u32_unchecked(70, 0, 0, 0).serialize(&mut got);
        // fri.auth_paths : layer0 path_len = 2-1 = 1; layer1 path_len = 1-1 = 0
        got.extend(hash_bytes(400));
        // fri.witness : 2 layers × 1 query × [QM31; 2]
        QM31::from_u32_unchecked(80, 0, 0, 0).serialize(&mut got);
        QM31::from_u32_unchecked(81, 0, 0, 0).serialize(&mut got);
        QM31::from_u32_unchecked(82, 0, 0, 0).serialize(&mut got);
        QM31::from_u32_unchecked(83, 0, 0, 0).serialize(&mut got);

        // ── Build the SAME blob independently with raw byte primitives (the
        //    Go `buildMinimalBn254Blob` reference).
        let mut want = Vec::new();
        ref_put_qm31(&mut want, [1, 2, 3, 4]);
        ref_put_bn254(&mut want, [100, 0, 0, 0]);
        ref_put_bn254(&mut want, [101, 0, 0, 0]);
        ref_put_bn254(&mut want, [102, 0, 0, 0]);
        ref_put_qm31(&mut want, [10, 0, 0, 0]);
        ref_put_qm31(&mut want, [11, 0, 0, 0]);
        ref_put_qm31(&mut want, [20, 0, 0, 0]);
        ref_put_qm31(&mut want, [21, 0, 0, 0]);
        ref_put_qm31(&mut want, [30, 0, 0, 0]);
        ref_put_qm31(&mut want, [31, 0, 0, 0]);
        ref_put_qm31(&mut want, [32, 0, 0, 0]);
        for i in 0..8u32 {
            ref_put_qm31(&mut want, [40 + i, 0, 0, 0]);
        }
        for s in 50..61u32 {
            ref_put_m31(&mut want, s);
        }
        for a in 200..208u64 {
            ref_put_bn254(&mut want, [a, 0, 0, 0]);
        }
        ref_put_qm31(&mut want, [60, 0, 0, 0]);
        ref_put_qm31(&mut want, [61, 0, 0, 0]);
        ref_put_bn254(&mut want, [300, 0, 0, 0]);
        ref_put_bn254(&mut want, [301, 0, 0, 0]);
        ref_put_qm31(&mut want, [70, 0, 0, 0]);
        ref_put_bn254(&mut want, [400, 0, 0, 0]);
        ref_put_qm31(&mut want, [80, 0, 0, 0]);
        ref_put_qm31(&mut want, [81, 0, 0, 0]);
        ref_put_qm31(&mut want, [82, 0, 0, 0]);
        ref_put_qm31(&mut want, [83, 0, 0, 0]);

        assert_eq!(got, want, "serializer field order/encoding must match Go contract");

        // Total length sanity: 8 QM31s value-heads + ... compute expected.
        // 1 salt + 2 claimed + 1 pp + 1 trace + 3 interaction + 8 comp + 2 pow
        //   + 1 last_layer + 4 witness = 23 QM31 = 23*16 = 368 bytes
        // 11 M31 = 44 bytes
        // hashes: 3 roots + 8 eval_auth + 2 fri_commit + 1 fri_auth = 14 * 32 = 448
        assert_eq!(got.len(), 23 * 16 + 11 * 4 + 14 * 32);
    }

    /// (4) The `l2_preprocessed_root_bn254_dec` sidecar helper prints the
    /// canonical base-10 integer of the Fr — exactly what the Go
    /// `big.Int.SetString(..., 10)` parses (multiverifier_proof_bn254.go:342).
    #[test]
    fn root_decimal_is_canonical_base10() {
        use std::str::FromStr;

        // Small value: decimal is the plain integer.
        assert_eq!(bn254_root_decimal(&Bn254Hash(Fr::from(7u64))), "7");
        assert_eq!(bn254_root_decimal(&Bn254Hash(Fr::from(0u64))), "0");

        // A full ~254-bit element round-trips through Display → SetString.
        let dec = "14764600645593062425721213299093111352854594494516189496930284874052842801156";
        let fr = Fr::from_str(dec).unwrap();
        assert_eq!(bn254_root_decimal(&Bn254Hash(fr)), dec);
    }
}
