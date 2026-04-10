//! Two-level recursive proof generation for TzEL.
//!
//! # Architecture
//!
//! The proving pipeline has two levels:
//!
//! ```text
//!   Cairo program ──→ [Privacy Bootloader] ──→ Execution trace
//!        │                                           │
//!        │                   Level 1: Cairo AIR proof (Stwo)
//!        │                   ~480 KB, NOT zero-knowledge
//!        │                                           │
//!        │                   Level 2: Circuit proof (Stwo circuits)
//!        │                   ~290 KB, zero-knowledge (ZK blinding added)
//!        ▼                                           ▼
//!   .executable.json                          compressed proof + output_preimage
//! ```
//!
//! The first-level Cairo proof proves correct execution of the program.
//! The second-level circuit proof proves that the first-level proof
//! verified correctly. ZK blinding is added at the circuit level,
//! ensuring that the final proof leaks no information about the private
//! witness (spending keys, note values, Merkle paths, etc.).
//!
//! # Why two levels?
//!
//! Stwo's Cairo prover (level 1) produces proofs in the Circle STARK
//! framework. These proofs are valid but:
//!   - Large (~480 KB compressed)
//!   - NOT zero-knowledge (FRI query responses expose witness trace values)
//!
//! The circuit reprover (level 2) compresses the proof and adds ZK
//! blinding in a single step, producing a ~290 KB zero-knowledge proof.
//!
//! # Dynamic component detection
//!
//! Unlike StarkWare's hardcoded privacy prover (57 components), we
//! dynamically detect which Cairo AIR components are active in our proof
//! by reading the claim's `component_enable_bits`. This lets us handle
//! any Cairo program without hardcoding component sets.
//!
//! # Security
//!
//! Both proof levels target 96-bit security:
//!   - Level 1: pow_bits=27 + log_blowup(3) * n_queries(23) = 96 bits
//!   - Level 2: pow_bits=26 + log_blowup(2) * n_queries(35) = 96 bits

use std::cmp::max;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, anyhow};
use cairo_air::PreProcessedTraceVariant;
use cairo_air::flat_claims::FlatClaim;
use circuit_air::statement::INTERACTION_POW_BITS as CIRCUIT_INTERACTION_POW_BITS;
use circuit_air::verify::CircuitConfig;
use circuit_cairo_air::all_components::all_components;
use circuit_cairo_air::preprocessed_columns::PREPROCESSED_COLUMNS_ORDER;
use circuit_cairo_air::statement::MEMORY_VALUES_LIMBS;
use circuit_cairo_air::verify::{
    CairoVerifierConfig, build_fixed_cairo_circuit, get_preprocessed_root,
    prepare_cairo_proof_for_circuit_verifier,
};
use circuit_common::finalize::{add_zk_blinding, finalize_context};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{
    prepare_circuit_proof_for_circuit_verifier, prove_circuit_with_precompute,
};
use circuit_serialize::serialize::CircuitSerialize;
use circuits::blake::HashValue;
use circuits::ivalue::IValue;
use circuits_stark_verifier::empty_component::EmptyComponent;
use circuits_stark_verifier::proof::ProofConfig;
use circuits_stark_verifier::proof_from_stark_proof::pack_into_qm31s;
use privacy_circuit_verify::{compute_privacy_bootloader_output, get_privacy_bootloader_program};
use starknet_types_core::felt::Felt;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use tzel_core::F as RawF;

fn felt_to_raw(felt: &Felt) -> RawF {
    felt.to_bytes_le()
}

fn raw_to_felt(raw: &RawF) -> Felt {
    Felt::from_bytes_le(raw)
}
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::MaybeOwned;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::prover::CommitmentTreeProver;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::mempool::BaseColumnPool;
use stwo::prover::poly::circle::PolyOps;
use stwo_cairo_adapter::ProverInput;
use stwo_cairo_common::prover_types::cpu::Felt252;
use stwo_cairo_prover::prover::{ChannelHash, ProverParameters, prove_cairo_with_precompute};
use stwo_cairo_prover::witness::preprocessed_trace::gen_trace;
use tracing::{Level, info, span};

// ── Configuration ────────────────────────────────────────────────────

/// Build a ProofConfig that matches the actual proof's column structure.
///
/// The Stwo Cairo AIR defines ~81 possible components (opcodes, builtins,
/// memory, range checks, etc.). Our programs only activate a subset (~46).
/// Components that are disabled (claim says `None`) get replaced with
/// `EmptyComponent` which has 0 trace/interaction columns. This makes the
/// ProofConfig's column counts match the actual proof structure.
fn build_proof_config_from_enable_bits(enable_bits: &[bool]) -> ProofConfig {
    let all = all_components::<QM31>();
    assert_eq!(all.len(), enable_bits.len());
    let components: Vec<Box<dyn circuits_stark_verifier::constraint_eval::CircuitEval<QM31>>> = all
        .into_iter()
        .zip(enable_bits.iter())
        .map(|((_name, comp), &enabled)| {
            if enabled {
                comp
            } else {
                Box::new(EmptyComponent {}) as _
            }
        })
        .collect();
    ProofConfig::from_components(
        &components,
        PREPROCESSED_COLUMNS_ORDER.len(),
        &CAIRO_PCS_CONFIG,
        cairo_air::verifier::INTERACTION_POW_BITS,
    )
}

/// Level 2 (circuit) FRI configuration.
/// Security: pow_bits(26) + log_blowup(2) * n_queries(35) = 96 bits.
const CIRCUIT_FRI_CONFIG: FriConfig = FriConfig {
    log_blowup_factor: 2,
    log_last_layer_degree_bound: 0,
    n_queries: 35,
    fold_step: 4,
};

/// Level 1 (Cairo) PCS configuration.
/// Security: pow_bits(27) + log_blowup(3) * n_queries(23) = 96 bits.
/// lifting_log_size = 23 means the FRI evaluation domain is 2^23 (= 2^20 trace * 2^3 blowup).
const CAIRO_PCS_CONFIG: PcsConfig = PcsConfig {
    pow_bits: 27,
    fri_config: FriConfig {
        log_blowup_factor: 3,
        log_last_layer_degree_bound: 0,
        n_queries: 23,
        fold_step: 4,
    },
    lifting_log_size: Some(23),
};

/// Level 1 prover parameters.
///
/// Uses CanonicalSmall preprocessed trace (lookup tables for all builtins
/// including Pedersen, even though we don't use it). The `include_all_
/// preprocessed_columns = true` flag includes OODS samples for all
/// preprocessed columns in the proof — this is required for the circuit
/// verifier to check all commitments.
///
/// TODO: Build a custom preprocessed trace without Pedersen columns to
/// reduce the commitment size and potentially shrink the proof further.
const CUSTOM_PROVER_PARAMS: ProverParameters = ProverParameters {
    channel_hash: ChannelHash::Blake2sM31,
    pcs_config: CAIRO_PCS_CONFIG,
    preprocessed_trace: PreProcessedTraceVariant::CanonicalSmall,
    channel_salt: 0,
    store_polynomials_coefficients: true,
    include_all_preprocessed_columns: true,
};

// ── Helpers ──────────────────────────────────────────────────────────

/// Compute the bootloader output hash from the output preimage.
///
/// The privacy bootloader writes the program's public outputs as a list
/// of Felt values. This function hashes them with Blake2s to produce the
/// 28-limb M31 representation that the circuit embeds as public data.
fn compute_output(output_preimage: &[Felt]) -> [M31; MEMORY_VALUES_LIMBS] {
    compute_privacy_bootloader_output(output_preimage)
}

fn qm31_to_m31s(q: QM31) -> Vec<u32> {
    vec![q.0.0.0, q.0.1.0, q.1.0.0, q.1.1.0]
}

fn compute_output_hash_values(output_preimage: &[Felt]) -> Vec<u32> {
    let outputs = compute_output(output_preimage);
    let output_qm31s = pack_into_qm31s(outputs.into_iter());
    let output_hash: HashValue<QM31> =
        QM31::blake(output_qm31s.as_slice(), output_qm31s.len() * 16);
    vec![output_hash.0, output_hash.1]
        .into_iter()
        .flat_map(qm31_to_m31s)
        .collect()
}

// ── Public API ───────────────────────────────────────────────────────

pub struct CustomProofOutput {
    pub proof: Vec<u8>,
    pub output_preimage: Vec<Felt>,
    pub verify_meta: VerifyMeta,
    pub cairo_prove_ms: u128,
    pub circuit_prove_ms: u128,
    pub verify_ms: u128,
}

/// Proof bundle: everything needed for standalone verification.
/// Serialized as JSON for transport between prover and verifier.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    /// Hex-encoded zstd-compressed circuit proof bytes.
    #[serde(with = "tzel_core::hex_bytes")]
    pub proof_bytes: Vec<u8>,
    /// Output preimage (public outputs as raw felt252 values).
    #[serde(with = "tzel_core::hex_f_vec")]
    pub output_preimage: Vec<RawF>,
    /// Verification metadata — serialized ProofConfig, CircuitConfig, CircuitPublicData.
    /// Contains everything needed to deserialize and verify the circuit proof standalone.
    #[serde(default)]
    pub verify_meta: Option<VerifyMeta>,
}

/// Serializable verification metadata.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyMeta {
    // ProofConfig fields
    pub n_pow_bits: u32,
    pub n_preprocessed_columns: usize,
    pub n_trace_columns: usize,
    pub n_interaction_columns: usize,
    pub trace_columns_per_component: Vec<usize>,
    pub interaction_columns_per_component: Vec<usize>,
    pub cumulative_sum_columns: Vec<bool>,
    pub n_components: usize,
    pub fri_log_trace_size: usize,
    pub fri_log_blowup: u32,
    pub fri_log_last_layer: u32,
    pub fri_n_queries: usize,
    pub fri_fold_step: u32,
    pub interaction_pow_bits: u32,
    // CircuitConfig fields
    pub circuit_pow_bits: u32,
    pub circuit_fri_log_blowup: u32,
    pub circuit_fri_log_last_layer: u32,
    pub circuit_fri_n_queries: usize,
    pub circuit_fri_fold_step: u32,
    pub circuit_lifting: Option<u32>,
    pub output_addresses: Vec<usize>,
    pub n_blake_gates: usize,
    pub preprocessed_column_ids: Vec<String>,
    /// Preprocessed root as [a.0, a.1, a.2, a.3, b.0, b.1, b.2, b.3] (8 M31 values)
    pub preprocessed_root: Vec<u32>,
    /// CircuitPublicData output_values as flat M31 values (4 per QM31)
    pub public_output_values: Vec<u32>,
}

impl ProofBundle {
    pub fn from_output(out: &CustomProofOutput) -> Self {
        Self {
            proof_bytes: out.proof.clone(),
            output_preimage: out.output_preimage.iter().map(felt_to_raw).collect(),
            verify_meta: Some(out.verify_meta.clone()),
        }
    }

    pub fn proof_bytes(&self) -> Vec<u8> {
        self.proof_bytes.clone()
    }

    pub fn output_preimage_felts(&self) -> Vec<Felt> {
        self.output_preimage.iter().map(raw_to_felt).collect()
    }

    /// Standalone verification: deserialize the circuit proof and verify it
    /// using the stored verification metadata. Returns Ok(()) if valid.
    ///
    /// SECURITY: This method also verifies that `output_preimage` hashes to the
    /// same public output values that the STARK proof was verified against.
    /// Without this check, a tampered `output_preimage` could pass verification
    /// while the ledger interprets different (attacker-chosen) public outputs.
    pub fn verify(&self) -> Result<()> {
        use circuit_air::verify::{CircuitConfig, CircuitPublicData, verify_circuit};
        use circuit_serialize::deserialize::deserialize_proof_with_config;
        use circuits_stark_verifier::proof::ProofConfig;
        use stwo::core::fields::qm31::QM31;

        let meta = self
            .verify_meta
            .as_ref()
            .ok_or_else(|| anyhow!("proof bundle missing verify_meta"))?;

        // ── Step 0: Bind output_preimage to the verified public outputs ──
        // The first two QM31 public outputs are the output hash derived from
        // the bootloader output preimage. If these do not match, the ledger
        // is interpreting attacker-chosen outputs that were not authenticated
        // by the proof.
        let preimage_felts = self.output_preimage_felts();
        let expected_output_hash_values = compute_output_hash_values(&preimage_felts);
        if meta.public_output_values.len() < expected_output_hash_values.len() {
            return Err(anyhow!("verify_meta public_output_values too short"));
        }
        if meta.public_output_values[..expected_output_hash_values.len()]
            != expected_output_hash_values
        {
            return Err(anyhow!(
                "output_preimage does not match verified public_output_values — \
                 the preimage may have been tampered with"
            ));
        }

        // Reconstruct ProofConfig (uses circuits_stark_verifier::fri_proof::FriConfig)
        let proof_config = ProofConfig {
            n_proof_of_work_bits: meta.n_pow_bits,
            n_preprocessed_columns: meta.n_preprocessed_columns,
            n_trace_columns: meta.n_trace_columns,
            n_interaction_columns: meta.n_interaction_columns,
            trace_columns_per_component: meta.trace_columns_per_component.clone(),
            interaction_columns_per_component: meta.interaction_columns_per_component.clone(),
            cumulative_sum_columns: meta.cumulative_sum_columns.clone(),
            n_components: meta.n_components,
            fri: circuits_stark_verifier::fri_proof::FriConfig {
                log_trace_size: meta.fri_log_trace_size,
                log_blowup_factor: meta.fri_log_blowup as usize,
                n_queries: meta.fri_n_queries as usize,
                log_n_last_layer_coefs: meta.fri_log_last_layer as usize,
                fold_step: meta.fri_fold_step as usize,
            },
            interaction_pow_bits: meta.interaction_pow_bits,
        };

        // Helper to reconstruct QM31 from 4 u32 M31 values
        let qm31_from = |vals: &[u32]| -> QM31 {
            QM31::from_m31(
                M31::from(vals[0]),
                M31::from(vals[1]),
                M31::from(vals[2]),
                M31::from(vals[3]),
            )
        };

        // Reconstruct CircuitConfig
        let pr = &meta.preprocessed_root;
        let circuit_config = CircuitConfig {
            config: stwo::core::pcs::PcsConfig {
                pow_bits: meta.circuit_pow_bits,
                fri_config: stwo::core::fri::FriConfig {
                    log_blowup_factor: meta.circuit_fri_log_blowup,
                    log_last_layer_degree_bound: meta.circuit_fri_log_last_layer,
                    n_queries: meta.circuit_fri_n_queries,
                    fold_step: meta.circuit_fri_fold_step,
                },
                lifting_log_size: meta.circuit_lifting,
            },
            output_addresses: meta.output_addresses.clone(),
            n_blake_gates: meta.n_blake_gates,
            preprocessed_column_ids: meta
                .preprocessed_column_ids
                .iter()
                .map(
                    |s| stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId {
                        id: s.clone().into(),
                    },
                )
                .collect(),
            preprocessed_root: HashValue(qm31_from(&pr[0..4]), qm31_from(&pr[4..8])),
        };

        // Reconstruct CircuitPublicData
        let public_data = CircuitPublicData {
            output_values: meta
                .public_output_values
                .chunks(4)
                .map(|c| qm31_from(c))
                .collect(),
        };

        // Decompress and deserialize proof
        let compressed = self.proof_bytes();
        let proof_bytes =
            zstd::decode_all(&compressed[..]).map_err(|e| anyhow!("zstd decompress: {e}"))?;
        let mut data = proof_bytes.as_slice();
        let proof = deserialize_proof_with_config(&mut data, &proof_config)
            .map_err(|e| anyhow!("deserialize proof: {e}"))?;

        // Verify
        verify_circuit(circuit_config, proof, public_data)
            .map_err(|e| anyhow!("circuit verification FAILED: {e}"))?;

        Ok(())
    }
}

/// Generate a two-level recursive zero-knowledge proof.
///
/// This is the main entry point for proof generation. It:
///   1. Generates a first-level Cairo AIR proof (NOT zero-knowledge)
///   2. Dynamically detects which components are active
///   3. Builds a circuit that verifies the Cairo proof
///   4. Adds ZK blinding to the circuit (making it zero-knowledge)
///   5. Proves the circuit execution with Stwo
///   6. Verifies both proofs for correctness
///   7. Serializes and compresses the circuit proof (~290 KB)
/// Generate a two-level recursive ZK proof from an execution trace.
/// Returns proof bytes (zstd-compressed), public outputs, and timing data.
pub fn custom_recursive_prove(
    prover_input: ProverInput,
    output_preimage: Vec<Felt>,
) -> Result<CustomProofOutput> {
    let _span = span!(Level::INFO, "custom_recursive_prove").entered();
    let base_column_pool = BaseColumnPool::<SimdBackend>::new();

    // ── Level 1: Generate Cairo AIR proof ────────────────────────────
    // This proves correct execution of the Cairo program. The proof is
    // ~480 KB and includes FRI query responses that leak witness data.
    // It will be consumed by the circuit prover and never exposed.

    let t_cairo = Instant::now();

    // Build the preprocessed trace (static lookup tables shared by all proofs).
    info!("Preparing Cairo preprocessed trace");
    let cairo_preprocessed_trace = Arc::new(
        CUSTOM_PROVER_PARAMS
            .preprocessed_trace
            .to_preprocessed_trace(),
    );
    let cairo_lifting = CAIRO_PCS_CONFIG.lifting_log_size.unwrap();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(cairo_lifting).circle_domain().half_coset,
    );

    // Commit to the preprocessed trace in a Merkle tree. This commitment
    // is the first thing mixed into the Fiat-Shamir channel.
    let cairo_pp_polys =
        SimdBackend::interpolate_columns(gen_trace(cairo_preprocessed_trace.clone()), &twiddles);
    let cairo_pp_tree = CommitmentTreeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(
        cairo_pp_polys,
        CAIRO_PCS_CONFIG.fri_config.log_blowup_factor,
        &twiddles,
        CUSTOM_PROVER_PARAMS.store_polynomials_coefficients,
        Some(cairo_lifting),
        &base_column_pool,
    );

    // Run the Stwo prover on the execution trace.
    info!("Generating Cairo proof");
    let cairo_proof = prove_cairo_with_precompute(
        &base_column_pool,
        &twiddles,
        cairo_preprocessed_trace,
        MaybeOwned::Borrowed(&cairo_pp_tree),
        prover_input,
        CUSTOM_PROVER_PARAMS,
    )
    .map_err(|e| anyhow!("{e}"))?;

    let cairo_prove_ms = t_cairo.elapsed().as_millis();
    info!("Cairo proof generated in {}ms", cairo_prove_ms);

    // ── Dynamic component detection ──────────────────────────────────
    // The Cairo AIR has ~81 possible components. Our programs activate a
    // subset (e.g., 46 for all-Blake programs without Poseidon). We read
    // the claim's enable bits to build a ProofConfig that matches the
    // actual proof structure — this is what makes our circuit reprover
    // work for any Cairo program, not just a hardcoded component set.

    let FlatClaim {
        component_enable_bits,
        ..
    } = cairo_proof.claim.flatten_claim();
    info!(
        "Proof has {} enabled components out of {}",
        component_enable_bits.iter().filter(|&&b| b).count(),
        component_enable_bits.len()
    );

    let cairo_proof_config = build_proof_config_from_enable_bits(&component_enable_bits);

    // Sanity check: the ProofConfig's column counts must exactly match
    // what's in the proof. A mismatch means the circuit verifier would
    // index out of bounds.
    let sampled = &cairo_proof.extended_stark_proof.proof.sampled_values;
    let config_cols: Vec<usize> = cairo_proof_config.n_columns_per_trace().to_vec();
    let proof_cols: Vec<usize> = sampled.0.iter().map(|t| t.len()).collect();
    assert_eq!(
        config_cols, proof_cols,
        "Column count mismatch between config and proof"
    );

    // ── Build the Cairo verifier configuration ───────────────────────
    // The CairoVerifierConfig tells the circuit what program was executed,
    // how many outputs to expect, and what the preprocessed trace root is.

    let bootloader_program = get_privacy_bootloader_program().map_err(|e| anyhow!("{e}"))?;
    let mut program = vec![];
    for value in bootloader_program.iter_data() {
        program.push(
            Felt252::from(value.get_int().ok_or_else(|| anyhow!("bad program data"))?).get_limbs(),
        );
    }
    let cairo_lifting_log_size = cairo_proof_config.fri.log_evaluation_domain_size() as u32;
    let cairo_verifier_config = CairoVerifierConfig {
        proof_config: cairo_proof_config,
        program,
        n_outputs: 1,
        preprocessed_root: get_preprocessed_root(cairo_lifting_log_size),
    };

    // ── Transform the Cairo proof for circuit consumption ────────────
    // This converts the Stwo STARK proof into a format the circuit
    // verifier can process: Merkle roots, OODS evaluations, FRI layers.

    info!("Preparing Cairo proof for circuit verifier");
    let (proof, public_data) =
        prepare_cairo_proof_for_circuit_verifier(&cairo_proof, &cairo_verifier_config.proof_config);

    // ── Build and evaluate the circuit ──���────────────────────────────
    // The circuit is a fixed-topology computation that verifies the Cairo
    // proof. It replays the verifier's logic: check commitments, evaluate
    // constraints at the OODS point, verify FRI, check proof-of-work.

    info!("Building circuit verifier context");
    let (public_claim, _outputs, _program) = public_data.pack_into_u32s();
    let outputs = compute_output(&output_preimage);
    let mut context =
        build_fixed_cairo_circuit(&cairo_verifier_config, proof, public_claim, vec![outputs]);

    // The circuit context now holds the full execution trace of the
    // verifier. Check that all constraints are satisfied.
    if !context.is_circuit_valid() {
        return Err(anyhow!(
            "Circuit verification failed — the Cairo proof may be invalid"
        ));
    }

    // ── Add ZK blinding ──────────────────────────────────────────────
    // This is what makes the final proof zero-knowledge. Random values
    // are injected into the circuit's qm31_ops and eq components,
    // masking the witness trace so FRI queries reveal nothing.
    // The seed is derived from the Cairo proof's trace commitment,
    // making it deterministic but unpredictable to an adversary.

    let zk_blinding_seed = cairo_proof.extended_stark_proof.proof.commitments.0[1].0;
    add_zk_blinding(&mut context, zk_blinding_seed, CIRCUIT_FRI_CONFIG.n_queries);
    finalize_context(&mut context);
    let context_values = context.values();

    // ── Level 2: Prove the circuit ───────────────────────────────────
    // Now we prove the circuit execution itself with Stwo, producing
    // a second STARK proof. This proof is zero-knowledge (due to the
    // blinding added above) and much smaller than the first-level proof.

    info!("Building circuit preprocessed trace");
    let preprocessed_circuit = {
        // Build the circuit topology with NoValue types to get the
        // preprocessed trace (lookup tables for the circuit itself).
        let mut nv =
            circuit_cairo_air::verify::build_cairo_verifier_circuit(&cairo_verifier_config);
        add_zk_blinding(&mut nv, [0; 32], CIRCUIT_FRI_CONFIG.n_queries);
        PreprocessedCircuit::preprocess_circuit(&mut nv)
    };
    let circuit_trace_log_size = preprocessed_circuit.params.trace_log_size;
    let circuit_lifting = circuit_trace_log_size + CIRCUIT_FRI_CONFIG.log_blowup_factor;
    info!(
        "Circuit trace log_size: {}, lifting: {}",
        circuit_trace_log_size, circuit_lifting
    );

    // The circuit may need a larger domain than the Cairo proof.
    // Recompute twiddles for the maximum of both.
    let max_domain = max(cairo_lifting, circuit_lifting);
    let twiddles =
        SimdBackend::precompute_twiddles(CanonicCoset::new(max_domain).circle_domain().half_coset);

    // Commit to the circuit's preprocessed trace.
    let circuit_pp_trace = preprocessed_circuit
        .preprocessed_trace
        .get_trace::<SimdBackend>();
    let circuit_pp_polys = SimdBackend::interpolate_columns(circuit_pp_trace, &twiddles);
    let circuit_pp_tree = CommitmentTreeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(
        circuit_pp_polys,
        CIRCUIT_FRI_CONFIG.log_blowup_factor,
        &twiddles,
        true,
        Some(circuit_lifting),
        &base_column_pool,
    );

    let circuit_pcs_config = PcsConfig {
        pow_bits: 26,
        fri_config: CIRCUIT_FRI_CONFIG,
        lifting_log_size: Some(circuit_lifting),
    };
    let circuit_config = CircuitConfig {
        config: circuit_pcs_config,
        output_addresses: preprocessed_circuit.params.output_addresses.clone(),
        n_blake_gates: preprocessed_circuit.params.n_blake_gates,
        preprocessed_column_ids: preprocessed_circuit.preprocessed_trace.ids(),
        // The preprocessed root is the Merkle root of the circuit's own
        // preprocessed trace — it's a public parameter of the circuit.
        preprocessed_root: circuit_pp_tree.commitment.root().into(),
    };

    let circuit_proof_config = {
        use circuit_air::statement::all_circuit_components;
        ProofConfig::from_components(
            &all_circuit_components::<QM31>(),
            preprocessed_circuit.preprocessed_trace.ids().len(),
            &circuit_pcs_config,
            CIRCUIT_INTERACTION_POW_BITS,
        )
    };

    // Run the Stwo prover on the circuit trace.
    let t_circuit = Instant::now();
    info!("Proving circuit");
    let circuit_proof = prove_circuit_with_precompute(
        &base_column_pool,
        &twiddles,
        &preprocessed_circuit,
        MaybeOwned::Borrowed(&circuit_pp_tree),
        context_values,
        circuit_config.config,
    );
    let circuit_prove_ms = t_circuit.elapsed().as_millis();
    info!("Circuit proof generated in {}ms", circuit_prove_ms);

    // ── Serialize and compress ────────────────────────────────────────
    info!("Serializing circuit proof");
    let (proof_qm31s, circuit_public_data) =
        prepare_circuit_proof_for_circuit_verifier(circuit_proof, &circuit_proof_config);
    let mut proof_bytes: Vec<u8> = vec![];
    proof_qm31s.serialize(&mut proof_bytes);
    let compressed = zstd::encode_all(&proof_bytes[..], 3)?;

    // ── Capture verification metadata for standalone verification ────
    let verify_meta = {
        use stwo::core::fields::qm31::QM31;
        let hash_to_m31s = |h: &circuits::blake::HashValue<QM31>| -> Vec<u32> {
            let mut v = qm31_to_m31s(h.0);
            v.extend(qm31_to_m31s(h.1));
            v
        };

        VerifyMeta {
            // ProofConfig
            n_pow_bits: circuit_proof_config.n_proof_of_work_bits,
            n_preprocessed_columns: circuit_proof_config.n_preprocessed_columns,
            n_trace_columns: circuit_proof_config.n_trace_columns,
            n_interaction_columns: circuit_proof_config.n_interaction_columns,
            trace_columns_per_component: circuit_proof_config.trace_columns_per_component.clone(),
            interaction_columns_per_component: circuit_proof_config
                .interaction_columns_per_component
                .clone(),
            cumulative_sum_columns: circuit_proof_config.cumulative_sum_columns.clone(),
            n_components: circuit_proof_config.n_components,
            fri_log_trace_size: circuit_proof_config.fri.log_trace_size,
            fri_log_blowup: circuit_proof_config.fri.log_blowup_factor as u32,
            fri_log_last_layer: circuit_proof_config.fri.log_n_last_layer_coefs as u32,
            fri_n_queries: circuit_proof_config.fri.n_queries,
            fri_fold_step: circuit_proof_config.fri.fold_step as u32,
            interaction_pow_bits: circuit_proof_config.interaction_pow_bits,
            // CircuitConfig
            circuit_pow_bits: circuit_config.config.pow_bits,
            circuit_fri_log_blowup: circuit_config.config.fri_config.log_blowup_factor,
            circuit_fri_log_last_layer: circuit_config
                .config
                .fri_config
                .log_last_layer_degree_bound,
            circuit_fri_n_queries: circuit_config.config.fri_config.n_queries,
            circuit_fri_fold_step: circuit_config.config.fri_config.fold_step,
            circuit_lifting: circuit_config.config.lifting_log_size,
            output_addresses: circuit_config.output_addresses.clone(),
            n_blake_gates: circuit_config.n_blake_gates,
            preprocessed_column_ids: circuit_config
                .preprocessed_column_ids
                .iter()
                .map(|id| id.id.to_string())
                .collect(),
            preprocessed_root: hash_to_m31s(&circuit_config.preprocessed_root),
            // CircuitPublicData
            public_output_values: circuit_public_data
                .output_values
                .iter()
                .flat_map(|q| qm31_to_m31s(*q))
                .collect(),
        }
    };

    // ── Verify both proofs ───────────────────────────────────────────
    let t_verify = Instant::now();

    info!("Verifying Cairo proof");
    cairo_air::verifier::verify_cairo_ex::<Blake2sM31MerkleChannel>(
        cairo_proof.into(),
        CUSTOM_PROVER_PARAMS.include_all_preprocessed_columns,
    )
    .map_err(|e| anyhow!("{e}"))?;

    info!("Verifying circuit proof");
    use circuit_air::verify::verify_circuit;
    verify_circuit(circuit_config, proof_qm31s, circuit_public_data)
        .map_err(|e| anyhow!("circuit verify: {e}"))?;

    let verify_ms = t_verify.elapsed().as_millis();
    info!("Both proofs verified in {}ms", verify_ms);

    Ok(CustomProofOutput {
        proof: compressed,
        output_preimage,
        verify_meta,
        cairo_prove_ms,
        circuit_prove_ms,
        verify_ms,
    })
}
