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
use circuits_stark_verifier::empty_component::EmptyComponent;
use circuits_stark_verifier::proof::ProofConfig;
use privacy_circuit_verify::{compute_privacy_bootloader_output, get_privacy_bootloader_program};
use starknet_types_core::felt::Felt;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
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

// ── Public API ───────────────────────────────────────────────────────

pub struct CustomProofOutput {
    pub proof: Vec<u8>,
    pub output_preimage: Vec<Felt>,
    pub cairo_prove_ms: u128,
    pub circuit_prove_ms: u128,
    pub verify_ms: u128,
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
        cairo_prove_ms,
        circuit_prove_ms,
        verify_ms,
    })
}
