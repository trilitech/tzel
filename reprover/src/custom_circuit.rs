//! Custom circuit reprover for our privacy programs.
//!
//! Builds a circuit verifier config matching the actual proof's component structure,
//! then proves the circuit.

use std::cmp::max;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, anyhow};
use cairo_air::PreProcessedTraceVariant;
use cairo_air::flat_claims::FlatClaim;
use circuit_air::verify::CircuitConfig;
use circuit_air::statement::INTERACTION_POW_BITS as CIRCUIT_INTERACTION_POW_BITS;
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
use privacy_circuit_verify::get_privacy_bootloader_program;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::Blake2Felt252;
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

/// Build a ProofConfig matching the actual proof by using the claim's enable bits.
fn build_proof_config_from_enable_bits(enable_bits: &[bool]) -> ProofConfig {
    let all = all_components::<QM31>();
    assert_eq!(all.len(), enable_bits.len());
    let components: Vec<Box<dyn circuits_stark_verifier::constraint_eval::CircuitEval<QM31>>> = all
        .into_iter()
        .zip(enable_bits.iter())
        .map(|((_name, comp), &enabled)| {
            if enabled { comp } else { Box::new(EmptyComponent {}) as _ }
        })
        .collect();
    ProofConfig::from_components(
        &components,
        PREPROCESSED_COLUMNS_ORDER.len(),
        &CAIRO_PCS_CONFIG,
        cairo_air::verifier::INTERACTION_POW_BITS,
    )
}

const CIRCUIT_FRI_CONFIG: FriConfig = FriConfig {
    log_blowup_factor: 2,
    log_last_layer_degree_bound: 0,
    n_queries: 35,
    fold_step: 4,
};

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

/// Custom prover params: CanonicalSmall with all preprocessed columns included.
/// Uses the same params as the privacy prover for now.
/// TODO: build a custom preprocessed trace without Pedersen columns for further optimization.
const CUSTOM_PROVER_PARAMS: ProverParameters = ProverParameters {
    channel_hash: ChannelHash::Blake2sM31,
    pcs_config: CAIRO_PCS_CONFIG,
    preprocessed_trace: PreProcessedTraceVariant::CanonicalSmall,
    channel_salt: 0,
    store_polynomials_coefficients: true,
    include_all_preprocessed_columns: true,
};

fn compute_output(output_preimage: &[Felt]) -> [M31; MEMORY_VALUES_LIMBS] {
    let output = Blake2Felt252::encode_felt252_data_and_calc_blake_hash(output_preimage);
    Felt252::from(output).get_limbs()
}

pub struct CustomProofOutput {
    pub proof: Vec<u8>,
    pub cairo_prove_ms: u128,
    pub circuit_prove_ms: u128,
    pub verify_ms: u128,
}

/// One-shot recursive prove: generates Cairo proof, then proves it inside a circuit.
/// No precomputation — simpler but slower per proof.
pub fn custom_recursive_prove(
    prover_input: ProverInput,
    output_preimage: Vec<Felt>,
) -> Result<CustomProofOutput> {
    let _span = span!(Level::INFO, "custom_recursive_prove").entered();

    let base_column_pool = BaseColumnPool::<SimdBackend>::new();

    let t_cairo = Instant::now();

    // Precompute Cairo side
    info!("Preparing Cairo preprocessed trace");
    let cairo_preprocessed_trace = Arc::new(
        CUSTOM_PROVER_PARAMS.preprocessed_trace.to_preprocessed_trace(),
    );
    let cairo_lifting = CAIRO_PCS_CONFIG.lifting_log_size.unwrap();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(cairo_lifting).circle_domain().half_coset,
    );
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

    // Generate Cairo proof
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

    // Extract enable bits from the actual proof claim
    let FlatClaim { component_enable_bits, .. } = cairo_proof.claim.flatten_claim();
    info!(
        "Proof has {} enabled components out of {}",
        component_enable_bits.iter().filter(|&&b| b).count(),
        component_enable_bits.len()
    );

    // Build ProofConfig matching this proof's structure
    let cairo_proof_config = build_proof_config_from_enable_bits(&component_enable_bits);

    // Verify column counts match
    let sampled = &cairo_proof.extended_stark_proof.proof.sampled_values;
    let config_cols: Vec<usize> = cairo_proof_config.n_columns_per_trace().to_vec();
    let proof_cols: Vec<usize> = sampled.0.iter().map(|t| t.len()).collect();
    info!("Config columns per trace: {:?}", config_cols);
    info!("Proof columns per trace: {:?}", proof_cols);
    assert_eq!(config_cols, proof_cols, "Column count mismatch between config and proof");

    // Build CairoVerifierConfig
    let bootloader_program = get_privacy_bootloader_program().map_err(|e| anyhow!("{e}"))?;
    let mut program = vec![];
    for value in bootloader_program.iter_data() {
        program.push(Felt252::from(value.get_int().ok_or_else(|| anyhow!("bad program data"))?).get_limbs());
    }
    let cairo_lifting_log_size = cairo_proof_config.fri.log_evaluation_domain_size() as u32;
    let cairo_verifier_config = CairoVerifierConfig {
        proof_config: cairo_proof_config,
        program,
        n_outputs: 1,
        preprocessed_root: get_preprocessed_root(cairo_lifting_log_size),
    };

    // Prepare proof for circuit verifier
    info!("Preparing Cairo proof for circuit verifier");
    let (proof, public_data) = prepare_cairo_proof_for_circuit_verifier(
        &cairo_proof,
        &cairo_verifier_config.proof_config,
    );

    // Build circuit context
    info!("Building circuit verifier context");
    let (public_claim, _outputs, _program) = public_data.pack_into_u32s();
    let outputs = compute_output(&output_preimage);
    let mut context = build_fixed_cairo_circuit(
        &cairo_verifier_config,
        proof,
        public_claim,
        vec![outputs],
    );

    if !context.is_circuit_valid() {
        return Err(anyhow!("Circuit verification failed"));
    }

    // Add ZK blinding and finalize
    let zk_blinding_seed = cairo_proof.extended_stark_proof.proof.commitments.0[1].0;
    add_zk_blinding(&mut context, zk_blinding_seed, CIRCUIT_FRI_CONFIG.n_queries);
    finalize_context(&mut context);
    let context_values = context.values();

    // Build circuit preprocessed data
    info!("Building circuit preprocessed trace");
    let preprocessed_circuit = {
        let mut nv = circuit_cairo_air::verify::build_cairo_verifier_circuit(&cairo_verifier_config);
        add_zk_blinding(&mut nv, [0; 32], CIRCUIT_FRI_CONFIG.n_queries);
        PreprocessedCircuit::preprocess_circuit(&mut nv)
    };
    let circuit_trace_log_size = preprocessed_circuit.params.trace_log_size;
    let circuit_lifting = circuit_trace_log_size + CIRCUIT_FRI_CONFIG.log_blowup_factor;
    info!("Circuit trace log_size: {}, lifting: {}", circuit_trace_log_size, circuit_lifting);

    // Need bigger twiddles if circuit is larger
    let max_domain = max(cairo_lifting, circuit_lifting);
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_domain).circle_domain().half_coset,
    );

    let circuit_pp_trace = preprocessed_circuit.preprocessed_trace.get_trace::<SimdBackend>();
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
        preprocessed_root: circuit_pp_tree.commitment.root().into(),
    };

    // Build circuit proof config
    let circuit_proof_config = {
        use circuit_air::statement::all_circuit_components;
        ProofConfig::from_components(
            &all_circuit_components::<QM31>(),
            preprocessed_circuit.preprocessed_trace.ids().len(),
            &circuit_pcs_config,
            CIRCUIT_INTERACTION_POW_BITS,
        )
    };

    // Prove circuit
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

    // Serialize circuit proof
    info!("Serializing circuit proof");
    let (proof_qm31s, circuit_public_data) =
        prepare_circuit_proof_for_circuit_verifier(circuit_proof, &circuit_proof_config);
    let mut proof_bytes: Vec<u8> = vec![];
    proof_qm31s.serialize(&mut proof_bytes);
    let compressed = zstd::encode_all(&proof_bytes[..], 3)?;

    // Verify both proofs
    let t_verify = Instant::now();

    info!("Verifying Cairo proof");
    cairo_air::verifier::verify_cairo_ex::<Blake2sM31MerkleChannel>(
        cairo_proof.into(),
        CUSTOM_PROVER_PARAMS.include_all_preprocessed_columns,
    ).map_err(|e| anyhow!("{e}"))?;

    info!("Verifying circuit proof");
    use circuit_air::verify::verify_circuit;
    verify_circuit(circuit_config, proof_qm31s, circuit_public_data)
        .map_err(|e| anyhow!("circuit verify: {e}"))?;

    let verify_ms = t_verify.elapsed().as_millis();
    info!("Both proofs verified in {}ms", verify_ms);

    Ok(CustomProofOutput {
        proof: compressed,
        cairo_prove_ms,
        circuit_prove_ms,
        verify_ms,
    })
}
