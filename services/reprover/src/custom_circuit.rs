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
use cairo_air::flat_claims::FlatClaim;
use circuit_verifier::statement::INTERACTION_POW_BITS as CIRCUIT_INTERACTION_POW_BITS;
use circuit_verifier::verify::CircuitConfig;
use circuit_cairo_verifier::all_components::all_components;
use circuit_cairo_verifier::preprocessed_columns::CANONICAL_SMALL_PREPROCESSED_COLUMNS;
use circuit_cairo_verifier::statement::MEMORY_VALUES_LIMBS;
use circuit_cairo_verifier::verify::{
    CairoVerifierConfig, build_fixed_cairo_circuit, get_preprocessed_root,
    prepare_cairo_proof_for_circuit_verifier,
};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use circuit_common::finalize::{add_zk_blinding, finalize_context};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{
    prepare_circuit_proof_for_circuit_verifier, prove_circuit_with_precompute,
};
use circuit_serialize::serialize::CircuitSerialize;
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
    let components: indexmap::IndexMap<
        &'static str,
        Box<dyn circuits_stark_verifier::constraint_eval::CircuitEval<QM31>>,
    > = all
        .into_iter()
        .zip(enable_bits.iter())
        .filter_map(|((name, comp), &enabled)| if enabled { Some((name, comp)) } else { None })
        .collect();
    ProofConfig::new(
        &components,
        enable_bits.to_vec(),
        CANONICAL_SMALL_PREPROCESSED_COLUMNS.len(),
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

/// Level 2 PCS pow_bits for the prod config. 26 + 2*35 = 96-bit FRI soundness.
const CIRCUIT_PCS_POW_BITS_PROD: u32 = 26;

/// Chip-compat L2 FRI configuration — matches stwo-gnark-tzel's BenchCircuit
/// hardcoded shape (n_queries=23, log_blowup=1, fold_step=1). Combined with
/// PoW=10 this gives ~33-bit standalone FRI soundness, NOT production-grade.
///
/// Use this when feeding the resulting L2 STARK proof into the SNARK-wrap
/// pipeline whose chip is currently hardcoded for this shape. The chip will
/// be rebuilt for the prod shape before mainnet — at which point this
/// constant goes away.
const CIRCUIT_FRI_CONFIG_CHIP_COMPAT: FriConfig = FriConfig {
    log_blowup_factor: 1,
    log_last_layer_degree_bound: 0,
    n_queries: 23,
    fold_step: 1,
};

/// Chip-compat L2 PCS pow_bits.
const CIRCUIT_PCS_POW_BITS_CHIP_COMPAT: u32 = 10;

thread_local! {
    /// When set (via [`set_chip_compat_mode`]), `run_leaf_pipeline_internal`
    /// substitutes the chip-compat FRI + PoW config for the prod ones. Used
    /// by the `--chip-compat` flag of `reprove`.
    static CHIP_COMPAT_MODE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Enable chip-compat L2 prove mode on the current thread. Subsequent calls
/// to [`custom_recursive_prove`] (and friends) use the chip-aligned FRI
/// config instead of the prod one. See [`CIRCUIT_FRI_CONFIG_CHIP_COMPAT`].
pub fn set_chip_compat_mode() {
    CHIP_COMPAT_MODE.with(|c| c.set(true));
}

fn active_circuit_fri_config() -> FriConfig {
    if CHIP_COMPAT_MODE.with(|c| c.get()) {
        CIRCUIT_FRI_CONFIG_CHIP_COMPAT
    } else {
        CIRCUIT_FRI_CONFIG
    }
}

fn active_circuit_pcs_pow_bits() -> u32 {
    if CHIP_COMPAT_MODE.with(|c| c.get()) {
        CIRCUIT_PCS_POW_BITS_CHIP_COMPAT
    } else {
        CIRCUIT_PCS_POW_BITS_PROD
    }
}

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
    /// Raw (uncompressed) CircuitSerialize bytes — drop-in compatible with
    /// stwo-gnark-tzel's `l2_proof.bin` format. The `proof` field above is
    /// the same data zstd-compressed for storage/transport.
    pub proof_uncompressed: Vec<u8>,
    pub output_preimage: Vec<Felt>,
    pub cairo_prove_ms: u128,
    pub circuit_prove_ms: u128,
    pub verify_ms: u128,
}

/// In-memory artifacts of a single leaf proof, ready to be fed into the
/// aggregation harness (see [`crate::aggregate`]). The `circuit_proof` is
/// the raw, undelivered (non-serialized) STARK proof produced by the
/// two-level pipeline. Aggregation needs both the proof itself and the
/// `preprocessed_circuit`/`pcs_config` that describe its shape.
pub struct LeafArtifacts {
    pub circuit_proof:
        circuit_verifier::circuit_proof::CircuitProof<
            stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher,
        >,
    pub preprocessed_circuit: Arc<PreprocessedCircuit>,
    pub circuit_pcs_config: PcsConfig,
    pub output_preimage: Vec<Felt>,
    pub cairo_prove_ms: u128,
    pub circuit_prove_ms: u128,
}

/// Internal richer state returned by [`run_leaf_pipeline_internal`]. It
/// holds the artifacts callers need for aggregation
/// ([`produce_leaf_artifacts`]) plus the extra in-memory state required by
/// [`custom_recursive_prove`] to finish the serialize + verify steps.
struct LeafPipelineState {
    artifacts: LeafArtifacts,
    cairo_proof: cairo_air::CairoProof<
        stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher,
    >,
    circuit_proof_config: ProofConfig,
    circuit_config: CircuitConfig,
}

/// Run the two-level proving pipeline (Cairo AIR → circuit verifier with ZK
/// blinding). Returns the raw artifacts + the additional in-memory state
/// needed by [`custom_recursive_prove`] to serialize and verify.
fn run_leaf_pipeline_internal(
    prover_input: ProverInput,
    output_preimage: Vec<Felt>,
) -> Result<LeafPipelineState> {
    let _span = span!(Level::INFO, "run_leaf_pipeline").entered();
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
        component_log_sizes,
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
    let mut program: Vec<[M31; MEMORY_VALUES_LIMBS]> = vec![];
    for value in bootloader_program.iter_data() {
        program.push(
            Felt252::from(value.get_int().ok_or_else(|| anyhow!("bad program data"))?).get_limbs(),
        );
    }
    let cairo_lifting_log_size = cairo_proof_config.fri.log_evaluation_domain_size() as u32;
    let cairo_verifier_config = CairoVerifierConfig {
        proof_config: cairo_proof_config,
        program: Arc::from(program),
        n_outputs: 1,
        preprocessed_root: get_preprocessed_root(cairo_lifting_log_size),
        preprocessed_trace_variant: CUSTOM_PROVER_PARAMS.preprocessed_trace,
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
    let (mut public_claim, _outputs, _program) = public_data.pack_into_u32s();
    // 2bf051f: build_fixed_cairo_circuit expects public_claim to also include
    // the per-component log_sizes appended after the public data. Older
    // (618db0a-) revisions had the verifier code pull these from the
    // CircuitClaim; the new entry point gets them via public_claim.
    public_claim.extend(component_log_sizes);
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
    let circuit_fri_config = active_circuit_fri_config();
    let circuit_pcs_pow_bits = active_circuit_pcs_pow_bits();
    add_zk_blinding(&mut context, zk_blinding_seed, circuit_fri_config.n_queries);
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
            circuit_cairo_verifier::verify::build_cairo_verifier_circuit(&cairo_verifier_config);
        add_zk_blinding(&mut nv, [0; 32], circuit_fri_config.n_queries);
        PreprocessedCircuit::preprocess_circuit(&mut nv)
    };
    let circuit_trace_log_size = preprocessed_circuit.params.trace_log_size;
    let circuit_lifting = circuit_trace_log_size + circuit_fri_config.log_blowup_factor;
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
        circuit_fri_config.log_blowup_factor,
        &twiddles,
        true,
        Some(circuit_lifting),
        &base_column_pool,
    );

    let circuit_pcs_config = PcsConfig {
        pow_bits: circuit_pcs_pow_bits,
        fri_config: circuit_fri_config,
        lifting_log_size: Some(circuit_lifting),
    };
    let circuit_config = CircuitConfig {
        config: circuit_pcs_config,
        n_outputs: preprocessed_circuit.params.n_outputs,
        preprocessed_column_log_sizes: preprocessed_circuit.preprocessed_trace.log_sizes(),
        // The preprocessed root is the Merkle root of the circuit's own
        // preprocessed trace — it's a public parameter of the circuit.
        preprocessed_root: circuit_pp_tree.commitment.root().into(),
    };

    let circuit_proof_config = {
        use circuit_verifier::statement::all_circuit_components;
        let components = all_circuit_components::<QM31>();
        let n_components = components.len();
        ProofConfig::new(
            &components,
            vec![true; n_components],
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
    )
    .map_err(|e| anyhow!("{e}"))?;
    let circuit_prove_ms = t_circuit.elapsed().as_millis();
    info!("Circuit proof generated in {}ms", circuit_prove_ms);

    Ok(LeafPipelineState {
        artifacts: LeafArtifacts {
            circuit_proof,
            preprocessed_circuit: Arc::new(preprocessed_circuit),
            circuit_pcs_config,
            output_preimage,
            cairo_prove_ms,
            circuit_prove_ms,
        },
        cairo_proof,
        circuit_proof_config,
        circuit_config,
    })
}

/// Run the leaf pipeline and return only the artifacts callers need for
/// aggregation. The intermediate cairo proof + verifier configs are
/// dropped.
pub fn produce_leaf_artifacts(
    prover_input: ProverInput,
    output_preimage: Vec<Felt>,
) -> Result<LeafArtifacts> {
    Ok(run_leaf_pipeline_internal(prover_input, output_preimage)?.artifacts)
}

/// Generate a two-level recursive zero-knowledge proof.
///
/// Internally calls [`run_leaf_pipeline_internal`] to produce the in-memory
/// leaf artifacts, then serializes the circuit proof and runs sanity
/// verification of both the Cairo and circuit proofs.
pub fn custom_recursive_prove(
    prover_input: ProverInput,
    output_preimage: Vec<Felt>,
) -> Result<CustomProofOutput> {
    let LeafPipelineState {
        artifacts,
        cairo_proof,
        circuit_proof_config,
        circuit_config,
    } = run_leaf_pipeline_internal(prover_input, output_preimage)?;

    let LeafArtifacts {
        circuit_proof,
        preprocessed_circuit: _,
        circuit_pcs_config: _,
        output_preimage,
        cairo_prove_ms,
        circuit_prove_ms,
    } = artifacts;

    // ── Serialize and compress ────────────────────────────────────────
    info!("Serializing circuit proof");
    let (proof_qm31s, circuit_public_data) =
        prepare_circuit_proof_for_circuit_verifier(circuit_proof, &circuit_proof_config);
    let mut proof_bytes: Vec<u8> = vec![];
    proof_qm31s.serialize(&mut proof_bytes);
    let compressed = zstd::encode_all(&proof_bytes[..], 3)?;
    let proof_uncompressed = proof_bytes;

    // ── Verify both proofs ───────────────────────────────────────────
    let t_verify = Instant::now();

    info!("Verifying Cairo proof");
    cairo_air::verifier::verify_cairo_ex::<Blake2sM31MerkleChannel>(
        cairo_proof.into(),
        CUSTOM_PROVER_PARAMS.include_all_preprocessed_columns,
    )
    .map_err(|e| anyhow!("{e}"))?;

    info!("Verifying circuit proof");
    use circuit_verifier::verify::verify_circuit;
    verify_circuit(circuit_config, proof_qm31s, circuit_public_data)
        .map_err(|e| anyhow!("circuit verify: {e}"))?;

    let verify_ms = t_verify.elapsed().as_millis();
    info!("Both proofs verified in {}ms", verify_ms);

    Ok(CustomProofOutput {
        proof: compressed,
        proof_uncompressed,
        output_preimage,
        cairo_prove_ms,
        circuit_prove_ms,
        verify_ms,
    })
}
