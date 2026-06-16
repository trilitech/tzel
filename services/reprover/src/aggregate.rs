//! TZEL aggregation harness — recursive STARK proof composition via
//! `circuit_multiverifier`.
//!
//! Architecture
//! ------------
//!
//! Given N leaf proofs (each a circuit-shaped Cairo verifier proof produced
//! by the existing two-level pipeline in [`crate::custom_circuit`]), we
//! build a binary tree of `circuit_multiverifier` nodes:
//!
//! ```text
//!                      root proof (level d)
//!                       /              \
//!                      /                \
//!                  mv proof          mv proof          ← level d-1
//!                 /        \        /        \
//!                ...      ...      ...      ...
//!               P1        P2       P3        P4        ← level 0 (leaves)
//! ```
//!
//! Each tree node verifies its two children inside a STARK circuit and emits
//! one STARK proof. After level 1 every node has the same shape (the
//! multiverifier's own preprocessed), so the same SharedConfig is reused for
//! all internal levels.
//!
//! Shapes
//! ------
//! - Leaves (level 0): Cairo verifier circuit. Shape derived from the
//!   `PreprocessedCircuit` of the Cairo verifier topology.
//! - Internal nodes (level ≥ 1): multiverifier circuit. Shape derived from
//!   the `PreprocessedCircuit` of `build_multiverifier_circuit::<NoValue>`.
//!
//! The leaf-shape vs internal-shape distinction is captured in
//! [`AggregationShape`]. Per-level SharedConfig and PreprocessedCircuit are
//! computed once and reused.
//!
//! Scope (G2)
//! ----------
//! This module exposes the harness: pair → prove and tree-walk. It does
//! NOT include the E2E plumbing from a Cairo executable down to leaf
//! `CircuitProof`s — that's wired up in G3.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use circuit_common::finalize::finalize_context;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_multiverifier::verify::{
    MultiverifierInput, SharedConfig, build_multiverifier_circuit,
};
use circuit_common::N_RESERVED;
use circuit_prover::prover::{
    CircuitProof, prepare_circuit_proof_for_circuit_verifier, prove_circuit_assignment,
};
use circuit_verifier::statement::{INTERACTION_POW_BITS, all_circuit_components};
use circuits::blake::HashValue;
use circuits::ivalue::NoValue;
use circuits_stark_verifier::proof::{ProofConfig, empty_proof};
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::mempool::BaseColumnPool;

/// Aggregation node level. Level 0 = leaves (Cairo verifier proofs).
/// Levels ≥ 1 = multiverifier proofs (same shape across all levels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregationShape {
    /// Children are Cairo verifier proofs.
    Leaf,
    /// Children are multiverifier proofs.
    Internal,
}

/// One node of the aggregation tree, ready to be combined with a sibling.
pub struct AggregationNode {
    /// The STARK proof produced for this subtree.
    pub proof: CircuitProof<Blake2sM31MerkleHasher>,
    /// The shape the proof has (its `PreprocessedCircuit` family).
    pub shape: AggregationShape,
    /// Per-component `log_sizes` of the multiverifier node that produced
    /// this proof, captured during `aggregate_pair` when the
    /// `TZEL_DUMP_LOG_SIZES=1` env var is set (otherwise `None`).
    ///
    /// These are the values the gnark BenchCircuit hardcodes as
    /// `l2ComponentLogSizes` and Fiat-Shamir-binds; the fixture exporter
    /// emits them into the shape sidecar. `None` for leaf inputs (which
    /// are not produced by `aggregate_pair`).
    pub component_log_sizes: Option<Vec<u32>>,
}

/// Per-level resources reused across all nodes at the same level (or, for
/// the internal level, across all levels ≥ 1).
///
/// Two multiverifier topologies are needed in a binary tree:
///
/// 1. `leaf_to_mv_preprocessed` — the multiverifier that VERIFIES two
///    leaf-shape proofs. Used at level 0 → 1.
/// 2. `mv_to_mv_preprocessed` — the multiverifier that VERIFIES two
///    multiverifier-shape proofs. Used at every level ≥ 1, since all
///    multiverifier proofs share the same outer shape.
///
/// The matching `SharedConfig` describes the inner-proof shape (leaf or
/// internal). Earlier `aggregate.rs` revisions used `leaf_to_mv_preprocessed`
/// for both levels, which causes silent witness corruption at level ≥ 1
/// (xor_8 / eq panics during `prove_circuit_assignment`) because the
/// preprocessed addresses don't match the runtime topology.
pub struct AggregationContext {
    pub leaf_shared_config: SharedConfig,
    pub leaf_preprocessed: Arc<PreprocessedCircuit>,
    pub leaf_to_mv_preprocessed: Arc<PreprocessedCircuit>,
    pub internal_shared_config: SharedConfig,
    pub mv_to_mv_preprocessed: Arc<PreprocessedCircuit>,
}

impl AggregationContext {
    /// Build the per-shape resources.
    ///
    /// `leaf_preprocessed` and `leaf_pcs_config` describe the Cairo verifier
    /// circuit shape that the leaves of the tree have. They typically come
    /// from the same pipeline that produced the leaves (see
    /// [`crate::custom_circuit`]).
    pub fn new(
        leaf_preprocessed: Arc<PreprocessedCircuit>,
        leaf_pcs_config: PcsConfig,
    ) -> Result<Self> {
        let components = all_circuit_components::<QM31>();
        let enabled_bits = vec![true; components.len()];

        let leaf_proof_config = ProofConfig::new(
            &components,
            enabled_bits.clone(),
            leaf_preprocessed.preprocessed_trace.n_columns(),
            &leaf_pcs_config,
            INTERACTION_POW_BITS,
        );
        let leaf_shared_config = SharedConfig {
            pcs_config: leaf_pcs_config,
            proof_config: leaf_proof_config,
            preprocessed_column_log_sizes: leaf_preprocessed.preprocessed_trace.log_sizes(),
        };

        // Build the multiverifier's preprocessed for the level 0 → 1 case:
        // the inner proofs are leaf-shape. The topology is captured once via
        // a `NoValue` build over `leaf_shared_config`.
        let mut nv_leaf_to_mv = build_multiverifier_circuit::<NoValue>(
            empty_mv_input(&leaf_shared_config),
            empty_mv_input(&leaf_shared_config),
            &leaf_shared_config,
        );
        let leaf_to_mv_preprocessed =
            Arc::new(PreprocessedCircuit::preprocess_circuit(&mut nv_leaf_to_mv));

        // The level-1 proofs are produced with a config derived from
        // `PcsConfig::default()` but with `lifting_log_size` set explicitly:
        // `prove_circuit_assignment` injects it at prove time, so the
        // verifier-side config must match (otherwise stark_verifier's
        // `proof.rs:294` panics with "Lifting log size must be set"). The
        // lifting equals `trace_log_size + log_blowup_factor` — same formula
        // the prover uses internally.
        //
        // The internal_pcs_config is the FRI config the multiverifier root
        // proof uses. Composite soundness = min(N × leaf_bits, mv_bits, ...);
        // for production we must align mv_bits with the desired total.
        //
        // Aligned with stwo-gnark-tzel's chip target shape (chip-compat):
        //   pow_bits=10, log_blowup=1, n_queries=23, fold_step=1
        // = 33 bits conjectured FRI soundness (Stwo's own security_bits
        // formula). Not production-grade; sized for E2E pipeline validation
        // against the existing 110M-constraint chip. For prod (96 bits) bump
        // n_queries=35 + log_blowup=2 (option β per MULTIVERIFIER-REBUILD-PLAN
        // in the stwo-gnark-tzel sibling repo) and re-Setup the chip.
        let base_internal_pcs_config = PcsConfig {
            pow_bits: 10,
            fri_config: stwo::core::fri::FriConfig {
                log_blowup_factor: 1,
                log_last_layer_degree_bound: 0,
                n_queries: 23,
                fold_step: 1,
            },
            lifting_log_size: None,
        };
        let internal_lifting = leaf_to_mv_preprocessed.params.trace_log_size
            + base_internal_pcs_config.fri_config.log_blowup_factor;
        let internal_pcs_config = PcsConfig {
            lifting_log_size: Some(internal_lifting),
            ..base_internal_pcs_config
        };
        let internal_proof_config = ProofConfig::new(
            &components,
            enabled_bits.clone(),
            leaf_to_mv_preprocessed.preprocessed_trace.n_columns(),
            &internal_pcs_config,
            INTERACTION_POW_BITS,
        );
        let internal_shared_config = SharedConfig {
            pcs_config: internal_pcs_config,
            proof_config: internal_proof_config,
            preprocessed_column_log_sizes: leaf_to_mv_preprocessed
                .preprocessed_trace
                .log_sizes(),
        };

        // Build the multiverifier's preprocessed for level ≥ 1: the inner
        // proofs are multiverifier-shape. F3 reference test calls this
        // `preprocessed_root_pp`. The same preprocessed is reused for every
        // internal level because all multiverifier proofs share an outer
        // shape (same components, same n_outputs, same column log_sizes).
        let mut nv_mv_to_mv = build_multiverifier_circuit::<NoValue>(
            empty_mv_input(&internal_shared_config),
            empty_mv_input(&internal_shared_config),
            &internal_shared_config,
        );
        let mv_to_mv_preprocessed =
            Arc::new(PreprocessedCircuit::preprocess_circuit(&mut nv_mv_to_mv));

        Ok(Self {
            leaf_shared_config,
            leaf_preprocessed,
            leaf_to_mv_preprocessed,
            internal_shared_config,
            mv_to_mv_preprocessed,
        })
    }
}

/// Build a `NoValue` `MultiverifierInput` shaped per the given SharedConfig.
fn empty_mv_input(shared_config: &SharedConfig) -> MultiverifierInput<NoValue> {
    MultiverifierInput::<NoValue> {
        proof: empty_proof(&shared_config.proof_config),
        preprocessed_root: HashValue(QM31::default(), QM31::default()),
        output_values: [QM31::default(); N_RESERVED],
    }
}

/// Combine two sibling nodes into a single multiverifier proof. The
/// resulting node always has shape [`AggregationShape::Internal`].
pub fn aggregate_pair(
    ctx: &AggregationContext,
    left: AggregationNode,
    right: AggregationNode,
) -> Result<AggregationNode> {
    if left.shape != right.shape {
        return Err(anyhow!(
            "aggregate_pair: sibling shapes differ ({:?} vs {:?})",
            left.shape,
            right.shape
        ));
    }

    // The `shared_config` describes the SHAPE of the INNER proofs to be
    // verified by the multiverifier (i.e. the children we just unpacked).
    // The OUTER multiverifier's own `prove_circuit_assignment` step uses
    // a preprocessed whose topology was built FROM THIS SAME shared_config
    // (otherwise the witness address layout doesn't match the runtime
    // node_ctx, producing silent value corruption and downstream xor_8/eq
    // panics during witness extraction).
    let (shared_config, mv_preprocessed) = match left.shape {
        AggregationShape::Leaf => (&ctx.leaf_shared_config, &ctx.leaf_to_mv_preprocessed),
        AggregationShape::Internal => (&ctx.internal_shared_config, &ctx.mv_to_mv_preprocessed),
    };

    let mv_input_left = circuit_proof_to_mv_input(left.proof, shared_config);
    let mv_input_right = circuit_proof_to_mv_input(right.proof, shared_config);

    let mut node_ctx = build_multiverifier_circuit(mv_input_left, mv_input_right, shared_config);
    if !node_ctx.is_circuit_valid() {
        return Err(anyhow!(
            "multiverifier constraints failed — input proofs do not verify inside the aggregator"
        ));
    }
    finalize_context(&mut node_ctx);

    // Optional debug dump of the multiverifier's per-component log_sizes +
    // preprocessed root — the data the gnark BenchCircuit hardcodes
    // (`l2ComponentLogSizes`, `L2PreprocessedRoot`) for the SNARK-wrap chip
    // rebuild. Gated by env var so the prod path is unaffected.
    let mut component_log_sizes = None;
    if std::env::var("TZEL_DUMP_LOG_SIZES").as_deref() == Ok("1") {
        let label = match left.shape {
            AggregationShape::Leaf => "leaf_to_mv",
            AggregationShape::Internal => "mv_to_mv",
        };
        component_log_sizes = Some(debug_dump_component_log_sizes(
            node_ctx.values(),
            mv_preprocessed,
            ctx.internal_shared_config.pcs_config,
            label,
        ));
    }

    let proof = prove_circuit_assignment(
        node_ctx.values(),
        mv_preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
        ctx.internal_shared_config.pcs_config,
    )
    .map_err(|e| anyhow!("prove multiverifier node: {e}"))?;

    Ok(AggregationNode {
        proof,
        shape: AggregationShape::Internal,
        component_log_sizes,
    })
}

/// Debug helper — standalone `write_trace` replay that captures the
/// multiverifier's per-component `log_sizes` and the preprocessed root.
/// These feed the gnark BenchCircuit's hardcoded constants
/// (`l2ComponentLogSizes`, `L2PreprocessedRoot`) for the SNARK-wrap
/// chip rebuild.
///
/// Faithful copy of witness-extractor's `debug_dump_l2_component_log_sizes`
/// (stwo-gnark-tzel/tools/witness-extractor/src/main.rs:720-800) — the
/// recipe mirrors `prove_circuit_with_precompute` up to (and excluding)
/// the interaction draw, then discards the tree builder.
pub fn debug_dump_component_log_sizes(
    values: &[QM31],
    preprocessed_circuit: &PreprocessedCircuit,
    pcs_config: PcsConfig,
    label: &str,
) -> Vec<u32> {
    use circuit_common::Qm31OpsTraceGenerator;
    use circuit_prover::witness::trace::{TraceGenerator, write_trace};
    use stwo::core::channel::{Channel, MerkleChannel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::CommitmentTreeProver;
    use stwo::prover::pcs::CommitmentSchemeProver;
    use stwo::prover::poly::circle::PolyOps;

    // Local constant — upstream prover.rs has this private (=1).
    const COMPOSITION_POLYNOMIAL_LOG_DEGREE_BOUND: u32 = 1;

    let base_column_pool = BaseColumnPool::<SimdBackend>::new();

    let trace_log_size = preprocessed_circuit.params.trace_log_size;
    let lifting_log_size = trace_log_size + pcs_config.fri_config.log_blowup_factor;
    let pcs_config = PcsConfig {
        lifting_log_size: Some(lifting_log_size),
        ..pcs_config
    };

    // Precompute twiddles — account for blowup + composition split.
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(
            trace_log_size
                + std::cmp::max(
                    pcs_config.fri_config.log_blowup_factor,
                    COMPOSITION_POLYNOMIAL_LOG_DEGREE_BOUND,
                ),
        )
        .circle_domain()
        .half_coset,
    );

    // Build preprocessed tree (tree 0).
    let preprocessed_trace_cols = preprocessed_circuit
        .preprocessed_trace
        .get_trace::<SimdBackend>();
    let preprocessed_trace_polys =
        SimdBackend::interpolate_columns(preprocessed_trace_cols, &twiddles);
    let preprocessed_tree = CommitmentTreeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(
        preprocessed_trace_polys,
        pcs_config.fri_config.log_blowup_factor,
        &twiddles,
        true,
        pcs_config.lifting_log_size,
        &base_column_pool,
    );

    // Dump the preprocessed root (hex) — chip-side `L2PreprocessedRoot`.
    // Same HashValue<QM31> → 8 LE M31 words encoding as witness-extractor's
    // shape sidecar (main.rs:434-443).
    let root_hv: HashValue<QM31> = preprocessed_tree.commitment.root().into();
    let mut root_bytes = Vec::with_capacity(32);
    for c in root_hv
        .0
        .to_m31_array()
        .iter()
        .chain(root_hv.1.to_m31_array().iter())
    {
        root_bytes.extend_from_slice(&c.0.to_le_bytes());
    }
    eprintln!(
        "[TZEL_DUMP {label}] preprocessed_root_hex = {}",
        hex::encode(&root_bytes)
    );
    eprintln!("[TZEL_DUMP {label}] trace_log_size = {trace_log_size}");
    eprintln!("[TZEL_DUMP {label}] lifting_log_size = {lifting_log_size}");

    // Fresh channel + commitment scheme, mirroring prove_circuit_with_precompute
    // up to (and excluding) the interaction draw.
    let channel = &mut <Blake2sM31MerkleChannel as MerkleChannel>::C::default();
    let channel_salt: u32 = 0;
    channel.mix_felts(&[channel_salt.into()]);
    pcs_config.mix_into(channel);

    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sM31MerkleChannel>::with_memory_pool(
            pcs_config,
            &twiddles,
            &base_column_pool,
        );
    commitment_scheme.set_store_polynomials_coefficients();
    commitment_scheme.commit_tree(
        stwo::core::utils::MaybeOwned::Owned(preprocessed_tree),
        channel,
    );

    let trace_generator = TraceGenerator {
        qm31_ops_trace_generator: Qm31OpsTraceGenerator {
            first_permutation_row: preprocessed_circuit.params.first_permutation_row,
        },
    };
    let mut tree_builder = commitment_scheme.tree_builder();
    let (_claim, component_log_sizes, _interaction_generator) = write_trace(
        values,
        preprocessed_circuit.preprocessed_trace.clone(),
        preprocessed_circuit.params.n_outputs,
        &mut tree_builder,
        &trace_generator,
        &twiddles,
    );

    eprintln!("[TZEL_DUMP {label}] component_log_sizes = {component_log_sizes:?}");
    // tree_builder + commitment_scheme dropped here — no side effects.
    component_log_sizes.to_vec()
}

/// SPIKE (item-d, BN254 outer recursion layer) — build the OUTER multiverifier
/// circuit that VERIFIES two `Internal`-shape (Blake2sM31-committed) inner
/// proofs, then prove + commit the OUTER proof with an arbitrary
/// `MerkleChannel` (e.g. `Poseidon2Bn254MerkleChannel`).
///
/// This is the only field-change recursion step: the inner mv-root proof(s)
/// stay Blake2sM31-committed (they are finished `CircuitProof<Blake2sM31…>`),
/// and the outer AIR verifies them exactly as `aggregate_pair` does today
/// (`build_multiverifier_circuit` over the same `internal_shared_config`).
/// Only the OUTER proof's Merkle commitment + Fiat-Shamir transcript become
/// `MC`. The two-channel mismatch is sound because the inner proof's verifier
/// transcript is replayed *inside the circuit* as Blake constraints (the
/// outer commitment hash is independent of the inner one).
///
/// Returns the raw `CircuitProof<MC::H>` plus the witness `values` (needed by
/// [`stwo_verify_outer`] to rebuild the verifier-side components).
#[allow(clippy::type_complexity)]
pub fn aggregate_pair_outer_with_channel<MC>(
    ctx: &AggregationContext,
    left: CircuitProof<Blake2sM31MerkleHasher>,
    right: CircuitProof<Blake2sM31MerkleHasher>,
) -> Result<(
    circuit_verifier::circuit_proof::CircuitProof<MC::H>,
    Vec<QM31>,
)>
where
    MC: stwo::core::channel::MerkleChannel,
    SimdBackend: stwo::prover::backend::BackendForChannel<MC>,
{
    use circuit_prover::prover::prove_circuit_assignment_with_channel;

    // Inner proofs are Internal (mv) shape.
    let shared_config = &ctx.internal_shared_config;
    let mv_preprocessed = &ctx.mv_to_mv_preprocessed;

    let mv_input_left = circuit_proof_to_mv_input(left, shared_config);
    let mv_input_right = circuit_proof_to_mv_input(right, shared_config);

    let mut node_ctx = build_multiverifier_circuit(mv_input_left, mv_input_right, shared_config);
    if !node_ctx.is_circuit_valid() {
        return Err(anyhow!(
            "outer multiverifier constraints failed — inner mv proofs do not verify inside the aggregator"
        ));
    }
    finalize_context(&mut node_ctx);

    let values: Vec<QM31> = node_ctx.values().to_vec();

    let proof = prove_circuit_assignment_with_channel::<MC>(
        &values,
        mv_preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
        ctx.internal_shared_config.pcs_config,
    )
    .map_err(|e| anyhow!("prove outer multiverifier node (BN254 channel): {e}"))?;

    Ok((proof, values))
}

/// SPIKE — full stwo STARK verification of an OUTER multiverifier proof
/// committed/transcripted with `MC` (mirrors the channel-generic recipe of
/// stwo-circuits' `prover_test::stwo_verify`, specialised to the
/// multiverifier / `circuit_verifier` component family).
///
/// Re-derives the verifier transcript over `MC::C`, commits the 3 trees with
/// `MC`, replays the interaction PoW + draw, then calls
/// `stwo::core::verifier::verify_ex::<MC>` against the outer `stark_proof`.
pub fn stwo_verify_outer<MC>(
    proof: circuit_verifier::circuit_proof::CircuitProof<MC::H>,
    preprocessed_circuit: &PreprocessedCircuit,
) -> Result<()>
where
    MC: stwo::core::channel::MerkleChannel,
{
    use circuit_verifier::circuit_claim::{
        CircuitInteractionElements, column_log_sizes_per_tree, lookup_sum,
    };
    use circuit_verifier::circuit_components::N_COMPONENTS;
    use circuit_verifier::statement::{INTERACTION_POW_BITS, all_circuit_components};
    use circuit_prover::circuit_air::circuit_components::CircuitComponents;
    use stwo::core::air::Component;
    use stwo::core::channel::Channel;
    use stwo::core::pcs::CommitmentSchemeVerifier;

    let circuit_verifier::circuit_proof::CircuitProof {
        claim,
        interaction_claim,
        pcs_config,
        stark_proof,
        interaction_pow_nonce,
        channel_salt,
    } = proof;

    let preprocessed_column_log_sizes = preprocessed_circuit.preprocessed_trace.log_sizes();
    let log_sizes: [u32; N_COMPONENTS] = all_circuit_components::<circuits::ivalue::NoValue>()
        .values()
        .map(|c| {
            c.log_size(&preprocessed_column_log_sizes)
                .expect("circuit components must have a static log_size")
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow!("component count != N_COMPONENTS"))?;

    let verifier_channel = &mut MC::C::default();
    verifier_channel.mix_felts(&[channel_salt.into()]);
    pcs_config.mix_into(verifier_channel);
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(pcs_config);

    let [trace_log_sizes, interaction_log_sizes] = column_log_sizes_per_tree(&log_sizes);

    commitment_scheme.commit(
        stark_proof.proof.commitments[0],
        &preprocessed_column_log_sizes
            .values()
            .copied()
            .collect::<Vec<_>>(),
        verifier_channel,
    );
    claim.mix_into(verifier_channel);
    commitment_scheme.commit(
        stark_proof.proof.commitments[1],
        &trace_log_sizes,
        verifier_channel,
    );

    if !verifier_channel.verify_pow_nonce(INTERACTION_POW_BITS, interaction_pow_nonce) {
        return Err(anyhow!("outer interaction PoW nonce verification failed"));
    }
    verifier_channel.mix_u64(interaction_pow_nonce);
    let interaction_elements = CircuitInteractionElements::draw(verifier_channel);
    interaction_claim.mix_into(verifier_channel);
    commitment_scheme.commit(
        stark_proof.proof.commitments[2],
        &interaction_log_sizes,
        verifier_channel,
    );

    let components = CircuitComponents::new(
        &interaction_elements,
        &interaction_claim,
        &log_sizes,
        &preprocessed_circuit.preprocessed_trace.ids(),
    )
    .components();

    stwo::core::verifier::verify_ex::<MC>(
        &components
            .iter()
            .map(|c| c.as_ref())
            .collect::<Vec<&dyn Component>>(),
        verifier_channel,
        commitment_scheme,
        stark_proof.proof,
        true,
    )
    .map_err(|e| anyhow!("outer stwo verify_ex: {e:?}"))?;

    if lookup_sum(&claim, &interaction_claim, &interaction_elements) != QM31::default() {
        return Err(anyhow!("outer lookup_sum != 0"));
    }
    Ok(())
}

/// Reduce N leaf nodes to a single root via a binary tree of pairwise
/// multiverifier proofs.
///
/// `leaves.len()` must be a power of two and ≥ 2. Padding is the caller's
/// responsibility (typically a "dummy" leaf duplicating an existing one).
pub fn aggregate_tree(
    ctx: &AggregationContext,
    leaves: Vec<AggregationNode>,
) -> Result<AggregationNode> {
    if leaves.is_empty() {
        return Err(anyhow!("aggregate_tree: empty input"));
    }
    if !leaves.len().is_power_of_two() {
        return Err(anyhow!(
            "aggregate_tree: input length {} is not a power of two",
            leaves.len()
        ));
    }
    if !leaves.iter().all(|n| n.shape == AggregationShape::Leaf) {
        return Err(anyhow!("aggregate_tree: all inputs must be leaves"));
    }

    let mut level: Vec<AggregationNode> = leaves;
    while level.len() > 1 {
        let mut next: Vec<AggregationNode> = Vec::with_capacity(level.len() / 2);
        let mut it = level.into_iter();
        while let (Some(l), Some(r)) = (it.next(), it.next()) {
            next.push(aggregate_pair(ctx, l, r)?);
        }
        level = next;
    }
    Ok(level.pop().expect("non-empty by construction"))
}

/// Convert a freshly produced `CircuitProof` into a `MultiverifierInput`
/// using the given `SharedConfig` to interpret its public data. The
/// preprocessed root is read from the proof's first commitment.
fn circuit_proof_to_mv_input(
    proof: CircuitProof<Blake2sM31MerkleHasher>,
    shared_config: &SharedConfig,
) -> MultiverifierInput<QM31> {
    let preprocessed_root: HashValue<QM31> =
        proof.stark_proof.proof.commitments.0[0].into();
    let (proof_qm31, public_data) =
        prepare_circuit_proof_for_circuit_verifier(proof, &shared_config.proof_config);
    let output_values: [QM31; N_RESERVED] = public_data
        .output_values
        .as_slice()
        .try_into()
        .expect("inner proof outputs length != N_RESERVED");
    MultiverifierInput {
        proof: proof_qm31,
        preprocessed_root,
        output_values,
    }
}

