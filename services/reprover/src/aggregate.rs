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
        let base_internal_pcs_config = PcsConfig::default();
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
    })
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

