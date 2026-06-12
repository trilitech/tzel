//! Export a GENUINELY DIFFERENT but VALID multiverifier-root proof.
//!
//! Mirrors `export_mv_fixture.rs`, but instead of replaying the committed
//! deterministic `run_shield_args.json`, it generates 4 self-consistent
//! SHIELD witnesses with VARIED nonces/amounts/owner-material and proves
//! them against the SAME deployed `run_shield.executable.json`.
//!
//! The deployed executable is the commit-`89834818` shield circuit
//! ("Bind shield deposits to secret-derived keys"), 19-arg layout:
//!   [v_note, fee, producer_fee, cm_new, cm_producer, deposit_id,
//!    memo_ct_hash, producer_memo_ct_hash, deposit_secret,
//!    auth_root, auth_pub_seed, nk_tag, d_j, rseed,
//!    producer_auth_root, producer_auth_pub_seed, producer_nk_tag,
//!    producer_d_j, producer_rseed]
//! Constraints the witness must satisfy (verified against the fixture in
//! `decode_check.rs`):
//!   1. deposit_id   == hash2_generic("deposit", deposit_secret)
//!   2. cm_new       == commit(d_j, v_note, derive_rcm(rseed),
//!                             owner_tag(auth_root, auth_pub_seed, nk_tag))
//!   3. cm_producer  == commit(producer_d_j, producer_fee,
//!                             derive_rcm(producer_rseed), owner_tag(...))
//!   4. producer_fee  > 0
//! memo_ct_hash / producer_memo_ct_hash are unconstrained public outputs.
//!
//! Each of the 4 leaves uses a distinct nonce, so the witnesses (and hence
//! the leaf proofs, and the aggregated mv-root) differ from the baseline
//! fixture while keeping the normalized component_log_sizes shape identical.
//!
//! Run with `TZEL_DUMP_LOG_SIZES=1`. Heavy (~3-6 min). `#[ignore]`.

use std::path::PathBuf;

use circuit_prover::prover::prepare_circuit_proof_for_circuit_verifier;
use circuit_serialize::serialize::CircuitSerialize;
use circuit_verifier::statement::{
    INTERACTION_POW_BITS as L2_INTERACTION_POW_BITS, all_circuit_components,
};
use circuits::blake::HashValue;
use circuits_stark_verifier::proof::ProofConfig;
use stwo::core::fields::qm31::QM31;
use tzel_core::{commit, derive_rcm, hash_two, owner_tag, u64_to_felt, F};
use tzel_reprover::aggregate::{
    AggregationContext, AggregationNode, AggregationShape, aggregate_tree,
};
use tzel_reprover::custom_circuit::{LeafArtifacts, produce_leaf_artifacts};
use tzel_reprover::run_privacy_bootloader;

#[derive(serde::Serialize)]
struct ProofShape {
    n_traces: usize,
    n_composition_columns: usize,
    extension_degree: usize,
    n_pow_bits: u32,
    n_interaction_pow_bits: u32,
    n_components: usize,
    n_preprocessed_columns: usize,
    n_trace_columns: usize,
    n_interaction_columns: usize,
    cumulative_sum_columns: Vec<bool>,
    enabled_bits: Vec<bool>,
    n_columns_per_trace: Vec<usize>,
    log_trace_size: usize,
    log_blowup_factor: usize,
    n_queries: usize,
    log_n_last_layer_coefs: usize,
    fold_step: usize,
    log_evaluation_domain_size: usize,
    all_fold_steps: Vec<usize>,
    l2_preprocessed_root_hex: String,
    component_log_sizes: Vec<u32>,
    preprocessed_column_registry: Vec<(String, u32)>,
    output_values_qm31s: Vec<[u32; 4]>,
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("cairo/target/dev")
        .join(name)
}

/// Big-endian, trimmed hex (matches the committed args file's encoding and
/// the original `felt_to_hex`).
fn felt_to_hex(f: &F) -> String {
    let mut be = [0u8; 32];
    for (dst, src) in be.iter_mut().zip(f.iter().rev()) {
        *dst = *src;
    }
    let s = hex::encode(be);
    let t = s.trim_start_matches('0');
    if t.is_empty() {
        "0x0".to_string()
    } else {
        format!("0x{}", t)
    }
}

fn u64_hex(v: u64) -> String {
    format!("0x{:x}", v)
}

/// "deposit" short string as a felt.
fn deposit_tag() -> F {
    // 0x6465706f736974 = b"deposit", little-endian into F.
    let bytes = b"deposit";
    let mut f = [0u8; 32];
    for (i, b) in bytes.iter().rev().enumerate() {
        f[i] = *b;
    }
    f
}

/// Build a self-consistent VARIED shield witness (89834818 layout) from a
/// per-leaf `nonce`. Every nonce yields a fresh, valid statement.
fn build_varied_shield_args(nonce: u64) -> Vec<String> {
    // ── Free knobs, all derived from `nonce` so each leaf is distinct. ──
    let v_note: u64 = 250_000 + nonce; // varied amount
    let fee: u64 = 50_000;
    let producer_fee: u64 = 1 + nonce; // > 0, varied

    // Recipient note owner material (private inputs). Pick arbitrary but
    // consistent felts; the circuit only checks the commitment opens.
    let auth_root = hash_two(&u64_to_felt(0xA001), &u64_to_felt(nonce));
    let auth_pub_seed = hash_two(&u64_to_felt(0xA002), &u64_to_felt(nonce));
    let nk_tag = hash_two(&u64_to_felt(0xA003), &u64_to_felt(nonce));
    let d_j = hash_two(&u64_to_felt(0xA004), &u64_to_felt(nonce));
    let rseed = hash_two(&u64_to_felt(0xA005), &u64_to_felt(nonce));

    let otag = owner_tag(&auth_root, &auth_pub_seed, &nk_tag);
    let cm_new = commit(&d_j, v_note, &derive_rcm(&rseed), &otag);

    // Producer-fee note owner material.
    let p_auth_root = hash_two(&u64_to_felt(0xB001), &u64_to_felt(nonce));
    let p_auth_pub_seed = hash_two(&u64_to_felt(0xB002), &u64_to_felt(nonce));
    let p_nk_tag = hash_two(&u64_to_felt(0xB003), &u64_to_felt(nonce));
    let p_d_j = hash_two(&u64_to_felt(0xB004), &u64_to_felt(nonce));
    let p_rseed = hash_two(&u64_to_felt(0xB005), &u64_to_felt(nonce));

    let p_otag = owner_tag(&p_auth_root, &p_auth_pub_seed, &p_nk_tag);
    let cm_producer = commit(&p_d_j, producer_fee, &derive_rcm(&p_rseed), &p_otag);

    // deposit_id = hash2_generic("deposit", deposit_secret)
    let deposit_secret = hash_two(&u64_to_felt(0xDEC0), &u64_to_felt(nonce));
    let deposit_id = hash_two(&deposit_tag(), &deposit_secret);

    // Unconstrained public-output memos — vary them too.
    let memo_ct_hash = hash_two(&u64_to_felt(0x3E30), &u64_to_felt(nonce));
    let producer_memo_ct_hash = hash_two(&u64_to_felt(0x3E31), &u64_to_felt(nonce));

    // 19-arg flattened layout, prefixed with the array length (20 total).
    let mut args = Vec::with_capacity(20);
    args.push(u64_hex(19)); // array-length prefix
    args.push(u64_hex(v_note));
    args.push(u64_hex(fee));
    args.push(u64_hex(producer_fee));
    args.push(felt_to_hex(&cm_new));
    args.push(felt_to_hex(&cm_producer));
    args.push(felt_to_hex(&deposit_id));
    args.push(felt_to_hex(&memo_ct_hash));
    args.push(felt_to_hex(&producer_memo_ct_hash));
    args.push(felt_to_hex(&deposit_secret));
    args.push(felt_to_hex(&auth_root));
    args.push(felt_to_hex(&auth_pub_seed));
    args.push(felt_to_hex(&nk_tag));
    args.push(felt_to_hex(&d_j));
    args.push(felt_to_hex(&rseed));
    args.push(felt_to_hex(&p_auth_root));
    args.push(felt_to_hex(&p_auth_pub_seed));
    args.push(felt_to_hex(&p_nk_tag));
    args.push(felt_to_hex(&p_d_j));
    args.push(felt_to_hex(&p_rseed));
    args
}

fn one_varied_leaf(out_dir: &std::path::Path, nonce: u64) -> LeafArtifacts {
    let exe_path = fixture("run_shield.executable.json");
    let args = build_varied_shield_args(nonce);
    let args_path = out_dir.join(format!("varied_shield_args_{nonce}.json"));
    std::fs::write(&args_path, serde_json::to_string(&args).unwrap())
        .expect("write varied args");
    let (prover_input, output_preimage) =
        run_privacy_bootloader(&exe_path, None, Some(args_path)).expect("bootloader");
    produce_leaf_artifacts(prover_input, output_preimage).expect("leaf")
}

#[test]
#[ignore]
fn export_mv_root_varied() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let out_dir = PathBuf::from("/tmp/tzel-mv-varied");
    std::fs::create_dir_all(&out_dir).expect("mkdir out_dir");

    eprintln!("[EXPORT-MV-VARIED] generating 4 varied valid SHIELD leaves …");
    let t0 = std::time::Instant::now();
    let nonces: [u64; 4] = [0x11, 0x22, 0x33, 0x44];
    let leaves: Vec<LeafArtifacts> = nonces
        .iter()
        .map(|&nonce| {
            let t = std::time::Instant::now();
            let leaf = one_varied_leaf(&out_dir, nonce);
            eprintln!("[EXPORT-MV-VARIED]   shield nonce={nonce:#x} in {:?}", t.elapsed());
            leaf
        })
        .collect();
    eprintln!("[EXPORT-MV-VARIED] 4 leaves in {:?}", t0.elapsed());

    let leaf_preprocessed = leaves[0].preprocessed_circuit.clone();
    let leaf_pcs_config = leaves[0].circuit_pcs_config;
    let ctx = AggregationContext::new(leaf_preprocessed, leaf_pcs_config).expect("ctx");

    let nodes: Vec<AggregationNode> = leaves
        .into_iter()
        .map(|l| AggregationNode {
            proof: l.circuit_proof,
            shape: AggregationShape::Leaf,
            component_log_sizes: None,
        })
        .collect();

    eprintln!("[EXPORT-MV-VARIED] aggregating 4 → 1 …");
    let t_agg = std::time::Instant::now();
    let root = aggregate_tree(&ctx, nodes).expect("aggregate_tree");
    eprintln!("[EXPORT-MV-VARIED] root in {:?}", t_agg.elapsed());
    assert_eq!(root.shape, AggregationShape::Internal);

    eprintln!("[EXPORT-MV-VARIED] pcs_config = {:?}", root.proof.pcs_config);
    eprintln!(
        "[EXPORT-MV-VARIED] root output_values = {:?}",
        root.proof.claim.output_values
    );

    let mv_actual_pcs_config = root.proof.stark_proof.proof.config;
    let mv_components = all_circuit_components::<QM31>();
    let mv_n_preprocessed_cols = ctx.mv_to_mv_preprocessed.preprocessed_trace.n_columns();
    let mv_proof_config = ProofConfig::new(
        &mv_components,
        vec![true; mv_components.len()],
        mv_n_preprocessed_cols,
        &mv_actual_pcs_config,
        L2_INTERACTION_POW_BITS,
    );

    let captured_output_values: Vec<[u32; 4]> = root
        .proof
        .claim
        .output_values
        .iter()
        .map(|q| q.to_m31_array().map(|m| m.0))
        .collect();

    let l2_preprocessed_root_hex = {
        let a = root.proof.stark_proof.proof.commitments.0[0];
        let hv: HashValue<QM31> = a.into();
        let mut h = Vec::with_capacity(32);
        for c in hv.0.to_m31_array().iter().chain(hv.1.to_m31_array().iter()) {
            h.extend_from_slice(&c.0.to_le_bytes());
        }
        hex::encode(&h)
    };

    let component_log_sizes = root
        .component_log_sizes
        .clone()
        .expect("component_log_sizes missing — run with TZEL_DUMP_LOG_SIZES=1");

    let preprocessed_column_registry: Vec<(String, u32)> = ctx
        .mv_to_mv_preprocessed
        .preprocessed_trace
        .log_sizes()
        .iter()
        .map(|(id, log_size)| (id.id.clone(), *log_size))
        .collect();

    let (proof_qm31s, public_data) = prepare_circuit_proof_for_circuit_verifier(
        root.proof,
        &ctx.internal_shared_config.proof_config,
    );
    eprintln!(
        "[EXPORT-MV-VARIED] public_data.output_values = {:?}",
        public_data.output_values
    );

    let mut bytes: Vec<u8> = vec![];
    proof_qm31s.serialize(&mut bytes);
    let out_path = out_dir.join("mv_root_proof.bin");
    std::fs::write(&out_path, &bytes).expect("write mv_root_proof.bin");
    eprintln!(
        "[EXPORT-MV-VARIED] wrote {} bytes to {}",
        bytes.len(),
        out_path.display()
    );

    let n_columns_per_trace = mv_proof_config.n_columns_per_trace().to_vec();
    let n_interaction_columns = n_columns_per_trace[2];

    let log_trace_size = mv_proof_config.fri.log_trace_size;
    let log_blowup_factor = mv_proof_config.fri.log_blowup_factor;
    let log_n_last_layer_coefs = mv_proof_config.fri.log_n_last_layer_coefs;
    let fold_step = mv_proof_config.fri.fold_step;
    let n_queries = mv_proof_config.fri.n_queries;
    let log_evaluation_domain_size = log_trace_size + log_blowup_factor;

    let all_fold_steps = {
        let degree_log_ratio = log_trace_size - log_n_last_layer_coefs;
        let n_folds = degree_log_ratio.div_ceil(fold_step);
        let rem = degree_log_ratio % fold_step;
        let mut v = vec![fold_step; n_folds];
        if rem != 0 {
            *v.last_mut().unwrap() = rem;
        }
        v
    };

    let shape = ProofShape {
        n_traces: 4,
        n_composition_columns: 8,
        extension_degree: 4,
        n_pow_bits: mv_proof_config.n_pow_bits,
        n_interaction_pow_bits: mv_proof_config.n_interaction_pow_bits,
        n_components: mv_proof_config.n_components(),
        n_preprocessed_columns: mv_proof_config.n_preprocessed_columns,
        n_trace_columns: mv_proof_config.n_trace_columns,
        n_interaction_columns,
        cumulative_sum_columns: mv_proof_config.cumulative_sum_columns.clone(),
        enabled_bits: mv_proof_config.enabled_bits.clone(),
        n_columns_per_trace,
        log_trace_size,
        log_blowup_factor,
        n_queries,
        log_n_last_layer_coefs,
        fold_step,
        log_evaluation_domain_size,
        all_fold_steps,
        l2_preprocessed_root_hex,
        component_log_sizes,
        preprocessed_column_registry,
        output_values_qm31s: captured_output_values,
    };
    let shape_json = serde_json::to_string_pretty(&shape).expect("serialize ProofShape");
    let shape_path = out_dir.join("mv_root_proof.shape.json");
    std::fs::write(&shape_path, shape_json.as_bytes()).expect("write shape.json");
    eprintln!(
        "[EXPORT-MV-VARIED] wrote shape {} bytes to {}",
        shape_json.len(),
        shape_path.display()
    );
    eprintln!(
        "[EXPORT-MV-VARIED] component_log_sizes = {:?}",
        shape.component_log_sizes
    );
    eprintln!(
        "[EXPORT-MV-VARIED] output_values_qm31s = {:?}",
        shape.output_values_qm31s
    );

    eprintln!("[EXPORT-MV-VARIED] total wall {:?}", t0.elapsed());
}
