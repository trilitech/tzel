use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use ml_kem::KeyExport;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant};
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{inbox::ExternalMessageFrame, smart_rollup::SmartRollupAddress};
#[cfg(any(test, debug_assertions))]
use tzel_core::{auth_leaf_hash, derive_auth_pub_seed};
use tzel_core::{
    commit, decrypt_memo, derive_kem_keys, derive_rcm, detect, hash,
    kernel_wire::{
        decode_kernel_inbox_message, encode_kernel_inbox_message, kernel_bridge_config_sighash,
        kernel_verifier_config_sighash, KernelDalChunkPointer, KernelDalPayloadKind,
        KernelDalPayloadPointer, KernelInboxMessage, KERNEL_BRIDGE_CONFIG_KEY_INDEX,
        KERNEL_VERIFIER_CONFIG_KEY_INDEX,
    },
    operator_api::{
        RollupDalChunk, RollupSubmission, RollupSubmissionKind, RollupSubmissionStatus,
        RollupSubmissionTransport, SubmitRollupMessageReq, SubmitRollupMessageResp,
    },
    owner_tag, verify_wots_signature_against_leaf, EncryptedNote, PaymentAddress, ASSET_TEZ, F,
};

const DEFAULT_DIRECT_MAX_MESSAGE_BYTES: usize = 4096;

#[derive(Parser, Debug)]
#[command(
    name = "tzel-operator",
    about = "TzEL rollup operator submission service"
)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    #[arg(long)]
    source_alias: String,
    #[arg(long, default_value = "operator-state")]
    state_dir: String,
    #[arg(long, default_value_t = DEFAULT_DIRECT_MAX_MESSAGE_BYTES)]
    direct_max_message_bytes: usize,
    #[arg(long)]
    dal_max_chunk_bytes: Option<usize>,
    #[arg(long, default_value = "octez-client")]
    octez_client_bin: String,
    #[arg(long)]
    octez_client_dir: Option<String>,
    #[arg(long)]
    octez_node_endpoint: Option<String>,
    #[arg(long)]
    dal_node_endpoint: Option<String>,
    #[arg(long)]
    octez_protocol: Option<String>,
    #[arg(long)]
    bearer_token: Option<String>,
    #[arg(long)]
    bearer_token_file: Option<String>,
    #[arg(long)]
    required_dal_fee: Option<u64>,
    #[arg(long)]
    dal_fee_view_material: Option<String>,
    #[arg(long)]
    dal_fee_address_index: Option<u32>,
    #[arg(long, default_value_t = 5)]
    reconcile_interval_secs: u64,
    /// Restrict DAL slot selection to a half-open range `START..END`
    /// (e.g. `0..8`). Slots are picked round-robin within the range.
    /// Defaults to the full `0..number_of_slots` reported by the DAL
    /// protocol parameters. Useful for partitioning slot usage across
    /// multiple operators sharing the same DAL node.
    #[arg(long, value_parser = parse_dal_slot_range)]
    dal_slot_range: Option<std::ops::Range<u16>>,
}

fn parse_dal_slot_range(s: &str) -> Result<std::ops::Range<u16>, String> {
    let (start_str, end_str) = s
        .split_once("..")
        .ok_or_else(|| format!("invalid --dal-slot-range '{}': expected START..END", s))?;
    let start: u16 = start_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid --dal-slot-range start '{}': {}", start_str, e))?;
    let end: u16 = end_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid --dal-slot-range end '{}': {}", end_str, e))?;
    if start >= end {
        return Err(format!(
            "--dal-slot-range start ({}) must be strictly less than end ({})",
            start, end
        ));
    }
    Ok(start..end)
}

#[derive(Clone)]
struct AppState {
    config: Arc<OperatorConfig>,
    advance_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug)]
struct OperatorConfig {
    source_alias: String,
    bearer_token: String,
    state_dir: PathBuf,
    direct_max_message_bytes: usize,
    dal_max_chunk_bytes: Option<usize>,
    octez_client_bin: String,
    octez_client_dir: Option<String>,
    octez_node_endpoint: Option<String>,
    dal_node_endpoint: Option<String>,
    octez_protocol: Option<String>,
    dal_fee_policy: Option<OperatorDalFeePolicy>,
    /// Half-open range of DAL slot indices this operator is allowed to
    /// publish to. `None` means "use all slots reported by the protocol".
    /// Validated against `number_of_slots` at publish time.
    dal_slot_range: Option<std::ops::Range<u16>>,
    octez_client_timeout: Duration,
    id_counter: AtomicU64,
    slot_counter: AtomicU64,
    reconcile_cursor: AtomicU64,
}

#[derive(Debug, Clone)]
struct OperatorDalFeePolicy {
    amount: u64,
    incoming_seed: F,
    address_index: u32,
    address: PaymentAddress,
}

fn default_chunk_attempts() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ChunkMeta {
    #[serde(default = "default_chunk_attempts")]
    attempts: u32,
    #[serde(default)]
    injected_level: Option<i32>,
    #[serde(default)]
    scan_cursor: Option<i32>,
    #[serde(default)]
    inclusion_block: Option<String>,
    #[serde(default)]
    inclusion_block_failures: u32,
    #[serde(default)]
    skipped_pruned_levels: bool,
    #[serde(default)]
    max_operations_ttl: Option<i32>,
}

impl Default for ChunkMeta {
    fn default() -> Self {
        Self {
            attempts: 1,
            injected_level: None,
            scan_cursor: None,
            inclusion_block: None,
            inclusion_block_failures: 0,
            skipped_pruned_levels: false,
            max_operations_ttl: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredSubmission {
    submission: RollupSubmission,
    #[serde(default, with = "tzel_core::hex_bytes_opt")]
    payload: Option<Vec<u8>>,
    #[serde(default)]
    chunk_meta: Vec<ChunkMeta>,
}

#[derive(Debug, Clone, Deserialize)]
struct DalProtocolParametersResp {
    number_of_slots: u64,
    cryptobox_parameters: DalCryptoboxParametersResp,
}

#[derive(Debug, Clone, Deserialize)]
struct DalCryptoboxParametersResp {
    slot_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct DalSlotPublishResp {
    commitment: String,
    commitment_proof: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DalSlotStatusResp {
    Plain(String),
    Detailed {
        kind: String,
        #[allow(dead_code)]
        attestation_lag: Option<u64>,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct OperatorViewAddressRecord {
    index: u32,
    #[serde(with = "tzel_core::hex_f")]
    d_j: F,
    #[serde(with = "tzel_core::hex_f")]
    auth_root: F,
    #[serde(with = "tzel_core::hex_f")]
    auth_pub_seed: F,
    #[serde(with = "tzel_core::hex_f")]
    nk_tag: F,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum OperatorViewMaterial {
    View {
        #[serde(rename = "version")]
        _version: u16,
        #[serde(with = "tzel_core::hex_f")]
        incoming_seed: F,
        addresses: Vec<OperatorViewAddressRecord>,
    },
    Detect {
        #[serde(rename = "version")]
        _version: u16,
        #[serde(rename = "detect_root")]
        #[serde(with = "tzel_core::hex_f")]
        _detect_root: F,
        #[serde(rename = "addr_count")]
        _addr_count: u32,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct BlockHeaderResp {
    level: i32,
}

#[derive(Debug, Clone, Deserialize)]
struct ContextConstantsResp {
    #[serde(rename = "max_operations_time_to_live")]
    max_operations_ttl: i32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ReconcileSummary {
    visited: usize,
    updated: usize,
    errors: usize,
}

const MAX_DAL_CHUNK_ATTEMPTS: u32 = 8;
const MAX_WAITING_ATTESTATION_LEVEL_AGE: i32 = 12;
const TENDERBAKE_FINALITY_LAG: i32 = 2;
const MAX_INCLUSION_SCAN_LEVELS_PER_TICK: i32 = 32;
const MAX_INCLUSION_BLOCK_LOOKUP_FAILURES: u32 = 3;

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn run(cli: Cli) -> Result<(), String> {
    let bearer_token = match (&cli.bearer_token, &cli.bearer_token_file) {
        (Some(_), Some(_)) => {
            return Err("specify only one of --bearer-token or --bearer-token-file".into())
        }
        (Some(token), None) => token.clone(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|e| format!("read bearer token file: {}", e))?
            .trim()
            .to_string(),
        (None, None) => {
            return Err("operator requires --bearer-token or --bearer-token-file".into())
        }
    };
    if bearer_token.is_empty() {
        return Err("operator bearer token must not be empty".into());
    }
    let dal_fee_policy = match (
        cli.required_dal_fee,
        cli.dal_fee_view_material.as_deref(),
        cli.dal_fee_address_index,
    ) {
        (None, None, None) => None,
        (Some(amount), Some(material_path), Some(address_index)) => Some(
            load_dal_fee_policy(amount, material_path, address_index)?,
        ),
        _ => {
            return Err(
                "specify all of --required-dal-fee, --dal-fee-view-material, and --dal-fee-address-index together"
                    .into(),
            )
        }
    };
    if cli.dal_node_endpoint.is_some() && dal_fee_policy.is_none() {
        return Err(
            "DAL publication requires --required-dal-fee, --dal-fee-view-material, and --dal-fee-address-index"
                .into(),
        );
    }
    let state_dir = PathBuf::from(&cli.state_dir);
    std::fs::create_dir_all(submissions_dir(&state_dir))
        .map_err(|e| format!("create state dir: {}", e))?;

    let state = AppState {
        config: Arc::new(OperatorConfig {
            source_alias: cli.source_alias,
            bearer_token,
            state_dir,
            direct_max_message_bytes: cli.direct_max_message_bytes,
            dal_max_chunk_bytes: cli.dal_max_chunk_bytes.filter(|value| *value > 0),
            octez_client_bin: cli.octez_client_bin,
            octez_client_dir: cli.octez_client_dir,
            octez_node_endpoint: cli.octez_node_endpoint,
            dal_node_endpoint: cli.dal_node_endpoint,
            octez_protocol: cli.octez_protocol,
            dal_fee_policy,
            dal_slot_range: cli.dal_slot_range,
            octez_client_timeout: OCTEZ_CLIENT_TIMEOUT,
            id_counter: AtomicU64::new(0),
            slot_counter: AtomicU64::new(0),
            reconcile_cursor: AtomicU64::new(0),
        }),
        advance_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    tokio::spawn(reconcile_loop(
        state.config.clone(),
        state.advance_lock.clone(),
        Duration::from_secs(cli.reconcile_interval_secs.max(1)),
    ));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/rollup/submissions", post(submit_rollup_message))
        .route("/v1/rollup/submissions/{id}", get(get_rollup_submission))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen)
        .await
        .map_err(|e| format!("bind {}: {}", cli.listen, e))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("serve: {}", e))
}

async fn healthz() -> &'static str {
    "ok"
}

fn require_bearer_auth(
    headers: &HeaderMap,
    config: &OperatorConfig,
) -> Result<(), (StatusCode, String)> {
    let Some(raw) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "missing Authorization header".into(),
        ));
    };
    let auth = raw.to_str().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "invalid Authorization header".into(),
        )
    })?;
    let Some(token) = auth.strip_prefix("Bearer ") else {
        return Err((StatusCode::UNAUTHORIZED, "expected Bearer token".into()));
    };
    if token != config.bearer_token {
        return Err((StatusCode::UNAUTHORIZED, "invalid bearer token".into()));
    }
    Ok(())
}

fn load_dal_fee_policy(
    amount: u64,
    material_path: &str,
    address_index: u32,
) -> Result<OperatorDalFeePolicy, String> {
    if amount == 0 {
        return Err("required DAL fee must be greater than zero".into());
    }
    let body = std::fs::read_to_string(material_path)
        .map_err(|e| format!("read DAL fee view material {}: {}", material_path, e))?;
    let material: OperatorViewMaterial = serde_json::from_str(&body)
        .map_err(|e| format!("parse DAL fee view material {}: {}", material_path, e))?;
    let (incoming_seed, addresses) = match material {
        OperatorViewMaterial::View {
            _version: _,
            incoming_seed,
            addresses,
        } => (incoming_seed, addresses),
        OperatorViewMaterial::Detect { .. } => {
            return Err("DAL fee policy requires view material, not detect-only material".into())
        }
    };
    let address = addresses
        .into_iter()
        .find(|record| record.index == address_index)
        .ok_or_else(|| {
            format!(
                "DAL fee view material does not contain address index {}",
                address_index
            )
        })?;
    let (ek_v, _dk_v, ek_d, _dk_d) = derive_kem_keys(&incoming_seed, address_index);
    Ok(OperatorDalFeePolicy {
        amount,
        incoming_seed,
        address_index,
        address: PaymentAddress {
            d_j: address.d_j,
            auth_root: address.auth_root,
            auth_pub_seed: address.auth_pub_seed,
            nk_tag: address.nk_tag,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        },
    })
}

fn kernel_message_matches_submission_kind(
    kind: RollupSubmissionKind,
    message: &KernelInboxMessage,
) -> bool {
    matches!(
        (kind, message),
        (
            RollupSubmissionKind::ConfigureVerifier,
            KernelInboxMessage::ConfigureVerifier(_)
        ) | (
            RollupSubmissionKind::ConfigureBridge,
            KernelInboxMessage::ConfigureBridge(_)
        ) | (RollupSubmissionKind::Shield, KernelInboxMessage::Shield(_))
            | (
                RollupSubmissionKind::Transfer,
                KernelInboxMessage::Transfer(_)
            )
            | (
                RollupSubmissionKind::Unshield,
                KernelInboxMessage::Unshield(_)
            )
    )
}

fn submission_kind_requires_dal_fee_policy(kind: RollupSubmissionKind) -> bool {
    matches!(
        kind,
        RollupSubmissionKind::Shield
            | RollupSubmissionKind::Transfer
            | RollupSubmissionKind::Unshield
    )
}

#[cfg(any(test, debug_assertions))]
fn dev_config_admin_ask() -> F {
    hash(b"tzel-dev-rollup-config-admin")
}

fn parse_runtime_felt_hex(var: &str) -> Result<F, String> {
    let value = std::env::var(var).map_err(|_| format!("missing required env var: {}", var))?;
    let bytes = hex::decode(&value).map_err(|e| format!("{} is not valid hex: {}", var, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{} must decode to exactly 32 bytes, got {}",
            var,
            bytes.len()
        ));
    }
    let mut felt = [0u8; 32];
    felt.copy_from_slice(&bytes);
    Ok(felt)
}

fn operator_config_admin_pub_seed() -> Result<F, String> {
    match std::env::var("TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX") {
        Ok(_) => parse_runtime_felt_hex("TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX"),
        Err(_) => {
            #[cfg(any(test, debug_assertions))]
            {
                return Ok(derive_auth_pub_seed(&dev_config_admin_ask()));
            }
            #[allow(unreachable_code)]
            Err("operator missing TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX".into())
        }
    }
}

fn operator_verifier_config_leaf() -> Result<F, String> {
    match std::env::var("TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX") {
        Ok(_) => parse_runtime_felt_hex("TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX"),
        Err(_) => {
            #[cfg(any(test, debug_assertions))]
            {
                return Ok(auth_leaf_hash(
                    &dev_config_admin_ask(),
                    KERNEL_VERIFIER_CONFIG_KEY_INDEX,
                ));
            }
            #[allow(unreachable_code)]
            Err("operator missing TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX".into())
        }
    }
}

fn operator_bridge_config_leaf() -> Result<F, String> {
    match std::env::var("TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX") {
        Ok(_) => parse_runtime_felt_hex("TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX"),
        Err(_) => {
            #[cfg(any(test, debug_assertions))]
            {
                return Ok(auth_leaf_hash(
                    &dev_config_admin_ask(),
                    KERNEL_BRIDGE_CONFIG_KEY_INDEX,
                ));
            }
            #[allow(unreachable_code)]
            Err("operator missing TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX".into())
        }
    }
}

fn authenticate_config_submission(message: &KernelInboxMessage) -> Result<(), String> {
    match message {
        KernelInboxMessage::ConfigureVerifier(config) => {
            let pub_seed = operator_config_admin_pub_seed()?;
            let expected_leaf = operator_verifier_config_leaf()?;
            let sighash = kernel_verifier_config_sighash(&config.config)?;
            verify_wots_signature_against_leaf(
                &sighash,
                &pub_seed,
                KERNEL_VERIFIER_CONFIG_KEY_INDEX,
                &config.signature,
                &expected_leaf,
            )
        }
        KernelInboxMessage::ConfigureBridge(config) => {
            let pub_seed = operator_config_admin_pub_seed()?;
            let expected_leaf = operator_bridge_config_leaf()?;
            let sighash = kernel_bridge_config_sighash(&config.config)?;
            verify_wots_signature_against_leaf(
                &sighash,
                &pub_seed,
                KERNEL_BRIDGE_CONFIG_KEY_INDEX,
                &config.signature,
                &expected_leaf,
            )
        }
        _ => Ok(()),
    }
}

fn decode_and_validate_submission_payload(
    kind: RollupSubmissionKind,
    payload: &[u8],
) -> Result<KernelInboxMessage, String> {
    let message = decode_kernel_inbox_message(payload)
        .map_err(|e| format!("decode kernel payload: {}", e))?;
    if !kernel_message_matches_submission_kind(kind, &message) {
        return Err("submission kind does not match kernel payload".into());
    }
    authenticate_config_submission(&message)?;
    Ok(message)
}

fn validate_fee_note_against_policy(
    policy: &OperatorDalFeePolicy,
    commitment: &F,
    enc: &EncryptedNote,
    claimed_fee: u64,
) -> Result<(), String> {
    if claimed_fee != policy.amount {
        return Err(format!(
            "DAL fee mismatch: expected {}, got {}",
            policy.amount, claimed_fee
        ));
    }
    let (_ek_v, dk_v, _ek_d, dk_d) = derive_kem_keys(&policy.incoming_seed, policy.address_index);
    if !detect(enc, &dk_d) {
        return Err("DAL fee note is not detectable by the configured operator fee address".into());
    }
    let (value, rseed, _memo) = decrypt_memo(enc, &dk_v).ok_or_else(|| {
        "DAL fee note is not decryptable by the configured operator fee address".to_string()
    })?;
    if value != policy.amount {
        return Err(format!(
            "DAL fee note decrypts to {}, expected {}",
            value, policy.amount
        ));
    }
    let rcm = derive_rcm(&rseed);
    let otag = owner_tag(
        &policy.address.auth_root,
        &policy.address.auth_pub_seed,
        &policy.address.nk_tag,
    );
    let expected = commit(&policy.address.d_j, value, &ASSET_TEZ, &rcm, &otag);
    if &expected != commitment {
        return Err(
            "DAL fee note commitment does not match the configured operator fee address".into(),
        );
    }
    Ok(())
}

fn enforce_dal_fee_policy(
    config: &OperatorConfig,
    message: &KernelInboxMessage,
) -> Result<(), String> {
    let policy = config
        .dal_fee_policy
        .as_ref()
        .ok_or_else(|| "operator is missing DAL fee policy".to_string())?;
    match message {
        KernelInboxMessage::Shield(req) => validate_fee_note_against_policy(
            policy,
            &req.producer_cm,
            &req.producer_enc,
            req.producer_fee,
        ),
        KernelInboxMessage::Transfer(req) => {
            // Phase C: 4 output slots in fixed order — cm_1
            // (recipient), cm_2 (change_1), cm_3 (change_2
            // placeholder; zero-value when not used), cm_4 (producer
            // fee, permanently tez). The producer fee lives in slot
            // 4; checking slot 3 would inspect the change_2
            // placeholder which never decrypts under the operator's
            // key, causing every Phase-C transfer to be rejected.
            validate_fee_note_against_policy(policy, &req.cm_4, &req.enc_4, policy.amount)
        }
        KernelInboxMessage::Unshield(req) => {
            validate_fee_note_against_policy(policy, &req.cm_fee, &req.enc_fee, policy.amount)
        }
        KernelInboxMessage::ConfigureVerifier(_)
        | KernelInboxMessage::ConfigureBridge(_)
        | KernelInboxMessage::DalPointer(_) => {
            Err("operator only publishes shield, transfer, and unshield payloads to DAL".into())
        }
    }
}

async fn reconcile_loop(
    config: Arc<OperatorConfig>,
    advance_lock: Arc<tokio::sync::Mutex<()>>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let _guard = advance_lock.lock().await;
        let config_for_reconcile = config.clone();
        match tokio::task::spawn_blocking(move || {
            reconcile_pending_submissions(&config_for_reconcile)
        })
        .await
        {
            Err(err) => eprintln!("reconciler join error: {}", err),
            Ok(Err(err)) => eprintln!("reconciler: {}", err),
            Ok(Ok(summary)) => {
                if summary.updated > 0 || summary.errors > 0 {
                    eprintln!(
                        "reconciler: visited={} updated={} errors={}",
                        summary.visited, summary.updated, summary.errors
                    );
                }
            }
        }
    }
}

async fn submit_rollup_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SubmitRollupMessageReq>,
) -> Result<Json<SubmitRollupMessageResp>, (StatusCode, String)> {
    require_bearer_auth(&headers, &state.config)?;
    let _guard = state.advance_lock.lock().await;
    let config = state.config.clone();
    let submission = tokio::task::spawn_blocking(move || process_submission(&config, req))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("submission task failed: {}", e),
            )
        })?
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    Ok(Json(SubmitRollupMessageResp { submission }))
}

async fn get_rollup_submission(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<SubmitRollupMessageResp>, (StatusCode, String)> {
    require_bearer_auth(&headers, &state.config)?;
    let config = state.config.clone();
    let stored = tokio::task::spawn_blocking({
        let config = config.clone();
        let id = id.clone();
        move || load_stored_submission(&config.state_dir, &id)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("load submission task failed: {}", e),
        )
    })?
    .map_err(map_load_submission_err)?;
    Ok(Json(SubmitRollupMessageResp {
        submission: stored.submission,
    }))
}

fn map_load_submission_err(err: String) -> (StatusCode, String) {
    if err.contains("No such file") {
        (StatusCode::NOT_FOUND, err)
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, err)
    }
}

fn reconcile_pending_submissions(config: &OperatorConfig) -> Result<ReconcileSummary, String> {
    let mut summary = ReconcileSummary::default();
    let mut scan_budget = MAX_INCLUSION_SCAN_LEVELS_PER_TICK;
    let mut cached_head_level: Option<Result<i32, String>> = None;
    let mut pending = Vec::new();
    for path in submission_paths(&config.state_dir)? {
        let Some(id) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(|s| s.to_string())
        else {
            continue;
        };
        let stored = match load_stored_submission(&config.state_dir, &id) {
            Ok(stored) => stored,
            Err(err) => {
                summary.errors += 1;
                eprintln!("reconciler: load submission {}: {}", id, err);
                continue;
            }
        };
        if matches!(
            stored.submission.status,
            RollupSubmissionStatus::PendingDal
                | RollupSubmissionStatus::CommitmentIncluded
                | RollupSubmissionStatus::Attested
        ) {
            pending.push((id, stored));
        }
    }
    if !pending.is_empty() {
        let start =
            (config.reconcile_cursor.fetch_add(1, Ordering::Relaxed) as usize) % pending.len();
        pending.rotate_left(start);
    }
    for (id, stored) in pending {
        summary.visited += 1;
        let original = stored.clone();
        match maybe_advance_submission_with_budget(
            config,
            stored,
            &mut scan_budget,
            &mut cached_head_level,
        ) {
            Ok(updated) => {
                if updated != original {
                    persist_submission(config, &updated)?;
                    summary.updated += 1;
                }
            }
            Err(err) => {
                summary.errors += 1;
                eprintln!("reconciler: advance submission {}: {}", id, err);
            }
        }
    }
    Ok(summary)
}

fn submission_paths(state_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    let dir = submissions_dir(state_dir);
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("read submissions dir: {}", e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read submissions dir entry: {}", e))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn load_stored_submission(state_dir: &Path, id: &str) -> Result<StoredSubmission, String> {
    let path = submission_path(state_dir, id);
    let body =
        std::fs::read_to_string(&path).map_err(|e| format!("read submission {}: {}", id, e))?;
    let mut stored: StoredSubmission =
        serde_json::from_str(&body).map_err(|e| format!("parse submission {}: {}", id, e))?;
    align_chunk_meta(&mut stored);
    Ok(stored)
}

#[cfg(test)]
fn load_submission(state_dir: &Path, id: &str) -> Result<RollupSubmission, String> {
    load_stored_submission(state_dir, id).map(|stored| stored.submission)
}

fn process_submission(
    config: &OperatorConfig,
    req: SubmitRollupMessageReq,
) -> Result<RollupSubmission, String> {
    let id = next_submission_id(config);
    let targeted_bytes = encode_targeted_rollup_message(&req.rollup_address, &req.payload)?;
    let mut stored = StoredSubmission {
        submission: RollupSubmission {
            id,
            kind: req.kind,
            rollup_address: req.rollup_address.clone(),
            status: RollupSubmissionStatus::PendingDal,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: None,
            dal_chunks: vec![],
            commitment: None,
            published_level: None,
            slot_index: None,
            payload_hash: Some(hex::encode(hash(&req.payload))),
            payload_len: req.payload.len(),
            detail: None,
        },
        payload: Some(req.payload.clone()),
        chunk_meta: vec![],
    };

    if targeted_bytes.len() <= config.direct_max_message_bytes {
        // Wait for inclusion (-w 1): the op must be baked before we return and
        // release advance_lock, otherwise the next injection from this key reuses
        // the same counter and L1 rejects it ("mempool already contains a
        // conflicting operation") — the shield then fails spuriously.
        match inject_direct_message(config, &targeted_bytes, true) {
            Ok(output) => {
                stored.submission.status = RollupSubmissionStatus::SubmittedToL1;
                stored.submission.transport = RollupSubmissionTransport::DirectInbox;
                stored.submission.operation_hash = extract_operation_hash(&output);
                stored.submission.detail = Some(output);
                persist_submission(config, &stored)?;
                return Ok(stored.submission);
            }
            Err(CmdError::Timeout { message, output }) => {
                stored.submission.transport = RollupSubmissionTransport::DirectInbox;
                // Idempotency: octez-client prints the op hash the moment the op
                // is injected, before it waits for confirmation. If the command
                // timed out after printing the hash, the op reached the node and
                // the error is a post-injection confirmation timeout — record it
                // as SubmittedToL1 rather than Failed, because re-injecting would
                // duplicate it. Inclusion is not verified here; a dropped op is
                // caught by the caller's settlement timeout.
                if let Some(op_hash) = extract_operation_hash(&output) {
                    stored.submission.status = RollupSubmissionStatus::SubmittedToL1;
                    stored.submission.operation_hash = Some(op_hash);
                    stored.submission.detail =
                        Some(format!("injected; confirmation unverified: {}", message));
                    persist_submission(config, &stored)?;
                    return Ok(stored.submission);
                }
                stored.submission.status = RollupSubmissionStatus::Failed;
                stored.submission.detail = Some(message.clone());
                persist_submission(config, &stored)?;
                return Err(message);
            }
            Err(CmdError::Failed { message }) => {
                stored.submission.transport = RollupSubmissionTransport::DirectInbox;
                stored.submission.status = RollupSubmissionStatus::Failed;
                stored.submission.detail = Some(message.clone());
                persist_submission(config, &stored)?;
                return Err(message);
            }
        }
    }

    stored.submission.transport = RollupSubmissionTransport::Dal;
    if config.dal_node_endpoint.is_none() {
        stored.submission.status = RollupSubmissionStatus::Failed;
        stored.submission.detail = Some(format!(
            "message is {} bytes after framing, above direct inbox limit {}; DAL node endpoint is not configured",
            targeted_bytes.len(),
            config.direct_max_message_bytes
        ));
        persist_submission(config, &stored)?;
        return Ok(stored.submission);
    }

    let message = decode_and_validate_submission_payload(req.kind, &req.payload)?;
    if submission_kind_requires_dal_fee_policy(req.kind) {
        enforce_dal_fee_policy(config, &message)?;
    }
    stored.submission.detail = Some("Accepted for DAL publication".into());
    persist_submission(config, &stored)?;

    let failed_template = stored.clone();
    match maybe_advance_submission(config, stored) {
        Ok(stored) => {
            persist_submission(config, &stored)?;
            Ok(stored.submission)
        }
        Err(err) => {
            let mut failed =
                load_stored_submission(&config.state_dir, &failed_template.submission.id)
                    .unwrap_or(failed_template);
            failed.submission.status = RollupSubmissionStatus::Failed;
            failed.submission.detail = Some(err.clone());
            let _ = persist_submission(config, &failed);
            Err(err)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UnresolvedChunkResolution {
    Resolved(i32),
    Waiting(String),
    Retry(String),
}

fn fetch_head_level_cached(
    endpoint: &str,
    cached_head_level: &mut Option<Result<i32, String>>,
) -> Result<i32, String> {
    if cached_head_level.is_none() {
        *cached_head_level = Some(fetch_head_level(endpoint));
    }
    cached_head_level.as_ref().expect("initialized").clone()
}

fn resolve_unresolved_chunk_level(
    octez_node_endpoint: Option<&str>,
    op_hash: Option<&str>,
    meta: &mut ChunkMeta,
    dirty_metadata: &mut bool,
    scan_budget: &mut i32,
    cached_head_level: &mut Option<Result<i32, String>>,
) -> UnresolvedChunkResolution {
    let Some(op_hash) = op_hash else {
        return UnresolvedChunkResolution::Retry("unresolved chunk missing operation_hash".into());
    };
    let Some(octez_node_endpoint) = octez_node_endpoint else {
        return UnresolvedChunkResolution::Waiting("waiting_inclusion".into());
    };
    let head_level = match fetch_head_level_cached(octez_node_endpoint, cached_head_level) {
        Ok(level) if level > UNRESOLVED_PUBLISHED_LEVEL => level,
        Ok(_) | Err(_) => {
            return UnresolvedChunkResolution::Waiting("waiting_inclusion".into());
        }
    };
    // Only trust inclusion or absence in Tenderbake-final blocks (`head - 2`).
    let final_head = head_level.saturating_sub(TENDERBAKE_FINALITY_LAG);

    if let Some(block_hash) = meta.inclusion_block.clone() {
        match fetch_block_level(octez_node_endpoint, &block_hash) {
            Ok(level) if level > UNRESOLVED_PUBLISHED_LEVEL => {
                if meta.inclusion_block_failures != 0 {
                    meta.inclusion_block_failures = 0;
                    *dirty_metadata = true;
                }
                if level > final_head {
                    return UnresolvedChunkResolution::Waiting("waiting_inclusion".into());
                }
                if *scan_budget <= 0 {
                    return UnresolvedChunkResolution::Waiting("waiting_inclusion".into());
                }
                *scan_budget = scan_budget.saturating_sub(1);
                match block_contains_manager_operation(octez_node_endpoint, level, op_hash) {
                    Ok(true) => {
                        meta.inclusion_block = None;
                        meta.inclusion_block_failures = 0;
                        meta.skipped_pruned_levels = false;
                        meta.injected_level = None;
                        meta.scan_cursor = None;
                        meta.max_operations_ttl = None;
                        return UnresolvedChunkResolution::Resolved(level);
                    }
                    Ok(false) | Err(BlockLookupError::NotFound) => {
                        // Confirmed non-canonical on the main chain at finalized `level`
                        // (e.g. reorged away), or `operation_hashes/3` at `level` returned
                        // 404 (pruned): clear `inclusion_block` and fall through to the
                        // canonical scan without moving `scan_cursor` past `level`, seeding
                        // `injected_level` with `level - TENDERBAKE_FINALITY_LAG` if unset
                        // so a canonical branch inclusion a block or two earlier is scanned.
                        meta.inclusion_block = None;
                        if meta.injected_level.is_none() {
                            meta.injected_level =
                                Some(level.saturating_sub(TENDERBAKE_FINALITY_LAG).max(1));
                        }
                        *dirty_metadata = true;
                    }
                    Err(BlockLookupError::Other(_)) => {
                        // Transient RPC failure checking `operation_hashes/3` at the
                        // hinted `level`: keep `inclusion_block` intact and retry on
                        // the next tick rather than dropping or skipping `level`.
                        return UnresolvedChunkResolution::Waiting("waiting_inclusion".into());
                    }
                }
            }
            Ok(_) | Err(BlockLookupError::NotFound) => {
                // If the node returns 404 for `block_hash` (e.g. reorged out and
                // forgotten), clear `inclusion_block` and fall through to the scan
                // so the chunk cannot wait forever.
                meta.inclusion_block = None;
                meta.inclusion_block_failures = 0;
                *dirty_metadata = true;
            }
            Err(BlockLookupError::Other(_)) => {
                meta.inclusion_block_failures = meta.inclusion_block_failures.saturating_add(1);
                *dirty_metadata = true;
                if meta.inclusion_block_failures < MAX_INCLUSION_BLOCK_LOOKUP_FAILURES {
                    // Transient RPC error (e.g. 500 or timeout): keep `inclusion_block`
                    // intact and wait for the next tick.
                    return UnresolvedChunkResolution::Waiting("waiting_inclusion".into());
                }
                // Persistent non-404 failure looking up `block_hash`: clear
                // `inclusion_block` and fall through to the canonical scan.
                meta.inclusion_block = None;
                meta.inclusion_block_failures = 0;
            }
        }
    }

    let max_ops_ttl = match meta.max_operations_ttl {
        Some(ttl) if ttl > 0 => ttl,
        _ => match fetch_max_operations_ttl(octez_node_endpoint) {
            Ok(ttl) => {
                meta.max_operations_ttl = Some(ttl);
                *dirty_metadata = true;
                ttl
            }
            Err(_) => {
                return UnresolvedChunkResolution::Waiting("waiting_inclusion".into());
            }
        },
    };

    if meta.injected_level.is_none() {
        let lookback = head_level.saturating_sub(max_ops_ttl).max(1);
        meta.injected_level = Some(head_level);
        if meta.scan_cursor.is_none() {
            meta.scan_cursor = Some(lookback);
        }
        *dirty_metadata = true;
    }
    let start_level = meta.injected_level.unwrap_or(head_level).max(1);
    let deadline_level = start_level.saturating_add(max_ops_ttl);
    let scan_start = meta.scan_cursor.unwrap_or(start_level).max(1);
    let scan_target = final_head.min(deadline_level);
    if *scan_budget > 0 && scan_start <= scan_target {
        let scan_end = scan_target.min(scan_start.saturating_add(*scan_budget - 1));
        for level in scan_start..=scan_end {
            *scan_budget = scan_budget.saturating_sub(1);
            match block_contains_manager_operation(octez_node_endpoint, level, op_hash) {
                Ok(true) => {
                    meta.inclusion_block = None;
                    meta.inclusion_block_failures = 0;
                    meta.skipped_pruned_levels = false;
                    meta.injected_level = None;
                    meta.scan_cursor = None;
                    meta.max_operations_ttl = None;
                    return UnresolvedChunkResolution::Resolved(level);
                }
                Ok(false) => {
                    meta.scan_cursor = Some(level.saturating_add(1));
                    *dirty_metadata = true;
                }
                Err(BlockLookupError::NotFound) => {
                    // A rolling/pruned node returned 404 on finalized `level`'s
                    // `operation_hashes/3`: skip the pruned level and record that
                    // history was incomplete so the chunk can still resolve at a
                    // later retained level or expire at TTL.
                    eprintln!(
                        "reconciler: block operation_hashes at finalized level {} returned 404 (pruned) while scanning for {}; skipping level",
                        level, op_hash
                    );
                    meta.skipped_pruned_levels = true;
                    meta.scan_cursor = Some(level.saturating_add(1));
                    *dirty_metadata = true;
                }
                Err(BlockLookupError::Other(_)) => {
                    return UnresolvedChunkResolution::Waiting("waiting_inclusion".into());
                }
            }
        }
    }
    let scanned_through_deadline = meta.scan_cursor.unwrap_or(start_level) > deadline_level;
    if final_head >= deadline_level && scanned_through_deadline {
        let age = final_head.saturating_sub(start_level);
        let pruned_note = if meta.skipped_pruned_levels {
            " (pruned levels skipped during scan)"
        } else {
            ""
        };
        UnresolvedChunkResolution::Retry(format!(
            "unresolved operation {} not included after {} finalized levels (ttl {}){}",
            op_hash, age, max_ops_ttl, pruned_note
        ))
    } else {
        UnresolvedChunkResolution::Waiting("waiting_inclusion".into())
    }
}

fn maybe_advance_submission(
    config: &OperatorConfig,
    stored: StoredSubmission,
) -> Result<StoredSubmission, String> {
    let mut scan_budget = MAX_INCLUSION_SCAN_LEVELS_PER_TICK;
    let mut cached_head_level = None;
    maybe_advance_submission_with_budget(config, stored, &mut scan_budget, &mut cached_head_level)
}

fn maybe_advance_submission_with_budget(
    config: &OperatorConfig,
    mut stored: StoredSubmission,
    scan_budget: &mut i32,
    cached_head_level: &mut Option<Result<i32, String>>,
) -> Result<StoredSubmission, String> {
    if stored.submission.status == RollupSubmissionStatus::PendingDal {
        resume_pending_dal_submission(config, &mut stored)?;
        return Ok(stored);
    }
    if !matches!(
        stored.submission.status,
        RollupSubmissionStatus::CommitmentIncluded | RollupSubmissionStatus::Attested
    ) {
        return Ok(stored);
    }
    if stored.submission.dal_chunks.is_empty() {
        return Ok(stored);
    }
    let Some(dal_node_endpoint) = config.dal_node_endpoint.as_deref() else {
        return Ok(stored);
    };

    align_chunk_meta(&mut stored);
    let mut status_lines = Vec::with_capacity(stored.submission.dal_chunks.len());
    let mut retry_indices: Vec<(usize, String)> = Vec::new();
    let mut waiting_indices = Vec::new();
    let mut waiting_for_attestation = false;
    for idx in 0..stored.submission.dal_chunks.len() {
        if stored.submission.dal_chunks[idx].published_level <= UNRESOLVED_PUBLISHED_LEVEL {
            let slot_index = stored.submission.dal_chunks[idx].slot_index;
            let op_hash = stored.submission.dal_chunks[idx].operation_hash.clone();
            let mut dirty_metadata = false;
            let resolution = resolve_unresolved_chunk_level(
                config.octez_node_endpoint.as_deref(),
                op_hash.as_deref(),
                &mut stored.chunk_meta[idx],
                &mut dirty_metadata,
                scan_budget,
                cached_head_level,
            );
            match resolution {
                UnresolvedChunkResolution::Resolved(level) => {
                    stored.submission.dal_chunks[idx].published_level = level;
                    update_submission_commitment_summary(&mut stored.submission)?;
                    // Persist immediately so a subsequent `fetch_dal_slot_status`
                    // error on this or a later chunk cannot lose the resolved level.
                    persist_submission(config, &stored)?;
                }
                UnresolvedChunkResolution::Waiting(state) => {
                    if dirty_metadata {
                        persist_submission(config, &stored)?;
                    }
                    status_lines.push(format!(
                        "chunk[{idx}] slot {} op {} => {}",
                        slot_index,
                        op_hash.as_deref().unwrap_or("<missing>"),
                        state
                    ));
                    waiting_for_attestation = true;
                    continue;
                }
                UnresolvedChunkResolution::Retry(reason) => {
                    if dirty_metadata {
                        persist_submission(config, &stored)?;
                    }
                    status_lines.push(format!(
                        "chunk[{idx}] slot {} op {} => dropped",
                        slot_index,
                        op_hash.as_deref().unwrap_or("<missing>")
                    ));
                    retry_indices.push((idx, reason));
                    continue;
                }
            }
        }

        let chunk = &stored.submission.dal_chunks[idx];
        let status =
            fetch_dal_slot_status(dal_node_endpoint, chunk.published_level, chunk.slot_index)?;
        status_lines.push(format!(
            "chunk[{idx}] slot {} at level {} => {}",
            chunk.slot_index, chunk.published_level, status
        ));
        if status == "unattested" {
            retry_indices.push((idx, "unattested".into()));
        } else if status != "attested" {
            waiting_indices.push(idx);
        }
    }

    if !waiting_indices.is_empty() {
        if let Some(octez_node_endpoint) = config.octez_node_endpoint.as_deref() {
            match fetch_head_level_cached(octez_node_endpoint, cached_head_level) {
                Ok(head_level) => {
                    for idx in waiting_indices {
                        let published_level = stored.submission.dal_chunks[idx].published_level;
                        let age = head_level.saturating_sub(published_level);
                        if age >= MAX_WAITING_ATTESTATION_LEVEL_AGE {
                            retry_indices.push((
                                idx,
                                format!("stale waiting_attestation after {} levels", age),
                            ));
                        } else {
                            waiting_for_attestation = true;
                        }
                    }
                }
                Err(_) => {
                    waiting_for_attestation = true;
                }
            }
        } else {
            waiting_for_attestation = true;
        }
    }

    if !retry_indices.is_empty() {
        // Check all retry indices against the attempt cap upfront so we never
        // republish an earlier chunk on L1 when a later chunk has already
        // exhausted `MAX_DAL_CHUNK_ATTEMPTS`.
        if let Some(&(idx, _)) = retry_indices
            .iter()
            .find(|&&(idx, _)| stored.chunk_meta[idx].attempts >= MAX_DAL_CHUNK_ATTEMPTS)
        {
            let attempts = stored.chunk_meta[idx].attempts;
            stored.submission.status = RollupSubmissionStatus::Failed;
            stored.submission.detail = Some(format!(
                "DAL attestation failed after {} attempts\n{}",
                attempts,
                status_lines.join("\n")
            ));
            return Ok(stored);
        }

        let mut republished_lines = Vec::with_capacity(retry_indices.len());
        for (idx, reason) in retry_indices {
            let attempts = stored.chunk_meta[idx].attempts;
            let (published_chunk, meta) = {
                let payload = stored
                    .payload
                    .as_deref()
                    .ok_or_else(|| "DAL submission payload is unavailable for retry".to_string())?;
                let chunk_bytes = submission_chunk_bytes(payload, &stored.submission, idx)?;
                publish_dal_chunk(config, chunk_bytes)?
            };
            republished_lines.push(format!(
                "republished chunk[{idx}] attempt {} -> slot {} level {} ({})",
                attempts + 1,
                published_chunk.slot_index,
                published_chunk.published_level,
                reason
            ));
            stored.submission.dal_chunks[idx] = published_chunk;
            stored.chunk_meta[idx] = ChunkMeta {
                attempts: attempts + 1,
                injected_level: meta.injected_level,
                scan_cursor: None,
                inclusion_block: meta.inclusion_block,
                inclusion_block_failures: 0,
                skipped_pruned_levels: false,
                max_operations_ttl: None,
            };
            update_submission_commitment_summary(&mut stored.submission)?;
            stored.submission.operation_hash = stored
                .submission
                .dal_chunks
                .last()
                .and_then(|chunk| chunk.operation_hash.clone());
            stored.submission.status = RollupSubmissionStatus::CommitmentIncluded;
            stored.submission.detail = Some(format!(
                "Republished {} DAL chunk(s)\n{}\n{}",
                republished_lines.len(),
                republished_lines.join("\n"),
                status_lines.join("\n")
            ));
            // Persist after each republished chunk so an error on a later chunk
            // cannot lose earlier republished chunks' L1 operations or attempts.
            persist_submission(config, &stored)?;
        }
        return Ok(stored);
    }

    if waiting_for_attestation {
        stored.submission.status = RollupSubmissionStatus::CommitmentIncluded;
        stored.submission.detail = Some(format!(
            "Waiting for DAL attestation\n{}",
            status_lines.join("\n")
        ));
        return Ok(stored);
    }

    stored.submission.status = RollupSubmissionStatus::Attested;
    let pointer = dal_pointer_from_submission(&stored.submission)?;
    let pointer_payload = encode_kernel_inbox_message(&KernelInboxMessage::DalPointer(pointer))?;
    let targeted_bytes =
        encode_targeted_rollup_message(&stored.submission.rollup_address, &pointer_payload)?;
    // Wait for inclusion (-w 1), not fire-and-forget: the op must be baked
    // before we return and release advance_lock, otherwise the next injection
    // from this key reuses the same counter and L1 rejects it ("mempool already
    // contains a conflicting operation"), failing the shield spuriously.
    let output = match inject_direct_message(config, &targeted_bytes, true) {
        Ok(output) => output,
        Err(CmdError::Timeout { message, output }) => {
            // Idempotency (see process_submission): if octez-client timed out
            // after printing the op hash, the pointer op reached the node, so
            // record it and stop here — returning Err would leave status Attested
            // and make the reconciler inject a duplicate pointer next tick.
            if let Some(op_hash) = extract_operation_hash(&output) {
                stored.submission.status = RollupSubmissionStatus::SubmittedToL1;
                stored.submission.operation_hash = Some(op_hash);
                stored.submission.detail = Some(format!(
                    "All DAL chunks attested; pointer injected, confirmation unverified\n{}\n{}",
                    status_lines.join("\n"),
                    message
                ));
                return Ok(stored);
            }
            return Err(message);
        }
        Err(CmdError::Failed { message }) => {
            return Err(message);
        }
    };
    stored.submission.status = RollupSubmissionStatus::SubmittedToL1;
    stored.submission.operation_hash = extract_operation_hash(&output);
    stored.submission.detail = Some(format!(
        "All DAL chunks attested\n{}\n{}",
        status_lines.join("\n"),
        output
    ));
    Ok(stored)
}

fn resume_pending_dal_submission(
    config: &OperatorConfig,
    stored: &mut StoredSubmission,
) -> Result<(), String> {
    if stored.submission.transport != RollupSubmissionTransport::Dal {
        return Ok(());
    }
    let dal_node_endpoint = config
        .dal_node_endpoint
        .as_deref()
        .ok_or_else(|| "DAL node endpoint is not configured".to_string())?;
    align_chunk_meta(stored);
    let payload_len = stored
        .payload
        .as_ref()
        .ok_or_else(|| "DAL submission payload is unavailable for publication".to_string())?
        .len();
    let protocol = fetch_dal_protocol_parameters(dal_node_endpoint)?;
    if protocol.number_of_slots == 0 {
        return Err("DAL protocol reported zero slots".into());
    }
    if protocol.cryptobox_parameters.slot_size == 0 {
        return Err("DAL protocol reported zero slot size".into());
    }
    let octez_node_endpoint = config
        .octez_node_endpoint
        .as_deref()
        .ok_or_else(|| "octez node endpoint is required for DAL submissions".to_string())?;

    let chunk_size = config
        .dal_max_chunk_bytes
        .map(|value| value.min(protocol.cryptobox_parameters.slot_size))
        .unwrap_or(protocol.cryptobox_parameters.slot_size);
    if chunk_size == 0 {
        return Err("DAL chunk size must be greater than zero".into());
    }

    let already_published: usize = stored
        .submission
        .dal_chunks
        .iter()
        .map(|chunk| chunk.payload_len)
        .sum();
    if already_published > payload_len {
        return Err(format!(
            "persisted DAL chunks exceed payload length: {} > {}",
            already_published, payload_len
        ));
    }
    let total_chunks = payload_len.div_ceil(chunk_size);
    let mut offset = already_published;
    while offset < payload_len {
        let end = offset.saturating_add(chunk_size).min(payload_len);
        let (published_chunk, meta) = {
            let payload = stored.payload.as_deref().ok_or_else(|| {
                "DAL submission payload is unavailable for publication".to_string()
            })?;
            publish_dal_chunk_with_protocol(
                config,
                dal_node_endpoint,
                octez_node_endpoint,
                protocol.number_of_slots,
                &payload[offset..end],
            )?
        };
        offset = end;
        stored.submission.dal_chunks.push(published_chunk);
        stored.chunk_meta.push(ChunkMeta {
            attempts: 1,
            injected_level: meta.injected_level,
            scan_cursor: None,
            inclusion_block: meta.inclusion_block,
            inclusion_block_failures: 0,
            skipped_pruned_levels: false,
            max_operations_ttl: None,
        });
        stored.submission.detail = Some(format!(
            "Published {} / {} DAL chunk(s)",
            stored.submission.dal_chunks.len(),
            total_chunks
        ));
        persist_submission(config, stored)?;
    }

    update_submission_commitment_summary(&mut stored.submission)?;
    stored.submission.operation_hash = stored
        .submission
        .dal_chunks
        .last()
        .and_then(|chunk| chunk.operation_hash.clone());
    stored.submission.status = RollupSubmissionStatus::CommitmentIncluded;
    stored.submission.detail = Some(format!(
        "Published {} DAL chunk(s); waiting for attestation",
        stored.submission.dal_chunks.len()
    ));
    Ok(())
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PublishedDalChunkMeta {
    injected_level: Option<i32>,
    inclusion_block: Option<String>,
}

fn publish_dal_chunk(
    config: &OperatorConfig,
    payload: &[u8],
) -> Result<(RollupDalChunk, PublishedDalChunkMeta), String> {
    let dal_node_endpoint = config
        .dal_node_endpoint
        .as_deref()
        .ok_or_else(|| "DAL node endpoint is not configured".to_string())?;
    let protocol = fetch_dal_protocol_parameters(dal_node_endpoint)?;
    if protocol.number_of_slots == 0 {
        return Err("DAL protocol reported zero slots".into());
    }
    let octez_node_endpoint = config
        .octez_node_endpoint
        .as_deref()
        .ok_or_else(|| "octez node endpoint is required for DAL submissions".to_string())?;
    publish_dal_chunk_with_protocol(
        config,
        dal_node_endpoint,
        octez_node_endpoint,
        protocol.number_of_slots,
        payload,
    )
}

/// Sentinel `published_level` stored on a `RollupDalChunk` when the DAL
/// commitment operation was injected (we have its `operation_hash`) but its
/// inclusion block level could not yet be determined (either `-w 1` timed out
/// before printing `Operation found in block`, or the follow-up block header
/// RPC failed). The reconciler resolves the inclusion block via non-blocking
/// RPC scan (`/chains/main/blocks/<lvl>/operation_hashes/3`) before querying
/// DAL slot status.
const UNRESOLVED_PUBLISHED_LEVEL: i32 = 0;

fn publish_dal_chunk_with_protocol(
    config: &OperatorConfig,
    dal_node_endpoint: &str,
    octez_node_endpoint: &str,
    number_of_slots: u64,
    payload: &[u8],
) -> Result<(RollupDalChunk, PublishedDalChunkMeta), String> {
    validate_dal_slot_range(config, number_of_slots)?;
    let attempts = dal_slot_attempt_budget(config, number_of_slots);
    let mut last_slot_error = None;
    for _attempt in 0..attempts {
        let slot_index = select_slot_index(config, number_of_slots)?;
        let publish = post_dal_slot(dal_node_endpoint, slot_index, payload)?;
        // Sample `head` before injecting so we have a sound lower bound for an
        // unresolved inclusion scan: an operation injected after `pre_head`
        // cannot be included at or below `pre_head`, so `pre_head + 1` is the
        // earliest level it could land in (including when `-w 1` races a timeout
        // kill right as block `pre_head + 1` is baked).
        let pre_head = fetch_head_level(octez_node_endpoint)
            .ok()
            .filter(|&lvl| lvl > UNRESOLVED_PUBLISHED_LEVEL);
        let (operation_hash, published_level, inclusion_block) = match publish_dal_commitment(
            config,
            &publish.commitment,
            slot_index,
            &publish.commitment_proof,
        ) {
            Ok(output) => {
                let operation_hash = extract_operation_hash(&output);
                let (published_level, inclusion_block) = match extract_block_hash(&output) {
                    Some(block_hash) => match fetch_block_level(octez_node_endpoint, &block_hash) {
                        Ok(level) => (level, None),
                        Err(_) if operation_hash.is_some() => {
                            (UNRESOLVED_PUBLISHED_LEVEL, Some(block_hash))
                        }
                        Err(err) => return Err(err.to_string()),
                    },
                    None if operation_hash.is_some() => (UNRESOLVED_PUBLISHED_LEVEL, None),
                    None => {
                        return Err(format!(
                            "missing block hash in dal commitment output: {}",
                            output
                        ))
                    }
                };
                (operation_hash, published_level, inclusion_block)
            }
            Err(err) if is_slot_header_collision(err.output()) => {
                last_slot_error = Some(err.to_string());
                continue;
            }
            Err(CmdError::Timeout { message, output }) => {
                // Idempotency: octez-client prints `Operation hash is ...` as
                // soon as the commitment op is injected, before waiting for
                // `-w 1` inclusion. If the command timed out after injection:
                //   - Never guess `head` as `published_level`: an op that timed
                //     out before `Operation found in block` was not included at
                //     `head` (it will land at `head + 1` or later), and querying
                //     `/levels/{head}/slots/{i}/status` could observe another
                //     publisher's commitment on the same slot.
                //   - Never propagate a follow-up RPC error with `?` once we
                //     have `op_hash`, or the op hash proving injection is lost.
                //   - Only recover on `CmdError::Timeout`, not on `CmdError::Failed`.
                if let Some(op_hash) = extract_operation_hash(&output) {
                    let (published_level, inclusion_block) = match extract_block_hash(&output) {
                        Some(block_hash) => {
                            match fetch_block_level(octez_node_endpoint, &block_hash) {
                                Ok(level) => (level, None),
                                Err(_) => (UNRESOLVED_PUBLISHED_LEVEL, Some(block_hash)),
                            }
                        }
                        None => (UNRESOLVED_PUBLISHED_LEVEL, None),
                    };
                    (Some(op_hash), published_level, inclusion_block)
                } else {
                    return Err(message);
                }
            }
            Err(CmdError::Failed { message }) => {
                return Err(message);
            }
        };
        let injected_level = if published_level <= UNRESOLVED_PUBLISHED_LEVEL {
            pre_head.map(|lvl| lvl.saturating_add(1))
        } else {
            None
        };
        return Ok((
            RollupDalChunk {
                slot_index,
                published_level,
                payload_len: payload.len(),
                commitment: publish.commitment,
                operation_hash,
            },
            PublishedDalChunkMeta {
                injected_level,
                inclusion_block,
            },
        ));
    }
    Err(last_slot_error
        .unwrap_or_else(|| "failed to publish DAL chunk: no free slot index available".into()))
}

fn align_chunk_meta(stored: &mut StoredSubmission) {
    let len = stored.submission.dal_chunks.len();
    stored.chunk_meta.resize(len, ChunkMeta::default());
}

fn submission_chunk_bytes<'a>(
    payload: &'a [u8],
    submission: &RollupSubmission,
    index: usize,
) -> Result<&'a [u8], String> {
    if index >= submission.dal_chunks.len() {
        return Err(format!("chunk index {} out of range", index));
    }
    let start: usize = submission
        .dal_chunks
        .iter()
        .take(index)
        .map(|chunk| chunk.payload_len)
        .sum();
    let end = start
        .checked_add(submission.dal_chunks[index].payload_len)
        .ok_or_else(|| "chunk range overflowed".to_string())?;
    if end > payload.len() {
        return Err(format!(
            "chunk {} exceeds payload length: end={} payload={}",
            index,
            end,
            payload.len()
        ));
    }
    Ok(&payload[start..end])
}

fn update_submission_commitment_summary(submission: &mut RollupSubmission) -> Result<(), String> {
    let first = submission
        .dal_chunks
        .first()
        .ok_or_else(|| "DAL submission unexpectedly produced zero chunks".to_string())?;
    submission.commitment = Some(first.commitment.clone());
    submission.published_level =
        (first.published_level > UNRESOLVED_PUBLISHED_LEVEL).then_some(first.published_level);
    submission.slot_index = Some(first.slot_index);
    Ok(())
}

fn select_slot_index(config: &OperatorConfig, number_of_slots: u64) -> Result<u16, String> {
    let (base, span) = match &config.dal_slot_range {
        Some(range) => (u64::from(range.start), u64::from(range.end - range.start)),
        None => (0, number_of_slots),
    };
    // Check span before bumping the counter — otherwise a degenerate
    // config (unreachable via the CLI parser but theoretically callable
    // from the AppState construction path) would waste counter ticks
    // on every failed call, breaking round-robin fairness for any
    // concurrent caller sharing the same AtomicU64.
    if span == 0 {
        return Err("DAL slot selection has zero usable slots".into());
    }
    let counter = config.slot_counter.fetch_add(1, Ordering::Relaxed);
    let slot = base + (counter % span);
    u16::try_from(slot).map_err(|_| format!("slot index {} does not fit in u16", slot))
}

fn dal_slot_attempt_budget(config: &OperatorConfig, number_of_slots: u64) -> u64 {
    match &config.dal_slot_range {
        Some(range) => u64::from(range.end - range.start),
        None => number_of_slots,
    }
}

fn validate_dal_slot_range(config: &OperatorConfig, number_of_slots: u64) -> Result<(), String> {
    if let Some(range) = &config.dal_slot_range {
        if u64::from(range.end) > number_of_slots {
            return Err(format!(
                "--dal-slot-range {}..{} exceeds DAL protocol number_of_slots={}",
                range.start, range.end, number_of_slots
            ));
        }
    }
    Ok(())
}

fn is_slot_header_collision(err: &str) -> bool {
    err.to_ascii_lowercase().contains("already proposed")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CmdError {
    Timeout { message: String, output: String },
    Failed { message: String },
}

impl CmdError {
    fn output(&self) -> &str {
        match self {
            Self::Timeout { output, .. } => output,
            Self::Failed { message } => message,
        }
    }
}

impl std::fmt::Display for CmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { message, .. } | Self::Failed { message } => f.write_str(message),
        }
    }
}

const HTTP_RPC_TIMEOUT: Duration = Duration::from_secs(10);
// Uploading up to a full ~126 KB slot while the DAL node computes the
// commitment and proof can exceed `HTTP_RPC_TIMEOUT` under load; give slot
// publication the same 60s ceiling as `octez-client` commands.
const DAL_SLOT_POST_TIMEOUT: Duration = OCTEZ_CLIENT_TIMEOUT;

fn http_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .timeout_global(Some(HTTP_RPC_TIMEOUT))
            .build()
            .into()
    })
}

fn dal_slot_post_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .timeout_global(Some(DAL_SLOT_POST_TIMEOUT))
            .build()
            .into()
    })
}

fn fetch_dal_protocol_parameters(endpoint: &str) -> Result<DalProtocolParametersResp, String> {
    let url = format!("{}/protocol_parameters", endpoint.trim_end_matches('/'));
    let resp = http_agent()
        .get(&url)
        .call()
        .map_err(|e| format!("DAL protocol parameters request failed: {}", e))?;
    resp.into_body()
        .read_json()
        .map_err(|e| format!("parse DAL protocol parameters: {}", e))
}

fn post_dal_slot(
    endpoint: &str,
    slot_index: u16,
    payload: &[u8],
) -> Result<DalSlotPublishResp, String> {
    let url = format!(
        "{}/slots?slot_index={}&padding=%00",
        endpoint.trim_end_matches('/'),
        slot_index
    );
    let body = serde_json::to_string(&json!({ "invalid_utf8_string": payload }))
        .map_err(|e| format!("serialize DAL slot publish body: {}", e))?;
    let resp = dal_slot_post_agent()
        .post(&url)
        .header("Content-Type", "application/json")
        .send(body)
        .map_err(|e| format!("DAL slot publish request failed: {}", e))?;
    resp.into_body()
        .read_json()
        .map_err(|e| format!("parse DAL slot publish response: {}", e))
}

fn publish_dal_commitment(
    config: &OperatorConfig,
    commitment: &str,
    slot_index: u16,
    proof: &str,
) -> Result<String, CmdError> {
    let mut command = std::process::Command::new(&config.octez_client_bin);
    if let Some(dir) = &config.octez_client_dir {
        command.arg("-d").arg(dir);
    }
    if let Some(endpoint) = &config.octez_node_endpoint {
        command.arg("-E").arg(endpoint);
    }
    if let Some(protocol) = &config.octez_protocol {
        command.arg("-p").arg(protocol);
    }
    command
        .arg("-w")
        .arg("1")
        .arg("publish")
        .arg("dal")
        .arg("commitment")
        .arg(commitment)
        .arg("from")
        .arg(&config.source_alias)
        .arg("for")
        .arg("slot")
        .arg(slot_index.to_string())
        .arg("with")
        .arg("proof")
        .arg(proof);
    run_command_collect_output(
        command,
        &config.octez_client_bin,
        config.octez_client_timeout,
    )
}

fn block_contains_manager_operation(
    endpoint: &str,
    level: i32,
    operation_hash: &str,
) -> Result<bool, BlockLookupError> {
    let url = format!(
        "{}/chains/main/blocks/{}/operation_hashes/3",
        endpoint.trim_end_matches('/'),
        level
    );
    let resp = match http_agent().get(&url).call() {
        Ok(resp) => resp,
        Err(ureq::Error::StatusCode(404)) => return Err(BlockLookupError::NotFound),
        Err(e) => {
            return Err(BlockLookupError::Other(format!(
                "block operation_hashes request failed at level {}: {}",
                level, e
            )))
        }
    };
    let hashes: Vec<String> = resp.into_body().read_json().map_err(|e| {
        BlockLookupError::Other(format!(
            "parse block operation_hashes at level {}: {}",
            level, e
        ))
    })?;
    Ok(hashes.iter().any(|h| h == operation_hash))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BlockLookupError {
    NotFound,
    Other(String),
}

impl std::fmt::Display for BlockLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("block header request failed: http status: 404"),
            Self::Other(msg) => f.write_str(msg),
        }
    }
}

fn fetch_block_level(endpoint: &str, block_hash: &str) -> Result<i32, BlockLookupError> {
    let url = format!(
        "{}/chains/main/blocks/{}/header",
        endpoint.trim_end_matches('/'),
        block_hash
    );
    let resp = match http_agent().get(&url).call() {
        Ok(resp) => resp,
        Err(ureq::Error::StatusCode(404)) => return Err(BlockLookupError::NotFound),
        Err(e) => {
            return Err(BlockLookupError::Other(format!(
                "block header request failed: {}",
                e
            )))
        }
    };
    let header: BlockHeaderResp = resp
        .into_body()
        .read_json()
        .map_err(|e| BlockLookupError::Other(format!("parse block header: {}", e)))?;
    Ok(header.level)
}

fn fetch_head_level(endpoint: &str) -> Result<i32, String> {
    let url = format!(
        "{}/chains/main/blocks/head/header",
        endpoint.trim_end_matches('/')
    );
    let resp = http_agent()
        .get(&url)
        .call()
        .map_err(|e| format!("block head header request failed: {}", e))?;
    let header: BlockHeaderResp = resp
        .into_body()
        .read_json()
        .map_err(|e| format!("parse block head header: {}", e))?;
    Ok(header.level)
}

fn fetch_max_operations_ttl(endpoint: &str) -> Result<i32, String> {
    let url = format!(
        "{}/chains/main/blocks/head/context/constants",
        endpoint.trim_end_matches('/')
    );
    let resp = http_agent()
        .get(&url)
        .call()
        .map_err(|e| format!("context constants request failed: {}", e))?;
    let constants: ContextConstantsResp = resp
        .into_body()
        .read_json()
        .map_err(|e| format!("parse context constants: {}", e))?;
    Ok(constants.max_operations_ttl.max(1))
}

fn fetch_dal_slot_status(
    endpoint: &str,
    published_level: i32,
    slot_index: u16,
) -> Result<String, String> {
    let url = format!(
        "{}/levels/{}/slots/{}/status",
        endpoint.trim_end_matches('/'),
        published_level,
        slot_index
    );
    let resp = match http_agent().get(&url).call() {
        Ok(resp) => resp,
        Err(ureq::Error::StatusCode(404)) => return Ok("waiting_attestation".into()),
        Err(err) => return Err(format!("DAL slot status request failed: {}", err)),
    };
    let parsed: DalSlotStatusResp = resp
        .into_body()
        .read_json()
        .map_err(|e| format!("parse DAL slot status: {}", e))?;
    Ok(match parsed {
        DalSlotStatusResp::Plain(status) => status,
        DalSlotStatusResp::Detailed { kind, .. } => kind,
    })
}

fn dal_pointer_from_submission(
    submission: &RollupSubmission,
) -> Result<KernelDalPayloadPointer, String> {
    let kind = match submission.kind {
        RollupSubmissionKind::ConfigureVerifier => KernelDalPayloadKind::ConfigureVerifier,
        RollupSubmissionKind::ConfigureBridge => KernelDalPayloadKind::ConfigureBridge,
        RollupSubmissionKind::Shield => KernelDalPayloadKind::Shield,
        RollupSubmissionKind::Transfer => KernelDalPayloadKind::Transfer,
        RollupSubmissionKind::Unshield => KernelDalPayloadKind::Unshield,
    };
    let payload_hash_hex = submission
        .payload_hash
        .as_deref()
        .ok_or_else(|| "submission is missing payload_hash".to_string())?;
    let payload_hash = decode_felt_hex(payload_hash_hex)?;
    Ok(KernelDalPayloadPointer {
        kind,
        chunks: submission
            .dal_chunks
            .iter()
            .map(|chunk| -> Result<KernelDalChunkPointer, String> {
                if chunk.published_level <= UNRESOLVED_PUBLISHED_LEVEL {
                    return Err("chunk published_level is not yet resolved".to_string());
                }
                Ok(KernelDalChunkPointer {
                    published_level: u64::try_from(chunk.published_level)
                        .map_err(|_| "published_level must be positive".to_string())?,
                    slot_index: u8::try_from(chunk.slot_index)
                        .map_err(|_| "slot_index does not fit in u8".to_string())?,
                    payload_len: u64::try_from(chunk.payload_len)
                        .map_err(|_| "payload_len does not fit in u64".to_string())?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        payload_len: u64::try_from(submission.payload_len)
            .map_err(|_| "payload_len does not fit in u64".to_string())?,
        payload_hash,
    })
}

fn decode_felt_hex(value: &str) -> Result<F, String> {
    let bytes = hex::decode(value).map_err(|e| format!("invalid payload hash hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "payload hash must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut felt = [0u8; 32];
    felt.copy_from_slice(&bytes);
    Ok(felt)
}

fn inject_direct_message(
    config: &OperatorConfig,
    bytes: &[u8],
    wait_for_inclusion: bool,
) -> Result<String, CmdError> {
    let payload_file = write_temp_payload(bytes).map_err(|message| CmdError::Failed { message })?;
    let payload = format!("bin:{}", payload_file.display());
    let mut command = std::process::Command::new(&config.octez_client_bin);
    if let Some(dir) = &config.octez_client_dir {
        command.arg("-d").arg(dir);
    }
    if let Some(endpoint) = &config.octez_node_endpoint {
        command.arg("-E").arg(endpoint);
    }
    if let Some(protocol) = &config.octez_protocol {
        command.arg("-p").arg(protocol);
    }
    command
        .arg("-w")
        .arg(if wait_for_inclusion { "1" } else { "none" })
        .arg("send")
        .arg("smart")
        .arg("rollup")
        .arg("message")
        .arg(payload)
        .arg("from")
        .arg(&config.source_alias);

    let result = run_command_collect_output(
        command,
        &config.octez_client_bin,
        config.octez_client_timeout,
    );
    let _ = std::fs::remove_file(&payload_file);
    result
}

fn encode_targeted_rollup_message(rollup_address: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let address = SmartRollupAddress::from_b58check(rollup_address)
        .map_err(|_| format!("invalid rollup address: {}", rollup_address))?;
    let frame = ExternalMessageFrame::Targetted {
        address,
        contents: payload,
    };
    let mut output = Vec::new();
    frame
        .bin_write(&mut output)
        .map_err(|e| format!("failed to encode targeted rollup message: {}", e))?;
    Ok(output)
}

// Ceiling on a single octez-client invocation. `-w 1` waits for the op to be
// baked (~1-2 blocks); this bounds the wait so a stuck/never-confirmed op can't
// hang forever while advance_lock is held and wedge the whole operator.
// 60s is ~4-7 blocks: well past the ~8-16s happy path, so it only fires when
// confirmation genuinely never comes, and frees a wedged operator quickly.
// ponytail: fixed ceiling; make it a config flag if operators ever need to
// tune per-network block times.
const OCTEZ_CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

fn run_command_collect_output(
    mut command: std::process::Command,
    program_name: &str,
    timeout: Duration,
) -> Result<String, CmdError> {
    // Capture stdout/stderr to temp files rather than pipes: a `-w 1` inject can
    // block for many blocks, and reading a full pipe buffer via .output() could
    // deadlock. Files also let us recover partial output after a timeout-kill —
    // octez-client prints the injected op hash *before* it waits for
    // confirmation, and callers use that hash for idempotency on a timeout.
    // Using `NamedTempFile` avoids symlink-following and guarantees cleanup on
    // any early error return.
    let stdout_temp = tempfile::NamedTempFile::new().map_err(|e| CmdError::Failed {
        message: format!("create stdout capture for {}: {}", program_name, e),
    })?;
    let stderr_temp = tempfile::NamedTempFile::new().map_err(|e| CmdError::Failed {
        message: format!("create stderr capture for {}: {}", program_name, e),
    })?;
    let stdout_file = stdout_temp.reopen().map_err(|e| CmdError::Failed {
        message: format!("reopen stdout capture for {}: {}", program_name, e),
    })?;
    let stderr_file = stderr_temp.reopen().map_err(|e| CmdError::Failed {
        message: format!("reopen stderr capture for {}: {}", program_name, e),
    })?;
    command.stdout(stdout_file).stderr(stderr_file);

    const LINUX_ETXTBSY_ERRNO: i32 = 26;
    let mut spawn_attempts = 0u32;
    let mut child = loop {
        match command.spawn() {
            Ok(child) => break child,
            Err(e) if e.raw_os_error() == Some(LINUX_ETXTBSY_ERRNO) && spawn_attempts < 10 => {
                spawn_attempts += 1;
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                return Err(CmdError::Failed {
                    message: format!("failed to start {}: {}", program_name, e),
                });
            }
        }
    };

    let deadline = Instant::now() + timeout;
    let mut poll_interval = Duration::from_millis(5);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                let sleep_for = poll_interval.min(deadline - now);
                std::thread::sleep(sleep_for);
                poll_interval = (poll_interval * 2).min(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(CmdError::Failed {
                    message: format!("failed to wait for {}: {}", program_name, e),
                });
            }
        }
    };

    let stdout = std::fs::read_to_string(stdout_temp.path())
        .unwrap_or_default()
        .trim()
        .to_string();
    let stderr = std::fs::read_to_string(stderr_temp.path())
        .unwrap_or_default()
        .trim()
        .to_string();
    let combined = match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{}\n{}", stdout, stderr),
    };

    if timed_out {
        // Keep any partial output in the error: octez-client emits the op hash
        // before waiting, so callers can still detect that the op was injected.
        let message = if combined.is_empty() {
            format!("{} timed out after {}s", program_name, timeout.as_secs())
        } else {
            format!(
                "{} timed out after {}s\n{}",
                program_name,
                timeout.as_secs(),
                combined
            )
        };
        return Err(CmdError::Timeout {
            message,
            output: combined,
        });
    }
    let status = status.expect("status is set whenever the command did not time out");
    if !status.success() {
        return Err(CmdError::Failed {
            message: if combined.is_empty() {
                format!("{} exited with status {}", program_name, status)
            } else {
                combined
            },
        });
    }
    Ok(combined)
}

fn extract_operation_hash(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (_, tail) = line.split_once("Operation hash is")?;
        extract_token_with_prefix(tail, 'o')
    })
}

fn extract_block_hash(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (_, tail) = line.split_once("Operation found in block")?;
        extract_token_with_prefix(tail, 'B')
    })
}

fn extract_token_with_prefix(output: &str, prefix: char) -> Option<String> {
    output
        .split(|ch: char| {
            ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';' | ':' | '(' | ')')
        })
        .find_map(|token| {
            if token.starts_with(prefix)
                && token.len() >= 20
                && token.chars().all(|ch| ch.is_ascii_alphanumeric())
            {
                Some(token.to_string())
            } else {
                None
            }
        })
}

fn write_temp_payload(bytes: &[u8]) -> Result<PathBuf, String> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "tzel-operator-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {}", e))?
            .as_nanos()
    ));
    std::fs::write(&path, bytes).map_err(|e| format!("write payload file: {}", e))?;
    Ok(path)
}

fn next_submission_id(config: &OperatorConfig) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let seq = config.id_counter.fetch_add(1, Ordering::Relaxed);
    format!("sub-{}-{:04}", now, seq)
}

fn submissions_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("submissions")
}

fn submission_path(state_dir: &Path, id: &str) -> PathBuf {
    submissions_dir(state_dir).join(format!("{}.json", id))
}

fn persist_submission(config: &OperatorConfig, stored: &StoredSubmission) -> Result<(), String> {
    let mut stored = stored.clone();
    align_chunk_meta(&mut stored);
    if stored.submission.status == RollupSubmissionStatus::SubmittedToL1 {
        stored.payload = None;
    }
    std::fs::create_dir_all(submissions_dir(&config.state_dir))
        .map_err(|e| format!("create submissions dir: {}", e))?;
    let path = submission_path(&config.state_dir, &stored.submission.id);
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create tmp: {}", e))?;
    let body = serde_json::to_string_pretty(&stored)
        .map_err(|e| format!("serialize submission: {}", e))?;
    file.write_all(body.as_bytes())
        .map_err(|e| format!("write tmp: {}", e))?;
    file.sync_all().map_err(|e| format!("fsync tmp: {}", e))?;
    drop(file);
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename submission: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;
    use std::collections::HashMap;
    use std::io::Read;
    use std::net::TcpListener;
    use tzel_core::kernel_wire::{
        sign_kernel_bridge_config, sign_kernel_verifier_config, KernelBridgeConfig,
        KernelVerifierConfig,
    };
    use tzel_core::ProgramHashes;

    fn config_with_client(script: &Path) -> OperatorConfig {
        let state_dir = std::env::temp_dir().join(format!(
            "tzel-operator-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&state_dir).unwrap();
        OperatorConfig {
            source_alias: "alice".into(),
            bearer_token: "test-token".into(),
            state_dir,
            direct_max_message_bytes: 1024,
            dal_max_chunk_bytes: None,
            octez_client_bin: script.display().to_string(),
            octez_client_dir: None,
            octez_node_endpoint: Some("http://octez-node.invalid".into()),
            dal_node_endpoint: None,
            octez_protocol: None,
            dal_fee_policy: None,
            dal_slot_range: None,
            octez_client_timeout: OCTEZ_CLIENT_TIMEOUT,
            id_counter: AtomicU64::new(0),
            slot_counter: AtomicU64::new(0),
            reconcile_cursor: AtomicU64::new(0),
        }
    }

    fn sample_fee_policy() -> OperatorDalFeePolicy {
        let incoming_seed = [0x41; 32];
        let address_index = 0;
        let (ek_v, _dk_v, ek_d, _dk_d) = derive_kem_keys(&incoming_seed, address_index);
        OperatorDalFeePolicy {
            amount: 7,
            incoming_seed,
            address_index,
            address: PaymentAddress {
                d_j: [0x11; 32],
                auth_root: [0x12; 32],
                auth_pub_seed: [0x13; 32],
                nk_tag: [0x14; 32],
                ek_v: ek_v.to_bytes().to_vec(),
                ek_d: ek_d.to_bytes().to_vec(),
            },
        }
    }

    fn sample_fee_note(policy: &OperatorDalFeePolicy, rseed: F) -> (EncryptedNote, F) {
        let ek_v = tzel_core::Ek::new(
            policy
                .address
                .ek_v
                .as_slice()
                .try_into()
                .expect("fixed ek_v length"),
        )
        .expect("valid ek_v");
        let ek_d = tzel_core::Ek::new(
            policy
                .address
                .ek_d
                .as_slice()
                .try_into()
                .expect("fixed ek_d length"),
        )
        .expect("valid ek_d");
        let enc = tzel_core::encrypt_note_deterministic(
            policy.amount,
            &rseed,
            Some(b"dal"),
            &ek_v,
            &ek_d,
            &[0x21; 32],
            &[0x22; 32],
        );
        let rcm = derive_rcm(&rseed);
        let otag = owner_tag(
            &policy.address.auth_root,
            &policy.address.auth_pub_seed,
            &policy.address.nk_tag,
        );
        let cm = commit(&policy.address.d_j, policy.amount, &ASSET_TEZ, &rcm, &otag);
        (enc, cm)
    }

    fn sample_shield_payload_with_producer_note(
        producer_fee: u64,
        producer_cm: F,
        producer_enc: EncryptedNote,
    ) -> Vec<u8> {
        let _policy = sample_fee_policy();
        let mut pubkey_hash = [0u8; 32];
        pubkey_hash[..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        // Use a deterministic synthetic client cm/enc for the operator's
        // fee-policy decoder; consensus validation is exercised elsewhere.
        let mut client_cm = [0u8; 32];
        client_cm[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let client_enc = producer_enc.clone();
        encode_kernel_inbox_message(&KernelInboxMessage::Shield(
            tzel_core::kernel_wire::KernelShieldReq {
                asset_id: tzel_core::ASSET_TEZ,
                pubkey_hash,
                fee: 100_000,
                v: 25,
                producer_fee,
                proof: tzel_core::kernel_wire::KernelStarkProof {
                    proof_bytes: vec![],
                    output_preimage: vec![],
                },
                client_cm,
                client_enc,
                producer_cm,
                producer_enc,
            },
        ))
        .expect("shield payload should encode")
    }

    fn sample_config_admin_ask() -> F {
        hash(b"tzel-dev-rollup-config-admin")
    }

    fn sample_configure_bridge_payload() -> Vec<u8> {
        encode_kernel_inbox_message(&KernelInboxMessage::ConfigureBridge(
            sign_kernel_bridge_config(
                &sample_config_admin_ask(),
                KernelBridgeConfig {
                    ticketer: "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc".into(),
                },
            )
            .unwrap(),
        ))
        .unwrap()
    }

    fn sample_configure_verifier_payload() -> Vec<u8> {
        encode_kernel_inbox_message(&KernelInboxMessage::ConfigureVerifier(
            sign_kernel_verifier_config(
                &sample_config_admin_ask(),
                KernelVerifierConfig {
                    auth_domain: [0x21; 32],
                    verified_program_hashes: ProgramHashes {
                        shield: [0x22; 32],
                        transfer: [0x23; 32],
                        unshield: [0x24; 32],
                    },
                },
            )
            .unwrap(),
        ))
        .unwrap()
    }

    fn sample_invalid_configure_bridge_payload() -> Vec<u8> {
        let mut message = decode_kernel_inbox_message(&sample_configure_bridge_payload()).unwrap();
        let KernelInboxMessage::ConfigureBridge(config) = &mut message else {
            panic!("expected configure-bridge payload")
        };
        config.signature[0][0] ^= 0xff;
        encode_kernel_inbox_message(&message).unwrap()
    }

    fn sample_small_direct_payload() -> Vec<u8> {
        vec![0x54, 0x5a, 0x45, 0x4c]
    }

    #[test]
    fn direct_small_payload_fits_protocol_limit() {
        let framed = encode_targeted_rollup_message(
            "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP",
            &sample_small_direct_payload(),
        )
        .unwrap();
        assert!(
            framed.len() <= DEFAULT_DIRECT_MAX_MESSAGE_BYTES,
            "framed direct message is {} bytes, above {}",
            framed.len(),
            DEFAULT_DIRECT_MAX_MESSAGE_BYTES
        );
    }

    #[test]
    fn signed_config_messages_exceed_protocol_l1_limit() {
        let bridge = encode_targeted_rollup_message(
            "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP",
            &sample_configure_bridge_payload(),
        )
        .unwrap();
        let verifier = encode_targeted_rollup_message(
            "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP",
            &sample_configure_verifier_payload(),
        )
        .unwrap();
        assert!(
            bridge.len() > DEFAULT_DIRECT_MAX_MESSAGE_BYTES,
            "configure-bridge unexpectedly fits direct L1 limit: {} <= {}",
            bridge.len(),
            DEFAULT_DIRECT_MAX_MESSAGE_BYTES
        );
        assert!(
            verifier.len() > DEFAULT_DIRECT_MAX_MESSAGE_BYTES,
            "configure-verifier unexpectedly fits direct L1 limit: {} <= {}",
            verifier.len(),
            DEFAULT_DIRECT_MAX_MESSAGE_BYTES
        );
    }

    #[test]
    fn require_bearer_auth_rejects_missing_and_invalid_tokens() {
        let config = config_with_client(Path::new("/bin/true"));

        let missing = HeaderMap::new();
        let err = require_bearer_auth(&missing, &config).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);

        let mut invalid = HeaderMap::new();
        invalid.insert(AUTHORIZATION, "Bearer wrong-token".parse().unwrap());
        let err = require_bearer_auth(&invalid, &config).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_bearer_auth_accepts_matching_token() {
        let config = config_with_client(Path::new("/bin/true"));
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer test-token".parse().unwrap());
        require_bearer_auth(&headers, &config).expect("matching token should authenticate");
    }

    fn app_state_with_config(config: OperatorConfig) -> AppState {
        AppState {
            config: Arc::new(config),
            advance_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn sample_submit_req() -> SubmitRollupMessageReq {
        SubmitRollupMessageReq {
            kind: RollupSubmissionKind::ConfigureBridge,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: vec![1, 2, 3, 4],
        }
    }

    #[tokio::test]
    async fn submit_route_rejects_missing_bearer_auth() {
        let script_dir = make_client_script("#!/bin/sh\necho 'Operation hash is ooShouldNotRun'\n");
        let state =
            app_state_with_config(config_with_client(&script_dir.path().join("octez-client")));

        let err = submit_rollup_message(State(state), HeaderMap::new(), Json(sample_submit_req()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_route_rejects_missing_bearer_auth() {
        let state = app_state_with_config(config_with_client(Path::new("/bin/true")));

        let err = get_rollup_submission(
            State(state),
            HeaderMap::new(),
            AxumPath("sub-missing-auth".into()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn submit_route_accepts_matching_bearer_auth() {
        let script_dir =
            make_client_script("#!/bin/sh\necho 'Operation hash is ooRouteAuthHash123456789AB'\n");
        let state =
            app_state_with_config(config_with_client(&script_dir.path().join("octez-client")));
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer test-token".parse().unwrap());

        let resp = submit_rollup_message(State(state), headers, Json(sample_submit_req()))
            .await
            .expect("matching token should pass route auth");
        assert_eq!(
            resp.0.submission.status,
            RollupSubmissionStatus::SubmittedToL1
        );
    }

    fn stored_submission(
        submission: RollupSubmission,
        payload: Option<Vec<u8>>,
        chunk_attempts: &[u32],
    ) -> StoredSubmission {
        let len = submission.dal_chunks.len();
        let mut chunk_meta: Vec<ChunkMeta> = chunk_attempts
            .iter()
            .map(|&attempts| ChunkMeta {
                attempts,
                ..Default::default()
            })
            .collect();
        chunk_meta.resize(len, ChunkMeta::default());
        StoredSubmission {
            submission,
            payload,
            chunk_meta,
        }
    }

    fn chunk_attempts_vec(stored: &StoredSubmission) -> Vec<u32> {
        stored.chunk_meta.iter().map(|m| m.attempts).collect()
    }

    fn make_client_script(body: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("octez-client");
        std::fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        dir
    }

    fn spawn_mock_http_server(routes: HashMap<String, (u16, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(routes.len().max(32)) {
                let mut stream = stream.unwrap();
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let (status, body) = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or_else(|| (404, "\"missing\"".to_string()));
                let response = format!(
                    "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    #[test]
    fn large_message_without_dal_endpoint_fails_cleanly() {
        let script_dir = make_client_script("#!/bin/sh\nexit 1\n");
        let config = config_with_client(&script_dir.path().join("octez-client"));
        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: vec![7u8; 5000],
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(submission.status, RollupSubmissionStatus::Failed);
        assert_eq!(submission.transport, RollupSubmissionTransport::Dal);
        assert!(submission.operation_hash.is_none());
        assert!(submission
            .detail
            .as_deref()
            .unwrap()
            .contains("DAL node endpoint is not configured"));
    }

    #[test]
    fn oversized_dal_submission_rejects_fee_note_for_wrong_owner() {
        let script_dir = make_client_script("#!/bin/sh\necho 'should not publish'\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        config.dal_node_endpoint = Some("http://dal.invalid".into());
        config.dal_fee_policy = Some(sample_fee_policy());

        let wrong_incoming_seed = [0x51; 32];
        let (wrong_ek_v, _wrong_dk_v, wrong_ek_d, _wrong_dk_d) =
            derive_kem_keys(&wrong_incoming_seed, 0);
        let wrong_policy = OperatorDalFeePolicy {
            amount: 7,
            incoming_seed: wrong_incoming_seed,
            address_index: 0,
            address: PaymentAddress {
                d_j: [0x61; 32],
                auth_root: [0x62; 32],
                auth_pub_seed: [0x63; 32],
                nk_tag: [0x64; 32],
                ek_v: wrong_ek_v.to_bytes().to_vec(),
                ek_d: wrong_ek_d.to_bytes().to_vec(),
            },
        };
        let (wrong_enc, wrong_cm) = sample_fee_note(&wrong_policy, [0x71; 32]);

        let err = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::Shield,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload: sample_shield_payload_with_producer_note(
                    wrong_policy.amount,
                    wrong_cm,
                    wrong_enc,
                ),
            },
        )
        .unwrap_err();

        assert!(err.contains("configured operator fee address"));
    }

    #[test]
    fn oversized_dal_submission_accepts_matching_fee_note() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooDalFeeHash123456789ABCDEFG'\necho 'Operation found in block BLDalFeeHash123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        let policy = sample_fee_policy();
        config.dal_fee_policy = Some(policy.clone());
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1dalfee\",\"commitment_proof\":\"proof-dalfee\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/BLDalFeeHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":123}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let (enc, cm) = sample_fee_note(&policy, [0x72; 32]);
        let submission = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::Shield,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload: sample_shield_payload_with_producer_note(policy.amount, cm, enc),
            },
        )
        .unwrap();

        assert_eq!(submission.transport, RollupSubmissionTransport::Dal);
        assert_eq!(
            submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(submission.dal_chunks.len(), 1);
    }

    /// Phase E.5 regression: the operator's `enforce_dal_fee_policy`
    /// for KernelInboxMessage::Transfer must inspect cm_4/enc_4 (the
    /// producer-fee slot in Phase C), not cm_3/enc_3 (the change_2
    /// placeholder). Earlier drafts of `enforce_dal_fee_policy`
    /// inspected slot 3, which never decrypts under the operator's
    /// key — making every Phase-C transfer with a configured fee
    /// policy fail to publish (a hard liveness bug, not a
    /// vulnerability, but a complete block on transfer throughput).
    ///
    /// We test `enforce_dal_fee_policy` directly rather than running
    /// the full DAL-publish pipeline so the assertion stays focused
    /// on the cm_4 inspection invariant.
    #[test]
    fn enforce_dal_fee_policy_transfer_accepts_matching_fee_note_in_slot_4() {
        let script_dir = make_client_script("#!/bin/sh\nexit 0\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let policy = sample_fee_policy();
        config.dal_fee_policy = Some(policy.clone());

        let (fee_enc, fee_cm) = sample_fee_note(&policy, [0x73; 32]);
        let placeholder_enc = fee_enc.clone();
        let message = KernelInboxMessage::Transfer(tzel_core::kernel_wire::KernelTransferReq {
            root: [0x10; 32],
            nullifiers: vec![[0x20; 32]],
            fee: 100_000,
            cm_1: [0x31; 32],
            cm_2: [0x32; 32],
            // cm_3 is the change_2 placeholder. Earlier drafts of
            // `enforce_dal_fee_policy` inspected this slot, which
            // never decrypts under the operator's key. To pin down
            // that the check looks at slot 4, we deliberately put a
            // garbage placeholder here.
            cm_3: [0x33; 32],
            cm_4: fee_cm,
            enc_1: placeholder_enc.clone(),
            enc_2: placeholder_enc.clone(),
            enc_3: placeholder_enc,
            enc_4: fee_enc,
            proof: tzel_core::kernel_wire::KernelStarkProof {
                proof_bytes: vec![],
                output_preimage: vec![],
            },
        });

        enforce_dal_fee_policy(&config, &message).expect(
            "operator must accept a Phase-C transfer whose cm_4 decrypts under the policy key — \
             this test fails if `enforce_dal_fee_policy` regresses to inspecting cm_3 (the \
             change_2 placeholder)",
        );
    }

    /// Phase E.5 regression: the operator must REJECT a Phase-C
    /// transfer whose producer-fee note (in slot 4) is owned by a
    /// different address than the policy. Complements the
    /// slot-4-accept test above; together they pin down "operator
    /// inspects slot 4" as the load-bearing invariant.
    #[test]
    fn enforce_dal_fee_policy_transfer_rejects_fee_note_for_wrong_owner_in_slot_4() {
        let script_dir = make_client_script("#!/bin/sh\nexit 0\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.dal_fee_policy = Some(sample_fee_policy());

        let wrong_incoming_seed = [0x52; 32];
        let (wrong_ek_v, _, wrong_ek_d, _) = derive_kem_keys(&wrong_incoming_seed, 0);
        let wrong_policy = OperatorDalFeePolicy {
            amount: 7,
            incoming_seed: wrong_incoming_seed,
            address_index: 0,
            address: PaymentAddress {
                d_j: [0x65; 32],
                auth_root: [0x66; 32],
                auth_pub_seed: [0x67; 32],
                nk_tag: [0x68; 32],
                ek_v: wrong_ek_v.to_bytes().to_vec(),
                ek_d: wrong_ek_d.to_bytes().to_vec(),
            },
        };
        let (wrong_enc, wrong_cm) = sample_fee_note(&wrong_policy, [0x74; 32]);
        let placeholder_enc = wrong_enc.clone();
        let message = KernelInboxMessage::Transfer(tzel_core::kernel_wire::KernelTransferReq {
            root: [0x10; 32],
            nullifiers: vec![[0x20; 32]],
            fee: 100_000,
            cm_1: [0x31; 32],
            cm_2: [0x32; 32],
            cm_3: [0x33; 32],
            cm_4: wrong_cm,
            enc_1: placeholder_enc.clone(),
            enc_2: placeholder_enc.clone(),
            enc_3: placeholder_enc,
            enc_4: wrong_enc,
            proof: tzel_core::kernel_wire::KernelStarkProof {
                proof_bytes: vec![],
                output_preimage: vec![],
            },
        });

        let err = enforce_dal_fee_policy(&config, &message).unwrap_err();
        assert!(
            err.contains("configured operator fee address"),
            "rejection must surface the fee-address mismatch from slot 4: {}",
            err,
        );
    }

    #[test]
    fn oversized_configure_bridge_submission_uses_dal_without_fee_policy() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooCfgBridgeHash123456789ABCDEFG'\necho 'Operation found in block BLCfgBridgeHash123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        config.dal_fee_policy = Some(sample_fee_policy());
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1cfgbridge\",\"commitment_proof\":\"proof-cfgbridge\"}"
                        .into(),
                ),
            ),
            (
                "/chains/main/blocks/BLCfgBridgeHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":123}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::ConfigureBridge,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload: sample_configure_bridge_payload(),
            },
        )
        .unwrap();

        assert_eq!(submission.transport, RollupSubmissionTransport::Dal);
        assert_eq!(
            submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(submission.dal_chunks.len(), 1);
    }

    #[test]
    fn oversized_configure_submission_rejects_kind_mismatch_before_publish() {
        let script_dir = make_client_script("#!/bin/sh\necho 'should not publish'\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        config.dal_node_endpoint = Some("http://dal.invalid".into());

        let err = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::ConfigureVerifier,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload: sample_configure_bridge_payload(),
            },
        )
        .unwrap_err();

        assert!(err.contains("submission kind does not match kernel payload"));
    }

    #[test]
    fn oversized_configure_verifier_submission_uses_dal_without_fee_policy() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooCfgVerifierHash123456789ABCD'\necho 'Operation found in block BLCfgVerifierHash123456789ABCD'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        config.dal_fee_policy = Some(sample_fee_policy());
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1cfgverifier\",\"commitment_proof\":\"proof-cfgverifier\"}"
                        .into(),
                ),
            ),
            (
                "/chains/main/blocks/BLCfgVerifierHash123456789ABCD/header".into(),
                (200, "{\"level\":123}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::ConfigureVerifier,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload: sample_configure_verifier_payload(),
            },
        )
        .unwrap();

        assert_eq!(submission.transport, RollupSubmissionTransport::Dal);
        assert_eq!(
            submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(submission.dal_chunks.len(), 1);
    }

    #[test]
    fn oversized_configure_submission_rejects_malformed_payload_before_publish() {
        let script_dir = make_client_script("#!/bin/sh\necho 'should not publish'\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        config.dal_node_endpoint = Some("http://dal.invalid".into());

        let err = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::ConfigureBridge,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload: vec![0xde, 0xad, 0xbe, 0xef, 0x01],
            },
        )
        .unwrap_err();

        assert!(err.contains("decode kernel payload"));
    }

    #[test]
    fn oversized_configure_submission_rejects_invalid_signature_before_publish() {
        let script_dir = make_client_script("#!/bin/sh\necho 'should not publish'\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        config.dal_node_endpoint = Some("http://dal.invalid".into());

        let err = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::ConfigureBridge,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload: sample_invalid_configure_bridge_payload(),
            },
        )
        .unwrap_err();

        assert!(err.contains("configuration signature verification failed"));
    }

    #[test]
    fn config_submission_routes_to_dal_at_real_l1_limit() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooCfgRealLimitHash123456789AB'\necho 'Operation found in block BLCfgRealLimitHash123456789AB'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = DEFAULT_DIRECT_MAX_MESSAGE_BYTES;
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1cfgreallimit\",\"commitment_proof\":\"proof-cfgreallimit\"}"
                        .into(),
                ),
            ),
            (
                "/chains/main/blocks/BLCfgRealLimitHash123456789AB/header".into(),
                (200, "{\"level\":123}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let payload = sample_configure_bridge_payload();
        let targeted =
            encode_targeted_rollup_message("sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP", &payload)
                .unwrap();
        assert!(targeted.len() > config.direct_max_message_bytes);

        let submission = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::ConfigureBridge,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload,
            },
        )
        .unwrap();

        assert_eq!(submission.transport, RollupSubmissionTransport::Dal);
        assert_eq!(
            submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
    }

    #[test]
    fn small_message_is_sent_directly() {
        let script_dir =
            make_client_script("#!/bin/sh\necho 'Operation hash is ooTestHash123456789ABCDEFG'\n");
        let config = config_with_client(&script_dir.path().join("octez-client"));
        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: sample_small_direct_payload(),
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(submission.status, RollupSubmissionStatus::SubmittedToL1);
        assert_eq!(submission.transport, RollupSubmissionTransport::DirectInbox);
        assert_eq!(
            submission.operation_hash.as_deref(),
            Some("ooTestHash123456789ABCDEFG")
        );
        let stored = load_stored_submission(&config.state_dir, &submission.id).unwrap();
        assert!(stored.payload.is_none());
    }

    #[test]
    fn attested_dal_submission_sends_pointer_message() {
        let script_dir = tempfile::tempdir().unwrap();
        let log_path = script_dir.path().join("client.log");
        let client_path = script_dir.path().join("octez-client");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"{}\"\necho 'Operation hash is ooPointerHash123456789ABCDEFG'\necho 'Operation found in block BLPointerHash123456789ABCDEFG'\n",
            log_path.display()
        );
        std::fs::write(&client_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&client_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&client_path, perms).unwrap();
        }
        let mut config = config_with_client(&client_path);
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/levels/101/slots/3/status".into(),
                (200, "{\"kind\":\"attested\",\"attestation_lag\":8}".into()),
            ),
            (
                "/levels/102/slots/4/status".into(),
                (200, "{\"kind\":\"attested\",\"attestation_lag\":8}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-1".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![
                RollupDalChunk {
                    slot_index: 3,
                    published_level: 101,
                    payload_len: 128,
                    commitment: "commitment-1".into(),
                    operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
                },
                RollupDalChunk {
                    slot_index: 4,
                    published_level: 102,
                    payload_len: 64,
                    commitment: "commitment-2".into(),
                    operation_hash: Some("ooChunkTwo123456789ABCDEFG".into()),
                },
            ],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x44; 32])),
            payload_len: 192,
            detail: None,
        };

        let advanced =
            maybe_advance_submission(&config, stored_submission(submission, None, &[])).unwrap();
        assert_eq!(
            advanced.submission.status,
            RollupSubmissionStatus::SubmittedToL1
        );
        assert_eq!(
            advanced.submission.operation_hash.as_deref(),
            Some("ooPointerHash123456789ABCDEFG")
        );
        assert!(advanced
            .submission
            .detail
            .as_deref()
            .unwrap()
            .contains("All DAL chunks attested"));
        let log = std::fs::read_to_string(log_path).unwrap();
        assert!(log.contains("send"));
        assert!(log.contains("smart"));
        assert!(log.contains("rollup"));
        assert!(log.contains("message"));
        // Must wait for inclusion (-w 1), not fire-and-forget (-w none): the op
        // has to be baked before advance_lock releases, else the next injection
        // reuses the counter and L1 rejects it as a mempool conflict. The
        // args are one-per-line, so this pins the exact `-w 1` sequence and a
        // revert to `-w none` fails it.
        assert!(
            log.contains("-w\n1\n"),
            "pointer inject must wait for inclusion (-w 1); args were:\n{log}"
        );
    }

    #[test]
    fn pointer_inject_error_with_op_hash_is_recorded_not_retried() {
        // octez-client prints the op hash the instant it injects, then times
        // out during the `-w 1` confirmation wait. Because the op reached the
        // node, the submission must land as SubmittedToL1 with that hash — NOT
        // propagate an error (which would make the reconciler inject a
        // duplicate pointer op next tick).
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooPointerHash123456789ABCDEFG'\nsleep 10\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.octez_client_timeout = Duration::from_millis(100);
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/levels/101/slots/3/status".into(),
                (200, "{\"kind\":\"attested\",\"attestation_lag\":8}".into()),
            ),
            (
                "/levels/102/slots/4/status".into(),
                (200, "{\"kind\":\"attested\",\"attestation_lag\":8}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-1".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![
                RollupDalChunk {
                    slot_index: 3,
                    published_level: 101,
                    payload_len: 128,
                    commitment: "commitment-1".into(),
                    operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
                },
                RollupDalChunk {
                    slot_index: 4,
                    published_level: 102,
                    payload_len: 64,
                    commitment: "commitment-2".into(),
                    operation_hash: Some("ooChunkTwo123456789ABCDEFG".into()),
                },
            ],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x44; 32])),
            payload_len: 192,
            detail: None,
        };

        let advanced =
            maybe_advance_submission(&config, stored_submission(submission, None, &[])).unwrap();
        assert_eq!(
            advanced.submission.status,
            RollupSubmissionStatus::SubmittedToL1,
            "an injected-but-unconfirmed pointer must be recorded, not left to re-inject"
        );
        assert_eq!(
            advanced.submission.operation_hash.as_deref(),
            Some("ooPointerHash123456789ABCDEFG")
        );
        assert!(advanced
            .submission
            .detail
            .as_deref()
            .unwrap()
            .contains("confirmation unverified"));
    }

    #[test]
    fn pointer_inject_non_timeout_failure_with_op_hash_returns_error() {
        // A non-timeout `CmdError::Failed` exit on pointer injection (or direct
        // inbox injection) must surface as an error even if output contains an
        // `Operation hash is ...` line.
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooPointerFailed123456789ABCDEFG'\necho 'Fatal error: simulation failed' >&2\nexit 1\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([(
            "/levels/101/slots/3/status".into(),
            (200, "{\"kind\":\"attested\",\"attestation_lag\":8}".into()),
        )]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-ptr-fail".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 3,
                published_level: 101,
                payload_len: 128,
                commitment: "commitment-1".into(),
                operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
            }],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x44; 32])),
            payload_len: 128,
            detail: None,
        };

        let err = maybe_advance_submission(&config, stored_submission(submission, None, &[]))
            .unwrap_err();
        assert!(err.contains("simulation failed"), "unexpected error: {err}");

        // Direct inbox path must also fail rather than recording SubmittedToL1.
        let direct_err = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::Shield,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload: sample_small_direct_payload(),
            },
        )
        .unwrap_err();
        assert!(
            direct_err.contains("simulation failed"),
            "unexpected direct error: {direct_err}"
        );
    }

    #[test]
    fn run_command_times_out_and_keeps_partial_output() {
        // A command that emits an op hash and then blocks past the deadline must
        // be killed and surface a timeout error that still carries the hash, so
        // callers can apply the injected-but-unconfirmed idempotency path.
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg("echo 'Operation hash is ooTimeoutHash123456789ABCDEFG'; sleep 30");
        let started = Instant::now();
        let err = run_command_collect_output(command, "octez-client", Duration::from_millis(500))
            .expect_err("command that outlives the timeout must error");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "timeout should fire well before the command's own sleep"
        );
        assert!(
            matches!(err, CmdError::Timeout { .. }),
            "expected a structured CmdError::Timeout, got: {err:?}"
        );
        assert!(
            err.to_string().contains("timed out"),
            "expected a timeout error, got: {err}"
        );
        assert_eq!(
            extract_operation_hash(err.output()).as_deref(),
            Some("ooTimeoutHash123456789ABCDEFG"),
            "partial output (the op hash) must survive a timeout kill"
        );
    }

    #[test]
    fn extract_operation_hash_ignores_foreign_hashes_in_conflict_errors() {
        assert_eq!(
            extract_operation_hash(
                "Manager tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx already has the operation ooForeignOpHash123456789ABCDEFG in the current block."
            ),
            None
        );
        assert_eq!(
            extract_operation_hash(
                "Error: prevalidation error: mempool already contains a conflicting operation ooForeignOpHash123456789ABCDEFG"
            ),
            None
        );
        assert_eq!(
            extract_operation_hash("Operation hash is 'ooInjectedOpHash123456789ABCDEFG'")
                .as_deref(),
            Some("ooInjectedOpHash123456789ABCDEFG")
        );
    }

    #[test]
    fn unattested_dal_submission_waits_for_chunks() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooUnexpected123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([(
            "/levels/101/slots/3/status".into(),
            (200, "\"waiting_attestation\"".into()),
        )]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-2".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 3,
                published_level: 101,
                payload_len: 128,
                commitment: "commitment-1".into(),
                operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
            }],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x55; 32])),
            payload_len: 128,
            detail: None,
        };

        let advanced =
            maybe_advance_submission(&config, stored_submission(submission.clone(), None, &[]))
                .unwrap();
        assert_eq!(
            advanced.submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(
            advanced.submission.operation_hash,
            submission.operation_hash
        );
        assert!(advanced
            .submission
            .detail
            .as_deref()
            .unwrap()
            .contains("waiting_attestation"));
    }

    #[test]
    fn missing_dal_status_endpoint_is_treated_as_waiting() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooUnexpected123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([(
            "/still-alive".into(),
            (200, "\"ok\"".into()),
        )]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-missing".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 3,
                published_level: 101,
                payload_len: 128,
                commitment: "commitment-1".into(),
                operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
            }],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x57; 32])),
            payload_len: 128,
            detail: None,
        };

        let advanced =
            maybe_advance_submission(&config, stored_submission(submission, None, &[])).unwrap();
        assert_eq!(
            advanced.submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert!(advanced
            .submission
            .detail
            .as_deref()
            .unwrap()
            .contains("waiting_attestation"));
    }

    #[test]
    fn unattested_dal_submission_republishes_chunk() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooRetryHash123456789ABCDEFG'\necho 'Operation found in block BLRetryHash123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/levels/101/slots/3/status".into(),
                (200, "\"unattested\"".into()),
            ),
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1retry\",\"commitment_proof\":\"proof-retry\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/BLRetryHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":123}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-3".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 3,
                published_level: 101,
                payload_len: 128,
                commitment: "commitment-1".into(),
                operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
            }],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x66; 32])),
            payload_len: 128,
            detail: None,
        };

        let advanced = maybe_advance_submission(
            &config,
            stored_submission(submission.clone(), Some(vec![0x42; 128]), &[1]),
        )
        .unwrap();
        assert_eq!(
            advanced.submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(chunk_attempts_vec(&advanced), vec![2]);
        assert_eq!(advanced.submission.dal_chunks[0].slot_index, 0);
        assert_eq!(advanced.submission.dal_chunks[0].published_level, 123);
        assert!(advanced
            .submission
            .detail
            .as_deref()
            .unwrap()
            .contains("Republished 1 DAL chunk(s)"));
    }

    #[test]
    fn mixed_chunk_attestation_only_republishes_the_unattested_chunk() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooMixedHash123456789ABCDEFG'\necho 'Operation found in block BLMixedHash123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/levels/101/slots/3/status".into(),
                (200, "{\"kind\":\"attested\",\"attestation_lag\":8}".into()),
            ),
            (
                "/levels/102/slots/4/status".into(),
                (200, "\"unattested\"".into()),
            ),
            (
                "/levels/103/slots/5/status".into(),
                (200, "{\"kind\":\"attested\",\"attestation_lag\":8}".into()),
            ),
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1mixed\",\"commitment_proof\":\"proof-mixed\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/BLMixedHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":222}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-mixed".into(),
            kind: RollupSubmissionKind::Transfer,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![
                RollupDalChunk {
                    slot_index: 3,
                    published_level: 101,
                    payload_len: 2,
                    commitment: "commitment-1".into(),
                    operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
                },
                RollupDalChunk {
                    slot_index: 4,
                    published_level: 102,
                    payload_len: 3,
                    commitment: "commitment-2".into(),
                    operation_hash: Some("ooChunkTwo123456789ABCDEFG".into()),
                },
                RollupDalChunk {
                    slot_index: 5,
                    published_level: 103,
                    payload_len: 4,
                    commitment: "commitment-3".into(),
                    operation_hash: Some("ooChunkThree123456789ABCD".into()),
                },
            ],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x68; 32])),
            payload_len: 9,
            detail: None,
        };

        let advanced = maybe_advance_submission(
            &config,
            stored_submission(
                submission,
                Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf1, 0xf2, 0xf3, 0xf4]),
                &[1, 1, 1],
            ),
        )
        .unwrap();
        assert_eq!(
            advanced.submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(chunk_attempts_vec(&advanced), vec![1, 2, 1]);
        assert_eq!(advanced.submission.dal_chunks[0].slot_index, 3);
        assert_eq!(advanced.submission.dal_chunks[0].published_level, 101);
        assert_eq!(advanced.submission.dal_chunks[1].slot_index, 0);
        assert_eq!(advanced.submission.dal_chunks[1].published_level, 222);
        assert_eq!(advanced.submission.dal_chunks[1].payload_len, 3);
        assert_eq!(advanced.submission.dal_chunks[2].slot_index, 5);
        assert_eq!(advanced.submission.dal_chunks[2].published_level, 103);
        assert_eq!(
            advanced.submission.commitment.as_deref(),
            Some("commitment-1")
        );
        assert_eq!(advanced.submission.published_level, Some(101));
        assert_eq!(advanced.submission.slot_index, Some(3));
        assert!(advanced
            .submission
            .detail
            .as_deref()
            .unwrap()
            .contains("Republished 1 DAL chunk(s)"));
    }

    #[test]
    fn stale_waiting_attestation_republishes_chunk() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooStaleHash123456789ABCDEFG'\necho 'Operation found in block BLStaleHash123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/levels/101/slots/3/status".into(),
                (200, "\"waiting_attestation\"".into()),
            ),
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":114}".into()),
            ),
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1stale\",\"commitment_proof\":\"proof-stale\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/BLStaleHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":222}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-stale".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 3,
                published_level: 101,
                payload_len: 8,
                commitment: "commitment-1".into(),
                operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
            }],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x69; 32])),
            payload_len: 8,
            detail: None,
        };

        let advanced = maybe_advance_submission(
            &config,
            stored_submission(submission, Some(vec![0x42; 8]), &[1]),
        )
        .unwrap();
        assert_eq!(
            advanced.submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(chunk_attempts_vec(&advanced), vec![2]);
        assert_eq!(advanced.submission.dal_chunks[0].slot_index, 0);
        assert_eq!(advanced.submission.dal_chunks[0].published_level, 222);
        assert!(advanced
            .submission
            .detail
            .as_deref()
            .unwrap()
            .contains("stale waiting_attestation"));
    }

    #[test]
    fn unattested_dal_submission_without_payload_fails_terminally() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooUnexpected123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/levels/101/slots/3/status".into(),
                (200, "\"unattested\"".into()),
            ),
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1retry2\",\"commitment_proof\":\"proof-retry-2\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/BLUnexpected123456789ABCDEFG/header".into(),
                (200, "{\"level\":202}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-3b".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 3,
                published_level: 101,
                payload_len: 128,
                commitment: "commitment-1".into(),
                operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
            }],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x67; 32])),
            payload_len: 128,
            detail: None,
        };

        let err = maybe_advance_submission(&config, stored_submission(submission, None, &[]))
            .unwrap_err();
        assert!(err.contains("payload is unavailable"));
    }

    #[test]
    fn reconciler_persists_updated_submission_status() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooUnexpected123456789ABCDEFG'\necho 'Operation found in block BLUnexpected123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/levels/101/slots/3/status".into(),
                (200, "\"unattested\"".into()),
            ),
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1reconcile\",\"commitment_proof\":\"proof-reconcile\"}"
                        .into(),
                ),
            ),
            (
                "/chains/main/blocks/BLUnexpected123456789ABCDEFG/header".into(),
                (200, "{\"level\":202}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-reconcile".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 3,
                published_level: 101,
                payload_len: 128,
                commitment: "commitment-1".into(),
                operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
            }],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x77; 32])),
            payload_len: 128,
            detail: None,
        };
        persist_submission(
            &config,
            &stored_submission(submission, Some(vec![0x77; 128]), &[1]),
        )
        .unwrap();

        let summary = reconcile_pending_submissions(&config).unwrap();
        assert_eq!(
            summary,
            ReconcileSummary {
                visited: 1,
                updated: 1,
                errors: 0
            }
        );

        let updated = load_submission(&config.state_dir, "sub-reconcile").unwrap();
        assert_eq!(updated.status, RollupSubmissionStatus::CommitmentIncluded);
        assert!(updated
            .detail
            .as_deref()
            .unwrap()
            .contains("Republished 1 DAL chunk(s)"));
    }

    #[test]
    fn pending_dal_submission_resumes_remaining_chunk_publication_after_restart() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooResumeHash123456789ABCDEFG'\necho 'Operation found in block BLResumeHash123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1resume\",\"commitment_proof\":\"proof-resume\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/BLResumeHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":321}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-resume".into(),
            kind: RollupSubmissionKind::Transfer,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::PendingDal,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: None,
            dal_chunks: vec![RollupDalChunk {
                slot_index: 7,
                published_level: 111,
                payload_len: 2,
                commitment: "commitment-1".into(),
                operation_hash: Some("ooExistingChunk123456789ABCDEFG".into()),
            }],
            commitment: None,
            published_level: None,
            slot_index: None,
            payload_hash: Some(hex::encode([0x88; 32])),
            payload_len: 5,
            detail: Some("Accepted for DAL publication".into()),
        };

        let advanced = maybe_advance_submission(
            &config,
            stored_submission(submission, Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee]), &[1]),
        )
        .unwrap();
        assert_eq!(
            advanced.submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(advanced.submission.dal_chunks.len(), 2);
        assert_eq!(advanced.submission.dal_chunks[0].slot_index, 7);
        assert_eq!(advanced.submission.dal_chunks[1].slot_index, 0);
        assert_eq!(advanced.submission.dal_chunks[1].published_level, 321);
        assert_eq!(chunk_attempts_vec(&advanced), vec![1, 1]);
        assert!(advanced
            .submission
            .detail
            .as_deref()
            .unwrap()
            .contains("Published 2 DAL chunk(s); waiting for attestation"));

        let stored = load_stored_submission(&config.state_dir, "sub-resume").unwrap();
        assert_eq!(stored.submission.status, RollupSubmissionStatus::PendingDal);
        assert_eq!(stored.submission.dal_chunks.len(), 2);
        assert!(stored.payload.is_some());
    }

    #[test]
    fn submitted_to_l1_prunes_payload_from_disk() {
        let script_dir = tempfile::tempdir().unwrap();
        let client_path = script_dir.path().join("octez-client");
        let script = "#!/bin/sh\necho 'Operation hash is ooPointerHash123456789ABCDEFG'\necho 'Operation found in block BLPointerHash123456789ABCDEFG'\n";
        std::fs::write(&client_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&client_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&client_path, perms).unwrap();
        }
        let mut config = config_with_client(&client_path);
        let endpoint = spawn_mock_http_server(HashMap::from([(
            "/levels/101/slots/3/status".into(),
            (200, "{\"kind\":\"attested\",\"attestation_lag\":8}".into()),
        )]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-prune".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooCommitmentHash123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 3,
                published_level: 101,
                payload_len: 4,
                commitment: "commitment-1".into(),
                operation_hash: Some("ooChunkOne123456789ABCDEFG".into()),
            }],
            commitment: Some("commitment-1".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x44; 32])),
            payload_len: 4,
            detail: None,
        };

        let advanced = maybe_advance_submission(
            &config,
            stored_submission(submission, Some(vec![1, 2, 3, 4]), &[1]),
        )
        .unwrap();
        assert_eq!(
            advanced.submission.status,
            RollupSubmissionStatus::SubmittedToL1
        );
        persist_submission(&config, &advanced).unwrap();
        let stored = load_stored_submission(&config.state_dir, "sub-prune").unwrap();
        assert!(stored.payload.is_none());
    }

    #[test]
    fn dal_chunk_size_can_be_capped_below_protocol_limit() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooChunkHash123456789ABCDEFG'\necho 'Operation found in block BLChunkHash123456789ABCDEFG'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        config.dal_max_chunk_bytes = Some(1024);
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1aaa\",\"commitment_proof\":\"proof-a\"}".into(),
                ),
            ),
            (
                "/slots?slot_index=1&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1bbb\",\"commitment_proof\":\"proof-b\"}".into(),
                ),
            ),
            (
                "/slots?slot_index=2&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1ccc\",\"commitment_proof\":\"proof-c\"}".into(),
                ),
            ),
            (
                "/slots?slot_index=3&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1ddd\",\"commitment_proof\":\"proof-d\"}".into(),
                ),
            ),
            (
                "/slots?slot_index=4&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1eee\",\"commitment_proof\":\"proof-e\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/BLChunkHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":123}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::ConfigureBridge,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: sample_configure_bridge_payload(),
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(submission.transport, RollupSubmissionTransport::Dal);
        assert!(submission.dal_chunks.len() > 1);
        assert_eq!(submission.dal_chunks[0].payload_len, 1024);
        assert!(submission
            .dal_chunks
            .iter()
            .all(|chunk| chunk.payload_len <= 1024));
    }

    #[test]
    fn dal_slot_collision_retries_next_slot_index() {
        let script_dir = tempfile::tempdir().unwrap();
        let log_path = script_dir.path().join("client.log");
        let client_path = script_dir.path().join("octez-client");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"{}\"\nif printf '%s ' \"$@\" | grep -q 'slot 0 '; then\n  echo 'Error: A slot header for this slot was already proposed' >&2\n  exit 1\nfi\necho 'Operation hash is ooChunkHash123456789ABCDEFG'\necho 'Operation found in block BLChunkHash123456789ABCDEFG'\n",
            log_path.display()
        );
        std::fs::write(&client_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&client_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&client_path, perms).unwrap();
        }
        let mut config = config_with_client(&client_path);
        config.direct_max_message_bytes = 1;
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1aaa\",\"commitment_proof\":\"proof-a\"}".into(),
                ),
            ),
            (
                "/slots?slot_index=1&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1bbb\",\"commitment_proof\":\"proof-b\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/BLChunkHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":123}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::ConfigureBridge,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: sample_configure_bridge_payload(),
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(submission.dal_chunks.len(), 1);
        assert_eq!(submission.dal_chunks[0].slot_index, 1);
        let log = std::fs::read_to_string(log_path).unwrap();
        assert!(log.contains("publish"));
        assert!(log.contains("slot"));
    }

    #[test]
    fn dal_publish_timeout_after_injection_records_chunk_and_resolves_level_later() {
        let script_dir = tempfile::tempdir().unwrap();
        let client_path = script_dir.path().join("octez-client");
        // Simulate octez-client injecting the DAL commitment operation and printing
        // its hash, then blocking past `octez_client_timeout` so the real timeout
        // kill path in `run_command_collect_output` fires (`CmdError::Timeout`).
        let script = r#"#!/bin/sh
case "$*" in
  *"publish dal commitment"*)
    echo "Operation hash is 'ooDalTimedOut123456789ABCDEFG'"
    sleep 10
    ;;
  *)
    echo "Operation hash is 'ooPointerOp123456789ABCDEFG'"
    echo "Operation found in block: BLockGenesis111111111111111111111111111111111111111"
    exit 0
    ;;
esac
"#;
        std::fs::write(&client_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&client_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&client_path, perms).unwrap();
        }
        let mut config = config_with_client(&client_path);
        config.direct_max_message_bytes = 1;
        config.octez_client_timeout = Duration::from_millis(100);
        // At publish time `pre_head` is 456, so `pre_head + 1 = 457` is recorded
        // as the lower bound for the inclusion scan.
        let publish_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1timeout\",\"commitment_proof\":\"proof-t\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":456}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(publish_endpoint.clone());
        config.octez_node_endpoint = Some(publish_endpoint);

        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::ConfigureBridge,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: sample_configure_bridge_payload(),
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(
            submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(submission.dal_chunks.len(), 1);
        assert_eq!(
            submission.dal_chunks[0].operation_hash.as_deref(),
            Some("ooDalTimedOut123456789ABCDEFG")
        );
        assert_eq!(
            submission.dal_chunks[0].published_level,
            UNRESOLVED_PUBLISHED_LEVEL
        );
        assert_eq!(submission.published_level, None);
        let stored_after_publish =
            load_stored_submission(&config.state_dir, &submission.id).unwrap();
        assert_eq!(stored_after_publish.chunk_meta[0].injected_level, Some(457));

        // At head=458 (`final_head = 456 < 457`), level 457 is not yet Tenderbake-final,
        // so the chunk must stay `waiting_inclusion` without inspecting level 457.
        let unfinalized_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":458}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(unfinalized_endpoint.clone());
        config.octez_node_endpoint = Some(unfinalized_endpoint);
        let summary_unfinalized = reconcile_pending_submissions(&config).unwrap();
        assert_eq!(summary_unfinalized.errors, 0);
        let still_unresolved = load_submission(&config.state_dir, &submission.id).unwrap();
        assert_eq!(
            still_unresolved.dal_chunks[0].published_level,
            UNRESOLVED_PUBLISHED_LEVEL
        );

        // Once head reaches 459 (`final_head = 457`), level 457 is finalized and
        // resolved via `/chains/main/blocks/457/operation_hashes/3`, advancing the
        // submission once the slot at level 457 is attested.
        let reconcile_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":459}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
            (
                "/chains/main/blocks/457/operation_hashes/3".into(),
                (200, "[\"ooDalTimedOut123456789ABCDEFG\"]".into()),
            ),
            (
                "/levels/457/slots/0/status".into(),
                (200, "\"attested\"".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(reconcile_endpoint.clone());
        config.octez_node_endpoint = Some(reconcile_endpoint);
        let summary = reconcile_pending_submissions(&config).unwrap();
        assert_eq!(summary.errors, 0);
        let updated = load_submission(&config.state_dir, &submission.id).unwrap();
        assert_eq!(updated.dal_chunks[0].published_level, 457);
        assert_eq!(updated.published_level, Some(457));
        assert_eq!(updated.status, RollupSubmissionStatus::SubmittedToL1);
    }

    #[test]
    fn dal_publish_non_timeout_failure_after_op_hash_returns_error() {
        let script_dir = tempfile::tempdir().unwrap();
        let client_path = script_dir.path().join("octez-client");
        // Even if stderr/stdout begins with a fake "timed out after" line, a
        // non-timeout process exit produces `CmdError::Failed`, not `Timeout`.
        let script = "#!/bin/sh\necho 'octez-client timed out after 60s'\necho \"Operation hash is 'ooFailedOp123456789ABCDEFG'\"\necho 'Fatal error: simulation failed after precheck' >&2\nexit 1\n";
        std::fs::write(&client_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&client_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&client_path, perms).unwrap();
        }
        let mut config = config_with_client(&client_path);
        config.direct_max_message_bytes = 1;
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1fail\",\"commitment_proof\":\"proof-f\"}".into(),
                ),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::ConfigureBridge,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: sample_configure_bridge_payload(),
        };
        let err = process_submission(&config, req).unwrap_err();
        assert!(
            err.contains("simulation failed after precheck"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn dal_publish_success_without_block_hash_records_unresolved_when_op_hash_present() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho \"Operation hash is 'ooOkNoBlockHash123456789ABCDEFG'\"\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1noblock\",\"commitment_proof\":\"proof-nb\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":300}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::ConfigureBridge,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: sample_configure_bridge_payload(),
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(
            submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(
            submission.dal_chunks[0].operation_hash.as_deref(),
            Some("ooOkNoBlockHash123456789ABCDEFG")
        );
        assert_eq!(
            submission.dal_chunks[0].published_level,
            UNRESOLVED_PUBLISHED_LEVEL
        );
        let stored = load_stored_submission(&config.state_dir, &submission.id).unwrap();
        assert_eq!(stored.chunk_meta[0].injected_level, Some(301));
    }

    #[test]
    fn dal_publish_with_block_hash_but_failed_block_header_rpc_persists_block_hash_and_resolves_directly(
    ) {
        let script_dir = make_client_script(
            "#!/bin/sh\necho \"Operation hash is 'ooKnownBlockOp123456789ABCDEFG'\"\necho \"Operation found in block: BLKnownBlockHash123456789ABCDEFG\"\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        // At publish time, `/chains/main/blocks/BLKnownBlockHash123456789ABCDEFG/header`
        // fails (500), so `published_level` stays UNRESOLVED_PUBLISHED_LEVEL,
        // while both `inclusion_block` and `injected_level = pre_head + 1` are
        // persisted in `chunk_meta`.
        let publish_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1knownblock\",\"commitment_proof\":\"proof-kb\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":299}".into()),
            ),
            (
                "/chains/main/blocks/BLKnownBlockHash123456789ABCDEFG/header".into(),
                (500, "temporary header rpc failure".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(publish_endpoint.clone());
        config.octez_node_endpoint = Some(publish_endpoint);

        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::ConfigureBridge,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: sample_configure_bridge_payload(),
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(
            submission.status,
            RollupSubmissionStatus::CommitmentIncluded
        );
        assert_eq!(
            submission.dal_chunks[0].published_level,
            UNRESOLVED_PUBLISHED_LEVEL
        );
        let stored = load_stored_submission(&config.state_dir, &submission.id).unwrap();
        assert_eq!(
            stored.chunk_meta[0].inclusion_block.as_deref(),
            Some("BLKnownBlockHash123456789ABCDEFG")
        );
        assert_eq!(stored.chunk_meta[0].injected_level, Some(300));

        // On the next reconcile tick, `fetch_block_level` succeeds for the
        // persisted block hash, verifies canonicity at level 300 on the main
        // chain, and resolves directly without needing `context/constants` or
        // a multi-level scan.
        let reconcile_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/BLKnownBlockHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":300}".into()),
            ),
            (
                "/chains/main/blocks/300/operation_hashes/3".into(),
                (200, "[\"ooKnownBlockOp123456789ABCDEFG\"]".into()),
            ),
            (
                "/levels/300/slots/0/status".into(),
                (200, "\"waiting_attestation\"".into()),
            ),
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":305}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(reconcile_endpoint.clone());
        config.octez_node_endpoint = Some(reconcile_endpoint);
        let summary = reconcile_pending_submissions(&config).unwrap();
        assert_eq!(summary.errors, 0);
        let resolved = load_stored_submission(&config.state_dir, &submission.id).unwrap();
        assert_eq!(resolved.submission.dal_chunks[0].published_level, 300);
        assert_eq!(resolved.submission.published_level, Some(300));
        assert_eq!(resolved.chunk_meta[0].inclusion_block, None);
        assert_eq!(resolved.chunk_meta[0].injected_level, None);
    }

    #[test]
    fn unresolved_chunk_reorged_inclusion_block_falls_back_to_canonical_scan() {
        let script_dir = make_client_script("#!/bin/sh\nexit 1\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));

        let submission = RollupSubmission {
            id: "sub-reorg-404".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooReorgedOp123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 0,
                published_level: UNRESOLVED_PUBLISHED_LEVEL,
                payload_len: 4,
                commitment: "sh1reorg".into(),
                operation_hash: Some("ooReorgedOp123456789ABCDEFG".into()),
            }],
            commitment: Some("sh1reorg".into()),
            published_level: None,
            slot_index: Some(0),
            payload_hash: Some(hex::encode([0x58; 32])),
            payload_len: 4,
            detail: None,
        };

        // Case 0: up to `MAX_INCLUSION_BLOCK_LOOKUP_FAILURES - 1` transient 500
        // responses on `/blocks/<hash>/header` keep `inclusion_block` intact,
        // a successful `fetch_block_level` (even when `level > final_head` returns
        // early) resets `inclusion_block_failures` to 0 so only *consecutive*
        // failures count, and the `MAX_INCLUSION_BLOCK_LOOKUP_FAILURES`-th
        // consecutive failure clears the hint and falls back to the canonical scan.
        let unfinalized_ok_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":301}".into()),
            ),
            (
                "/chains/main/blocks/BLTransient500Block123456789ABCDEFG/header".into(),
                (200, "{\"level\":300}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(unfinalized_ok_endpoint.clone());
        config.octez_node_endpoint = Some(unfinalized_ok_endpoint);
        let mut stored_reset = stored_submission(submission.clone(), Some(vec![1, 2, 3, 4]), &[1]);
        stored_reset.chunk_meta[0].inclusion_block =
            Some("BLTransient500Block123456789ABCDEFG".into());
        stored_reset.chunk_meta[0].inclusion_block_failures =
            MAX_INCLUSION_BLOCK_LOOKUP_FAILURES - 1;
        let after_ok_unfinalized = maybe_advance_submission(&config, stored_reset).unwrap();
        assert_eq!(
            after_ok_unfinalized.chunk_meta[0].inclusion_block_failures,
            0
        );
        assert_eq!(
            after_ok_unfinalized.chunk_meta[0]
                .inclusion_block
                .as_deref(),
            Some("BLTransient500Block123456789ABCDEFG")
        );

        let transient_500_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":304}".into()),
            ),
            (
                "/chains/main/blocks/BLTransient500Block123456789ABCDEFG/header".into(),
                (500, "temporary node error".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
            (
                "/chains/main/blocks/300/operation_hashes/3".into(),
                (200, "[]".into()),
            ),
            (
                "/chains/main/blocks/301/operation_hashes/3".into(),
                (200, "[\"ooReorgedOp123456789ABCDEFG\"]".into()),
            ),
            (
                "/levels/301/slots/0/status".into(),
                (200, "\"waiting_attestation\"".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(transient_500_endpoint.clone());
        config.octez_node_endpoint = Some(transient_500_endpoint);

        let mut stored_500 = stored_submission(submission.clone(), Some(vec![1, 2, 3, 4]), &[1]);
        stored_500.chunk_meta[0].inclusion_block =
            Some("BLTransient500Block123456789ABCDEFG".into());
        stored_500.chunk_meta[0].injected_level = Some(300);
        for expected_failures in 1..MAX_INCLUSION_BLOCK_LOOKUP_FAILURES {
            stored_500 = maybe_advance_submission(&config, stored_500).unwrap();
            assert_eq!(
                stored_500.submission.dal_chunks[0].published_level,
                UNRESOLVED_PUBLISHED_LEVEL
            );
            assert_eq!(
                stored_500.chunk_meta[0].inclusion_block.as_deref(),
                Some("BLTransient500Block123456789ABCDEFG")
            );
            assert_eq!(
                stored_500.chunk_meta[0].inclusion_block_failures,
                expected_failures
            );
        }
        let resolved_after_500s = maybe_advance_submission(&config, stored_500).unwrap();
        assert_eq!(
            resolved_after_500s.submission.dal_chunks[0].published_level,
            301
        );
        assert_eq!(resolved_after_500s.chunk_meta[0].inclusion_block, None);
        assert_eq!(
            resolved_after_500s.chunk_meta[0].inclusion_block_failures,
            0
        );

        // Case 0b: when `/chains/main/blocks/300/operation_hashes/3` returns 404
        // (pruned block on a rolling node), the canonical scan skips level 300 and
        // resolves at level 301; by contrast, a transient 500 on `operation_hashes/3`
        // keeps waiting without skipping level 300 or dropping `inclusion_block`.
        let pruned_level_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":304}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
            (
                "/chains/main/blocks/300/operation_hashes/3".into(),
                (404, "pruned block".into()),
            ),
            (
                "/chains/main/blocks/301/operation_hashes/3".into(),
                (200, "[\"ooReorgedOp123456789ABCDEFG\"]".into()),
            ),
            (
                "/levels/301/slots/0/status".into(),
                (200, "\"waiting_attestation\"".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(pruned_level_endpoint.clone());
        config.octez_node_endpoint = Some(pruned_level_endpoint);

        let mut stored_pruned = stored_submission(submission.clone(), Some(vec![1, 2, 3, 4]), &[1]);
        stored_pruned.chunk_meta[0].injected_level = Some(300);
        let resolved_after_pruned = maybe_advance_submission(&config, stored_pruned).unwrap();
        assert_eq!(
            resolved_after_pruned.submission.dal_chunks[0].published_level,
            301
        );
        assert!(!resolved_after_pruned.chunk_meta[0].skipped_pruned_levels);

        let op_hashes_500_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":304}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
            (
                "/chains/main/blocks/BLHint300Block123456789ABCDEFG/header".into(),
                (200, "{\"level\":300}".into()),
            ),
            (
                "/chains/main/blocks/300/operation_hashes/3".into(),
                (500, "transient op hashes error".into()),
            ),
            (
                "/chains/main/blocks/301/operation_hashes/3".into(),
                (200, "[\"ooReorgedOp123456789ABCDEFG\"]".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(op_hashes_500_endpoint.clone());
        config.octez_node_endpoint = Some(op_hashes_500_endpoint);

        let mut stored_op_500 = stored_submission(submission.clone(), Some(vec![1, 2, 3, 4]), &[1]);
        stored_op_500.chunk_meta[0].inclusion_block = Some("BLHint300Block123456789ABCDEFG".into());
        stored_op_500.chunk_meta[0].injected_level = Some(300);
        for _ in 0..4 {
            stored_op_500 = maybe_advance_submission(&config, stored_op_500).unwrap();
            assert_eq!(
                stored_op_500.submission.dal_chunks[0].published_level,
                UNRESOLVED_PUBLISHED_LEVEL
            );
            assert_eq!(
                stored_op_500.chunk_meta[0].inclusion_block.as_deref(),
                Some("BLHint300Block123456789ABCDEFG")
            );
            assert_eq!(stored_op_500.chunk_meta[0].scan_cursor, None);
            assert!(!stored_op_500.chunk_meta[0].skipped_pruned_levels);
        }
        stored_op_500.chunk_meta[0].inclusion_block = None;
        for _ in 0..4 {
            stored_op_500 = maybe_advance_submission(&config, stored_op_500).unwrap();
            assert_eq!(
                stored_op_500.submission.dal_chunks[0].published_level,
                UNRESOLVED_PUBLISHED_LEVEL
            );
            assert_eq!(stored_op_500.chunk_meta[0].scan_cursor, None);
            assert!(!stored_op_500.chunk_meta[0].skipped_pruned_levels);
        }

        // Case A: `inclusion_block` returns 404 (reorged out and forgotten by node),
        // so `resolve_unresolved_chunk_level` clears `inclusion_block`, falls back
        // to the level scan from `injected_level = 300`, and resolves at 301.
        let orphan_404_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":304}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
            (
                "/chains/main/blocks/300/operation_hashes/3".into(),
                (200, "[]".into()),
            ),
            (
                "/chains/main/blocks/301/operation_hashes/3".into(),
                (200, "[\"ooReorgedOp123456789ABCDEFG\"]".into()),
            ),
            (
                "/levels/301/slots/0/status".into(),
                (200, "\"waiting_attestation\"".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(orphan_404_endpoint.clone());
        config.octez_node_endpoint = Some(orphan_404_endpoint);

        let mut stored_a = stored_submission(submission.clone(), Some(vec![1, 2, 3, 4]), &[1]);
        stored_a.chunk_meta[0].inclusion_block = Some("BLOrphan404Block123456789ABCDEFG".into());
        stored_a.chunk_meta[0].injected_level = Some(300);
        let resolved_a = maybe_advance_submission(&config, stored_a).unwrap();
        assert_eq!(resolved_a.submission.dal_chunks[0].published_level, 301);
        assert_eq!(resolved_a.chunk_meta[0].inclusion_block, None);

        // Case B: `inclusion_block` header is still known to the node at level 300,
        // `injected_level` is `None`, and canonical block 300 does NOT contain the
        // op; it was included on the canonical branch at level 299 (earlier than
        // the orphaned block's level 300, within `level - TENDERBAKE_FINALITY_LAG`).
        let uncle_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":304}".into()),
            ),
            (
                "/chains/main/blocks/BLUncleBlockHash123456789ABCDEFG/header".into(),
                (200, "{\"level\":300}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
            (
                "/chains/main/blocks/298/operation_hashes/3".into(),
                (200, "[]".into()),
            ),
            (
                "/chains/main/blocks/299/operation_hashes/3".into(),
                (200, "[\"ooReorgedOp123456789ABCDEFG\"]".into()),
            ),
            (
                "/chains/main/blocks/300/operation_hashes/3".into(),
                (200, "[]".into()),
            ),
            (
                "/levels/299/slots/0/status".into(),
                (200, "\"waiting_attestation\"".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(uncle_endpoint.clone());
        config.octez_node_endpoint = Some(uncle_endpoint);

        let mut stored_b = stored_submission(submission, Some(vec![1, 2, 3, 4]), &[1]);
        stored_b.chunk_meta[0].inclusion_block = Some("BLUncleBlockHash123456789ABCDEFG".into());
        stored_b.chunk_meta[0].injected_level = None;
        let resolved_b = maybe_advance_submission(&config, stored_b).unwrap();
        assert_eq!(resolved_b.submission.dal_chunks[0].published_level, 299);
        assert_eq!(resolved_b.chunk_meta[0].inclusion_block, None);
    }

    #[test]
    fn reconcile_pass_shares_scan_budget_across_submissions() {
        let script_dir = make_client_script("#!/bin/sh\nexit 1\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        // Two unresolved submissions in the same `reconcile_pending_submissions`
        // pass share `MAX_INCLUSION_SCAN_LEVELS_PER_TICK = 32` total `/operation_hashes/3`
        // requests (and fetch `/chains/main/blocks/head/header` only once):
        // on tick 1 (`reconcile_cursor = 0`), sub-1 scans 32 levels (`100..=131`)
        // and exhausts the tick's budget, so sub-2 waits; on tick 2 (`reconcile_cursor = 1`),
        // `reconcile_pending_submissions` rotates across active submissions only
        // (ignoring terminal `SubmittedToL1`/`Failed` files) so sub-2 is visited
        // first and advances (`150..=181`) instead of starving behind sub-1.
        let mut routes = HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":200}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
        ]);
        for lvl in (100..=131).chain(150..=181) {
            routes.insert(
                format!("/chains/main/blocks/{lvl}/operation_hashes/3"),
                (200, "[]".into()),
            );
        }
        let endpoint = spawn_mock_http_server(routes);
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        // Persist terminal submissions that sort before `sub-budget-1` so rotating
        // raw `submission_paths` before filtering to active statuses would still
        // visit `sub-budget-1` first on tick 2.
        for (term_id, status) in [
            ("sub-a-terminal-1", RollupSubmissionStatus::SubmittedToL1),
            ("sub-a-terminal-2", RollupSubmissionStatus::Failed),
        ] {
            let term_sub = RollupSubmission {
                id: term_id.into(),
                kind: RollupSubmissionKind::Shield,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                status,
                transport: RollupSubmissionTransport::DirectInbox,
                operation_hash: None,
                dal_chunks: vec![],
                commitment: None,
                published_level: None,
                slot_index: None,
                payload_hash: None,
                payload_len: 0,
                detail: None,
            };
            persist_submission(&config, &stored_submission(term_sub, None, &[])).unwrap();
        }

        for (id, start_lvl) in [("sub-budget-1", 100), ("sub-budget-2", 150)] {
            let sub = RollupSubmission {
                id: id.into(),
                kind: RollupSubmissionKind::Shield,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                status: RollupSubmissionStatus::CommitmentIncluded,
                transport: RollupSubmissionTransport::Dal,
                operation_hash: Some(format!("ooBudgetOp{start_lvl}123456789ABCDEFG")),
                dal_chunks: vec![RollupDalChunk {
                    slot_index: 0,
                    published_level: UNRESOLVED_PUBLISHED_LEVEL,
                    payload_len: 4,
                    commitment: "sh1budget".into(),
                    operation_hash: Some(format!("ooBudgetOp{start_lvl}123456789ABCDEFG")),
                }],
                commitment: Some("sh1budget".into()),
                published_level: None,
                slot_index: Some(0),
                payload_hash: Some(hex::encode([0x59; 32])),
                payload_len: 4,
                detail: None,
            };
            let mut stored = stored_submission(sub, Some(vec![1, 2, 3, 4]), &[1]);
            stored.chunk_meta[0].injected_level = Some(start_lvl);
            stored.chunk_meta[0].max_operations_ttl = Some(600);
            persist_submission(&config, &stored).unwrap();
        }

        let summary1 = reconcile_pending_submissions(&config).unwrap();
        assert_eq!(summary1.errors, 0);
        let sub1 = load_stored_submission(&config.state_dir, "sub-budget-1").unwrap();
        let sub2 = load_stored_submission(&config.state_dir, "sub-budget-2").unwrap();
        assert_eq!(
            sub1.chunk_meta[0].scan_cursor,
            Some(100 + MAX_INCLUSION_SCAN_LEVELS_PER_TICK)
        );
        // sub-2's cursor was not advanced on tick 1 because sub-1 consumed the
        // entire 32-level per-tick budget.
        assert_eq!(sub2.chunk_meta[0].scan_cursor, None);

        // On tick 2, rotation over active submissions visits sub-2 first so it
        // gets the 32-level budget even though sub-1 still has unresolved levels
        // remaining (`132..=198`) and terminal files precede both on disk.
        let summary2 = reconcile_pending_submissions(&config).unwrap();
        assert_eq!(summary2.errors, 0);
        let sub1_tick2 = load_stored_submission(&config.state_dir, "sub-budget-1").unwrap();
        let sub2_tick2 = load_stored_submission(&config.state_dir, "sub-budget-2").unwrap();
        assert_eq!(
            sub1_tick2.chunk_meta[0].scan_cursor,
            Some(100 + MAX_INCLUSION_SCAN_LEVELS_PER_TICK)
        );
        assert_eq!(
            sub2_tick2.chunk_meta[0].scan_cursor,
            Some(150 + MAX_INCLUSION_SCAN_LEVELS_PER_TICK)
        );
    }

    #[test]
    fn retry_loop_checks_attempt_cap_before_republishing_earlier_chunks() {
        // If `octez-client` is invoked at all, fail the test: when chunk 1 has
        // already reached `MAX_DAL_CHUNK_ATTEMPTS`, chunk 0 must NOT be republished
        // before the submission transitions to `Failed`.
        let script_dir =
            make_client_script("#!/bin/sh\necho 'should not republish chunk 0' >&2\nexit 1\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/levels/101/slots/3/status".into(),
                (200, "\"unattested\"".into()),
            ),
            (
                "/levels/102/slots/4/status".into(),
                (200, "\"unattested\"".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-cap-upfront".into(),
            kind: RollupSubmissionKind::Transfer,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooOrigChunkTwo123456789ABCDEFG".into()),
            dal_chunks: vec![
                RollupDalChunk {
                    slot_index: 3,
                    published_level: 101,
                    payload_len: 2,
                    commitment: "sh1old0".into(),
                    operation_hash: Some("ooOrigChunkOne123456789ABCDEFG".into()),
                },
                RollupDalChunk {
                    slot_index: 4,
                    published_level: 102,
                    payload_len: 2,
                    commitment: "sh1old1".into(),
                    operation_hash: Some("ooOrigChunkTwo123456789ABCDEFG".into()),
                },
            ],
            commitment: Some("sh1old0".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x7a; 32])),
            payload_len: 4,
            detail: None,
        };
        let initial = stored_submission(
            submission,
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd]),
            &[1, MAX_DAL_CHUNK_ATTEMPTS],
        );
        let advanced = maybe_advance_submission(&config, initial).unwrap();
        assert_eq!(advanced.submission.status, RollupSubmissionStatus::Failed);
        assert_eq!(
            chunk_attempts_vec(&advanced),
            vec![1, MAX_DAL_CHUNK_ATTEMPTS]
        );
    }

    #[test]
    fn partial_republish_failure_persists_earlier_republished_chunks() {
        let script_dir = tempfile::tempdir().unwrap();
        let counter_file = script_dir.path().join("call_count");
        let client_path = script_dir.path().join("octez-client");
        // Succeeds on the first `publish dal commitment` call (chunk 0) and fails
        // on the second call (chunk 1).
        let script = format!(
            "#!/bin/sh\nif [ ! -f \"{0}\" ]; then\n  echo 1 > \"{0}\"\n  echo \"Operation hash is 'ooRepubChunkZero123456789ABCDEFG'\"\n  echo \"Operation found in block: BLRepubChunkZero123456789ABCDEFG\"\n  exit 0\nfi\necho 'second chunk publish failed' >&2\nexit 1\n",
            counter_file.display()
        );
        std::fs::write(&client_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&client_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&client_path, perms).unwrap();
        }
        let mut config = config_with_client(&client_path);
        let endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/levels/101/slots/3/status".into(),
                (200, "\"unattested\"".into()),
            ),
            (
                "/levels/102/slots/4/status".into(),
                (200, "\"unattested\"".into()),
            ),
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1chunk0new\",\"commitment_proof\":\"proof-0\"}".into(),
                ),
            ),
            (
                "/slots?slot_index=1&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1chunk1new\",\"commitment_proof\":\"proof-1\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/BLRepubChunkZero123456789ABCDEFG/header".into(),
                (200, "{\"level\":210}".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-partial-repub".into(),
            kind: RollupSubmissionKind::Transfer,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooOrigChunkTwo123456789ABCDEFG".into()),
            dal_chunks: vec![
                RollupDalChunk {
                    slot_index: 3,
                    published_level: 101,
                    payload_len: 2,
                    commitment: "sh1old0".into(),
                    operation_hash: Some("ooOrigChunkOne123456789ABCDEFG".into()),
                },
                RollupDalChunk {
                    slot_index: 4,
                    published_level: 102,
                    payload_len: 2,
                    commitment: "sh1old1".into(),
                    operation_hash: Some("ooOrigChunkTwo123456789ABCDEFG".into()),
                },
            ],
            commitment: Some("sh1old0".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x79; 32])),
            payload_len: 4,
            detail: None,
        };
        let initial = stored_submission(submission, Some(vec![0xaa, 0xbb, 0xcc, 0xdd]), &[1, 1]);
        persist_submission(&config, &initial).unwrap();

        let err = maybe_advance_submission(&config, initial).unwrap_err();
        assert!(
            err.contains("second chunk publish failed"),
            "unexpected error: {err}"
        );

        // Chunk 0's new commitment, level, op_hash, and incremented attempt count
        // must already be persisted on disk even though chunk 1 failed.
        let persisted = load_stored_submission(&config.state_dir, "sub-partial-repub").unwrap();
        assert_eq!(chunk_attempts_vec(&persisted), vec![2, 1]);
        assert_eq!(persisted.submission.dal_chunks[0].published_level, 210);
        assert_eq!(
            persisted.submission.dal_chunks[0].commitment,
            "sh1chunk0new"
        );
        assert_eq!(
            persisted.submission.dal_chunks[0].operation_hash.as_deref(),
            Some("ooRepubChunkZero123456789ABCDEFG")
        );
        assert_eq!(persisted.submission.dal_chunks[1].published_level, 102);
    }

    #[test]
    fn unresolved_chunk_dropped_operation_republishes_after_ttl() {
        let script_dir = make_client_script(
            "#!/bin/sh\necho \"Operation hash is 'ooRepublished123456789ABCDEFG'\"\necho \"Operation found in block: BLRepublished123456789ABCDEFG\"\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        // Use `max_operations_time_to_live = 20` (> MAX_WAITING_ATTESTATION_LEVEL_AGE = 12)
        // so tick 1 at head=116 (`final_head = 114`, age=14 > 12) must NOT prematurely
        // declare the operation dropped, and must persist `scan_cursor = Some(115)`
        // and `max_operations_ttl = Some(20)` in `chunk_meta`.
        let mut tick1_routes = HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":116}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":20}".into()),
            ),
        ]);
        for lvl in 100..=114 {
            tick1_routes.insert(
                format!("/chains/main/blocks/{lvl}/operation_hashes/3"),
                (200, "[]".into()),
            );
        }
        let tick1_endpoint = spawn_mock_http_server(tick1_routes);
        config.dal_node_endpoint = Some(tick1_endpoint.clone());
        config.octez_node_endpoint = Some(tick1_endpoint);

        let submission = RollupSubmission {
            id: "sub-dropped".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooDroppedOp123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 0,
                published_level: UNRESOLVED_PUBLISHED_LEVEL,
                payload_len: 4,
                commitment: "sh1old".into(),
                operation_hash: Some("ooDroppedOp123456789ABCDEFG".into()),
            }],
            commitment: Some("sh1old".into()),
            published_level: None,
            slot_index: Some(0),
            payload_hash: Some(hex::encode([0x55; 32])),
            payload_len: 4,
            detail: None,
        };
        let mut stored = stored_submission(submission, Some(vec![1, 2, 3, 4]), &[1]);
        stored.chunk_meta[0].injected_level = Some(100);
        persist_submission(&config, &stored).unwrap();

        let after_tick1 = maybe_advance_submission(&config, stored).unwrap();
        assert_eq!(chunk_attempts_vec(&after_tick1), vec![1]);
        assert_eq!(
            after_tick1.submission.dal_chunks[0].published_level,
            UNRESOLVED_PUBLISHED_LEVEL
        );
        assert_eq!(after_tick1.chunk_meta[0].scan_cursor, Some(115));
        assert_eq!(after_tick1.chunk_meta[0].max_operations_ttl, Some(20));
        let persisted_tick1 = load_stored_submission(&config.state_dir, "sub-dropped").unwrap();
        assert_eq!(persisted_tick1.chunk_meta[0].scan_cursor, Some(115));
        assert_eq!(persisted_tick1.chunk_meta[0].max_operations_ttl, Some(20));

        // Tick 2 at head=122 (`final_head = 120 >= start_level (100) + ttl (20)`):
        // only levels 115..=120 are served (100..=114 and `context/constants` are
        // omitted, proving both `scan_cursor` and `max_operations_ttl` are reused
        // from `ChunkMeta`), and the chunk is then declared dropped and republished.
        let mut tick2_routes = HashMap::from([
            (
                "/protocol_parameters".into(),
                (
                    200,
                    "{\"number_of_slots\":32,\"cryptobox_parameters\":{\"slot_size\":8192}}".into(),
                ),
            ),
            (
                "/slots?slot_index=0&padding=%00".into(),
                (
                    200,
                    "{\"commitment\":\"sh1repub\",\"commitment_proof\":\"proof-r\"}".into(),
                ),
            ),
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":122}".into()),
            ),
            (
                "/chains/main/blocks/BLRepublished123456789ABCDEFG/header".into(),
                (200, "{\"level\":123}".into()),
            ),
        ]);
        for lvl in 115..=120 {
            tick2_routes.insert(
                format!("/chains/main/blocks/{lvl}/operation_hashes/3"),
                (200, "[]".into()),
            );
        }
        let tick2_endpoint = spawn_mock_http_server(tick2_routes);
        config.dal_node_endpoint = Some(tick2_endpoint.clone());
        config.octez_node_endpoint = Some(tick2_endpoint);

        let advanced = maybe_advance_submission(&config, after_tick1).unwrap();
        assert_eq!(chunk_attempts_vec(&advanced), vec![2]);
        assert_eq!(advanced.submission.dal_chunks[0].published_level, 123);
        assert_eq!(
            advanced.submission.dal_chunks[0].operation_hash.as_deref(),
            Some("ooRepublished123456789ABCDEFG")
        );
        assert_eq!(advanced.chunk_meta[0].scan_cursor, None);
        assert_eq!(advanced.chunk_meta[0].max_operations_ttl, None);
    }

    #[test]
    fn unresolved_chunk_lazy_init_looks_back_and_does_not_expire_immediately() {
        let script_dir = make_client_script("#!/bin/sh\nexit 1\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        // When `injected_level` was `None` (because `pre_head` failed at publish
        // time), the first reconcile tick at head=702 (`final_head = 700`) with
        // Alpha's `max_operations_time_to_live = 600` looks back to `702 - 600 = 102`,
        // sets `injected_level = Some(702)` (so the expiry deadline is `702 + 600 = 1302`),
        // and scans at most `MAX_INCLUSION_SCAN_LEVELS_PER_TICK = 32` levels (`102..=133`)
        // on a single tick so `advance_lock` is not held across ~600 RPCs.
        let mut routes = HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":702}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
        ]);
        for lvl in 102..=133 {
            routes.insert(
                format!("/chains/main/blocks/{lvl}/operation_hashes/3"),
                (200, "[]".into()),
            );
        }
        let endpoint = spawn_mock_http_server(routes);
        config.dal_node_endpoint = Some(endpoint.clone());
        config.octez_node_endpoint = Some(endpoint);

        let submission = RollupSubmission {
            id: "sub-lazy".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooLazyOp123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 0,
                published_level: UNRESOLVED_PUBLISHED_LEVEL,
                payload_len: 4,
                commitment: "sh1lazy".into(),
                operation_hash: Some("ooLazyOp123456789ABCDEFG".into()),
            }],
            commitment: Some("sh1lazy".into()),
            published_level: None,
            slot_index: Some(0),
            payload_hash: Some(hex::encode([0x56; 32])),
            payload_len: 4,
            detail: None,
        };
        let stored = stored_submission(submission, Some(vec![1, 2, 3, 4]), &[1]);
        persist_submission(&config, &stored).unwrap();

        let advanced = maybe_advance_submission(&config, stored).unwrap();
        assert_eq!(chunk_attempts_vec(&advanced), vec![1]);
        assert_eq!(advanced.chunk_meta[0].injected_level, Some(702));
        assert_eq!(advanced.chunk_meta[0].max_operations_ttl, Some(600));
        assert_eq!(
            advanced.chunk_meta[0].scan_cursor,
            Some(102 + MAX_INCLUSION_SCAN_LEVELS_PER_TICK)
        );
    }

    #[test]
    fn unresolved_chunk_transient_rpc_error_waits_and_persists_resolved_level_before_status_error()
    {
        let script_dir = make_client_script("#!/bin/sh\nexit 1\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        // 1) When head/operation_hashes RPC fails transiently (500), the chunk stays
        //    waiting_inclusion without consuming a retry attempt.
        let failing_endpoint = spawn_mock_http_server(HashMap::from([(
            "/chains/main/blocks/head/header".into(),
            (500, "internal error".into()),
        )]));
        config.dal_node_endpoint = Some(failing_endpoint.clone());
        config.octez_node_endpoint = Some(failing_endpoint);

        let submission = RollupSubmission {
            id: "sub-transient".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooPendingOp123456789ABCDEFG".into()),
            dal_chunks: vec![RollupDalChunk {
                slot_index: 2,
                published_level: UNRESOLVED_PUBLISHED_LEVEL,
                payload_len: 4,
                commitment: "sh1pend".into(),
                operation_hash: Some("ooPendingOp123456789ABCDEFG".into()),
            }],
            commitment: Some("sh1pend".into()),
            published_level: None,
            slot_index: Some(2),
            payload_hash: Some(hex::encode([0x66; 32])),
            payload_len: 4,
            detail: None,
        };
        let mut stored = stored_submission(submission, Some(vec![1, 2, 3, 4]), &[1]);
        stored.chunk_meta[0].injected_level = Some(200);
        persist_submission(&config, &stored).unwrap();

        let waiting = maybe_advance_submission(&config, stored.clone()).unwrap();
        assert_eq!(chunk_attempts_vec(&waiting), vec![1]);
        assert_eq!(
            waiting.submission.dal_chunks[0].published_level,
            UNRESOLVED_PUBLISHED_LEVEL
        );

        // 2) When inclusion resolves at level 201 (`head = 203`, `final_head = 201`),
        //    but the subsequent DAL slot status call returns 500, the resolved
        //    `published_level = 201` must still be persisted to disk before
        //    `maybe_advance_submission` errors.
        let resolving_endpoint = spawn_mock_http_server(HashMap::from([
            (
                "/chains/main/blocks/head/header".into(),
                (200, "{\"level\":203}".into()),
            ),
            (
                "/chains/main/blocks/head/context/constants".into(),
                (200, "{\"max_operations_time_to_live\":600}".into()),
            ),
            (
                "/chains/main/blocks/200/operation_hashes/3".into(),
                (200, "[]".into()),
            ),
            (
                "/chains/main/blocks/201/operation_hashes/3".into(),
                (200, "[\"ooPendingOp123456789ABCDEFG\"]".into()),
            ),
            (
                "/levels/201/slots/2/status".into(),
                (500, "dal status error".into()),
            ),
        ]));
        config.dal_node_endpoint = Some(resolving_endpoint.clone());
        config.octez_node_endpoint = Some(resolving_endpoint);

        let err = maybe_advance_submission(&config, stored).unwrap_err();
        assert!(err.contains("DAL slot status request failed"));
        let persisted = load_stored_submission(&config.state_dir, "sub-transient").unwrap();
        assert_eq!(persisted.submission.dal_chunks[0].published_level, 201);
        assert_eq!(persisted.submission.published_level, Some(201));
        assert_eq!(persisted.chunk_meta[0].injected_level, None);
        assert_eq!(persisted.chunk_meta[0].scan_cursor, None);
        assert_eq!(persisted.chunk_meta[0].max_operations_ttl, None);
    }

    #[test]
    fn extract_block_hash_requires_operation_found_in_block_anchor() {
        let noisy_output = "Branch: BNoiseBranchHash11111111111111111111111111111111111\nOperation hash is 'ooSomeOp123456789'\n";
        assert_eq!(extract_block_hash(noisy_output), None);

        let anchored_output = format!(
            "{noisy_output}Operation found in block: BKiLedvfcefN4vB5tC9PQZ1D6pA28F1u4B8v7z4D9sE6R3gK1wM (pass: 3, offset: 0)\n"
        );
        assert_eq!(
            extract_block_hash(&anchored_output).as_deref(),
            Some("BKiLedvfcefN4vB5tC9PQZ1D6pA28F1u4B8v7z4D9sE6R3gK1wM")
        );
    }

    #[test]
    fn parse_dal_slot_range_accepts_well_formed_input() {
        let r = parse_dal_slot_range("0..8").unwrap();
        assert_eq!(r, 0..8);
        let r = parse_dal_slot_range("3..7").unwrap();
        assert_eq!(r, 3..7);
        // Whitespace around either side is tolerated.
        let r = parse_dal_slot_range(" 1..4 ").unwrap();
        assert_eq!(r, 1..4);
        // u16::MAX end is accepted; one slot below MAX.
        let r = parse_dal_slot_range("65534..65535").unwrap();
        assert_eq!(r, 65534..65535);
    }

    #[test]
    fn parse_dal_slot_range_rejects_invalid_input() {
        // Empty range (half-open semantics: start must be strictly less).
        let err = parse_dal_slot_range("0..0").unwrap_err();
        assert!(
            err.contains("strictly less"),
            "expected `strictly less` in {err}"
        );
        // Inverted bounds.
        let err = parse_dal_slot_range("8..3").unwrap_err();
        assert!(err.contains("strictly less"));
        // Missing separator.
        let err = parse_dal_slot_range("5").unwrap_err();
        assert!(err.contains("expected START..END"));
        // Non-numeric end.
        let err = parse_dal_slot_range("0..bar").unwrap_err();
        assert!(err.contains("--dal-slot-range end"));
        // Non-numeric start.
        let err = parse_dal_slot_range("foo..5").unwrap_err();
        assert!(err.contains("--dal-slot-range start"));
        // Overflowing u16.
        let err = parse_dal_slot_range("0..65536").unwrap_err();
        assert!(err.contains("--dal-slot-range end"));
        // Empty string.
        let err = parse_dal_slot_range("").unwrap_err();
        assert!(err.contains("expected START..END"));
    }
}
