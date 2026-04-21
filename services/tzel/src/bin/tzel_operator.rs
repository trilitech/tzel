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
    Arc,
};
use std::time::Duration;
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{inbox::ExternalMessageFrame, smart_rollup::SmartRollupAddress};
use tzel_core::{
    auth_leaf_hash, commit, decrypt_memo, derive_auth_pub_seed, derive_kem_keys, derive_rcm,
    detect, hash,
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
    owner_tag, verify_wots_signature_against_leaf, EncryptedNote, PaymentAddress, F,
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
    id_counter: AtomicU64,
    slot_counter: AtomicU64,
}

#[derive(Debug, Clone)]
struct OperatorDalFeePolicy {
    amount: u64,
    incoming_seed: F,
    address_index: u32,
    address: PaymentAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredSubmission {
    submission: RollupSubmission,
    #[serde(default, with = "tzel_core::hex_bytes_opt")]
    payload: Option<Vec<u8>>,
    #[serde(default)]
    chunk_attempts: Vec<u32>,
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ReconcileSummary {
    visited: usize,
    updated: usize,
    errors: usize,
}

const MAX_DAL_CHUNK_ATTEMPTS: u32 = 8;
const MAX_WAITING_ATTESTATION_LEVEL_AGE: i32 = 12;

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
            id_counter: AtomicU64::new(0),
            slot_counter: AtomicU64::new(0),
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
            | (
                RollupSubmissionKind::Withdraw,
                KernelInboxMessage::Withdraw(_)
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
    let expected = commit(&policy.address.d_j, value, &rcm, &otag);
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
        KernelInboxMessage::Shield(req) => {
            let enc = req
                .producer_enc
                .as_ref()
                .ok_or_else(|| "shield DAL fee note is missing producer_enc".to_string())?;
            validate_fee_note_against_policy(policy, &req.producer_cm, enc, req.producer_fee)
        }
        KernelInboxMessage::Transfer(req) => {
            validate_fee_note_against_policy(policy, &req.cm_3, &req.enc_3, policy.amount)
        }
        KernelInboxMessage::Unshield(req) => {
            validate_fee_note_against_policy(policy, &req.cm_fee, &req.enc_fee, policy.amount)
        }
        KernelInboxMessage::ConfigureVerifier(_)
        | KernelInboxMessage::ConfigureBridge(_)
        | KernelInboxMessage::Withdraw(_)
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
        if !matches!(
            stored.submission.status,
            RollupSubmissionStatus::PendingDal
                | RollupSubmissionStatus::CommitmentIncluded
                | RollupSubmissionStatus::Attested
        ) {
            continue;
        }
        summary.visited += 1;
        let original = stored.clone();
        match maybe_advance_submission(config, stored) {
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
    align_chunk_attempts(&mut stored);
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
        chunk_attempts: vec![],
    };

    if targeted_bytes.len() <= config.direct_max_message_bytes {
        match inject_direct_message(config, &targeted_bytes, false) {
            Ok(output) => {
                stored.submission.status = RollupSubmissionStatus::SubmittedToL1;
                stored.submission.transport = RollupSubmissionTransport::DirectInbox;
                stored.submission.operation_hash = extract_operation_hash(&output);
                stored.submission.detail = Some(output);
                persist_submission(config, &stored)?;
                return Ok(stored.submission);
            }
            Err(err) => {
                stored.submission.status = RollupSubmissionStatus::Failed;
                stored.submission.transport = RollupSubmissionTransport::DirectInbox;
                stored.submission.detail = Some(err.clone());
                persist_submission(config, &stored)?;
                return Err(err);
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
    if matches!(req.kind, RollupSubmissionKind::Withdraw) {
        return Err("withdraw submissions do not support DAL publication".into());
    }
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

fn maybe_advance_submission(
    config: &OperatorConfig,
    mut stored: StoredSubmission,
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

    align_chunk_attempts(&mut stored);
    let mut status_lines = Vec::with_capacity(stored.submission.dal_chunks.len());
    let mut retry_indices: Vec<(usize, String)> = Vec::new();
    let mut waiting_indices = Vec::new();
    for (idx, chunk) in stored.submission.dal_chunks.iter().enumerate() {
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

    let mut waiting_for_attestation = false;
    if !waiting_indices.is_empty() {
        if let Some(octez_node_endpoint) = config.octez_node_endpoint.as_deref() {
            match fetch_head_level(octez_node_endpoint) {
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
        let payload = stored
            .payload
            .as_deref()
            .ok_or_else(|| "DAL submission payload is unavailable for retry".to_string())?;
        let mut republished_lines = Vec::with_capacity(retry_indices.len());
        for (idx, reason) in retry_indices {
            let attempts = stored.chunk_attempts.get(idx).copied().unwrap_or(1);
            if attempts >= MAX_DAL_CHUNK_ATTEMPTS {
                stored.submission.status = RollupSubmissionStatus::Failed;
                stored.submission.detail = Some(format!(
                    "DAL attestation failed after {} attempts\n{}",
                    attempts,
                    status_lines.join("\n")
                ));
                return Ok(stored);
            }
            let chunk_bytes = submission_chunk_bytes(payload, &stored.submission, idx)?;
            let published_chunk = publish_dal_chunk(config, chunk_bytes)?;
            republished_lines.push(format!(
                "republished chunk[{idx}] attempt {} -> slot {} level {} ({})",
                attempts + 1,
                published_chunk.slot_index,
                published_chunk.published_level,
                reason
            ));
            stored.submission.dal_chunks[idx] = published_chunk;
            stored.chunk_attempts[idx] = attempts + 1;
        }
        update_submission_commitment_summary(&mut stored.submission)?;
        stored.submission.status = RollupSubmissionStatus::CommitmentIncluded;
        stored.submission.detail = Some(format!(
            "Republished {} DAL chunk(s)\n{}\n{}",
            republished_lines.len(),
            republished_lines.join("\n"),
            status_lines.join("\n")
        ));
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
    // The operator only needs successful injection here; callers can wait for
    // inclusion by tracking the returned operation hash and baking/progressing
    // the chain as needed.
    let output = inject_direct_message(config, &targeted_bytes, false)?;
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
    let payload = stored
        .payload
        .as_deref()
        .ok_or_else(|| "DAL submission payload is unavailable for publication".to_string())?;
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
    if already_published > payload.len() {
        return Err(format!(
            "persisted DAL chunks exceed payload length: {} > {}",
            already_published,
            payload.len()
        ));
    }
    let total_chunks = payload.len().div_ceil(chunk_size);
    for chunk in payload[already_published..].chunks(chunk_size) {
        let published_chunk = publish_dal_chunk_with_protocol(
            config,
            dal_node_endpoint,
            octez_node_endpoint,
            protocol.number_of_slots,
            chunk,
        )?;
        stored.submission.dal_chunks.push(published_chunk);
        stored.chunk_attempts.push(1);
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

fn publish_dal_chunk(config: &OperatorConfig, payload: &[u8]) -> Result<RollupDalChunk, String> {
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

fn publish_dal_chunk_with_protocol(
    config: &OperatorConfig,
    dal_node_endpoint: &str,
    octez_node_endpoint: &str,
    number_of_slots: u64,
    payload: &[u8],
) -> Result<RollupDalChunk, String> {
    let mut last_slot_error = None;
    for _attempt in 0..number_of_slots {
        let slot_index = select_slot_index(config, number_of_slots)?;
        let publish = post_dal_slot(dal_node_endpoint, slot_index, payload)?;
        let output = match publish_dal_commitment(
            config,
            &publish.commitment,
            slot_index,
            &publish.commitment_proof,
        ) {
            Ok(output) => output,
            Err(err) if is_slot_header_collision(&err) => {
                last_slot_error = Some(err);
                continue;
            }
            Err(err) => return Err(err),
        };
        let operation_hash = extract_operation_hash(&output);
        let block_hash = extract_block_hash(&output)
            .ok_or_else(|| format!("missing block hash in dal commitment output: {}", output))?;
        let published_level = fetch_block_level(octez_node_endpoint, &block_hash)?;
        return Ok(RollupDalChunk {
            slot_index,
            published_level,
            payload_len: payload.len(),
            commitment: publish.commitment,
            operation_hash,
        });
    }
    Err(last_slot_error
        .unwrap_or_else(|| "failed to publish DAL chunk: no free slot index available".into()))
}

fn align_chunk_attempts(stored: &mut StoredSubmission) {
    if stored.chunk_attempts.len() < stored.submission.dal_chunks.len() {
        stored
            .chunk_attempts
            .resize(stored.submission.dal_chunks.len(), 1);
    } else if stored.chunk_attempts.len() > stored.submission.dal_chunks.len() {
        stored
            .chunk_attempts
            .truncate(stored.submission.dal_chunks.len());
    }
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
    submission.published_level = Some(first.published_level);
    submission.slot_index = Some(first.slot_index);
    Ok(())
}

fn select_slot_index(config: &OperatorConfig, number_of_slots: u64) -> Result<u16, String> {
    let slot = config.slot_counter.fetch_add(1, Ordering::Relaxed) % number_of_slots;
    u16::try_from(slot).map_err(|_| format!("slot index {} does not fit in u16", slot))
}

fn is_slot_header_collision(err: &str) -> bool {
    err.to_ascii_lowercase().contains("already proposed")
}

fn fetch_dal_protocol_parameters(endpoint: &str) -> Result<DalProtocolParametersResp, String> {
    let url = format!("{}/protocol_parameters", endpoint.trim_end_matches('/'));
    let resp = ureq::get(&url)
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
    let resp = ureq::post(&url)
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
) -> Result<String, String> {
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
    run_command_collect_output(command, &config.octez_client_bin)
}

fn fetch_block_level(endpoint: &str, block_hash: &str) -> Result<i32, String> {
    let url = format!(
        "{}/chains/main/blocks/{}/header",
        endpoint.trim_end_matches('/'),
        block_hash
    );
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("block header request failed: {}", e))?;
    let header: BlockHeaderResp = resp
        .into_body()
        .read_json()
        .map_err(|e| format!("parse block header: {}", e))?;
    Ok(header.level)
}

fn fetch_head_level(endpoint: &str) -> Result<i32, String> {
    let url = format!(
        "{}/chains/main/blocks/head/header",
        endpoint.trim_end_matches('/')
    );
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("block head header request failed: {}", e))?;
    let header: BlockHeaderResp = resp
        .into_body()
        .read_json()
        .map_err(|e| format!("parse block head header: {}", e))?;
    Ok(header.level)
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
    let resp = match ureq::get(&url).call() {
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
        RollupSubmissionKind::Withdraw => {
            return Err("withdraw submissions do not support DAL pointers".into())
        }
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
                Ok(KernelDalChunkPointer {
                    published_level: u64::try_from(chunk.published_level)
                        .map_err(|_| "published_level must be non-negative".to_string())?,
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
) -> Result<String, String> {
    let payload_file = write_temp_payload(bytes)?;
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

    let result = run_command_collect_output(command, &config.octez_client_bin);
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

fn run_command_collect_output(
    mut command: std::process::Command,
    program_name: &str,
) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|e| format!("failed to start {}: {}", program_name, e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let combined = match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{}\n{}", stdout, stderr),
    };
    if !output.status.success() {
        return Err(if combined.is_empty() {
            format!("{} exited with status {}", program_name, output.status)
        } else {
            combined
        });
    }
    Ok(combined)
}

fn extract_operation_hash(output: &str) -> Option<String> {
    extract_token_with_prefix(output, 'o')
}

fn extract_block_hash(output: &str) -> Option<String> {
    extract_token_with_prefix(output, 'B')
}

fn extract_token_with_prefix(output: &str, prefix: char) -> Option<String> {
    output
        .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';' | '(' | ')'))
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
    align_chunk_attempts(&mut stored);
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
            id_counter: AtomicU64::new(0),
            slot_counter: AtomicU64::new(0),
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
        let cm = commit(&policy.address.d_j, policy.amount, &rcm, &otag);
        (enc, cm)
    }

    fn sample_shield_payload_with_producer_note(
        producer_fee: u64,
        producer_cm: F,
        producer_enc: EncryptedNote,
    ) -> Vec<u8> {
        let policy = sample_fee_policy();
        encode_kernel_inbox_message(&KernelInboxMessage::Shield(
            tzel_core::kernel_wire::KernelShieldReq {
                deposit_id: tzel_core::deposit_id_from_label("alice"),
                fee: 100_000,
                v: 25,
                producer_fee,
                address: policy.address,
                memo: None,
                proof: tzel_core::kernel_wire::KernelStarkProof {
                    proof_bytes: vec![],
                    output_preimage: vec![],
                    verify_meta: vec![],
                },
                client_cm: [0u8; 32],
                client_enc: None,
                producer_cm,
                producer_enc: Some(producer_enc),
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

    fn sample_withdraw_payload() -> Vec<u8> {
        encode_kernel_inbox_message(&KernelInboxMessage::Withdraw(
            tzel_core::kernel_wire::KernelWithdrawReq {
                sender: "alice".into(),
                recipient: "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx".into(),
                amount: 1,
            },
        ))
        .unwrap()
    }

    #[test]
    fn direct_l1_withdraw_message_fits_protocol_limit() {
        let framed = encode_targeted_rollup_message(
            "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP",
            &sample_withdraw_payload(),
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
            kind: RollupSubmissionKind::Withdraw,
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
        StoredSubmission {
            submission,
            payload,
            chunk_attempts: chunk_attempts.to_vec(),
        }
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
    fn oversized_withdraw_submission_is_rejected_before_dal_publication() {
        let script_dir = make_client_script("#!/bin/sh\necho 'should not publish'\n");
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        config.direct_max_message_bytes = 1;
        config.dal_node_endpoint = Some("http://dal.invalid".into());

        let err = process_submission(
            &config,
            SubmitRollupMessageReq {
                kind: RollupSubmissionKind::Withdraw,
                rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                payload: sample_withdraw_payload(),
            },
        )
        .unwrap_err();

        assert!(err.contains("withdraw submissions do not support DAL publication"));
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
            kind: RollupSubmissionKind::Withdraw,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: vec![1, 2, 3, 4],
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
        assert_eq!(advanced.chunk_attempts, vec![2]);
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
        assert_eq!(advanced.chunk_attempts, vec![1, 2, 1]);
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
        assert_eq!(advanced.chunk_attempts, vec![2]);
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
        assert_eq!(advanced.chunk_attempts, vec![1, 1]);
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
}
