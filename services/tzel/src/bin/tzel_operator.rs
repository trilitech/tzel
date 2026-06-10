use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{inbox::ExternalMessageFrame, smart_rollup::SmartRollupAddress};
use tzel_core::{
    hash,
    kernel_wire::encode_kernel_inbox_message,
    operator_api::{
        RollupSubmission, RollupSubmissionKind, RollupSubmissionStatus, RollupSubmissionTransport,
        SubmitRollupMessageReq, SubmitRollupMessageResp,
    },
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
    #[arg(long, default_value = "octez-client")]
    octez_client_bin: String,
    #[arg(long)]
    octez_client_dir: Option<String>,
    #[arg(long)]
    octez_node_endpoint: Option<String>,
    #[arg(long)]
    octez_protocol: Option<String>,
    #[arg(long)]
    bearer_token: Option<String>,
    #[arg(long)]
    bearer_token_file: Option<String>,
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
    octez_client_bin: String,
    octez_client_dir: Option<String>,
    octez_node_endpoint: Option<String>,
    octez_protocol: Option<String>,
    id_counter: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredSubmission {
    submission: RollupSubmission,
    #[serde(default, with = "tzel_core::hex_bytes_opt")]
    payload: Option<Vec<u8>>,
}

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
    let state_dir = PathBuf::from(&cli.state_dir);
    std::fs::create_dir_all(submissions_dir(&state_dir))
        .map_err(|e| format!("create state dir: {}", e))?;

    let state = AppState {
        config: Arc::new(OperatorConfig {
            source_alias: cli.source_alias,
            bearer_token,
            state_dir,
            direct_max_message_bytes: cli.direct_max_message_bytes,
            octez_client_bin: cli.octez_client_bin,
            octez_client_dir: cli.octez_client_dir,
            octez_node_endpoint: cli.octez_node_endpoint,
            octez_protocol: cli.octez_protocol,
            id_counter: AtomicU64::new(0),
        }),
        advance_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

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

fn load_stored_submission(state_dir: &Path, id: &str) -> Result<StoredSubmission, String> {
    let path = submission_path(state_dir, id);
    let body =
        std::fs::read_to_string(&path).map_err(|e| format!("read submission {}: {}", id, e))?;
    let stored: StoredSubmission =
        serde_json::from_str(&body).map_err(|e| format!("parse submission {}: {}", id, e))?;
    Ok(stored)
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
            status: RollupSubmissionStatus::Failed,
            transport: RollupSubmissionTransport::DirectInbox,
            operation_hash: None,
            payload_hash: Some(hex::encode(hash(&req.payload))),
            payload_len: req.payload.len(),
            detail: None,
        },
        payload: Some(req.payload.clone()),
    };

    if targeted_bytes.len() > config.direct_max_message_bytes {
        // The DAL transport was deleted together with the v17 DAL-pointer
        // wire path (docs/SNARK-SUBMISSION-DESIGN.md, "What gets deleted").
        // Oversized payloads now take the v18 staged submission pipeline.
        //
        // Signed config (ConfigureVerifier/ConfigureBridge) envelopes exceed
        // 4096 bytes; the operator stages them in chunks then references the
        // sealed entry with SubmitStagedConfig (Deliverable B / gap #1).
        //
        // Oversized OP payloads (Shield/Transfer/Unshield) are NOT handled
        // here: the wallet produces the v18 message sequence (per-note
        // StageChunk + a SubmitOps that each fit one inbox message) and
        // submits them individually through this same direct path, because
        // building the aggregation-tree binding requires the bootloader
        // output preimages + the gnark wrap proof, which the operator does
        // not have (it only sees an opaque pre-encoded payload).
        match req.kind {
            RollupSubmissionKind::ConfigureVerifier | RollupSubmissionKind::ConfigureBridge => {
                return process_staged_config_submission(config, &req, stored);
            }
            _ => {
                stored.submission.detail = Some(format!(
                    "message is {} bytes after framing, above direct inbox limit {}; \
                     oversized op payloads must be produced as a v18 StageChunk + \
                     SubmitOps sequence by the wallet (each message fits the inbox \
                     cap) — the operator only stages oversized signed config",
                    targeted_bytes.len(),
                    config.direct_max_message_bytes
                ));
                persist_submission(config, &stored)?;
                return Ok(stored.submission);
            }
        }
    }

    match inject_direct_message(config, &targeted_bytes, false) {
        Ok(output) => {
            stored.submission.status = RollupSubmissionStatus::SubmittedToL1;
            stored.submission.operation_hash = extract_operation_hash(&output);
            stored.submission.detail = Some(output);
            persist_submission(config, &stored)?;
            Ok(stored.submission)
        }
        Err(err) => {
            stored.submission.detail = Some(err.clone());
            persist_submission(config, &stored)?;
            Err(err)
        }
    }
}

/// Stage an oversized signed config envelope (the `req.payload`, which is a
/// full `ConfigureVerifier`/`ConfigureBridge` inbox message) across
/// `StageChunk`s, then submit a `SubmitStagedConfig` referencing the sealed
/// entry (`docs/SNARK-SUBMISSION-DESIGN.md`, gap #1 / Deliverable B). Each
/// produced message fits the inbox cap; they are injected in order so the
/// staging entry is sealed by the time `SubmitStagedConfig` lands.
///
/// The `staging_id` is derived from the submission counter so concurrent
/// config submissions from this operator do not collide in the kernel's
/// `(sender, staging_id)` namespace.
fn process_staged_config_submission(
    config: &OperatorConfig,
    req: &SubmitRollupMessageReq,
    mut stored: StoredSubmission,
) -> Result<RollupSubmission, String> {
    let staging_id = config.id_counter.fetch_add(1, Ordering::Relaxed);
    let messages = tzel_services::submit_v18::build_staged_config_submission(
        staging_id,
        &req.payload,
    )
    .map_err(|e| format!("failed to build staged config submission: {}", e))?;

    let mut hashes: Vec<String> = Vec::with_capacity(messages.len());
    for (index, message) in messages.iter().enumerate() {
        let encoded = encode_kernel_inbox_message(message)
            .map_err(|e| format!("failed to encode staged config message {}: {}", index, e))?;
        let framed = encode_targeted_rollup_message(&req.rollup_address, &encoded)?;
        if framed.len() > config.direct_max_message_bytes {
            let detail = format!(
                "staged config message {} is {} bytes after framing, above inbox limit {}",
                index,
                framed.len(),
                config.direct_max_message_bytes
            );
            stored.submission.detail = Some(detail.clone());
            persist_submission(config, &stored)?;
            return Err(detail);
        }
        match inject_direct_message(config, &framed, false) {
            Ok(output) => {
                if let Some(h) = extract_operation_hash(&output) {
                    hashes.push(h);
                }
            }
            Err(err) => {
                stored.submission.detail = Some(format!(
                    "staged config message {} of {} injection failed: {}",
                    index,
                    messages.len(),
                    err
                ));
                persist_submission(config, &stored)?;
                return Err(err);
            }
        }
    }

    stored.submission.status = RollupSubmissionStatus::SubmittedToL1;
    // The terminal SubmitStagedConfig op hash is the meaningful receipt.
    stored.submission.operation_hash = hashes.last().cloned();
    stored.submission.detail = Some(format!(
        "staged signed config across {} StageChunk message(s) + 1 SubmitStagedConfig \
         (staging_id {})",
        messages.len().saturating_sub(1),
        staging_id
    ));
    persist_submission(config, &stored)?;
    Ok(stored.submission)
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
    use tzel_core::kernel_wire::{
        encode_kernel_inbox_message, sign_kernel_bridge_config, sign_kernel_verifier_config,
        KernelBridgeConfig, KernelInboxMessage, KernelVerifierConfig,
    };
    use tzel_core::operator_api::RollupSubmissionKind;
    use tzel_core::{hash, ProgramHashes, F};

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
            octez_client_bin: script.display().to_string(),
            octez_client_dir: None,
            octez_node_endpoint: Some("http://octez-node.invalid".into()),
            octez_protocol: None,
            id_counter: AtomicU64::new(0),
        }
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
    ) -> StoredSubmission {
        StoredSubmission { submission, payload }
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

    #[test]
    fn oversized_op_message_fails_cleanly() {
        // Oversized OP payloads (Shield/Transfer/Unshield) are not staged by
        // the operator — the wallet must produce the v18 message sequence.
        let script_dir = make_client_script("#!/bin/sh\necho 'should not inject'\n");
        let config = config_with_client(&script_dir.path().join("octez-client"));
        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: vec![7u8; 5000],
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(submission.status, RollupSubmissionStatus::Failed);
        assert_eq!(submission.transport, RollupSubmissionTransport::DirectInbox);
        assert!(submission.operation_hash.is_none());
        let detail = submission.detail.as_deref().unwrap();
        assert!(detail.contains("above direct inbox limit"));
        assert!(detail.contains("StageChunk"));
        assert!(detail.contains("SubmitOps"));
    }

    #[test]
    fn oversized_config_is_staged_and_submitted() {
        // A >4KiB signed config envelope is staged across StageChunk messages
        // then applied via SubmitStagedConfig — each injection succeeds.
        let script_dir = make_client_script(
            "#!/bin/sh\necho 'Operation hash is ooStagedConfigHash123456789'\n",
        );
        let mut config = config_with_client(&script_dir.path().join("octez-client"));
        // The real L1 inbox cap — large enough to frame a full StageChunk
        // (~3.9 KiB payload) but smaller than the whole config envelope, so
        // the config is forced down the staged path while each chunk fits.
        config.direct_max_message_bytes = DEFAULT_DIRECT_MAX_MESSAGE_BYTES;
        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::ConfigureVerifier,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: sample_configure_verifier_payload(),
        };
        // Sanity: the config envelope really is oversized (would not fit
        // one framed inbox message), so it takes the staged path.
        let framed = encode_targeted_rollup_message(&req.rollup_address, &req.payload).unwrap();
        assert!(framed.len() > config.direct_max_message_bytes);

        let submission = process_submission(&config, req).unwrap();
        assert_eq!(submission.status, RollupSubmissionStatus::SubmittedToL1);
        assert_eq!(submission.transport, RollupSubmissionTransport::DirectInbox);
        assert_eq!(
            submission.operation_hash.as_deref(),
            Some("ooStagedConfigHash123456789")
        );
        let detail = submission.detail.as_deref().unwrap();
        assert!(detail.contains("staged signed config"));
        assert!(detail.contains("SubmitStagedConfig"));
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
    fn submitted_to_l1_prunes_payload_from_disk() {
        let config = config_with_client(Path::new("/bin/true"));
        let submission = RollupSubmission {
            id: "sub-prune".into(),
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::SubmittedToL1,
            transport: RollupSubmissionTransport::DirectInbox,
            operation_hash: Some("ooPointerHash123456789ABCDEFG".into()),
            payload_hash: Some(hex::encode([0x44; 32])),
            payload_len: 4,
            detail: None,
        };
        persist_submission(&config, &stored_submission(submission, Some(vec![1, 2, 3, 4])))
            .unwrap();
        let stored = load_stored_submission(&config.state_dir, "sub-prune").unwrap();
        assert!(stored.payload.is_none());
    }
}
