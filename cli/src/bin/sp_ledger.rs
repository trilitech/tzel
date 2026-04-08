use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use starkprivacy_cli::*;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

struct LedgerState {
    ledger: Mutex<Ledger>,
    allow_trust_me_bro: bool,
    reprove_bin: Option<String>,
}

type AppState = Arc<LedgerState>;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// DANGEROUS: accept TrustMeBro proofs (no STARK verification).
    /// Only for local development/testing.
    #[arg(long)]
    trust_me_bro: bool,

    /// Path to the reprove binary for STARK proof verification.
    /// When set, the ledger re-proves transactions to verify them.
    #[arg(long)]
    reprove_bin: Option<String>,
    /// Optional big-endian felt252 domain binding for spend authorizations.
    /// Production deployments should set a unique value.
    #[arg(long)]
    auth_domain: Option<String>,
}

fn err(s: String) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, s)
}

fn parse_felt_be_hex(s: &str) -> Result<F, String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.is_empty() {
        return Err("empty auth_domain".into());
    }
    let raw = hex::decode(hex).map_err(|_| "auth_domain must be hex".to_string())?;
    if raw.len() > 32 {
        return Err("auth_domain must fit in 32 bytes".into());
    }
    let mut be = [0u8; 32];
    be[32 - raw.len()..].copy_from_slice(&raw);
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    if le[31] & 0xF8 != 0 {
        return Err("auth_domain exceeds 251 bits".into());
    }
    Ok(le)
}

fn check_proof(
    proof: &Proof,
    allow_trust_me_bro: bool,
    has_verifier: bool,
) -> Result<(), (StatusCode, String)> {
    match proof {
        Proof::TrustMeBro => {
            if !allow_trust_me_bro {
                return Err(err("TrustMeBro proofs rejected. Ledger requires real STARK proofs. (Start ledger with --trust-me-bro to allow.)".into()));
            }
            eprintln!("  WARNING: accepting TrustMeBro proof — NO cryptographic verification");
            Ok(())
        }
        Proof::Stark {
            proof_hex,
            output_preimage,
            verify_meta: _,
        } => {
            if !has_verifier {
                return Err(err(
                    "Stark proofs rejected: ledger is not configured with --reprove-bin. \
                     Start the ledger with --reprove-bin for verified proofs or use --trust-me-bro for development."
                        .into(),
                ));
            }
            let proof_bytes = hex::decode(proof_hex).map_err(|_| err("bad proof hex".into()))?;
            if proof_bytes.is_empty() {
                return Err(err("empty proof".into()));
            }
            if output_preimage.is_empty() {
                return Err(err("empty output_preimage".into()));
            }
            eprintln!(
                "  Stark proof received ({} bytes, {} public outputs)",
                proof_bytes.len(),
                output_preimage.len()
            );
            // Output_preimage is validated positionally by the calling handler.
            Ok(())
        }
    }
}

/// Verify a STARK proof cryptographically by shelling out to the reprover.
/// The reprover deserializes the circuit proof, reconstructs the verification
/// context from the stored metadata, and runs verify_circuit (~50ms).
/// The reprover internally verifies; if it succeeds and produces matching output_preimage,
/// the proof is valid.
fn verify_stark_proof(reprove_bin: &str, proof: &Proof) -> Result<(), String> {
    let Proof::Stark {
        proof_hex,
        output_preimage,
        verify_meta,
    } = proof
    else {
        return Ok(());
    };

    if verify_meta.is_none() {
        return Err("Stark proof missing verify_meta — cannot verify".into());
    }

    // Write the proof bundle to a temp file for the reprover to verify
    let bundle_file = tempfile::NamedTempFile::new().map_err(|e| format!("tempfile: {}", e))?;
    let bundle = serde_json::json!({
        "proof_hex": proof_hex,
        "output_preimage": output_preimage,
        "verify_meta": verify_meta,
    });
    std::fs::write(bundle_file.path(), serde_json::to_string(&bundle).unwrap())
        .map_err(|e| format!("write bundle: {}", e))?;

    eprintln!("  Verifying STARK proof via reprover...");
    let output = std::process::Command::new(reprove_bin)
        .arg("dummy") // executable arg required by clap but not used for --verify
        .arg("--verify")
        .arg(bundle_file.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("reprove failed to start: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "STARK proof verification FAILED: {}",
            stderr.trim()
        ));
    }

    eprintln!("  STARK proof verified ✓ (~50ms)");
    Ok(())
}

async fn fund_handler(
    State(st): State<AppState>,
    Json(req): Json<FundReq>,
) -> Json<serde_json::Value> {
    let mut ledger = st.ledger.lock().unwrap();
    ledger.fund(&req.addr, req.amount);
    eprintln!("[fund] {} += {}", req.addr, req.amount);
    Json(serde_json::json!({"ok": true}))
}

async fn shield_handler(
    State(st): State<AppState>,
    Json(req): Json<ShieldReq>,
) -> Result<Json<ShieldResp>, (StatusCode, String)> {
    check_proof(&req.proof, st.allow_trust_me_bro, st.reprove_bin.is_some())?;
    if let Some(ref bin) = st.reprove_bin {
        verify_stark_proof(bin, &req.proof).map_err(err)?;
    }
    let mut ledger = st.ledger.lock().unwrap();
    let resp = ledger.shield(&req).map_err(err)?;
    eprintln!(
        "[shield] {} deposited {} -> cm={} idx={}",
        req.sender,
        req.v,
        short(&resp.cm),
        resp.index
    );
    Ok(Json(resp))
}

async fn transfer_handler(
    State(st): State<AppState>,
    Json(req): Json<TransferReq>,
) -> Result<Json<TransferResp>, (StatusCode, String)> {
    check_proof(&req.proof, st.allow_trust_me_bro, st.reprove_bin.is_some())?;
    if let Some(ref bin) = st.reprove_bin {
        verify_stark_proof(bin, &req.proof).map_err(err)?;
    }
    let mut ledger = st.ledger.lock().unwrap();
    let n = req.nullifiers.len();
    let resp = ledger.transfer(&req).map_err(err)?;
    eprintln!(
        "[transfer] N={} -> idx={},{} (cm1={} cm2={})",
        n,
        resp.index_1,
        resp.index_2,
        short(&req.cm_1),
        short(&req.cm_2)
    );
    Ok(Json(resp))
}

async fn unshield_handler(
    State(st): State<AppState>,
    Json(req): Json<UnshieldReq>,
) -> Result<Json<UnshieldResp>, (StatusCode, String)> {
    check_proof(&req.proof, st.allow_trust_me_bro, st.reprove_bin.is_some())?;
    if let Some(ref bin) = st.reprove_bin {
        verify_stark_proof(bin, &req.proof).map_err(err)?;
    }
    let mut ledger = st.ledger.lock().unwrap();
    let n = req.nullifiers.len();
    let resp = ledger.unshield(&req).map_err(err)?;
    eprintln!(
        "[unshield] N={} -> {} to {} (change idx={:?})",
        n, req.v_pub, req.recipient, resp.change_index
    );
    Ok(Json(resp))
}

#[derive(serde::Deserialize)]
struct CursorParam {
    cursor: Option<usize>,
}

async fn notes_handler(
    State(st): State<AppState>,
    Query(params): Query<CursorParam>,
) -> Json<NotesFeedResp> {
    let ledger = st.ledger.lock().unwrap();
    let cursor = params.cursor.unwrap_or(0);
    let notes: Vec<NoteMemo> = ledger
        .memos
        .iter()
        .enumerate()
        .skip(cursor)
        .map(|(i, (cm, enc))| NoteMemo {
            index: i,
            cm: *cm,
            enc: enc.clone(),
        })
        .collect();
    let next_cursor = ledger.memos.len();
    Json(NotesFeedResp { notes, next_cursor })
}

async fn tree_handler(State(st): State<AppState>) -> Json<TreeInfoResp> {
    let ledger = st.ledger.lock().unwrap();
    Json(TreeInfoResp {
        root: ledger.tree.root(),
        size: ledger.tree.leaves.len(),
        depth: DEPTH,
    })
}

async fn tree_path_handler(
    State(st): State<AppState>,
    axum::extract::Path(index): axum::extract::Path<usize>,
) -> Result<Json<MerklePathResp>, (StatusCode, String)> {
    let ledger = st.ledger.lock().unwrap();
    if index >= ledger.tree.leaves.len() {
        return Err(err(format!(
            "index {} out of range (tree has {} leaves)",
            index,
            ledger.tree.leaves.len()
        )));
    }
    let (siblings, root) = ledger.tree.auth_path(index);
    Ok(Json(MerklePathResp { siblings, root }))
}

async fn nullifiers_handler(State(st): State<AppState>) -> Json<NullifiersResp> {
    let ledger = st.ledger.lock().unwrap();
    Json(NullifiersResp {
        nullifiers: ledger.nullifiers.iter().cloned().collect(),
    })
}

async fn balances_handler(State(st): State<AppState>) -> Json<BalanceResp> {
    let ledger = st.ledger.lock().unwrap();
    Json(BalanceResp {
        balances: ledger.balances.clone(),
    })
}

async fn config_handler(State(st): State<AppState>) -> Json<ConfigResp> {
    let ledger = st.ledger.lock().unwrap();
    Json(ConfigResp {
        auth_domain: ledger.auth_domain,
    })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let auth_domain = match cli.auth_domain.as_deref() {
        Some(s) => match parse_felt_be_hex(s) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ERROR: invalid --auth-domain: {}", e);
                std::process::exit(2);
            }
        },
        None => default_auth_domain(),
    };
    if !cli.trust_me_bro && cli.reprove_bin.is_none() {
        eprintln!(
            "ERROR: refusing to start without proof verification. \
             Pass --reprove-bin for verified Stark proofs or --trust-me-bro for development."
        );
        std::process::exit(2);
    }
    if cli.trust_me_bro {
        eprintln!("WARNING: --trust-me-bro is enabled. TrustMeBro proofs will be accepted.");
        eprintln!(
            "WARNING: Transactions have NO cryptographic verification. DO NOT use in production."
        );
    }
    if cli.reprove_bin.is_some() {
        eprintln!("STARK proof verification enabled (re-proving via reprover).");
    }
    let state: AppState = Arc::new(LedgerState {
        ledger: Mutex::new(Ledger::with_auth_domain(auth_domain)),
        allow_trust_me_bro: cli.trust_me_bro,
        reprove_bin: cli.reprove_bin,
    });

    let app = Router::new()
        .route("/config", get(config_handler))
        .route("/fund", post(fund_handler))
        .route("/shield", post(shield_handler))
        .route("/transfer", post(transfer_handler))
        .route("/unshield", post(unshield_handler))
        .route("/notes", get(notes_handler))
        .route("/tree", get(tree_handler))
        .route("/tree/path/{index}", get(tree_path_handler))
        .route("/nullifiers", get(nullifiers_handler))
        .route("/balances", get(balances_handler))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cli.port);
    eprintln!("sp-ledger listening on {}", addr);
    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
