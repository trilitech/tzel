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
    proof_verifier: LedgerProofVerifier,
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

    /// Directory containing the compiled Cairo executables used by verified proofs.
    #[arg(long, default_value = "target/dev")]
    executables_dir: String,

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

async fn fund_handler(
    State(st): State<AppState>,
    Json(req): Json<FundReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut ledger = st.ledger.lock().unwrap();
    ledger.fund(&req.addr, req.amount).map_err(err)?;
    eprintln!("[fund] {} += {}", req.addr, req.amount);
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn shield_handler(
    State(st): State<AppState>,
    Json(req): Json<ShieldReq>,
) -> Result<Json<ShieldResp>, (StatusCode, String)> {
    st.proof_verifier
        .validate(&req.proof, CircuitKind::Shield)
        .map_err(err)?;
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
    st.proof_verifier
        .validate(&req.proof, CircuitKind::Transfer)
        .map_err(err)?;
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
    st.proof_verifier
        .validate(&req.proof, CircuitKind::Unshield)
        .map_err(err)?;
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
    let proof_verifier = match cli.reprove_bin {
        Some(reprove_bin) => match LedgerProofVerifier::from_reprove_bin(
            cli.trust_me_bro,
            reprove_bin,
            &cli.executables_dir,
        ) {
            Ok(verifier) => verifier,
            Err(e) => {
                eprintln!("ERROR: {}", e);
                std::process::exit(2);
            }
        },
        None => LedgerProofVerifier::trust_me_bro_only(),
    };
    let state: AppState = Arc::new(LedgerState {
        ledger: Mutex::new(Ledger::with_auth_domain(auth_domain)),
        proof_verifier,
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
