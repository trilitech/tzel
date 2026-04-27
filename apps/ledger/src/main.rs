use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tzel_services::*;
use tzel_services::LedgerState as _;

struct LedgerState {
    ledger: Mutex<Ledger>,
    proof_verifier: LedgerProofVerifier,
}

type AppState = Arc<LedgerState>;

#[derive(Parser)]
struct Cli {
    /// Interface to bind sp-ledger to. Defaults to loopback because /deposit
    /// is demo-only.
    #[arg(long, default_value = "127.0.0.1")]
    listen: String,

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
    #[arg(long, default_value = "cairo/target/dev")]
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

async fn deposit_handler(
    State(st): State<AppState>,
    Json(req): Json<DepositReq>,
) -> Result<Json<DepositResp>, (StatusCode, String)> {
    let mut ledger = st.ledger.lock().unwrap();
    ledger.deposit(&req.recipient, req.amount).map_err(err)?;
    let pubkey_hash = parse_deposit_recipient_pubkey_hash(&req.recipient).map_err(err)?;
    let balance = ledger
        .deposit_balance(&pubkey_hash)
        .map_err(err)?
        .unwrap_or(0);
    eprintln!(
        "[deposit] {} += {} (pool balance now {})",
        req.recipient, req.amount, balance
    );
    Ok(Json(DepositResp { balance }))
}

async fn balance_handler(
    State(st): State<AppState>,
    Query(params): Query<BalanceByPubkeyHashParam>,
) -> Result<Json<DepositBalanceResp>, (StatusCode, String)> {
    let pubkey_hash = parse_pubkey_hash_hex(&params.pubkey_hash).map_err(err)?;
    let ledger = st.ledger.lock().unwrap();
    let balance = ledger
        .deposit_balance(&pubkey_hash)
        .map_err(err)?
        .unwrap_or(0);
    Ok(Json(DepositBalanceResp { balance }))
}

#[derive(serde::Deserialize)]
struct BalanceByPubkeyHashParam {
    pubkey_hash: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DepositBalanceResp {
    pub balance: u64,
}

fn parse_pubkey_hash_hex(s: &str) -> Result<F, String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 64 {
        return Err("pubkey_hash must be 32-byte hex".into());
    }
    let raw = hex::decode(hex).map_err(|_| "pubkey_hash must be hex".to_string())?;
    let mut pubkey_hash = ZERO;
    pubkey_hash.copy_from_slice(&raw);
    Ok(pubkey_hash)
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
        "[shield] pool {} shielded {} -> cm={} idx={}",
        deposit_recipient_string(&req.pubkey_hash),
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
    let recipient = validate_l1_withdrawal_recipient(&req.recipient).map_err(err)?;
    let mut req = req;
    req.recipient = recipient;
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


async fn config_handler(State(st): State<AppState>) -> Json<ConfigResp> {
    let ledger = st.ledger.lock().unwrap();
    Json(ConfigResp {
        auth_domain: ledger.auth_domain,
        required_tx_fee: MIN_TX_FEE,
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
        .route("/deposit", post(deposit_handler))
        .route("/deposits/balance", get(balance_handler))
        .route("/shield", post(shield_handler))
        .route("/transfer", post(transfer_handler))
        .route("/unshield", post(unshield_handler))
        .route("/notes", get(notes_handler))
        .route("/tree", get(tree_handler))
        .route("/tree/path/{index}", get(tree_path_handler))
        .route("/nullifiers", get(nullifiers_handler))
        .with_state(state);

    let addr = format!("{}:{}", cli.listen, cli.port);
    if !matches!(cli.listen.as_str(), "127.0.0.1" | "::1" | "localhost") {
        eprintln!(
            "WARNING: sp-ledger is binding to a non-loopback interface ({}). \
             The /deposit endpoint is demo-only and unauthenticated.",
            cli.listen
        );
    }
    eprintln!("sp-ledger listening on {}", addr);
    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tzel_services::MIN_TX_FEE;

    fn test_state(auth_domain: F) -> AppState {
        Arc::new(LedgerState {
            ledger: Mutex::new(Ledger::with_auth_domain(auth_domain)),
            proof_verifier: LedgerProofVerifier::trust_me_bro_only(),
        })
    }

    fn rejecting_tmb_state(auth_domain: F) -> AppState {
        Arc::new(LedgerState {
            ledger: Mutex::new(Ledger::with_auth_domain(auth_domain)),
            proof_verifier: LedgerProofVerifier::verified(
                false,
                "unused-reprove-bin".into(),
                ProgramHashes {
                    shield: ZERO,
                    transfer: ZERO,
                    unshield: ZERO,
                },
            ),
        })
    }

    fn dummy_payment_address(tag: u16) -> PaymentAddress {
        PaymentAddress {
            d_j: u64_to_felt(0x1000 + tag as u64),
            auth_root: u64_to_felt(0x2000 + tag as u64),
            auth_pub_seed: u64_to_felt(0x3000 + tag as u64),
            nk_tag: u64_to_felt(0x4000 + tag as u64),
            ek_v: vec![0x11; tzel_services::canonical_wire::ML_KEM768_ENCAPSULATION_KEY_BYTES],
            ek_d: vec![0x22; tzel_services::canonical_wire::ML_KEM768_ENCAPSULATION_KEY_BYTES],
        }
    }

    fn dummy_note(tag: u16) -> EncryptedNote {
        EncryptedNote {
            ct_d: vec![0xA5; ML_KEM768_CIPHERTEXT_BYTES],
            tag,
            ct_v: vec![0x5A; ML_KEM768_CIPHERTEXT_BYTES],
            nonce: vec![0x33; NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![0x11; ENCRYPTED_NOTE_BYTES],
            outgoing_ct: empty_outgoing_recovery_ct(),
        }
    }

    #[test]
    fn test_parse_felt_be_hex_accepts_plain_and_prefixed_forms() {
        let plain = parse_felt_be_hex("2a").expect("plain hex should parse");
        let prefixed = parse_felt_be_hex("0x2a").expect("prefixed hex should parse");
        assert_eq!(plain, prefixed);
        assert_eq!(plain[0], 0x2a);
        assert!(plain[1..].iter().all(|b| *b == 0));
    }

    #[test]
    fn test_parse_felt_be_hex_rejects_invalid_inputs() {
        assert!(parse_felt_be_hex("")
            .unwrap_err()
            .contains("empty auth_domain"));
        assert!(parse_felt_be_hex("zz").unwrap_err().contains("must be hex"));
        assert!(parse_felt_be_hex(&"11".repeat(33))
            .unwrap_err()
            .contains("fit in 32 bytes"));

        let mut oversized = [0u8; 32];
        oversized[0] = 0x08;
        let oversized_hex = hex::encode(oversized);
        assert!(parse_felt_be_hex(&oversized_hex)
            .unwrap_err()
            .contains("exceeds 251 bits"));
    }

    #[tokio::test]
    async fn test_deposit_handler_aggregates_balance_across_multiple_l1_tickets() {
        let st = test_state(default_auth_domain());
        let pubkey_hash = u64_to_felt(0xAB);
        let recipient = deposit_recipient_string(&pubkey_hash);

        let Json(first) = deposit_handler(
            State(st.clone()),
            Json(DepositReq {
                recipient: recipient.clone(),
                amount: 5101,
            }),
        )
        .await
        .expect("first deposit credits the pool");
        assert_eq!(first.balance, 5101);

        // Second deposit (same recipient → top-up; balance aggregates).
        let Json(second) = deposit_handler(
            State(st.clone()),
            Json(DepositReq {
                recipient: recipient.clone(),
                amount: 1,
            }),
        )
        .await
        .expect("top-up deposit");
        assert_eq!(second.balance, 5102);

        // Balance query returns the same total.
        let Json(balance) = balance_handler(
            State(st.clone()),
            Query(BalanceByPubkeyHashParam {
                pubkey_hash: hex::encode(pubkey_hash),
            }),
        )
        .await
        .expect("balance query");
        assert_eq!(balance.balance, 5102);
    }

    #[tokio::test]
    async fn test_deposit_handler_rejects_non_deposit_recipient() {
        let st = test_state(default_auth_domain());
        let err = deposit_handler(
            State(st.clone()),
            Json(DepositReq {
                recipient: "alice".into(),
                amount: 55,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("deposit recipient"));
    }

    #[test]
    fn test_cli_defaults_to_loopback_listen_address() {
        let cli = Cli::parse_from(["sp-ledger"]);
        assert_eq!(cli.listen, "127.0.0.1");
        assert_eq!(cli.port, 8080);
    }

    #[test]
    fn test_cli_accepts_custom_listen_address() {
        let cli = Cli::parse_from(["sp-ledger", "--listen", "0.0.0.0", "--port", "9090"]);
        assert_eq!(cli.listen, "0.0.0.0");
        assert_eq!(cli.port, 9090);
    }

    #[tokio::test]
    async fn test_tree_and_config_handlers_reflect_state() {
        let auth_domain = u64_to_felt(0x44);
        let st = test_state(auth_domain);
        {
            let mut ledger = st.ledger.lock().unwrap();
            ledger.tree.append(u64_to_felt(7));
            ledger.tree.append(u64_to_felt(9));
        }

        let Json(config) = config_handler(State(st.clone())).await;
        assert_eq!(config.auth_domain, auth_domain);
        assert_eq!(config.required_tx_fee, MIN_TX_FEE);

        let Json(tree) = tree_handler(State(st.clone())).await;
        assert_eq!(tree.size, 2);
        assert_eq!(tree.depth, DEPTH);

        let Json(path) = tree_path_handler(State(st.clone()), axum::extract::Path(1))
            .await
            .expect("path should exist");
        assert_eq!(path.root, tree.root);
        assert_eq!(path.siblings.len(), DEPTH);
    }

    #[tokio::test]
    async fn test_notes_handler_applies_cursor_and_next_cursor() {
        let st = test_state(default_auth_domain());
        {
            let mut ledger = st.ledger.lock().unwrap();
            ledger.memos.push((u64_to_felt(10), dummy_note(1)));
            ledger.memos.push((u64_to_felt(11), dummy_note(2)));
            ledger.memos.push((u64_to_felt(12), dummy_note(3)));
        }

        let Json(resp) =
            notes_handler(State(st.clone()), Query(CursorParam { cursor: Some(1) })).await;
        assert_eq!(resp.next_cursor, 3);
        assert_eq!(resp.notes.len(), 2);
        assert_eq!(resp.notes[0].index, 1);
        assert_eq!(resp.notes[0].cm, u64_to_felt(11));
        assert_eq!(resp.notes[1].index, 2);

        let Json(from_zero) = notes_handler(State(st), Query(CursorParam { cursor: None })).await;
        assert_eq!(from_zero.notes.len(), 3);
        assert_eq!(from_zero.next_cursor, 3);
    }

    #[tokio::test]
    async fn test_notes_handler_empty_state_returns_empty_feed() {
        let st = test_state(default_auth_domain());
        let Json(resp) = notes_handler(State(st), Query(CursorParam { cursor: None })).await;
        assert!(resp.notes.is_empty());
        assert_eq!(resp.next_cursor, 0);
    }

    #[tokio::test]
    async fn test_notes_handler_cursor_past_end_returns_empty_feed() {
        let st = test_state(default_auth_domain());
        {
            let mut ledger = st.ledger.lock().unwrap();
            ledger.memos.push((u64_to_felt(10), dummy_note(1)));
            ledger.memos.push((u64_to_felt(11), dummy_note(2)));
        }

        let Json(resp) = notes_handler(State(st), Query(CursorParam { cursor: Some(9) })).await;
        assert!(resp.notes.is_empty());
        assert_eq!(resp.next_cursor, 2);
    }

    #[tokio::test]
    async fn test_nullifiers_handler_returns_inserted_values() {
        let st = test_state(default_auth_domain());
        let nf0 = u64_to_felt(21);
        let nf1 = u64_to_felt(22);
        {
            let mut ledger = st.ledger.lock().unwrap();
            ledger.nullifiers.insert(nf0);
            ledger.nullifiers.insert(nf1);
        }

        let Json(resp) = nullifiers_handler(State(st)).await;
        assert_eq!(resp.nullifiers.len(), 2);
        assert!(resp.nullifiers.contains(&nf0));
        assert!(resp.nullifiers.contains(&nf1));
    }

    #[tokio::test]
    async fn test_nullifiers_handler_empty_state_returns_empty_list() {
        let st = test_state(default_auth_domain());
        let Json(resp) = nullifiers_handler(State(st)).await;
        assert!(resp.nullifiers.is_empty());
    }

    #[tokio::test]
    async fn test_tree_path_handler_rejects_out_of_range() {
        let st = test_state(default_auth_domain());
        let err = tree_path_handler(State(st), axum::extract::Path(0))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("out of range"));
    }

    #[tokio::test]
    async fn test_shield_handler_rejects_trust_me_bro_when_verifier_is_required() {
        let st = rejecting_tmb_state(default_auth_domain());
        let _ = dummy_payment_address(1);
        let err = shield_handler(
            State(st),
            Json(ShieldReq {
                pubkey_hash: hash(b"alice"),
                v: 5,
                fee: MIN_TX_FEE,
                producer_fee: 1,
                proof: Proof::TrustMeBro,
                client_cm: u64_to_felt(7),
                client_enc: dummy_note(5),
                producer_cm: u64_to_felt(2),
                producer_enc: dummy_note(6),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("TrustMeBro proofs rejected"));
    }

    #[tokio::test]
    async fn test_transfer_handler_rejects_trust_me_bro_when_verifier_is_required() {
        let st = rejecting_tmb_state(default_auth_domain());
        let err = transfer_handler(
            State(st),
            Json(TransferReq {
                root: ZERO,
                nullifiers: vec![u64_to_felt(1)],
                fee: MIN_TX_FEE,
                cm_1: u64_to_felt(2),
                cm_2: u64_to_felt(3),
                cm_3: u64_to_felt(4),
                enc_1: dummy_note(7),
                enc_2: dummy_note(8),
                enc_3: dummy_note(9),
                proof: Proof::TrustMeBro,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("TrustMeBro proofs rejected"));
    }

    #[tokio::test]
    async fn test_unshield_handler_rejects_trust_me_bro_when_verifier_is_required() {
        let st = rejecting_tmb_state(default_auth_domain());
        let err = unshield_handler(
            State(st),
            Json(UnshieldReq {
                root: ZERO,
                nullifiers: vec![u64_to_felt(1)],
                v_pub: 7,
                fee: MIN_TX_FEE,
                recipient: "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx".into(),
                cm_change: ZERO,
                enc_change: None,
                cm_fee: u64_to_felt(2),
                enc_fee: dummy_note(8),
                proof: Proof::TrustMeBro,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("TrustMeBro proofs rejected"));
    }

    #[tokio::test]
    async fn test_unshield_handler_rejects_invalid_l1_recipient_before_mutation() {
        let st = test_state(default_auth_domain());
        let err = unshield_handler(
            State(st.clone()),
            Json(UnshieldReq {
                root: ZERO,
                nullifiers: vec![u64_to_felt(1)],
                v_pub: 7,
                fee: MIN_TX_FEE,
                recipient: "bob_pub".into(),
                cm_change: ZERO,
                enc_change: None,
                cm_fee: u64_to_felt(2),
                enc_fee: dummy_note(8),
                proof: Proof::TrustMeBro,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("invalid L1 withdrawal recipient: bob_pub"));

        let ledger = st.ledger.lock().unwrap();
        assert!(ledger.withdrawals.is_empty());
        assert!(ledger.nullifiers.is_empty());
        assert_eq!(ledger.tree.leaves.len(), 0);
    }

    #[tokio::test]
    async fn test_unshield_handler_normalizes_l1_recipient_before_queueing() {
        let st = test_state(default_auth_domain());
        let root = {
            let ledger = st.ledger.lock().unwrap();
            ledger.tree.root()
        };
        let resp = unshield_handler(
            State(st.clone()),
            Json(UnshieldReq {
                root,
                nullifiers: vec![u64_to_felt(1)],
                v_pub: 7,
                fee: MIN_TX_FEE,
                recipient: " tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx ".into(),
                cm_change: ZERO,
                enc_change: None,
                cm_fee: u64_to_felt(2),
                enc_fee: dummy_note(8),
                proof: Proof::TrustMeBro,
            }),
        )
        .await
        .expect("whitespace-padded recipient should normalize");
        assert_eq!(resp.0.change_index, None);
        assert_eq!(resp.0.producer_index, 0);

        let ledger = st.ledger.lock().unwrap();
        assert_eq!(
            ledger.withdrawals,
            vec![WithdrawalRecord {
                recipient: "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx".into(),
                amount: 7,
            }]
        );
    }
}
