use clap::{Parser, Subcommand};
use ml_kem::KeyExport;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use tzel_services::*;

// ═══════════════════════════════════════════════════════════════════════
// Wallet file
// ═══════════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize)]
struct WalletFile {
    #[serde(with = "hex_f")]
    master_sk: F,
    /// Legacy global KEM seeds — ignored when per-address derivation is available.
    /// Kept for backwards compatibility during wallet migration.
    #[serde(default, with = "hex_bytes")]
    kem_seed_v: Vec<u8>,
    #[serde(default, with = "hex_bytes")]
    kem_seed_d: Vec<u8>,
    addr_counter: u32,
    notes: Vec<Note>,
    scanned: usize,
    /// Tracks the next unused WOTS+ key index per address.
    /// Key = addr_index, Value = next unused key index within that address's auth tree.
    /// WOTS+ keys are one-time — reuse leaks secret material and allows forgery.
    #[serde(default)]
    wots_key_indices: std::collections::HashMap<u32, u32>,
}

impl WalletFile {
    fn account(&self) -> Account {
        derive_account(&self.master_sk)
    }

    /// Legacy global KEM keys used by pre-migration wallets.
    /// Returns None when the wallet was created after the per-address migration.
    fn legacy_kem_keys(&self) -> Option<(Ek, Dk, Ek, Dk)> {
        let seed_v: [u8; 64] = self.kem_seed_v.as_slice().try_into().ok()?;
        let seed_d: [u8; 64] = self.kem_seed_d.as_slice().try_into().ok()?;
        let (ek_v, dk_v) = kem_keygen_from_seed(&seed_v);
        let (ek_d, dk_d) = kem_keygen_from_seed(&seed_d);
        Some((ek_v, dk_v, ek_d, dk_d))
    }

    /// Per-address KEM keys derived from incoming_seed + address index.
    /// Each address j gets unique (ek_v_j, dk_v_j, ek_d_j, dk_d_j) so that
    /// addresses from the same wallet are unlinkable by their public keys.
    fn kem_keys(&self, j: u32) -> (Ek, Dk, Ek, Dk) {
        let acc = self.account();
        derive_kem_keys(&acc.incoming_seed, j)
    }

    fn recover_note_for_address(
        &self,
        acc: &Account,
        j: u32,
        v: u64,
        rseed: F,
        cm: F,
        index: usize,
    ) -> Option<Note> {
        let d_j = derive_address(&acc.incoming_seed, j);
        let ask_j = derive_ask(&acc.ask_base, j);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&auth_root, &nk_tg);
        let rcm = derive_rcm(&rseed);
        if commit(&d_j, v, &rcm, &otag) != cm {
            return None;
        }
        Some(Note {
            nk_spend: nk_sp,
            nk_tag: nk_tg,
            auth_root,
            d_j,
            v,
            rseed,
            cm,
            index,
            addr_index: j,
        })
    }

    /// Recover a note from the notes feed using either:
    /// 1. Legacy global KEM keys (for pre-migration wallets), or
    /// 2. Current per-address KEM keys.
    fn try_recover_note(&self, nm: &NoteMemo) -> Option<Note> {
        let acc = self.account();

        // Legacy compatibility: old wallets used one global ML-KEM keypair
        // for all addresses. Keep scanning those notes until users migrate.
        if let Some((_, dk_v_legacy, _, dk_d_legacy)) = self.legacy_kem_keys() {
            if detect(&nm.enc, &dk_d_legacy) {
                if let Some((v, rseed, _memo)) = decrypt_memo(&nm.enc, &dk_v_legacy) {
                    for j in 0..self.addr_counter {
                        if let Some(note) =
                            self.recover_note_for_address(&acc, j, v, rseed, nm.cm, nm.index)
                        {
                            return Some(note);
                        }
                    }
                }
            }
        }

        for j in 0..self.addr_counter {
            let (_, dk_v_j, _, dk_d_j) = derive_kem_keys(&acc.incoming_seed, j);
            if !detect(&nm.enc, &dk_d_j) {
                continue;
            }
            let Some((v, rseed, _memo)) = decrypt_memo(&nm.enc, &dk_v_j) else {
                continue;
            };
            if let Some(note) = self.recover_note_for_address(&acc, j, v, rseed, nm.cm, nm.index) {
                return Some(note);
            }
        }

        None
    }

    /// Generate next address. Returns (d_j, auth_root, nk_tag, j).
    /// Builds the full auth tree (1024 WOTS+ key derivations).
    fn next_address(&mut self) -> (F, F, F, u32) {
        let acc = self.account();
        let j = self.addr_counter;
        let d_j = derive_address(&acc.incoming_seed, j);
        let ask_j = derive_ask(&acc.ask_base, j);
        let (auth_root, _leaves) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        self.addr_counter += 1;
        (d_j, auth_root, nk_tg, j)
    }

    /// Allocate the next unused WOTS+ key index for an address.
    /// Panics if all 1024 keys are exhausted.
    fn next_wots_key(&mut self, addr_index: u32) -> u32 {
        let idx = self.wots_key_indices.entry(addr_index).or_insert(0);
        let key_idx = *idx;
        assert!(
            (key_idx as usize) < AUTH_TREE_SIZE,
            "WOTS+ keys exhausted for address {} — generate a new address",
            addr_index
        );
        *idx = key_idx + 1;
        key_idx
    }

    fn balance(&self) -> u128 {
        self.notes.iter().map(|n| n.v as u128).sum()
    }

    /// Select notes to cover at least `amount`. Returns indices into self.notes.
    fn select_notes(&self, amount: u64) -> Result<Vec<usize>, String> {
        let mut indexed: Vec<(usize, u64)> = self
            .notes
            .iter()
            .enumerate()
            .map(|(i, n)| (i, n.v))
            .collect();
        indexed.sort_by(|a, b| b.1.cmp(&a.1)); // largest first
        let mut sum = 0u128;
        let mut selected = vec![];
        for (i, v) in indexed {
            selected.push(i);
            sum += v as u128;
            if sum >= amount as u128 {
                return Ok(selected);
            }
        }
        Err(format!(
            "insufficient funds: have {} need {}",
            self.balance(),
            amount
        ))
    }
}

#[derive(Debug)]
struct WalletLock {
    path: PathBuf,
}

impl Drop for WalletLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn wallet_lock_path(path: &str) -> PathBuf {
    PathBuf::from(format!("{}.lock", path))
}

#[cfg(unix)]
fn is_stale_wallet_lock(path: &Path) -> Result<bool, String> {
    let pid_text = std::fs::read_to_string(path).map_err(|e| format!("read lock file: {}", e))?;
    let pid = pid_text
        .trim()
        .parse::<u32>()
        .map_err(|_| "lock file contains invalid pid".to_string())?;
    Ok(!PathBuf::from(format!("/proc/{}", pid)).exists())
}

#[cfg(not(unix))]
fn is_stale_wallet_lock(_path: &Path) -> Result<bool, String> {
    Ok(false)
}

fn acquire_wallet_lock(path: &str) -> Result<WalletLock, String> {
    fn try_acquire(lock_path: &Path, allow_stale_recovery: bool) -> Result<WalletLock, String> {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock_path)
        {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())
                    .map_err(|e| format!("write lock file: {}", e))?;
                file.sync_all()
                    .map_err(|e| format!("fsync lock file: {}", e))?;
                Ok(WalletLock {
                    path: lock_path.to_path_buf(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if allow_stale_recovery && is_stale_wallet_lock(lock_path).unwrap_or(false) {
                    std::fs::remove_file(lock_path)
                        .map_err(|e| format!("remove stale lock: {}", e))?;
                    return try_acquire(lock_path, false);
                }
                Err(format!(
                    "wallet is locked by another process: {}",
                    lock_path.display()
                ))
            }
            Err(e) => Err(format!("create lock file: {}", e)),
        }
    }

    try_acquire(&wallet_lock_path(path), true)
}

fn load_wallet(path: &str) -> Result<WalletFile, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("read wallet: {}", e))?;
    serde_json::from_str(&data).map_err(|e| format!("parse wallet: {}", e))
}

fn save_wallet(path: &str, w: &WalletFile) -> Result<(), String> {
    let data = serde_json::to_string_pretty(w).map_err(|e| format!("serialize: {}", e))?;
    // Durable write: fsync temp file, rename atomically, then fsync the parent
    // directory so one-time WOTS state survives crashes before submit returns.
    let wallet_path = std::path::Path::new(path);
    let tmp = std::path::PathBuf::from(format!("{}.tmp", path));
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create tmp: {}", e))?;
    file.write_all(data.as_bytes())
        .map_err(|e| format!("write tmp: {}", e))?;
    file.sync_all().map_err(|e| format!("fsync tmp: {}", e))?;
    drop(file);
    std::fs::rename(&tmp, wallet_path).map_err(|e| format!("rename: {}", e))?;
    sync_parent_dir(wallet_path)
}

#[cfg(unix)]
fn sync_parent_dir(path: &std::path::Path) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let dir = std::fs::File::open(parent).map_err(|e| format!("open parent dir: {}", e))?;
    dir.sync_all()
        .map_err(|e| format!("fsync parent dir: {}", e))
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

fn load_address(path: &str) -> Result<PaymentAddress, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("read address: {}", e))?;
    serde_json::from_str(&data).map_err(|e| format!("parse address: {}", e))
}

// ═══════════════════════════════════════════════════════════════════════
// HTTP helpers
// ═══════════════════════════════════════════════════════════════════════

fn post_json<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
    url: &str,
    body: &Req,
) -> Result<Resp, String> {
    let resp = ureq::post(url)
        .send_json(serde_json::to_value(body).unwrap())
        .map_err(|e| format!("HTTP error: {}", e))?;
    let status = resp.status();
    if status != 200 {
        let body = resp.into_body().read_to_string().unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, body));
    }
    resp.into_body()
        .read_json()
        .map_err(|e| format!("parse response: {}", e))
}

fn get_json<Resp: for<'de> Deserialize<'de>>(url: &str) -> Result<Resp, String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("HTTP error: {}", e))?;
    resp.into_body()
        .read_json()
        .map_err(|e| format!("parse response: {}", e))
}

fn ensure_path_matches_root(
    path_root: &F,
    expected_root: &F,
    tree_idx: usize,
) -> Result<(), String> {
    if path_root != expected_root {
        return Err(format!(
            "stale Merkle path for note at tree index {}: expected root {}, got {}",
            tree_idx,
            short(expected_root),
            short(path_root)
        ));
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

#[derive(Parser)]
#[command(name = "sp-client", about = "TzEL CLI wallet")]
struct Cli {
    #[arg(short, long, default_value = "wallet.json")]
    wallet: String,

    /// DANGEROUS: skip STARK proof generation and send TrustMeBro instead.
    /// The ledger accepts transactions without cryptographic verification.
    /// Only for local development/testing.
    #[arg(long)]
    trust_me_bro: bool,

    /// Path to the reprove binary
    #[arg(long, default_value = "reprove")]
    reprove_bin: String,

    /// Path to directory containing compiled .executable.json files
    #[arg(long, default_value = "cairo/target/dev")]
    executables_dir: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new wallet
    Keygen,
    /// Derive a new payment address
    Address,
    /// Export detection key (for delegation)
    ExportDetect,
    /// Export viewing keys (incoming_seed + kem_seed_v)
    ExportView,
    /// Scan ledger for new notes
    Scan {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
    },
    /// Show wallet balance
    Balance,
    /// Shield: deposit public tokens into a private note
    Shield {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        sender: String,
        #[arg(long)]
        amount: u64,
        /// Path to recipient address JSON (default: generate new self-address)
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        memo: Option<String>,
    },
    /// Transfer private notes to a recipient
    Transfer {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        memo: Option<String>,
    },
    /// Unshield: withdraw private notes to a public address
    Unshield {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        recipient: String,
    },
    /// Fund a public address (calls ledger /fund)
    Fund {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        addr: String,
        #[arg(long)]
        amount: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

struct ProveConfig {
    skip_proof: bool,
    reprove_bin: String,
    executables_dir: String,
}

impl ProveConfig {
    fn make_proof(&self, circuit: &str, args: &[String]) -> Result<Proof, String> {
        if self.skip_proof {
            eprintln!("WARNING: --trust-me-bro is set. Skipping STARK proof generation.");
            eprintln!(
                "WARNING: Transaction has NO cryptographic guarantee. DO NOT use in production."
            );
            Ok(Proof::TrustMeBro)
        } else {
            generate_proof(&self.reprove_bin, &self.executables_dir, circuit, args)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let _wallet_lock = match &cli.cmd {
        Cmd::Keygen
        | Cmd::Address
        | Cmd::Scan { .. }
        | Cmd::Shield { .. }
        | Cmd::Transfer { .. }
        | Cmd::Unshield { .. } => Some(acquire_wallet_lock(&cli.wallet)?),
        Cmd::ExportDetect | Cmd::ExportView | Cmd::Balance | Cmd::Fund { .. } => None,
    };
    let pc = ProveConfig {
        skip_proof: cli.trust_me_bro,
        reprove_bin: cli.reprove_bin,
        executables_dir: cli.executables_dir,
    };
    match cli.cmd {
        Cmd::Keygen => cmd_keygen(&cli.wallet),
        Cmd::Address => cmd_address(&cli.wallet),
        Cmd::ExportDetect => cmd_export_detect(&cli.wallet),
        Cmd::ExportView => cmd_export_view(&cli.wallet),
        Cmd::Scan { ledger } => cmd_scan(&cli.wallet, &ledger),
        Cmd::Balance => cmd_balance(&cli.wallet),
        Cmd::Shield {
            ledger,
            sender,
            amount,
            to,
            memo,
        } => cmd_shield(&cli.wallet, &ledger, &sender, amount, to, memo, &pc),
        Cmd::Transfer {
            ledger,
            to,
            amount,
            memo,
        } => cmd_transfer(&cli.wallet, &ledger, &to, amount, memo, &pc),
        Cmd::Unshield {
            ledger,
            amount,
            recipient,
        } => cmd_unshield(&cli.wallet, &ledger, amount, &recipient, &pc),
        Cmd::Fund {
            ledger,
            addr,
            amount,
        } => cmd_fund(&ledger, &addr, amount),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Proving helper — shells out to reprove binary
// ═══════════════════════════════════════════════════════════════════════

/// Felt252 as a hex string for BigUintAsHex format.
fn felt_to_hex(f: &F) -> String {
    // Convert LE bytes to big integer, then to hex
    let mut val = [0u8; 32];
    val.copy_from_slice(f);
    // Reverse to big-endian for hex display
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = val[31 - i];
    }
    // Strip leading zeros
    let hex_str = hex::encode(be);
    let trimmed = hex_str.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_string()
    } else {
        format!("0x{}", trimmed)
    }
}

fn felt_u64_to_hex(v: u64) -> String {
    format!("0x{:x}", v)
}

/// Call the reprover to generate a ZK proof.
/// `circuit` is "run_shield", "run_transfer", or "run_unshield".
/// `args` is the list of felt252 values (already length-prefixed for Array<felt252>).
fn generate_proof(
    reprove_bin: &str,
    executables_dir: &str,
    circuit: &str,
    args: &[String],
) -> Result<Proof, String> {
    #[derive(Deserialize)]
    struct ProofBundleJson {
        #[serde(with = "hex_bytes")]
        proof_bytes: Vec<u8>,
        #[serde(with = "hex_f_vec")]
        output_preimage: Vec<F>,
        #[serde(default)]
        verify_meta: Option<serde_json::Value>,
    }

    let executable = format!("{}/{}.executable.json", executables_dir, circuit);
    let args_file = tempfile::NamedTempFile::new().map_err(|e| format!("tempfile: {}", e))?;
    let args_json = serde_json::to_string(&args).map_err(|e| format!("json: {}", e))?;
    std::fs::write(args_file.path(), &args_json).map_err(|e| format!("write: {}", e))?;

    let proof_file = tempfile::NamedTempFile::new().map_err(|e| format!("tempfile: {}", e))?;

    eprintln!("Generating proof for {} ({} args)...", circuit, args.len());
    let output = std::process::Command::new(reprove_bin)
        .arg(&executable)
        .arg("--arguments-file")
        .arg(args_file.path())
        .arg("--output")
        .arg(proof_file.path())
        .output()
        .map_err(|e| {
            format!(
                "reprove failed to start: {} (is '{}' in PATH?)",
                e, reprove_bin
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("reprove failed: {}", stderr));
    }

    // Parse the proof bundle
    let bundle_json =
        std::fs::read_to_string(proof_file.path()).map_err(|e| format!("read proof: {}", e))?;
    let bundle: ProofBundleJson =
        serde_json::from_str(&bundle_json).map_err(|e| format!("parse proof: {}", e))?;

    let proof_kb = bundle.proof_bytes.len() / 1024;
    eprintln!(
        "Proof generated: {} KB, {} public outputs",
        proof_kb,
        bundle.output_preimage.len()
    );

    Ok(Proof::Stark {
        proof_bytes: bundle.proof_bytes,
        output_preimage: bundle.output_preimage,
        verify_meta: bundle.verify_meta,
    })
}

fn persist_wallet_and_make_proof(
    path: &str,
    w: &WalletFile,
    pc: &ProveConfig,
    circuit: &str,
    args: &[String],
) -> Result<Proof, String> {
    save_wallet(path, w)?;
    pc.make_proof(circuit, args)
}

// ═══════════════════════════════════════════════════════════════════════
// Commands
// ═══════════════════════════════════════════════════════════════════════

fn cmd_keygen(path: &str) -> Result<(), String> {
    if std::path::Path::new(path).exists() {
        return Err(format!("{} already exists", path));
    }
    let master_sk = random_felt();

    let w = WalletFile {
        master_sk,
        kem_seed_v: vec![], // legacy, unused — keys derived per-address from incoming_seed
        kem_seed_d: vec![],
        addr_counter: 0,
        notes: vec![],
        scanned: 0,
        wots_key_indices: std::collections::HashMap::new(),
    };
    save_wallet(path, &w)?;
    println!("Wallet created: {}", path);
    Ok(())
}

fn cmd_address(path: &str) -> Result<(), String> {
    let mut w = load_wallet(path)?;
    let (d_j, auth_root, nk_tag, j) = w.next_address();
    let (ek_v, _, ek_d, _) = w.kem_keys(j);

    let addr = PaymentAddress {
        d_j,
        auth_root,
        nk_tag,
        ek_v: ek_v.to_bytes().to_vec(),
        ek_d: ek_d.to_bytes().to_vec(),
    };

    save_wallet(path, &w)?;
    println!("Address #{}", j);
    println!("{}", serde_json::to_string_pretty(&addr).unwrap());
    Ok(())
}

fn cmd_export_detect(path: &str) -> Result<(), String> {
    let w = load_wallet(path)?;
    let acc = w.account();
    let detect_root = derive_detect_root(&acc.incoming_seed);
    // Export detection root only: holder can derive per-address dk_d_j
    // for any j, but cannot derive viewing keys or decrypt memos.
    println!(
        "{{\"detect_root\":\"{}\",\"addr_count\":{},\"mode\":\"detect\"}}",
        hex::encode(detect_root),
        w.addr_counter
    );
    Ok(())
}

fn cmd_export_view(path: &str) -> Result<(), String> {
    let w = load_wallet(path)?;
    let acc = w.account();
    // Export incoming_seed: holder can derive per-address dk_v_j and dk_d_j
    // for any j, enabling full viewing (decrypt + detect) but not spending.
    println!(
        "{{\"incoming_seed\":\"{}\",\"addr_count\":{}}}",
        hex::encode(acc.incoming_seed),
        w.addr_counter
    );
    Ok(())
}

fn cmd_scan(path: &str, ledger: &str) -> Result<(), String> {
    let mut w = load_wallet(path)?;

    let url = format!("{}/notes?cursor={}", ledger, w.scanned);
    let feed: NotesFeedResp = get_json(&url)?;

    let mut found = 0usize;
    let mut known_notes: std::collections::HashSet<(usize, F)> =
        w.notes.iter().map(|n| (n.index, n.cm)).collect();
    for nm in &feed.notes {
        if let Some(note) = w.try_recover_note(nm) {
            if known_notes.insert((note.index, note.cm)) {
                println!(
                    "  found: v={} cm={} index={}",
                    note.v,
                    short(&note.cm),
                    note.index
                );
                w.notes.push(note);
                found += 1;
            }
        }
    }

    // Check which notes have been spent (nullified)
    let nf_resp: NullifiersResp = get_json(&format!("{}/nullifiers", ledger))?;
    let nf_set: std::collections::HashSet<F> = nf_resp.nullifiers.into_iter().collect();
    let before = w.notes.len();
    w.notes.retain(|n| {
        let nf = nullifier(&n.nk_spend, &n.cm, n.index as u64);
        !nf_set.contains(&nf)
    });
    let spent = before - w.notes.len();

    w.scanned = feed.next_cursor;
    save_wallet(path, &w)?;
    println!(
        "Scanned: {} new notes found, {} spent removed, balance={}",
        found,
        spent,
        w.balance()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn test_wallet(addr_counter: u32, legacy: Option<([u8; 64], [u8; 64])>) -> WalletFile {
        let mut master_sk = ZERO;
        master_sk[0] = 0x42;
        let (kem_seed_v, kem_seed_d) = legacy
            .map(|(v, d)| (v.to_vec(), d.to_vec()))
            .unwrap_or_else(|| (vec![], vec![]));
        WalletFile {
            master_sk,
            kem_seed_v,
            kem_seed_d,
            addr_counter,
            notes: vec![],
            scanned: 0,
            wots_key_indices: std::collections::HashMap::new(),
        }
    }

    fn wallet_with_single_note(note_value: u64) -> (WalletFile, F) {
        let mut w = test_wallet(1, None);
        let acc = w.account();
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&auth_root, &nk_tg);
        let rseed = random_felt();
        let rcm = derive_rcm(&rseed);
        let cm = commit(&d_j, note_value, &rcm, &otag);
        w.notes.push(Note {
            nk_spend: nk_sp,
            nk_tag: nk_tg,
            auth_root,
            d_j,
            v: note_value,
            rseed,
            cm,
            index: 0,
            addr_index: 0,
        });
        (w, cm)
    }

    fn sample_payment_address(seed_byte: u8) -> PaymentAddress {
        let mut master_sk = ZERO;
        master_sk[0] = seed_byte;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let (ek_v, _, ek_d, _) = derive_kem_keys(&acc.incoming_seed, 0);
        PaymentAddress {
            d_j,
            auth_root,
            nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        }
    }

    fn note_memo_for_wallet_address(
        w: &WalletFile,
        j: u32,
        value: u64,
        rseed: F,
        memo: Option<&[u8]>,
    ) -> NoteMemo {
        let acc = w.account();
        let d_j = derive_address(&acc.incoming_seed, j);
        let ask_j = derive_ask(&acc.ask_base, j);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&auth_root, &nk_tg);
        let rcm = derive_rcm(&rseed);
        let cm = commit(&d_j, value, &rcm, &otag);
        let (ek_v, _, ek_d, _) = w.kem_keys(j);
        let enc = encrypt_note(value, &rseed, memo, &ek_v, &ek_d);
        NoteMemo { index: 0, cm, enc }
    }

    proptest! {
        #[test]
        fn prop_select_notes_returns_valid_covering_set(
            values in prop::collection::vec(1u64..10_000, 1..12)
        ) {
            let total = values.iter().copied().sum::<u64>();
            let amount = 1 + (total / 2);
            let mut w = test_wallet(0, None);
            w.notes = values.iter().enumerate().map(|(i, v)| Note {
                nk_spend: ZERO,
                nk_tag: ZERO,
                auth_root: ZERO,
                d_j: ZERO,
                v: *v,
                rseed: ZERO,
                cm: u64_to_felt(i as u64 + 1),
                index: i,
                addr_index: 0,
            }).collect();

            let selected = w.select_notes(amount).expect("selection should succeed");
            let mut seen = std::collections::HashSet::new();
            let mut selected_sum: u128 = 0;
            for i in selected {
                prop_assert!(seen.insert(i));
                prop_assert!(i < w.notes.len());
                selected_sum += w.notes[i].v as u128;
            }

            prop_assert!(selected_sum >= amount as u128);
        }
    }

    #[test]
    fn test_export_detect_uses_detect_root_not_incoming_seed() {
        let w = test_wallet(3, None);
        let acc = w.account();
        let detect_root = derive_detect_root(&acc.incoming_seed);
        assert_ne!(
            detect_root, acc.incoming_seed,
            "detect export material must not expose incoming_seed"
        );
    }

    #[test]
    fn test_try_recover_note_new_per_address_wallet() {
        let w = test_wallet(1, None);
        let acc = w.account();
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&auth_root, &nk_tg);
        let rseed = random_felt();
        let rcm = derive_rcm(&rseed);
        let cm = commit(&d_j, 77, &rcm, &otag);
        let (ek_v, _, ek_d, _) = w.kem_keys(0);
        let enc = encrypt_note(77, &rseed, Some(b"new"), &ek_v, &ek_d);
        let nm = NoteMemo { index: 5, cm, enc };

        let note = w
            .try_recover_note(&nm)
            .expect("new per-address note should recover");
        assert_eq!(note.index, 5);
        assert_eq!(note.addr_index, 0);
        assert_eq!(note.v, 77);
        assert_eq!(note.cm, cm);
    }

    #[test]
    fn test_try_recover_note_legacy_wallet() {
        let legacy_v = [0x11; 64];
        let legacy_d = [0x22; 64];
        let w = test_wallet(1, Some((legacy_v, legacy_d)));
        let acc = w.account();
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&auth_root, &nk_tg);
        let rseed = random_felt();
        let rcm = derive_rcm(&rseed);
        let cm = commit(&d_j, 91, &rcm, &otag);
        let (ek_v, _dk_v, ek_d, _dk_d) = w.legacy_kem_keys().expect("legacy keys");
        let enc = encrypt_note(91, &rseed, Some(b"legacy"), &ek_v, &ek_d);
        let nm = NoteMemo { index: 2, cm, enc };

        let note = w.try_recover_note(&nm).expect("legacy note should recover");
        assert_eq!(note.index, 2);
        assert_eq!(note.addr_index, 0);
        assert_eq!(note.v, 91);
        assert_eq!(note.cm, cm);
    }

    #[test]
    fn test_try_recover_note_rejects_phantom_note_with_wrong_commitment() {
        let w = test_wallet(1, None);
        let mut rseed = ZERO;
        rseed[0] = 0x55;
        let mut nm = note_memo_for_wallet_address(&w, 0, 77, rseed, Some(b"phantom"));
        nm.cm[0] ^= 0x01;
        assert!(
            w.try_recover_note(&nm).is_none(),
            "wallet must reject decrypted notes whose commitment does not match"
        );
    }

    #[test]
    fn test_try_recover_note_rejects_wrong_owner_metadata_even_with_valid_decryption() {
        let w = test_wallet(1, None);
        let acc = w.account();
        let d_j = derive_address(&acc.incoming_seed, 0);
        let (ek_v, _, ek_d, _) = w.kem_keys(0);
        let mut other_master_sk = ZERO;
        other_master_sk[0] = 0x91;
        let other_acc = derive_account(&other_master_sk);
        let other_d = derive_address(&other_acc.incoming_seed, 0);
        let other_ask = derive_ask(&other_acc.ask_base, 0);
        let (other_auth_root, _) = build_auth_tree(&other_ask);
        let other_nk_sp = derive_nk_spend(&other_acc.nk, &other_d);
        let other_nk_tag = derive_nk_tag(&other_nk_sp);
        let other_owner_tag = owner_tag(&other_auth_root, &other_nk_tag);
        let mut rseed = ZERO;
        rseed[0] = 0x22;
        let cm = commit(&d_j, 88, &derive_rcm(&rseed), &other_owner_tag);
        let nm = NoteMemo {
            index: 3,
            cm,
            enc: encrypt_note(88, &rseed, Some(b"wrong-owner"), &ek_v, &ek_d),
        };

        assert!(
            w.try_recover_note(&nm).is_none(),
            "wallet must recompute owner metadata and reject non-spendable notes"
        );
    }

    #[test]
    fn test_save_wallet_roundtrip_cleans_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let w = test_wallet(2, None);

        save_wallet(wallet_path_str, &w).expect("wallet should save");
        let loaded = load_wallet(wallet_path_str).expect("wallet should load");

        assert_eq!(loaded.addr_counter, 2);
        assert_eq!(loaded.master_sk, w.master_sk);
        assert!(!dir.path().join("wallet.json.tmp").exists());
    }

    #[test]
    fn test_wallet_lock_rejects_concurrent_access() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();

        let _guard = acquire_wallet_lock(wallet_path_str).expect("first lock should succeed");
        let err = acquire_wallet_lock(wallet_path_str).unwrap_err();
        assert!(
            err.contains("wallet is locked by another process"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_wallet_lock_recovers_stale_lock() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let lock_path = wallet_lock_path(wallet_path.to_str().unwrap());

        std::fs::write(&lock_path, "999999\n").expect("write stale lock");
        let guard = acquire_wallet_lock(wallet_path.to_str().unwrap())
            .expect("stale lock should be recovered");
        assert!(lock_path.exists(), "live lock file should exist while held");
        drop(guard);
        assert!(
            !lock_path.exists(),
            "lock file should be removed when guard drops"
        );
    }

    #[test]
    fn test_ensure_path_matches_root_rejects_mismatch() {
        let expected = [1u8; 32];
        let actual = [2u8; 32];
        let err = ensure_path_matches_root(&actual, &expected, 7).unwrap_err();
        assert!(err.contains("stale Merkle path"));
        assert!(err.contains("tree index 7"));
    }

    #[test]
    fn test_next_address_derivation_is_isolated_per_index() {
        let mut w = test_wallet(0, None);
        let (d0, auth0, nk0, j0) = w.next_address();
        let (ek_v0, _, ek_d0, _) = w.kem_keys(j0);
        let (d1, auth1, nk1, j1) = w.next_address();
        let (ek_v1, _, ek_d1, _) = w.kem_keys(j1);

        assert_ne!(j0, j1);
        assert_ne!(d0, d1);
        assert_ne!(auth0, auth1);
        assert_ne!(nk0, nk1);
        assert_ne!(ek_v0.to_bytes(), ek_v1.to_bytes());
        assert_ne!(ek_d0.to_bytes(), ek_d1.to_bytes());
    }

    #[test]
    fn test_next_wots_key_is_monotonic_and_exhausts() {
        let mut w = test_wallet(1, None);
        assert_eq!(w.next_wots_key(0), 0);
        assert_eq!(w.next_wots_key(0), 1);
        w.wots_key_indices.insert(0, (AUTH_TREE_SIZE - 1) as u32);
        assert_eq!(w.next_wots_key(0), (AUTH_TREE_SIZE - 1) as u32);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = w.next_wots_key(0);
        }));
        assert!(panic.is_err(), "WOTS key exhaustion must panic");
    }

    #[test]
    fn test_transfer_persists_wots_state_before_proving() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();

        let (w, cm) = wallet_with_single_note(50);
        save_wallet(wallet_path_str, &w).expect("wallet should save");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        let _recipient = sample_payment_address(0x99);
        let _change_address = loaded.next_address();
        let _key_idx = loaded.next_wots_key(0);
        let args = vec![felt_u64_to_hex(0)];

        let pc = ProveConfig {
            skip_proof: false,
            reprove_bin: "/definitely/missing/reprove".into(),
            executables_dir: "cairo/target/dev".into(),
        };
        let err =
            persist_wallet_and_make_proof(wallet_path_str, &loaded, &pc, "run_transfer", &args)
                .unwrap_err();

        assert!(
            err.contains("reprove failed to start"),
            "unexpected error: {}",
            err
        );
        let loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        assert_eq!(
            loaded.addr_counter, 2,
            "change address reservation must persist"
        );
        assert_eq!(
            loaded.wots_key_indices.get(&0),
            Some(&1),
            "consumed WOTS leaf must persist across proving failure"
        );
        assert_eq!(loaded.notes[0].cm, cm);
    }

    #[test]
    fn test_unshield_persists_wots_state_before_proving() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();

        let (w, cm) = wallet_with_single_note(50);
        save_wallet(wallet_path_str, &w).expect("wallet should save");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        let _change_address = loaded.next_address();
        let _key_idx = loaded.next_wots_key(0);
        let args = vec![felt_u64_to_hex(0)];

        let pc = ProveConfig {
            skip_proof: false,
            reprove_bin: "/definitely/missing/reprove".into(),
            executables_dir: "cairo/target/dev".into(),
        };
        let err =
            persist_wallet_and_make_proof(wallet_path_str, &loaded, &pc, "run_unshield", &args)
                .unwrap_err();

        assert!(
            err.contains("reprove failed to start"),
            "unexpected error: {}",
            err
        );
        let loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        assert_eq!(
            loaded.addr_counter, 2,
            "change address reservation must persist"
        );
        assert_eq!(
            loaded.wots_key_indices.get(&0),
            Some(&1),
            "consumed WOTS leaf must persist across proving failure"
        );
        assert_eq!(loaded.notes[0].cm, cm);
    }
}

fn cmd_balance(path: &str) -> Result<(), String> {
    let w = load_wallet(path)?;
    println!("Private balance: {}", w.balance());
    println!("Notes: {}", w.notes.len());
    for (i, n) in w.notes.iter().enumerate() {
        println!("  [{}] v={} cm={} index={}", i, n.v, short(&n.cm), n.index);
    }
    Ok(())
}

fn cmd_shield(
    path: &str,
    ledger: &str,
    sender: &str,
    amount: u64,
    to: Option<String>,
    memo: Option<String>,
    pc: &ProveConfig,
) -> Result<(), String> {
    let mut w = load_wallet(path)?;

    let (address, generated_self_address) = if let Some(addr_path) = to {
        (load_address(&addr_path)?, false)
    } else {
        let (d_j, auth_root, nk_tag, j) = w.next_address();
        let (ek_v, _, ek_d, _) = w.kem_keys(j);
        (
            PaymentAddress {
                d_j,
                auth_root,
                nk_tag,
                ek_v: ek_v.to_bytes().to_vec(),
                ek_d: ek_d.to_bytes().to_vec(),
            },
            true,
        )
    };

    // Build the proof if --prove is set.
    // Shield witness: [v_pub, cm_new, sender, memo_ct_hash, auth_root, nk_tag, d_j, rseed]
    // Note: with TrustMeBro, the ledger generates rseed and computes the commitment.
    // With a real proof, the client must do this and prove it.
    let (proof, shield_cm, shield_enc) = if !pc.skip_proof {
        let rseed = random_felt();
        let rcm = derive_rcm(&rseed);
        let otag = owner_tag(&address.auth_root, &address.nk_tag);
        let cm = commit(&address.d_j, amount, &rcm, &otag);

        // sender as felt252
        let sender_f = hash(sender.as_bytes());

        // Create encrypted note to compute memo hash
        let ek_v_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
            address.ek_v.as_slice().try_into().map_err(|_| "bad ek_v")?,
        )
        .map_err(|_| "invalid ek_v")?;
        let ek_d_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
            address.ek_d.as_slice().try_into().map_err(|_| "bad ek_d")?,
        )
        .map_err(|_| "invalid ek_d")?;
        let memo_bytes = memo.as_deref().map(|s| s.as_bytes());
        let enc = encrypt_note(amount, &rseed, memo_bytes, &ek_v_recv, &ek_d_recv);
        let memo_ct_hash_f = memo_ct_hash(&enc);

        let args: Vec<String> = vec![
            felt_u64_to_hex(8), // Array length prefix
            felt_u64_to_hex(amount),
            felt_to_hex(&cm),
            felt_to_hex(&sender_f),
            felt_to_hex(&memo_ct_hash_f),
            felt_to_hex(&address.auth_root),
            felt_to_hex(&address.nk_tag),
            felt_to_hex(&address.d_j),
            felt_to_hex(&rseed),
        ];
        let proof = pc.make_proof("run_shield", &args)?;
        (proof, cm, Some(enc))
    } else {
        (Proof::TrustMeBro, ZERO, None)
    };

    let req = ShieldReq {
        sender: sender.into(),
        v: amount,
        address,
        memo,
        proof,
        client_cm: shield_cm,
        client_enc: shield_enc,
    };
    if generated_self_address {
        // Persist generated self-addresses before submission so a crash after a
        // successful shield does not hide the note from future scans.
        save_wallet(path, &w)?;
    }
    let resp: ShieldResp = post_json(&format!("{}/shield", ledger), &req)?;
    save_wallet(path, &w)?;
    println!(
        "Shielded {} -> cm={} index={}",
        amount,
        short(&resp.cm),
        resp.index
    );
    println!("Run 'scan' to pick up the note.");
    Ok(())
}

fn cmd_transfer(
    path: &str,
    ledger: &str,
    to_path: &str,
    amount: u64,
    memo: Option<String>,
    pc: &ProveConfig,
) -> Result<(), String> {
    let mut w = load_wallet(path)?;
    let recipient = load_address(to_path)?;

    // Select notes
    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;

    // Get current root
    let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))?;
    let root = tree_info.root;

    // Compute nullifiers
    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();

    // Build output 1: recipient
    let rseed_1 = random_felt();
    let rcm_1 = derive_rcm(&rseed_1);
    let ek_v_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
        recipient
            .ek_v
            .as_slice()
            .try_into()
            .map_err(|_| "bad ek_v")?,
    )
    .map_err(|_| "invalid ek_v")?;
    let ek_d_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
        recipient
            .ek_d
            .as_slice()
            .try_into()
            .map_err(|_| "bad ek_d")?,
    )
    .map_err(|_| "invalid ek_d")?;
    let otag_1 = owner_tag(&recipient.auth_root, &recipient.nk_tag);
    let cm_1 = commit(&recipient.d_j, amount, &rcm_1, &otag_1);
    let memo_bytes = memo.as_deref().map(|s| s.as_bytes());
    let enc_1 = encrypt_note(amount, &rseed_1, memo_bytes, &ek_v_recv, &ek_d_recv);

    // Build output 2: change to self (per-address KEM keys)
    let (d_j_c, auth_root_c, nk_tag_c, j_c) = w.next_address();
    let (ek_v_c, _, ek_d_c, _) = w.kem_keys(j_c);
    let rseed_2 = random_felt();
    let rcm_2 = derive_rcm(&rseed_2);
    let otag_2 = owner_tag(&auth_root_c, &nk_tag_c);
    let cm_2 = commit(&d_j_c, change, &rcm_2, &otag_2);
    let enc_2 = encrypt_note(change, &rseed_2, None, &ek_v_c, &ek_d_c);

    let proof = if !pc.skip_proof {
        let cfg: ConfigResp = get_json(&format!("{}/config", ledger))?;
        let auth_domain = cfg.auth_domain;

        // Build witness for run_transfer with WOTS+ w=4 inside the STARK.
        // Layout:
        // [N, auth_domain, root, per-input(nf,nk_spend,auth_root,auth_idx,d_j,v,rseed,cm_path_idx)×N,
        //  cm_siblings(N×DEPTH), auth_siblings(N×AUTH_DEPTH),
        //  wots_sig(N×133), wots_pk(N×133),
        //  (digits computed by circuit from sighash — not in args)
        //  output1(7), output2(7)]
        let n = selected.len();
        let mut args: Vec<String> = vec![];
        let mut cm_paths: Vec<Vec<F>> = vec![];
        let mut auth_paths: Vec<Vec<F>> = vec![];
        let mut wots_sigs: Vec<Vec<F>> = vec![];
        let mut wots_pks: Vec<Vec<F>> = vec![];

        // Compute sighash matching the Cairo circuit's computation
        let nfs_for_sh: Vec<F> = selected
            .iter()
            .map(|&i| {
                let n = &w.notes[i];
                nullifier(&n.nk_spend, &n.cm, n.index as u64)
            })
            .collect();
        let mh_1 = memo_ct_hash(&enc_1);
        let mh_2 = memo_ct_hash(&enc_2);
        let sighash =
            transfer_sighash(&auth_domain, &root, &nfs_for_sh, &cm_1, &cm_2, &mh_1, &mh_2);

        let mut wots_key_indices: Vec<u32> = vec![];
        // Clone note data to avoid borrow conflict with next_wots_key
        let selected_notes: Vec<(usize, u32, F)> = selected
            .iter()
            .map(|&i| {
                (
                    w.notes[i].index,
                    w.notes[i].addr_index,
                    w.notes[i].auth_root,
                )
            })
            .collect();
        for &(tree_idx, addr_idx, stored_auth_root) in &selected_notes {
            let path_resp: MerklePathResp =
                get_json(&format!("{}/tree/path/{}", ledger, tree_idx))?;
            ensure_path_matches_root(&path_resp.root, &root, tree_idx)?;
            cm_paths.push(path_resp.siblings);
            let ask_j = derive_ask(&w.account().ask_base, addr_idx);
            let key_idx = w.next_wots_key(addr_idx);
            let (rebuilt_root, auth_leaves) = build_auth_tree(&ask_j);
            if rebuilt_root != stored_auth_root {
                return Err(format!(
                    "auth_root mismatch for note at tree index {}",
                    tree_idx
                ));
            }
            auth_paths.push(auth_tree_path(&auth_leaves, key_idx as usize));
            let (sig, pk, _digits) = wots_sign(&ask_j, key_idx, &sighash);
            wots_sigs.push(sig);
            wots_pks.push(pk);
            wots_key_indices.push(key_idx);
        }

        let total_fields = 3 + 8 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS * 2 + 14;
        args.push(felt_u64_to_hex(total_fields as u64));
        args.push(felt_u64_to_hex(n as u64));
        args.push(felt_to_hex(&auth_domain));
        args.push(felt_to_hex(&root));

        // Per-input scalar fields (8 per input)
        for (idx, &si) in selected.iter().enumerate() {
            let note = &w.notes[si];
            let nf = nullifier(&note.nk_spend, &note.cm, note.index as u64);
            args.push(felt_to_hex(&nf));
            args.push(felt_to_hex(&note.nk_spend));
            args.push(felt_to_hex(&note.auth_root));
            args.push(felt_u64_to_hex(wots_key_indices[idx] as u64));
            args.push(felt_to_hex(&note.d_j));
            args.push(felt_u64_to_hex(note.v));
            args.push(felt_to_hex(&note.rseed));
            args.push(felt_u64_to_hex(note.index as u64));
        }

        for path in &cm_paths {
            for sib in path {
                args.push(felt_to_hex(sib));
            }
        }
        for path in &auth_paths {
            for sib in path {
                args.push(felt_to_hex(sib));
            }
        }
        for sig in &wots_sigs {
            for s in sig {
                args.push(felt_to_hex(s));
            }
        }
        for pk in &wots_pks {
            for p in pk {
                args.push(felt_to_hex(p));
            }
        }

        // Output 1
        args.push(felt_to_hex(&cm_1));
        args.push(felt_to_hex(&recipient.d_j));
        args.push(felt_u64_to_hex(amount));
        args.push(felt_to_hex(&rseed_1));
        args.push(felt_to_hex(&recipient.auth_root));
        args.push(felt_to_hex(&recipient.nk_tag));
        args.push(felt_to_hex(&memo_ct_hash(&enc_1)));

        // Output 2
        args.push(felt_to_hex(&cm_2));
        args.push(felt_to_hex(&d_j_c));
        args.push(felt_u64_to_hex(change));
        args.push(felt_to_hex(&rseed_2));
        args.push(felt_to_hex(&auth_root_c));
        args.push(felt_to_hex(&nk_tag_c));
        args.push(felt_to_hex(&memo_ct_hash(&enc_2)));

        // Persist consumed WOTS+ leaf reservations before handing witness material
        // to the prover. If proving fails, the keys stay burned instead of being
        // silently reused on retry.
        persist_wallet_and_make_proof(path, &w, pc, "run_transfer", &args)?
    } else {
        Proof::TrustMeBro
    };

    // Save wallet BEFORE submitting — persists consumed WOTS+ key indices.
    // If submission fails, the key is "burned" but never reused. Safe for one-time sigs.
    save_wallet(path, &w)?;

    let req = TransferReq {
        root,
        nullifiers,
        cm_1,
        cm_2,
        enc_1,
        enc_2,
        proof,
    };
    let resp: TransferResp = post_json(&format!("{}/transfer", ledger), &req)?;

    // Remove spent notes after successful submission
    let mut to_remove = selected.clone();
    to_remove.sort_unstable();
    for &i in to_remove.iter().rev() {
        w.notes.remove(i);
    }
    save_wallet(path, &w)?;

    println!(
        "Transferred {} to recipient, change={} (idx={},{})",
        amount, change, resp.index_1, resp.index_2
    );
    println!("Run 'scan' to pick up change note.");
    Ok(())
}

fn cmd_unshield(
    path: &str,
    ledger: &str,
    amount: u64,
    recipient: &str,
    pc: &ProveConfig,
) -> Result<(), String> {
    let mut w = load_wallet(path)?;

    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;

    let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))?;
    let root = tree_info.root;

    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();

    // Build change output — save intermediate values for proving path
    struct ChangeData {
        d_j: F,
        rseed: F,
        auth_root: F,
        nk_tag: F,
        mh: F,
    }
    let (cm_change, enc_change, change_data) = if change > 0 {
        let (d_j_c, auth_root_c, nk_tag_c, j_c) = w.next_address();
        let (ek_v_c, _, ek_d_c, _) = w.kem_keys(j_c);
        let rseed_c = random_felt();
        let rcm_c = derive_rcm(&rseed_c);
        let otag_c = owner_tag(&auth_root_c, &nk_tag_c);
        let cm = commit(&d_j_c, change, &rcm_c, &otag_c);
        let enc = encrypt_note(change, &rseed_c, None, &ek_v_c, &ek_d_c);
        let mh = memo_ct_hash(&enc);
        let cd = ChangeData {
            d_j: d_j_c,
            rseed: rseed_c,
            auth_root: auth_root_c,
            nk_tag: nk_tag_c,
            mh,
        };
        (cm, Some(enc), Some(cd))
    } else {
        (ZERO, None, None)
    };

    let proof = if !pc.skip_proof {
        let cfg: ConfigResp = get_json(&format!("{}/config", ledger))?;
        let auth_domain = cfg.auth_domain;

        let n = selected.len();
        let mut args: Vec<String> = vec![];
        let mut cm_paths: Vec<Vec<F>> = vec![];
        let mut auth_paths: Vec<Vec<F>> = vec![];
        let mut wots_sigs: Vec<Vec<F>> = vec![];
        let mut wots_pks: Vec<Vec<F>> = vec![];

        let has_change_val: u64 = if change > 0 { 1 } else { 0 };
        let recipient_f = hash(recipient.as_bytes());
        let mh_change_f = change_data.as_ref().map(|cd| cd.mh).unwrap_or(ZERO);

        // Compute sighash matching Cairo circuit
        let nfs_for_sh: Vec<F> = selected
            .iter()
            .map(|&i| {
                let n = &w.notes[i];
                nullifier(&n.nk_spend, &n.cm, n.index as u64)
            })
            .collect();
        let sighash = unshield_sighash(
            &auth_domain,
            &root,
            &nfs_for_sh,
            amount,
            &recipient_f,
            &cm_change,
            &mh_change_f,
        );

        let mut wots_key_indices: Vec<u32> = vec![];
        let selected_notes: Vec<(usize, u32, F)> = selected
            .iter()
            .map(|&i| {
                (
                    w.notes[i].index,
                    w.notes[i].addr_index,
                    w.notes[i].auth_root,
                )
            })
            .collect();
        for &(tree_idx, addr_idx, stored_auth_root) in &selected_notes {
            let path_resp: MerklePathResp =
                get_json(&format!("{}/tree/path/{}", ledger, tree_idx))?;
            ensure_path_matches_root(&path_resp.root, &root, tree_idx)?;
            cm_paths.push(path_resp.siblings);
            let ask_j = derive_ask(&w.account().ask_base, addr_idx);
            let key_idx = w.next_wots_key(addr_idx);
            let (rebuilt_root, auth_leaves) = build_auth_tree(&ask_j);
            if rebuilt_root != stored_auth_root {
                return Err(format!(
                    "auth_root mismatch for note at tree index {}",
                    tree_idx
                ));
            }
            auth_paths.push(auth_tree_path(&auth_leaves, key_idx as usize));
            let (sig, pk, _digits) = wots_sign(&ask_j, key_idx, &sighash);
            wots_sigs.push(sig);
            wots_pks.push(pk);
            wots_key_indices.push(key_idx);
        }

        let total = 5 + 8 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS * 2 + 7;
        args.push(felt_u64_to_hex(total as u64));
        args.push(felt_u64_to_hex(n as u64));
        args.push(felt_to_hex(&auth_domain));
        args.push(felt_to_hex(&root));
        args.push(felt_u64_to_hex(amount));
        args.push(felt_to_hex(&recipient_f));

        for (idx, &si) in selected.iter().enumerate() {
            let note = &w.notes[si];
            let nf = nullifier(&note.nk_spend, &note.cm, note.index as u64);
            args.push(felt_to_hex(&nf));
            args.push(felt_to_hex(&note.nk_spend));
            args.push(felt_to_hex(&note.auth_root));
            args.push(felt_u64_to_hex(wots_key_indices[idx] as u64));
            args.push(felt_to_hex(&note.d_j));
            args.push(felt_u64_to_hex(note.v));
            args.push(felt_to_hex(&note.rseed));
            args.push(felt_u64_to_hex(note.index as u64));
        }

        for path in &cm_paths {
            for sib in path {
                args.push(felt_to_hex(sib));
            }
        }
        for path in &auth_paths {
            for sib in path {
                args.push(felt_to_hex(sib));
            }
        }
        for sig in &wots_sigs {
            for s in sig {
                args.push(felt_to_hex(s));
            }
        }
        for pk in &wots_pks {
            for p in pk {
                args.push(felt_to_hex(p));
            }
        }

        args.push(felt_u64_to_hex(has_change_val));
        if let Some(cd) = &change_data {
            args.push(felt_to_hex(&cd.d_j));
            args.push(felt_u64_to_hex(change));
            args.push(felt_to_hex(&cd.rseed));
            args.push(felt_to_hex(&cd.auth_root));
            args.push(felt_to_hex(&cd.nk_tag));
            args.push(felt_to_hex(&cd.mh));
        } else {
            for _ in 0..6 {
                args.push("0x0".to_string());
            }
        }

        // Persist consumed WOTS+ leaf reservations before handing witness material
        // to the prover. If proving fails, the keys stay burned instead of being
        // silently reused on retry.
        persist_wallet_and_make_proof(path, &w, pc, "run_unshield", &args)?
    } else {
        Proof::TrustMeBro
    };

    // Save wallet BEFORE submitting — persists consumed WOTS+ key indices.
    save_wallet(path, &w)?;

    let req = UnshieldReq {
        root,
        nullifiers,
        v_pub: amount,
        recipient: recipient.into(),
        cm_change,
        enc_change,
        proof,
    };
    let resp: UnshieldResp = post_json(&format!("{}/unshield", ledger), &req)?;

    let mut to_remove = selected.clone();
    to_remove.sort_unstable();
    for &i in to_remove.iter().rev() {
        w.notes.remove(i);
    }
    save_wallet(path, &w)?;

    println!(
        "Unshielded {} to {}, change={} (change_idx={:?})",
        amount, recipient, change, resp.change_index
    );
    if change > 0 {
        println!("Run 'scan' to pick up change note.");
    }
    Ok(())
}

fn cmd_fund(ledger: &str, addr: &str, amount: u64) -> Result<(), String> {
    let req = FundReq {
        recipient: addr.into(),
        amount,
    };
    let _: serde_json::Value = post_json(&format!("{}/fund", ledger), &req)?;
    println!("Funded {} with {}", addr, amount);
    Ok(())
}
