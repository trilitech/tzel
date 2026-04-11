use clap::{Parser, Subcommand};
use ml_kem::KeyExport;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use tzel_services::*;

// ═══════════════════════════════════════════════════════════════════════
// Wallet file
// ═══════════════════════════════════════════════════════════════════════

const XMSS_BDS_K: usize = 2;

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[derive(Clone, Serialize, Deserialize)]
struct FeltSlot {
    present: bool,
    #[serde(with = "hex_f")]
    value: F,
}

impl FeltSlot {
    fn none() -> Self {
        Self {
            present: false,
            value: ZERO,
        }
    }

    fn some(value: F) -> Self {
        Self {
            present: true,
            value,
        }
    }

    fn take(&mut self) -> Option<F> {
        if self.present {
            self.present = false;
            Some(self.value)
        } else {
            None
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct XmssNode {
    start_idx: u32,
    height: u8,
    #[serde(with = "hex_f")]
    value: F,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct RetainLevel {
    #[serde(with = "hex_f_vec")]
    nodes: Vec<F>,
    next: usize,
}

impl RetainLevel {
    fn push(&mut self, value: F) {
        self.nodes.push(value);
    }

    fn pop(&mut self) -> Option<F> {
        if self.next < self.nodes.len() {
            let value = self.nodes[self.next];
            self.next += 1;
            Some(value)
        } else {
            None
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct TreeHashState {
    target_height: u8,
    start_idx: u32,
    next_idx: u32,
    initialized: bool,
    finished: bool,
    node: FeltSlot,
    node_start_idx: u32,
    node_height: u8,
    stack: Vec<XmssNode>,
}

impl TreeHashState {
    fn new(target_height: usize) -> Self {
        Self {
            target_height: target_height as u8,
            start_idx: 0,
            next_idx: 0,
            initialized: false,
            finished: false,
            node: FeltSlot::none(),
            node_start_idx: 0,
            node_height: target_height as u8,
            stack: Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.initialized = false;
        self.finished = false;
        self.node = FeltSlot::none();
        self.node_start_idx = 0;
        self.node_height = self.target_height;
        self.stack.clear();
    }

    fn seed_completed(&mut self, node: &XmssNode) {
        self.initialized = false;
        self.finished = true;
        self.node = FeltSlot::some(node.value);
        self.node_start_idx = node.start_idx;
        self.node_height = node.height;
        self.next_idx = node.start_idx;
        self.stack.clear();
    }

    fn start(&mut self, start_idx: u32) {
        self.start_idx = start_idx;
        self.next_idx = start_idx;
        self.initialized = true;
        self.finished = false;
        self.node = FeltSlot::none();
        self.node_start_idx = 0;
        self.node_height = self.target_height;
        self.stack.clear();
    }

    fn take_ready(&mut self) -> Option<F> {
        let value = self.node.take()?;
        self.finished = false;
        self.initialized = false;
        Some(value)
    }

    fn step(&mut self, ask_j: &F, pub_seed: &F) {
        if !self.initialized || self.finished {
            return;
        }

        let mut node = XmssNode {
            start_idx: self.next_idx,
            height: 0,
            value: auth_leaf_hash_with_pub_seed(ask_j, pub_seed, self.next_idx),
        };
        self.next_idx += 1;

        while let Some(top) = self.stack.last() {
            if top.height != node.height {
                break;
            }
            let left = self.stack.pop().expect("stack element must exist");
            let level = u32::from(node.height);
            let node_idx = left.start_idx >> (level + 1);
            node = XmssNode {
                start_idx: left.start_idx,
                height: node.height + 1,
                value: xmss_tree_node_hash(pub_seed, level, node_idx, &left.value, &node.value),
            };
        }

        if node.height == self.target_height {
            self.finished = true;
            self.node = FeltSlot::some(node.value);
            self.node_start_idx = node.start_idx;
            self.node_height = node.height;
            self.stack.clear();
        } else {
            self.stack.push(node);
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct XmssBdsState {
    next_index: u32,
    #[serde(with = "hex_f_vec")]
    auth_path: Vec<F>,
    keep: Vec<FeltSlot>,
    treehash: Vec<TreeHashState>,
    retain: Vec<RetainLevel>,
}

impl XmssBdsState {
    fn new(ask_j: &F, pub_seed: &F) -> Result<(Self, F), String> {
        let mut auth_path = vec![ZERO; AUTH_DEPTH];
        let keep = vec![FeltSlot::none(); AUTH_DEPTH];
        let mut treehash: Vec<TreeHashState> = (0..(AUTH_DEPTH - XMSS_BDS_K))
            .map(TreeHashState::new)
            .collect();
        let mut retain = vec![RetainLevel::default(); AUTH_DEPTH];
        let mut stack: Vec<XmssNode> = Vec::new();

        for idx in 0..(AUTH_TREE_SIZE as u32) {
            let mut node = XmssNode {
                start_idx: idx,
                height: 0,
                value: auth_leaf_hash_with_pub_seed(ask_j, pub_seed, idx),
            };
            if idx == 1 {
                auth_path[0] = node.value;
            }
            while matches!(stack.last(), Some(top) if top.height == node.height) {
                let h = node.height as usize;
                let node_idx = idx >> h;
                if node_idx == 1 {
                    auth_path[h] = node.value;
                } else if node_idx == 3 && h < (AUTH_DEPTH - XMSS_BDS_K) {
                    treehash[h].seed_completed(&node);
                } else if node_idx >= 3
                    && (node_idx & 1) == 1
                    && h >= (AUTH_DEPTH - XMSS_BDS_K)
                    && h < (AUTH_DEPTH - 1)
                {
                    retain[h].push(node.value);
                }

                let left = stack.pop().expect("stack element must exist");
                let level = u32::from(node.height);
                let parent_node_idx = left.start_idx >> (level + 1);
                node = XmssNode {
                    start_idx: left.start_idx,
                    height: node.height + 1,
                    value: xmss_tree_node_hash(
                        pub_seed,
                        level,
                        parent_node_idx,
                        &left.value,
                        &node.value,
                    ),
                };
            }
            stack.push(node);
        }

        let root = stack
            .pop()
            .ok_or_else(|| "XMSS tree initialization produced no root".to_string())?;
        Ok((
            Self {
                next_index: 0,
                auth_path,
                keep,
                treehash,
                retain,
            },
            root.value,
        ))
    }

    fn from_index(ask_j: &F, pub_seed: &F, next_index: u32) -> Result<(Self, F), String> {
        if next_index as usize > AUTH_TREE_SIZE {
            return Err(format!("invalid XMSS index {}", next_index));
        }
        let (mut state, root) = Self::new(ask_j, pub_seed)?;
        for _ in 0..next_index {
            state.advance(ask_j, pub_seed)?;
        }
        Ok((state, root))
    }

    fn current_path(&self) -> &[F] {
        &self.auth_path
    }

    fn advance(&mut self, ask_j: &F, pub_seed: &F) -> Result<(), String> {
        let index = self.next_index;
        if index as usize >= AUTH_TREE_SIZE {
            return Err("XMSS keys exhausted".to_string());
        }
        if index as usize == AUTH_TREE_SIZE - 1 {
            self.next_index += 1;
            self.auth_path.clear();
            return Ok(());
        }

        let tau = index.trailing_ones() as usize;
        if tau < AUTH_DEPTH - 1 && ((index >> (tau + 1)) & 1) == 0 {
            self.keep[tau] = FeltSlot::some(self.auth_path[tau]);
        }

        if tau == 0 {
            self.auth_path[0] = auth_leaf_hash_with_pub_seed(ask_j, pub_seed, index);
        } else {
            let left = self.auth_path[tau - 1];
            let right = self.keep[tau - 1]
                .take()
                .ok_or_else(|| format!("missing BDS keep node at level {}", tau - 1))?;
            self.auth_path[tau] = xmss_tree_node_hash(
                pub_seed,
                (tau - 1) as u32,
                index >> (tau + 1),
                &left,
                &right,
            );

            for h in 0..tau {
                self.auth_path[h] = if h < (AUTH_DEPTH - XMSS_BDS_K) {
                    self.treehash[h]
                        .take_ready()
                        .ok_or_else(|| format!("missing BDS treehash node at level {}", h))?
                } else {
                    self.retain[h]
                        .pop()
                        .ok_or_else(|| format!("missing BDS retain node at level {}", h))?
                };
            }

            for h in 0..std::cmp::min(tau, AUTH_DEPTH - XMSS_BDS_K) {
                let start_idx = index + 1 + (3u32 << h);
                if (start_idx as usize) < AUTH_TREE_SIZE {
                    self.treehash[h].start(start_idx);
                } else {
                    self.treehash[h].clear();
                }
            }
        }

        self.next_index += 1;
        for instance in &mut self.treehash {
            instance.step(ask_j, pub_seed);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct WalletAddressState {
    index: u32,
    #[serde(with = "hex_f")]
    d_j: F,
    #[serde(with = "hex_f")]
    auth_root: F,
    #[serde(with = "hex_f")]
    auth_pub_seed: F,
    #[serde(with = "hex_f")]
    nk_tag: F,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bds: Option<XmssBdsState>,
    /// Legacy migration-only field from the old wallet format.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    next_auth_index: u32,
    /// Legacy migration-only field from the old wallet format.
    #[serde(default, with = "hex_f_vec", skip_serializing_if = "Vec::is_empty")]
    next_auth_path: Vec<F>,
}

impl WalletAddressState {
    fn ensure_bds(&mut self, ask_j: &F) -> Result<(), String> {
        if self.bds.is_some() {
            return Ok(());
        }
        let (state, root) =
            XmssBdsState::from_index(ask_j, &self.auth_pub_seed, self.next_auth_index)?;
        if root != self.auth_root {
            return Err(format!(
                "rebuilt XMSS root mismatch for address {}",
                self.index
            ));
        }
        if !self.next_auth_path.is_empty() && state.current_path() != self.next_auth_path.as_slice()
        {
            return Err(format!(
                "rebuilt XMSS path mismatch for address {} at index {}",
                self.index, self.next_auth_index
            ));
        }
        self.bds = Some(state);
        self.next_auth_index = 0;
        self.next_auth_path.clear();
        Ok(())
    }

    fn payment_address(&self, ek_v: &Ek, ek_d: &Ek) -> PaymentAddress {
        PaymentAddress {
            d_j: self.d_j,
            auth_root: self.auth_root,
            auth_pub_seed: self.auth_pub_seed,
            nk_tag: self.nk_tag,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        }
    }
}

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
    #[serde(default)]
    addresses: Vec<WalletAddressState>,
    addr_counter: u32,
    notes: Vec<Note>,
    scanned: usize,
    #[serde(default)]
    wots_key_indices: std::collections::HashMap<u32, u32>,
}

impl WalletFile {
    fn account(&self) -> Account {
        derive_account(&self.master_sk)
    }

    fn derive_address_state(
        &self,
        j: u32,
        next_auth_index: u32,
    ) -> Result<WalletAddressState, String> {
        panic!(
            "unexpected XMSS address derivation for j={} next_auth_index={} — default tests must use fixed prederived wallet/address fixtures",
            j, next_auth_index
        );
        let acc = self.account();
        let d_j = derive_address(&acc.incoming_seed, j);
        let ask_j = derive_ask(&acc.ask_base, j);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let (bds, auth_root) = XmssBdsState::from_index(&ask_j, &auth_pub_seed, next_auth_index)?;
        let nk_spend = derive_nk_spend(&acc.nk, &d_j);
        let nk_tag = derive_nk_tag(&nk_spend);

        Ok(WalletAddressState {
            index: j,
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag,
            bds: Some(bds),
            next_auth_index: 0,
            next_auth_path: Vec::new(),
        })
    }

    fn materialize_addresses(&mut self) -> Result<(), String> {
        if self.addresses.len() == self.addr_counter as usize {
            let ask_base = self.account().ask_base;
            for addr in &mut self.addresses {
                let ask_j = derive_ask(&ask_base, addr.index);
                addr.ensure_bds(&ask_j)?;
                if let Some(bds) = &addr.bds {
                    self.wots_key_indices.insert(addr.index, bds.next_index);
                }
            }
            return Ok(());
        }
        let existing = self.addresses.len() as u32;
        for j in existing..self.addr_counter {
            let next_auth_index = *self.wots_key_indices.get(&j).unwrap_or(&0);
            self.addresses
                .push(self.derive_address_state(j, next_auth_index)?);
        }
        let ask_base = self.account().ask_base;
        for addr in &mut self.addresses {
            let ask_j = derive_ask(&ask_base, addr.index);
            addr.ensure_bds(&ask_j)?;
            if let Some(bds) = &addr.bds {
                self.wots_key_indices.insert(addr.index, bds.next_index);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn next_wots_key(&mut self, addr_index: u32) -> u32 {
        self.reserve_next_auth(addr_index)
            .expect("XMSS keys should be available for test wallet")
            .0
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
        addr: &WalletAddressState,
        v: u64,
        rseed: F,
        cm: F,
        index: usize,
    ) -> Option<Note> {
        let nk_sp = derive_nk_spend(&acc.nk, &addr.d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &nk_tg);
        let rcm = derive_rcm(&rseed);
        if commit(&addr.d_j, v, &rcm, &otag) != cm {
            return None;
        }
        Some(Note {
            nk_spend: nk_sp,
            nk_tag: nk_tg,
            auth_root: addr.auth_root,
            d_j: addr.d_j,
            v,
            rseed,
            cm,
            index,
            addr_index: addr.index,
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
                    for addr in &self.addresses {
                        if let Some(note) =
                            self.recover_note_for_address(&acc, addr, v, rseed, nm.cm, nm.index)
                        {
                            return Some(note);
                        }
                    }
                }
            }
        }

        for addr in &self.addresses {
            let (_, dk_v_j, _, dk_d_j) = derive_kem_keys(&acc.incoming_seed, addr.index);
            if !detect(&nm.enc, &dk_d_j) {
                continue;
            }
            let Some((v, rseed, _memo)) = decrypt_memo(&nm.enc, &dk_v_j) else {
                continue;
            };
            if let Some(note) = self.recover_note_for_address(&acc, addr, v, rseed, nm.cm, nm.index)
            {
                return Some(note);
            }
        }

        None
    }

    /// Generate the next address and initialize its sequential XMSS auth state.
    fn next_address(&mut self) -> Result<(WalletAddressState, PaymentAddress), String> {
        let j = self.addr_counter;
        let state = if let Some(existing) = self.addresses.get(j as usize) {
            existing.clone()
        } else {
            self.derive_address_state(j, 0)?
        };
        let (ek_v, _, ek_d, _) = self.kem_keys(j);
        self.addr_counter += 1;
        if j as usize >= self.addresses.len() {
            self.addresses.push(state.clone());
        }
        let payment = state.payment_address(&ek_v, &ek_d);
        Ok((state, payment))
    }

    fn reserve_next_auth(&mut self, addr_index: u32) -> Result<(u32, F, F, Vec<F>), String> {
        let ask_base = self.account().ask_base;
        let addr = self
            .addresses
            .get_mut(addr_index as usize)
            .ok_or_else(|| format!("missing address record {}", addr_index))?;
        let ask_j = derive_ask(&ask_base, addr_index);
        addr.ensure_bds(&ask_j)?;
        let bds = addr
            .bds
            .as_mut()
            .ok_or_else(|| format!("missing XMSS traversal state for address {}", addr_index))?;
        let key_idx = bds.next_index;
        if (key_idx as usize) >= AUTH_TREE_SIZE {
            return Err(format!(
                "XMSS keys exhausted for address {} — generate a new address",
                addr_index
            ));
        }
        let path = bds.current_path().to_vec();
        let auth_root = addr.auth_root;
        let auth_pub_seed = addr.auth_pub_seed;
        bds.advance(&ask_j, &auth_pub_seed)?;
        self.wots_key_indices.insert(addr_index, bds.next_index);
        Ok((key_idx, auth_root, auth_pub_seed, path))
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
    let mut wallet: WalletFile =
        serde_json::from_str(&data).map_err(|e| format!("parse wallet: {}", e))?;
    wallet.materialize_addresses()?;
    Ok(wallet)
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
        addresses: vec![],
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
    let (state, addr) = w.next_address()?;

    save_wallet(path, &w)?;
    println!("Address #{}", state.index);
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
    use std::path::PathBuf;
    use std::sync::OnceLock;

    fn rebuild_address_state(master_sk: &F, j: u32, next_auth_index: u32) -> WalletAddressState {
        let acc = derive_account(master_sk);
        let d_j = derive_address(&acc.incoming_seed, j);
        let ask_j = derive_ask(&acc.ask_base, j);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let (bds, auth_root) = XmssBdsState::from_index(&ask_j, &auth_pub_seed, next_auth_index)
            .expect("fixture XMSS rebuild should succeed");
        let nk_spend = derive_nk_spend(&acc.nk, &d_j);
        let nk_tag = derive_nk_tag(&nk_spend);

        WalletAddressState {
            index: j,
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag,
            bds: Some(bds),
            next_auth_index: 0,
            next_auth_path: Vec::new(),
        }
    }

    fn base_wallet_fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("base_wallet_bds.json")
    }

    #[test]
    #[ignore = "the single full-tree depth-16 XMSS/BDS rebuild used to validate the checked-in wallet fixture"]
    fn test_base_wallet_bds_fixture_matches_rebuild() {
        let path = base_wallet_fixture_path();
        let fixture: WalletFile =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture read"))
                .expect("fixture parse");
        let rebuilt = rebuild_address_state(&fixture.master_sk, 0, 0);
        assert_eq!(fixture.addresses[0].index, 0);
        assert_eq!(
            serde_json::to_value(&fixture.addresses[0]).unwrap(),
            serde_json::to_value(&rebuilt).unwrap()
        );
    }

    fn base_test_wallet() -> &'static WalletFile {
        static BASE: OnceLock<WalletFile> = OnceLock::new();
        BASE.get_or_init(|| {
            let path = base_wallet_fixture_path();
            serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture read"))
                .expect("fixture parse")
        })
    }

    fn small_subtree_root(ask_j: &F, pub_seed: &F, start_idx: u32, height: u32) -> F {
        if height == 0 {
            return auth_leaf_hash(ask_j, start_idx);
        }
        let half = 1u32 << (height - 1);
        let left = small_subtree_root(ask_j, pub_seed, start_idx, height - 1);
        let right = small_subtree_root(ask_j, pub_seed, start_idx + half, height - 1);
        xmss_tree_node_hash(pub_seed, height - 1, start_idx >> height, &left, &right)
    }

    fn test_wallet(addr_counter: u32, legacy: Option<([u8; 64], [u8; 64])>) -> WalletFile {
        let base = base_test_wallet();
        let (kem_seed_v, kem_seed_d) = legacy
            .map(|(v, d)| (v.to_vec(), d.to_vec()))
            .unwrap_or_else(|| (vec![], vec![]));
        let cached = std::cmp::min(addr_counter as usize, base.addresses.len());
        let mut wallet = WalletFile {
            master_sk: base.master_sk,
            kem_seed_v,
            kem_seed_d,
            addresses: base.addresses[..cached].to_vec(),
            addr_counter,
            notes: vec![],
            scanned: 0,
            wots_key_indices: std::collections::HashMap::new(),
        };
        if addr_counter as usize > cached {
            wallet
                .materialize_addresses()
                .expect("test wallet address materialization should succeed");
        }
        wallet
    }

    fn wallet_with_single_note(note_value: u64) -> (WalletFile, F) {
        let mut w = test_wallet(1, None);
        let addr = w.addresses[0].clone();
        let acc = w.account();
        let nk_sp = derive_nk_spend(&acc.nk, &addr.d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &nk_tg);
        let rseed = random_felt();
        let rcm = derive_rcm(&rseed);
        let cm = commit(&addr.d_j, note_value, &rcm, &otag);
        w.notes.push(Note {
            nk_spend: nk_sp,
            nk_tag: nk_tg,
            auth_root: addr.auth_root,
            d_j: addr.d_j,
            v: note_value,
            rseed,
            cm,
            index: 0,
            addr_index: 0,
        });
        (w, cm)
    }

    fn note_memo_for_wallet_address(
        w: &WalletFile,
        j: u32,
        value: u64,
        rseed: F,
        memo: Option<&[u8]>,
    ) -> NoteMemo {
        let acc = w.account();
        let addr = &w.addresses[j as usize];
        let nk_sp = derive_nk_spend(&acc.nk, &addr.d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &nk_tg);
        let rcm = derive_rcm(&rseed);
        let cm = commit(&addr.d_j, value, &rcm, &otag);
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
    fn test_xmss_bds_advances_fixture_state_without_rebuild() {
        let mut w = test_wallet(1, None);
        let initial_root = w.addresses[0].auth_root;
        let initial_path = w.addresses[0]
            .bds
            .as_ref()
            .expect("fixture should include BDS state")
            .current_path()
            .to_vec();
        assert_eq!(initial_path.len(), AUTH_DEPTH);

        let first_idx = w.next_wots_key(0);
        assert_eq!(first_idx, 0);
        assert_eq!(w.wots_key_indices.get(&0), Some(&1));
        assert_eq!(w.addresses[0].auth_root, initial_root);
        let after_first = w.addresses[0]
            .bds
            .as_ref()
            .expect("BDS should remain populated after first advance");
        assert_eq!(after_first.next_index, 1);
        assert_eq!(after_first.current_path().len(), AUTH_DEPTH);
        assert_ne!(after_first.current_path(), initial_path.as_slice());

        let path_after_first = after_first.current_path().to_vec();
        let second_idx = w.next_wots_key(0);
        assert_eq!(second_idx, 1);
        assert_eq!(w.wots_key_indices.get(&0), Some(&2));
        assert_eq!(w.addresses[0].auth_root, initial_root);
        let after_second = w.addresses[0]
            .bds
            .as_ref()
            .expect("BDS should remain populated after second advance");
        assert_eq!(after_second.next_index, 2);
        assert_eq!(after_second.current_path().len(), AUTH_DEPTH);
        assert_ne!(after_second.current_path(), path_after_first.as_slice());
    }

    #[test]
    fn test_treehash_matches_small_reference_subtrees() {
        let mut master_sk = ZERO;
        master_sk[0] = 0x44;
        let acc = derive_account(&master_sk);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let pub_seed = derive_auth_pub_seed(&ask_j);

        for (height, start_idx) in [(0u32, 5u32), (1, 6), (2, 8), (3, 16)] {
            let expected = small_subtree_root(&ask_j, &pub_seed, start_idx, height);
            let mut treehash = TreeHashState::new(height as usize);
            treehash.start(start_idx);
            while !treehash.finished {
                treehash.step(&ask_j, &pub_seed);
            }
            assert!(treehash.node.present, "treehash should produce a node");
            assert_eq!(
                treehash.node.value, expected,
                "treehash root mismatch at height {} start {}",
                height, start_idx
            );
            assert_eq!(treehash.node_start_idx, start_idx);
            assert_eq!(treehash.node_height, height as u8);
        }
    }

    #[test]
    fn test_export_detect_uses_detect_root_not_incoming_seed() {
        let w = test_wallet(0, None);
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
        let addr = &w.addresses[0];
        let nk_sp = derive_nk_spend(&acc.nk, &addr.d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &nk_tg);
        let rseed = random_felt();
        let rcm = derive_rcm(&rseed);
        let cm = commit(&addr.d_j, 77, &rcm, &otag);
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
        let addr = &w.addresses[0];
        let nk_sp = derive_nk_spend(&acc.nk, &addr.d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &nk_tg);
        let rseed = random_felt();
        let rcm = derive_rcm(&rseed);
        let cm = commit(&addr.d_j, 91, &rcm, &otag);
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
        let d_j = w.addresses[0].d_j;
        let (ek_v, _, ek_d, _) = w.kem_keys(0);
        let mut other_master_sk = ZERO;
        other_master_sk[0] = 0x91;
        let other_acc = derive_account(&other_master_sk);
        let other_d = derive_address(&other_acc.incoming_seed, 0);
        let other_ask = derive_ask(&other_acc.ask_base, 0);
        let other_auth_pub_seed = derive_auth_pub_seed(&other_ask);
        let other_auth_root = hash_two(&felt_tag(b"wrong-otag"), &other_auth_pub_seed);
        let other_nk_sp = derive_nk_spend(&other_acc.nk, &other_d);
        let other_nk_tag = derive_nk_tag(&other_nk_sp);
        let other_owner_tag = owner_tag(&other_auth_root, &other_auth_pub_seed, &other_nk_tag);
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
        let w = test_wallet(1, None);

        save_wallet(wallet_path_str, &w).expect("wallet should save");
        let loaded = load_wallet(wallet_path_str).expect("wallet should load");

        assert_eq!(loaded.addr_counter, 1);
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
        let w = test_wallet(3, None);
        let state0 = w.addresses[0].clone();
        let (ek_v0, _, ek_d0, _) = w.kem_keys(state0.index);
        let state1 = w.addresses[1].clone();
        let (ek_v1, _, ek_d1, _) = w.kem_keys(state1.index);

        assert_ne!(state0.index, state1.index);
        assert_ne!(state0.d_j, state1.d_j);
        assert_ne!(state0.auth_root, state1.auth_root);
        assert_ne!(state0.nk_tag, state1.nk_tag);
        assert_ne!(ek_v0.to_bytes(), ek_v1.to_bytes());
        assert_ne!(ek_d0.to_bytes(), ek_d1.to_bytes());
    }

    #[test]
    fn test_next_wots_key_is_monotonic() {
        let mut w = test_wallet(1, None);
        assert_eq!(w.next_wots_key(0), 0);
        assert_eq!(w.next_wots_key(0), 1);
        assert_eq!(w.next_wots_key(0), 2);
    }

    #[test]
    fn test_next_wots_key_exhausts_at_last_leaf() {
        let mut w = test_wallet(1, None);
        let last_idx = (AUTH_TREE_SIZE - 1) as u32;
        w.addresses[0].bds = Some(XmssBdsState {
            next_index: last_idx,
            auth_path: vec![ZERO; AUTH_DEPTH],
            keep: vec![FeltSlot::none(); AUTH_DEPTH],
            treehash: (0..(AUTH_DEPTH - XMSS_BDS_K))
                .map(TreeHashState::new)
                .collect(),
            retain: vec![RetainLevel::default(); AUTH_DEPTH],
        });
        w.addresses[0].next_auth_index = 0;
        w.addresses[0].next_auth_path.clear();
        w.wots_key_indices.insert(0, last_idx);
        assert_eq!(w.next_wots_key(0), last_idx);
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

        let (mut w, cm) = wallet_with_single_note(50);
        w.addr_counter = 2;
        w.addresses = test_wallet(2, None).addresses;
        save_wallet(wallet_path_str, &w).expect("wallet should save");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
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

        let (mut w, cm) = wallet_with_single_note(50);
        w.addr_counter = 2;
        w.addresses = test_wallet(2, None).addresses;
        save_wallet(wallet_path_str, &w).expect("wallet should save");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
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
        let (_state, addr) = w.next_address()?;
        (addr, true)
    };

    // Build the proof if --prove is set.
    // Shield witness: [v_pub, cm_new, sender, memo_ct_hash, auth_root, nk_tag, d_j, rseed]
    // Note: with TrustMeBro, the ledger generates rseed and computes the commitment.
    // With a real proof, the client must do this and prove it.
    let (proof, shield_cm, shield_enc) = if !pc.skip_proof {
        let rseed = random_felt();
        let rcm = derive_rcm(&rseed);
        let otag = owner_tag(&address.auth_root, &address.auth_pub_seed, &address.nk_tag);
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
            felt_u64_to_hex(9), // Array length prefix
            felt_u64_to_hex(amount),
            felt_to_hex(&cm),
            felt_to_hex(&sender_f),
            felt_to_hex(&memo_ct_hash_f),
            felt_to_hex(&address.auth_root),
            felt_to_hex(&address.auth_pub_seed),
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
    let otag_1 = owner_tag(
        &recipient.auth_root,
        &recipient.auth_pub_seed,
        &recipient.nk_tag,
    );
    let cm_1 = commit(&recipient.d_j, amount, &rcm_1, &otag_1);
    let memo_bytes = memo.as_deref().map(|s| s.as_bytes());
    let enc_1 = encrypt_note(amount, &rseed_1, memo_bytes, &ek_v_recv, &ek_d_recv);

    // Build output 2: change to self (per-address KEM keys)
    let (change_state, _change_addr) = w.next_address()?;
    let (ek_v_c, _, ek_d_c, _) = w.kem_keys(change_state.index);
    let rseed_2 = random_felt();
    let rcm_2 = derive_rcm(&rseed_2);
    let otag_2 = owner_tag(
        &change_state.auth_root,
        &change_state.auth_pub_seed,
        &change_state.nk_tag,
    );
    let cm_2 = commit(&change_state.d_j, change, &rcm_2, &otag_2);
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
        let mut auth_pub_seeds: Vec<F> = vec![];
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
            let (key_idx, auth_root, auth_pub_seed, path) = w.reserve_next_auth(addr_idx)?;
            if auth_root != stored_auth_root {
                return Err(format!(
                    "auth_root mismatch for note at tree index {}",
                    tree_idx
                ));
            }
            auth_paths.push(path);
            auth_pub_seeds.push(auth_pub_seed);
            let (sig, _pk, _digits) = wots_sign(&ask_j, key_idx, &sighash);
            wots_sigs.push(sig);
            wots_key_indices.push(key_idx);
        }

        let total_fields = 3 + 9 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS + 16;
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
            args.push(felt_to_hex(&auth_pub_seeds[idx]));
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

        // Output 1
        args.push(felt_to_hex(&cm_1));
        args.push(felt_to_hex(&recipient.d_j));
        args.push(felt_u64_to_hex(amount));
        args.push(felt_to_hex(&rseed_1));
        args.push(felt_to_hex(&recipient.auth_root));
        args.push(felt_to_hex(&recipient.auth_pub_seed));
        args.push(felt_to_hex(&recipient.nk_tag));
        args.push(felt_to_hex(&memo_ct_hash(&enc_1)));

        // Output 2
        args.push(felt_to_hex(&cm_2));
        args.push(felt_to_hex(&change_state.d_j));
        args.push(felt_u64_to_hex(change));
        args.push(felt_to_hex(&rseed_2));
        args.push(felt_to_hex(&change_state.auth_root));
        args.push(felt_to_hex(&change_state.auth_pub_seed));
        args.push(felt_to_hex(&change_state.nk_tag));
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
        auth_pub_seed: F,
        nk_tag: F,
        mh: F,
    }
    let (cm_change, enc_change, change_data) = if change > 0 {
        let (change_state, _change_addr) = w.next_address()?;
        let (ek_v_c, _, ek_d_c, _) = w.kem_keys(change_state.index);
        let rseed_c = random_felt();
        let rcm_c = derive_rcm(&rseed_c);
        let otag_c = owner_tag(
            &change_state.auth_root,
            &change_state.auth_pub_seed,
            &change_state.nk_tag,
        );
        let cm = commit(&change_state.d_j, change, &rcm_c, &otag_c);
        let enc = encrypt_note(change, &rseed_c, None, &ek_v_c, &ek_d_c);
        let mh = memo_ct_hash(&enc);
        let cd = ChangeData {
            d_j: change_state.d_j,
            rseed: rseed_c,
            auth_root: change_state.auth_root,
            auth_pub_seed: change_state.auth_pub_seed,
            nk_tag: change_state.nk_tag,
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
        let mut auth_pub_seeds: Vec<F> = vec![];

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
            let (key_idx, auth_root, auth_pub_seed, path) = w.reserve_next_auth(addr_idx)?;
            if auth_root != stored_auth_root {
                return Err(format!(
                    "auth_root mismatch for note at tree index {}",
                    tree_idx
                ));
            }
            auth_paths.push(path);
            auth_pub_seeds.push(auth_pub_seed);
            let (sig, _pk, _digits) = wots_sign(&ask_j, key_idx, &sighash);
            wots_sigs.push(sig);
            wots_key_indices.push(key_idx);
        }

        let total = 5 + 9 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS + 8;
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
            args.push(felt_to_hex(&auth_pub_seeds[idx]));
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

        args.push(felt_u64_to_hex(has_change_val));
        if let Some(cd) = &change_data {
            args.push(felt_to_hex(&cd.d_j));
            args.push(felt_u64_to_hex(change));
            args.push(felt_to_hex(&cd.rseed));
            args.push(felt_to_hex(&cd.auth_root));
            args.push(felt_to_hex(&cd.auth_pub_seed));
            args.push(felt_to_hex(&cd.nk_tag));
            args.push(felt_to_hex(&cd.mh));
        } else {
            for _ in 0..7 {
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
