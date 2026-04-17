use clap::{Parser, Subcommand};
use ml_kem::KeyExport;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{inbox::ExternalMessageFrame, smart_rollup::SmartRollupAddress};
use tzel_services::kernel_wire::{
    encode_kernel_inbox_message, KernelInboxMessage, KernelShieldReq, KernelStarkProof,
    KernelTransferReq, KernelUnshieldReq, KernelWithdrawReq,
};
use tzel_services::operator_api::{
    RollupSubmission, RollupSubmissionKind, RollupSubmissionStatus, RollupSubmissionTransport,
    SubmitRollupMessageReq, SubmitRollupMessageResp,
};
use tzel_services::*;
use tzel_verifier::{encode_verify_meta, ProofBundle as VerifyProofBundle};

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

    fn lowest_node_height(&self) -> Option<u8> {
        if !self.initialized || self.finished {
            return None;
        }
        Some(
            self.stack
                .iter()
                .map(|node| node.height)
                .min()
                .unwrap_or(self.target_height),
        )
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

#[cfg(test)]
static FULL_XMSS_REBUILD_TEST_GUARD: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();
#[cfg(test)]
static ALLOW_FULL_XMSS_REBUILD_IN_TESTS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn full_xmss_test_trap_enabled() -> bool {
    !ALLOW_FULL_XMSS_REBUILD_IN_TESTS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(not(test))]
fn full_xmss_test_trap_enabled() -> bool {
    false
}

fn assert_full_xmss_bds_rebuild_allowed(op: &str, depth: usize) {
    let env_trap = std::env::var_os("TZEL_TRAP_FULL_XMSS_REBUILDS").is_some()
        && std::env::var_os("TZEL_ALLOW_FULL_XMSS_REBUILD").is_none();
    let test_trap = full_xmss_test_trap_enabled();
    if depth == AUTH_DEPTH && (env_trap || test_trap) {
        panic!(
            "unexpected full depth-{} XMSS/BDS rebuild via {} — default tests must use fixed fixtures or small-depth helpers",
            AUTH_DEPTH, op
        );
    }
}

impl XmssBdsState {
    fn new_with_params(
        ask_j: &F,
        pub_seed: &F,
        depth: usize,
        k: usize,
    ) -> Result<(Self, F), String> {
        assert_full_xmss_bds_rebuild_allowed("XmssBdsState::new_with_params", depth);
        if depth == 0 {
            return Err("XMSS depth must be positive".to_string());
        }
        if k >= depth {
            return Err(format!("invalid XMSS BDS k={} for depth {}", k, depth));
        }

        let auth_tree_size = 1usize << depth;
        let mut auth_path = vec![ZERO; depth];
        let keep = vec![FeltSlot::none(); depth];
        let mut treehash: Vec<TreeHashState> = (0..(depth - k)).map(TreeHashState::new).collect();
        let mut retain = vec![RetainLevel::default(); depth];
        let mut stack: Vec<XmssNode> = Vec::new();

        for idx in 0..(auth_tree_size as u32) {
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
                } else if node_idx == 3 && h < (depth - k) {
                    treehash[h].seed_completed(&node);
                } else if node_idx >= 3
                    && (node_idx & 1) == 1
                    && h >= (depth - k)
                    && h < (depth - 1)
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
        Self::from_index_with_params(ask_j, pub_seed, next_index, AUTH_DEPTH, XMSS_BDS_K)
    }

    fn from_index_with_params(
        ask_j: &F,
        pub_seed: &F,
        next_index: u32,
        depth: usize,
        k: usize,
    ) -> Result<(Self, F), String> {
        assert_full_xmss_bds_rebuild_allowed("XmssBdsState::from_index_with_params", depth);
        let auth_tree_size = 1usize << depth;
        if next_index as usize > auth_tree_size {
            return Err(format!("invalid XMSS index {}", next_index));
        }
        let (mut state, root) = Self::new_with_params(ask_j, pub_seed, depth, k)?;
        for _ in 0..next_index {
            state.advance(ask_j, pub_seed)?;
        }
        Ok((state, root))
    }

    fn current_path(&self) -> &[F] {
        &self.auth_path
    }

    fn advance(&mut self, ask_j: &F, pub_seed: &F) -> Result<(), String> {
        let depth = self.auth_path.len();
        let treehash_levels = self.treehash.len();
        let auth_tree_size = 1usize << depth;
        let index = self.next_index;
        if index as usize >= auth_tree_size {
            return Err("XMSS keys exhausted".to_string());
        }
        if index as usize == auth_tree_size - 1 {
            self.next_index += 1;
            self.auth_path.clear();
            return Ok(());
        }

        let tau = index.trailing_ones() as usize;
        if tau < depth - 1 && ((index >> (tau + 1)) & 1) == 0 {
            self.keep[tau] = FeltSlot::some(self.auth_path[tau]);
        }

        if tau == 0 {
            self.auth_path[0] = auth_leaf_hash_with_pub_seed(ask_j, pub_seed, index);
        } else {
            let left = self.auth_path[tau - 1];
            let right = self.keep[tau - 1]
                .take()
                .ok_or_else(|| format!("missing BDS keep node at level {}", tau - 1))?;
            let parent_start = index + 1 - (1u32 << tau);
            self.auth_path[tau] = xmss_tree_node_hash(
                pub_seed,
                (tau - 1) as u32,
                parent_start >> tau,
                &left,
                &right,
            );

            for h in 0..tau {
                self.auth_path[h] = if h < treehash_levels {
                    self.treehash[h]
                        .take_ready()
                        .ok_or_else(|| format!("missing BDS treehash node at level {}", h))?
                } else {
                    self.retain[h]
                        .pop()
                        .ok_or_else(|| format!("missing BDS retain node at level {}", h))?
                };
            }

            for h in 0..std::cmp::min(tau, treehash_levels) {
                let start_idx = index + 1 + (3u32 << h);
                if (start_idx as usize) < auth_tree_size {
                    self.treehash[h].start(start_idx);
                } else {
                    self.treehash[h].clear();
                }
            }
        }

        self.next_index += 1;
        for _ in 0..(treehash_levels / 2) {
            let mut best_idx = None;
            let mut best_height = u8::MAX;
            let mut best_start = u32::MAX;

            for (idx, instance) in self.treehash.iter().enumerate() {
                let Some(height) = instance.lowest_node_height() else {
                    continue;
                };
                if height < best_height
                    || (height == best_height && instance.start_idx < best_start)
                {
                    best_idx = Some(idx);
                    best_height = height;
                    best_start = instance.start_idx;
                }
            }

            let Some(best_idx) = best_idx else {
                break;
            };
            self.treehash[best_idx].step(ask_j, pub_seed);
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
        self.ensure_bds_with(ask_j, |ask_j, pub_seed, next_auth_index| {
            XmssBdsState::from_index(ask_j, pub_seed, next_auth_index)
        })
    }

    fn ensure_bds_with<R>(&mut self, ask_j: &F, rebuild: R) -> Result<(), String>
    where
        R: FnOnce(&F, &F, u32) -> Result<(XmssBdsState, F), String>,
    {
        if self.bds.is_some() {
            return Ok(());
        }
        let (state, root) = rebuild(ask_j, &self.auth_pub_seed, self.next_auth_index)?;
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
    #[serde(default)]
    pending_spends: Vec<PendingSpend>,
}

#[derive(Serialize, Deserialize)]
struct WalletXmssFloor {
    #[serde(with = "hex_f")]
    wallet_fingerprint: F,
    addr_counter: u32,
    #[serde(default)]
    wots_key_indices: std::collections::HashMap<u32, u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PendingSpend {
    #[serde(with = "hex_f_vec")]
    nullifiers: Vec<F>,
    description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_hash: Option<String>,
}

const WATCH_WALLET_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct WatchAddressRecord {
    index: u32,
    #[serde(with = "hex_f")]
    d_j: F,
    #[serde(with = "hex_f")]
    auth_root: F,
    #[serde(with = "hex_f")]
    auth_pub_seed: F,
    #[serde(with = "hex_f")]
    nk_tag: F,
}

impl From<&WalletAddressState> for WatchAddressRecord {
    fn from(value: &WalletAddressState) -> Self {
        Self {
            index: value.index,
            d_j: value.d_j,
            auth_root: value.auth_root,
            auth_pub_seed: value.auth_pub_seed,
            nk_tag: value.nk_tag,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum WatchKeyMaterial {
    Detect {
        version: u16,
        #[serde(with = "hex_f")]
        detect_root: F,
        addr_count: u32,
    },
    View {
        version: u16,
        #[serde(with = "hex_f")]
        incoming_seed: F,
        addresses: Vec<WatchAddressRecord>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DetectedNoteRecord {
    index: usize,
    addr_index: u32,
    #[serde(with = "hex_f")]
    cm: F,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ViewedNoteRecord {
    index: usize,
    addr_index: u32,
    #[serde(with = "hex_f")]
    cm: F,
    value: u64,
    #[serde(default, with = "hex_bytes")]
    memo: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum WatchWalletFile {
    Detect {
        version: u16,
        #[serde(with = "hex_f")]
        detect_root: F,
        addr_count: u32,
        scanned: usize,
        matches: Vec<DetectedNoteRecord>,
    },
    View {
        version: u16,
        #[serde(with = "hex_f")]
        incoming_seed: F,
        addresses: Vec<WatchAddressRecord>,
        scanned: usize,
        notes: Vec<ViewedNoteRecord>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct WatchWalletStatus {
    mode: &'static str,
    scanned: usize,
    tracked: usize,
    incoming_total: u128,
    spend_status: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    matches: Vec<DetectedNoteRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<ViewedNoteRecord>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct WatchSyncSummary {
    found: usize,
    next_cursor: usize,
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
        #[cfg(test)]
        panic!(
            "unexpected XMSS address derivation for j={} next_auth_index={} — default tests must use fixed prederived wallet/address fixtures",
            j, next_auth_index
        );

        #[cfg(not(test))]
        let acc = self.account();
        #[cfg(not(test))]
        let d_j = derive_address(&acc.incoming_seed, j);
        #[cfg(not(test))]
        let ask_j = derive_ask(&acc.ask_base, j);
        #[cfg(not(test))]
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        #[cfg(not(test))]
        let (bds, auth_root) = XmssBdsState::from_index(&ask_j, &auth_pub_seed, next_auth_index)?;
        #[cfg(not(test))]
        let nk_spend = derive_nk_spend(&acc.nk, &d_j);
        #[cfg(not(test))]
        let nk_tag = derive_nk_tag(&nk_spend);

        #[cfg(not(test))]
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

    fn pending_nullifier_set(&self) -> std::collections::HashSet<F> {
        self.pending_spends
            .iter()
            .flat_map(|pending| pending.nullifiers.iter().copied())
            .collect()
    }

    fn available_balance(&self) -> u128 {
        let pending = self.pending_nullifier_set();
        self.notes
            .iter()
            .filter(|note| !pending.contains(&note_nullifier(note)))
            .map(|note| note.v as u128)
            .sum()
    }

    fn pending_outgoing_balance(&self) -> u128 {
        let pending = self.pending_nullifier_set();
        self.notes
            .iter()
            .filter(|note| pending.contains(&note_nullifier(note)))
            .map(|note| note.v as u128)
            .sum()
    }

    fn register_pending_spend(
        &mut self,
        nullifiers: Vec<F>,
        description: String,
        operation_hash: Option<String>,
    ) {
        self.pending_spends.push(PendingSpend {
            nullifiers,
            description,
            operation_hash,
        });
    }

    fn wallet_xmss_floor(&self) -> WalletXmssFloor {
        let mut wots_key_indices = self.wots_key_indices.clone();
        for addr in &self.addresses {
            let next_index = addr
                .bds
                .as_ref()
                .map(|bds| bds.next_index)
                .unwrap_or(addr.next_auth_index);
            wots_key_indices
                .entry(addr.index)
                .and_modify(|current| *current = (*current).max(next_index))
                .or_insert(next_index);
        }
        WalletXmssFloor {
            wallet_fingerprint: hash(&self.master_sk),
            addr_counter: self.addr_counter,
            wots_key_indices,
        }
    }

    /// Select notes to cover at least `amount`. Returns indices into self.notes.
    fn select_notes(&self, amount: u64) -> Result<Vec<usize>, String> {
        let pending = self.pending_nullifier_set();
        let mut indexed: Vec<(usize, u64)> = self
            .notes
            .iter()
            .enumerate()
            .filter(|(_, note)| !pending.contains(&note_nullifier(note)))
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
            "insufficient funds: have {} available ({} pending) need {}",
            self.available_balance(),
            self.pending_outgoing_balance(),
            amount
        ))
    }
}

impl WatchKeyMaterial {
    fn from_detect_wallet(wallet: &WalletFile) -> Self {
        let detect_root = derive_detect_root(&wallet.account().incoming_seed);
        Self::Detect {
            version: WATCH_WALLET_VERSION,
            detect_root,
            addr_count: wallet.addr_counter,
        }
    }

    fn from_view_wallet(wallet: &WalletFile) -> Self {
        let addresses = wallet
            .addresses
            .iter()
            .map(WatchAddressRecord::from)
            .collect();
        Self::View {
            version: WATCH_WALLET_VERSION,
            incoming_seed: wallet.account().incoming_seed,
            addresses,
        }
    }
}

impl WatchWalletFile {
    fn from_material(material: WatchKeyMaterial) -> Self {
        match material {
            WatchKeyMaterial::Detect {
                version,
                detect_root,
                addr_count,
            } => Self::Detect {
                version,
                detect_root,
                addr_count,
                scanned: 0,
                matches: Vec::new(),
            },
            WatchKeyMaterial::View {
                version,
                incoming_seed,
                addresses,
            } => Self::View {
                version,
                incoming_seed,
                addresses,
                scanned: 0,
                notes: Vec::new(),
            },
        }
    }

    fn status(&self) -> WatchWalletStatus {
        match self {
            WatchWalletFile::Detect {
                scanned, matches, ..
            } => WatchWalletStatus {
                mode: "detect",
                scanned: *scanned,
                tracked: matches.len(),
                incoming_total: 0,
                spend_status: "candidate_matches_only",
                matches: matches.clone(),
                notes: Vec::new(),
            },
            WatchWalletFile::View { scanned, notes, .. } => WatchWalletStatus {
                mode: "view",
                scanned: *scanned,
                tracked: notes.len(),
                incoming_total: notes.iter().map(|note| note.value as u128).sum(),
                spend_status: "unavailable_without_spend_key",
                matches: Vec::new(),
                notes: notes.clone(),
            },
        }
    }
}

fn detect_record_for_note(
    detect_root: &F,
    addr_count: u32,
    nm: &NoteMemo,
) -> Option<DetectedNoteRecord> {
    for addr_index in 0..addr_count {
        let (_, dk_d) = derive_kem_detect_keys_from_root(detect_root, addr_index);
        if detect(&nm.enc, &dk_d) {
            return Some(DetectedNoteRecord {
                index: nm.index,
                addr_index,
                cm: nm.cm,
            });
        }
    }
    None
}

fn view_record_for_note(
    incoming_seed: &F,
    addresses: &[WatchAddressRecord],
    nm: &NoteMemo,
) -> Option<ViewedNoteRecord> {
    for addr in addresses {
        let (_, dk_v, _, dk_d) = derive_kem_keys(incoming_seed, addr.index);
        if !detect(&nm.enc, &dk_d) {
            continue;
        }
        let Some((value, rseed, memo)) = decrypt_memo(&nm.enc, &dk_v) else {
            continue;
        };
        let rcm = derive_rcm(&rseed);
        let owner = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &addr.nk_tag);
        if commit(&addr.d_j, value, &rcm, &owner) != nm.cm {
            continue;
        }
        return Some(ViewedNoteRecord {
            index: nm.index,
            addr_index: addr.index,
            cm: nm.cm,
            value,
            memo: trim_decrypted_memo(memo),
        });
    }
    None
}

fn trim_decrypted_memo(mut memo: Vec<u8>) -> Vec<u8> {
    while memo.last().copied() == Some(0) {
        memo.pop();
    }
    memo
}

fn apply_watch_feed(watch: &mut WatchWalletFile, feed: &NotesFeedResp) -> WatchSyncSummary {
    let mut summary = WatchSyncSummary {
        found: 0,
        next_cursor: feed.next_cursor,
    };
    match watch {
        WatchWalletFile::Detect {
            detect_root,
            addr_count,
            scanned,
            matches,
            ..
        } => {
            let mut known: std::collections::HashSet<(usize, F)> =
                matches.iter().map(|m| (m.index, m.cm)).collect();
            for nm in &feed.notes {
                let Some(record) = detect_record_for_note(detect_root, *addr_count, nm) else {
                    continue;
                };
                if known.insert((record.index, record.cm)) {
                    matches.push(record);
                    summary.found += 1;
                }
            }
            *scanned = feed.next_cursor;
        }
        WatchWalletFile::View {
            incoming_seed,
            addresses,
            scanned,
            notes,
            ..
        } => {
            let mut known: std::collections::HashSet<(usize, F)> =
                notes.iter().map(|n| (n.index, n.cm)).collect();
            for nm in &feed.notes {
                let Some(record) = view_record_for_note(incoming_seed, addresses, nm) else {
                    continue;
                };
                if known.insert((record.index, record.cm)) {
                    notes.push(record);
                    summary.found += 1;
                }
            }
            *scanned = feed.next_cursor;
        }
    }
    summary
}

fn note_nullifier(note: &Note) -> F {
    nullifier(&note.nk_spend, &note.cm, note.index as u64)
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

fn wallet_xmss_floor_path(path: &str) -> PathBuf {
    PathBuf::from(format!("{}.xmss-floor", path))
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
    warn_if_wallet_permissions_are_too_open(path);
    let data = std::fs::read_to_string(path).map_err(|e| format!("read wallet: {}", e))?;
    let mut wallet: WalletFile =
        serde_json::from_str(&data).map_err(|e| format!("parse wallet: {}", e))?;
    enforce_wallet_xmss_floor(path, &wallet)?;
    wallet.materialize_addresses()?;
    Ok(wallet)
}

fn load_private_json<T: DeserializeOwned>(path: &str, label: &str) -> Result<T, String> {
    warn_if_wallet_permissions_are_too_open(path);
    let data = std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", label, e))?;
    serde_json::from_str(&data).map_err(|e| format!("parse {}: {}", label, e))
}

fn save_private_json<T: Serialize>(path: &str, value: &T, label: &str) -> Result<(), String> {
    let data =
        serde_json::to_string_pretty(value).map_err(|e| format!("serialize {}: {}", label, e))?;
    let output_path = std::path::Path::new(path);
    let tmp = std::path::PathBuf::from(format!("{}.tmp", path));
    let mut file =
        std::fs::File::create(&tmp).map_err(|e| format!("create {} tmp: {}", label, e))?;
    file.write_all(data.as_bytes())
        .map_err(|e| format!("write {} tmp: {}", label, e))?;
    file.sync_all()
        .map_err(|e| format!("fsync {} tmp: {}", label, e))?;
    drop(file);
    std::fs::rename(&tmp, output_path).map_err(|e| format!("rename {}: {}", label, e))?;
    set_wallet_permissions(output_path)?;
    sync_parent_dir(output_path)
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
    set_wallet_permissions(wallet_path)?;
    sync_parent_dir(wallet_path)?;
    save_wallet_xmss_floor(path, &w.wallet_xmss_floor())
}

fn load_watch_wallet(path: &str) -> Result<WatchWalletFile, String> {
    load_private_json(path, "watch wallet")
}

fn save_watch_wallet(path: &str, watch: &WatchWalletFile) -> Result<(), String> {
    save_private_json(path, watch, "watch wallet")
}

fn save_wallet_xmss_floor(path: &str, floor: &WalletXmssFloor) -> Result<(), String> {
    let data =
        serde_json::to_string_pretty(floor).map_err(|e| format!("serialize floor: {}", e))?;
    let floor_path = wallet_xmss_floor_path(path);
    let tmp = PathBuf::from(format!("{}.tmp", floor_path.display()));
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create floor tmp: {}", e))?;
    file.write_all(data.as_bytes())
        .map_err(|e| format!("write floor tmp: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("fsync floor tmp: {}", e))?;
    drop(file);
    std::fs::rename(&tmp, &floor_path).map_err(|e| format!("rename floor: {}", e))?;
    set_wallet_permissions(&floor_path)?;
    sync_parent_dir(&floor_path)
}

fn current_wallet_wots_floor(wallet: &WalletFile, addr_index: u32) -> u32 {
    wallet
        .wots_key_indices
        .get(&addr_index)
        .copied()
        .or_else(|| {
            wallet
                .addresses
                .iter()
                .find(|addr| addr.index == addr_index)
                .map(|addr| {
                    addr.bds
                        .as_ref()
                        .map(|bds| bds.next_index)
                        .unwrap_or(addr.next_auth_index)
                })
        })
        .unwrap_or(0)
}

fn enforce_wallet_xmss_floor(path: &str, wallet: &WalletFile) -> Result<(), String> {
    let floor_path = wallet_xmss_floor_path(path);
    let Ok(data) = std::fs::read_to_string(&floor_path) else {
        return Ok(());
    };
    let floor: WalletXmssFloor =
        serde_json::from_str(&data).map_err(|e| format!("parse xmss floor: {}", e))?;
    if floor.wallet_fingerprint != hash(&wallet.master_sk) {
        return Ok(());
    }
    if wallet.addr_counter < floor.addr_counter {
        return Err(format!(
            "wallet appears to be restored from a stale backup: addr_counter {} is behind durable XMSS floor {}",
            wallet.addr_counter, floor.addr_counter
        ));
    }
    for (addr_index, required_next) in &floor.wots_key_indices {
        let current_next = current_wallet_wots_floor(wallet, *addr_index);
        if current_next < *required_next {
            return Err(format!(
                "wallet appears to be restored from a stale backup: address {} next_auth_index {} is behind durable XMSS floor {}",
                addr_index, current_next, required_next
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_wallet_permissions(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| format!("chmod wallet: {}", e))
}

#[cfg(not(unix))]
fn set_wallet_permissions(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

#[cfg(all(unix, not(test)))]
fn warn_if_wallet_permissions_are_too_open(path: &str) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "warning: wallet file {} is not private (mode {:o}); it contains plaintext spending keys",
            path, mode
        );
    }
}

#[cfg(all(unix, test))]
fn warn_if_wallet_permissions_are_too_open(_path: &str) {}

#[cfg(not(unix))]
fn warn_if_wallet_permissions_are_too_open(_path: &str) {}

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

fn get_text(url: &str) -> Result<String, String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("HTTP error: {}", e))?;
    resp.into_body()
        .read_to_string()
        .map_err(|e| format!("read response: {}", e))
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct WalletNetworkProfile {
    network: String,
    rollup_node_url: String,
    rollup_address: String,
    bridge_ticketer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operator_url: Option<String>,
    source_alias: String,
    public_account: String,
    #[serde(default = "default_octez_client_bin")]
    octez_client_bin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    octez_client_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    octez_node_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    octez_protocol: Option<String>,
    #[serde(default = "default_octez_burn_cap")]
    burn_cap: String,
}

fn default_network_profile_path(wallet_path: &str) -> PathBuf {
    PathBuf::from(format!("{}.network.json", wallet_path))
}

fn default_octez_client_bin() -> String {
    "octez-client".into()
}

fn default_octez_burn_cap() -> String {
    "1".into()
}

fn shadownet_profile(
    rollup_node_url: String,
    rollup_address: String,
    bridge_ticketer: String,
    operator_url: Option<String>,
    source_alias: String,
    public_account: Option<String>,
    octez_client_dir: Option<String>,
    octez_node_endpoint: Option<String>,
    octez_protocol: Option<String>,
    octez_client_bin: Option<String>,
    burn_cap: Option<String>,
) -> WalletNetworkProfile {
    WalletNetworkProfile {
        network: "shadownet".into(),
        rollup_node_url,
        rollup_address,
        bridge_ticketer,
        operator_url,
        public_account: public_account.unwrap_or_else(|| source_alias.clone()),
        source_alias,
        octez_client_bin: octez_client_bin.unwrap_or_else(default_octez_client_bin),
        octez_client_dir,
        octez_node_endpoint,
        octez_protocol,
        burn_cap: burn_cap.unwrap_or_else(default_octez_burn_cap),
    }
}

fn load_network_profile(path: &Path) -> Result<WalletNetworkProfile, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("read network profile: {}", e))?;
    serde_json::from_str(&data).map_err(|e| format!("parse network profile: {}", e))
}

fn save_network_profile(path: &Path, profile: &WalletNetworkProfile) -> Result<(), String> {
    let data =
        serde_json::to_string_pretty(profile).map_err(|e| format!("serialize profile: {}", e))?;
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create profile tmp: {}", e))?;
    file.write_all(data.as_bytes())
        .map_err(|e| format!("write profile tmp: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("fsync profile tmp: {}", e))?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(|e| format!("rename profile: {}", e))?;
    sync_parent_dir(path)
}

fn load_required_network_profile(wallet_path: &str) -> Result<WalletNetworkProfile, String> {
    let profile_path = default_network_profile_path(wallet_path);
    let profile = load_network_profile(&profile_path).map_err(|e| {
        format!(
            "network profile is not configured: {}. Run `tzel-wallet profile init-shadownet --rollup-node-url ... --rollup-address ... --bridge-ticketer ... --source-alias ...`",
            e
        )
    })?;
    if profile.network != "shadownet" {
        return Err(format!(
            "unsupported wallet network profile '{}'",
            profile.network
        ));
    }
    Ok(profile)
}

const DURABLE_AUTH_DOMAIN: &str = "/tzel/v1/state/auth_domain";
const DURABLE_TREE_SIZE: &str = "/tzel/v1/state/tree/size";
const DURABLE_TREE_ROOT: &str = "/tzel/v1/state/tree/root";
const DURABLE_NOTE_PREFIX: &str = "/tzel/v1/state/notes/";
const DURABLE_NOTE_LEN_SUFFIX: &str = "/len";
const DURABLE_NOTE_CHUNK_PREFIX: &str = "/chunk/";
const DURABLE_NOTE_CHUNK_BYTES: usize = 1024;
const MAX_PUBLISHED_NOTE_BYTES: usize = 4 * 1024 * 1024;
const DURABLE_NULLIFIER_COUNT: &str = "/tzel/v1/state/nullifiers/count";
const DURABLE_NULLIFIER_INDEX_PREFIX: &str = "/tzel/v1/state/nullifiers/index/";
const DURABLE_BALANCE_COUNT: &str = "/tzel/v1/state/balances/count";
const DURABLE_BALANCE_INDEX_PREFIX: &str = "/tzel/v1/state/balances/index/";
const DURABLE_BALANCE_PREFIX: &str = "/tzel/v1/state/balances/by-key/";

#[derive(Debug, Clone)]
struct RollupSubmissionReceipt {
    output: String,
    operation_hash: Option<String>,
    submission_id: Option<String>,
    pending_dal: bool,
}

#[derive(Clone)]
struct RollupStateSnapshot {
    auth_domain: F,
    tree: MerkleTree,
    notes: Vec<NoteMemo>,
}

impl RollupStateSnapshot {
    fn current_root(&self) -> F {
        self.tree.root()
    }

    fn merkle_path(&self, index: usize) -> Result<MerklePathResp, String> {
        if index >= self.notes.len() {
            return Err(format!("note index {} is outside current tree", index));
        }
        let (siblings, root) = self.tree.auth_path(index);
        Ok(MerklePathResp { siblings, root })
    }
}

struct RollupRpc<'a> {
    profile: &'a WalletNetworkProfile,
}

impl<'a> RollupRpc<'a> {
    fn new(profile: &'a WalletNetworkProfile) -> Self {
        Self { profile }
    }

    fn durable_value_url(&self, key: &str) -> String {
        format!(
            "{}/global/block/head/durable/wasm_2_0_0/value?key={}",
            self.profile.rollup_node_url.trim_end_matches('/'),
            key
        )
    }

    fn durable_length_url(&self, key: &str) -> String {
        format!(
            "{}/global/block/head/durable/wasm_2_0_0/length?key={}",
            self.profile.rollup_node_url.trim_end_matches('/'),
            key
        )
    }

    fn head_hash_url(&self) -> String {
        format!(
            "{}/global/block/head/hash",
            self.profile.rollup_node_url.trim_end_matches('/')
        )
    }

    fn read_durable_text(&self, key: &str) -> Result<String, String> {
        let url = self.durable_value_url(key);
        get_text(&url).map_err(|e| format!("rollup RPC {} failed: {}", url, e))
    }

    fn read_durable_length(&self, key: &str) -> Result<Option<usize>, String> {
        let url = self.durable_length_url(key);
        let raw = get_text(&url).map_err(|e| format!("rollup RPC {} failed: {}", url, e))?;
        let value: Option<serde_json::Value> =
            serde_json::from_str(&raw).map_err(|e| format!("parse durable length: {}", e))?;
        match value {
            None => Ok(None),
            Some(serde_json::Value::String(text)) => {
                let parsed = text
                    .parse::<u64>()
                    .map_err(|e| format!("parse durable length integer: {}", e))?;
                usize::try_from(parsed)
                    .map(Some)
                    .map_err(|_| format!("durable length at {} does not fit in usize", key))
            }
            Some(serde_json::Value::Number(number)) => {
                let parsed = number
                    .as_u64()
                    .ok_or_else(|| format!("durable length at {} must be non-negative", key))?;
                usize::try_from(parsed)
                    .map(Some)
                    .map_err(|_| format!("durable length at {} does not fit in usize", key))
            }
            Some(other) => Err(format!(
                "durable length at {} has unexpected JSON form {}",
                key, other
            )),
        }
    }

    fn read_durable_bytes(&self, key: &str) -> Result<Vec<u8>, String> {
        let raw = self.read_durable_text(key)?;
        parse_rollup_rpc_bytes(&raw).map_err(|e| format!("decode durable value at {}: {}", key, e))
    }

    fn read_published_note_bytes(&self, index: u64) -> Result<Option<Vec<u8>>, String> {
        let direct_key = indexed_durable_key(DURABLE_NOTE_PREFIX, index);
        if self.read_durable_length(&direct_key)?.is_some() {
            let bytes = self.read_durable_bytes(&direct_key)?;
            if bytes.len() > MAX_PUBLISHED_NOTE_BYTES {
                return Err(format!(
                    "durable note {} at {} exceeds max supported size {}",
                    index, direct_key, MAX_PUBLISHED_NOTE_BYTES
                ));
            }
            return Ok(Some(bytes));
        }

        let len_key = indexed_durable_note_len_key(index);
        if self.read_durable_length(&len_key)?.is_none() {
            return Ok(None);
        }

        let total_len_u64 = self.read_u64(&len_key)?;
        let total_len = usize::try_from(total_len_u64).map_err(|_| {
            format!(
                "chunked durable note {} length does not fit in usize",
                index
            )
        })?;
        if total_len > MAX_PUBLISHED_NOTE_BYTES {
            return Err(format!(
                "chunked durable note {} length {} exceeds max supported size {}",
                index, total_len, MAX_PUBLISHED_NOTE_BYTES
            ));
        }
        let chunk_count = total_len.div_ceil(DURABLE_NOTE_CHUNK_BYTES);
        let mut bytes = Vec::with_capacity(total_len);
        for chunk_index in 0..chunk_count {
            let chunk_key = indexed_durable_note_chunk_key(index, chunk_index);
            let mut chunk = self.read_durable_bytes(&chunk_key)?;
            bytes.append(&mut chunk);
        }
        if bytes.len() != total_len {
            return Err(format!(
                "chunked durable note {} length mismatch: expected {}, got {}",
                index,
                total_len,
                bytes.len()
            ));
        }
        Ok(Some(bytes))
    }

    fn read_u64(&self, key: &str) -> Result<u64, String> {
        let bytes = self.read_durable_bytes(key)?;
        if bytes.len() != 8 {
            return Err(format!(
                "durable u64 at {} has {} bytes, expected 8",
                key,
                bytes.len()
            ));
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(out))
    }

    fn read_felt(&self, key: &str) -> Result<F, String> {
        let bytes = self.read_durable_bytes(key)?;
        if bytes.len() != 32 {
            return Err(format!(
                "durable felt at {} has {} bytes, expected 32",
                key,
                bytes.len()
            ));
        }
        let mut out = ZERO;
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn read_string(&self, key: &str) -> Result<String, String> {
        let bytes = self.read_durable_bytes(key)?;
        String::from_utf8(bytes).map_err(|_| format!("durable string at {} is not UTF-8", key))
    }

    fn load_notes_since(&self, cursor: usize) -> Result<NotesFeedResp, String> {
        let count: usize = self
            .read_u64(DURABLE_TREE_SIZE)?
            .try_into()
            .map_err(|_| "tree size does not fit in usize".to_string())?;
        if cursor > count {
            return Err(format!(
                "wallet cursor {} is ahead of rollup tree size {}",
                cursor, count
            ));
        }

        let mut notes = Vec::with_capacity(count - cursor);
        for i in cursor..count {
            let Some(bytes) = self.read_published_note_bytes(i as u64)? else {
                let key = indexed_durable_key(DURABLE_NOTE_PREFIX, i as u64);
                return Err(format!(
                    "rollup durable state is missing note {} at {} while tree size is {}. This usually means the deployed rollup kernel does not persist published note payloads, or the rollup node is not serving the expected durable state.",
                    i, key, count
                ));
            };
            let (cm, enc) = canonical_wire::decode_published_note(&bytes)?;
            notes.push(NoteMemo { index: i, cm, enc });
        }
        Ok(NotesFeedResp {
            notes,
            next_cursor: count,
        })
    }

    fn load_nullifiers(&self) -> Result<Vec<F>, String> {
        let count: usize = self
            .read_u64(DURABLE_NULLIFIER_COUNT)?
            .try_into()
            .map_err(|_| "nullifier count does not fit in usize".to_string())?;
        let mut nullifiers = Vec::with_capacity(count);
        for i in 0..count {
            nullifiers.push(self.read_felt(&indexed_durable_key(
                DURABLE_NULLIFIER_INDEX_PREFIX,
                i as u64,
            ))?);
        }
        Ok(nullifiers)
    }

    fn load_balances(&self) -> Result<std::collections::HashMap<String, u64>, String> {
        let count: usize = self
            .read_u64(DURABLE_BALANCE_COUNT)?
            .try_into()
            .map_err(|_| "balance count does not fit in usize".to_string())?;
        let mut balances = std::collections::HashMap::with_capacity(count);
        for i in 0..count {
            let account =
                self.read_string(&indexed_durable_key(DURABLE_BALANCE_INDEX_PREFIX, i as u64))?;
            let amount = self.read_u64(&balance_durable_key(&account))?;
            balances.insert(account, amount);
        }
        Ok(balances)
    }

    fn load_state_snapshot(&self) -> Result<RollupStateSnapshot, String> {
        let auth_domain = self.read_felt(DURABLE_AUTH_DOMAIN)?;
        let notes = self.load_notes_since(0)?.notes;
        let persisted_root = self.read_felt(DURABLE_TREE_ROOT)?;
        let tree = MerkleTree::from_leaves(notes.iter().map(|note| note.cm).collect());
        let recomputed_root = tree.root();
        if recomputed_root != persisted_root {
            return Err(format!(
                "rollup tree root mismatch: durable {} != recomputed {}",
                short(&persisted_root),
                short(&recomputed_root)
            ));
        }
        Ok(RollupStateSnapshot {
            auth_domain,
            tree,
            notes,
        })
    }

    fn head_hash(&self) -> Result<String, String> {
        let raw = get_text(&self.head_hash_url())?;
        serde_json::from_str::<String>(&raw).or_else(|_| Ok(raw.trim().to_string()))
    }

    fn submit_kernel_message(
        &self,
        message: &KernelInboxMessage,
    ) -> Result<RollupSubmissionReceipt, String> {
        let payload = encode_kernel_inbox_message(message)?;
        if let Some(operator_url) = &self.profile.operator_url {
            return submit_kernel_message_via_operator(
                operator_url,
                &self.profile.rollup_address,
                kernel_message_kind(message),
                payload,
            );
        }
        let encoded = encode_targeted_rollup_message(&self.profile.rollup_address, &payload)?;
        let payload_file = write_temp_rollup_message_file(&encoded)?;
        let payload = format!("bin:{}", payload_file.display());
        let mut args = vec![
            "send".to_string(),
            "smart".to_string(),
            "rollup".to_string(),
            "message".to_string(),
            payload,
            "from".to_string(),
            self.profile.source_alias.clone(),
        ];
        let result = self.run_octez_client(&mut args);
        let _ = std::fs::remove_file(&payload_file);
        result
    }

    fn deposit_to_bridge(
        &self,
        public_account: &str,
        amount_mutez: u64,
    ) -> Result<RollupSubmissionReceipt, String> {
        let tez_amount = mutez_to_tez_string(amount_mutez);
        let mint_arg = format!(
            "Pair 0x{} \"{}\"",
            hex::encode(public_account.as_bytes()),
            self.profile.rollup_address
        );
        let mut args = vec![
            "transfer".to_string(),
            tez_amount,
            "from".to_string(),
            self.profile.source_alias.clone(),
            "to".to_string(),
            self.profile.bridge_ticketer.clone(),
            "--entrypoint".to_string(),
            "mint".to_string(),
            "--arg".to_string(),
            mint_arg,
            "--burn-cap".to_string(),
            self.profile.burn_cap.clone(),
        ];
        self.run_octez_client(&mut args)
    }

    fn run_octez_client(&self, args: &mut Vec<String>) -> Result<RollupSubmissionReceipt, String> {
        let mut command = std::process::Command::new(&self.profile.octez_client_bin);
        if let Some(dir) = &self.profile.octez_client_dir {
            command.arg("-d").arg(dir);
        }
        if let Some(endpoint) = &self.profile.octez_node_endpoint {
            command.arg("-E").arg(endpoint);
        }
        if let Some(protocol) = &self.profile.octez_protocol {
            command.arg("-p").arg(protocol);
        }
        command.arg("-w").arg("none");
        command.args(args);

        let output = command
            .output()
            .map_err(|e| format!("failed to start {}: {}", self.profile.octez_client_bin, e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let combined = match (stdout.is_empty(), stderr.is_empty()) {
            (true, true) => String::new(),
            (false, true) => stdout.clone(),
            (true, false) => stderr.clone(),
            (false, false) => format!("{}\n{}", stdout, stderr),
        };

        if !output.status.success() {
            return Err(if combined.is_empty() {
                format!(
                    "{} exited with status {}",
                    self.profile.octez_client_bin, output.status
                )
            } else {
                combined
            });
        }

        Ok(RollupSubmissionReceipt {
            operation_hash: extract_operation_hash(&combined),
            output: combined,
            submission_id: None,
            pending_dal: false,
        })
    }
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

fn write_temp_rollup_message_file(bytes: &[u8]) -> Result<std::path::PathBuf, String> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "tzel-rollup-message-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {}", e))?
            .as_nanos()
    ));
    std::fs::write(&path, bytes).map_err(|e| format!("write rollup message file: {}", e))?;
    Ok(path)
}

fn kernel_message_kind(message: &KernelInboxMessage) -> RollupSubmissionKind {
    match message {
        KernelInboxMessage::Shield(_) => RollupSubmissionKind::Shield,
        KernelInboxMessage::Transfer(_) => RollupSubmissionKind::Transfer,
        KernelInboxMessage::Unshield(_) => RollupSubmissionKind::Unshield,
        KernelInboxMessage::Withdraw(_)
        | KernelInboxMessage::ConfigureVerifier(_)
        | KernelInboxMessage::ConfigureBridge(_) => RollupSubmissionKind::Withdraw,
        KernelInboxMessage::DalPointer(_) => {
            unreachable!("wallet should not submit raw DAL pointer messages")
        }
    }
}

fn submit_kernel_message_via_operator(
    operator_url: &str,
    rollup_address: &str,
    kind: RollupSubmissionKind,
    payload: Vec<u8>,
) -> Result<RollupSubmissionReceipt, String> {
    let base = operator_url.trim_end_matches('/');
    let resp: SubmitRollupMessageResp = post_json(
        &format!("{}/v1/rollup/submissions", base),
        &SubmitRollupMessageReq {
            kind,
            rollup_address: rollup_address.to_string(),
            payload,
        },
    )?;
    let submission = resp.submission;
    Ok(RollupSubmissionReceipt {
        output: format_rollup_submission(&submission),
        operation_hash: submission.operation_hash,
        submission_id: Some(submission.id),
        pending_dal: matches!(
            submission.status,
            RollupSubmissionStatus::PendingDal
                | RollupSubmissionStatus::CommitmentIncluded
                | RollupSubmissionStatus::Attested
        ),
    })
}

fn load_operator_submission(
    operator_url: &str,
    submission_id: &str,
) -> Result<SubmitRollupMessageResp, String> {
    let base = operator_url.trim_end_matches('/');
    get_json(&format!("{}/v1/rollup/submissions/{}", base, submission_id))
}

fn format_rollup_submission(submission: &RollupSubmission) -> String {
    let transport = match submission.transport {
        RollupSubmissionTransport::DirectInbox => "direct_inbox",
        RollupSubmissionTransport::Dal => "dal",
    };
    let status = match submission.status {
        RollupSubmissionStatus::SubmittedToL1 => "submitted_to_l1",
        RollupSubmissionStatus::PendingDal => "pending_dal",
        RollupSubmissionStatus::CommitmentIncluded => "commitment_included",
        RollupSubmissionStatus::Attested => "attested",
        RollupSubmissionStatus::Failed => "failed",
    };
    let mut lines = vec![
        format!("Operator submission id: {}", submission.id),
        format!("Kind: {:?}", submission.kind),
        format!("Status: {} via {}", status, transport),
    ];
    if let Some(op_hash) = &submission.operation_hash {
        lines.push(format!("Operation hash: {}", op_hash));
    }
    if !submission.dal_chunks.is_empty() {
        lines.push(format!("DAL chunks: {}", submission.dal_chunks.len()));
        for (index, chunk) in submission.dal_chunks.iter().enumerate() {
            lines.push(format!(
                "  chunk {}: slot {} level {} bytes {} commitment {}",
                index, chunk.slot_index, chunk.published_level, chunk.payload_len, chunk.commitment
            ));
        }
    }
    if let Some(detail) = &submission.detail {
        lines.push(detail.clone());
    }
    lines.join("\n")
}

fn indexed_durable_key(prefix: &str, index: u64) -> String {
    format!("{}{index:016x}", prefix)
}

fn indexed_durable_note_len_key(index: u64) -> String {
    format!(
        "{}{}",
        indexed_durable_key(DURABLE_NOTE_PREFIX, index),
        DURABLE_NOTE_LEN_SUFFIX
    )
}

fn indexed_durable_note_chunk_key(index: u64, chunk_index: usize) -> String {
    format!(
        "{}{}{chunk_index:08x}",
        indexed_durable_key(DURABLE_NOTE_PREFIX, index),
        DURABLE_NOTE_CHUNK_PREFIX
    )
}

fn balance_durable_key(account: &str) -> String {
    format!(
        "{}{}",
        DURABLE_BALANCE_PREFIX,
        hex::encode(account.as_bytes())
    )
}

fn parse_rollup_rpc_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    let unwrapped = serde_json::from_str::<String>(trimmed).unwrap_or_else(|_| trimmed.to_string());
    let payload = unwrapped.trim();
    let payload = payload
        .strip_prefix("0x")
        .or_else(|| payload.strip_prefix("0X"))
        .unwrap_or(payload);

    if !payload.is_empty()
        && payload.len() % 2 == 0
        && payload.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return hex::decode(payload).map_err(|e| e.to_string());
    }

    Ok(payload.as_bytes().to_vec())
}

fn mutez_to_tez_string(amount_mutez: u64) -> String {
    let whole = amount_mutez / 1_000_000;
    let fractional = amount_mutez % 1_000_000;
    if fractional == 0 {
        return whole.to_string();
    }
    let mut out = format!("{}.{:06}", whole, fractional);
    while out.ends_with('0') {
        out.pop();
    }
    out
}

fn extract_operation_hash(output: &str) -> Option<String> {
    output
        .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';' | '(' | ')'))
        .find_map(|token| {
            if token.starts_with('o')
                && token.len() >= 20
                && token.chars().all(|ch| ch.is_ascii_alphanumeric())
            {
                Some(token.to_string())
            } else {
                None
            }
        })
}

fn host_stark_proof_to_kernel(proof: &Proof) -> Result<KernelStarkProof, String> {
    match proof {
        Proof::TrustMeBro => Err("rollup submission requires a real STARK proof".into()),
        Proof::Stark {
            proof_bytes,
            output_preimage,
            verify_meta,
        } => Ok(KernelStarkProof {
            proof_bytes: proof_bytes.clone(),
            output_preimage: output_preimage.clone(),
            verify_meta: verify_meta
                .clone()
                .ok_or_else(|| "STARK proof is missing verify_meta".to_string())?,
        }),
    }
}

fn shield_req_to_kernel(req: &ShieldReq) -> Result<KernelShieldReq, String> {
    Ok(KernelShieldReq {
        sender: req.sender.clone(),
        v: req.v,
        address: req.address.clone(),
        memo: req.memo.clone(),
        proof: host_stark_proof_to_kernel(&req.proof)?,
        client_cm: req.client_cm,
        client_enc: req.client_enc.clone(),
    })
}

fn transfer_req_to_kernel(req: &TransferReq) -> Result<KernelTransferReq, String> {
    Ok(KernelTransferReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        cm_1: req.cm_1,
        cm_2: req.cm_2,
        enc_1: req.enc_1.clone(),
        enc_2: req.enc_2.clone(),
        proof: host_stark_proof_to_kernel(&req.proof)?,
    })
}

fn unshield_req_to_kernel(req: &UnshieldReq) -> Result<KernelUnshieldReq, String> {
    Ok(KernelUnshieldReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        v_pub: req.v_pub,
        recipient: req.recipient.clone(),
        cm_change: req.cm_change,
        enc_change: req.enc_change.clone(),
        proof: host_stark_proof_to_kernel(&req.proof)?,
    })
}

fn withdraw_req_to_kernel(req: &WithdrawReq) -> KernelWithdrawReq {
    KernelWithdrawReq {
        sender: req.sender.clone(),
        recipient: req.recipient.clone(),
        amount: req.amount,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// sp-client CLI
// ═══════════════════════════════════════════════════════════════════════

#[derive(Parser)]
#[command(name = "sp-client", about = "TzEL developer/test CLI wallet")]
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
    ExportDetect {
        #[arg(long)]
        out: Option<String>,
    },
    /// Export viewing material for delegated scanning and note validation.
    ExportView {
        #[arg(long)]
        out: Option<String>,
    },
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

pub fn sp_client_entry() {
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
    /// If set, delegate proof generation to this HTTP service (POST /prove).
    proving_service_url: Option<String>,
}

impl ProveConfig {
    fn make_proof(&self, circuit: &str, args: &[String]) -> Result<Proof, String> {
        if self.skip_proof {
            eprintln!("WARNING: --trust-me-bro is set. Skipping STARK proof generation.");
            eprintln!(
                "WARNING: Transaction has NO cryptographic guarantee. DO NOT use in production."
            );
            Ok(Proof::TrustMeBro)
        } else if let Some(url) = &self.proving_service_url {
            generate_proof_http(url, circuit, args)
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
        Cmd::ExportDetect { .. } | Cmd::ExportView { .. } | Cmd::Balance | Cmd::Fund { .. } => None,
    };
    let pc = ProveConfig {
        skip_proof: cli.trust_me_bro,
        reprove_bin: cli.reprove_bin,
        executables_dir: cli.executables_dir,
        proving_service_url: None,
    };
    match cli.cmd {
        Cmd::Keygen => cmd_keygen(&cli.wallet),
        Cmd::Address => cmd_address(&cli.wallet),
        Cmd::ExportDetect { out } => cmd_export_detect(&cli.wallet, out.as_deref()),
        Cmd::ExportView { out } => cmd_export_view(&cli.wallet, out.as_deref()),
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
// tzel-wallet CLI
// ═══════════════════════════════════════════════════════════════════════

#[derive(Parser)]
#[command(
    name = "tzel-wallet",
    about = "TzEL CLI wallet for rollup-backed networks such as Shadownet"
)]
struct UserCli {
    #[arg(short, long, default_value = "wallet.json")]
    wallet: String,

    /// Path to the reprove binary.
    #[arg(long, default_value = "reprove")]
    reprove_bin: String,

    /// Path to directory containing compiled .executable.json files.
    #[arg(long, default_value = "cairo/target/dev")]
    executables_dir: String,

    #[command(subcommand)]
    cmd: UserCmd,
}

#[derive(Subcommand)]
enum UserCmd {
    /// Create a new wallet file.
    Init,
    /// Manage the saved network profile for this wallet.
    Profile {
        #[command(subcommand)]
        cmd: UserProfileCmd,
    },
    /// Derive a new receiving address.
    Receive,
    /// Sync notes and spent nullifiers directly from the rollup node durable state.
    Sync {
        /// Keep polling until interrupted.
        #[arg(long)]
        watch: bool,
        /// Poll interval for `sync --watch`.
        #[arg(long, default_value_t = 5)]
        interval_secs: u64,
    },
    /// Show local private balance plus live public bridge balance when configured.
    Balance,
    /// Check whether the wallet profile, operator, and rollup node are usable.
    Check,
    /// Deposit tez on L1 into the configured bridge ticketer for your public rollup account.
    Deposit {
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        public_account: Option<String>,
    },
    /// Shield public bridge balance into a private note.
    Shield {
        #[arg(long)]
        amount: u64,
        /// Override the public rollup account to shield from.
        #[arg(long)]
        sender: Option<String>,
        /// Path to recipient address JSON. Defaults to a newly generated self-address.
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        memo: Option<String>,
    },
    /// Send shielded funds to another payment address.
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        memo: Option<String>,
    },
    /// Move private funds back into a public rollup balance.
    Unshield {
        #[arg(long)]
        amount: u64,
        /// Override the public rollup account to receive the transparent balance.
        #[arg(long)]
        recipient: Option<String>,
    },
    /// Withdraw public rollup balance back to an L1 tz1/KT1 address.
    Withdraw {
        #[arg(long)]
        amount: u64,
        /// Override the public rollup account to debit.
        #[arg(long)]
        sender: Option<String>,
        /// L1 recipient for the withdrawal outbox message.
        #[arg(long)]
        recipient: String,
    },
    /// Query a submission previously accepted by the configured operator.
    Status {
        #[arg(long)]
        submission_id: String,
    },
    /// Export detection material for delegated scanning.
    ExportDetect {
        #[arg(long)]
        out: Option<String>,
    },
    /// Export viewing material for delegated scanning and note validation.
    ExportView {
        #[arg(long)]
        out: Option<String>,
    },
    /// Manage a watch-only detection or viewing wallet.
    Watch {
        #[command(subcommand)]
        cmd: UserWatchCmd,
    },
}

#[derive(Subcommand)]
enum UserWatchCmd {
    /// Initialize a watch-only wallet from exported detection or viewing material.
    Init {
        #[arg(long)]
        material: String,
        #[arg(long)]
        force: bool,
    },
    /// Sync a watch-only wallet directly from rollup durable state.
    Sync {
        /// Keep polling until interrupted.
        #[arg(long)]
        watch: bool,
        /// Poll interval for `watch sync --watch`.
        #[arg(long, default_value_t = 5)]
        interval_secs: u64,
    },
    /// Show sanitized watch-only state.
    Show,
}

#[derive(Subcommand)]
enum UserProfileCmd {
    /// Save a Shadownet profile for this wallet.
    InitShadownet {
        #[arg(long)]
        rollup_node_url: String,
        #[arg(long)]
        rollup_address: String,
        #[arg(long)]
        bridge_ticketer: String,
        #[arg(long)]
        operator_url: Option<String>,
        #[arg(long)]
        source_alias: String,
        #[arg(long)]
        public_account: Option<String>,
        #[arg(long)]
        octez_client_dir: Option<String>,
        #[arg(long)]
        octez_node_endpoint: Option<String>,
        #[arg(long)]
        octez_protocol: Option<String>,
        #[arg(long)]
        octez_client_bin: Option<String>,
        #[arg(long)]
        burn_cap: Option<String>,
        #[arg(long)]
        force: bool,
    },
    /// Print the saved network profile as JSON.
    Show,
}

pub fn tzel_wallet_entry() {
    let cli = UserCli::parse();
    if let Err(e) = run_user(cli) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

#[derive(Parser)]
#[command(
    name = "tzel-detect",
    about = "TzEL watch-only detection/viewing service"
)]
struct DetectServiceCli {
    #[arg(short, long, default_value = "watch.json")]
    wallet: String,
    #[arg(long, default_value = "127.0.0.1:8789")]
    bind: String,
    #[arg(long, default_value_t = 5)]
    interval_secs: u64,
}

#[derive(Clone)]
struct DetectServiceState {
    wallet: String,
    sync_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

#[derive(Serialize)]
struct DetectServiceSyncResp {
    summary: WatchSyncSummary,
    status: WatchWalletStatus,
}

pub fn tzel_detect_entry() {
    let cli = DetectServiceCli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = runtime.block_on(run_detect_service(cli)) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

async fn run_detect_service(cli: DetectServiceCli) -> Result<(), String> {
    validate_detection_service_wallet(&cli.wallet)?;
    let state = DetectServiceState {
        wallet: cli.wallet.clone(),
        sync_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
    };

    let background_state = state.clone();
    let interval_secs = cli.interval_secs.max(1);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let _guard = background_state.sync_lock.lock().await;
            let _ = run_detection_service_once(&background_state.wallet);
        }
    });

    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(detect_service_healthz))
        .route("/v1/status", axum::routing::get(detect_service_get_status))
        .route("/v1/sync", axum::routing::post(detect_service_post_sync))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .map_err(|e| format!("bind detection service {}: {}", cli.bind, e))?;
    println!("Detection service listening on http://{}", cli.bind);
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("run detection service: {}", e))
}

async fn detect_service_healthz() -> &'static str {
    "ok"
}

async fn detect_service_get_status(
    axum::extract::State(state): axum::extract::State<DetectServiceState>,
) -> Result<axum::Json<WatchWalletStatus>, (axum::http::StatusCode, String)> {
    load_detection_service_status(&state.wallet)
        .map(axum::Json)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn detect_service_post_sync(
    axum::extract::State(state): axum::extract::State<DetectServiceState>,
) -> Result<axum::Json<DetectServiceSyncResp>, (axum::http::StatusCode, String)> {
    let _guard = state.sync_lock.lock().await;
    let (status, summary) = run_detection_service_once(&state.wallet)
        .map_err(|e| (axum::http::StatusCode::BAD_GATEWAY, e))?;
    Ok(axum::Json(DetectServiceSyncResp { summary, status }))
}

fn run_user(cli: UserCli) -> Result<(), String> {
    let _wallet_lock = match &cli.cmd {
        UserCmd::Init
        | UserCmd::Receive
        | UserCmd::Sync { .. }
        | UserCmd::Shield { .. }
        | UserCmd::Send { .. }
        | UserCmd::Unshield { .. } => Some(acquire_wallet_lock(&cli.wallet)?),
        UserCmd::Profile { .. }
        | UserCmd::Balance
        | UserCmd::Check
        | UserCmd::Deposit { .. }
        | UserCmd::Status { .. }
        | UserCmd::Withdraw { .. }
        | UserCmd::ExportDetect { .. }
        | UserCmd::ExportView { .. } => None,
        UserCmd::Watch { cmd } => match cmd {
            UserWatchCmd::Init { .. } | UserWatchCmd::Sync { .. } => {
                Some(acquire_wallet_lock(&cli.wallet)?)
            }
            UserWatchCmd::Show => None,
        },
    };

    let pc = ProveConfig {
        skip_proof: false,
        reprove_bin: cli.reprove_bin,
        executables_dir: cli.executables_dir,
        proving_service_url: None,
    };

    match cli.cmd {
        UserCmd::Init => cmd_keygen(&cli.wallet),
        UserCmd::Profile { cmd } => run_user_profile(&cli.wallet, cmd),
        UserCmd::Receive => cmd_address(&cli.wallet),
        UserCmd::Sync {
            watch,
            interval_secs,
        } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            if watch {
                cmd_rollup_sync_watch(&cli.wallet, &profile, interval_secs)
            } else {
                cmd_rollup_sync(&cli.wallet, &profile)
            }
        }
        UserCmd::Balance => cmd_user_balance(&cli.wallet),
        UserCmd::Check => {
            let profile = load_required_network_profile(&cli.wallet)?;
            cmd_wallet_check(&cli.wallet, &profile)
        }
        UserCmd::Deposit {
            amount,
            public_account,
        } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            let public_account = public_account.unwrap_or_else(|| profile.public_account.clone());
            cmd_bridge_deposit(&profile, amount, &public_account)
        }
        UserCmd::Shield {
            amount,
            sender,
            to,
            memo,
        } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            let sender = sender.unwrap_or_else(|| profile.public_account.clone());
            cmd_shield_rollup(&cli.wallet, &profile, &sender, amount, to, memo, &pc)
        }
        UserCmd::Send { to, amount, memo } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            cmd_transfer_rollup(&cli.wallet, &profile, &to, amount, memo, &pc)
        }
        UserCmd::Unshield { amount, recipient } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            let recipient = recipient.unwrap_or_else(|| profile.public_account.clone());
            cmd_unshield_rollup(&cli.wallet, &profile, amount, &recipient, &pc)
        }
        UserCmd::Withdraw {
            amount,
            sender,
            recipient,
        } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            let sender = sender.unwrap_or_else(|| profile.public_account.clone());
            cmd_withdraw_rollup(&profile, &sender, amount, &recipient)
        }
        UserCmd::Status { submission_id } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            cmd_operator_status(&profile, &submission_id)
        }
        UserCmd::ExportDetect { out } => cmd_export_detect(&cli.wallet, out.as_deref()),
        UserCmd::ExportView { out } => cmd_export_view(&cli.wallet, out.as_deref()),
        UserCmd::Watch { cmd } => run_watch_wallet(&cli.wallet, cmd),
    }
}

fn run_user_profile(wallet_path: &str, cmd: UserProfileCmd) -> Result<(), String> {
    let path = default_network_profile_path(wallet_path);
    match cmd {
        UserProfileCmd::InitShadownet {
            rollup_node_url,
            rollup_address,
            bridge_ticketer,
            operator_url,
            source_alias,
            public_account,
            octez_client_dir,
            octez_node_endpoint,
            octez_protocol,
            octez_client_bin,
            burn_cap,
            force,
        } => {
            if path.exists() && !force {
                return Err(format!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                ));
            }
            let profile = shadownet_profile(
                rollup_node_url,
                rollup_address,
                bridge_ticketer,
                operator_url,
                source_alias,
                public_account,
                octez_client_dir,
                octez_node_endpoint,
                octez_protocol,
                octez_client_bin,
                burn_cap,
            );
            save_network_profile(&path, &profile)?;
            println!("Saved {} profile to {}", profile.network, path.display());
            println!("{}", serde_json::to_string_pretty(&profile).unwrap());
            Ok(())
        }
        UserProfileCmd::Show => {
            let profile = load_network_profile(&path)?;
            println!("{}", serde_json::to_string_pretty(&profile).unwrap());
            Ok(())
        }
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
    let bundle: VerifyProofBundle =
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
        verify_meta: bundle
            .verify_meta
            .map(|meta| encode_verify_meta(&meta))
            .transpose()?,
    })
}

fn generate_proof_http(url: &str, circuit: &str, args: &[String]) -> Result<Proof, String> {
    eprintln!("Generating proof via proving-service for {}...", circuit);
    let bundle: VerifyProofBundle = post_json(
        &format!("{}/prove", url),
        &serde_json::json!({ "circuit": circuit, "args": args }),
    )
    .map_err(|e| format!("proving-service: {}", e))?;
    eprintln!(
        "Proof received: {} KB, {} outputs",
        bundle.proof_bytes.len() / 1024,
        bundle.output_preimage.len()
    );
    Ok(Proof::Stark {
        proof_bytes: bundle.proof_bytes,
        output_preimage: bundle.output_preimage,
        verify_meta: bundle
            .verify_meta
            .map(|meta| encode_verify_meta(&meta))
            .transpose()?,
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
        pending_spends: vec![],
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

fn write_json_stdout_or_file<T: Serialize>(value: &T, out: Option<&str>) -> Result<(), String> {
    let data = serde_json::to_string_pretty(value).map_err(|e| format!("serialize json: {}", e))?;
    if let Some(path) = out {
        save_private_json(path, value, "export")?;
        println!("Wrote {}", path);
    } else {
        println!("{data}");
    }
    Ok(())
}

fn cmd_export_detect(path: &str, out: Option<&str>) -> Result<(), String> {
    let w = load_wallet(path)?;
    // Export detection root only: holder can derive per-address dk_d_j
    // for known address indices, but cannot decrypt memos or spend.
    let exported = WatchKeyMaterial::from_detect_wallet(&w);
    write_json_stdout_or_file(&exported, out)
}

fn cmd_export_view(path: &str, out: Option<&str>) -> Result<(), String> {
    let w = load_wallet(path)?;
    // Export incoming_seed plus public address metadata so delegated viewers
    // can decrypt and validate incoming notes without spend authority.
    let exported = WatchKeyMaterial::from_view_wallet(&w);
    write_json_stdout_or_file(&exported, out)
}

fn load_watch_material(path: &str) -> Result<WatchKeyMaterial, String> {
    load_private_json(path, "watch material")
}

fn cmd_watch_init(path: &str, material_path: &str, force: bool) -> Result<(), String> {
    let output_path = Path::new(path);
    if output_path.exists() && !force {
        return Err(format!(
            "watch wallet {} already exists; pass --force to overwrite",
            path
        ));
    }
    let material = load_watch_material(material_path)?;
    let watch = WatchWalletFile::from_material(material);
    save_watch_wallet(path, &watch)?;
    println!("Watch wallet created: {}", path);
    Ok(())
}

fn sync_watch_wallet_once(
    path: &str,
    profile: &WalletNetworkProfile,
) -> Result<WatchSyncSummary, String> {
    let mut watch = load_watch_wallet(path)?;
    let cursor = match &watch {
        WatchWalletFile::Detect { scanned, .. } | WatchWalletFile::View { scanned, .. } => *scanned,
    };
    let rollup = RollupRpc::new(profile);
    let feed = rollup.load_notes_since(cursor).map_err(|e| {
        format!(
            "watch sync failed: {}. Run `tzel-wallet --wallet {} profile show` to confirm the saved rollup profile.",
            e, path
        )
    })?;
    let summary = apply_watch_feed(&mut watch, &feed);
    save_watch_wallet(path, &watch)?;
    Ok(summary)
}

fn cmd_watch_sync(path: &str, profile: &WalletNetworkProfile) -> Result<(), String> {
    let summary = sync_watch_wallet_once(path, profile)?;
    let watch = load_watch_wallet(path)?;
    let status = watch.status();
    match status.mode {
        "detect" => println!(
            "Watch sync: {} new candidate matches, cursor={}, tracked={}, mode={}",
            summary.found, status.scanned, status.tracked, status.mode
        ),
        "view" => println!(
            "Watch sync: {} new validated notes, cursor={}, tracked={}, incoming_total={}, spend_status={}",
            summary.found,
            status.scanned,
            status.tracked,
            status.incoming_total,
            status.spend_status
        ),
        _ => println!(
            "Watch sync: {} new records, cursor={}, tracked={}",
            summary.found, status.scanned, status.tracked
        ),
    }
    Ok(())
}

fn cmd_watch_sync_watch(
    path: &str,
    profile: &WalletNetworkProfile,
    interval_secs: u64,
) -> Result<(), String> {
    loop {
        cmd_watch_sync(path, profile)?;
        std::thread::sleep(std::time::Duration::from_secs(interval_secs.max(1)));
    }
}

fn cmd_watch_show(path: &str) -> Result<(), String> {
    let watch = load_watch_wallet(path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&watch.status())
            .map_err(|e| format!("serialize watch status: {}", e))?
    );
    Ok(())
}

fn run_watch_wallet(path: &str, cmd: UserWatchCmd) -> Result<(), String> {
    match cmd {
        UserWatchCmd::Init { material, force } => cmd_watch_init(path, &material, force),
        UserWatchCmd::Sync {
            watch,
            interval_secs,
        } => {
            let profile = load_required_network_profile(path)?;
            if watch {
                cmd_watch_sync_watch(path, &profile, interval_secs)
            } else {
                cmd_watch_sync(path, &profile)
            }
        }
        UserWatchCmd::Show => cmd_watch_show(path),
    }
}

fn detect_service_status(path: &str) -> Result<WatchWalletStatus, String> {
    Ok(load_watch_wallet(path)?.status())
}

fn detect_service_sync_once(
    path: &str,
    profile: &WalletNetworkProfile,
) -> Result<WatchSyncSummary, String> {
    let _lock = acquire_wallet_lock(path)?;
    sync_watch_wallet_once(path, profile)
}

pub fn run_detection_service_once(
    path: &str,
) -> Result<(WatchWalletStatus, WatchSyncSummary), String> {
    let profile = load_required_network_profile(path)?;
    let summary = detect_service_sync_once(path, &profile)?;
    let status = detect_service_status(path)?;
    Ok((status, summary))
}

pub fn load_detection_service_status(path: &str) -> Result<WatchWalletStatus, String> {
    detect_service_status(path)
}

pub fn validate_detection_service_wallet(path: &str) -> Result<(), String> {
    match load_watch_wallet(path)? {
        WatchWalletFile::Detect { .. } | WatchWalletFile::View { .. } => {}
    }
    Ok(())
}

fn cmd_scan(path: &str, ledger: &str) -> Result<(), String> {
    let mut w = load_wallet(path)?;

    let url = format!("{}/notes?cursor={}", ledger, w.scanned);
    let feed: NotesFeedResp = get_json(&url)?;
    let nf_resp: NullifiersResp = get_json(&format!("{}/nullifiers", ledger))?;
    let summary = apply_scan_feed(&mut w, &feed, nf_resp.nullifiers);
    save_wallet(path, &w)?;
    println!(
        "Scanned: {} new notes found, {} spent removed, balance={}",
        summary.found,
        summary.spent,
        w.available_balance()
    );
    Ok(())
}

struct ScanSummary {
    found: usize,
    spent: usize,
    confirmed_pending: usize,
}

fn apply_scan_feed(
    w: &mut WalletFile,
    feed: &NotesFeedResp,
    nullifiers: impl IntoIterator<Item = F>,
) -> ScanSummary {
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

    let nf_set: std::collections::HashSet<F> = nullifiers.into_iter().collect();
    let before = w.notes.len();
    w.notes.retain(|n| !nf_set.contains(&note_nullifier(n)));
    let spent = before - w.notes.len();
    let before_pending = w.pending_spends.len();
    w.pending_spends
        .retain(|pending| !pending.nullifiers.iter().all(|nf| nf_set.contains(nf)));
    w.scanned = feed.next_cursor;
    ScanSummary {
        found,
        spent,
        confirmed_pending: before_pending - w.pending_spends.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    fn allow_full_xmss_rebuild<T>(f: impl FnOnce() -> T) -> T {
        let guard = FULL_XMSS_REBUILD_TEST_GUARD
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("full XMSS rebuild guard should lock");
        ALLOW_FULL_XMSS_REBUILD_IN_TESTS.store(true, std::sync::atomic::Ordering::SeqCst);
        let result = f();
        ALLOW_FULL_XMSS_REBUILD_IN_TESTS.store(false, std::sync::atomic::Ordering::SeqCst);
        drop(guard);
        result
    }

    pub(super) fn spawn_mock_http_server(routes: HashMap<String, (u16, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock http server");
        let addr = listener.local_addr().expect("mock server local addr");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(stream) => stream,
                    Err(_) => break,
                };
                let mut buffer = [0u8; 8192];
                let read = match stream.read(&mut buffer) {
                    Ok(read) => read,
                    Err(_) => continue,
                };
                if read == 0 {
                    continue;
                }
                let request = String::from_utf8_lossy(&buffer[..read]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let (status, body) = routes
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| (404, "null".to_string()));
                let status_text = match status {
                    200 => "OK",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    _ => "Unknown",
                };
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    status_text,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    pub(super) fn rollup_profile_for_url(base_url: &str) -> WalletNetworkProfile {
        WalletNetworkProfile {
            network: "shadownet".into(),
            rollup_node_url: base_url.into(),
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            bridge_ticketer: "KT1Jg4fj5wwnKHuW8aa9uDX6dRYBdjXhm2sJ".into(),
            public_account: "alice".into(),
            operator_url: None,
            source_alias: "alice".into(),
            octez_client_bin: "octez-client".into(),
            octez_client_dir: None,
            octez_node_endpoint: None,
            octez_protocol: None,
            burn_cap: "1".into(),
        }
    }

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
        let rebuilt = allow_full_xmss_rebuild(|| rebuild_address_state(&fixture.master_sk, 0, 0));
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

    #[test]
    fn balance_durable_key_hex_encodes_public_account() {
        assert_eq!(
            balance_durable_key("tzelshadownet"),
            "/tzel/v1/state/balances/by-key/747a656c736861646f776e6574"
        );
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

    pub(super) fn test_wallet(
        addr_counter: u32,
        legacy: Option<([u8; 64], [u8; 64])>,
    ) -> WalletFile {
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
            pending_spends: vec![],
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

    pub(super) fn note_memo_for_wallet_address(
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

    fn wallet_note_for_address(w: &WalletFile, j: u32, value: u64, rseed: F, index: usize) -> Note {
        let acc = w.account();
        let addr = &w.addresses[j as usize];
        let nk_spend = derive_nk_spend(&acc.nk, &addr.d_j);
        let nk_tag = derive_nk_tag(&nk_spend);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &nk_tag);
        let rcm = derive_rcm(&rseed);
        let cm = commit(&addr.d_j, value, &rcm, &otag);
        Note {
            nk_spend,
            nk_tag,
            auth_root: addr.auth_root,
            d_j: addr.d_j,
            v: value,
            rseed,
            cm,
            index,
            addr_index: j,
        }
    }

    fn payment_address_for_wallet_address(w: &WalletFile, j: u32) -> PaymentAddress {
        let (ek_v, _, ek_d, _) = w.kem_keys(j);
        w.addresses[j as usize].payment_address(&ek_v, &ek_d)
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
    fn test_view_export_includes_address_metadata() {
        let w = test_wallet(2, None);
        let material = WatchKeyMaterial::from_view_wallet(&w);
        let WatchKeyMaterial::View {
            incoming_seed,
            addresses,
            ..
        } = material
        else {
            panic!("expected view material");
        };
        assert_eq!(incoming_seed, w.account().incoming_seed);
        assert_eq!(addresses.len(), 2);
        for (expected, exported) in w.addresses.iter().zip(addresses.iter()) {
            assert_eq!(exported.index, expected.index);
            assert_eq!(exported.d_j, expected.d_j);
            assert_eq!(exported.auth_root, expected.auth_root);
            assert_eq!(exported.auth_pub_seed, expected.auth_pub_seed);
            assert_eq!(exported.nk_tag, expected.nk_tag);
        }
    }

    #[test]
    fn test_detect_material_matches_wallet_note() {
        let w = test_wallet(1, None);
        let material = WatchKeyMaterial::from_detect_wallet(&w);
        let WatchKeyMaterial::Detect {
            detect_root,
            addr_count,
            ..
        } = material
        else {
            panic!("expected detect material");
        };
        let nm = note_memo_for_wallet_address(&w, 0, 55, felt_tag(b"watch-detect"), None);
        let detected = detect_record_for_note(&detect_root, addr_count, &nm)
            .expect("wallet note should match");
        assert_eq!(detected.addr_index, 0);
        assert_eq!(detected.index, nm.index);
        assert_eq!(detected.cm, nm.cm);
    }

    #[test]
    fn test_view_material_recovers_and_validates_note() {
        let w = test_wallet(1, None);
        let material = WatchKeyMaterial::from_view_wallet(&w);
        let WatchKeyMaterial::View {
            incoming_seed,
            addresses,
            ..
        } = material
        else {
            panic!("expected view material");
        };
        let nm =
            note_memo_for_wallet_address(&w, 0, 77, felt_tag(b"watch-view"), Some(b"watch-memo"));
        let recovered = view_record_for_note(&incoming_seed, &addresses, &nm)
            .expect("view material should recover wallet note");
        assert_eq!(recovered.addr_index, 0);
        assert_eq!(recovered.index, nm.index);
        assert_eq!(recovered.cm, nm.cm);
        assert_eq!(recovered.value, 77);
        assert_eq!(recovered.memo, b"watch-memo");
    }

    #[test]
    fn test_view_material_rejects_wrong_commitment() {
        let w = test_wallet(1, None);
        let material = WatchKeyMaterial::from_view_wallet(&w);
        let WatchKeyMaterial::View {
            incoming_seed,
            addresses,
            ..
        } = material
        else {
            panic!("expected view material");
        };
        let mut nm =
            note_memo_for_wallet_address(&w, 0, 77, felt_tag(b"watch-bad-cm"), Some(b"bad"));
        nm.cm[0] ^= 0x01;
        assert!(view_record_for_note(&incoming_seed, &addresses, &nm).is_none());
    }

    proptest! {
        #[test]
        fn prop_view_material_recovers_wallet_notes(
            value in 1u64..1_000_000u64,
            memo in prop::collection::vec(any::<u8>(), 0..32),
            mut rseed in any::<[u8; 32]>(),
        ) {
            rseed[31] &= 0x07;
            let w = test_wallet(1, None);
            let material = WatchKeyMaterial::from_view_wallet(&w);
            let WatchKeyMaterial::View {
                incoming_seed,
                addresses,
                ..
            } = material else {
                panic!("expected view material");
            };
            let memo_opt = if memo.is_empty() {
                None
            } else {
                Some(memo.as_slice())
            };
            let expected_memo = if memo.is_empty() {
                vec![0xF6]
            } else {
                trim_decrypted_memo(memo.clone())
            };
            let nm = note_memo_for_wallet_address(&w, 0, value, rseed, memo_opt);
            let recovered = view_record_for_note(&incoming_seed, &addresses, &nm)
                .expect("wallet note should recover with viewing material");
            prop_assert_eq!(recovered.addr_index, 0);
            prop_assert_eq!(recovered.value, value);
            prop_assert_eq!(recovered.cm, nm.cm);
            prop_assert_eq!(recovered.memo, expected_memo);
        }

        #[test]
        fn prop_view_status_sums_values_without_leaking_secrets(
            values in prop::collection::vec(0u16..10_000u16, 0..12),
        ) {
            let notes: Vec<ViewedNoteRecord> = values
                .iter()
                .enumerate()
                .map(|(idx, value)| {
                    let mut cm = ZERO;
                    cm[..8].copy_from_slice(&(idx as u64).to_le_bytes());
                    ViewedNoteRecord {
                        index: idx,
                        addr_index: (idx % 3) as u32,
                        cm,
                        value: *value as u64,
                        memo: vec![idx as u8],
                    }
                })
                .collect();
            let watch = WatchWalletFile::View {
                version: WATCH_WALLET_VERSION,
                incoming_seed: felt_tag(b"watch-status-seed"),
                addresses: Vec::new(),
                scanned: values.len(),
                notes,
            };

            let status = watch.status();
            let status_json = serde_json::to_string(&status).expect("serialize watch status");
            prop_assert_eq!(status.mode, "view");
            prop_assert_eq!(status.tracked, values.len());
            prop_assert_eq!(
                status.incoming_total,
                values.iter().map(|value| *value as u128).sum::<u128>()
            );
            prop_assert!(!status_json.contains("incoming_seed"));
            prop_assert!(!status_json.contains("detect_root"));
        }
    }

    #[test]
    fn test_apply_watch_feed_detect_deduplicates_and_advances_cursor() {
        let w = test_wallet(1, None);
        let mut state = WatchWalletFile::from_material(WatchKeyMaterial::from_detect_wallet(&w));
        let note = note_memo_for_wallet_address(&w, 0, 12, felt_tag(b"watch-detect-feed"), None);
        let feed = NotesFeedResp {
            notes: vec![note.clone(), note],
            next_cursor: 9,
        };

        let first = apply_watch_feed(&mut state, &feed);
        assert_eq!(first.found, 1);
        assert_eq!(first.next_cursor, 9);
        let status = state.status();
        assert_eq!(status.scanned, 9);
        assert_eq!(status.tracked, 1);

        let second = apply_watch_feed(&mut state, &feed);
        assert_eq!(second.found, 0);
        assert_eq!(state.status().tracked, 1);
    }

    #[test]
    fn test_apply_watch_feed_view_tracks_incoming_total() {
        let w = test_wallet(1, None);
        let mut state = WatchWalletFile::from_material(WatchKeyMaterial::from_view_wallet(&w));
        let note_1 = note_memo_for_wallet_address(&w, 0, 12, felt_tag(b"watch-view-1"), None);
        let note_2 =
            note_memo_for_wallet_address(&w, 0, 18, felt_tag(b"watch-view-2"), Some(b"memo"));
        let mut alien =
            note_memo_for_wallet_address(&w, 0, 99, felt_tag(b"watch-view-alien"), None);
        alien.cm[0] ^= 0x01;
        let feed = NotesFeedResp {
            notes: vec![note_1, alien, note_2],
            next_cursor: 7,
        };

        let summary = apply_watch_feed(&mut state, &feed);
        assert_eq!(summary.found, 2);
        let status = state.status();
        assert_eq!(status.mode, "view");
        assert_eq!(status.scanned, 7);
        assert_eq!(status.tracked, 2);
        assert_eq!(status.incoming_total, 30);
        assert_eq!(status.notes.len(), 2);
        assert_eq!(status.notes[1].memo, b"memo");
    }

    #[test]
    fn test_apply_watch_feed_view_is_idempotent() {
        let w = test_wallet(1, None);
        let mut state = WatchWalletFile::from_material(WatchKeyMaterial::from_view_wallet(&w));
        let note =
            note_memo_for_wallet_address(&w, 0, 27, felt_tag(b"watch-view-repeat"), Some(b"dup"));
        let feed = NotesFeedResp {
            notes: vec![note.clone(), note],
            next_cursor: 11,
        };

        let first = apply_watch_feed(&mut state, &feed);
        let second = apply_watch_feed(&mut state, &feed);
        let status = state.status();

        assert_eq!(first.found, 1);
        assert_eq!(second.found, 0);
        assert_eq!(status.mode, "view");
        assert_eq!(status.scanned, 11);
        assert_eq!(status.tracked, 1);
        assert_eq!(status.incoming_total, 27);
        assert_eq!(status.notes[0].memo, b"dup");
    }

    #[test]
    fn test_watch_init_from_view_export_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let watch_path = dir.path().join("watch.json");
        let material_path = dir.path().join("watch.view.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let watch_path_str = watch_path.to_str().unwrap();
        let material_path_str = material_path.to_str().unwrap();

        let w = test_wallet(2, None);
        save_wallet(wallet_path_str, &w).expect("save wallet");
        cmd_export_view(wallet_path_str, Some(material_path_str)).expect("export view");
        cmd_watch_init(watch_path_str, material_path_str, false).expect("init watch wallet");

        let watch = load_watch_wallet(watch_path_str).expect("load watch wallet");
        match watch {
            WatchWalletFile::View {
                version,
                incoming_seed,
                addresses,
                scanned,
                notes,
            } => {
                assert_eq!(version, WATCH_WALLET_VERSION);
                assert_eq!(incoming_seed, w.account().incoming_seed);
                assert_eq!(addresses.len(), 2);
                assert_eq!(scanned, 0);
                assert!(notes.is_empty());
            }
            WatchWalletFile::Detect { .. } => panic!("expected view watch wallet"),
        }
    }

    #[test]
    fn test_watch_init_from_detect_export_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let watch_path = dir.path().join("watch.json");
        let material_path = dir.path().join("watch.detect.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let watch_path_str = watch_path.to_str().unwrap();
        let material_path_str = material_path.to_str().unwrap();

        let w = test_wallet(3, None);
        save_wallet(wallet_path_str, &w).expect("save wallet");
        cmd_export_detect(wallet_path_str, Some(material_path_str)).expect("export detect");
        cmd_watch_init(watch_path_str, material_path_str, false).expect("init watch wallet");

        let watch = load_watch_wallet(watch_path_str).expect("load watch wallet");
        match watch {
            WatchWalletFile::Detect {
                version,
                detect_root,
                addr_count,
                scanned,
                matches,
            } => {
                assert_eq!(version, WATCH_WALLET_VERSION);
                assert_eq!(detect_root, derive_detect_root(&w.account().incoming_seed));
                assert_eq!(addr_count, 3);
                assert_eq!(scanned, 0);
                assert!(matches.is_empty());
            }
            WatchWalletFile::View { .. } => panic!("expected detect watch wallet"),
        }
    }

    #[test]
    fn test_watch_init_force_overwrites_existing_wallet_mode() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let watch_path = dir.path().join("watch.json");
        let view_path = dir.path().join("watch.view.json");
        let detect_path = dir.path().join("watch.detect.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let watch_path_str = watch_path.to_str().unwrap();
        let view_path_str = view_path.to_str().unwrap();
        let detect_path_str = detect_path.to_str().unwrap();

        let w = test_wallet(2, None);
        save_wallet(wallet_path_str, &w).expect("save wallet");
        cmd_export_view(wallet_path_str, Some(view_path_str)).expect("export view");
        cmd_export_detect(wallet_path_str, Some(detect_path_str)).expect("export detect");
        cmd_watch_init(watch_path_str, view_path_str, false).expect("init view watch");

        let err = cmd_watch_init(watch_path_str, detect_path_str, false)
            .expect_err("re-init without force should fail");
        assert!(err.contains("already exists"));

        cmd_watch_init(watch_path_str, detect_path_str, true).expect("force overwrite watch");
        match load_watch_wallet(watch_path_str).expect("load overwritten watch") {
            WatchWalletFile::Detect { addr_count, .. } => assert_eq!(addr_count, 2),
            WatchWalletFile::View { .. } => panic!("expected detect watch wallet after overwrite"),
        }
    }

    #[test]
    fn test_run_detection_service_once_view_mode_syncs_and_sanitizes_status() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let watch_path = dir.path().join("watch.json");
        let material_path = dir.path().join("watch.view.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let watch_path_str = watch_path.to_str().unwrap();
        let material_path_str = material_path.to_str().unwrap();

        let w = test_wallet(1, None);
        let note =
            note_memo_for_wallet_address(&w, 0, 91, felt_tag(b"watch-service-view"), Some(b"hi"));
        let encoded = canonical_wire::encode_published_note(&note.cm, &note.enc)
            .expect("published note should encode");
        let note_key = indexed_durable_key(DURABLE_NOTE_PREFIX, 0);

        save_wallet(wallet_path_str, &w).expect("save wallet");
        cmd_export_view(wallet_path_str, Some(material_path_str)).expect("export view");
        cmd_watch_init(watch_path_str, material_path_str, false).expect("init watch wallet");

        let routes = HashMap::from([
            (
                "/global/block/head/durable/wasm_2_0_0/length?key=/tzel/v1/state/tree/size".into(),
                (200, "8".into()),
            ),
            (
                "/global/block/head/durable/wasm_2_0_0/value?key=/tzel/v1/state/tree/size".into(),
                (200, format!("\"{}\"", hex::encode(1u64.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/length?key={}",
                    note_key
                ),
                (200, encoded.len().to_string()),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/value?key={}",
                    note_key
                ),
                (200, format!("\"{}\"", hex::encode(encoded))),
            ),
        ]);
        let base_url = spawn_mock_http_server(routes);
        let profile = rollup_profile_for_url(&base_url);
        let profile_path = default_network_profile_path(watch_path_str);
        save_network_profile(&profile_path, &profile).expect("save profile");

        let (status, summary) =
            run_detection_service_once(watch_path_str).expect("detection service sync");
        assert_eq!(summary.found, 1);
        assert_eq!(summary.next_cursor, 1);
        assert_eq!(status.mode, "view");
        assert_eq!(status.tracked, 1);
        assert_eq!(status.incoming_total, 91);
        assert_eq!(status.notes.len(), 1);
        assert_eq!(status.notes[0].memo, b"hi");

        let status_json = serde_json::to_string(&status).expect("serialize status");
        assert!(!status_json.contains("incoming_seed"));
        assert!(!status_json.contains("detect_root"));
    }

    #[test]
    fn test_run_detection_service_once_detect_mode_syncs_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let watch_path = dir.path().join("watch.json");
        let material_path = dir.path().join("watch.detect.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let watch_path_str = watch_path.to_str().unwrap();
        let material_path_str = material_path.to_str().unwrap();

        let w = test_wallet(1, None);
        let note = note_memo_for_wallet_address(&w, 0, 73, felt_tag(b"watch-service-detect"), None);
        let encoded = canonical_wire::encode_published_note(&note.cm, &note.enc)
            .expect("published note should encode");
        let note_key = indexed_durable_key(DURABLE_NOTE_PREFIX, 0);

        save_wallet(wallet_path_str, &w).expect("save wallet");
        cmd_export_detect(wallet_path_str, Some(material_path_str)).expect("export detect");
        cmd_watch_init(watch_path_str, material_path_str, false).expect("init watch wallet");

        let routes = HashMap::from([
            (
                "/global/block/head/durable/wasm_2_0_0/length?key=/tzel/v1/state/tree/size".into(),
                (200, "8".into()),
            ),
            (
                "/global/block/head/durable/wasm_2_0_0/value?key=/tzel/v1/state/tree/size".into(),
                (200, format!("\"{}\"", hex::encode(1u64.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/length?key={}",
                    note_key
                ),
                (200, encoded.len().to_string()),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/value?key={}",
                    note_key
                ),
                (200, format!("\"{}\"", hex::encode(encoded))),
            ),
        ]);
        let base_url = spawn_mock_http_server(routes);
        let profile = rollup_profile_for_url(&base_url);
        let profile_path = default_network_profile_path(watch_path_str);
        save_network_profile(&profile_path, &profile).expect("save profile");

        let (status, summary) =
            run_detection_service_once(watch_path_str).expect("detection service sync");
        assert_eq!(summary.found, 1);
        assert_eq!(status.mode, "detect");
        assert_eq!(status.incoming_total, 0);
        assert_eq!(status.spend_status, "candidate_matches_only");
        assert_eq!(status.matches.len(), 1);
        assert_eq!(status.matches[0].cm, note.cm);
    }

    #[test]
    fn test_load_detection_service_status_is_sanitized() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let watch_path = dir.path().join("watch.json");
        let material_path = dir.path().join("watch.view.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let watch_path_str = watch_path.to_str().unwrap();
        let material_path_str = material_path.to_str().unwrap();

        let w = test_wallet(1, None);
        save_wallet(wallet_path_str, &w).expect("save wallet");
        cmd_export_view(wallet_path_str, Some(material_path_str)).expect("export view");
        cmd_watch_init(watch_path_str, material_path_str, false).expect("init watch wallet");

        let status = load_detection_service_status(watch_path_str).expect("load service status");
        let status_json = serde_json::to_string(&status).expect("serialize status");
        assert_eq!(status.mode, "view");
        assert_eq!(status.tracked, 0);
        assert_eq!(status.incoming_total, 0);
        assert!(!status_json.contains("incoming_seed"));
        assert!(!status_json.contains("detect_root"));
        assert!(!status_json.contains("auth_root"));
    }

    #[test]
    fn test_validate_detection_service_wallet_rejects_private_wallet_file() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();

        save_wallet(wallet_path_str, &test_wallet(1, None)).expect("save private wallet");
        let err = validate_detection_service_wallet(wallet_path_str)
            .expect_err("private spending wallet must not validate as watch wallet");
        assert!(err.contains("parse watch wallet"));
    }

    #[test]
    fn test_legacy_kem_keys_absent_for_migrated_wallet() {
        let w = test_wallet(0, None);
        assert!(w.legacy_kem_keys().is_none());
    }

    #[test]
    fn test_legacy_kem_keys_are_recovered_from_seed_material() {
        let legacy_v = [0x33; 64];
        let legacy_d = [0x44; 64];
        let w = test_wallet(0, Some((legacy_v, legacy_d)));
        let (ek_v1, dk_v1, ek_d1, dk_d1) = w.legacy_kem_keys().expect("legacy keys");
        let (ek_v2, dk_v2) = kem_keygen_from_seed(&legacy_v);
        let (ek_d2, dk_d2) = kem_keygen_from_seed(&legacy_d);

        assert_eq!(ek_v1.to_bytes(), ek_v2.to_bytes());
        assert_eq!(dk_v1.to_bytes(), dk_v2.to_bytes());
        assert_eq!(ek_d1.to_bytes(), ek_d2.to_bytes());
        assert_eq!(dk_d1.to_bytes(), dk_d2.to_bytes());
    }

    #[test]
    fn test_legacy_kem_keys_reject_incomplete_seed_material() {
        let mut w = test_wallet(0, None);
        w.kem_seed_v = vec![0x11; 63];
        w.kem_seed_d = vec![0x22; 64];

        assert!(
            w.legacy_kem_keys().is_none(),
            "legacy KEM recovery must reject malformed seed lengths"
        );
    }

    #[test]
    fn test_per_address_kem_keys_are_deterministic_and_distinct() {
        let w = test_wallet(0, None);
        let (ek_v0_a, dk_v0_a, ek_d0_a, dk_d0_a) = w.kem_keys(0);
        let (ek_v0_b, dk_v0_b, ek_d0_b, dk_d0_b) = w.kem_keys(0);
        let (ek_v1, dk_v1, ek_d1, dk_d1) = w.kem_keys(1);

        assert_eq!(ek_v0_a.to_bytes(), ek_v0_b.to_bytes());
        assert_eq!(dk_v0_a.to_bytes(), dk_v0_b.to_bytes());
        assert_eq!(ek_d0_a.to_bytes(), ek_d0_b.to_bytes());
        assert_eq!(dk_d0_a.to_bytes(), dk_d0_b.to_bytes());
        assert_ne!(ek_v0_a.to_bytes(), ek_v1.to_bytes());
        assert_ne!(dk_v0_a.to_bytes(), dk_v1.to_bytes());
        assert_ne!(ek_d0_a.to_bytes(), ek_d1.to_bytes());
        assert_ne!(dk_d0_a.to_bytes(), dk_d1.to_bytes());
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
    fn test_try_recover_note_migrated_wallet_accepts_per_address_notes_even_with_legacy_seeds() {
        let legacy_v = [0x21; 64];
        let legacy_d = [0x43; 64];
        let w = test_wallet(1, Some((legacy_v, legacy_d)));
        let rseed = felt_tag(b"wallet-note-per-address-with-legacy");
        let nm = note_memo_for_wallet_address(&w, 0, 41, rseed, None);

        let note = w
            .try_recover_note(&nm)
            .expect("migrated wallet should still recover per-address notes");

        assert_eq!(note.addr_index, 0);
        assert_eq!(note.v, 41);
        assert_eq!(note.cm, nm.cm);
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
    fn test_save_wallet_writes_xmss_floor_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let w = test_wallet(1, None);

        save_wallet(wallet_path_str, &w).expect("wallet should save");

        let floor_path = wallet_xmss_floor_path(wallet_path_str);
        let floor: WalletXmssFloor =
            serde_json::from_str(&std::fs::read_to_string(&floor_path).expect("read floor"))
                .expect("parse floor");

        assert_eq!(floor.wallet_fingerprint, hash(&w.master_sk));
        assert_eq!(floor.addr_counter, w.addr_counter);
        assert_eq!(
            floor.wots_key_indices.get(&0),
            Some(&w.addresses[0].bds.as_ref().unwrap().next_index)
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_save_wallet_sets_private_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let w = test_wallet(1, None);

        save_wallet(wallet_path.to_str().unwrap(), &w).expect("wallet should save");

        let mode = std::fs::metadata(&wallet_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_load_wallet_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        std::fs::write(&wallet_path, "{not-json").expect("write invalid wallet");

        let err = match load_wallet(wallet_path.to_str().unwrap()) {
            Ok(_) => panic!("invalid wallet must fail"),
            Err(err) => err,
        };
        assert!(err.contains("parse wallet"));
    }

    #[test]
    fn test_load_wallet_reports_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("missing-wallet.json");
        let err = match load_wallet(wallet_path.to_str().unwrap()) {
            Ok(_) => panic!("missing wallet must fail"),
            Err(err) => err,
        };
        assert!(err.contains("read wallet"));
    }

    #[test]
    fn test_load_wallet_rejects_stale_backup_against_xmss_floor() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let backup_path = dir.path().join("wallet-backup.json");

        let original = test_wallet(1, None);
        save_wallet(wallet_path_str, &original).expect("save original wallet");
        std::fs::copy(&wallet_path, &backup_path).expect("copy backup");

        let mut advanced = load_wallet(wallet_path_str).expect("reload wallet");
        let _ = advanced
            .reserve_next_auth(0)
            .expect("fixture wallet should advance auth state");
        save_wallet(wallet_path_str, &advanced).expect("save advanced wallet");

        std::fs::copy(&backup_path, &wallet_path).expect("restore stale wallet file");
        let err = match load_wallet(wallet_path_str) {
            Ok(_) => panic!("stale restore should be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("stale backup"), "unexpected error: {}", err);
    }

    #[test]
    fn test_load_address_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let address_path = dir.path().join("address.json");
        std::fs::write(&address_path, "{\"d_j\": 1").expect("write invalid address");

        let err =
            load_address(address_path.to_str().unwrap()).expect_err("invalid address must fail");
        assert!(err.contains("parse address"));
    }

    #[test]
    fn test_load_address_reports_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let address_path = dir.path().join("missing-address.json");
        let err =
            load_address(address_path.to_str().unwrap()).expect_err("missing address must fail");
        assert!(err.contains("read address"));
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
    fn test_wallet_lock_invalid_pid_is_not_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let lock_path = wallet_lock_path(wallet_path.to_str().unwrap());

        std::fs::write(&lock_path, "not-a-pid\n").expect("write invalid lock");
        let err = acquire_wallet_lock(wallet_path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("wallet is locked by another process"));
        assert!(lock_path.exists(), "invalid lock should remain in place");
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
    fn test_next_address_reuses_preseeded_fixture_without_derivation() {
        let base = base_test_wallet();
        let mut wallet = WalletFile {
            master_sk: base.master_sk,
            kem_seed_v: vec![],
            kem_seed_d: vec![],
            addresses: base.addresses[..2].to_vec(),
            addr_counter: 0,
            notes: vec![],
            scanned: 0,
            wots_key_indices: std::collections::HashMap::new(),
            pending_spends: vec![],
        };

        let (state0, addr0) = wallet.next_address().expect("first fixture address");
        let (state1, addr1) = wallet.next_address().expect("second fixture address");

        assert_eq!(state0.index, 0);
        assert_eq!(state1.index, 1);
        assert_eq!(addr0.auth_root, base.addresses[0].auth_root);
        assert_eq!(addr1.auth_root, base.addresses[1].auth_root);
        assert_eq!(wallet.addr_counter, 2);
        assert_eq!(wallet.addresses.len(), 2);
    }

    #[test]
    fn test_materialize_addresses_populates_wots_index_map_from_fixture_state() {
        let base = base_test_wallet();
        let mut wallet = WalletFile {
            master_sk: base.master_sk,
            kem_seed_v: vec![],
            kem_seed_d: vec![],
            addresses: base.addresses[..2].to_vec(),
            addr_counter: 2,
            notes: vec![],
            scanned: 0,
            wots_key_indices: std::collections::HashMap::new(),
            pending_spends: vec![],
        };

        wallet
            .materialize_addresses()
            .expect("fixture materialization should stay on cached state");
        assert_eq!(wallet.wots_key_indices.get(&0), Some(&0));
        assert_eq!(wallet.wots_key_indices.get(&1), Some(&0));
    }

    #[test]
    fn test_materialize_addresses_refreshes_wots_index_after_fixture_state_advance() {
        let mut wallet = test_wallet(1, None);
        assert_eq!(wallet.next_wots_key(0), 0);
        wallet.wots_key_indices.clear();

        wallet
            .materialize_addresses()
            .expect("fixture materialization should refresh cached WOTS index");

        assert_eq!(wallet.wots_key_indices.get(&0), Some(&1));
    }

    #[test]
    fn test_ensure_bds_rebuild_clears_legacy_fields_small_depth() {
        let acc = derive_account(&felt_tag(b"wallet-small-bds"));
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let next_auth_index = 5;
        let (rebuilt_state, rebuilt_root) =
            XmssBdsState::from_index_with_params(&ask_j, &auth_pub_seed, next_auth_index, 6, 2)
                .expect("small-depth BDS state should rebuild");

        let mut addr = WalletAddressState {
            index: 0,
            d_j,
            auth_root: rebuilt_root,
            auth_pub_seed,
            nk_tag: derive_nk_tag(&derive_nk_spend(&acc.nk, &d_j)),
            bds: None,
            next_auth_index,
            next_auth_path: rebuilt_state.current_path().to_vec(),
        };

        addr.ensure_bds_with(&ask_j, |_, _, idx| {
            XmssBdsState::from_index_with_params(&ask_j, &auth_pub_seed, idx, 6, 2)
        })
        .expect("legacy small-depth address state should rebuild");

        let restored = addr.bds.as_ref().expect("BDS state should be restored");
        assert_eq!(restored.next_index, rebuilt_state.next_index);
        assert_eq!(restored.current_path(), rebuilt_state.current_path());
        assert_eq!(addr.next_auth_index, 0);
        assert!(addr.next_auth_path.is_empty());
    }

    #[test]
    fn test_ensure_bds_with_rejects_root_mismatch() {
        let acc = derive_account(&felt_tag(b"wallet-small-root-mismatch"));
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let next_auth_index = 3;
        let (rebuilt_state, rebuilt_root) =
            XmssBdsState::from_index_with_params(&ask_j, &auth_pub_seed, next_auth_index, 6, 2)
                .expect("small-depth BDS state should rebuild");
        let mut wrong_root = rebuilt_root;
        wrong_root[0] ^= 0x01;

        let mut addr = WalletAddressState {
            index: 0,
            d_j,
            auth_root: wrong_root,
            auth_pub_seed,
            nk_tag: derive_nk_tag(&derive_nk_spend(&acc.nk, &d_j)),
            bds: None,
            next_auth_index,
            next_auth_path: rebuilt_state.current_path().to_vec(),
        };

        let err = addr
            .ensure_bds_with(&ask_j, |_, _, idx| {
                XmssBdsState::from_index_with_params(&ask_j, &auth_pub_seed, idx, 6, 2)
            })
            .expect_err("root mismatch should be rejected");
        assert!(err.contains("rebuilt XMSS root mismatch"));
        assert!(addr.bds.is_none());
        assert_eq!(addr.next_auth_index, next_auth_index);
        assert_eq!(addr.next_auth_path, rebuilt_state.current_path().to_vec());
    }

    #[test]
    fn test_ensure_bds_with_rejects_path_mismatch() {
        let acc = derive_account(&felt_tag(b"wallet-small-path-mismatch"));
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let next_auth_index = 4;
        let (rebuilt_state, rebuilt_root) =
            XmssBdsState::from_index_with_params(&ask_j, &auth_pub_seed, next_auth_index, 6, 2)
                .expect("small-depth BDS state should rebuild");
        let mut wrong_path = rebuilt_state.current_path().to_vec();
        wrong_path[0][0] ^= 0x01;

        let mut addr = WalletAddressState {
            index: 0,
            d_j,
            auth_root: rebuilt_root,
            auth_pub_seed,
            nk_tag: derive_nk_tag(&derive_nk_spend(&acc.nk, &d_j)),
            bds: None,
            next_auth_index,
            next_auth_path: wrong_path,
        };

        let err = addr
            .ensure_bds_with(&ask_j, |_, _, idx| {
                XmssBdsState::from_index_with_params(&ask_j, &auth_pub_seed, idx, 6, 2)
            })
            .expect_err("path mismatch should be rejected");
        assert!(err.contains("rebuilt XMSS path mismatch"));
        assert!(addr.bds.is_none());
        assert_eq!(addr.next_auth_index, next_auth_index);
    }

    #[test]
    fn test_ensure_bds_with_short_circuits_when_state_is_already_present() {
        let ask_j = felt_tag(b"wallet-ensure-bds-ignored");
        let mut addr = test_wallet(1, None).addresses[0].clone();
        let original = addr
            .bds
            .clone()
            .expect("fixture address should include BDS");
        let stale_path = vec![felt_tag(b"stale-legacy-path")];
        addr.next_auth_index = 99;
        addr.next_auth_path = stale_path.clone();

        addr.ensure_bds_with(&ask_j, |_, _, _| -> Result<(XmssBdsState, F), String> {
            panic!("ensure_bds_with should not rebuild when BDS state is already populated");
        })
        .expect("existing BDS state should short-circuit");

        let restored = addr.bds.as_ref().expect("BDS state should remain present");
        assert_eq!(restored.next_index, original.next_index);
        assert_eq!(restored.current_path(), original.current_path());
        assert_eq!(addr.next_auth_index, 99);
        assert_eq!(addr.next_auth_path, stale_path);
    }

    fn recompute_xmss_root_from_path(leaf: F, key_idx: u32, pub_seed: &F, siblings: &[F]) -> F {
        let mut current = leaf;
        let mut idx = key_idx;
        for (level, sibling) in siblings.iter().enumerate() {
            let node_idx = idx >> 1;
            current = if idx & 1 == 0 {
                xmss_tree_node_hash(pub_seed, level as u32, node_idx, &current, sibling)
            } else {
                xmss_tree_node_hash(pub_seed, level as u32, node_idx, sibling, &current)
            };
            idx >>= 1;
        }
        current
    }

    fn small_reference_root_and_path(
        ask_j: &F,
        pub_seed: &F,
        depth: usize,
        target: u32,
    ) -> (F, Vec<F>) {
        let mut nodes: Vec<F> = (0..(1u32 << depth))
            .map(|idx| auth_leaf_hash_with_pub_seed(ask_j, pub_seed, idx))
            .collect();
        let mut idx = target as usize;
        let mut path = Vec::with_capacity(depth);

        for level in 0..depth {
            path.push(nodes[idx ^ 1]);
            let mut next = Vec::with_capacity(nodes.len() / 2);
            for (node_idx, pair) in nodes.chunks_exact(2).enumerate() {
                next.push(xmss_tree_node_hash(
                    pub_seed,
                    level as u32,
                    node_idx as u32,
                    &pair[0],
                    &pair[1],
                ));
            }
            nodes = next;
            idx >>= 1;
        }

        (nodes[0], path)
    }

    #[test]
    fn test_xmss_bds_from_index_matches_reference_path_small_depth() {
        let acc = derive_account(&felt_tag(b"wallet-bds-ref"));
        let ask_j = derive_ask(&acc.ask_base, 0);
        let pub_seed = derive_auth_pub_seed(&ask_j);
        let depth = 6usize;
        let k = 2usize;

        for next_index in [0u32, 1, 2, 5, 17, 31] {
            let (state, root) =
                XmssBdsState::from_index_with_params(&ask_j, &pub_seed, next_index, depth, k)
                    .expect("small-depth BDS state should build");
            let (reference_root, reference_path) =
                small_reference_root_and_path(&ask_j, &pub_seed, depth, next_index);
            let leaf = auth_leaf_hash_with_pub_seed(&ask_j, &pub_seed, next_index);
            let rebuilt_from_bds =
                recompute_xmss_root_from_path(leaf, next_index, &pub_seed, state.current_path());
            let rebuilt_from_reference =
                recompute_xmss_root_from_path(leaf, next_index, &pub_seed, &reference_path);

            assert_eq!(root, reference_root);
            assert_eq!(
                rebuilt_from_reference, root,
                "reference path must verify for key {}",
                next_index
            );
            assert_eq!(
                state.current_path(),
                reference_path.as_slice(),
                "BDS path bytes differ for key {}",
                next_index
            );
            assert_eq!(
                rebuilt_from_bds, root,
                "BDS path must verify for key {}",
                next_index
            );
        }
    }

    #[test]
    fn test_xmss_bds_advance_matches_reference_sequence_small_depth() {
        let acc = derive_account(&felt_tag(b"wallet-bds-advance"));
        let ask_j = derive_ask(&acc.ask_base, 0);
        let pub_seed = derive_auth_pub_seed(&ask_j);
        let depth = 6usize;
        let k = 2usize;
        let (mut state, _) = XmssBdsState::from_index_with_params(&ask_j, &pub_seed, 0, depth, k)
            .expect("small-depth BDS state should build");

        for key_idx in 0u32..12 {
            let (_, reference_path) =
                small_reference_root_and_path(&ask_j, &pub_seed, depth, key_idx);
            let leaf = auth_leaf_hash_with_pub_seed(&ask_j, &pub_seed, key_idx);
            let rebuilt_from_bds =
                recompute_xmss_root_from_path(leaf, key_idx, &pub_seed, state.current_path());
            let rebuilt_from_reference =
                recompute_xmss_root_from_path(leaf, key_idx, &pub_seed, &reference_path);
            let expected_root = small_subtree_root(&ask_j, &pub_seed, 0, depth as u32);
            assert_eq!(
                rebuilt_from_reference, expected_root,
                "reference path must verify for key {}",
                key_idx
            );
            assert_eq!(
                state.current_path(),
                reference_path.as_slice(),
                "BDS path bytes differ for key {}",
                key_idx
            );
            assert_eq!(
                rebuilt_from_bds, expected_root,
                "BDS path must verify for key {}",
                key_idx
            );
            state
                .advance(&ask_j, &pub_seed)
                .expect("advance should succeed");
        }
    }

    #[test]
    fn test_reserve_next_auth_returns_path_bound_to_auth_root() {
        let mut w = test_wallet(1, None);
        let acc = w.account();
        let ask_j = derive_ask(&acc.ask_base, 0);
        let msg_hash = felt_tag(b"wallet-reserve-auth");

        let (key_idx, auth_root, auth_pub_seed, path) = w
            .reserve_next_auth(0)
            .expect("fixture address should reserve auth path");
        let (sig, _pk, _digits) = wots_sign(&ask_j, key_idx, &msg_hash);
        let recovered_pk = recover_wots_pk(&msg_hash, &auth_pub_seed, key_idx, &sig);
        let leaf = wots_pk_to_leaf(&auth_pub_seed, key_idx, &recovered_pk);
        let recomputed = recompute_xmss_root_from_path(leaf, key_idx, &auth_pub_seed, &path);

        assert_eq!(recomputed, auth_root);
        assert_eq!(w.wots_key_indices.get(&0), Some(&1));
    }

    #[test]
    fn test_reserve_next_auth_rejects_missing_address() {
        let mut w = test_wallet(0, None);
        let err = w
            .reserve_next_auth(0)
            .expect_err("missing address record should error");
        assert!(err.contains("missing address record 0"));
    }

    #[test]
    fn test_reserve_next_auth_rejects_exhausted_tree() {
        let mut w = test_wallet(1, None);
        w.addresses[0].bds = Some(XmssBdsState {
            next_index: AUTH_TREE_SIZE as u32,
            auth_path: vec![],
            keep: vec![],
            treehash: vec![],
            retain: vec![],
        });

        let err = w
            .reserve_next_auth(0)
            .expect_err("exhausted XMSS tree should error");
        assert!(err.contains("XMSS keys exhausted for address 0"));
    }

    #[test]
    fn test_next_wots_key_is_monotonic() {
        let mut w = test_wallet(1, None);
        assert_eq!(w.next_wots_key(0), 0);
        assert_eq!(w.next_wots_key(0), 1);
        assert_eq!(w.next_wots_key(0), 2);
    }

    #[test]
    fn test_select_notes_rejects_insufficient_funds() {
        let mut w = test_wallet(0, None);
        w.notes = vec![
            Note {
                nk_spend: ZERO,
                nk_tag: ZERO,
                auth_root: ZERO,
                d_j: ZERO,
                v: 10,
                rseed: ZERO,
                cm: felt_tag(b"note-0"),
                index: 0,
                addr_index: 0,
            },
            Note {
                nk_spend: ZERO,
                nk_tag: ZERO,
                auth_root: ZERO,
                d_j: ZERO,
                v: 15,
                rseed: ZERO,
                cm: felt_tag(b"note-1"),
                index: 1,
                addr_index: 0,
            },
        ];

        let err = w.select_notes(40).expect_err("overspend should fail");
        assert!(err.contains("insufficient funds"));
    }

    #[test]
    fn test_select_notes_prefers_single_large_note_when_sufficient() {
        let mut w = test_wallet(0, None);
        w.notes = vec![
            Note {
                nk_spend: ZERO,
                nk_tag: ZERO,
                auth_root: ZERO,
                d_j: ZERO,
                v: 5,
                rseed: ZERO,
                cm: felt_tag(b"small-note"),
                index: 0,
                addr_index: 0,
            },
            Note {
                nk_spend: ZERO,
                nk_tag: ZERO,
                auth_root: ZERO,
                d_j: ZERO,
                v: 40,
                rseed: ZERO,
                cm: felt_tag(b"large-note"),
                index: 1,
                addr_index: 0,
            },
        ];

        let selected = w.select_notes(30).expect("selection should succeed");
        assert_eq!(selected, vec![1]);
    }

    #[test]
    fn test_select_notes_skips_pending_spends() {
        let mut w = test_wallet(1, None);
        let note_0 = wallet_note_for_address(&w, 0, 40, felt_tag(b"pending-note-0"), 0);
        let note_1 = wallet_note_for_address(&w, 0, 25, felt_tag(b"pending-note-1"), 1);
        let pending_nf = note_nullifier(&note_0);
        w.notes = vec![note_0, note_1];
        w.register_pending_spend(
            vec![pending_nf],
            "transfer 40".into(),
            Some("opHash".into()),
        );

        let selected = w
            .select_notes(20)
            .expect("unlocked note should still be selectable");
        assert_eq!(selected, vec![1]);

        let err = w
            .select_notes(30)
            .expect_err("pending note must not count toward spendable balance");
        assert!(err.contains("insufficient funds"));
        assert_eq!(w.available_balance(), 25);
        assert_eq!(w.pending_outgoing_balance(), 40);
    }

    #[test]
    fn test_apply_scan_feed_deduplicates_new_notes_and_prunes_spent_ones() {
        let mut w = test_wallet(1, None);
        let existing = wallet_note_for_address(&w, 0, 40, felt_tag(b"wallet-scan-existing"), 5);
        let spent_nf = nullifier(&existing.nk_spend, &existing.cm, existing.index as u64);
        w.notes.push(existing.clone());

        let new_rseed = felt_tag(b"wallet-scan-new");
        let new_nm = note_memo_for_wallet_address(&w, 0, 25, new_rseed, Some(b"fresh"));
        let (alien_ek_v, _) = kem_keygen_from_seed(&[0x55; 64]);
        let (alien_ek_d, _) = kem_keygen_from_seed(&[0x77; 64]);
        let alien_nm = NoteMemo {
            index: 0,
            cm: felt_tag(b"wallet-scan-alien-cm"),
            enc: encrypt_note(
                77,
                &felt_tag(b"wallet-scan-alien"),
                None,
                &alien_ek_v,
                &alien_ek_d,
            ),
        };

        let feed = NotesFeedResp {
            notes: vec![
                NoteMemo {
                    index: new_nm.index,
                    cm: new_nm.cm,
                    enc: new_nm.enc.clone(),
                },
                NoteMemo {
                    index: new_nm.index,
                    cm: new_nm.cm,
                    enc: new_nm.enc.clone(),
                },
                alien_nm,
            ],
            next_cursor: 9,
        };

        let summary = apply_scan_feed(&mut w, &feed, vec![spent_nf]);
        assert_eq!(
            summary.found, 1,
            "duplicate recovered notes must be coalesced"
        );
        assert_eq!(summary.spent, 1, "spent existing note must be pruned");
        assert_eq!(w.scanned, 9, "scan cursor must advance to feed cursor");
        assert_eq!(
            w.notes.len(),
            1,
            "only the fresh recoverable note should remain"
        );
        assert_eq!(w.notes[0].v, 25);
        assert_eq!(w.notes[0].cm, new_nm.cm);
    }

    #[test]
    fn test_apply_scan_feed_clears_confirmed_pending_spends() {
        let mut w = test_wallet(1, None);
        let existing = wallet_note_for_address(&w, 0, 40, felt_tag(b"wallet-scan-pending"), 5);
        let spent_nf = note_nullifier(&existing);
        w.notes.push(existing);
        w.register_pending_spend(vec![spent_nf], "transfer 40".into(), Some("opHash".into()));

        let feed = NotesFeedResp {
            notes: vec![],
            next_cursor: 6,
        };

        let summary = apply_scan_feed(&mut w, &feed, vec![spent_nf]);
        assert_eq!(summary.spent, 1);
        assert_eq!(summary.confirmed_pending, 1);
        assert!(w.pending_spends.is_empty());
        assert!(w.notes.is_empty());
        assert_eq!(w.scanned, 6);
    }

    #[test]
    fn test_apply_scan_feed_drops_newly_recovered_note_if_already_nullified() {
        let mut w = test_wallet(1, None);
        let new_rseed = felt_tag(b"wallet-scan-new-spent");
        let new_nm = note_memo_for_wallet_address(&w, 0, 19, new_rseed, None);
        let recovered = w
            .try_recover_note(&new_nm)
            .expect("fixture note should recover for nullifier check");
        let spent_nf = nullifier(&recovered.nk_spend, &recovered.cm, recovered.index as u64);

        let feed = NotesFeedResp {
            notes: vec![new_nm],
            next_cursor: 4,
        };

        let summary = apply_scan_feed(&mut w, &feed, vec![spent_nf]);
        assert_eq!(
            summary.found, 1,
            "recovered note is discovered before spent pruning"
        );
        assert_eq!(
            summary.spent, 1,
            "nullified recovered note must be removed immediately"
        );
        assert!(
            w.notes.is_empty(),
            "nullified note must not remain in wallet state"
        );
        assert_eq!(w.scanned, 4);
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
    fn test_transfer_skip_proof_multiple_inputs_uses_preseeded_change_address() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let recipient_path = dir.path().join("recipient.json");
        let recipient_path_str = recipient_path.to_str().unwrap();

        let mut w = test_wallet(2, None);
        w.addr_counter = 1;
        w.notes = vec![
            wallet_note_for_address(&w, 0, 40, felt_tag(b"wallet-transfer-note-0"), 7),
            wallet_note_for_address(&w, 0, 25, felt_tag(b"wallet-transfer-note-1"), 11),
        ];
        save_wallet(wallet_path_str, &w).expect("wallet should save");

        let recipient = payment_address_for_wallet_address(&w, 0);
        std::fs::write(
            &recipient_path,
            serde_json::to_string_pretty(&recipient).expect("serialize recipient address"),
        )
        .expect("write recipient address");

        let expected_nullifiers: std::collections::HashSet<F> = w
            .notes
            .iter()
            .map(|n| nullifier(&n.nk_spend, &n.cm, n.index as u64))
            .collect();
        let change_addr = w.addresses[1].clone();
        let (_ek_v0, dk_v0, _ek_d0, dk_d0) = w.kem_keys(0);
        let (_ek_v1, dk_v1, _ek_d1, dk_d1) = w.kem_keys(1);

        let ledger_root = felt_tag(b"wallet-transfer-root");
        let recipient = load_address(recipient_path_str).expect("recipient should load");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        let prepared =
            prepare_transfer_skip_proof(&mut loaded, ledger_root, &recipient, 50, Some("memo-1"))
                .expect("skip-proof transfer request should build");
        save_wallet(wallet_path_str, &loaded).expect("wallet should save before submit");
        let req = &prepared.req;

        assert_eq!(req.root, ledger_root);
        assert_eq!(
            req.nullifiers
                .iter()
                .copied()
                .collect::<std::collections::HashSet<F>>(),
            expected_nullifiers
        );
        assert!(matches!(&req.proof, Proof::TrustMeBro));

        assert!(detect(&req.enc_1, &dk_d0));
        let (recipient_value, recipient_rseed, recipient_memo) =
            decrypt_memo(&req.enc_1, &dk_v0).expect("recipient note should decrypt");
        assert_eq!(recipient_value, 50);
        assert_eq!(&recipient_memo[..6], b"memo-1");
        let recipient_otag = owner_tag(
            &recipient.auth_root,
            &recipient.auth_pub_seed,
            &recipient.nk_tag,
        );
        assert_eq!(
            commit(
                &recipient.d_j,
                recipient_value,
                &derive_rcm(&recipient_rseed),
                &recipient_otag
            ),
            req.cm_1
        );

        assert!(detect(&req.enc_2, &dk_d1));
        let (change_value, change_rseed, change_memo) =
            decrypt_memo(&req.enc_2, &dk_v1).expect("change note should decrypt");
        assert_eq!(change_value, 15);
        assert_eq!(change_memo[0], 0xF6);
        let change_otag = owner_tag(
            &change_addr.auth_root,
            &change_addr.auth_pub_seed,
            &change_addr.nk_tag,
        );
        assert_eq!(
            commit(
                &change_addr.d_j,
                change_value,
                &derive_rcm(&change_rseed),
                &change_otag
            ),
            req.cm_2
        );

        finalize_successful_spend(wallet_path_str, &mut loaded, &prepared.selected)
            .expect("wallet should finalize");

        let finalized = load_wallet(wallet_path_str).expect("wallet should reload");
        assert!(finalized.notes.is_empty(), "spent notes should be removed");
        assert_eq!(finalized.addr_counter, 2);
        assert_eq!(finalized.addresses.len(), 2);
    }

    #[test]
    fn test_unshield_skip_proof_multiple_inputs_uses_preseeded_change_address() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();

        let mut w = test_wallet(2, None);
        w.addr_counter = 1;
        w.notes = vec![
            wallet_note_for_address(&w, 0, 35, felt_tag(b"wallet-unshield-note-0"), 5),
            wallet_note_for_address(&w, 0, 30, felt_tag(b"wallet-unshield-note-1"), 9),
        ];
        save_wallet(wallet_path_str, &w).expect("wallet should save");

        let expected_nullifiers: std::collections::HashSet<F> = w
            .notes
            .iter()
            .map(|n| nullifier(&n.nk_spend, &n.cm, n.index as u64))
            .collect();
        let change_addr = w.addresses[1].clone();
        let (_ek_v1, dk_v1, _ek_d1, dk_d1) = w.kem_keys(1);

        let ledger_root = felt_tag(b"wallet-unshield-root");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        let prepared = prepare_unshield_skip_proof(&mut loaded, ledger_root, 50, "bob")
            .expect("skip-proof unshield request should build");
        save_wallet(wallet_path_str, &loaded).expect("wallet should save before submit");
        let req = &prepared.req;

        assert_eq!(req.root, ledger_root);
        assert_eq!(req.v_pub, 50);
        assert_eq!(req.recipient, "bob");
        assert_eq!(
            req.nullifiers
                .iter()
                .copied()
                .collect::<std::collections::HashSet<F>>(),
            expected_nullifiers
        );
        assert!(matches!(&req.proof, Proof::TrustMeBro));
        assert_ne!(req.cm_change, ZERO);

        let enc_change = req
            .enc_change
            .as_ref()
            .expect("change note should be present");
        assert!(detect(enc_change, &dk_d1));
        let (change_value, change_rseed, change_memo) =
            decrypt_memo(enc_change, &dk_v1).expect("change note should decrypt");
        assert_eq!(change_value, 15);
        assert_eq!(change_memo[0], 0xF6);
        let change_otag = owner_tag(
            &change_addr.auth_root,
            &change_addr.auth_pub_seed,
            &change_addr.nk_tag,
        );
        assert_eq!(
            commit(
                &change_addr.d_j,
                change_value,
                &derive_rcm(&change_rseed),
                &change_otag
            ),
            req.cm_change
        );

        finalize_successful_spend(wallet_path_str, &mut loaded, &prepared.selected)
            .expect("wallet should finalize");

        let finalized = load_wallet(wallet_path_str).expect("wallet should reload");
        assert!(finalized.notes.is_empty(), "spent notes should be removed");
        assert_eq!(finalized.addr_counter, 2);
        assert_eq!(finalized.addresses.len(), 2);
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

    #[test]
    fn test_format_rollup_submission_includes_status_and_chunks() {
        let submission = RollupSubmission {
            id: "sub-abc".into(),
            kind: RollupSubmissionKind::Transfer,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            status: RollupSubmissionStatus::CommitmentIncluded,
            transport: RollupSubmissionTransport::Dal,
            operation_hash: Some("ooTestHash123456789ABCDEFG".into()),
            dal_chunks: vec![tzel_services::operator_api::RollupDalChunk {
                slot_index: 3,
                published_level: 101,
                payload_len: 128,
                commitment: "sh1chunk".into(),
                operation_hash: Some("ooChunkHash123456789ABCDEFG".into()),
            }],
            commitment: Some("sh1chunk".into()),
            published_level: Some(101),
            slot_index: Some(3),
            payload_hash: Some(hex::encode([0x11; 32])),
            payload_len: 128,
            detail: Some("Waiting for DAL attestation".into()),
        };

        let text = format_rollup_submission(&submission);
        assert!(text.contains("Operator submission id: sub-abc"));
        assert!(text.contains("Kind: Transfer"));
        assert!(text.contains("Status: commitment_included via dal"));
        assert!(text.contains("Operation hash: ooTestHash123456789ABCDEFG"));
        assert!(text.contains("chunk 0: slot 3 level 101 bytes 128 commitment sh1chunk"));
        assert!(text.contains("Waiting for DAL attestation"));
    }
}

fn cmd_balance(path: &str) -> Result<(), String> {
    let w = load_wallet(path)?;
    let pending = w.pending_nullifier_set();
    println!("Private balance: {}", w.balance());
    if !w.pending_spends.is_empty() {
        println!("Private available: {}", w.available_balance());
        println!("Pending outgoing: {}", w.pending_outgoing_balance());
        println!("Pending operations: {}", w.pending_spends.len());
    }
    println!("Notes: {}", w.notes.len());
    for (i, n) in w.notes.iter().enumerate() {
        println!(
            "  [{}] v={} cm={} index={}{}",
            i,
            n.v,
            short(&n.cm),
            n.index,
            if pending.contains(&note_nullifier(n)) {
                " pending"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn cmd_user_balance(path: &str) -> Result<(), String> {
    let w = load_wallet(path)?;
    println!("Private available: {}", w.available_balance());
    println!("Private tracked total: {}", w.balance());
    println!("Private pending outgoing: {}", w.pending_outgoing_balance());
    println!("Tracked notes: {}", w.notes.len());
    println!("Pending operations: {}", w.pending_spends.len());

    let profile_path = default_network_profile_path(path);
    if profile_path.exists() {
        let profile = load_network_profile(&profile_path)?;
        let rollup = RollupRpc::new(&profile);
        let public_balance = rollup
            .load_balances()?
            .get(&profile.public_account)
            .copied()
            .unwrap_or(0);
        println!(
            "Public rollup balance ({}): {}",
            profile.public_account, public_balance
        );
    }
    Ok(())
}

fn cmd_wallet_check(path: &str, profile: &WalletNetworkProfile) -> Result<(), String> {
    let wallet = load_wallet(path)?;
    let rollup = RollupRpc::new(profile);
    let head_hash = rollup.head_hash()?;
    let auth_domain = rollup.read_felt(DURABLE_AUTH_DOMAIN)?;
    let tree_size = rollup.read_u64(DURABLE_TREE_SIZE)?;
    let public_balance = rollup
        .load_balances()?
        .get(&profile.public_account)
        .copied()
        .unwrap_or(0);

    println!("Wallet file: {}", path);
    println!("Network: {}", profile.network);
    println!("Rollup head: {}", head_hash);
    println!("Auth domain: {}", short(&auth_domain));
    println!("Tree size: {}", tree_size);
    println!(
        "Local wallet: notes={}, pending={}, scanned={}",
        wallet.notes.len(),
        wallet.pending_spends.len(),
        wallet.scanned
    );
    println!(
        "Public rollup balance ({}): {}",
        profile.public_account, public_balance
    );

    if let Some(operator_url) = &profile.operator_url {
        let health_url = format!("{}/healthz", operator_url.trim_end_matches('/'));
        let health = get_text(&health_url)?;
        println!("Operator health: {}", health.trim());
    } else {
        println!("Operator health: not configured");
    }

    let note_check_limit = usize::try_from(tree_size)
        .unwrap_or(usize::MAX)
        .min(wallet.scanned.max(1))
        .min(4);
    for index in 0..note_check_limit {
        let key = indexed_durable_key(DURABLE_NOTE_PREFIX, index as u64);
        if rollup.read_published_note_bytes(index as u64)?.is_none() {
            return Err(format!(
                "rollup durable note {} is missing at {} while tree size is {}. This deployment cannot serve private note sync correctly.",
                index, key, tree_size
            ));
        }
    }

    println!("Check passed");
    Ok(())
}

fn cmd_rollup_sync(path: &str, profile: &WalletNetworkProfile) -> Result<(), String> {
    let mut w = load_wallet(path)?;
    let rollup = RollupRpc::new(profile);
    let feed = rollup.load_notes_since(w.scanned).map_err(|e| {
        format!(
            "sync failed: {}. Run `tzel-wallet check` for a fuller diagnosis.",
            e
        )
    })?;
    let nullifiers = rollup.load_nullifiers()?;
    let summary = apply_scan_feed(&mut w, &feed, nullifiers);
    save_wallet(path, &w)?;
    let public_balance = rollup
        .load_balances()?
        .get(&profile.public_account)
        .copied()
        .unwrap_or(0);
    println!(
        "Synced: {} new notes, {} spent removed, {} pending confirmed, private_available={}, public_balance={}",
        summary.found,
        summary.spent,
        summary.confirmed_pending,
        w.available_balance(),
        public_balance
    );
    Ok(())
}

fn cmd_rollup_sync_watch(
    path: &str,
    profile: &WalletNetworkProfile,
    interval_secs: u64,
) -> Result<(), String> {
    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    println!(
        "Watching rollup state every {}s. Press Ctrl-C to stop.",
        interval.as_secs()
    );
    loop {
        cmd_rollup_sync(path, profile)?;
        std::thread::sleep(interval);
    }
}

fn cmd_bridge_deposit(
    profile: &WalletNetworkProfile,
    amount: u64,
    public_account: &str,
) -> Result<(), String> {
    let rollup = RollupRpc::new(profile);
    let submission = rollup.deposit_to_bridge(public_account, amount)?;
    println!(
        "Submitted L1 bridge deposit of {} mutez for public account {}",
        amount, public_account
    );
    if let Some(op_hash) = submission.operation_hash {
        println!("Operation hash: {}", op_hash);
    }
    if !submission.output.is_empty() {
        println!("{}", submission.output);
    }
    println!("Run `tzel-wallet sync` after the deposit is included and processed by the rollup.");
    Ok(())
}

fn cmd_operator_status(profile: &WalletNetworkProfile, submission_id: &str) -> Result<(), String> {
    let operator_url = profile
        .operator_url
        .as_deref()
        .ok_or_else(|| "this wallet profile has no operator_url configured".to_string())?;
    let resp = load_operator_submission(operator_url, submission_id)?;
    println!("{}", format_rollup_submission(&resp.submission));
    Ok(())
}

fn print_rollup_submission(submission: &RollupSubmissionReceipt) {
    if let Some(submission_id) = &submission.submission_id {
        println!("Submission id: {}", submission_id);
    }
    if let Some(op_hash) = &submission.operation_hash {
        println!("Operation hash: {}", op_hash);
    }
    if !submission.output.is_empty() {
        println!("{}", submission.output);
    }
}

fn print_rollup_sync_hint(submission: &RollupSubmissionReceipt) {
    if submission.pending_dal {
        println!(
            "The operator has parked this message for DAL publication; wait for it to reach L1 before syncing."
        );
    } else {
        println!("Run `tzel-wallet sync` after the rollup processes the message.");
    }
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

    // Get current root
    let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))?;
    let root = tree_info.root;

    if pc.skip_proof {
        let prepared =
            prepare_transfer_skip_proof(&mut w, root, &recipient, amount, memo.as_deref())?;
        save_wallet(path, &w)?;
        let resp: TransferResp = post_json(&format!("{}/transfer", ledger), &prepared.req)?;
        finalize_successful_spend(path, &mut w, &prepared.selected)?;
        println!(
            "Transferred {} to recipient, change={} (idx={},{})",
            amount, prepared.change, resp.index_1, resp.index_2
        );
        println!("Run 'scan' to pick up change note.");
        return Ok(());
    }

    // Select notes
    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;

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

    finalize_successful_spend(path, &mut w, &selected)?;

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

    let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))?;
    let root = tree_info.root;

    if pc.skip_proof {
        let prepared = prepare_unshield_skip_proof(&mut w, root, amount, recipient)?;
        save_wallet(path, &w)?;
        let resp: UnshieldResp = post_json(&format!("{}/unshield", ledger), &prepared.req)?;
        finalize_successful_spend(path, &mut w, &prepared.selected)?;
        println!(
            "Unshielded {} to {}, change={} (change_idx={:?})",
            amount, recipient, prepared.change, resp.change_index
        );
        if prepared.change > 0 {
            println!("Run 'scan' to pick up change note.");
        }
        return Ok(());
    }

    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;

    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();

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

    finalize_successful_spend(path, &mut w, &selected)?;

    println!(
        "Unshielded {} to {}, change={} (change_idx={:?})",
        amount, recipient, change, resp.change_index
    );
    if change > 0 {
        println!("Run 'scan' to pick up change note.");
    }
    Ok(())
}

fn cmd_shield_rollup(
    path: &str,
    profile: &WalletNetworkProfile,
    sender: &str,
    amount: u64,
    to: Option<String>,
    memo: Option<String>,
    pc: &ProveConfig,
) -> Result<(), String> {
    let rollup = RollupRpc::new(profile);
    let balances = rollup.load_balances()?;
    let public_balance = balances.get(sender).copied().unwrap_or(0);
    if public_balance < amount {
        return Err(format!(
            "insufficient public rollup balance for {}: have {}, need {}",
            sender, public_balance, amount
        ));
    }

    let mut w = load_wallet(path)?;
    let (address, generated_self_address) = if let Some(addr_path) = to {
        (load_address(&addr_path)?, false)
    } else {
        let (_state, addr) = w.next_address()?;
        (addr, true)
    };

    let rseed = random_felt();
    let rcm = derive_rcm(&rseed);
    let otag = owner_tag(&address.auth_root, &address.auth_pub_seed, &address.nk_tag);
    let cm = commit(&address.d_j, amount, &rcm, &otag);
    let sender_f = hash(sender.as_bytes());
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
        felt_u64_to_hex(9),
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
    let req = ShieldReq {
        sender: sender.into(),
        v: amount,
        address,
        memo,
        proof,
        client_cm: cm,
        client_enc: Some(enc),
    };

    if generated_self_address {
        save_wallet(path, &w)?;
    }

    let kernel_req = shield_req_to_kernel(&req)?;
    let submission = rollup.submit_kernel_message(&KernelInboxMessage::Shield(kernel_req))?;
    println!(
        "Submitted shield of {} from {} into note {}",
        amount,
        sender,
        short(&req.client_cm)
    );
    print_rollup_submission(&submission);
    print_rollup_sync_hint(&submission);
    Ok(())
}

fn cmd_transfer_rollup(
    path: &str,
    profile: &WalletNetworkProfile,
    to_path: &str,
    amount: u64,
    memo: Option<String>,
    pc: &ProveConfig,
) -> Result<(), String> {
    let rollup = RollupRpc::new(profile);
    let snapshot = rollup.load_state_snapshot()?;
    let root = snapshot.current_root();

    let mut w = load_wallet(path)?;
    let recipient = load_address(to_path)?;
    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;

    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| note_nullifier(&w.notes[i]))
        .collect();

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

    let proof = {
        let auth_domain = snapshot.auth_domain;
        let n = selected.len();
        let mut args: Vec<String> = vec![];
        let mut cm_paths: Vec<Vec<F>> = vec![];
        let mut auth_paths: Vec<Vec<F>> = vec![];
        let mut wots_sigs: Vec<Vec<F>> = vec![];

        let nfs_for_sh = nullifiers.clone();
        let mh_1 = memo_ct_hash(&enc_1);
        let mh_2 = memo_ct_hash(&enc_2);
        let sighash =
            transfer_sighash(&auth_domain, &root, &nfs_for_sh, &cm_1, &cm_2, &mh_1, &mh_2);

        let mut wots_key_indices: Vec<u32> = vec![];
        let mut auth_pub_seeds: Vec<F> = vec![];
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
            let path_resp = snapshot.merkle_path(tree_idx)?;
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

        for (idx, &si) in selected.iter().enumerate() {
            let note = &w.notes[si];
            args.push(felt_to_hex(&note_nullifier(note)));
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

        args.push(felt_to_hex(&cm_1));
        args.push(felt_to_hex(&recipient.d_j));
        args.push(felt_u64_to_hex(amount));
        args.push(felt_to_hex(&rseed_1));
        args.push(felt_to_hex(&recipient.auth_root));
        args.push(felt_to_hex(&recipient.auth_pub_seed));
        args.push(felt_to_hex(&recipient.nk_tag));
        args.push(felt_to_hex(&memo_ct_hash(&enc_1)));

        args.push(felt_to_hex(&cm_2));
        args.push(felt_to_hex(&change_state.d_j));
        args.push(felt_u64_to_hex(change));
        args.push(felt_to_hex(&rseed_2));
        args.push(felt_to_hex(&change_state.auth_root));
        args.push(felt_to_hex(&change_state.auth_pub_seed));
        args.push(felt_to_hex(&change_state.nk_tag));
        args.push(felt_to_hex(&memo_ct_hash(&enc_2)));

        persist_wallet_and_make_proof(path, &w, pc, "run_transfer", &args)?
    };

    save_wallet(path, &w)?;
    let req = TransferReq {
        root,
        nullifiers: nullifiers.clone(),
        cm_1,
        cm_2,
        enc_1,
        enc_2,
        proof,
    };
    let kernel_req = transfer_req_to_kernel(&req)?;
    let submission = rollup.submit_kernel_message(&KernelInboxMessage::Transfer(kernel_req))?;
    w.register_pending_spend(
        nullifiers,
        format!("transfer {}", amount),
        submission.operation_hash.clone(),
    );
    save_wallet(path, &w)?;

    println!("Submitted transfer of {} with change {}", amount, change);
    print_rollup_submission(&submission);
    print_rollup_sync_hint(&submission);
    Ok(())
}

fn cmd_unshield_rollup(
    path: &str,
    profile: &WalletNetworkProfile,
    amount: u64,
    recipient: &str,
    pc: &ProveConfig,
) -> Result<(), String> {
    let rollup = RollupRpc::new(profile);
    let snapshot = rollup.load_state_snapshot()?;
    let root = snapshot.current_root();

    let mut w = load_wallet(path)?;
    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;

    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| note_nullifier(&w.notes[i]))
        .collect();

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

    let proof = {
        let auth_domain = snapshot.auth_domain;
        let n = selected.len();
        let mut args: Vec<String> = vec![];
        let mut cm_paths: Vec<Vec<F>> = vec![];
        let mut auth_paths: Vec<Vec<F>> = vec![];
        let mut wots_sigs: Vec<Vec<F>> = vec![];
        let mut auth_pub_seeds: Vec<F> = vec![];

        let has_change_val: u64 = if change > 0 { 1 } else { 0 };
        let recipient_f = hash(recipient.as_bytes());
        let mh_change_f = change_data.as_ref().map(|cd| cd.mh).unwrap_or(ZERO);
        let sighash = unshield_sighash(
            &auth_domain,
            &root,
            &nullifiers,
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
            let path_resp = snapshot.merkle_path(tree_idx)?;
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
            args.push(felt_to_hex(&note_nullifier(note)));
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

        persist_wallet_and_make_proof(path, &w, pc, "run_unshield", &args)?
    };

    save_wallet(path, &w)?;
    let req = UnshieldReq {
        root,
        nullifiers: nullifiers.clone(),
        v_pub: amount,
        recipient: recipient.into(),
        cm_change,
        enc_change,
        proof,
    };
    let kernel_req = unshield_req_to_kernel(&req)?;
    let submission = rollup.submit_kernel_message(&KernelInboxMessage::Unshield(kernel_req))?;
    w.register_pending_spend(
        nullifiers,
        format!("unshield {}", amount),
        submission.operation_hash.clone(),
    );
    save_wallet(path, &w)?;

    println!(
        "Submitted unshield of {} into public account {}",
        amount, recipient
    );
    print_rollup_submission(&submission);
    print_rollup_sync_hint(&submission);
    Ok(())
}

fn cmd_withdraw_rollup(
    profile: &WalletNetworkProfile,
    sender: &str,
    amount: u64,
    recipient: &str,
) -> Result<(), String> {
    let rollup = RollupRpc::new(profile);
    let balances = rollup.load_balances()?;
    let public_balance = balances.get(sender).copied().unwrap_or(0);
    if public_balance < amount {
        return Err(format!(
            "insufficient public rollup balance for {}: have {}, need {}",
            sender, public_balance, amount
        ));
    }
    let req = WithdrawReq {
        sender: sender.into(),
        recipient: recipient.into(),
        amount,
    };
    let submission = rollup
        .submit_kernel_message(&KernelInboxMessage::Withdraw(withdraw_req_to_kernel(&req)))?;
    println!(
        "Submitted withdrawal of {} from {} to {}",
        amount, sender, recipient
    );
    print_rollup_submission(&submission);
    println!("The L1 release still requires the normal smart-rollup outbox/cementation flow.");
    Ok(())
}

struct PreparedTransferSubmit {
    selected: Vec<usize>,
    change: u64,
    req: TransferReq,
}

struct ChangeData {
    d_j: F,
    rseed: F,
    auth_root: F,
    auth_pub_seed: F,
    nk_tag: F,
    mh: F,
}

struct PreparedUnshieldSubmit {
    selected: Vec<usize>,
    change: u64,
    req: UnshieldReq,
}

fn prepare_transfer_skip_proof(
    w: &mut WalletFile,
    root: F,
    recipient: &PaymentAddress,
    amount: u64,
    memo: Option<&str>,
) -> Result<PreparedTransferSubmit, String> {
    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;
    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();

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
    let memo_bytes = memo.map(str::as_bytes);
    let enc_1 = encrypt_note(amount, &rseed_1, memo_bytes, &ek_v_recv, &ek_d_recv);

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

    Ok(PreparedTransferSubmit {
        selected,
        change,
        req: TransferReq {
            root,
            nullifiers,
            cm_1,
            cm_2,
            enc_1,
            enc_2,
            proof: Proof::TrustMeBro,
        },
    })
}

fn prepare_unshield_skip_proof(
    w: &mut WalletFile,
    root: F,
    amount: u64,
    recipient: &str,
) -> Result<PreparedUnshieldSubmit, String> {
    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;
    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();

    let (cm_change, enc_change, _change_data) = if change > 0 {
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

    Ok(PreparedUnshieldSubmit {
        selected,
        change,
        req: UnshieldReq {
            root,
            nullifiers,
            v_pub: amount,
            recipient: recipient.into(),
            cm_change,
            enc_change,
            proof: Proof::TrustMeBro,
        },
    })
}

fn prepare_transfer_with_proof(
    w: &mut WalletFile,
    path: &str,
    ledger: &str,
    root: F,
    recipient: &PaymentAddress,
    amount: u64,
    memo: Option<&str>,
    pc: &ProveConfig,
) -> Result<PreparedTransferSubmit, String> {
    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;
    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| { let n = &w.notes[i]; nullifier(&n.nk_spend, &n.cm, n.index as u64) })
        .collect();

    let rseed_1 = random_felt();
    let rcm_1 = derive_rcm(&rseed_1);
    let ek_v_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
        recipient.ek_v.as_slice().try_into().map_err(|_| "bad ek_v")?,
    ).map_err(|_| "invalid ek_v")?;
    let ek_d_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
        recipient.ek_d.as_slice().try_into().map_err(|_| "bad ek_d")?,
    ).map_err(|_| "invalid ek_d")?;
    let otag_1 = owner_tag(&recipient.auth_root, &recipient.auth_pub_seed, &recipient.nk_tag);
    let cm_1 = commit(&recipient.d_j, amount, &rcm_1, &otag_1);
    let memo_bytes = memo.map(str::as_bytes);
    let enc_1 = encrypt_note(amount, &rseed_1, memo_bytes, &ek_v_recv, &ek_d_recv);

    let (change_state, _) = w.next_address()?;
    let (ek_v_c, _, ek_d_c, _) = w.kem_keys(change_state.index);
    let rseed_2 = random_felt();
    let rcm_2 = derive_rcm(&rseed_2);
    let otag_2 = owner_tag(&change_state.auth_root, &change_state.auth_pub_seed, &change_state.nk_tag);
    let cm_2 = commit(&change_state.d_j, change, &rcm_2, &otag_2);
    let enc_2 = encrypt_note(change, &rseed_2, None, &ek_v_c, &ek_d_c);

    let cfg: ConfigResp = get_json(&format!("{}/config", ledger))?;
    let auth_domain = cfg.auth_domain;
    let n = selected.len();
    let mut cm_paths: Vec<Vec<F>> = vec![];
    let mut auth_paths: Vec<Vec<F>> = vec![];
    let mut wots_sigs: Vec<Vec<F>> = vec![];
    let mut auth_pub_seeds: Vec<F> = vec![];
    let mut wots_key_indices: Vec<u32> = vec![];

    let nfs_for_sh: Vec<F> = selected
        .iter()
        .map(|&i| { let n = &w.notes[i]; nullifier(&n.nk_spend, &n.cm, n.index as u64) })
        .collect();
    let mh_1 = memo_ct_hash(&enc_1);
    let mh_2 = memo_ct_hash(&enc_2);
    let sighash = transfer_sighash(&auth_domain, &root, &nfs_for_sh, &cm_1, &cm_2, &mh_1, &mh_2);

    let selected_notes: Vec<(usize, u32, F)> = selected
        .iter()
        .map(|&i| (w.notes[i].index, w.notes[i].addr_index, w.notes[i].auth_root))
        .collect();
    for &(tree_idx, addr_idx, stored_auth_root) in &selected_notes {
        let path_resp: MerklePathResp = get_json(&format!("{}/tree/path/{}", ledger, tree_idx))?;
        ensure_path_matches_root(&path_resp.root, &root, tree_idx)?;
        cm_paths.push(path_resp.siblings);
        let ask_j = derive_ask(&w.account().ask_base, addr_idx);
        let (key_idx, auth_root, auth_pub_seed, apath) = w.reserve_next_auth(addr_idx)?;
        if auth_root != stored_auth_root {
            return Err(format!("auth_root mismatch for note at tree index {}", tree_idx));
        }
        auth_paths.push(apath);
        auth_pub_seeds.push(auth_pub_seed);
        let (sig, _, _) = wots_sign(&ask_j, key_idx, &sighash);
        wots_sigs.push(sig);
        wots_key_indices.push(key_idx);
    }

    let total_fields = 3 + 9 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS + 16;
    let mut args: Vec<String> = vec![
        felt_u64_to_hex(total_fields as u64),
        felt_u64_to_hex(n as u64),
        felt_to_hex(&auth_domain),
        felt_to_hex(&root),
    ];
    for (idx, &si) in selected.iter().enumerate() {
        let note = &w.notes[si];
        let nf = nullifier(&note.nk_spend, &note.cm, note.index as u64);
        args.extend([
            felt_to_hex(&nf), felt_to_hex(&note.nk_spend), felt_to_hex(&note.auth_root),
            felt_to_hex(&auth_pub_seeds[idx]), felt_u64_to_hex(wots_key_indices[idx] as u64),
            felt_to_hex(&note.d_j), felt_u64_to_hex(note.v),
            felt_to_hex(&note.rseed), felt_u64_to_hex(note.index as u64),
        ]);
    }
    for path in &cm_paths   { for s in path { args.push(felt_to_hex(s)); } }
    for path in &auth_paths { for s in path { args.push(felt_to_hex(s)); } }
    for sig  in &wots_sigs  { for s in sig  { args.push(felt_to_hex(s)); } }
    args.extend([
        felt_to_hex(&cm_1), felt_to_hex(&recipient.d_j), felt_u64_to_hex(amount),
        felt_to_hex(&rseed_1), felt_to_hex(&recipient.auth_root),
        felt_to_hex(&recipient.auth_pub_seed), felt_to_hex(&recipient.nk_tag),
        felt_to_hex(&mh_1),
        felt_to_hex(&cm_2), felt_to_hex(&change_state.d_j), felt_u64_to_hex(change),
        felt_to_hex(&rseed_2), felt_to_hex(&change_state.auth_root),
        felt_to_hex(&change_state.auth_pub_seed), felt_to_hex(&change_state.nk_tag),
        felt_to_hex(&mh_2),
    ]);

    let proof = persist_wallet_and_make_proof(path, w, pc, "run_transfer", &args)?;
    Ok(PreparedTransferSubmit { selected, change, req: TransferReq { root, nullifiers, cm_1, cm_2, enc_1, enc_2, proof } })
}

fn prepare_unshield_with_proof(
    w: &mut WalletFile,
    path: &str,
    ledger: &str,
    root: F,
    amount: u64,
    recipient: &str,
    pc: &ProveConfig,
) -> Result<PreparedUnshieldSubmit, String> {
    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;
    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| { let n = &w.notes[i]; nullifier(&n.nk_spend, &n.cm, n.index as u64) })
        .collect();

    let (cm_change, enc_change, change_data) = if change > 0 {
        let (change_state, _) = w.next_address()?;
        let (ek_v_c, _, ek_d_c, _) = w.kem_keys(change_state.index);
        let rseed_c = random_felt();
        let rcm_c = derive_rcm(&rseed_c);
        let otag_c = owner_tag(&change_state.auth_root, &change_state.auth_pub_seed, &change_state.nk_tag);
        let cm = commit(&change_state.d_j, change, &rcm_c, &otag_c);
        let enc = encrypt_note(change, &rseed_c, None, &ek_v_c, &ek_d_c);
        let mh = memo_ct_hash(&enc);
        let cd = ChangeData { d_j: change_state.d_j, rseed: rseed_c, auth_root: change_state.auth_root, auth_pub_seed: change_state.auth_pub_seed, nk_tag: change_state.nk_tag, mh };
        (cm, Some(enc), Some(cd))
    } else {
        (ZERO, None, None)
    };

    let cfg: ConfigResp = get_json(&format!("{}/config", ledger))?;
    let auth_domain = cfg.auth_domain;
    let n = selected.len();
    let mut cm_paths: Vec<Vec<F>> = vec![];
    let mut auth_paths: Vec<Vec<F>> = vec![];
    let mut wots_sigs: Vec<Vec<F>> = vec![];
    let mut auth_pub_seeds: Vec<F> = vec![];
    let mut wots_key_indices: Vec<u32> = vec![];

    let recipient_f = hash(recipient.as_bytes());
    let mh_change_f = change_data.as_ref().map(|cd| cd.mh).unwrap_or(ZERO);
    let nfs_for_sh: Vec<F> = selected
        .iter()
        .map(|&i| { let n = &w.notes[i]; nullifier(&n.nk_spend, &n.cm, n.index as u64) })
        .collect();
    let sighash = unshield_sighash(&auth_domain, &root, &nfs_for_sh, amount, &recipient_f, &cm_change, &mh_change_f);

    let selected_notes: Vec<(usize, u32, F)> = selected
        .iter()
        .map(|&i| (w.notes[i].index, w.notes[i].addr_index, w.notes[i].auth_root))
        .collect();
    for &(tree_idx, addr_idx, stored_auth_root) in &selected_notes {
        let path_resp: MerklePathResp = get_json(&format!("{}/tree/path/{}", ledger, tree_idx))?;
        ensure_path_matches_root(&path_resp.root, &root, tree_idx)?;
        cm_paths.push(path_resp.siblings);
        let ask_j = derive_ask(&w.account().ask_base, addr_idx);
        let (key_idx, auth_root, auth_pub_seed, apath) = w.reserve_next_auth(addr_idx)?;
        if auth_root != stored_auth_root {
            return Err(format!("auth_root mismatch for note at tree index {}", tree_idx));
        }
        auth_paths.push(apath);
        auth_pub_seeds.push(auth_pub_seed);
        let (sig, _, _) = wots_sign(&ask_j, key_idx, &sighash);
        wots_sigs.push(sig);
        wots_key_indices.push(key_idx);
    }

    let total = 5 + 9 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS + 8;
    let mut args: Vec<String> = vec![
        felt_u64_to_hex(total as u64), felt_u64_to_hex(n as u64),
        felt_to_hex(&auth_domain), felt_to_hex(&root),
        felt_u64_to_hex(amount), felt_to_hex(&recipient_f),
    ];
    for (idx, &si) in selected.iter().enumerate() {
        let note = &w.notes[si];
        let nf = nullifier(&note.nk_spend, &note.cm, note.index as u64);
        args.extend([
            felt_to_hex(&nf), felt_to_hex(&note.nk_spend), felt_to_hex(&note.auth_root),
            felt_to_hex(&auth_pub_seeds[idx]), felt_u64_to_hex(wots_key_indices[idx] as u64),
            felt_to_hex(&note.d_j), felt_u64_to_hex(note.v),
            felt_to_hex(&note.rseed), felt_u64_to_hex(note.index as u64),
        ]);
    }
    for path in &cm_paths   { for s in path { args.push(felt_to_hex(s)); } }
    for path in &auth_paths { for s in path { args.push(felt_to_hex(s)); } }
    for sig  in &wots_sigs  { for s in sig  { args.push(felt_to_hex(s)); } }
    args.push(felt_u64_to_hex(if change > 0 { 1 } else { 0 }));
    if let Some(cd) = &change_data {
        args.extend([
            felt_to_hex(&cd.d_j), felt_u64_to_hex(change), felt_to_hex(&cd.rseed),
            felt_to_hex(&cd.auth_root), felt_to_hex(&cd.auth_pub_seed),
            felt_to_hex(&cd.nk_tag), felt_to_hex(&cd.mh),
        ]);
    } else {
        args.extend(std::iter::repeat("0x0".to_string()).take(7));
    }

    let proof = persist_wallet_and_make_proof(path, w, pc, "run_unshield", &args)?;
    Ok(PreparedUnshieldSubmit { selected, change, req: UnshieldReq { root, nullifiers, v_pub: amount, recipient: recipient.into(), cm_change, enc_change, proof } })
}

fn finalize_successful_spend(
    path: &str,
    w: &mut WalletFile,
    selected: &[usize],
) -> Result<(), String> {
    let mut to_remove = selected.to_vec();
    to_remove.sort_unstable();
    for &i in to_remove.iter().rev() {
        w.notes.remove(i);
    }
    save_wallet(path, w)
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

#[cfg(test)]
mod network_profile_tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn network_profile_roundtrip_persists_shadownet_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wallet_path = dir.path().join("wallet.json");
        let profile_path = default_network_profile_path(wallet_path.to_str().unwrap());
        let profile = shadownet_profile(
            "https://rollup.shadownet.example".into(),
            "sr1ExampleRollup".into(),
            "KT1ExampleTicketer".into(),
            Some("https://operator.shadownet.example".into()),
            "alice".into(),
            Some("tz1alicepublicaccount".into()),
            Some("/tmp/octez-client".into()),
            Some("https://rpc.shadownet.example".into()),
            Some("ProtoExample".into()),
            Some("octez-client".into()),
            Some("2".into()),
        );

        save_network_profile(&profile_path, &profile).expect("save profile");
        let loaded = load_network_profile(&profile_path).expect("load profile");
        assert_eq!(loaded, profile);
    }

    #[test]
    fn load_required_network_profile_reads_saved_shadownet_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let profile_path = default_network_profile_path(wallet_path_str);
        let saved = shadownet_profile(
            "https://saved-rollup.example".into(),
            "sr1SavedRollup".into(),
            "KT1SavedTicketer".into(),
            None,
            "bootstrap1".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        save_network_profile(&profile_path, &saved).expect("save profile");

        let loaded = load_required_network_profile(wallet_path_str).expect("saved profile");
        assert_eq!(loaded, saved);
        assert_eq!(loaded.public_account, "bootstrap1");
    }

    #[test]
    fn parse_rollup_rpc_bytes_accepts_json_hex_and_utf8() {
        assert_eq!(
            parse_rollup_rpc_bytes("\"0x616263\"").expect("json hex"),
            b"abc"
        );
        assert_eq!(parse_rollup_rpc_bytes("646566").expect("bare hex"), b"def");
        assert_eq!(
            parse_rollup_rpc_bytes("\"tz1Alice\"").expect("utf8"),
            b"tz1Alice"
        );
    }

    #[test]
    fn rollup_rpc_load_notes_since_reads_chunked_note_payloads() {
        let wallet = super::tests::test_wallet(1, None);
        let mut rseed = ZERO;
        rseed[0] = 0x55;
        let note_memo =
            super::tests::note_memo_for_wallet_address(&wallet, 0, 77, rseed, Some(b"chunked"));
        let encoded = canonical_wire::encode_published_note(&note_memo.cm, &note_memo.enc)
            .expect("published note should encode");
        assert!(encoded.len() > DURABLE_NOTE_CHUNK_BYTES);

        let note_len_key = indexed_durable_note_len_key(0);
        let mut routes = HashMap::from([
            (
                "/global/block/head/durable/wasm_2_0_0/length?key=/tzel/v1/state/tree/size".into(),
                (200, "8".into()),
            ),
            (
                "/global/block/head/durable/wasm_2_0_0/value?key=/tzel/v1/state/tree/size".into(),
                (200, format!("\"{}\"", hex::encode(1u64.to_le_bytes()))),
            ),
            (
                "/global/block/head/durable/wasm_2_0_0/length?key=/tzel/v1/state/notes/0000000000000000".into(),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/length?key={}",
                    note_len_key
                ),
                (200, "8".into()),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/value?key={}",
                    note_len_key
                ),
                (
                    200,
                    format!("\"{}\"", hex::encode((encoded.len() as u64).to_le_bytes())),
                ),
            ),
        ]);
        for (chunk_index, chunk) in encoded.chunks(DURABLE_NOTE_CHUNK_BYTES).enumerate() {
            routes.insert(
                format!(
                    "/global/block/head/durable/wasm_2_0_0/value?key={}",
                    indexed_durable_note_chunk_key(0, chunk_index)
                ),
                (200, format!("\"{}\"", hex::encode(chunk))),
            );
        }
        let base_url = super::tests::spawn_mock_http_server(routes);
        let profile = super::tests::rollup_profile_for_url(&base_url);
        let rollup = RollupRpc::new(&profile);

        let feed = rollup
            .load_notes_since(0)
            .expect("chunked note should load");
        assert_eq!(feed.next_cursor, 1);
        assert_eq!(feed.notes.len(), 1);
        assert_eq!(feed.notes[0].index, note_memo.index);
        assert_eq!(feed.notes[0].cm, note_memo.cm);
        assert_eq!(feed.notes[0].enc.tag, note_memo.enc.tag);
        assert_eq!(feed.notes[0].enc.ct_d, note_memo.enc.ct_d);
        assert_eq!(feed.notes[0].enc.ct_v, note_memo.enc.ct_v);
        assert_eq!(feed.notes[0].enc.nonce, note_memo.enc.nonce);
        assert_eq!(
            feed.notes[0].enc.encrypted_data,
            note_memo.enc.encrypted_data
        );
    }

    #[test]
    fn rollup_rpc_rejects_oversized_chunked_note_lengths() {
        let note_len_key = indexed_durable_note_len_key(0);
        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/block/head/durable/wasm_2_0_0/length?key=/tzel/v1/state/tree/size".into(),
                (200, "8".into()),
            ),
            (
                "/global/block/head/durable/wasm_2_0_0/value?key=/tzel/v1/state/tree/size".into(),
                (200, format!("\"{}\"", hex::encode(1u64.to_le_bytes()))),
            ),
            (
                "/global/block/head/durable/wasm_2_0_0/length?key=/tzel/v1/state/notes/0000000000000000".into(),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/length?key={}",
                    note_len_key
                ),
                (200, "8".into()),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/value?key={}",
                    note_len_key
                ),
                (
                    200,
                    format!(
                        "\"{}\"",
                        hex::encode(((MAX_PUBLISHED_NOTE_BYTES as u64) + 1).to_le_bytes())
                    ),
                ),
            ),
        ]));
        let profile = super::tests::rollup_profile_for_url(&base_url);
        let rollup = RollupRpc::new(&profile);

        let err = rollup
            .load_notes_since(0)
            .expect_err("oversized note length should fail");
        assert!(err.contains("exceeds max supported size"));
    }

    #[test]
    fn mutez_to_tez_string_formats_exact_tezos_amounts() {
        assert_eq!(mutez_to_tez_string(1), "0.000001");
        assert_eq!(mutez_to_tez_string(1_500_000), "1.5");
        assert_eq!(mutez_to_tez_string(2_000_000), "2");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Wallet HTTP server (trust-me-bro mode)
// ═══════════════════════════════════════════════════════════════════════

pub fn wallet_server_entry() {
    use axum::{
        extract::State,
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    // Parse args — supports both `--flag value` and `--flag=value` forms.
    let args: Vec<String> = std::env::args().collect();
    let mut wallet_path = "wallet.json".to_string();
    let mut ledger_url = "http://localhost:8080".to_string();
    let mut port: u16 = 8081;
    let mut trust_me_bro = false;
    let mut proving_service: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        if let Some(v) = arg.strip_prefix("--wallet=") {
            wallet_path = v.to_string();
        } else if arg == "--wallet" {
            i += 1; if i < args.len() { wallet_path = args[i].clone(); }
        } else if let Some(v) = arg.strip_prefix("--ledger=") {
            ledger_url = v.to_string();
        } else if arg == "--ledger" {
            i += 1; if i < args.len() { ledger_url = args[i].clone(); }
        } else if let Some(v) = arg.strip_prefix("--port=") {
            port = v.parse().unwrap_or(8081);
        } else if arg == "--port" {
            i += 1; if i < args.len() { port = args[i].parse().unwrap_or(8081); }
        } else if arg == "--trust-me-bro" {
            trust_me_bro = true;
        } else if let Some(v) = arg.strip_prefix("--proving-service=") {
            proving_service = Some(v.to_string());
        } else if arg == "--proving-service" {
            i += 1; if i < args.len() { proving_service = Some(args[i].clone()); }
        }
        i += 1;
    }

    let pc = ProveConfig {
        skip_proof: trust_me_bro,
        reprove_bin: String::new(),
        executables_dir: String::new(),
        proving_service_url: proving_service,
    };

    // Create wallet if it does not exist.
    if !std::path::Path::new(&wallet_path).exists() {
        cmd_keygen(&wallet_path).expect("failed to create wallet");
    }

    let wallet = load_wallet(&wallet_path).expect("failed to load wallet");

    type WalletState = Arc<Mutex<(WalletFile, String, String, ProveConfig)>>;

    async fn balance_handler(
        State(st): State<WalletState>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
        let guard = st.lock().unwrap();
        let (ref w, _, _, _) = *guard;
        let bal = w.available_balance();
        Ok(Json(serde_json::json!({ "private_balance": bal })))
    }

    async fn address_handler(
        State(st): State<WalletState>,
    ) -> Result<Json<PaymentAddress>, (StatusCode, String)> {
        let mut guard = st.lock().unwrap();
        let (ref mut w, ref path, _, _) = *guard;
        let (_, addr) = w.next_address().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        save_wallet(path, w).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        Ok(Json(addr))
    }

    #[derive(serde::Deserialize)]
    struct ShieldBody {
        sender: String,
        amount: u64,
    }

    async fn shield_handler(
        State(st): State<WalletState>,
        Json(body): Json<ShieldBody>,
    ) -> Result<Json<ShieldResp>, (StatusCode, String)> {
        tokio::task::block_in_place(|| {
            let mut guard = st.lock().unwrap();
            let (ref mut w, ref path, ref ledger, ref pc) = *guard;

            let (_state, address) = w
                .next_address()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            let (proof, shield_cm, shield_enc) = if pc.skip_proof {
                (Proof::TrustMeBro, ZERO, None)
            } else {
                let rseed = random_felt();
                let rcm = derive_rcm(&rseed);
                let otag = owner_tag(&address.auth_root, &address.auth_pub_seed, &address.nk_tag);
                let cm = commit(&address.d_j, body.amount, &rcm, &otag);
                let sender_f = hash(body.sender.as_bytes());
                let ek_v_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
                    address.ek_v.as_slice().try_into()
                        .map_err(|_| (StatusCode::BAD_REQUEST, "bad ek_v length".to_string()))?,
                ).map_err(|_| (StatusCode::BAD_REQUEST, "invalid ek_v".to_string()))?;
                let ek_d_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
                    address.ek_d.as_slice().try_into()
                        .map_err(|_| (StatusCode::BAD_REQUEST, "bad ek_d length".to_string()))?,
                ).map_err(|_| (StatusCode::BAD_REQUEST, "invalid ek_d".to_string()))?;
                let enc = encrypt_note(body.amount, &rseed, None, &ek_v_recv, &ek_d_recv);
                let memo_ct_hash_f = memo_ct_hash(&enc);
                let args: Vec<String> = vec![
                    felt_u64_to_hex(9),
                    felt_u64_to_hex(body.amount),
                    felt_to_hex(&cm),
                    felt_to_hex(&sender_f),
                    felt_to_hex(&memo_ct_hash_f),
                    felt_to_hex(&address.auth_root),
                    felt_to_hex(&address.auth_pub_seed),
                    felt_to_hex(&address.nk_tag),
                    felt_to_hex(&address.d_j),
                    felt_to_hex(&rseed),
                ];
                let proof = pc.make_proof("run_shield", &args)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
                (proof, cm, Some(enc))
            };

            let req = ShieldReq {
                sender: body.sender,
                v: body.amount,
                address,
                memo: None,
                proof,
                client_cm: shield_cm,
                client_enc: shield_enc,
            };

            let resp: ShieldResp = post_json(&format!("{}/shield", ledger), &req)
                .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

            // Save only after successful POST so a failed shield doesn't
            // permanently consume an address slot on disk.
            save_wallet(path, w).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
            Ok(Json(resp))
        })
    }

    #[derive(serde::Deserialize)]
    struct TransferBody {
        to: PaymentAddress,
        amount: u64,
    }

    async fn transfer_handler(
        State(st): State<WalletState>,
        Json(body): Json<TransferBody>,
    ) -> Result<Json<TransferResp>, (StatusCode, String)> {
        tokio::task::block_in_place(|| {
            let mut guard = st.lock().unwrap();
            let (ref mut w, ref path, ref ledger, ref pc) = *guard;

            let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))
                .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
            let root = tree_info.root;

            let prepared = if pc.skip_proof {
                prepare_transfer_skip_proof(w, root, &body.to, body.amount, None)
                    .map_err(|e| (StatusCode::BAD_REQUEST, e))?
            } else {
                prepare_transfer_with_proof(w, path, ledger, root, &body.to, body.amount, None, pc)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
            };

            save_wallet(path, w).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            let resp: TransferResp = post_json(&format!("{}/transfer", ledger), &prepared.req)
                .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;

            finalize_successful_spend(path, w, &prepared.selected)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            Ok(Json(resp))
        })
    }

    #[derive(serde::Deserialize)]
    struct UnshieldBody {
        recipient: String,
        amount: u64,
    }

    async fn unshield_handler(
        State(st): State<WalletState>,
        Json(body): Json<UnshieldBody>,
    ) -> Result<Json<UnshieldResp>, (StatusCode, String)> {
        tokio::task::block_in_place(|| {
            let mut guard = st.lock().unwrap();
            let (ref mut w, ref path, ref ledger, ref pc) = *guard;

            let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))
                .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
            let root = tree_info.root;

            let prepared = if pc.skip_proof {
                prepare_unshield_skip_proof(w, root, body.amount, &body.recipient)
                    .map_err(|e| (StatusCode::BAD_REQUEST, e))?
            } else {
                prepare_unshield_with_proof(w, path, ledger, root, body.amount, &body.recipient, pc)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
            };

            save_wallet(path, w).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            let resp: UnshieldResp = post_json(&format!("{}/unshield", ledger), &prepared.req)
                .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;

            finalize_successful_spend(path, w, &prepared.selected)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            Ok(Json(resp))
        })
    }

    async fn scan_handler(
        State(st): State<WalletState>,
    ) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
        tokio::task::block_in_place(|| {
            let mut guard = st.lock().unwrap();
            let (ref mut w, ref path, ref ledger, _) = *guard;

            let url = format!("{}/notes?cursor={}", ledger, w.scanned);
            let feed: NotesFeedResp =
                get_json(&url).map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
            let nf_resp: NullifiersResp =
                get_json(&format!("{}/nullifiers", ledger))
                    .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;

            let summary = apply_scan_feed(w, &feed, nf_resp.nullifiers);
            save_wallet(path, w).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            Ok(Json(serde_json::json!({
                "found": summary.found,
                "spent": summary.spent,
            })))
        })
    }

    let mode = if trust_me_bro {
        "trust-me-bro".to_string()
    } else if let Some(ref url) = pc.proving_service_url {
        format!("proving-service={}", url)
    } else {
        "trust-me-bro (default)".to_string()
    };

    let state: WalletState = Arc::new(Mutex::new((wallet, wallet_path, ledger_url, pc)));

    let app = Router::new()
        .route("/balance", get(balance_handler))
        .route("/address", get(address_handler))
        .route("/shield", post(shield_handler))
        .route("/transfer", post(transfer_handler))
        .route("/unshield", post(unshield_handler))
        .route("/scan", post(scan_handler))
        .with_state(state);

    eprintln!("wallet-server listening on 0.0.0.0:{} [{}]", port, mode);

    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async move {
            let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        });
}
