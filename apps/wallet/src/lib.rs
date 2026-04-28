use clap::{Parser, Subcommand};
use ml_kem::KeyExport;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{
    contract::Contract as TezosContract, inbox::ExternalMessageFrame,
    smart_rollup::SmartRollupAddress,
};
use tzel_services::kernel_wire::{
    encode_kernel_inbox_message, KernelInboxMessage, KernelShieldReq, KernelStarkProof,
    KernelTransferReq, KernelUnshieldReq,
};
use tzel_services::operator_api::{
    RollupSubmission, RollupSubmissionKind, RollupSubmissionStatus, RollupSubmissionTransport,
    SubmitRollupMessageReq, SubmitRollupMessageResp,
};
use tzel_services::*;
use tzel_verifier::ProofBundle as VerifyProofBundle;

// ═══════════════════════════════════════════════════════════════════════
// Wallet file
// ═══════════════════════════════════════════════════════════════════════

const XMSS_BDS_K: usize = 2;

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
    bds: XmssBdsState,
}

impl WalletAddressState {
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
    #[serde(default)]
    addresses: Vec<WalletAddressState>,
    addr_counter: u32,
    notes: Vec<Note>,
    scanned: usize,
    #[serde(default)]
    wots_key_indices: std::collections::HashMap<u32, u32>,
    #[serde(default)]
    pending_spends: Vec<PendingSpend>,
    #[serde(default)]
    pending_deposits: Vec<PendingDeposit>,
    /// Monotonic counter feeding `derive_deposit_blind`. Each new bridge
    /// deposit increments it so distinct pools have distinct blinds even
    /// when they share an address index.
    #[serde(default)]
    deposit_nonce: u64,
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

/// A pending L1 bridge deposit pool. Each pool is keyed by
/// `pubkey_hash = H(auth_domain, auth_root, auth_pub_seed, blind)` and
/// the kernel maintains a per-pool aggregated balance. Multiple L1 tickets
/// to the same `deposit:<hex(pubkey_hash)>` recipient just add to that
/// balance (top-up). Shield decrements the balance by `v + fee +
/// producer_fee`; the user picks `v, fee, producer_fee` at shield time and
/// signs the request with one of the recipient's auth-tree WOTS+ keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingDeposit {
    /// Deposit pool key. The L1 recipient string is
    /// `deposit:<hex(pubkey_hash)>`.
    #[serde(with = "hex_f")]
    pubkey_hash: F,
    /// Per-deposit blind — the entropy that distinguishes this pool from
    /// other pools the same auth tree might own. Persisted so the wallet
    /// can re-derive `pubkey_hash` and prove ownership at shield time.
    #[serde(with = "hex_f")]
    blind: F,
    /// Wallet's address index whose auth tree owns this pool. Used to look
    /// up auth_root/auth_pub_seed/nk_spend at shield time.
    address_index: u32,
    /// auth_domain at deposit time. Persisted so we can reproduce the
    /// pubkey_hash exactly even if the kernel's auth_domain were ever
    /// inspected post-rotation. (auth_domain is frozen, so this is
    /// belt-and-braces.)
    #[serde(with = "hex_f")]
    auth_domain: F,
    /// Total mutez sent in this wallet's L1 ticket(s) to the pool. The
    /// kernel's actual balance can exceed this if other parties (e.g.,
    /// dust-attackers, or the user issuing top-ups) deposited to the same
    /// pool; sync reads the kernel-side authoritative balance.
    amount: u64,
    operation_hash: Option<String>,
    /// `Some(client_cm)` once the wallet has submitted a shield request
    /// against this pool. The kernel's balance entry will read empty
    /// once the shield lands; this flag lets reporting code distinguish
    /// "drained by us" from "never credited yet". Cleared by sync /
    /// pruning once the recipient note has been observed in the rollup
    /// tree.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_f_option")]
    shielded_cm: Option<F>,
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
    Outgoing {
        version: u16,
        #[serde(with = "hex_f")]
        outgoing_seed: F,
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
struct OutgoingNoteRecord {
    index: usize,
    role: String,
    value: u64,
    #[serde(with = "hex_f")]
    cm: F,
    #[serde(with = "hex_f")]
    rseed: F,
    #[serde(with = "hex_f")]
    d_j: F,
    #[serde(with = "hex_f")]
    auth_root: F,
    #[serde(with = "hex_f")]
    auth_pub_seed: F,
    #[serde(with = "hex_f")]
    nk_tag: F,
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
    Outgoing {
        version: u16,
        #[serde(with = "hex_f")]
        outgoing_seed: F,
        scanned: usize,
        notes: Vec<OutgoingNoteRecord>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct WatchWalletStatus {
    mode: &'static str,
    scanned: usize,
    tracked: usize,
    incoming_total: u128,
    outgoing_total: u128,
    spend_status: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    matches: Vec<DetectedNoteRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<ViewedNoteRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    outgoing_notes: Vec<OutgoingNoteRecord>,
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
        next_wots_index: u32,
    ) -> Result<WalletAddressState, String> {
        #[cfg(test)]
        panic!(
            "unexpected XMSS address derivation for j={} next_wots_index={} — default tests must use fixed prederived wallet/address fixtures",
            j, next_wots_index
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
        let (bds, auth_root) = XmssBdsState::from_index(&ask_j, &auth_pub_seed, next_wots_index)?;
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
            bds,
        })
    }

    fn materialize_addresses(&mut self) -> Result<(), String> {
        let existing = self.addresses.len() as u32;
        for j in existing..self.addr_counter {
            let next_wots_index = *self.wots_key_indices.get(&j).unwrap_or(&0);
            self.addresses
                .push(self.derive_address_state(j, next_wots_index)?);
        }
        for addr in &self.addresses {
            self.wots_key_indices
                .insert(addr.index, addr.bds.next_index);
        }
        Ok(())
    }

    #[cfg(test)]
    fn next_wots_key(&mut self, addr_index: u32) -> u32 {
        self.reserve_next_auth(addr_index)
            .expect("XMSS keys should be available for test wallet")
            .0
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

    /// Recover a note from the notes feed using the current per-address KEM keys.
    fn try_recover_note(&self, nm: &NoteMemo) -> Option<Note> {
        let acc = self.account();

        for addr in &self.addresses {
            let (_, dk_v_j, _, dk_d_j) = self.kem_keys(addr.index);
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
        let bds = &mut addr.bds;
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
            let next_index = addr.bds.next_index;
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

    fn from_outgoing_wallet(wallet: &WalletFile) -> Self {
        Self::Outgoing {
            version: WATCH_WALLET_VERSION,
            outgoing_seed: wallet.account().outgoing_seed,
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
            WatchKeyMaterial::Outgoing {
                version,
                outgoing_seed,
            } => Self::Outgoing {
                version,
                outgoing_seed,
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
                outgoing_total: 0,
                spend_status: "candidate_matches_only",
                matches: matches.clone(),
                notes: Vec::new(),
                outgoing_notes: Vec::new(),
            },
            WatchWalletFile::View { scanned, notes, .. } => WatchWalletStatus {
                mode: "view",
                scanned: *scanned,
                tracked: notes.len(),
                incoming_total: notes.iter().map(|note| note.value as u128).sum(),
                outgoing_total: 0,
                spend_status: "unavailable_without_spend_key",
                matches: Vec::new(),
                notes: notes.clone(),
                outgoing_notes: Vec::new(),
            },
            WatchWalletFile::Outgoing { scanned, notes, .. } => WatchWalletStatus {
                mode: "outgoing",
                scanned: *scanned,
                tracked: notes.len(),
                incoming_total: 0,
                outgoing_total: notes.iter().map(|note| note.value as u128).sum(),
                spend_status: "unavailable_without_spend_key",
                matches: Vec::new(),
                notes: Vec::new(),
                outgoing_notes: notes.clone(),
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

fn outgoing_record_for_note(outgoing_seed: &F, nm: &NoteMemo) -> Option<OutgoingNoteRecord> {
    let recovery = decrypt_outgoing_recovery(outgoing_seed, &nm.cm, &nm.enc.outgoing_ct)?;
    if recovery.commitment() != nm.cm {
        return None;
    }
    Some(OutgoingNoteRecord {
        index: nm.index,
        role: recovery.role.as_str().into(),
        value: recovery.value,
        cm: nm.cm,
        rseed: recovery.rseed,
        d_j: recovery.d_j,
        auth_root: recovery.auth_root,
        auth_pub_seed: recovery.auth_pub_seed,
        nk_tag: recovery.nk_tag,
    })
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
        WatchWalletFile::Outgoing {
            outgoing_seed,
            scanned,
            notes,
            ..
        } => {
            let mut known: std::collections::HashSet<(usize, F)> =
                notes.iter().map(|n| (n.index, n.cm)).collect();
            for nm in &feed.notes {
                let Some(record) = outgoing_record_for_note(outgoing_seed, nm) else {
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
    let (tmp, mut file) = create_private_temp_file(output_path, label)?;
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
    let (tmp, mut file) = create_private_temp_file(wallet_path, "wallet")?;
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
    let (tmp, mut file) = create_private_temp_file(&floor_path, "wallet xmss floor")?;
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
                .map(|addr| addr.bds.next_index)
        })
        .unwrap_or(0)
}

fn create_private_temp_file(
    output_path: &std::path::Path,
    label: &str,
) -> Result<(PathBuf, std::fs::File), String> {
    let parent = output_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let base_name = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("wallet");
    for attempt in 0..16u32 {
        let tmp = parent.join(format!(
            ".{}.tmp.{}.{}.{}",
            base_name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("system clock error: {}", e))?
                .as_nanos(),
            attempt
        ));
        match create_private_file(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(format!("create {} tmp: {}", label, err)),
        }
    }
    Err(format!("create {} tmp: too many collisions", label))
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
                "wallet appears to be restored from a stale backup: address {} next_wots_index {} is behind durable XMSS floor {}",
                addr_index, current_next, required_next
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_file(path: &std::path::Path) -> Result<std::fs::File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &std::path::Path) -> Result<std::fs::File, std::io::Error> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
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

fn post_json_with_bearer<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
    url: &str,
    body: &Req,
    bearer_token: Option<&str>,
) -> Result<Resp, String> {
    let mut req = ureq::post(url);
    if let Some(token) = bearer_token {
        req = req.header("Authorization", &format!("Bearer {}", token));
    }
    let resp = req
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

fn get_json_with_bearer<Resp: for<'de> Deserialize<'de>>(
    url: &str,
    bearer_token: Option<&str>,
) -> Result<Resp, String> {
    let mut req = ureq::get(url);
    if let Some(token) = bearer_token {
        req = req.header("Authorization", &format!("Bearer {}", token));
    }
    let resp = req.call().map_err(|e| format!("HTTP error: {}", e))?;
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

fn get_text_allow_404(url: &str) -> Result<Option<String>, String> {
    match ureq::get(url).call() {
        Ok(resp) => resp
            .into_body()
            .read_to_string()
            .map(Some)
            .map_err(|e| format!("read response: {}", e)),
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(e) => Err(format!("HTTP error: {}", e)),
    }
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
    dal_fee: u64,
    dal_fee_address: PaymentAddress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operator_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operator_bearer_token: Option<String>,
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

fn default_shadownet_octez_protocol() -> &'static str {
    "PtTALLiN"
}

fn default_octez_burn_cap() -> String {
    "1".into()
}

fn shadownet_profile(
    rollup_node_url: String,
    rollup_address: String,
    bridge_ticketer: String,
    dal_fee: u64,
    dal_fee_address: PaymentAddress,
    operator_url: Option<String>,
    operator_bearer_token: Option<String>,
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
        dal_fee,
        dal_fee_address,
        operator_url,
        operator_bearer_token,
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

fn validate_network_profile(profile: &WalletNetworkProfile) -> Result<(), String> {
    if profile.dal_fee == 0 {
        return Err("dal_fee must be greater than zero".into());
    }
    let has_operator_url = profile.operator_url.is_some();
    let has_operator_token = profile
        .operator_bearer_token
        .as_ref()
        .map(|token| !token.trim().is_empty())
        .unwrap_or(false);
    match (has_operator_url, has_operator_token) {
        (true, false) => {
            Err("operator_url requires operator_bearer_token; pass both or neither".into())
        }
        (false, true) => {
            Err("operator_bearer_token requires operator_url; pass both or neither".into())
        }
        _ => Ok(()),
    }
}

fn redacted_network_profile(profile: &WalletNetworkProfile) -> WalletNetworkProfile {
    let mut redacted = profile.clone();
    if redacted.operator_bearer_token.is_some() {
        redacted.operator_bearer_token = Some("<redacted>".into());
    }
    redacted
}

fn display_network_profile_json(profile: &WalletNetworkProfile) -> String {
    serde_json::to_string_pretty(&redacted_network_profile(profile)).unwrap()
}

fn save_network_profile(path: &Path, profile: &WalletNetworkProfile) -> Result<(), String> {
    validate_network_profile(profile)?;
    let data =
        serde_json::to_string_pretty(profile).map_err(|e| format!("serialize profile: {}", e))?;
    let (tmp, mut file) = create_private_temp_file(path, "network profile")?;
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
            "network profile is not configured: {}. Run `tzel-wallet profile init-shadownet --rollup-node-url ... --rollup-address ... --bridge-ticketer ... --dal-fee ... --dal-fee-address ... --source-alias ...`",
            e
        )
    })?;
    if profile.network != "shadownet" {
        return Err(format!(
            "unsupported wallet network profile '{}'",
            profile.network
        ));
    }
    validate_network_profile(&profile)?;
    Ok(profile)
}

const DURABLE_AUTH_DOMAIN: &str = "/tzel/v1/state/auth_domain";
const DURABLE_LAST_INPUT_LEVEL: &str = "/tzel/v1/state/last_input_level";
const DURABLE_PRIVATE_TX_FEE_LEVEL: &str = "/tzel/v1/state/fees/private_tx_level";
const DURABLE_PRIVATE_TX_COUNT_IN_LEVEL: &str = "/tzel/v1/state/fees/private_tx_count_in_level";
const DURABLE_TREE_SIZE: &str = "/tzel/v1/state/tree/size";
const DURABLE_TREE_ROOT: &str = "/tzel/v1/state/tree/root";
const DURABLE_NOTE_PREFIX: &str = "/tzel/v1/state/notes/";
const DURABLE_NOTE_LEN_SUFFIX: &str = "/len";
const DURABLE_NOTE_CHUNK_PREFIX: &str = "/chunk/";
const DURABLE_NOTE_CHUNK_BYTES: usize = 1024;
const MAX_PUBLISHED_NOTE_BYTES: usize = 4 * 1024 * 1024;
const DURABLE_NULLIFIER_COUNT: &str = "/tzel/v1/state/nullifiers/count";
const DURABLE_NULLIFIER_INDEX_PREFIX: &str = "/tzel/v1/state/nullifiers/index/";
const DURABLE_DEPOSIT_BALANCE_PREFIX: &str = "/tzel/v1/state/deposits/balance/";
const DURABLE_VERIFIER_CONFIG: &str = "/tzel/v1/state/verifier_config.bin";
const DURABLE_BRIDGE_TICKETER: &str = "/tzel/v1/state/bridge/ticketer";

#[derive(Debug, Clone)]
struct RollupSubmissionReceipt {
    output: String,
    operation_hash: Option<String>,
    submission_id: Option<String>,
    pending_dal: bool,
}

struct OctezAddressInfo {
    hash: String,
}

fn is_implicit_tezos_account_id(value: &str) -> bool {
    matches!(
        TezosContract::from_b58check(value),
        Ok(TezosContract::Implicit(_))
    )
}

fn canonicalize_public_balance_key(source_hash: &str, value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("public rollup account must not be empty".into());
    }
    if is_implicit_tezos_account_id(value) {
        return Ok(value.to_string());
    }
    if parse_public_balance_key(value).is_some() {
        let _ = withdraw_owner_from_public_balance_key(value)?;
        return Ok(value.to_string());
    }
    public_balance_key(source_hash, value)
}

fn withdraw_owner_from_public_balance_key<'a>(value: &'a str) -> Result<&'a str, String> {
    if is_implicit_tezos_account_id(value) {
        return Ok(value);
    }
    if let Some((owner, _label)) = parse_public_balance_key(value) {
        if is_implicit_tezos_account_id(owner) {
            return Ok(owner);
        }
        return Err(format!(
            "public rollup account {} has non-implicit owner {}",
            value, owner
        ));
    }
    Err(format!(
        "public rollup account {} must be a tz1/tz2/tz3 address or public:<tz-address>:<label>",
        value
    ))
}

fn resolve_rollup_unshield_recipient(
    rollup: &RollupRpc,
    recipient: Option<&str>,
) -> Result<String, String> {
    match recipient {
        Some(value) => validate_l1_withdrawal_recipient(value),
        None => Ok(rollup.source_address_info()?.hash),
    }
}

fn effective_octez_protocol(profile: &WalletNetworkProfile) -> Option<&str> {
    profile.octez_protocol.as_deref().or_else(|| {
        if profile.network == "shadownet" {
            Some(default_shadownet_octez_protocol())
        } else {
            None
        }
    })
}

#[derive(Clone)]
struct RollupStateSnapshot {
    auth_domain: F,
    required_tx_fee: u64,
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

    fn block_durable_value_url(&self, block_ref: &str, key: &str) -> String {
        format!(
            "{}/global/block/{}/durable/wasm_2_0_0/value?key={}",
            self.profile.rollup_node_url.trim_end_matches('/'),
            block_ref,
            key
        )
    }

    fn block_durable_length_url(&self, block_ref: &str, key: &str) -> String {
        format!(
            "{}/global/block/{}/durable/wasm_2_0_0/length?key={}",
            self.profile.rollup_node_url.trim_end_matches('/'),
            block_ref,
            key
        )
    }

    fn head_hash_url(&self) -> String {
        format!(
            "{}/global/block/head/hash",
            self.profile.rollup_node_url.trim_end_matches('/')
        )
    }

    fn smart_rollup_address_url(&self) -> String {
        format!(
            "{}/global/smart_rollup_address",
            self.profile.rollup_node_url.trim_end_matches('/')
        )
    }

    fn block_level_url(&self, block_ref: &str) -> String {
        format!(
            "{}/global/block/{}/level",
            self.profile.rollup_node_url.trim_end_matches('/'),
            block_ref
        )
    }

    fn read_durable_text_at_block(&self, block_ref: &str, key: &str) -> Result<String, String> {
        let url = self.block_durable_value_url(block_ref, key);
        get_text(&url).map_err(|e| format!("rollup RPC {} failed: {}", url, e))
    }

    fn read_durable_length_at_block(
        &self,
        block_ref: &str,
        key: &str,
    ) -> Result<Option<usize>, String> {
        let url = self.block_durable_length_url(block_ref, key);
        let Some(raw) =
            get_text_allow_404(&url).map_err(|e| format!("rollup RPC {} failed: {}", url, e))?
        else {
            return Ok(None);
        };
        Self::parse_durable_length(key, &raw)
    }

    fn parse_durable_length(key: &str, raw: &str) -> Result<Option<usize>, String> {
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

    fn read_durable_bytes_at_block(&self, block_ref: &str, key: &str) -> Result<Vec<u8>, String> {
        let raw = self.read_durable_text_at_block(block_ref, key)?;
        parse_rollup_rpc_bytes(&raw).map_err(|e| format!("decode durable value at {}: {}", key, e))
    }

    fn read_u64_at_block(&self, block_ref: &str, key: &str) -> Result<u64, String> {
        let bytes = self.read_durable_bytes_at_block(block_ref, key)?;
        Self::parse_u64(key, &bytes)
    }

    fn parse_u64(key: &str, bytes: &[u8]) -> Result<u64, String> {
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

    fn read_optional_u64_at_block(
        &self,
        block_ref: &str,
        key: &str,
    ) -> Result<Option<u64>, String> {
        if self.read_durable_length_at_block(block_ref, key)?.is_none() {
            return Ok(None);
        }
        let bytes = self.read_durable_bytes_at_block(block_ref, key)?;
        Self::parse_u64(key, &bytes).map(Some)
    }

    fn read_optional_i32_at_block(
        &self,
        block_ref: &str,
        key: &str,
    ) -> Result<Option<i32>, String> {
        if self.read_durable_length_at_block(block_ref, key)?.is_none() {
            return Ok(None);
        }
        let bytes = self.read_durable_bytes_at_block(block_ref, key)?;
        Self::parse_i32(key, &bytes).map(Some)
    }

    fn parse_i32(key: &str, bytes: &[u8]) -> Result<i32, String> {
        if bytes.len() != 4 {
            return Err(format!(
                "durable i32 at {} has {} bytes, expected 4",
                key,
                bytes.len()
            ));
        }
        let mut out = [0u8; 4];
        out.copy_from_slice(&bytes);
        Ok(i32::from_le_bytes(out))
    }

    fn read_felt_at_block(&self, block_ref: &str, key: &str) -> Result<F, String> {
        let bytes = self.read_durable_bytes_at_block(block_ref, key)?;
        Self::parse_felt(key, &bytes)
    }

    fn parse_felt(key: &str, bytes: &[u8]) -> Result<F, String> {
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

    fn block_level(&self, block_ref: &str) -> Result<i32, String> {
        let raw = get_text(&self.block_level_url(block_ref))?;
        if let Ok(level) = serde_json::from_str::<i32>(&raw) {
            return Ok(level);
        }
        if let Ok(text) = serde_json::from_str::<String>(&raw) {
            return text
                .parse::<i32>()
                .map_err(|e| format!("parse head level integer: {}", e));
        }
        raw.trim()
            .parse::<i32>()
            .map_err(|e| format!("parse head level integer: {}", e))
    }

    #[cfg(test)]
    fn current_required_tx_fee(&self) -> Result<u64, String> {
        let head_hash = self.head_hash()?;
        self.current_required_tx_fee_at_block(&head_hash)
    }

    fn current_required_tx_fee_at_block(&self, block_ref: &str) -> Result<u64, String> {
        let head_level = self.block_level(block_ref)?;
        let next_inbox_level = head_level.saturating_add(1);
        let last_input_level =
            self.read_optional_i32_at_block(block_ref, DURABLE_LAST_INPUT_LEVEL)?;
        let fee_level = self.read_optional_i32_at_block(block_ref, DURABLE_PRIVATE_TX_FEE_LEVEL)?;
        let private_tx_count_in_level =
            if last_input_level == Some(next_inbox_level) && fee_level == Some(next_inbox_level) {
                self.read_optional_u64_at_block(block_ref, DURABLE_PRIVATE_TX_COUNT_IN_LEVEL)?
                    .unwrap_or(0)
            } else {
                0
            };
        Ok(required_tx_fee_for_private_tx_count(
            private_tx_count_in_level,
        ))
    }

    fn load_notes_since(&self, cursor: usize) -> Result<NotesFeedResp, String> {
        self.load_notes_since_at_block("head", cursor)
    }

    fn read_published_note_bytes_at_block(
        &self,
        block_ref: &str,
        index: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        let direct_key = indexed_durable_key(DURABLE_NOTE_PREFIX, index);
        if self
            .read_durable_length_at_block(block_ref, &direct_key)?
            .is_some()
        {
            let bytes = self.read_durable_bytes_at_block(block_ref, &direct_key)?;
            if bytes.len() > MAX_PUBLISHED_NOTE_BYTES {
                return Err(format!(
                    "durable note {} at {} exceeds max supported size {}",
                    index, direct_key, MAX_PUBLISHED_NOTE_BYTES
                ));
            }
            return Ok(Some(bytes));
        }

        let len_key = indexed_durable_note_len_key(index);
        if self
            .read_durable_length_at_block(block_ref, &len_key)?
            .is_none()
        {
            return Ok(None);
        }

        let total_len_u64 = self.read_u64_at_block(block_ref, &len_key)?;
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
            let mut chunk = self.read_durable_bytes_at_block(block_ref, &chunk_key)?;
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

    fn load_notes_since_at_block(
        &self,
        block_ref: &str,
        cursor: usize,
    ) -> Result<NotesFeedResp, String> {
        let count: usize = self
            .read_u64_at_block(block_ref, DURABLE_TREE_SIZE)?
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
            let Some(bytes) = self.read_published_note_bytes_at_block(block_ref, i as u64)? else {
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
        self.load_nullifiers_at_block("head")
    }

    fn load_nullifiers_at_block(&self, block_ref: &str) -> Result<Vec<F>, String> {
        let count: usize = self
            .read_u64_at_block(block_ref, DURABLE_NULLIFIER_COUNT)?
            .try_into()
            .map_err(|_| "nullifier count does not fit in usize".to_string())?;
        let mut nullifiers = Vec::with_capacity(count);
        for i in 0..count {
            nullifiers.push(self.read_felt_at_block(
                block_ref,
                &indexed_durable_key(DURABLE_NULLIFIER_INDEX_PREFIX, i as u64),
            )?);
        }
        Ok(nullifiers)
    }

    /// For each pending deposit pool, fetch the kernel-side current balance.
    /// `None` (absent from the map) means the pool has never been credited
    /// (or has been fully drained — implementations may garbage-collect).
    fn load_pool_balances(
        &self,
        pending: &[PendingDeposit],
    ) -> Result<std::collections::HashMap<F, u64>, String> {
        let head = self.head_hash()?;
        let mut map: std::collections::HashMap<F, u64> = std::collections::HashMap::new();
        let mut seen: std::collections::HashSet<F> = std::collections::HashSet::new();
        for p in pending {
            if !seen.insert(p.pubkey_hash) {
                continue;
            }
            if let Some(balance) = self.try_read_deposit_balance(&head, &p.pubkey_hash)? {
                map.insert(p.pubkey_hash, balance);
            }
        }
        Ok(map)
    }

    /// Read a deposit pool's current balance from durable storage, returning
    /// `None` when the pool has never been credited or has been fully drained
    /// (kernel writes an empty value to bound storage).
    fn try_read_deposit_balance(
        &self,
        block_ref: &str,
        pubkey_hash: &F,
    ) -> Result<Option<u64>, String> {
        let key = format!("{}{}", DURABLE_DEPOSIT_BALANCE_PREFIX, hex::encode(pubkey_hash));
        match self.read_durable_length_at_block(block_ref, &key)? {
            None => Ok(None),
            Some(0) => Ok(None),
            Some(_) => {
                let bytes = self.read_durable_bytes_at_block(block_ref, &key)?;
                if bytes.is_empty() {
                    return Ok(None);
                }
                if bytes.len() != 8 {
                    return Err(format!(
                        "deposit balance for pool {} has unexpected length {}",
                        hex::encode(pubkey_hash),
                        bytes.len()
                    ));
                }
                Ok(Some(u64::from_le_bytes(bytes.try_into().unwrap())))
            }
        }
    }

    /// Probe the rollup's durable storage for an installed verifier config.
    /// Returns Ok(()) if the config key exists; Err otherwise. Used by
    /// `cmd_bridge_deposit` to refuse pre-config L1 tickets — the kernel
    /// would reject them and the funds would never be slotted.
    fn ensure_verifier_configured(&self, block_ref: &str) -> Result<(), String> {
        match self.read_durable_length_at_block(block_ref, DURABLE_VERIFIER_CONFIG)? {
            Some(_) => Ok(()),
            None => Err(
                "rollup verifier is not configured yet — refusing to send a bridge deposit. \
                 The kernel rejects deposits before verifier configuration. Wait for the \
                 admin to install the verifier config and retry."
                    .into(),
            ),
        }
    }

    /// Confirm the rollup node `rollup_node_url` actually serves the
    /// rollup at `profile.rollup_address`. Without this cross-check, a
    /// stale or malicious profile that points the two at different
    /// rollups could pass the verifier / ticketer preflight (both of
    /// which read state from `rollup_node_url`) while the L1 mint
    /// targets `rollup_address` — sending real mutez to a rollup the
    /// wallet has never inspected.
    fn ensure_rollup_address_matches(&self) -> Result<(), String> {
        let url = self.smart_rollup_address_url();
        let raw = get_text(&url)
            .map_err(|e| format!("rollup RPC {} failed: {}", url, e))?;
        let served = serde_json::from_str::<String>(&raw)
            .unwrap_or_else(|_| raw.trim().trim_matches('"').to_string());
        if served != self.profile.rollup_address {
            return Err(format!(
                "rollup-node served address ({}) does not match wallet profile.rollup_address ({}); \
                 refusing to send a bridge deposit. Update the wallet profile or point \
                 rollup_node_url at the right rollup.",
                served, self.profile.rollup_address,
            ));
        }
        Ok(())
    }

    /// Confirm the rollup's configured bridge ticketer matches the
    /// wallet's profile-supplied `bridge_ticketer`. The kernel rejects
    /// deposits whose `transfer.sender` doesn't match its configured
    /// ticketer, so submitting an L1 ticket against a different bridge
    /// would burn real mutez to a slot that never appears.
    fn ensure_bridge_ticketer_matches(
        &self,
        block_ref: &str,
        expected_ticketer: &str,
    ) -> Result<(), String> {
        let bytes = match self.read_durable_length_at_block(block_ref, DURABLE_BRIDGE_TICKETER)? {
            Some(_) => self.read_durable_bytes_at_block(block_ref, DURABLE_BRIDGE_TICKETER)?,
            None => {
                return Err(
                    "rollup bridge ticketer is not configured yet — refusing to send a bridge \
                     deposit. The kernel rejects deposits before bridge configuration."
                        .into(),
                )
            }
        };
        let configured =
            String::from_utf8(bytes).map_err(|_| "stored bridge ticketer is not UTF-8")?;
        if configured != expected_ticketer {
            return Err(format!(
                "wallet profile's bridge_ticketer {} does not match the rollup's configured \
                 ticketer {}; refusing to send a bridge deposit that the kernel would reject.",
                expected_ticketer, configured
            ));
        }
        Ok(())
    }

    fn load_state_snapshot(&self) -> Result<RollupStateSnapshot, String> {
        let head_hash = self.head_hash()?;
        self.load_state_snapshot_at_block(&head_hash)
    }

    fn load_state_snapshot_at_block(&self, block_ref: &str) -> Result<RollupStateSnapshot, String> {
        let auth_domain = self.read_felt_at_block(block_ref, DURABLE_AUTH_DOMAIN)?;
        let notes = self.load_notes_since_at_block(block_ref, 0)?.notes;
        let persisted_root = self.read_felt_at_block(block_ref, DURABLE_TREE_ROOT)?;
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
            required_tx_fee: self.current_required_tx_fee_at_block(block_ref)?,
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
                self.profile.operator_bearer_token.as_deref(),
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
        pubkey_hash: &F,
        amount_mutez: u64,
    ) -> Result<RollupSubmissionReceipt, String> {
        let tez_amount = mutez_to_tez_string(amount_mutez);
        let recipient = deposit_recipient_string(pubkey_hash);
        let mint_arg = format!(
            "Pair 0x{} \"{}\"",
            hex::encode(recipient.as_bytes()),
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

    fn source_address_info(&self) -> Result<OctezAddressInfo, String> {
        let mut args = vec![
            "show".to_string(),
            "address".to_string(),
            self.profile.source_alias.clone(),
        ];
        let output = self.run_octez_client_output(&mut args)?;
        parse_octez_address_info(&output)
    }

    fn run_octez_client(&self, args: &mut Vec<String>) -> Result<RollupSubmissionReceipt, String> {
        let combined = self.run_octez_client_output(args)?;
        Ok(RollupSubmissionReceipt {
            output: combined.clone(),
            operation_hash: extract_operation_hash(&combined),
            submission_id: None,
            pending_dal: false,
        })
    }

    fn run_octez_client_output(&self, args: &mut Vec<String>) -> Result<String, String> {
        let mut command = std::process::Command::new(&self.profile.octez_client_bin);
        if let Some(dir) = &self.profile.octez_client_dir {
            command.arg("-d").arg(dir);
        }
        if let Some(endpoint) = &self.profile.octez_node_endpoint {
            command.arg("-E").arg(endpoint);
        }
        if let Some(protocol) = effective_octez_protocol(self.profile) {
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

        Ok(combined)
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
        KernelInboxMessage::ConfigureVerifier(_) => RollupSubmissionKind::ConfigureVerifier,
        KernelInboxMessage::ConfigureBridge(_) => RollupSubmissionKind::ConfigureBridge,
        KernelInboxMessage::DalPointer(_) => {
            unreachable!("wallet should not submit raw DAL pointer messages")
        }
    }
}

fn submit_kernel_message_via_operator(
    operator_url: &str,
    operator_bearer_token: Option<&str>,
    rollup_address: &str,
    kind: RollupSubmissionKind,
    payload: Vec<u8>,
) -> Result<RollupSubmissionReceipt, String> {
    let base = operator_url.trim_end_matches('/');
    let resp: SubmitRollupMessageResp = post_json_with_bearer(
        &format!("{}/v1/rollup/submissions", base),
        &SubmitRollupMessageReq {
            kind,
            rollup_address: rollup_address.to_string(),
            payload,
        },
        operator_bearer_token,
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
    operator_bearer_token: Option<&str>,
    submission_id: &str,
) -> Result<SubmitRollupMessageResp, String> {
    let base = operator_url.trim_end_matches('/');
    get_json_with_bearer(
        &format!("{}/v1/rollup/submissions/{}", base, submission_id),
        operator_bearer_token,
    )
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

fn ensure_required_tx_fee(fee: u64, required_fee: u64) -> Result<(), String> {
    if fee < required_fee {
        return Err(format!(
            "fee below minimum: {} mutez < {} mutez ({} tez)",
            fee,
            required_fee,
            mutez_to_tez_string(required_fee),
        ));
    }
    Ok(())
}

fn resolve_requested_tx_fee(requested_fee: Option<u64>, required_fee: u64) -> Result<u64, String> {
    let fee = requested_fee.unwrap_or(required_fee);
    ensure_required_tx_fee(fee, required_fee)?;
    Ok(fee)
}

fn ensure_positive_dal_fee(dal_fee: u64) -> Result<(), String> {
    if dal_fee == 0 {
        return Err("dal_fee must be greater than zero".into());
    }
    Ok(())
}

struct PreparedOutputNote {
    cm: F,
    enc: EncryptedNote,
    mh: F,
    rseed: F,
}

fn outgoing_recovery_plaintext(
    address: &PaymentAddress,
    role: OutgoingNoteRole,
    value: u64,
    rseed: F,
) -> OutgoingRecoveryPlaintext {
    OutgoingRecoveryPlaintext {
        role,
        value,
        rseed,
        d_j: address.d_j,
        auth_root: address.auth_root,
        auth_pub_seed: address.auth_pub_seed,
        nk_tag: address.nk_tag,
    }
}

fn build_output_note_inner(
    address: &PaymentAddress,
    value: u64,
    memo: Option<&[u8]>,
    outgoing: Option<(&F, OutgoingNoteRole)>,
) -> Result<PreparedOutputNote, String> {
    let rseed = random_felt();
    let rcm = derive_rcm(&rseed);
    let ek_v = ml_kem::ml_kem_768::EncapsulationKey::new(
        address.ek_v.as_slice().try_into().map_err(|_| "bad ek_v")?,
    )
    .map_err(|_| "invalid ek_v")?;
    let ek_d = ml_kem::ml_kem_768::EncapsulationKey::new(
        address.ek_d.as_slice().try_into().map_err(|_| "bad ek_d")?,
    )
    .map_err(|_| "invalid ek_d")?;
    let otag = owner_tag(&address.auth_root, &address.auth_pub_seed, &address.nk_tag);
    let cm = commit(&address.d_j, value, &rcm, &otag);
    let mut enc = encrypt_note(value, &rseed, memo, &ek_v, &ek_d);
    if let Some((outgoing_seed, role)) = outgoing {
        let recovery = outgoing_recovery_plaintext(address, role, value, rseed);
        enc.outgoing_ct = encrypt_outgoing_recovery(outgoing_seed, &cm, &recovery);
    }
    let mh = memo_ct_hash(&enc);
    Ok(PreparedOutputNote { cm, enc, mh, rseed })
}

fn build_output_note_with_outgoing(
    address: &PaymentAddress,
    value: u64,
    memo: Option<&[u8]>,
    outgoing_seed: &F,
    role: OutgoingNoteRole,
) -> Result<PreparedOutputNote, String> {
    build_output_note_inner(address, value, memo, Some((outgoing_seed, role)))
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

fn extract_octez_prefixed_value(output: &str, prefix: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix(prefix)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
    })
}

fn parse_octez_address_info(output: &str) -> Result<OctezAddressInfo, String> {
    let hash = extract_octez_prefixed_value(output, "Hash:").ok_or_else(|| {
        format!(
            "could not parse octez-client address hash from output: {}",
            output
        )
    })?;
    Ok(OctezAddressInfo { hash })
}

fn host_stark_proof_to_kernel(proof: &Proof) -> Result<KernelStarkProof, String> {
    match proof {
        Proof::TrustMeBro => Err("rollup submission requires a real STARK proof".into()),
        Proof::Stark {
            proof_bytes,
            output_preimage,
        } => Ok(KernelStarkProof {
            proof_bytes: proof_bytes.clone(),
            output_preimage: output_preimage.clone(),
        }),
    }
}

fn shield_req_to_kernel(req: &ShieldReq) -> Result<KernelShieldReq, String> {
    Ok(KernelShieldReq {
        pubkey_hash: req.pubkey_hash,
        fee: req.fee,
        producer_fee: req.producer_fee,
        v: req.v,
        proof: host_stark_proof_to_kernel(&req.proof)?,
        client_cm: req.client_cm,
        client_enc: req.client_enc.clone(),
        producer_cm: req.producer_cm,
        producer_enc: req.producer_enc.clone(),
    })
}

fn transfer_req_to_kernel(req: &TransferReq) -> Result<KernelTransferReq, String> {
    Ok(KernelTransferReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        fee: req.fee,
        cm_1: req.cm_1,
        cm_2: req.cm_2,
        cm_3: req.cm_3,
        enc_1: req.enc_1.clone(),
        enc_2: req.enc_2.clone(),
        enc_3: req.enc_3.clone(),
        proof: host_stark_proof_to_kernel(&req.proof)?,
    })
}

fn unshield_req_to_kernel(req: &UnshieldReq) -> Result<KernelUnshieldReq, String> {
    Ok(KernelUnshieldReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        v_pub: req.v_pub,
        fee: req.fee,
        recipient: req.recipient.clone(),
        cm_change: req.cm_change,
        enc_change: req.enc_change.clone(),
        cm_fee: req.cm_fee,
        enc_fee: req.enc_fee.clone(),
        proof: host_stark_proof_to_kernel(&req.proof)?,
    })
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
    /// Export outgoing viewing material for sent-output recovery.
    ExportOutgoing {
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
    /// Transfer private notes to a recipient
    Transfer {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        dal_fee: u64,
        #[arg(long)]
        dal_fee_address: String,
        #[arg(long)]
        memo: Option<String>,
    },
    /// Unshield: withdraw private notes to an L1 address
    Unshield {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        dal_fee: u64,
        #[arg(long)]
        dal_fee_address: String,
        #[arg(long)]
        recipient: String,
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
    /// Upstream patch ②: when set, the CLI delegates proof generation to an
    /// HTTP proving-service (POST /v1/jobs + long-poll) instead of spawning
    /// `reprove` as a subprocess.
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
            generate_proof_via_service(
                url,
                &self.reprove_bin,
                &self.executables_dir,
                circuit,
                args,
            )
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
        | Cmd::Transfer { .. }
        | Cmd::Unshield { .. } => Some(acquire_wallet_lock(&cli.wallet)?),
        Cmd::ExportDetect { .. }
        | Cmd::ExportView { .. }
        | Cmd::ExportOutgoing { .. }
        | Cmd::Balance => None,
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
        Cmd::ExportOutgoing { out } => cmd_export_outgoing(&cli.wallet, out.as_deref()),
        Cmd::Scan { ledger } => cmd_scan(&cli.wallet, &ledger),
        Cmd::Balance => cmd_balance(&cli.wallet),
        Cmd::Transfer {
            ledger,
            to,
            amount,
            fee,
            dal_fee,
            dal_fee_address,
            memo,
        } => cmd_transfer(
            &cli.wallet,
            &ledger,
            &to,
            amount,
            fee,
            dal_fee,
            &dal_fee_address,
            memo,
            &pc,
        ),
        Cmd::Unshield {
            ledger,
            amount,
            fee,
            dal_fee,
            dal_fee_address,
            recipient,
        } => cmd_unshield(
            &cli.wallet,
            &ledger,
            amount,
            fee,
            dal_fee,
            &dal_fee_address,
            &recipient,
            &pc,
        ),
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

    /// HTTP endpoint of a tzel proving-service. When set, every command
    /// that needs a STARK proof delegates to the service instead of
    /// spawning the local `reprove` binary.
    ///
    /// See tzel-infra/docs/proving-service-api.md for the API contract.
    #[arg(long, global = true)]
    proving_service_url: Option<String>,

    #[command(subcommand)]
    cmd: UserCmd,
}

// ── Phase events (upstream patch ④) ────────────────────────────────────
//
// Emit one JSON Lines record per progress milestone on stderr. The
// daemon parses these line-by-line and drives the `JobPhase` watch
// channel off them. Free-form `eprintln!` lines remain alongside so
// humans tailing logs still get readable text; the JSON event is
// emitted just before each free-form line.
//
// Schema (each line is one self-contained object terminated by `\n`):
//
//   {"event":"phase","phase":"<name>","ts":"<RFC3339>","detail":{...}}
//
// where <name> ∈
//   op_started | witness_built | proving_started | proving_finished |
//   submitting_to_operator | operator_done | failed.
//
// The events are emitted unconditionally — they are not gated on
// `--json` because they are progress signals for tooling, distinct
// from the end-of-run result envelope (which IS gated on `--json`).
// The line is always one record terminated by `\n` so `BufRead::lines`
// in the daemon parses cleanly.

/// Build an RFC3339-ish UTC timestamp with seconds precision. Avoids
/// pulling chrono in just for this — the daemon does not parse the
/// timestamp, it only forwards it for display, so a bespoke formatter
/// is enough. `1970-01-01T00:00:00Z` style.
fn phase_event_now_ts() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Days since epoch, then convert to civil date by the standard
    // "civil_from_days" algorithm. Cheap, branchless, chrono-free.
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as u32;
    let (y, mo, d) = civil_from_days(days);
    let hh = sod / 3600;
    let mm = (sod / 60) % 60;
    let ss = sod % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, mo, d, hh, mm, ss
    )
}

/// Howard Hinnant's date algorithm — civil_from_days. Returns
/// (year, month [1..=12], day [1..=31]) for a UNIX-epoch day count.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// Emit one JSON-Lines phase event to stderr. `detail` is a
/// `serde_json::Value` (typically an object) — phase-specific fields.
/// Best-effort: a write failure is silently ignored, the CLI's primary
/// output channels are unaffected.
pub(crate) fn emit_phase_event(phase: &str, detail: serde_json::Value) {
    let line = serde_json::json!({
        "event": "phase",
        "phase": phase,
        "ts": phase_event_now_ts(),
        "detail": detail,
    });
    // Single write to stderr so the line cannot interleave with another
    // thread's output mid-record; `eprintln!` already line-buffers.
    eprintln!("{}", serde_json::to_string(&line).unwrap_or_default());
}

/// Convenience macro mirroring `serde_json::json!` for the `detail`
/// payload. Usage:
///
///   phase_event!("op_started", { "kind": "shield", "amount": 1000 });
macro_rules! phase_event {
    ($phase:expr, $detail:tt) => {{
        emit_phase_event($phase, serde_json::json!($detail));
    }};
}

/// Render an `operator_done` phase event from a `RollupSubmissionReceipt`.
/// Pulled out of the call sites because each of cmd_shield/cmd_transfer/
/// cmd_unshield_rollup needs the same shape.
fn emit_operator_done_event(receipt: &RollupSubmissionReceipt) {
    // The receipt does not carry a structured transport flag (it was
    // already serialised into `output`). For pedagogy purposes the
    // distinction we surface is "did the operator route via DAL" — the
    // operator_url path always uses DAL on shadownet, the local
    // octez-client fallback uses direct_inbox.
    let transport = if receipt.submission_id.is_some() {
        "dal"
    } else {
        "direct_inbox"
    };
    phase_event!("operator_done", {
        "submission_id": receipt.submission_id.clone().unwrap_or_default(),
        "l1_op_hash": receipt.operation_hash.clone(),
        "transport": transport,
        "dal_chunks_attested": receipt.pending_dal,
    });
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
    /// Deposit tez on L1 into a fresh self-owned pool. The wallet
    /// allocates a new auth-tree address, derives a deterministic blind,
    /// computes `pubkey_hash = H(0x04, auth_domain, auth_root,
    /// auth_pub_seed, blind)`, and instructs the bridge to credit
    /// `deposit:<hex(pubkey_hash)>` for `amount` mutez. Recipient,
    /// fee, and memo are decided later at shield time, not here.
    Deposit {
        /// L1 mutez to credit to the pool.
        #[arg(long)]
        amount: u64,
    },
    /// Reconstruct `PendingDeposit` entries from the seed alone after a
    /// wallet-file loss. For each candidate `(address_index,
    /// deposit_nonce)` pair within the bounds, derive the deterministic
    /// blind, compute the pubkey_hash, and probe the rollup for a
    /// non-zero balance. Each found pool is added to
    /// `pending_deposits` and the local `deposit_nonce` counter is
    /// bumped past the highest recovered value so a subsequent
    /// `deposit` doesn't collide with an existing pool. The address
    /// derivation requires a full XMSS rebuild per address index, so
    /// this command is slow (~tens of seconds per address).
    RecoverDeposits {
        /// Inclusive upper bound on `address_index` to scan. Default
        /// is 16 — the address-index space is `u32`, but realistic
        /// users only ever consume small values.
        #[arg(long, default_value_t = 16)]
        max_address_index: u32,
        /// Inclusive upper bound on `deposit_nonce` to scan per
        /// address. Default is 16 — the nonce space is `u64`, but
        /// realistic users only ever consume small values.
        #[arg(long, default_value_t = 16)]
        max_deposit_nonce: u64,
    },
    /// Drain a deposit pool into a shielded note owned by the pool's own
    /// auth tree. The shield circuit verifies an in-circuit WOTS+ signature
    /// under the recipient's auth tree, so only the wallet that owns the
    /// pool's `(auth_root, auth_pub_seed, blind)` can shield against it.
    Shield {
        /// Hex pubkey_hash identifying the deposit pool to drain.
        #[arg(long)]
        pubkey_hash: String,
        /// Recipient note value. Defaults to the pool balance minus
        /// `required_tx_fee + producer_fee`. Pool balance must be at least
        /// `amount + required_tx_fee + producer_fee`.
        #[arg(long)]
        amount: Option<u64>,
    },
    /// Send shielded funds to another payment address.
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        memo: Option<String>,
    },
    /// Unshield private notes directly to an L1 tz/KT1 recipient.
    Unshield {
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: Option<u64>,
        /// Override the default L1 recipient. Defaults to the source alias address.
        #[arg(long)]
        recipient: Option<String>,
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
    /// Export outgoing viewing material for sent-output recovery.
    ExportOutgoing {
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
        dal_fee: u64,
        #[arg(long)]
        dal_fee_address: String,
        #[arg(long, requires = "operator_bearer_token")]
        operator_url: Option<String>,
        #[arg(long, requires = "operator_url")]
        operator_bearer_token: Option<String>,
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
        | UserCmd::Deposit { .. }
        | UserCmd::RecoverDeposits { .. }
        | UserCmd::Shield { .. }
        | UserCmd::Send { .. }
        | UserCmd::Unshield { .. } => Some(acquire_wallet_lock(&cli.wallet)?),
        UserCmd::Profile { .. }
        | UserCmd::Balance
        | UserCmd::Check
        | UserCmd::Status { .. }
        | UserCmd::ExportDetect { .. }
        | UserCmd::ExportView { .. }
        | UserCmd::ExportOutgoing { .. } => None,
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
        // Upstream patch ②: propagate --proving-service-url (declared by
        // patch ① on UserCli) into ProveConfig.
        proving_service_url: cli.proving_service_url,
    };

    let outcome: Result<(), String> = match cli.cmd {
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
        UserCmd::Deposit { amount } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            cmd_bridge_deposit(&cli.wallet, &profile, amount)
        }
        UserCmd::RecoverDeposits {
            max_address_index,
            max_deposit_nonce,
        } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            cmd_recover_deposits(
                &cli.wallet,
                &profile,
                max_address_index,
                max_deposit_nonce,
            )
        }
        UserCmd::Shield {
            pubkey_hash,
            amount,
        } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            cmd_shield_rollup(&cli.wallet, &profile, &pubkey_hash, amount, &pc)
        }
        UserCmd::Send {
            to,
            amount,
            fee,
            memo,
        } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            cmd_transfer_rollup(&cli.wallet, &profile, &to, amount, fee, memo, &pc)
        }
        UserCmd::Unshield {
            amount,
            fee,
            recipient,
        } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            cmd_unshield_rollup(
                &cli.wallet,
                &profile,
                amount,
                fee,
                recipient.as_deref(),
                &pc,
            )
        }
        UserCmd::Status { submission_id } => {
            let profile = load_required_network_profile(&cli.wallet)?;
            cmd_operator_status(&profile, &submission_id)
        }
        UserCmd::ExportDetect { out } => cmd_export_detect(&cli.wallet, out.as_deref()),
        UserCmd::ExportView { out } => cmd_export_view(&cli.wallet, out.as_deref()),
        UserCmd::ExportOutgoing { out } => cmd_export_outgoing(&cli.wallet, out.as_deref()),
        UserCmd::Watch { cmd } => run_watch_wallet(&cli.wallet, cmd),
    };
    // Upstream patch ④: phase event — terminal failure. The daemon picks
    // this up from stderr and flips the JobPhase to Failed; the human
    // error message is the CLI's existing stderr write (eprintln in the
    // bin entry point).
    if let Err(e) = &outcome {
        // `reason` is a short slug used for telemetry / log filtering;
        // `detail` carries the full error string so the daemon's
        // CliOutput.stderr still carries the same bytes for display.
        let reason: &str = e
            .split(|c: char| c == ':' || c.is_ascii_whitespace())
            .next()
            .unwrap_or("error");
        phase_event!("failed", {
            "reason": reason,
            "detail": e,
        });
    }
    outcome
}

fn run_user_profile(wallet_path: &str, cmd: UserProfileCmd) -> Result<(), String> {
    let path = default_network_profile_path(wallet_path);
    match cmd {
        UserProfileCmd::InitShadownet {
            rollup_node_url,
            rollup_address,
            bridge_ticketer,
            dal_fee,
            dal_fee_address,
            operator_url,
            operator_bearer_token,
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
            let dal_fee_address = load_address(&dal_fee_address)?;
            let public_account = {
                let candidate = public_account.unwrap_or_else(|| source_alias.clone());
                if is_implicit_tezos_account_id(&candidate)
                    || parse_public_balance_key(&candidate).is_some()
                {
                    Some(candidate)
                } else {
                    let probe_profile = shadownet_profile(
                        rollup_node_url.clone(),
                        rollup_address.clone(),
                        bridge_ticketer.clone(),
                        dal_fee,
                        dal_fee_address.clone(),
                        operator_url.clone(),
                        operator_bearer_token.clone(),
                        source_alias.clone(),
                        Some(candidate.clone()),
                        octez_client_dir.clone(),
                        octez_node_endpoint.clone(),
                        octez_protocol.clone(),
                        octez_client_bin.clone(),
                        burn_cap.clone(),
                    );
                    let source = RollupRpc::new(&probe_profile).source_address_info()?;
                    Some(canonicalize_public_balance_key(&source.hash, &candidate)?)
                }
            };
            let profile = shadownet_profile(
                rollup_node_url,
                rollup_address,
                bridge_ticketer,
                dal_fee,
                dal_fee_address,
                operator_url,
                operator_bearer_token,
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
            println!("{}", display_network_profile_json(&profile));
            Ok(())
        }
        UserProfileCmd::Show => {
            let profile = load_network_profile(&path)?;
            println!("{}", display_network_profile_json(&profile));
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

/// Parse a `--pubkey-hash` argument. Accepts exactly one canonical
/// form: 64 lowercase hex characters, no `0x` prefix, no `deposit:`
/// prefix. This matches what `pubkey_hash_hex` prints, so a user
/// can copy a value out of `tzel-wallet check` / `tzel-wallet
/// balance` directly. Reject the alternate forms outright — there
/// is no live system to be backwards-compatible with.
fn parse_pubkey_hash_hex(value: &str) -> Result<F, String> {
    if value.starts_with("0x") || value.starts_with("0X") {
        return Err("pubkey_hash must be 64 lowercase hex chars (no `0x` prefix)".into());
    }
    if value.starts_with(DEPOSIT_RECIPIENT_PREFIX) {
        return Err(format!(
            "pubkey_hash must be 64 lowercase hex chars (no `{}` prefix)",
            DEPOSIT_RECIPIENT_PREFIX,
        ));
    }
    if value.len() != 64 {
        return Err(format!(
            "pubkey_hash must be 64 lowercase hex chars; got {} chars",
            value.len(),
        ));
    }
    if value.chars().any(|c| !matches!(c, '0'..='9' | 'a'..='f')) {
        return Err("pubkey_hash must be lowercase hex (0-9, a-f) only".into());
    }
    let bytes =
        hex::decode(value).map_err(|e| format!("invalid pubkey_hash hex: {}", e))?;
    let mut out = ZERO;
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn pubkey_hash_hex(pubkey_hash: &F) -> String {
    hex::encode(pubkey_hash)
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

    // Upstream patch ④: phase event — local reprove subprocess about to
    // start. We don't have a job_id (subprocess), and the program_hash
    // requires a separate `reprove --program-hash` invocation that the
    // local path skips, so emit empty strings for those fields.
    let proving_started_at = std::time::Instant::now();
    phase_event!("proving_started", {
        "prover_url": "local:reprove",
        "prover_job_id": "",
        "program_hash": "",
    });
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
    // Upstream patch ④: phase event — proof bundle parsed.
    phase_event!("proving_finished", {
        "proof_bytes": bundle.proof_bytes.len() as u64,
        "public_outputs": bundle.output_preimage.len() as u32,
        "duration_ms": proving_started_at.elapsed().as_millis() as u64,
    });
    eprintln!(
        "Proof generated: {} KB, {} public outputs",
        proof_kb,
        bundle.output_preimage.len()
    );

    Ok(Proof::Stark {
        proof_bytes: bundle.proof_bytes,
        output_preimage: bundle.output_preimage,
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Proving via HTTP proving-service (upstream patch ②)
// ═══════════════════════════════════════════════════════════════════════
//
// POST the witness to a proving-service endpoint and long-poll until the
// proof bundle is ready. Returns a `Proof::Stark` equivalent to what
// `generate_proof` returns when spawning `reprove` locally.
//
// API contract (see tzel-infra/docs/proving-service-api.md):
//   POST {url}/v1/jobs    {"program_hash": "<64-hex>", "arguments": [...]}
//     → 202 {"job_id": "...", "status": "queued", ...}
//   GET  {url}/v1/jobs/{id}?wait=30
//     → 200 {"status": "queued|running|done|failed", "proof_bundle": {...}, ...}
//
// The `program_hash` is computed locally by invoking `reprove --program-hash`
// — the reprove binary is still required at runtime to derive the hash for
// the specific cairo executable. Deferring this to the service would
// require the service to know which executable corresponds to which
// `circuit` name, which is a premature coupling.
//
// HTTP transport uses `ureq` (already a wallet dep — same crate that
// powers `get_text`, `get_json`, `post_json` above) with explicit
// per-request timeouts to match the CLI-wide liveness story:
//   - connect timeout  5 s — slow DNS / unreachable host fails fast
//   - global  timeout 35 s — per call, covering ?wait=30 long-poll + slack
//
// The poll loop is capped at `PROVING_SERVICE_POLL_CAP` iterations × 30 s
// per wait = documented worst-case ceiling below.

/// Max number of 30-second long-poll iterations before we give up on a job.
/// 60 × 30 s = 30 min worst-case before the CLI aborts with a timeout
/// error. This is deliberately generous: shield proofs typically complete
/// in 30-60 s, but shadownet retry backoffs can push a job into minutes.
const PROVING_SERVICE_POLL_CAP: usize = 60;

/// Number of consecutive polls returning `status:"unknown"` before we
/// abort — a healthy service never reports this.
const PROVING_SERVICE_MAX_UNKNOWN: usize = 3;

/// Per-request connect timeout.
const PROVING_SERVICE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Per-request global timeout. Must be > long-poll `wait` so the server
/// has a chance to respond before the client side aborts.
const PROVING_SERVICE_GLOBAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(35);

fn generate_proof_via_service(
    service_url: &str,
    reprove_bin: &str,
    executables_dir: &str,
    circuit: &str,
    args: &[String],
) -> Result<Proof, String> {
    // Resolve program_hash by querying the proving-service's program
    // registry (`GET /v1/programs`). This avoids requiring the CLI's
    // environment to have the cairo executables at `{executables_dir}/
    // {circuit}.executable.json`: when the daemon spawns the CLI as a
    // subprocess with only `--proving-service-url` set, it does not also
    // pass `--executables-dir`, so the legacy local-hash path fails with
    // a spurious "Failed to open file" error before the HTTP POST runs.
    //
    // Falls back to the local `reprove --program-hash` path if the service
    // does not expose `/v1/programs` or the circuit is not registered.
    let program_hash = match resolve_program_hash_via_service(service_url, circuit) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!(
                "proving-service: /v1/programs lookup failed ({}), falling back to local reprove --program-hash",
                e
            );
            let executable = format!("{}/{}.executable.json", executables_dir, circuit);
            compute_program_hash(reprove_bin, &executable)?
        }
    };

    let url = format!("{}/v1/jobs", service_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "program_hash": program_hash,
        "arguments": args,
    });
    eprintln!(
        "Generating proof for {} ({} args) via proving-service {}...",
        circuit,
        args.len(),
        service_url
    );

    let submit = http_post_json(&url, &body)
        .map_err(|e| format!("proving-service submit failed: {} (url={})", e, url))?;
    let job_id = submit
        .get("job_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("proving-service: POST {} missing job_id", url))?
        .to_string();

    // Upstream patch ④: phase event — job created on the proving-service,
    // we are about to wait on it.
    let proving_started_at = std::time::Instant::now();
    phase_event!("proving_started", {
        "prover_url": service_url,
        "prover_job_id": &job_id,
        "program_hash": &program_hash,
    });

    let poll_url_base = format!("{}/v1/jobs/{}", service_url.trim_end_matches('/'), job_id);
    // Long-poll cap: PROVING_SERVICE_POLL_CAP × 30 s wait = documented
    // worst-case ceiling. Each call has an independent 35 s client-side
    // timeout so a stalled server can't wedge the CLI.
    //
    // The proving-service's GET /v1/jobs/{id}?wait=N only actually blocks
    // when the client passes `if_state_changed_from=<last-seen-status>`
    // (see services/proving-service/src/registry.rs::long_poll — without
    // the reference state, the handler short-circuits and returns
    // immediately). We track the last status we observed and feed it back
    // on each iteration so 60 iterations × 30 s really is ~30 min of
    // wall time, not ~30 ms of tight polling.
    let mut consecutive_unknown = 0usize;
    let mut last_status: Option<&'static str> = None;
    for _ in 0..PROVING_SERVICE_POLL_CAP {
        let poll_url = match last_status {
            Some(s) => format!("{}?wait=30&if_state_changed_from={}", poll_url_base, s),
            None => format!("{}?wait=30", poll_url_base),
        };
        let resp = http_get_json(&poll_url)
            .map_err(|e| format!("proving-service poll failed: {} (url={})", e, poll_url))?;
        let status = resp
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        match status {
            "done" => {
                let bundle_value = resp.get("proof_bundle").ok_or_else(|| {
                    "proving-service: done response missing proof_bundle".to_string()
                })?;
                let bundle: VerifyProofBundle = serde_json::from_value(bundle_value.clone())
                    .map_err(|e| format!("parse proof bundle: {}", e))?;
                // Upstream patch ④: phase event — proof bundle delivered.
                phase_event!("proving_finished", {
                    "proof_bytes": bundle.proof_bytes.len() as u64,
                    "public_outputs": bundle.output_preimage.len() as u32,
                    "duration_ms": proving_started_at.elapsed().as_millis() as u64,
                });
                eprintln!(
                    "Proof generated: {} KB, {} public outputs",
                    bundle.proof_bytes.len() / 1024,
                    bundle.output_preimage.len()
                );
                return Ok(Proof::Stark {
                    proof_bytes: bundle.proof_bytes,
                    output_preimage: bundle.output_preimage,
                });
            }
            "failed" => {
                let err = resp
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                return Err(format!("proving-service reported failure: {}", err));
            }
            "queued" => {
                consecutive_unknown = 0;
                last_status = Some("queued");
                continue;
            }
            "running" => {
                consecutive_unknown = 0;
                last_status = Some("running");
                continue;
            }
            "unknown" => {
                consecutive_unknown += 1;
                if consecutive_unknown >= PROVING_SERVICE_MAX_UNKNOWN {
                    return Err(format!(
                        "proving-service: job {} stuck reporting status=unknown for {} consecutive polls",
                        job_id, consecutive_unknown,
                    ));
                }
                continue;
            }
            other => {
                return Err(format!("proving-service: unknown status '{}'", other));
            }
        }
    }
    Err(format!(
        "proving-service: job {} did not complete within poll budget ({} iterations × 30 s wait)",
        job_id, PROVING_SERVICE_POLL_CAP,
    ))
}

/// Query the proving-service's program registry (`GET /v1/programs`) and
/// return the `program_hash` whose `name` matches `circuit`. The
/// proving-service strips `.executable.json` from the filename stem, so
/// `circuit = "run_shield"` matches a registered program at
/// `…/run_shield.executable.json`.
///
/// This is the preferred way to resolve the hash in daemon / container
/// environments where the CLI does not have access to the cairo
/// executables on disk. Falls through to the caller's `reprove
/// --program-hash` path on any error (network failure, non-2xx, empty
/// result, or unknown circuit).
fn resolve_program_hash_via_service(service_url: &str, circuit: &str) -> Result<String, String> {
    let url = format!("{}/v1/programs", service_url.trim_end_matches('/'));
    let resp = http_get_json(&url)
        .map_err(|e| format!("GET {} failed: {}", url, e))?;
    let programs = resp
        .get("programs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("GET {}: response missing 'programs' array", url))?;
    for prog in programs {
        let name = prog.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name == circuit {
            let hash = prog
                .get("program_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    format!("GET {}: program {} missing program_hash", url, circuit)
                })?;
            return Ok(hash.to_string());
        }
    }
    Err(format!(
        "proving-service has no registered program named '{}' (found {} programs)",
        circuit,
        programs.len()
    ))
}

fn compute_program_hash(reprove_bin: &str, executable: &str) -> Result<String, String> {
    let out = std::process::Command::new(reprove_bin)
        .arg(executable)
        .arg("--program-hash")
        .output()
        .map_err(|e| format!("reprove --program-hash failed to start: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "reprove --program-hash failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// HTTP JSON POST via `ureq` — the wallet CLI already depends on ureq
/// (see `post_json`, `get_text` above). Adds explicit connect + global
/// timeouts so a stalled proving-service cannot wedge the CLI. Non-2xx
/// responses are surfaced as errors (no retry at this layer — the caller
/// does the long-polling).
fn http_post_json(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let req = ureq::post(url)
        .config()
        .timeout_connect(Some(PROVING_SERVICE_CONNECT_TIMEOUT))
        .timeout_global(Some(PROVING_SERVICE_GLOBAL_TIMEOUT))
        .build();
    let resp = req
        .send_json(body.clone())
        .map_err(|e| format!("HTTP POST error: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.into_body().read_to_string().unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, body));
    }
    resp.into_body()
        .read_json()
        .map_err(|e| format!("parse response: {}", e))
}

/// HTTP JSON GET via `ureq`, with the same timeout discipline as
/// `http_post_json`. Matches the error semantics of upstream's `get_text`
/// so failures surface consistently across the CLI.
fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let req = ureq::get(url)
        .config()
        .timeout_connect(Some(PROVING_SERVICE_CONNECT_TIMEOUT))
        .timeout_global(Some(PROVING_SERVICE_GLOBAL_TIMEOUT))
        .build();
    let resp = req.call().map_err(|e| format!("HTTP GET error: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.into_body().read_to_string().unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, body));
    }
    resp.into_body()
        .read_json()
        .map_err(|e| format!("parse response: {}", e))
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
        addresses: vec![],
        addr_counter: 0,
        notes: vec![],
        scanned: 0,
        wots_key_indices: std::collections::HashMap::new(),
        pending_spends: vec![],
        pending_deposits: vec![],
        deposit_nonce: 0,
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

fn cmd_export_outgoing(path: &str, out: Option<&str>) -> Result<(), String> {
    let w = load_wallet(path)?;
    // Export outgoing_seed only: holder can recover sender-encrypted output metadata,
    // but cannot detect incoming notes or spend.
    let exported = WatchKeyMaterial::from_outgoing_wallet(&w);
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
        WatchWalletFile::Detect { scanned, .. }
        | WatchWalletFile::View { scanned, .. }
        | WatchWalletFile::Outgoing { scanned, .. } => *scanned,
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
        "outgoing" => println!(
            "Watch sync: {} new outgoing notes, cursor={}, tracked={}, outgoing_total={}, spend_status={}",
            summary.found,
            status.scanned,
            status.tracked,
            status.outgoing_total,
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
        WatchWalletFile::Detect { .. }
        | WatchWalletFile::View { .. }
        | WatchWalletFile::Outgoing { .. } => {}
    }
    Ok(())
}

/// Fetch each tracked deposit pool's current balance from the demo
/// HTTP ledger. Returns a sparse map; pools with no recorded balance
/// (never credited or fully drained) are absent.
fn fetch_pool_balances_http(
    ledger: &str,
    pending: &[PendingDeposit],
) -> Result<std::collections::HashMap<F, u64>, String> {
    let mut map: std::collections::HashMap<F, u64> = std::collections::HashMap::new();
    let mut seen: std::collections::HashSet<F> = std::collections::HashSet::new();
    for p in pending {
        if !seen.insert(p.pubkey_hash) {
            continue;
        }
        let url = format!(
            "{}/deposits/balance?pubkey_hash={}",
            ledger,
            hex::encode(p.pubkey_hash)
        );
        #[derive(serde::Deserialize)]
        struct BalanceBody {
            balance: u64,
        }
        // Treat 404 / missing keys as "no pool yet"; surface other errors.
        match get_json::<BalanceBody>(&url) {
            Ok(body) => {
                map.insert(p.pubkey_hash, body.balance);
            }
            Err(e) if e.contains("404") => {}
            Err(e) => return Err(e),
        }
    }
    Ok(map)
}

fn cmd_scan(path: &str, ledger: &str) -> Result<(), String> {
    let mut w = load_wallet(path)?;

    let url = format!("{}/notes?cursor={}", ledger, w.scanned);
    let feed: NotesFeedResp = get_json(&url)?;
    let nf_resp: NullifiersResp = get_json(&format!("{}/nullifiers", ledger))?;
    let pool_balances = fetch_pool_balances_http(ledger, &w.pending_deposits)?;
    let summary = apply_scan_feed(&mut w, &feed, nf_resp.nullifiers, &pool_balances);
    save_wallet(path, &w)?;
    println!(
        "Scanned: {} new notes found, {} spent removed, balance={}",
        summary.found,
        summary.spent,
        w.available_balance()
    );
    if !summary.pool_balances.is_empty() {
        println!("Deposit pools:");
        for (pubkey_hash, balance) in &summary.pool_balances {
            println!("  pool {} = {} mutez", pubkey_hash_hex(pubkey_hash), balance);
        }
    }
    Ok(())
}

struct ScanSummary {
    found: usize,
    spent: usize,
    confirmed_pending: usize,
    /// Snapshot of each known pool's current kernel-side balance.
    pool_balances: std::collections::HashMap<F, u64>,
    /// Number of `PendingDeposit` entries pruned because their
    /// `shielded_cm` was observed as a tree leaf this round.
    pruned_drained_pools: usize,
}

fn apply_scan_feed(
    w: &mut WalletFile,
    feed: &NotesFeedResp,
    nullifiers: impl IntoIterator<Item = F>,
    pool_balances: &std::collections::HashMap<F, u64>,
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

    // Build the cumulative known-cm set BEFORE the nullifier-driven
    // note prune. We merge two sources:
    //   * `w.notes` (after this round's recovery, before nullifier
    //     pruning) — every shield/transfer/unshield output cm the
    //     wallet has ever recovered. Cumulative across syncs, which
    //     handles "user runs sync twice and only the first contained
    //     the cm" and "user multi-stage drains a pool, sync 2 only
    //     contains cm2 but cm1 was absorbed in sync 1".
    //   * `feed.notes` — defensively covers cms in this round's feed
    //     that the wallet didn't recover (e.g., wallet restored
    //     without the kem keys for the recipient address).
    // Building before nullifier pruning matters because a shielded cm
    // that has since been spent would otherwise drop out of `w.notes`
    // and leave the `PendingDeposit` pinned forever.
    let mut known_cms: std::collections::HashSet<F> =
        w.notes.iter().map(|n| n.cm).collect();
    known_cms.extend(feed.notes.iter().map(|nm| nm.cm));

    let nf_set: std::collections::HashSet<F> = nullifiers.into_iter().collect();
    let before = w.notes.len();
    w.notes.retain(|n| !nf_set.contains(&note_nullifier(n)));
    let spent = before - w.notes.len();
    let before_pending = w.pending_spends.len();
    w.pending_spends
        .retain(|pending| !pending.nullifiers.iter().all(|nf| nf_set.contains(nf)));

    // Prune `PendingDeposit` entries whose recipient note has been
    // seen on chain (any of the wallet's shielded cms appears in the
    // cumulative known-cm set above) AND whose pool now reads zero
    // balance. Until both signals align, the entry stays around so a
    // wallet that ran shield but never re-synced still has the
    // metadata it needs.
    let before_pools = w.pending_deposits.len();
    w.pending_deposits.retain(|p| {
        let drained_on_chain = pool_balances.get(&p.pubkey_hash).copied().unwrap_or(0) == 0;
        let cm_observed = p
            .shielded_cm
            .as_ref()
            .map(|cm| known_cms.contains(cm))
            .unwrap_or(false);
        !(drained_on_chain && cm_observed)
    });
    let pruned_drained_pools = before_pools - w.pending_deposits.len();

    w.scanned = feed.next_cursor;
    ScanSummary {
        found,
        spent,
        confirmed_pending: before_pending - w.pending_spends.len(),
        pool_balances: pool_balances.clone(),
        pruned_drained_pools,
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
        let wallet = test_wallet(1);
        WalletNetworkProfile {
            network: "shadownet".into(),
            rollup_node_url: base_url.into(),
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            bridge_ticketer: "KT1Jg4fj5wwnKHuW8aa9uDX6dRYBdjXhm2sJ".into(),
            dal_fee: 1,
            dal_fee_address: payment_address_for_wallet_address(&wallet, 0),
            public_account: "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN".into(),
            operator_url: None,
            operator_bearer_token: None,
            source_alias: "alice".into(),
            octez_client_bin: "octez-client".into(),
            octez_client_dir: None,
            octez_node_endpoint: None,
            octez_protocol: None,
            burn_cap: "1".into(),
        }
    }

    fn rebuild_address_state(master_sk: &F, j: u32, next_wots_index: u32) -> WalletAddressState {
        let acc = derive_account(master_sk);
        let d_j = derive_address(&acc.incoming_seed, j);
        let ask_j = derive_ask(&acc.ask_base, j);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let (bds, auth_root) = XmssBdsState::from_index(&ask_j, &auth_pub_seed, next_wots_index)
            .expect("fixture XMSS rebuild should succeed");
        let nk_spend = derive_nk_spend(&acc.nk, &d_j);
        let nk_tag = derive_nk_tag(&nk_spend);

        WalletAddressState {
            index: j,
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag,
            bds,
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
    fn canonicalize_public_balance_key_wraps_plain_labels_with_source_owner() {
        assert_eq!(
            canonicalize_public_balance_key("tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN", "alice")
                .unwrap(),
            "public:tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN:alice"
        );
    }

    #[test]
    fn canonicalize_public_balance_key_preserves_withdrawable_keys() {
        let implicit = "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN";
        let owner_bound = "public:tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN:alice";
        assert_eq!(
            canonicalize_public_balance_key(implicit, implicit).unwrap(),
            implicit
        );
        assert_eq!(
            canonicalize_public_balance_key(implicit, owner_bound).unwrap(),
            owner_bound
        );
        assert_eq!(
            withdraw_owner_from_public_balance_key(owner_bound).unwrap(),
            implicit
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

    pub(super) fn test_wallet(addr_counter: u32) -> WalletFile {
        let base = base_test_wallet();
        let cached = std::cmp::min(addr_counter as usize, base.addresses.len());
        let mut wallet = WalletFile {
            master_sk: base.master_sk,
            addresses: base.addresses[..cached].to_vec(),
            addr_counter,
            notes: vec![],
            scanned: 0,
            wots_key_indices: std::collections::HashMap::new(),
            pending_spends: vec![],
            pending_deposits: vec![],
            deposit_nonce: 0,
        };
        if addr_counter as usize > cached {
            wallet
                .materialize_addresses()
                .expect("test wallet address materialization should succeed");
        }
        wallet
    }

    fn wallet_with_single_note(note_value: u64) -> (WalletFile, F) {
        let mut w = test_wallet(1);
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

    pub(super) fn payment_address_for_wallet_address(w: &WalletFile, j: u32) -> PaymentAddress {
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
            let mut w = test_wallet(0);
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
        let mut w = test_wallet(1);
        let initial_root = w.addresses[0].auth_root;
        let initial_path = w.addresses[0].bds.current_path().to_vec();
        assert_eq!(initial_path.len(), AUTH_DEPTH);

        let first_idx = w.next_wots_key(0);
        assert_eq!(first_idx, 0);
        assert_eq!(w.wots_key_indices.get(&0), Some(&1));
        assert_eq!(w.addresses[0].auth_root, initial_root);
        let after_first = &w.addresses[0].bds;
        assert_eq!(after_first.next_index, 1);
        assert_eq!(after_first.current_path().len(), AUTH_DEPTH);
        assert_ne!(after_first.current_path(), initial_path.as_slice());

        let path_after_first = after_first.current_path().to_vec();
        let second_idx = w.next_wots_key(0);
        assert_eq!(second_idx, 1);
        assert_eq!(w.wots_key_indices.get(&0), Some(&2));
        assert_eq!(w.addresses[0].auth_root, initial_root);
        let after_second = &w.addresses[0].bds;
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
        let w = test_wallet(0);
        let acc = w.account();
        let detect_root = derive_detect_root(&acc.incoming_seed);
        assert_ne!(
            detect_root, acc.incoming_seed,
            "detect export material must not expose incoming_seed"
        );
    }

    #[test]
    fn test_view_export_includes_address_metadata() {
        let w = test_wallet(2);
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
        let w = test_wallet(1);
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
        let w = test_wallet(1);
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
        let w = test_wallet(1);
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

    #[test]
    fn test_outgoing_export_and_watch_recover_sent_output() {
        let w = test_wallet(1);
        let material = WatchKeyMaterial::from_outgoing_wallet(&w);
        let WatchKeyMaterial::Outgoing { outgoing_seed, .. } = material else {
            panic!("expected outgoing material");
        };
        assert_eq!(outgoing_seed, w.account().outgoing_seed);
        assert_ne!(outgoing_seed, w.account().incoming_seed);

        let (ek_v, _, ek_d, _) = w.kem_keys(0);
        let address = w.addresses[0].payment_address(&ek_v, &ek_d);
        let note = build_output_note_with_outgoing(
            &address,
            91,
            Some(b"not in outgoing view"),
            &outgoing_seed,
            OutgoingNoteRole::TransferRecipient,
        )
        .expect("output note should build");
        let nm = NoteMemo {
            index: 7,
            cm: note.cm,
            enc: note.enc,
        };

        let recovered = outgoing_record_for_note(&outgoing_seed, &nm)
            .expect("outgoing material should recover sender note");
        assert_eq!(recovered.index, 7);
        assert_eq!(recovered.role, "transfer_recipient");
        assert_eq!(recovered.value, 91);
        assert_eq!(recovered.cm, nm.cm);
        assert_eq!(recovered.rseed, note.rseed);
        assert_eq!(recovered.d_j, address.d_j);
        assert_eq!(recovered.auth_root, address.auth_root);
        assert_eq!(recovered.auth_pub_seed, address.auth_pub_seed);
        assert_eq!(recovered.nk_tag, address.nk_tag);

        let other = test_wallet(1);
        assert!(
            outgoing_record_for_note(&other.account().incoming_seed, &nm).is_none(),
            "wrong key material must not recover outgoing note"
        );
    }

    #[test]
    fn test_outgoing_material_rejects_recovery_plaintext_with_wrong_commitment() {
        let w = test_wallet(1);
        let outgoing_seed = w.account().outgoing_seed;
        let (ek_v, _, ek_d, _) = w.kem_keys(0);
        let address = w.addresses[0].payment_address(&ek_v, &ek_d);
        let value = 91;
        let note = build_output_note_with_outgoing(
            &address,
            value,
            Some(b"not in outgoing view"),
            &outgoing_seed,
            OutgoingNoteRole::TransferRecipient,
        )
        .expect("output note should build");
        let mut nm = NoteMemo {
            index: 7,
            cm: note.cm,
            enc: note.enc,
        };

        let forged_recovery = outgoing_recovery_plaintext(
            &address,
            OutgoingNoteRole::TransferRecipient,
            value + 1,
            note.rseed,
        );
        nm.enc.outgoing_ct = encrypt_outgoing_recovery(&outgoing_seed, &nm.cm, &forged_recovery);
        assert!(
            decrypt_outgoing_recovery(&outgoing_seed, &nm.cm, &nm.enc.outgoing_ct).is_some(),
            "malformed sender recovery payload is still authenticated under the outgoing key"
        );

        assert!(
            outgoing_record_for_note(&outgoing_seed, &nm).is_none(),
            "outgoing watch must not trust metadata that does not recompute to the note commitment"
        );

        let feed = NotesFeedResp {
            notes: vec![nm],
            next_cursor: 8,
        };
        let mut watch = WatchWalletFile::from_material(WatchKeyMaterial::from_outgoing_wallet(&w));
        let summary = apply_watch_feed(&mut watch, &feed);
        assert_eq!(summary.found, 0);
        assert_eq!(watch.status().outgoing_total, 0);
    }

    #[test]
    fn test_apply_watch_feed_outgoing_tracks_sender_outputs() {
        let w = test_wallet(1);
        let outgoing_seed = w.account().outgoing_seed;
        let (ek_v, _, ek_d, _) = w.kem_keys(0);
        let address = w.addresses[0].payment_address(&ek_v, &ek_d);
        let note = build_output_note_with_outgoing(
            &address,
            12,
            None,
            &outgoing_seed,
            OutgoingNoteRole::ProducerFee,
        )
        .expect("output note should build");
        let feed = NotesFeedResp {
            notes: vec![NoteMemo {
                index: 3,
                cm: note.cm,
                enc: note.enc,
            }],
            next_cursor: 4,
        };
        let mut watch = WatchWalletFile::from_material(WatchKeyMaterial::from_outgoing_wallet(&w));

        let summary = apply_watch_feed(&mut watch, &feed);

        assert_eq!(summary.found, 1);
        assert_eq!(summary.next_cursor, 4);
        let status = watch.status();
        assert_eq!(status.mode, "outgoing");
        assert_eq!(status.tracked, 1);
        assert_eq!(status.outgoing_total, 12);
        assert_eq!(status.outgoing_notes[0].role, "producer_fee");
    }

    proptest! {
        #[test]
        fn prop_view_material_recovers_wallet_notes(
            value in 1u64..1_000_000u64,
            memo in prop::collection::vec(any::<u8>(), 0..32),
            mut rseed in any::<[u8; 32]>(),
        ) {
            rseed[31] &= 0x07;
            let w = test_wallet(1);
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
        let w = test_wallet(1);
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
        let w = test_wallet(1);
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
        let w = test_wallet(1);
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

        let w = test_wallet(2);
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
            WatchWalletFile::Detect { .. } | WatchWalletFile::Outgoing { .. } => {
                panic!("expected view watch wallet")
            }
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

        let w = test_wallet(3);
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
            WatchWalletFile::View { .. } | WatchWalletFile::Outgoing { .. } => {
                panic!("expected detect watch wallet")
            }
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

        let w = test_wallet(2);
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
            WatchWalletFile::View { .. } | WatchWalletFile::Outgoing { .. } => {
                panic!("expected detect watch wallet after overwrite")
            }
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

        let w = test_wallet(1);
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

        let w = test_wallet(1);
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

        let w = test_wallet(1);
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

        save_wallet(wallet_path_str, &test_wallet(1)).expect("save private wallet");
        let err = validate_detection_service_wallet(wallet_path_str)
            .expect_err("private spending wallet must not validate as watch wallet");
        assert!(err.contains("parse watch wallet"));
    }

    #[test]
    fn test_per_address_kem_keys_are_deterministic_and_distinct() {
        let w = test_wallet(0);
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
        let w = test_wallet(1);
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
    fn test_try_recover_note_rejects_phantom_note_with_wrong_commitment() {
        let w = test_wallet(1);
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
        let w = test_wallet(1);
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
        let w = test_wallet(1);

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
        let w = test_wallet(1);

        save_wallet(wallet_path_str, &w).expect("wallet should save");

        let floor_path = wallet_xmss_floor_path(wallet_path_str);
        let floor: WalletXmssFloor =
            serde_json::from_str(&std::fs::read_to_string(&floor_path).expect("read floor"))
                .expect("parse floor");

        assert_eq!(floor.wallet_fingerprint, hash(&w.master_sk));
        assert_eq!(floor.addr_counter, w.addr_counter);
        assert_eq!(
            floor.wots_key_indices.get(&0),
            Some(&w.addresses[0].bds.next_index)
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_save_wallet_sets_private_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let w = test_wallet(1);

        save_wallet(wallet_path.to_str().unwrap(), &w).expect("wallet should save");

        let mode = std::fs::metadata(&wallet_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_private_temp_files_start_with_private_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let (tmp_path, _file) =
            create_private_temp_file(&wallet_path, "wallet").expect("create private temp file");

        let mode = std::fs::metadata(&tmp_path).unwrap().permissions().mode() & 0o777;
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

        let original = test_wallet(1);
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
        let w = test_wallet(3);
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
            addresses: base.addresses[..2].to_vec(),
            addr_counter: 0,
            notes: vec![],
            scanned: 0,
            wots_key_indices: std::collections::HashMap::new(),
            pending_spends: vec![],
            pending_deposits: vec![],
            deposit_nonce: 0,
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
            addresses: base.addresses[..2].to_vec(),
            addr_counter: 2,
            notes: vec![],
            scanned: 0,
            wots_key_indices: std::collections::HashMap::new(),
            pending_spends: vec![],
            pending_deposits: vec![],
            deposit_nonce: 0,
        };

        wallet
            .materialize_addresses()
            .expect("fixture materialization should stay on cached state");
        assert_eq!(wallet.wots_key_indices.get(&0), Some(&0));
        assert_eq!(wallet.wots_key_indices.get(&1), Some(&0));
    }

    #[test]
    fn test_materialize_addresses_refreshes_wots_index_after_fixture_state_advance() {
        let mut wallet = test_wallet(1);
        assert_eq!(wallet.next_wots_key(0), 0);
        wallet.wots_key_indices.clear();

        wallet
            .materialize_addresses()
            .expect("fixture materialization should refresh cached WOTS index");

        assert_eq!(wallet.wots_key_indices.get(&0), Some(&1));
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
        let mut w = test_wallet(1);
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
        let mut w = test_wallet(0);
        let err = w
            .reserve_next_auth(0)
            .expect_err("missing address record should error");
        assert!(err.contains("missing address record 0"));
    }

    #[test]
    fn test_reserve_next_auth_rejects_exhausted_tree() {
        let mut w = test_wallet(1);
        w.addresses[0].bds = XmssBdsState {
            next_index: AUTH_TREE_SIZE as u32,
            auth_path: vec![],
            keep: vec![],
            treehash: vec![],
            retain: vec![],
        };

        let err = w
            .reserve_next_auth(0)
            .expect_err("exhausted XMSS tree should error");
        assert!(err.contains("XMSS keys exhausted for address 0"));
    }

    #[test]
    fn test_next_wots_key_is_monotonic() {
        let mut w = test_wallet(1);
        assert_eq!(w.next_wots_key(0), 0);
        assert_eq!(w.next_wots_key(0), 1);
        assert_eq!(w.next_wots_key(0), 2);
    }

    #[test]
    fn test_select_notes_rejects_insufficient_funds() {
        let mut w = test_wallet(0);
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
        let mut w = test_wallet(0);
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
        let mut w = test_wallet(1);
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
        let mut w = test_wallet(1);
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

        let summary = apply_scan_feed(&mut w, &feed, vec![spent_nf], &Default::default());
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
        let mut w = test_wallet(1);
        let existing = wallet_note_for_address(&w, 0, 40, felt_tag(b"wallet-scan-pending"), 5);
        let spent_nf = note_nullifier(&existing);
        w.notes.push(existing);
        w.register_pending_spend(vec![spent_nf], "transfer 40".into(), Some("opHash".into()));

        let feed = NotesFeedResp {
            notes: vec![],
            next_cursor: 6,
        };

        let summary = apply_scan_feed(&mut w, &feed, vec![spent_nf], &Default::default());
        assert_eq!(summary.spent, 1);
        assert_eq!(summary.confirmed_pending, 1);
        assert!(w.pending_spends.is_empty());
        assert!(w.notes.is_empty());
        assert_eq!(w.scanned, 6);
    }

    #[test]
    fn test_apply_scan_feed_prunes_drained_pool_after_recipient_cm_seen() {
        // After a successful shield, the wallet marks the pool's
        // PendingDeposit with `shielded_cm = Some(cm)`. The kernel
        // entry reads empty (best-effort delete after full drain),
        // but the wallet must keep the entry around until it has
        // *also* observed the recipient note in the rollup feed —
        // otherwise an offline wallet would discard the metadata it
        // needs if the shield message never lands. Once both signals
        // line up, sync prunes.
        let mut w = test_wallet(1);
        let pubkey_hash = felt_tag(b"scan-feed-prune-pkh");
        let blind = felt_tag(b"scan-feed-prune-blind");
        let auth_domain = felt_tag(b"scan-feed-prune-domain");
        let recipient_cm = felt_tag(b"scan-feed-prune-cm");

        w.pending_deposits.push(PendingDeposit {
            pubkey_hash,
            blind,
            address_index: 0,
            auth_domain,
            amount: 100_000,
            operation_hash: Some("opAfterShield".into()),
            shielded_cm: Some(recipient_cm),
        });

        // First sync: kernel reports zero balance for the pool but
        // the recipient note is NOT yet in the feed → keep the entry.
        let pool_balances_drained: std::collections::HashMap<F, u64> =
            std::collections::HashMap::new();
        let summary = apply_scan_feed(
            &mut w,
            &NotesFeedResp {
                notes: vec![],
                next_cursor: 1,
            },
            Vec::<F>::new(),
            &pool_balances_drained,
        );
        assert_eq!(
            summary.pruned_drained_pools, 0,
            "must not prune before observing the recipient cm in the feed"
        );
        assert_eq!(w.pending_deposits.len(), 1);

        // Second sync: kernel still reports zero balance and the
        // recipient cm is now in the feed → prune.
        let alien_nm = NoteMemo {
            index: 7,
            cm: recipient_cm,
            enc: encrypt_note(
                100_000,
                &felt_tag(b"prune-alien-rseed"),
                None,
                &kem_keygen_from_seed(&[0xAA; 64]).0,
                &kem_keygen_from_seed(&[0xBB; 64]).0,
            ),
        };
        let summary = apply_scan_feed(
            &mut w,
            &NotesFeedResp {
                notes: vec![alien_nm],
                next_cursor: 2,
            },
            Vec::<F>::new(),
            &pool_balances_drained,
        );
        assert_eq!(summary.pruned_drained_pools, 1);
        assert!(w.pending_deposits.is_empty());
    }

    #[test]
    fn test_apply_scan_feed_keeps_funded_pool_even_when_cm_observed() {
        // Defensive: a pool with a positive kernel-side balance is
        // never pruned, even if its `shielded_cm` happens to also
        // appear in the feed (e.g., a dust attacker top-up after our
        // shield landed). The wallet may still want to drain the
        // residue.
        let mut w = test_wallet(1);
        let pubkey_hash = felt_tag(b"scan-feed-keep-pkh");
        let cm = felt_tag(b"scan-feed-keep-cm");
        w.pending_deposits.push(PendingDeposit {
            pubkey_hash,
            blind: felt_tag(b"scan-feed-keep-blind"),
            address_index: 0,
            auth_domain: felt_tag(b"scan-feed-keep-domain"),
            amount: 100,
            operation_hash: None,
            shielded_cm: Some(cm),
        });
        let mut pool_balances = std::collections::HashMap::new();
        pool_balances.insert(pubkey_hash, 42u64);
        let alien_nm = NoteMemo {
            index: 0,
            cm,
            enc: encrypt_note(
                100,
                &felt_tag(b"keep-alien-rseed"),
                None,
                &kem_keygen_from_seed(&[0xAA; 64]).0,
                &kem_keygen_from_seed(&[0xBB; 64]).0,
            ),
        };
        let summary = apply_scan_feed(
            &mut w,
            &NotesFeedResp {
                notes: vec![alien_nm],
                next_cursor: 1,
            },
            Vec::<F>::new(),
            &pool_balances,
        );
        assert_eq!(summary.pruned_drained_pools, 0);
        assert_eq!(w.pending_deposits.len(), 1);
    }

    #[test]
    fn test_apply_scan_feed_prunes_multi_stage_drain_after_residue_shield() {
        // Multi-stage drain: a pool with two distinct shields against
        // it (legitimate — `core` explicitly supports it via
        // `test_apply_shield_two_distinct_shields_can_share_one_pool`).
        // The wallet records `shielded_cm = Some(cm1)` after the first
        // shield, then overwrites it to `Some(cm2)` after the second.
        // Across two sync runs (one each between the shields, one
        // after the residue is drained), apply_scan_feed must:
        //   sync 1: see cm1, but pool still has balance → keep entry.
        //   sync 2: see cm2, pool drained → prune entry.
        //
        // This pinned forever in the prior implementation because
        // (a) the wallet only updated `shielded_cm` when it was
        // `None` and (b) sync 2's known-cm set was the incremental
        // feed only, so cm1 (last seen in sync 1) never appeared
        // alongside the drained signal.
        let mut w = test_wallet(1);
        let pubkey_hash = felt_tag(b"multi-stage-pkh");

        // First shield: set shielded_cm to cm1.
        let cm1 = felt_tag(b"multi-stage-cm-1");
        w.pending_deposits.push(PendingDeposit {
            pubkey_hash,
            blind: felt_tag(b"multi-stage-blind"),
            address_index: 0,
            auth_domain: felt_tag(b"multi-stage-domain"),
            amount: 200_000,
            operation_hash: Some("opShield1".into()),
            shielded_cm: Some(cm1),
        });

        // Sync 1: cm1 in feed, pool balance > 0 → keep.
        let mut pool_balances = std::collections::HashMap::new();
        pool_balances.insert(pubkey_hash, 80_000u64);
        let nm1 = NoteMemo {
            index: 0,
            cm: cm1,
            enc: encrypt_note(
                100_000,
                &felt_tag(b"multi-stage-rseed1"),
                None,
                &kem_keygen_from_seed(&[0xAA; 64]).0,
                &kem_keygen_from_seed(&[0xBB; 64]).0,
            ),
        };
        let summary = apply_scan_feed(
            &mut w,
            &NotesFeedResp {
                notes: vec![nm1],
                next_cursor: 1,
            },
            Vec::<F>::new(),
            &pool_balances,
        );
        assert_eq!(
            summary.pruned_drained_pools, 0,
            "must not prune while pool still has balance"
        );
        assert_eq!(w.pending_deposits.len(), 1);

        // Second shield: overwrite shielded_cm to cm2.
        let cm2 = felt_tag(b"multi-stage-cm-2");
        for p in w
            .pending_deposits
            .iter_mut()
            .filter(|p| p.pubkey_hash == pubkey_hash)
        {
            p.shielded_cm = Some(cm2);
        }

        // Sync 2: cm2 in feed (cm1 is in past sync's notes only),
        // pool balance == 0 → must prune.
        let pool_balances_drained: std::collections::HashMap<F, u64> =
            std::collections::HashMap::new();
        let nm2 = NoteMemo {
            index: 1,
            cm: cm2,
            enc: encrypt_note(
                80_000,
                &felt_tag(b"multi-stage-rseed2"),
                None,
                &kem_keygen_from_seed(&[0xCC; 64]).0,
                &kem_keygen_from_seed(&[0xDD; 64]).0,
            ),
        };
        let summary = apply_scan_feed(
            &mut w,
            &NotesFeedResp {
                notes: vec![nm2],
                next_cursor: 2,
            },
            Vec::<F>::new(),
            &pool_balances_drained,
        );
        assert_eq!(
            summary.pruned_drained_pools, 1,
            "drained pool with cm2 in feed must prune even though cm1 was the original cm"
        );
        assert!(w.pending_deposits.is_empty());
    }

    #[test]
    fn test_apply_scan_feed_prunes_drained_pool_via_cumulative_state() {
        // Bulletproof against the scenario where a user runs sync
        // twice: the first run absorbs the recipient cm into
        // `w.notes` while the pool was still funded; the second run
        // has an empty feed (cursor advanced past cm) but observes
        // that the pool has now been drained on chain. Pruning must
        // still fire on the second run because `w.notes` is the
        // cumulative source-of-truth for observed cms.
        let mut w = test_wallet(1);
        let pubkey_hash = felt_tag(b"two-syncs-pkh");
        let recipient_rseed = felt_tag(b"two-syncs-rseed");
        // Build a recoverable recipient note for address 0.
        let new_nm = note_memo_for_wallet_address(&w, 0, 100_000, recipient_rseed, None);
        let cm = new_nm.cm;
        w.pending_deposits.push(PendingDeposit {
            pubkey_hash,
            blind: felt_tag(b"two-syncs-blind"),
            address_index: 0,
            auth_domain: felt_tag(b"two-syncs-domain"),
            amount: 100_000,
            operation_hash: Some("opShield".into()),
            shielded_cm: Some(cm),
        });

        // Sync 1: cm in feed, pool still funded (residual or stale
        // read) → don't prune; cm gets absorbed into w.notes.
        let mut pool_balances_funded = std::collections::HashMap::new();
        pool_balances_funded.insert(pubkey_hash, 50u64);
        let summary = apply_scan_feed(
            &mut w,
            &NotesFeedResp {
                notes: vec![new_nm],
                next_cursor: 1,
            },
            Vec::<F>::new(),
            &pool_balances_funded,
        );
        assert_eq!(summary.pruned_drained_pools, 0);
        assert_eq!(w.pending_deposits.len(), 1);
        assert!(w.notes.iter().any(|n| n.cm == cm));

        // Sync 2: empty feed, pool drained. Without cumulative cm
        // tracking the entry would stay pinned. With it, w.notes
        // still contains cm → prune.
        let pool_balances_drained: std::collections::HashMap<F, u64> =
            std::collections::HashMap::new();
        let summary = apply_scan_feed(
            &mut w,
            &NotesFeedResp {
                notes: vec![],
                next_cursor: 2,
            },
            Vec::<F>::new(),
            &pool_balances_drained,
        );
        assert_eq!(
            summary.pruned_drained_pools, 1,
            "second sync with empty feed must still prune via cumulative w.notes"
        );
        assert!(w.pending_deposits.is_empty());
    }

    #[test]
    fn test_apply_scan_feed_drops_newly_recovered_note_if_already_nullified() {
        let mut w = test_wallet(1);
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

        let summary = apply_scan_feed(&mut w, &feed, vec![spent_nf], &Default::default());
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
        let mut w = test_wallet(1);
        let last_idx = (AUTH_TREE_SIZE - 1) as u32;
        w.addresses[0].bds = XmssBdsState {
            next_index: last_idx,
            auth_path: vec![ZERO; AUTH_DEPTH],
            keep: vec![FeltSlot::none(); AUTH_DEPTH],
            treehash: (0..(AUTH_DEPTH - XMSS_BDS_K))
                .map(TreeHashState::new)
                .collect(),
            retain: vec![RetainLevel::default(); AUTH_DEPTH],
        };
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

        let mut w = test_wallet(2);
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
        let producer_address = payment_address_for_wallet_address(&w, 0);
        let (_ek_v0, dk_v0, _ek_d0, dk_d0) = w.kem_keys(0);
        let (_ek_v1, dk_v1, _ek_d1, dk_d1) = w.kem_keys(1);

        let ledger_root = felt_tag(b"wallet-transfer-root");
        let recipient = load_address(recipient_path_str).expect("recipient should load");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        let prepared = prepare_transfer_skip_proof(
            &mut loaded,
            ledger_root,
            &recipient,
            50,
            0,
            1,
            &producer_address,
            Some("memo-1"),
        )
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
        assert_eq!(change_value, 14);
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

        assert!(detect(&req.enc_3, &dk_d0));
        let (producer_value, producer_rseed, producer_memo) =
            decrypt_memo(&req.enc_3, &dk_v0).expect("producer note should decrypt");
        assert_eq!(producer_value, 1);
        assert_eq!(&producer_memo[..3], b"dal");
        let producer_otag = owner_tag(
            &producer_address.auth_root,
            &producer_address.auth_pub_seed,
            &producer_address.nk_tag,
        );
        assert_eq!(
            commit(
                &producer_address.d_j,
                producer_value,
                &derive_rcm(&producer_rseed),
                &producer_otag
            ),
            req.cm_3
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

        let mut w = test_wallet(2);
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
        let producer_address = payment_address_for_wallet_address(&w, 0);
        let (_ek_v0, dk_v0, _ek_d0, dk_d0) = w.kem_keys(0);
        let (_ek_v1, dk_v1, _ek_d1, dk_d1) = w.kem_keys(1);

        let ledger_root = felt_tag(b"wallet-unshield-root");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        let prepared = prepare_unshield_skip_proof(
            &mut loaded,
            ledger_root,
            50,
            0,
            1,
            &producer_address,
            "bob",
        )
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
        assert_eq!(change_value, 14);
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

        assert!(detect(&req.enc_fee, &dk_d0));
        let (producer_value, producer_rseed, producer_memo) =
            decrypt_memo(&req.enc_fee, &dk_v0).expect("producer note should decrypt");
        assert_eq!(producer_value, 1);
        assert_eq!(&producer_memo[..3], b"dal");
        let producer_otag = owner_tag(
            &producer_address.auth_root,
            &producer_address.auth_pub_seed,
            &producer_address.nk_tag,
        );
        assert_eq!(
            commit(
                &producer_address.d_j,
                producer_value,
                &derive_rcm(&producer_rseed),
                &producer_otag
            ),
            req.cm_fee
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
        w.addresses = test_wallet(2).addresses;
        save_wallet(wallet_path_str, &w).expect("wallet should save");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        let _key_idx = loaded.next_wots_key(0);
        let args = vec![felt_u64_to_hex(0)];

        let pc = ProveConfig {
            skip_proof: false,
            reprove_bin: "/definitely/missing/reprove".into(),
            executables_dir: "cairo/target/dev".into(),
            proving_service_url: None,
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
        w.addresses = test_wallet(2).addresses;
        save_wallet(wallet_path_str, &w).expect("wallet should save");
        let mut loaded = load_wallet(wallet_path_str).expect("wallet should reload");
        let _key_idx = loaded.next_wots_key(0);
        let args = vec![felt_u64_to_hex(0)];

        let pc = ProveConfig {
            skip_proof: false,
            reprove_bin: "/definitely/missing/reprove".into(),
            executables_dir: "cairo/target/dev".into(),
            proving_service_url: None,
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
        let balances = rollup.load_pool_balances(&w.pending_deposits)?;
        print_deposit_pool_summary(&w, &balances);
    }
    Ok(())
}

/// Three-way deposit-pool tally: funded (positive kernel balance),
/// awaiting on-chain credit (no balance and we have not submitted a
/// shield), and drained-pending-prune (no balance because we already
/// shielded; sync clears these once the recipient note has been
/// observed in the tree).
fn print_deposit_pool_summary(
    w: &WalletFile,
    balances: &std::collections::HashMap<F, u64>,
) {
    let funded_count = balances.len();
    let total_funded: u64 = balances.values().sum();
    let mut drained_pending_scan = 0usize;
    let mut awaiting_credit = 0usize;
    for p in &w.pending_deposits {
        if balances.contains_key(&p.pubkey_hash) {
            continue;
        }
        if p.shielded_cm.is_some() {
            drained_pending_scan += 1;
        } else {
            awaiting_credit += 1;
        }
    }
    println!(
        "Deposit pools: {} funded, total balance {} mutez",
        funded_count, total_funded
    );
    if awaiting_credit > 0 {
        println!(
            "Deposit pools awaiting on-chain credit: {}",
            awaiting_credit
        );
    }
    if drained_pending_scan > 0 {
        println!(
            "Deposit pools drained but not yet pruned (run `tzel-wallet sync`): {}",
            drained_pending_scan
        );
    }
}

fn cmd_wallet_check(path: &str, profile: &WalletNetworkProfile) -> Result<(), String> {
    let wallet = load_wallet(path)?;
    let rollup = RollupRpc::new(profile);
    // Bind the rollup the wallet inspects below to the rollup the
    // user's profile targets for L1 mints. Without this, every other
    // health check could pass while pointing at the wrong rollup.
    rollup.ensure_rollup_address_matches()?;
    let head_hash = rollup.head_hash()?;
    let snapshot = rollup.load_state_snapshot_at_block(&head_hash)?;
    let auth_domain = snapshot.auth_domain;
    let tree_size = snapshot.tree.leaves.len();
    let required_tx_fee = snapshot.required_tx_fee;
    let balances = rollup.load_pool_balances(&wallet.pending_deposits)?;

    println!("Wallet file: {}", path);
    println!("Network: {}", profile.network);
    println!("Rollup head: {}", head_hash);
    println!("Auth domain: {}", short(&auth_domain));
    println!("Tree size: {}", tree_size);
    println!(
        "Current required burn fee: {} mutez ({} tez)",
        required_tx_fee,
        mutez_to_tez_string(required_tx_fee)
    );
    println!(
        "Local wallet: notes={}, pending={}, scanned={}",
        wallet.notes.len(),
        wallet.pending_spends.len(),
        wallet.scanned
    );
    print_deposit_pool_summary(&wallet, &balances);

    if let Some(operator_url) = &profile.operator_url {
        let health_url = format!("{}/healthz", operator_url.trim_end_matches('/'));
        let health = get_text(&health_url)?;
        println!("Operator health: {}", health.trim());
    } else {
        println!("Operator health: not configured");
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
    let pool_balances = rollup.load_pool_balances(&w.pending_deposits)?;
    let summary = apply_scan_feed(&mut w, &feed, nullifiers, &pool_balances);
    save_wallet(path, &w)?;
    let total_funded: u64 = summary.pool_balances.values().sum();
    let mut pools_awaiting_credit = 0usize;
    let mut pools_drained_pending_scan = 0usize;
    for p in &w.pending_deposits {
        if summary.pool_balances.contains_key(&p.pubkey_hash) {
            continue;
        }
        if p.shielded_cm.is_some() {
            pools_drained_pending_scan += 1;
        } else {
            pools_awaiting_credit += 1;
        }
    }
    println!(
        "Synced: {} new notes, {} spent removed, {} pending confirmed, {} drained-pool entries pruned, private_available={}, pool_funded_total={}, pools_awaiting_credit={}, pools_drained_pending_scan={}",
        summary.found,
        summary.spent,
        summary.confirmed_pending,
        summary.pruned_drained_pools,
        w.available_balance(),
        total_funded,
        pools_awaiting_credit,
        pools_drained_pending_scan,
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

fn select_pending_deposit_by_pubkey_hash<'a>(
    wallet: &'a WalletFile,
    pubkey_hash: &F,
) -> Result<&'a PendingDeposit, String> {
    wallet
        .pending_deposits
        .iter()
        .find(|p| &p.pubkey_hash == pubkey_hash)
        .ok_or_else(|| {
            format!(
                "deposit pool {} is not tracked by this wallet",
                hex::encode(pubkey_hash)
            )
        })
}

/// Derive a deterministic blinding factor for a fresh deposit pool.
/// The blind is `H("tzel-deposit-blind", master_sk, address_index,
/// deposit_nonce)`, so the *blind itself* is recoverable from the
/// seed alone — but the `(address_index, deposit_nonce)` pairs that
/// were actually used live in the wallet's local `pending_deposits`
/// state plus its `deposit_nonce` counter, neither of which is on
/// chain. A wallet that loses its local file therefore cannot
/// discover its pools without a bounded brute-force scan over
/// candidate `(i, j)` pairs followed by per-candidate balance probes
/// (see `findings.md` F-W-4 for the open recovery-scan feature). Do
/// not assume seed-only recovery is automatic.
fn derive_deposit_blind(master_sk: &F, address_index: u32, deposit_nonce: u64) -> F {
    let mut payload = b"tzel-deposit-blind".to_vec();
    payload.extend_from_slice(master_sk);
    payload.extend_from_slice(&address_index.to_le_bytes());
    payload.extend_from_slice(&deposit_nonce.to_le_bytes());
    hash(&payload)
}

/// Bridge deposit: derives a fresh deposit-pool `pubkey_hash` from the
/// wallet's auth tree and a deterministic blind, then L1-tickets `amount`
/// mutez to `deposit:<hex(pubkey_hash)>`. Multiple deposits to the same
/// pool aggregate as top-ups. The actual `(v, fee, producer_fee, recipient)`
/// is chosen at shield time, not deposit time, so this command is
/// meta-information only — it just funds a balance the wallet later signs
/// against.
fn cmd_bridge_deposit(
    path: &str,
    profile: &WalletNetworkProfile,
    amount: u64,
) -> Result<(), String> {
    let rollup = RollupRpc::new(profile);
    let head_hash = rollup.head_hash()?;
    let auth_domain = rollup.read_felt_at_block(&head_hash, DURABLE_AUTH_DOMAIN)?;

    let mut wallet = load_wallet(path)?;
    let master_sk = wallet.master_sk;

    // Pick the auth tree that owns this new pool. Default to allocating a
    // fresh address so each deposit has its own pubkey_hash and pools
    // don't aggregate by accident.
    let (address_state, recipient_address) = wallet.next_address()?;
    let address_index = address_state.index;
    save_wallet(path, &wallet)?;

    // Refuse to send the L1 ticket unless every preflight gate
    // passes. Producer-fee owner_tag matching no longer applies at
    // deposit time (the producer-fee recipient is chosen at shield
    // time), but the rollup the wallet just inspected via
    // `rollup_node_url` MUST match the rollup the L1 mint is going to
    // target via `rollup_address`, otherwise a stale/malicious profile
    // could pass verifier+ticketer preflight while the irreversible
    // L1 ticket flies to the wrong rollup. Bridge-ticketer mismatch
    // would also burn mutez to a pool that the configured rollup
    // never sees.
    rollup.ensure_rollup_address_matches()?;
    rollup.ensure_verifier_configured(&head_hash)?;
    rollup.ensure_bridge_ticketer_matches(&head_hash, &profile.bridge_ticketer)?;

    // Deterministic blind: address index plus the wallet's running deposit
    // nonce. Stored locally so we can re-derive pubkey_hash on demand.
    let deposit_nonce = wallet.deposit_nonce;
    wallet.deposit_nonce = deposit_nonce
        .checked_add(1)
        .ok_or_else(|| "deposit nonce overflow".to_string())?;
    let blind = derive_deposit_blind(&master_sk, address_index, deposit_nonce);
    let pubkey_hash = deposit_pubkey_hash(
        &auth_domain,
        &recipient_address.auth_root,
        &recipient_address.auth_pub_seed,
        &blind,
    );

    // Persist the pool entry BEFORE the L1 ticket. If save_wallet fails we
    // haven't sent any mutez, so nothing is stranded. If
    // `deposit_to_bridge` fails after, the wallet has a phantom pending
    // pool (no operation_hash) which the user can detect and prune via
    // `tzel-wallet check` — strictly better than losing the blind for a
    // successful L1 deposit (which would strand the pool, since only the
    // wallet that knows the blind can recompute pubkey_hash and shield).
    let pending = PendingDeposit {
        pubkey_hash,
        blind,
        address_index,
        auth_domain,
        amount,
        operation_hash: None,
        shielded_cm: None,
    };
    wallet.pending_deposits.push(pending);
    save_wallet(path, &wallet)?;

    let submission = rollup.deposit_to_bridge(&pubkey_hash, amount)?;
    if let Some(p) = wallet
        .pending_deposits
        .iter_mut()
        .find(|p| p.pubkey_hash == pubkey_hash)
    {
        p.operation_hash = submission.operation_hash.clone();
    }
    save_wallet(path, &wallet)?;
    println!(
        "Submitted L1 bridge deposit of {} mutez to pool {}",
        amount,
        pubkey_hash_hex(&pubkey_hash)
    );
    if let Some(op_hash) = submission.operation_hash {
        println!("Operation hash: {}", op_hash);
    }
    if !submission.output.is_empty() {
        println!("{}", submission.output);
    }
    println!(
        "Run `tzel-wallet shield --pubkey-hash {} --amount <v> --to <addr>` once the \
         deposit settles on the rollup.",
        pubkey_hash_hex(&pubkey_hash)
    );
    Ok(())
}

/// Reconstruct `PendingDeposit` entries after wallet-file loss using
/// only the seed already in the wallet. The deterministic blind
/// derivation `H("tzel-deposit-blind", master_sk, address_index,
/// deposit_nonce)` lets us recompute every pubkey_hash the wallet
/// could ever have created; we just have to brute-force the
/// `(i, j)` grid up to user-supplied bounds and ask the kernel
/// which pubkey_hashes have a non-zero balance.
///
/// Each iteration of `i` requires a full XMSS auth-tree rebuild
/// (~tens of seconds on a modern CPU), so default bounds are
/// deliberately small. Bumping them is cheap if the user knows they
/// went deeper.
///
/// Drained pools are NOT recovered: the kernel writes empty bytes
/// after a full drain (best-effort delete) and the wallet treats
/// that as absent. That's fine — funds in a drained pool are
/// already in the recipient note, recoverable through `sync` via
/// the ML-KEM detection key. Only currently-funded pools matter
/// here.
fn cmd_recover_deposits(
    path: &str,
    profile: &WalletNetworkProfile,
    max_address_index: u32,
    max_deposit_nonce: u64,
) -> Result<(), String> {
    let mut wallet = load_wallet(path)?;
    let master_sk = wallet.master_sk;
    let rollup = RollupRpc::new(profile);
    rollup.ensure_rollup_address_matches()?;
    let head_hash = rollup.head_hash()?;
    let auth_domain = rollup.read_felt_at_block(&head_hash, DURABLE_AUTH_DOMAIN)?;

    // Materialize addresses 0..=max_address_index. `materialize_addresses`
    // derives any addresses below `addr_counter` that aren't already in
    // `addresses`; setting `addr_counter` first guarantees the loop
    // covers the whole range we're about to scan.
    let target_count = max_address_index
        .checked_add(1)
        .ok_or_else(|| "max_address_index overflow".to_string())?;
    if wallet.addr_counter < target_count {
        wallet.addr_counter = target_count;
    }
    let needs_derivation = (wallet.addresses.len() as u32) < target_count;
    if needs_derivation {
        eprintln!(
            "Materializing addresses {}..{} (full XMSS rebuild per address — slow)",
            wallet.addresses.len(),
            target_count,
        );
    }
    wallet.materialize_addresses()?;
    save_wallet(path, &wallet)?;

    let known_pubkey_hashes: std::collections::HashSet<F> = wallet
        .pending_deposits
        .iter()
        .map(|p| p.pubkey_hash)
        .collect();

    let mut recovered = 0usize;
    let mut max_nonce_seen: Option<u64> = None;

    for i in 0..target_count {
        let addr = wallet.addresses[i as usize].clone();
        eprintln!(
            "Scanning address_index={} auth_root={} for deposit_nonce 0..={}",
            i,
            short(&addr.auth_root),
            max_deposit_nonce,
        );
        for j in 0..=max_deposit_nonce {
            let blind = derive_deposit_blind(&master_sk, i, j);
            let pubkey_hash = deposit_pubkey_hash(
                &auth_domain,
                &addr.auth_root,
                &addr.auth_pub_seed,
                &blind,
            );
            if known_pubkey_hashes.contains(&pubkey_hash) {
                continue;
            }
            let balance = rollup.try_read_deposit_balance(&head_hash, &pubkey_hash)?;
            let Some(amount) = balance else { continue };
            if amount == 0 {
                continue;
            }
            eprintln!(
                "  recovered: address_index={} deposit_nonce={} balance={} pubkey_hash={}",
                i,
                j,
                amount,
                pubkey_hash_hex(&pubkey_hash),
            );
            wallet.pending_deposits.push(PendingDeposit {
                pubkey_hash,
                blind,
                address_index: i,
                auth_domain,
                amount,
                operation_hash: None,
                shielded_cm: None,
            });
            max_nonce_seen = Some(match max_nonce_seen {
                Some(prev) => prev.max(j),
                None => j,
            });
            recovered += 1;
        }
    }

    // Bump deposit_nonce so a subsequent `tzel-wallet deposit` doesn't
    // re-derive a blind that already collides with a recovered pool.
    if let Some(max_j) = max_nonce_seen {
        let target_nonce = max_j
            .checked_add(1)
            .ok_or_else(|| "deposit_nonce overflow".to_string())?;
        if wallet.deposit_nonce < target_nonce {
            wallet.deposit_nonce = target_nonce;
        }
    }
    save_wallet(path, &wallet)?;

    println!("Recovered {} deposit pool(s)", recovered);
    println!("addr_counter now {}", wallet.addr_counter);
    println!("deposit_nonce now {}", wallet.deposit_nonce);
    if recovered == 0 {
        println!(
            "No funded pools found in the scan window. Bump --max-address-index or \
             --max-deposit-nonce if you suspect deposits beyond these bounds."
        );
    }
    Ok(())
}

fn cmd_operator_status(profile: &WalletNetworkProfile, submission_id: &str) -> Result<(), String> {
    let operator_url = profile
        .operator_url
        .as_deref()
        .ok_or_else(|| "this wallet profile has no operator_url configured".to_string())?;
    let resp = load_operator_submission(
        operator_url,
        profile.operator_bearer_token.as_deref(),
        submission_id,
    )?;
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

fn cmd_transfer(
    path: &str,
    ledger: &str,
    to_path: &str,
    amount: u64,
    fee: Option<u64>,
    dal_fee: u64,
    dal_fee_address_path: &str,
    memo: Option<String>,
    pc: &ProveConfig,
) -> Result<(), String> {
    let cfg: ConfigResp = get_json(&format!("{}/config", ledger))?;
    let fee = resolve_requested_tx_fee(fee, cfg.required_tx_fee)?;
    ensure_positive_dal_fee(dal_fee)?;
    let mut w = load_wallet(path)?;
    let outgoing_seed = w.account().outgoing_seed;
    let recipient = load_address(to_path)?;
    let producer_address = load_address(dal_fee_address_path)?;

    // Get current root
    let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))?;
    let root = tree_info.root;

    if pc.skip_proof {
        let prepared = prepare_transfer_skip_proof(
            &mut w,
            root,
            &recipient,
            amount,
            fee,
            dal_fee,
            &producer_address,
            memo.as_deref(),
        )?;
        save_wallet(path, &w)?;
        let resp: TransferResp = post_json(&format!("{}/transfer", ledger), &prepared.req)?;
        finalize_successful_spend(path, &mut w, &prepared.selected)?;
        println!(
            "Transferred {} to recipient, fee={}, dal fee={}, change={} (idx={},{},{})",
            amount, fee, dal_fee, prepared.change, resp.index_1, resp.index_2, resp.index_3
        );
        println!("Run 'scan' to pick up change note.");
        return Ok(());
    }

    // Select notes
    let total_spend = amount
        .checked_add(fee)
        .and_then(|value| value.checked_add(dal_fee))
        .ok_or_else(|| "transfer total spend overflow".to_string())?;
    let selected = w.select_notes(total_spend)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128 - fee as u128 - dal_fee as u128) as u64;

    // Compute nullifiers
    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();

    let note_1 = build_output_note_with_outgoing(
        &recipient,
        amount,
        memo.as_deref().map(str::as_bytes),
        &outgoing_seed,
        OutgoingNoteRole::TransferRecipient,
    )?;

    // Build output 2: change to self (per-address KEM keys)
    let (change_state, _change_addr) = w.next_address()?;
    let (ek_v_c, _, ek_d_c, _) = w.kem_keys(change_state.index);
    let change_address = change_state.payment_address(&ek_v_c, &ek_d_c);
    let note_2 = build_output_note_with_outgoing(
        &change_address,
        change,
        None,
        &outgoing_seed,
        OutgoingNoteRole::TransferChange,
    )?;
    let note_3 = build_output_note_with_outgoing(
        &producer_address,
        dal_fee,
        Some(b"dal"),
        &outgoing_seed,
        OutgoingNoteRole::ProducerFee,
    )?;

    let proof = if !pc.skip_proof {
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
        let sighash = transfer_sighash(
            &auth_domain,
            &root,
            &nfs_for_sh,
            fee,
            &note_1.cm,
            &note_2.cm,
            &note_3.cm,
            &note_1.mh,
            &note_2.mh,
            &note_3.mh,
        );

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

        let total_fields = 4 + 9 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS + 24;
        args.push(felt_u64_to_hex(total_fields as u64));
        args.push(felt_u64_to_hex(n as u64));
        args.push(felt_to_hex(&auth_domain));
        args.push(felt_to_hex(&root));
        args.push(felt_u64_to_hex(fee));

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
        args.push(felt_to_hex(&note_1.cm));
        args.push(felt_to_hex(&recipient.d_j));
        args.push(felt_u64_to_hex(amount));
        args.push(felt_to_hex(&note_1.rseed));
        args.push(felt_to_hex(&recipient.auth_root));
        args.push(felt_to_hex(&recipient.auth_pub_seed));
        args.push(felt_to_hex(&recipient.nk_tag));
        args.push(felt_to_hex(&note_1.mh));

        // Output 2
        args.push(felt_to_hex(&note_2.cm));
        args.push(felt_to_hex(&change_state.d_j));
        args.push(felt_u64_to_hex(change));
        args.push(felt_to_hex(&note_2.rseed));
        args.push(felt_to_hex(&change_state.auth_root));
        args.push(felt_to_hex(&change_state.auth_pub_seed));
        args.push(felt_to_hex(&change_state.nk_tag));
        args.push(felt_to_hex(&note_2.mh));

        // Output 3
        args.push(felt_to_hex(&note_3.cm));
        args.push(felt_to_hex(&producer_address.d_j));
        args.push(felt_u64_to_hex(dal_fee));
        args.push(felt_to_hex(&note_3.rseed));
        args.push(felt_to_hex(&producer_address.auth_root));
        args.push(felt_to_hex(&producer_address.auth_pub_seed));
        args.push(felt_to_hex(&producer_address.nk_tag));
        args.push(felt_to_hex(&note_3.mh));

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
        fee,
        cm_1: note_1.cm,
        cm_2: note_2.cm,
        cm_3: note_3.cm,
        enc_1: note_1.enc,
        enc_2: note_2.enc,
        enc_3: note_3.enc,
        proof,
    };
    let resp: TransferResp = post_json(&format!("{}/transfer", ledger), &req)?;

    finalize_successful_spend(path, &mut w, &selected)?;

    println!(
        "Transferred {} to recipient, fee={}, dal fee={}, change={} (idx={},{},{})",
        amount, fee, dal_fee, change, resp.index_1, resp.index_2, resp.index_3
    );
    println!("Run 'scan' to pick up change note.");
    Ok(())
}

fn cmd_unshield(
    path: &str,
    ledger: &str,
    amount: u64,
    fee: Option<u64>,
    dal_fee: u64,
    dal_fee_address_path: &str,
    recipient: &str,
    pc: &ProveConfig,
) -> Result<(), String> {
    let recipient = validate_l1_withdrawal_recipient(recipient)?;
    let cfg: ConfigResp = get_json(&format!("{}/config", ledger))?;
    let fee = resolve_requested_tx_fee(fee, cfg.required_tx_fee)?;
    ensure_positive_dal_fee(dal_fee)?;
    let mut w = load_wallet(path)?;
    let outgoing_seed = w.account().outgoing_seed;
    let producer_address = load_address(dal_fee_address_path)?;

    let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))?;
    let root = tree_info.root;

    if pc.skip_proof {
        let prepared = prepare_unshield_skip_proof(
            &mut w,
            root,
            amount,
            fee,
            dal_fee,
            &producer_address,
            &recipient,
        )?;
        save_wallet(path, &w)?;
        let resp: UnshieldResp = post_json(&format!("{}/unshield", ledger), &prepared.req)?;
        finalize_successful_spend(path, &mut w, &prepared.selected)?;
        println!(
            "Unshielded {} to {}, fee={}, dal fee={}, change={} (change_idx={:?}, producer_idx={})",
            amount,
            recipient,
            fee,
            dal_fee,
            prepared.change,
            resp.change_index,
            resp.producer_index
        );
        if prepared.change > 0 {
            println!("Run 'scan' to pick up change note.");
        }
        return Ok(());
    }

    let total_spend = amount
        .checked_add(fee)
        .and_then(|value| value.checked_add(dal_fee))
        .ok_or_else(|| "unshield total spend overflow".to_string())?;
    let selected = w.select_notes(total_spend)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128 - fee as u128 - dal_fee as u128) as u64;

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
        let change_address = change_state.payment_address(&ek_v_c, &ek_d_c);
        let note = build_output_note_with_outgoing(
            &change_address,
            change,
            None,
            &outgoing_seed,
            OutgoingNoteRole::UnshieldChange,
        )?;
        let cd = ChangeData {
            d_j: change_state.d_j,
            rseed: note.rseed,
            auth_root: change_state.auth_root,
            auth_pub_seed: change_state.auth_pub_seed,
            nk_tag: change_state.nk_tag,
            mh: note.mh,
        };
        (note.cm, Some(note.enc), Some(cd))
    } else {
        (ZERO, None, None)
    };
    let producer_note = build_output_note_with_outgoing(
        &producer_address,
        dal_fee,
        Some(b"dal"),
        &outgoing_seed,
        OutgoingNoteRole::ProducerFee,
    )?;

    let proof = if !pc.skip_proof {
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
            fee,
            &recipient_f,
            &cm_change,
            &mh_change_f,
            &producer_note.cm,
            &producer_note.mh,
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

        let total = 6 + 9 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS + 15;
        args.push(felt_u64_to_hex(total as u64));
        args.push(felt_u64_to_hex(n as u64));
        args.push(felt_to_hex(&auth_domain));
        args.push(felt_to_hex(&root));
        args.push(felt_u64_to_hex(amount));
        args.push(felt_u64_to_hex(fee));
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

        args.push(felt_to_hex(&producer_address.d_j));
        args.push(felt_u64_to_hex(dal_fee));
        args.push(felt_to_hex(&producer_note.rseed));
        args.push(felt_to_hex(&producer_address.auth_root));
        args.push(felt_to_hex(&producer_address.auth_pub_seed));
        args.push(felt_to_hex(&producer_address.nk_tag));
        args.push(felt_to_hex(&producer_note.mh));

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
        fee,
        recipient: recipient.clone(),
        cm_change,
        enc_change,
        cm_fee: producer_note.cm,
        enc_fee: producer_note.enc,
        proof,
    };
    let resp: UnshieldResp = post_json(&format!("{}/unshield", ledger), &req)?;

    finalize_successful_spend(path, &mut w, &selected)?;

    println!(
        "Unshielded {} to {}, fee={}, dal fee={}, change={} (change_idx={:?}, producer_idx={})",
        amount, recipient, fee, dal_fee, change, resp.change_index, resp.producer_index
    );
    if change > 0 {
        println!("Run 'scan' to pick up change note.");
    }
    Ok(())
}

/// Drain a deposit pool into a freshly-minted shielded note owned by the
/// pool's auth tree. The shield circuit verifies an in-circuit WOTS+
/// signature under that same auth tree, binding the request payload (v,
/// fee, producer_fee, output commitments) so a delegated prover holding
/// the witness still cannot redirect funds. Each shield consumes one
/// WOTS+ key from the pool-owning address's auth tree (mirroring transfer
/// / unshield).
fn cmd_shield_rollup(
    path: &str,
    profile: &WalletNetworkProfile,
    pubkey_hash_arg: &str,
    amount_arg: Option<u64>,
    pc: &ProveConfig,
) -> Result<(), String> {
    // Upstream patch ④: phase event — entered the shield path, deposit
    // selection / witness build is about to start.
    phase_event!("op_started", {
        "kind": "shield",
        "amount": amount_arg,
        "pubkey_hash": pubkey_hash_arg,
        "recipient": serde_json::Value::Null,
    });
    let rollup = RollupRpc::new(profile);
    let pubkey_hash = parse_pubkey_hash_hex(pubkey_hash_arg)?;

    let head_hash = rollup.head_hash()?;
    let snapshot = rollup.load_state_snapshot_at_block(&head_hash)?;
    let fee = snapshot.required_tx_fee;
    ensure_positive_dal_fee(profile.dal_fee)?;
    let producer_fee = profile.dal_fee;
    let producer_address = profile.dal_fee_address.clone();

    // Pool must currently hold at least the fixed fees; otherwise even a
    // zero-value shield can't settle.
    let pool_balance = rollup
        .try_read_deposit_balance(&head_hash, &pubkey_hash)?
        .ok_or_else(|| {
            format!(
                "deposit pool {} not found or already drained",
                pubkey_hash_hex(&pubkey_hash)
            )
        })?;
    let min_fees = fee
        .checked_add(producer_fee)
        .ok_or_else(|| "fee + producer_fee overflow".to_string())?;
    if pool_balance < min_fees {
        return Err(format!(
            "deposit pool {} balance {} < required fees {} (tx_fee {} + producer_fee {})",
            pubkey_hash_hex(&pubkey_hash),
            pool_balance,
            min_fees,
            fee,
            producer_fee,
        ));
    }
    let amount = match amount_arg {
        Some(a) => a,
        None => pool_balance - min_fees,
    };
    let total_drain = amount
        .checked_add(min_fees)
        .ok_or_else(|| "shield total draw overflow".to_string())?;
    if pool_balance < total_drain {
        return Err(format!(
            "deposit pool {} balance {} < requested draw {} (amount {} + tx_fee {} + producer_fee {})",
            pubkey_hash_hex(&pubkey_hash),
            pool_balance,
            total_drain,
            amount,
            fee,
            producer_fee,
        ));
    }

    let mut w = load_wallet(path)?;
    let pending_match = select_pending_deposit_by_pubkey_hash(&w, &pubkey_hash)?;
    let blind = pending_match.blind;
    let address_index = pending_match.address_index;
    let stored_auth_domain = pending_match.auth_domain;

    let auth_domain = snapshot.auth_domain;
    if auth_domain != stored_auth_domain {
        return Err(format!(
            "auth_domain mismatch: kernel {} != local PendingDeposit {} for pool {}",
            short(&auth_domain),
            short(&stored_auth_domain),
            pubkey_hash_hex(&pubkey_hash),
        ));
    }

    // Recipient note is owned by the pool's auth tree (same auth_root /
    // auth_pub_seed). Build a `PaymentAddress` from the wallet's address
    // record so we can re-use the standard note builder.
    let (ek_v_recipient, _, ek_d_recipient, _) = w.kem_keys(address_index);
    let recipient_state = w
        .addresses
        .get(address_index as usize)
        .cloned()
        .ok_or_else(|| format!("missing wallet address record {}", address_index))?;
    let recipient = recipient_state.payment_address(&ek_v_recipient, &ek_d_recipient);

    let outgoing_seed = w.account().outgoing_seed;
    let note_recipient = build_output_note_with_outgoing(
        &recipient,
        amount,
        None,
        &outgoing_seed,
        OutgoingNoteRole::ShieldOutput,
    )?;
    let note_producer = build_output_note_with_outgoing(
        &producer_address,
        producer_fee,
        Some(b"dal"),
        &outgoing_seed,
        OutgoingNoteRole::ProducerFee,
    )?;

    let sighash = shield_sighash(
        &auth_domain,
        &pubkey_hash,
        amount,
        fee,
        producer_fee,
        &note_recipient.cm,
        &note_producer.cm,
        &note_recipient.mh,
        &note_producer.mh,
    );

    let ask_j = derive_ask(&w.account().ask_base, address_index);
    let (key_idx, auth_root, auth_pub_seed, auth_path) = w.reserve_next_auth(address_index)?;
    if auth_root != recipient.auth_root || auth_pub_seed != recipient.auth_pub_seed {
        return Err(format!(
            "auth tree mismatch for address {}: reserved ({}, {}) but recipient state has ({}, {})",
            address_index,
            short(&auth_root),
            short(&auth_pub_seed),
            short(&recipient.auth_root),
            short(&recipient.auth_pub_seed),
        ));
    }
    let recomputed_pkh = deposit_pubkey_hash(&auth_domain, &auth_root, &auth_pub_seed, &blind);
    if recomputed_pkh != pubkey_hash {
        return Err(format!(
            "pubkey_hash mismatch: recomputed {} != requested {}",
            pubkey_hash_hex(&recomputed_pkh),
            pubkey_hash_hex(&pubkey_hash),
        ));
    }
    let (sig, _pk, _digits) = wots_sign(&ask_j, key_idx, &sighash);

    let proof = {
        let total_fields: usize = 16 + WOTS_CHAINS + AUTH_DEPTH + 5;
        let mut args: Vec<String> = Vec::with_capacity(1 + total_fields);
        args.push(felt_u64_to_hex(total_fields as u64));

        // Fixed prefix (16): public outputs first, then recipient witness, then auth_idx.
        args.push(felt_to_hex(&auth_domain));
        args.push(felt_to_hex(&pubkey_hash));
        args.push(felt_u64_to_hex(amount));
        args.push(felt_u64_to_hex(fee));
        args.push(felt_u64_to_hex(producer_fee));
        args.push(felt_to_hex(&note_recipient.cm));
        args.push(felt_to_hex(&note_producer.cm));
        args.push(felt_to_hex(&note_recipient.mh));
        args.push(felt_to_hex(&note_producer.mh));
        args.push(felt_to_hex(&auth_root));
        args.push(felt_to_hex(&auth_pub_seed));
        args.push(felt_to_hex(&recipient.nk_tag));
        args.push(felt_to_hex(&recipient.d_j));
        args.push(felt_to_hex(&note_recipient.rseed));
        args.push(felt_to_hex(&blind));
        args.push(felt_u64_to_hex(key_idx as u64));

        // WOTS+ signature chains (WOTS_CHAINS).
        for s in &sig {
            args.push(felt_to_hex(s));
        }
        // Auth-tree siblings for `auth_idx = key_idx` (AUTH_DEPTH).
        for sib in &auth_path {
            args.push(felt_to_hex(sib));
        }

        // Producer-fee witness (5).
        args.push(felt_to_hex(&producer_address.auth_root));
        args.push(felt_to_hex(&producer_address.auth_pub_seed));
        args.push(felt_to_hex(&producer_address.nk_tag));
        args.push(felt_to_hex(&producer_address.d_j));
        args.push(felt_to_hex(&note_producer.rseed));

        persist_wallet_and_make_proof(path, &w, pc, "run_shield", &args)?
    };

    save_wallet(path, &w)?;
    let req = ShieldReq {
        pubkey_hash,
        fee,
        v: amount,
        producer_fee,
        proof,
        client_cm: note_recipient.cm,
        client_enc: note_recipient.enc,
        producer_cm: note_producer.cm,
        producer_enc: note_producer.enc,
    };
    let kernel_req = shield_req_to_kernel(&req)?;
    // Upstream patch ④: about to POST to operator.
    let kernel_msg = KernelInboxMessage::Shield(kernel_req);
    let payload_bytes = encode_kernel_inbox_message(&kernel_msg)
        .map(|p| p.len() as u64)
        .unwrap_or(0);
    phase_event!("submitting_to_operator", {
        "operator_url": profile.operator_url.as_deref().unwrap_or(""),
        "payload_bytes": payload_bytes,
    });
    let submission = rollup.submit_kernel_message(&kernel_msg)?;
    emit_operator_done_event(&submission);
    // Mark every local PendingDeposit for this pool as consumed by
    // *this* shield's recipient cm — overwriting any previous cm
    // recorded against the same pool. Multi-stage drains are
    // legitimate (the core ledger explicitly supports two distinct
    // shields draining one pool), so the latest cm is the one sync
    // most likely sees in the next feed; older cms are still tracked
    // cumulatively in `w.notes`, so the prune predicate in
    // `apply_scan_feed` accepts an observation of any prior cm too.
    for p in w
        .pending_deposits
        .iter_mut()
        .filter(|p| p.pubkey_hash == pubkey_hash)
    {
        p.shielded_cm = Some(note_recipient.cm);
    }
    save_wallet(path, &w)?;

    println!(
        "Submitted shield of {} from pool {} (fee {} + producer_fee {})",
        amount,
        pubkey_hash_hex(&pubkey_hash),
        fee,
        producer_fee
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
    fee: Option<u64>,
    memo: Option<String>,
    pc: &ProveConfig,
) -> Result<(), String> {
    // Upstream patch ④: phase event — entered the transfer path.
    phase_event!("op_started", {
        "kind": "transfer",
        "amount": amount,
        "deposit_id": serde_json::Value::Null,
        "recipient": to_path,
    });
    let rollup = RollupRpc::new(profile);
    let snapshot = rollup.load_state_snapshot()?;
    let fee = resolve_requested_tx_fee(fee, snapshot.required_tx_fee)?;
    ensure_positive_dal_fee(profile.dal_fee)?;
    let root = snapshot.current_root();

    let mut w = load_wallet(path)?;
    let outgoing_seed = w.account().outgoing_seed;
    let recipient = load_address(to_path)?;
    let producer_address = &profile.dal_fee_address;
    let total_spend = amount
        .checked_add(fee)
        .and_then(|value| value.checked_add(profile.dal_fee))
        .ok_or_else(|| "transfer total spend overflow".to_string())?;
    let selected = w.select_notes(total_spend)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128 - fee as u128 - profile.dal_fee as u128) as u64;

    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| note_nullifier(&w.notes[i]))
        .collect();

    let note_1 = build_output_note_with_outgoing(
        &recipient,
        amount,
        memo.as_deref().map(str::as_bytes),
        &outgoing_seed,
        OutgoingNoteRole::TransferRecipient,
    )?;

    let (change_state, _change_addr) = w.next_address()?;
    let (ek_v_c, _, ek_d_c, _) = w.kem_keys(change_state.index);
    let change_address = change_state.payment_address(&ek_v_c, &ek_d_c);
    let note_2 = build_output_note_with_outgoing(
        &change_address,
        change,
        None,
        &outgoing_seed,
        OutgoingNoteRole::TransferChange,
    )?;
    let note_3 = build_output_note_with_outgoing(
        producer_address,
        profile.dal_fee,
        Some(b"dal"),
        &outgoing_seed,
        OutgoingNoteRole::ProducerFee,
    )?;

    let proof = {
        let auth_domain = snapshot.auth_domain;
        let n = selected.len();
        let mut args: Vec<String> = vec![];
        let mut cm_paths: Vec<Vec<F>> = vec![];
        let mut auth_paths: Vec<Vec<F>> = vec![];
        let mut wots_sigs: Vec<Vec<F>> = vec![];

        let nfs_for_sh = nullifiers.clone();
        let sighash = transfer_sighash(
            &auth_domain,
            &root,
            &nfs_for_sh,
            fee,
            &note_1.cm,
            &note_2.cm,
            &note_3.cm,
            &note_1.mh,
            &note_2.mh,
            &note_3.mh,
        );

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

        let total_fields = 4 + 9 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS + 24;
        args.push(felt_u64_to_hex(total_fields as u64));
        args.push(felt_u64_to_hex(n as u64));
        args.push(felt_to_hex(&auth_domain));
        args.push(felt_to_hex(&root));
        args.push(felt_u64_to_hex(fee));

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

        args.push(felt_to_hex(&note_1.cm));
        args.push(felt_to_hex(&recipient.d_j));
        args.push(felt_u64_to_hex(amount));
        args.push(felt_to_hex(&note_1.rseed));
        args.push(felt_to_hex(&recipient.auth_root));
        args.push(felt_to_hex(&recipient.auth_pub_seed));
        args.push(felt_to_hex(&recipient.nk_tag));
        args.push(felt_to_hex(&note_1.mh));

        args.push(felt_to_hex(&note_2.cm));
        args.push(felt_to_hex(&change_state.d_j));
        args.push(felt_u64_to_hex(change));
        args.push(felt_to_hex(&note_2.rseed));
        args.push(felt_to_hex(&change_state.auth_root));
        args.push(felt_to_hex(&change_state.auth_pub_seed));
        args.push(felt_to_hex(&change_state.nk_tag));
        args.push(felt_to_hex(&note_2.mh));

        args.push(felt_to_hex(&note_3.cm));
        args.push(felt_to_hex(&producer_address.d_j));
        args.push(felt_u64_to_hex(profile.dal_fee));
        args.push(felt_to_hex(&note_3.rseed));
        args.push(felt_to_hex(&producer_address.auth_root));
        args.push(felt_to_hex(&producer_address.auth_pub_seed));
        args.push(felt_to_hex(&producer_address.nk_tag));
        args.push(felt_to_hex(&note_3.mh));

        persist_wallet_and_make_proof(path, &w, pc, "run_transfer", &args)?
    };

    save_wallet(path, &w)?;
    let req = TransferReq {
        root,
        nullifiers: nullifiers.clone(),
        fee,
        cm_1: note_1.cm,
        cm_2: note_2.cm,
        cm_3: note_3.cm,
        enc_1: note_1.enc,
        enc_2: note_2.enc,
        enc_3: note_3.enc,
        proof,
    };
    let kernel_req = transfer_req_to_kernel(&req)?;
    // Upstream patch ④: about to POST to operator.
    let kernel_msg = KernelInboxMessage::Transfer(kernel_req);
    let payload_bytes = encode_kernel_inbox_message(&kernel_msg)
        .map(|p| p.len() as u64)
        .unwrap_or(0);
    phase_event!("submitting_to_operator", {
        "operator_url": profile.operator_url.as_deref().unwrap_or(""),
        "payload_bytes": payload_bytes,
    });
    let submission = rollup.submit_kernel_message(&kernel_msg)?;
    emit_operator_done_event(&submission);
    w.register_pending_spend(
        nullifiers,
        format!("transfer {}", amount),
        submission.operation_hash.clone(),
    );
    save_wallet(path, &w)?;

    println!(
        "Submitted transfer of {} with fee {} + dal fee {} and change {}",
        amount, fee, profile.dal_fee, change
    );
    print_rollup_submission(&submission);
    print_rollup_sync_hint(&submission);
    Ok(())
}

fn cmd_unshield_rollup(
    path: &str,
    profile: &WalletNetworkProfile,
    amount: u64,
    fee: Option<u64>,
    recipient: Option<&str>,
    pc: &ProveConfig,
) -> Result<(), String> {
    // Upstream patch ④: phase event — entered the unshield path.
    // recipient may be `None` here (= default to caller's L1 address);
    // we forward that as null in the JSON.
    phase_event!("op_started", {
        "kind": "unshield",
        "amount": amount,
        "deposit_id": serde_json::Value::Null,
        "recipient": recipient.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null),
    });
    let rollup = RollupRpc::new(profile);
    let recipient = resolve_rollup_unshield_recipient(&rollup, recipient)?;
    let snapshot = rollup.load_state_snapshot()?;
    let fee = resolve_requested_tx_fee(fee, snapshot.required_tx_fee)?;
    ensure_positive_dal_fee(profile.dal_fee)?;
    let root = snapshot.current_root();

    let mut w = load_wallet(path)?;
    let outgoing_seed = w.account().outgoing_seed;
    let producer_address = &profile.dal_fee_address;
    let total_spend = amount
        .checked_add(fee)
        .and_then(|value| value.checked_add(profile.dal_fee))
        .ok_or_else(|| "unshield total spend overflow".to_string())?;
    let selected = w.select_notes(total_spend)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128 - fee as u128 - profile.dal_fee as u128) as u64;

    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| note_nullifier(&w.notes[i]))
        .collect();

    let (cm_change, enc_change, change_data) = if change > 0 {
        let (change_state, _change_addr) = w.next_address()?;
        let (ek_v_c, _, ek_d_c, _) = w.kem_keys(change_state.index);
        let change_address = change_state.payment_address(&ek_v_c, &ek_d_c);
        let note = build_output_note_with_outgoing(
            &change_address,
            change,
            None,
            &outgoing_seed,
            OutgoingNoteRole::UnshieldChange,
        )?;
        let cd = ChangeData {
            d_j: change_state.d_j,
            rseed: note.rseed,
            auth_root: change_state.auth_root,
            auth_pub_seed: change_state.auth_pub_seed,
            nk_tag: change_state.nk_tag,
            mh: note.mh,
        };
        (note.cm, Some(note.enc), Some(cd))
    } else {
        (ZERO, None, None)
    };
    let producer_note = build_output_note_with_outgoing(
        producer_address,
        profile.dal_fee,
        Some(b"dal"),
        &outgoing_seed,
        OutgoingNoteRole::ProducerFee,
    )?;

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
            fee,
            &recipient_f,
            &cm_change,
            &mh_change_f,
            &producer_note.cm,
            &producer_note.mh,
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

        let total = 6 + 9 * n + n * DEPTH + n * AUTH_DEPTH + n * WOTS_CHAINS + 15;
        args.push(felt_u64_to_hex(total as u64));
        args.push(felt_u64_to_hex(n as u64));
        args.push(felt_to_hex(&auth_domain));
        args.push(felt_to_hex(&root));
        args.push(felt_u64_to_hex(amount));
        args.push(felt_u64_to_hex(fee));
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

        args.push(felt_to_hex(&producer_address.d_j));
        args.push(felt_u64_to_hex(profile.dal_fee));
        args.push(felt_to_hex(&producer_note.rseed));
        args.push(felt_to_hex(&producer_address.auth_root));
        args.push(felt_to_hex(&producer_address.auth_pub_seed));
        args.push(felt_to_hex(&producer_address.nk_tag));
        args.push(felt_to_hex(&producer_note.mh));

        persist_wallet_and_make_proof(path, &w, pc, "run_unshield", &args)?
    };

    save_wallet(path, &w)?;
    let req = UnshieldReq {
        root,
        nullifiers: nullifiers.clone(),
        v_pub: amount,
        fee,
        recipient: recipient.clone(),
        cm_change,
        enc_change,
        cm_fee: producer_note.cm,
        enc_fee: producer_note.enc,
        proof,
    };
    let kernel_req = unshield_req_to_kernel(&req)?;
    // Upstream patch ④: about to POST to operator.
    let kernel_msg = KernelInboxMessage::Unshield(kernel_req);
    let payload_bytes = encode_kernel_inbox_message(&kernel_msg)
        .map(|p| p.len() as u64)
        .unwrap_or(0);
    phase_event!("submitting_to_operator", {
        "operator_url": profile.operator_url.as_deref().unwrap_or(""),
        "payload_bytes": payload_bytes,
    });
    let submission = rollup.submit_kernel_message(&kernel_msg)?;
    emit_operator_done_event(&submission);
    w.register_pending_spend(
        nullifiers,
        format!("unshield {}", amount),
        submission.operation_hash.clone(),
    );
    save_wallet(path, &w)?;

    println!(
        "Submitted unshield of {} to L1 recipient {} with fee {} + dal fee {}",
        amount, recipient, fee, profile.dal_fee
    );
    print_rollup_submission(&submission);
    println!("The L1 release now comes from this unshield via the normal smart-rollup outbox/cementation flow.");
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
    fee: u64,
    dal_fee: u64,
    producer_address: &PaymentAddress,
    memo: Option<&str>,
) -> Result<PreparedTransferSubmit, String> {
    let total_spend = amount
        .checked_add(fee)
        .and_then(|value| value.checked_add(dal_fee))
        .ok_or_else(|| "transfer total spend overflow".to_string())?;
    let selected = w.select_notes(total_spend)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128 - fee as u128 - dal_fee as u128) as u64;
    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();
    let outgoing_seed = w.account().outgoing_seed;

    let note_1 = build_output_note_with_outgoing(
        recipient,
        amount,
        memo.map(str::as_bytes),
        &outgoing_seed,
        OutgoingNoteRole::TransferRecipient,
    )?;

    let (change_state, _change_addr) = w.next_address()?;
    let (ek_v_c, _, ek_d_c, _) = w.kem_keys(change_state.index);
    let change_address = change_state.payment_address(&ek_v_c, &ek_d_c);
    let note_2 = build_output_note_with_outgoing(
        &change_address,
        change,
        None,
        &outgoing_seed,
        OutgoingNoteRole::TransferChange,
    )?;
    let note_3 = build_output_note_with_outgoing(
        producer_address,
        dal_fee,
        Some(b"dal"),
        &outgoing_seed,
        OutgoingNoteRole::ProducerFee,
    )?;

    Ok(PreparedTransferSubmit {
        selected,
        change,
        req: TransferReq {
            root,
            nullifiers,
            fee,
            cm_1: note_1.cm,
            cm_2: note_2.cm,
            cm_3: note_3.cm,
            enc_1: note_1.enc,
            enc_2: note_2.enc,
            enc_3: note_3.enc,
            proof: Proof::TrustMeBro,
        },
    })
}

fn prepare_unshield_skip_proof(
    w: &mut WalletFile,
    root: F,
    amount: u64,
    fee: u64,
    dal_fee: u64,
    producer_address: &PaymentAddress,
    recipient: &str,
) -> Result<PreparedUnshieldSubmit, String> {
    let total_spend = amount
        .checked_add(fee)
        .and_then(|value| value.checked_add(dal_fee))
        .ok_or_else(|| "unshield total spend overflow".to_string())?;
    let selected = w.select_notes(total_spend)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128 - fee as u128 - dal_fee as u128) as u64;
    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();
    let outgoing_seed = w.account().outgoing_seed;

    let (cm_change, enc_change, _change_data) = if change > 0 {
        let (change_state, _change_addr) = w.next_address()?;
        let (ek_v_c, _, ek_d_c, _) = w.kem_keys(change_state.index);
        let change_address = change_state.payment_address(&ek_v_c, &ek_d_c);
        let note = build_output_note_with_outgoing(
            &change_address,
            change,
            None,
            &outgoing_seed,
            OutgoingNoteRole::UnshieldChange,
        )?;
        let cd = ChangeData {
            d_j: change_state.d_j,
            rseed: note.rseed,
            auth_root: change_state.auth_root,
            auth_pub_seed: change_state.auth_pub_seed,
            nk_tag: change_state.nk_tag,
            mh: note.mh,
        };
        (note.cm, Some(note.enc), Some(cd))
    } else {
        (ZERO, None, None)
    };
    let producer_note = build_output_note_with_outgoing(
        producer_address,
        dal_fee,
        Some(b"dal"),
        &outgoing_seed,
        OutgoingNoteRole::ProducerFee,
    )?;

    Ok(PreparedUnshieldSubmit {
        selected,
        change,
        req: UnshieldReq {
            root,
            nullifiers,
            v_pub: amount,
            fee,
            recipient: recipient.into(),
            cm_change,
            enc_change,
            cm_fee: producer_note.cm,
            enc_fee: producer_note.enc,
            proof: Proof::TrustMeBro,
        },
    })
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


#[cfg(test)]
mod network_profile_tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_dal_fee_address() -> PaymentAddress {
        let wallet = super::tests::test_wallet(1);
        super::tests::payment_address_for_wallet_address(&wallet, 0)
    }

    #[test]
    fn network_profile_roundtrip_persists_shadownet_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wallet_path = dir.path().join("wallet.json");
        let profile_path = default_network_profile_path(wallet_path.to_str().unwrap());
        let profile = shadownet_profile(
            "https://rollup.shadownet.example".into(),
            "sr1ExampleRollup".into(),
            "KT1ExampleTicketer".into(),
            1,
            sample_dal_fee_address(),
            Some("https://operator.shadownet.example".into()),
            Some("operator-secret".into()),
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
            1,
            sample_dal_fee_address(),
            None,
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
    fn save_network_profile_rejects_operator_url_without_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("wallet.network.json");
        let profile = shadownet_profile(
            "https://saved-rollup.example".into(),
            "sr1SavedRollup".into(),
            "KT1SavedTicketer".into(),
            1,
            sample_dal_fee_address(),
            Some("https://operator.shadownet.example".into()),
            None,
            "bootstrap1".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let err = save_network_profile(&profile_path, &profile).unwrap_err();
        assert!(err.contains("operator_url requires operator_bearer_token"));
    }

    #[test]
    fn load_required_network_profile_rejects_saved_operator_url_without_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let profile_path = default_network_profile_path(wallet_path_str);
        let bad_profile = serde_json::json!({
            "network": "shadownet",
            "rollup_node_url": "https://saved-rollup.example",
            "rollup_address": "sr1SavedRollup",
            "bridge_ticketer": "KT1SavedTicketer",
            "dal_fee": 1,
            "dal_fee_address": sample_dal_fee_address(),
            "operator_url": "https://operator.shadownet.example",
            "source_alias": "bootstrap1",
            "public_account": "bootstrap1",
            "octez_client_bin": "octez-client",
            "burn_cap": "1"
        });
        std::fs::write(
            &profile_path,
            serde_json::to_string_pretty(&bad_profile).unwrap(),
        )
        .expect("write bad profile");

        let err = load_required_network_profile(wallet_path_str).unwrap_err();
        assert!(err.contains("operator_url requires operator_bearer_token"));
    }

    #[cfg(unix)]
    #[test]
    fn cmd_unshield_rollup_skips_octez_lookup_for_explicit_l1_recipient() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let note_value = 200_000u64;
        let mut wallet = super::tests::test_wallet(1);
        let addr = wallet.addresses[0].clone();
        let acc = wallet.account();
        let nk_spend = derive_nk_spend(&acc.nk, &addr.d_j);
        let nk_tag = derive_nk_tag(&nk_spend);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &nk_tag);
        let rseed = felt_tag(b"canonical-unshield");
        let rcm = derive_rcm(&rseed);
        let cm = commit(&addr.d_j, note_value, &rcm, &otag);
        wallet.notes.push(Note {
            nk_spend,
            nk_tag,
            auth_root: addr.auth_root,
            d_j: addr.d_j,
            v: note_value,
            rseed,
            cm,
            index: 0,
            addr_index: 0,
        });
        save_wallet(wallet_path_str, &wallet).expect("save wallet");

        let note = super::tests::note_memo_for_wallet_address(
            &wallet,
            0,
            note_value,
            wallet.notes[0].rseed,
            None,
        );
        let encoded = canonical_wire::encode_published_note(&note.cm, &note.enc)
            .expect("published note should encode");
        let root = MerkleTree::from_leaves(vec![note.cm]).root();

        let octez_log = dir.path().join("octez.log");
        let octez_client = dir.path().join("fake-octez-client.sh");
        let reprove = dir.path().join("fake-reprove.sh");
        std::fs::write(
            &octez_client,
            format!(
                "#!/bin/sh\nset -eu\necho \"$@\" >> '{}'\necho 'octez should not be invoked for canonical unshield recipients' >&2\nexit 64\n",
                octez_log.display()
            ),
        )
        .expect("write fake octez-client");
        std::fs::set_permissions(&octez_client, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake octez-client");
        std::fs::write(
            &reprove,
            "#!/bin/sh\nset -eu\nout=''\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = '--output' ]; then\n    out=\"$2\"\n    shift 2\n  else\n    shift\n  fi\ndone\nprintf '%s' '{\"proof_bytes\":\"de\",\"output_preimage\":[]}' > \"$out\"\n",
        )
        .expect("write fake reprove");
        std::fs::set_permissions(&reprove, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake reprove");

        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/block/head/hash".into(),
                (200, "\"BLunshieldhead\"".into()),
            ),
            (
                "/global/block/BLunshieldhead/level".into(),
                (200, "10".into()),
            ),
            (
                format!(
                    "/global/block/BLunshieldhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_AUTH_DOMAIN
                ),
                (200, format!("\"{}\"", hex::encode(default_auth_domain()))),
            ),
            (
                format!(
                    "/global/block/BLunshieldhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_TREE_SIZE
                ),
                (200, format!("\"{}\"", hex::encode(1u64.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLunshieldhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_TREE_ROOT
                ),
                (200, format!("\"{}\"", hex::encode(root))),
            ),
            (
                format!(
                    "/global/block/BLunshieldhead/durable/wasm_2_0_0/length?key={}",
                    indexed_durable_key(DURABLE_NOTE_PREFIX, 0)
                ),
                (200, encoded.len().to_string()),
            ),
            (
                format!(
                    "/global/block/BLunshieldhead/durable/wasm_2_0_0/value?key={}",
                    indexed_durable_key(DURABLE_NOTE_PREFIX, 0)
                ),
                (200, format!("\"{}\"", hex::encode(encoded))),
            ),
            (
                format!(
                    "/global/block/BLunshieldhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLunshieldhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLunshieldhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "null".into()),
            ),
            // Verifier config: owner_tag=ZERO so the wallet's gate proceeds
            // with a warning (not a hard refuse) for the test fixture.
            {
                let cfg = tzel_services::kernel_wire::KernelVerifierConfig {
                    auth_domain: default_auth_domain(),
                    verified_program_hashes: ProgramHashes {
                        shield: hash(b"test-shield"),
                        transfer: hash(b"test-transfer"),
                        unshield: hash(b"test-unshield"),
                    },
                };
                let encoded = tzel_services::kernel_wire::encode_kernel_verifier_config(&cfg)
                    .expect("verifier config encodes");
                (
                    format!(
                        "/global/block/BLunshieldhead/durable/wasm_2_0_0/length?key={}",
                        DURABLE_VERIFIER_CONFIG
                    ),
                    (200, encoded.len().to_string()),
                )
            },
            {
                let cfg = tzel_services::kernel_wire::KernelVerifierConfig {
                    auth_domain: default_auth_domain(),
                    verified_program_hashes: ProgramHashes {
                        shield: hash(b"test-shield"),
                        transfer: hash(b"test-transfer"),
                        unshield: hash(b"test-unshield"),
                    },
                };
                let encoded = tzel_services::kernel_wire::encode_kernel_verifier_config(&cfg)
                    .expect("verifier config encodes");
                (
                    format!(
                        "/global/block/BLunshieldhead/durable/wasm_2_0_0/value?key={}",
                        DURABLE_VERIFIER_CONFIG
                    ),
                    (200, format!("\"{}\"", hex::encode(&encoded))),
                )
            },
        ]));
        let operator_url = super::tests::spawn_mock_http_server(HashMap::from([(
            "/v1/rollup/submissions".into(),
            (
                200,
                serde_json::to_string(&SubmitRollupMessageResp {
                    submission: RollupSubmission {
                        id: "sub-unshield".into(),
                        kind: RollupSubmissionKind::Unshield,
                        rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
                        status: RollupSubmissionStatus::PendingDal,
                        transport: RollupSubmissionTransport::Dal,
                        operation_hash: Some("ooCanonicalUnshield".into()),
                        dal_chunks: vec![],
                        commitment: None,
                        published_level: None,
                        slot_index: None,
                        payload_hash: None,
                        payload_len: 123,
                        detail: Some("queued".into()),
                    },
                })
                .expect("serialize operator response"),
            ),
        )]));
        let mut profile = super::tests::rollup_profile_for_url(&base_url);
        profile.operator_url = Some(operator_url);
        profile.operator_bearer_token = Some("operator-secret".into());
        profile.octez_client_bin = octez_client.to_str().unwrap().into();

        let pc = ProveConfig {
            skip_proof: false,
            reprove_bin: reprove.to_str().unwrap().into(),
            executables_dir: "cairo/target/dev".into(),
            proving_service_url: None,
        };
        let recipient = "tz1LhXujSfRndomkcC64pCpkkjLWQwsmCUMk";
        let amount = note_value - MIN_TX_FEE - profile.dal_fee;

        cmd_unshield_rollup(
            wallet_path_str,
            &profile,
            amount,
            None,
            Some(recipient),
            &pc,
        )
        .expect("explicit L1 unshield recipient should not require octez source lookup");

        let octez_log = std::fs::read_to_string(&octez_log).unwrap_or_default();
        assert!(
            octez_log.trim().is_empty(),
            "unexpected octez invocations: {octez_log}"
        );
    }

    #[test]
    fn display_network_profile_redacts_operator_bearer_token() {
        let profile = shadownet_profile(
            "https://saved-rollup.example".into(),
            "sr1SavedRollup".into(),
            "KT1SavedTicketer".into(),
            1,
            sample_dal_fee_address(),
            Some("https://operator.shadownet.example".into()),
            Some("operator-secret".into()),
            "bootstrap1".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let displayed = display_network_profile_json(&profile);
        assert!(displayed.contains("\"operator_bearer_token\": \"<redacted>\""));
        assert!(!displayed.contains("operator-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn network_profile_is_saved_with_private_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("wallet.network.json");
        let profile = shadownet_profile(
            "https://saved-rollup.example".into(),
            "sr1SavedRollup".into(),
            "KT1SavedTicketer".into(),
            1,
            sample_dal_fee_address(),
            Some("https://operator.shadownet.example".into()),
            Some("operator-secret".into()),
            "bootstrap1".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        save_network_profile(&profile_path, &profile).expect("save profile");

        let mode = std::fs::metadata(&profile_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
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
        let wallet = super::tests::test_wallet(1);
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
    fn rollup_rpc_current_required_tx_fee_resets_after_idle_level() {
        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/block/head/hash".into(),
                (200, "\"BLmockhead\"".into()),
            ),
            ("/global/block/BLmockhead/level".into(), (200, "11".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(10i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(10i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "8".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(3u64.to_le_bytes()))),
            ),
        ]));
        let profile = super::tests::rollup_profile_for_url(&base_url);
        let rollup = RollupRpc::new(&profile);

        assert_eq!(rollup.current_required_tx_fee().unwrap(), MIN_TX_FEE);
    }

    #[test]
    fn rollup_rpc_current_required_tx_fee_quotes_next_inbox_level_not_congested_head() {
        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/block/head/hash".into(),
                (200, "\"BLmockhead\"".into()),
            ),
            ("/global/block/BLmockhead/level".into(), (200, "10".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(10i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(10i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "8".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(6u64.to_le_bytes()))),
            ),
        ]));
        let profile = super::tests::rollup_profile_for_url(&base_url);
        let rollup = RollupRpc::new(&profile);

        assert_eq!(rollup.current_required_tx_fee().unwrap(), MIN_TX_FEE);
    }

    #[test]
    fn rollup_rpc_current_required_tx_fee_uses_pinned_head_next_level_congestion() {
        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/block/head/hash".into(),
                (200, "\"BLmockhead\"".into()),
            ),
            ("/global/block/BLmockhead/level".into(), (200, "10".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(11i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(11i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "8".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(3u64.to_le_bytes()))),
            ),
        ]));
        let profile = super::tests::rollup_profile_for_url(&base_url);
        let rollup = RollupRpc::new(&profile);

        assert_eq!(
            rollup.current_required_tx_fee().unwrap(),
            required_tx_fee_for_private_tx_count(3)
        );
    }

    #[test]
    fn rollup_rpc_current_required_tx_fee_ignores_mismatched_fee_metadata() {
        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/block/head/hash".into(),
                (200, "\"BLmockhead\"".into()),
            ),
            ("/global/block/BLmockhead/level".into(), (200, "10".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(11i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(10i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "8".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(6u64.to_le_bytes()))),
            ),
        ]));
        let profile = super::tests::rollup_profile_for_url(&base_url);
        let rollup = RollupRpc::new(&profile);

        assert_eq!(rollup.current_required_tx_fee().unwrap(), MIN_TX_FEE);
    }

    #[test]
    fn rollup_rpc_current_required_tx_fee_does_not_require_tree_routes() {
        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/block/head/hash".into(),
                (200, "\"BLmockhead\"".into()),
            ),
            ("/global/block/BLmockhead/level".into(), (200, "12".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "null".into()),
            ),
        ]));
        let profile = super::tests::rollup_profile_for_url(&base_url);
        let rollup = RollupRpc::new(&profile);

        assert_eq!(rollup.current_required_tx_fee().unwrap(), MIN_TX_FEE);
    }

    #[test]
    fn rollup_rpc_current_required_tx_fee_pins_reads_to_one_head_hash() {
        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/block/head/hash".into(),
                (200, "\"BLstable\"".into()),
            ),
            ("/global/block/BLstable/level".into(), (200, "10".into())),
            (
                format!(
                    "/global/block/BLstable/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLstable/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLstable/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "null".into()),
            ),
            ("/global/block/head/level".into(), (200, "10".into())),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/value?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(11i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "4".into()),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(11i32.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "8".into()),
            ),
            (
                format!(
                    "/global/block/head/durable/wasm_2_0_0/value?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, format!("\"{}\"", hex::encode(6u64.to_le_bytes()))),
            ),
        ]));
        let profile = super::tests::rollup_profile_for_url(&base_url);
        let rollup = RollupRpc::new(&profile);

        assert_eq!(rollup.current_required_tx_fee().unwrap(), MIN_TX_FEE);
    }


    #[test]
    fn cmd_wallet_check_fails_when_full_snapshot_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let profile_path = default_network_profile_path(wallet_path_str);
        let wallet = super::tests::test_wallet(1);
        let note =
            super::tests::note_memo_for_wallet_address(&wallet, 0, 91, felt_tag(b"check"), None);
        let encoded = canonical_wire::encode_published_note(&note.cm, &note.enc)
            .expect("published note should encode");

        save_wallet(wallet_path_str, &wallet).expect("save wallet");

        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            ("/global/block/head/hash".into(), (200, "\"BLmockhead\"".into())),
            (
                "/global/smart_rollup_address".into(),
                (200, "\"sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP\"".into()),
            ),
            ("/global/block/BLmockhead/level".into(), (200, "12".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_AUTH_DOMAIN
                ),
                (200, format!("\"{}\"", hex::encode(default_auth_domain()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_TREE_SIZE
                ),
                (200, format!("\"{}\"", hex::encode(2u64.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_TREE_ROOT
                ),
                (200, format!("\"{}\"", hex::encode(default_auth_domain()))),
            ),
            (
                "/global/block/BLmockhead/durable/wasm_2_0_0/value?key=/tzel/v1/state/balances/count"
                    .into(),
                (200, format!("\"{}\"", hex::encode(0u64.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    indexed_durable_key(DURABLE_NOTE_PREFIX, 0)
                ),
                (200, "1".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    indexed_durable_key(DURABLE_NOTE_PREFIX, 0)
                ),
                (200, format!("\"{}\"", hex::encode(encoded))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    indexed_durable_key(DURABLE_NOTE_PREFIX, 1)
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    indexed_durable_note_len_key(1)
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "null".into()),
            ),
        ]));

        let profile = super::tests::rollup_profile_for_url(&base_url);
        save_network_profile(&profile_path, &profile).expect("save profile");

        let err = cmd_wallet_check(wallet_path_str, &profile)
            .expect_err("wallet check should fail when the rollup snapshot is incomplete");
        assert!(
            err.contains("missing note 1"),
            "expected missing note error, got: {err}"
        );
    }

    #[test]
    fn cmd_wallet_check_succeeds_with_consistent_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let profile_path = default_network_profile_path(wallet_path_str);
        let wallet = super::tests::test_wallet(1);
        let note =
            super::tests::note_memo_for_wallet_address(&wallet, 0, 91, felt_tag(b"check-ok"), None);
        let encoded = canonical_wire::encode_published_note(&note.cm, &note.enc)
            .expect("published note should encode");
        let root = MerkleTree::from_leaves(vec![note.cm]).root();

        save_wallet(wallet_path_str, &wallet).expect("save wallet");

        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            ("/global/block/head/hash".into(), (200, "\"BLmockhead\"".into())),
            (
                "/global/smart_rollup_address".into(),
                (200, "\"sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP\"".into()),
            ),
            ("/global/block/BLmockhead/level".into(), (200, "12".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_AUTH_DOMAIN
                ),
                (200, format!("\"{}\"", hex::encode(default_auth_domain()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_TREE_SIZE
                ),
                (200, format!("\"{}\"", hex::encode(1u64.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_TREE_ROOT
                ),
                (200, format!("\"{}\"", hex::encode(root))),
            ),
            (
                "/global/block/BLmockhead/durable/wasm_2_0_0/value?key=/tzel/v1/state/balances/count"
                    .into(),
                (200, format!("\"{}\"", hex::encode(0u64.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    indexed_durable_key(DURABLE_NOTE_PREFIX, 0)
                ),
                (200, encoded.len().to_string()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    indexed_durable_key(DURABLE_NOTE_PREFIX, 0)
                ),
                (200, format!("\"{}\"", hex::encode(encoded))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "null".into()),
            ),
        ]));

        let profile = super::tests::rollup_profile_for_url(&base_url);
        save_network_profile(&profile_path, &profile).expect("save profile");

        cmd_wallet_check(wallet_path_str, &profile).expect("wallet check should succeed");
    }

    #[test]
    fn cmd_wallet_check_fails_on_tree_root_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let profile_path = default_network_profile_path(wallet_path_str);
        let wallet = super::tests::test_wallet(1);
        let note =
            super::tests::note_memo_for_wallet_address(&wallet, 0, 52, felt_tag(b"root"), None);
        let encoded = canonical_wire::encode_published_note(&note.cm, &note.enc)
            .expect("published note should encode");

        save_wallet(wallet_path_str, &wallet).expect("save wallet");

        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            ("/global/block/head/hash".into(), (200, "\"BLmockhead\"".into())),
            (
                "/global/smart_rollup_address".into(),
                (200, "\"sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP\"".into()),
            ),
            ("/global/block/BLmockhead/level".into(), (200, "12".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_AUTH_DOMAIN
                ),
                (200, format!("\"{}\"", hex::encode(default_auth_domain()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_TREE_SIZE
                ),
                (200, format!("\"{}\"", hex::encode(1u64.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_TREE_ROOT
                ),
                (200, format!("\"{}\"", hex::encode(default_auth_domain()))),
            ),
            (
                "/global/block/BLmockhead/durable/wasm_2_0_0/value?key=/tzel/v1/state/balances/count"
                    .into(),
                (200, format!("\"{}\"", hex::encode(0u64.to_le_bytes()))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    indexed_durable_key(DURABLE_NOTE_PREFIX, 0)
                ),
                (200, encoded.len().to_string()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    indexed_durable_key(DURABLE_NOTE_PREFIX, 0)
                ),
                (200, format!("\"{}\"", hex::encode(encoded))),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_LAST_INPUT_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_FEE_LEVEL
                ),
                (200, "null".into()),
            ),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}",
                    DURABLE_PRIVATE_TX_COUNT_IN_LEVEL
                ),
                (200, "null".into()),
            ),
        ]));

        let profile = super::tests::rollup_profile_for_url(&base_url);
        save_network_profile(&profile_path, &profile).expect("save profile");

        let err = cmd_wallet_check(wallet_path_str, &profile)
            .expect_err("wallet check should fail on tree root mismatch");
        assert!(
            err.contains("tree root mismatch"),
            "expected tree root mismatch error, got: {err}"
        );
    }

    #[test]
    fn cmd_wallet_check_fails_when_rollup_node_serves_a_different_rollup() {
        // The actual L1 mint targets `profile.rollup_address`. If the
        // wallet's `rollup_node_url` happens to point at a different
        // rollup, every other preflight check is testing the wrong
        // state. The new `ensure_rollup_address_matches` gate at the
        // top of `cmd_wallet_check` (and `cmd_bridge_deposit`) catches
        // this before any other probe runs.
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let profile_path = default_network_profile_path(wallet_path_str);
        let wallet = super::tests::test_wallet(1);
        save_wallet(wallet_path_str, &wallet).expect("save wallet");

        // Mock server reports a *different* rollup than the wallet
        // profile pins. Nothing else needs to be mocked because the
        // rollup-address check fails first.
        let other_address = "sr1Ghp7iJC91k5tukgzMQTfUbY2t8ssVaHJk";
        let base_url = super::tests::spawn_mock_http_server(HashMap::from([(
            "/global/smart_rollup_address".into(),
            (200, format!("\"{}\"", other_address)),
        )]));

        let profile = super::tests::rollup_profile_for_url(&base_url);
        // sanity: the test fixture profile is pinned to a different sr1
        assert_ne!(profile.rollup_address, other_address);
        save_network_profile(&profile_path, &profile).expect("save profile");

        let err = cmd_wallet_check(wallet_path_str, &profile)
            .expect_err("wallet check must reject a wrong-rollup mock node");
        assert!(
            err.contains("rollup-node served address")
                && err.contains("does not match wallet profile.rollup_address"),
            "expected rollup-address mismatch error, got: {err}"
        );
    }

    #[test]
    fn cmd_recover_deposits_finds_funded_pool_from_seed_alone() {
        // After wallet-file loss the user keeps the seed. The new
        // `tzel-wallet recover-deposits` command brute-forces the
        // `(address_index, deposit_nonce)` grid up to user-supplied
        // bounds, recomputes each candidate `pubkey_hash`, and
        // probes the rollup. A funded pool produces a fresh
        // `PendingDeposit` entry and `deposit_nonce` is bumped past
        // the highest recovered value so a subsequent `deposit`
        // doesn't collide.
        //
        // Test wallet uses the prederived 3-address fixture so we
        // don't pay the full XMSS rebuild cost.
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let profile_path = default_network_profile_path(wallet_path_str);
        // Wallet starts with no `pending_deposits` and `deposit_nonce
        // = 0` — exactly the state after a fresh recovery from seed.
        let wallet = super::tests::test_wallet(3);
        save_wallet(wallet_path_str, &wallet).expect("save wallet");

        // Plant a balance for (address_index=1, deposit_nonce=2).
        // Picking values away from the diagonal exercises the full
        // grid scan, not just the simple case.
        let auth_domain = default_auth_domain();
        let target_addr_index = 1u32;
        let target_deposit_nonce = 2u64;
        let target_addr = wallet.addresses[target_addr_index as usize].clone();
        let target_blind = derive_deposit_blind(
            &wallet.master_sk,
            target_addr_index,
            target_deposit_nonce,
        );
        let target_pubkey_hash = deposit_pubkey_hash(
            &auth_domain,
            &target_addr.auth_root,
            &target_addr.auth_pub_seed,
            &target_blind,
        );
        let funded_balance: u64 = 314_159;

        let funded_length_route = format!(
            "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}{}",
            DURABLE_DEPOSIT_BALANCE_PREFIX,
            hex::encode(target_pubkey_hash),
        );
        let funded_value_route = format!(
            "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}{}",
            DURABLE_DEPOSIT_BALANCE_PREFIX,
            hex::encode(target_pubkey_hash),
        );

        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/smart_rollup_address".into(),
                (200, "\"sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP\"".into()),
            ),
            ("/global/block/head/hash".into(), (200, "\"BLmockhead\"".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_AUTH_DOMAIN
                ),
                (200, format!("\"{}\"", hex::encode(auth_domain))),
            ),
            // Funded pool: length+value mocked to return the planted
            // balance; every other candidate falls through to the
            // mock server's default 404, which `try_read_deposit_
            // balance` parses as None.
            (funded_length_route, (200, "\"8\"".into())),
            (
                funded_value_route,
                (200, format!("\"{}\"", hex::encode(funded_balance.to_le_bytes()))),
            ),
        ]));

        let profile = super::tests::rollup_profile_for_url(&base_url);
        save_network_profile(&profile_path, &profile).expect("save profile");

        cmd_recover_deposits(wallet_path_str, &profile, 2, 4)
            .expect("recover-deposits should succeed");

        let recovered = load_wallet(wallet_path_str).expect("reload wallet");
        assert_eq!(
            recovered.pending_deposits.len(),
            1,
            "exactly one pool should have been recovered"
        );
        let pending = &recovered.pending_deposits[0];
        assert_eq!(pending.pubkey_hash, target_pubkey_hash);
        assert_eq!(pending.address_index, target_addr_index);
        assert_eq!(pending.blind, target_blind);
        assert_eq!(pending.auth_domain, auth_domain);
        assert_eq!(pending.amount, funded_balance);
        assert!(pending.shielded_cm.is_none());
        // `deposit_nonce` bumped past the highest recovered value so
        // a subsequent fresh `deposit` doesn't reuse blind (i=*, j=2).
        assert_eq!(recovered.deposit_nonce, target_deposit_nonce + 1);
    }

    #[test]
    fn cmd_recover_deposits_skips_pools_already_tracked_locally() {
        // If the wallet already has a PendingDeposit for the funded
        // pubkey_hash, recovery must NOT add a duplicate. (The
        // command is idempotent under repeated runs.)
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.json");
        let wallet_path_str = wallet_path.to_str().unwrap();
        let profile_path = default_network_profile_path(wallet_path_str);
        let mut wallet = super::tests::test_wallet(3);

        let auth_domain = default_auth_domain();
        let target_addr = wallet.addresses[0].clone();
        let blind = derive_deposit_blind(&wallet.master_sk, 0, 0);
        let pkh = deposit_pubkey_hash(
            &auth_domain,
            &target_addr.auth_root,
            &target_addr.auth_pub_seed,
            &blind,
        );
        wallet.pending_deposits.push(PendingDeposit {
            pubkey_hash: pkh,
            blind,
            address_index: 0,
            auth_domain,
            amount: 999,
            operation_hash: Some("opPreexisting".into()),
            shielded_cm: None,
        });
        save_wallet(wallet_path_str, &wallet).expect("save wallet");

        let funded_length_route = format!(
            "/global/block/BLmockhead/durable/wasm_2_0_0/length?key={}{}",
            DURABLE_DEPOSIT_BALANCE_PREFIX,
            hex::encode(pkh),
        );
        let funded_value_route = format!(
            "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}{}",
            DURABLE_DEPOSIT_BALANCE_PREFIX,
            hex::encode(pkh),
        );
        let base_url = super::tests::spawn_mock_http_server(HashMap::from([
            (
                "/global/smart_rollup_address".into(),
                (200, "\"sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP\"".into()),
            ),
            ("/global/block/head/hash".into(), (200, "\"BLmockhead\"".into())),
            (
                format!(
                    "/global/block/BLmockhead/durable/wasm_2_0_0/value?key={}",
                    DURABLE_AUTH_DOMAIN
                ),
                (200, format!("\"{}\"", hex::encode(auth_domain))),
            ),
            (funded_length_route, (200, "\"8\"".into())),
            (
                funded_value_route,
                (200, format!("\"{}\"", hex::encode(42u64.to_le_bytes()))),
            ),
        ]));
        let profile = super::tests::rollup_profile_for_url(&base_url);
        save_network_profile(&profile_path, &profile).expect("save profile");

        cmd_recover_deposits(wallet_path_str, &profile, 2, 4)
            .expect("recover-deposits idempotent run");
        let after = load_wallet(wallet_path_str).expect("reload wallet");
        assert_eq!(
            after.pending_deposits.len(),
            1,
            "no duplicate entry must be added for an already-tracked pool"
        );
    }

    #[test]
    fn mutez_to_tez_string_formats_exact_tezos_amounts() {
        assert_eq!(mutez_to_tez_string(1), "0.000001");
        assert_eq!(mutez_to_tez_string(1_500_000), "1.5");
        assert_eq!(mutez_to_tez_string(2_000_000), "2");
    }

    #[test]
    fn derive_deposit_blind_distinguishes_master_sk_address_index_and_nonce() {
        // The blind feeds `pubkey_hash = H(0x04, auth_domain,
        // auth_root, auth_pub_seed, blind)`. If two distinct deposits
        // ever derive the same blind, the wallet would aggregate
        // them silently (and on wallet recovery from seed without
        // local nonce state, the user might be surprised). Ensure
        // each of the three inputs is folded into the blind.
        let master_a = ZERO;
        let mut master_b = ZERO;
        master_b[0] = 0x42;

        let blind_a0_n0 = derive_deposit_blind(&master_a, 0, 0);
        let blind_b0_n0 = derive_deposit_blind(&master_b, 0, 0);
        let blind_a1_n0 = derive_deposit_blind(&master_a, 1, 0);
        let blind_a0_n1 = derive_deposit_blind(&master_a, 0, 1);

        assert_ne!(blind_a0_n0, blind_b0_n0, "master_sk");
        assert_ne!(blind_a0_n0, blind_a1_n0, "address_index");
        assert_ne!(blind_a0_n0, blind_a0_n1, "deposit_nonce");
        assert_ne!(blind_a1_n0, blind_a0_n1);

        // Determinism: same inputs → same output (idempotent over
        // wallet restore for the same nonce).
        assert_eq!(blind_a0_n0, derive_deposit_blind(&master_a, 0, 0));
    }

    #[test]
    fn parse_pubkey_hash_hex_accepts_only_canonical_lowercase_hex() {
        // The CLI prints plain lowercase hex (no prefix) and accepts
        // exactly the same form back. The `0x` prefix and the
        // `deposit:` prefix used to be allowed as a convenience; both
        // are explicitly rejected now (no live system to be backwards-
        // compatible with).
        let mut sample = ZERO;
        for (i, b) in sample.iter_mut().enumerate() {
            *b = i as u8;
        }
        let hex = pubkey_hash_hex(&sample);

        // Round-trip: print → parse.
        assert_eq!(parse_pubkey_hash_hex(&hex).unwrap(), sample);

        // Old prefixed forms now reject.
        let err = parse_pubkey_hash_hex(&format!("0x{}", hex)).unwrap_err();
        assert!(err.contains("no `0x` prefix"), "{}", err);
        let err = parse_pubkey_hash_hex(&format!("0X{}", hex)).unwrap_err();
        assert!(err.contains("no `0x` prefix"), "{}", err);
        let err = parse_pubkey_hash_hex(&format!("deposit:{}", hex)).unwrap_err();
        assert!(err.contains("no `deposit:` prefix"), "{}", err);

        // Plain malformed inputs.
        assert!(parse_pubkey_hash_hex("nope").is_err());
        assert!(parse_pubkey_hash_hex("00").is_err());
        // 64 chars but uppercase: rejected.
        assert!(parse_pubkey_hash_hex(&hex.to_uppercase()).is_err());
        // 64 chars but with an embedded non-hex glyph.
        let bad = format!("{}g", &hex[..63]);
        assert!(parse_pubkey_hash_hex(&bad).is_err());
    }

    /// Phase-event wire format is consumed by the daemon's runner.rs
    /// line-parser; pin the JSON shape so a careless rename here is
    /// caught at unit-test time instead of by a daemon-side panic.
    /// Stderr capture itself is exercised by integration tests
    /// downstream.
    #[test]
    fn phase_event_json_shape_round_trips() {
        let detail = serde_json::json!({"kind": "shield", "amount": 1000u64});
        let line = serde_json::json!({
            "event": "phase",
            "phase": "op_started",
            "ts": phase_event_now_ts(),
            "detail": detail,
        });
        let s = serde_json::to_string(&line).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["event"], "phase");
        assert_eq!(parsed["phase"], "op_started");
        assert!(parsed["ts"].is_string());
        assert!(parsed["detail"].is_object());

        // Timestamp is RFC3339-shaped: 4-2-2 T 2:2:2 Z = 20 chars.
        let ts = parsed["ts"].as_str().unwrap();
        assert_eq!(ts.len(), 20, "ts must be 20-char RFC3339 UTC: {}", ts);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        // 1970-01-01 = 0 days since epoch
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2000-02-29 = 11_016 days since epoch (covers leap day handling)
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        // 2026-04-25 = 20_568 days since epoch
        assert_eq!(civil_from_days(20_568), (2026, 4, 25));
    }
}
