//! Minimal Tezos smart-rollup kernel scaffold for TzEL.
//!
//! This first cut is intentionally narrow:
//! - raw host-function bindings instead of the Tezos Rust SDK
//! - durable-state helpers that are easy to unit test on the host
//! - inbox-driven state transitions using the shared Rust `Ledger`
//! - direct proof verification through the shared verifier crate

use tzel_core::{
    apply_fund, apply_shield, apply_transfer, apply_unshield, default_auth_domain,
    canonical_wire::{decode_published_note, encode_published_note},
    hash_merkle,
    kernel_wire::{
        decode_kernel_inbox_message, decode_kernel_result, decode_kernel_verifier_config,
        encode_kernel_result, encode_kernel_verifier_config, kernel_shield_req_to_host,
        kernel_transfer_req_to_host, kernel_unshield_req_to_host, KernelInboxMessage,
        KernelResult, KernelVerifierConfig,
    },
    EncryptedNote, F, Ledger, LedgerState, ZERO, DEPTH,
};
use tzel_verifier::DirectProofVerifier;

pub const MAX_INPUT_BYTES: usize = 16 * 1024;
pub const MAX_LEDGER_STATE_BYTES: usize = 4 * 1024 * 1024;

const PATH_RAW_INPUT_COUNT: &[u8] = b"/tzel/v1/stats/raw_input_count";
const PATH_RAW_INPUT_BYTES: &[u8] = b"/tzel/v1/stats/raw_input_bytes";
const PATH_LAST_INPUT_LEVEL: &[u8] = b"/tzel/v1/state/last_input_level";
const PATH_LAST_INPUT_ID: &[u8] = b"/tzel/v1/state/last_input_id";
const PATH_LAST_INPUT_LEN: &[u8] = b"/tzel/v1/state/last_input_len";
const PATH_LAST_INPUT_PAYLOAD: &[u8] = b"/tzel/v1/state/last_input_payload";
const PATH_AUTH_DOMAIN: &[u8] = b"/tzel/v1/state/auth_domain";
const PATH_TREE_SIZE: &[u8] = b"/tzel/v1/state/tree/size";
const PATH_TREE_ROOT: &[u8] = b"/tzel/v1/state/tree/root";
const PATH_NULLIFIER_COUNT: &[u8] = b"/tzel/v1/state/nullifiers/count";
const PATH_VALID_ROOT_COUNT: &[u8] = b"/tzel/v1/state/roots/count";
const PATH_BALANCE_ACCOUNT_COUNT: &[u8] = b"/tzel/v1/state/balances/count";
const PATH_VERIFIER_CONFIG: &[u8] = b"/tzel/v1/state/verifier_config.bin";
const PATH_LAST_RESULT: &[u8] = b"/tzel/v1/state/last_result.bin";
const PATH_TREE_BRANCH_PREFIX: &[u8] = b"/tzel/v1/state/tree/branch/";
const PATH_NOTE_PREFIX: &[u8] = b"/tzel/v1/state/notes/";
const PATH_NULLIFIER_PREFIX: &[u8] = b"/tzel/v1/state/nullifiers/by-key/";
const PATH_NULLIFIER_INDEX_PREFIX: &[u8] = b"/tzel/v1/state/nullifiers/index/";
const PATH_VALID_ROOT_PREFIX: &[u8] = b"/tzel/v1/state/roots/by-key/";
const PATH_VALID_ROOT_INDEX_PREFIX: &[u8] = b"/tzel/v1/state/roots/index/";
const PATH_BALANCE_PREFIX: &[u8] = b"/tzel/v1/state/balances/by-key/";
const PATH_BALANCE_INDEX_PREFIX: &[u8] = b"/tzel/v1/state/balances/index/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputMessage {
    pub level: i32,
    pub id: i32,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelStats {
    pub raw_input_count: u64,
    pub raw_input_bytes: u64,
    pub last_input_level: Option<i32>,
    pub last_input_id: Option<i32>,
    pub last_input_len: Option<u32>,
}

pub trait Host {
    fn next_input(&mut self) -> Option<InputMessage>;
    fn read_store(&self, path: &[u8], max_bytes: usize) -> Option<Vec<u8>>;
    fn write_store(&mut self, path: &[u8], value: &[u8]);
    fn write_debug(&mut self, message: &str);
}

struct DurableLedgerState<'a, H: Host> {
    host: &'a mut H,
    zero_hashes: Vec<F>,
}

impl<'a, H: Host> DurableLedgerState<'a, H> {
    fn new(host: &'a mut H) -> Result<Self, String> {
        let mut zero_hashes = vec![ZERO];
        for i in 0..DEPTH {
            zero_hashes.push(hash_merkle(&zero_hashes[i], &zero_hashes[i]));
        }
        let mut state = Self { host, zero_hashes };
        state.ensure_initialized()?;
        Ok(state)
    }

    fn ensure_initialized(&mut self) -> Result<(), String> {
        if self.host.read_store(PATH_AUTH_DOMAIN, 32).is_none() {
            self.write_felt(PATH_AUTH_DOMAIN, &default_auth_domain());
        }
        if self.host.read_store(PATH_TREE_SIZE, 8).is_none() {
            self.write_u64(PATH_TREE_SIZE, 0);
        }
        if self.host.read_store(PATH_TREE_ROOT, 32).is_none() {
            let root = self.zero_hashes[DEPTH];
            self.write_felt(PATH_TREE_ROOT, &root);
        }
        if self.host.read_store(PATH_NULLIFIER_COUNT, 8).is_none() {
            self.write_u64(PATH_NULLIFIER_COUNT, 0);
        }
        if self.host.read_store(PATH_BALANCE_ACCOUNT_COUNT, 8).is_none() {
            self.write_u64(PATH_BALANCE_ACCOUNT_COUNT, 0);
        }
        if self.host.read_store(PATH_VALID_ROOT_COUNT, 8).is_none() {
            let root = self.read_felt(PATH_TREE_ROOT)?.unwrap_or(self.zero_hashes[DEPTH]);
            self.write_marker(&root_marker_path(&root));
            self.write_key_at_index(PATH_VALID_ROOT_INDEX_PREFIX, 0, &root);
            self.write_u64(PATH_VALID_ROOT_COUNT, 1);
        }
        Ok(())
    }

    fn is_pristine(&self) -> Result<bool, String> {
        Ok(self.read_u64(PATH_TREE_SIZE)?.unwrap_or(0) == 0
            && self.read_u64(PATH_NULLIFIER_COUNT)?.unwrap_or(0) == 0
            && self.read_u64(PATH_BALANCE_ACCOUNT_COUNT)?.unwrap_or(0) == 0)
    }

    fn read_u64(&self, path: &[u8]) -> Result<Option<u64>, String> {
        match self.host.read_store(path, 8) {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(format!("bad u64 at {}", String::from_utf8_lossy(path)));
                }
                Ok(Some(u64::from_le_bytes(bytes.try_into().unwrap())))
            }
        }
    }

    fn write_u64(&mut self, path: &[u8], value: u64) {
        self.host.write_store(path, &value.to_le_bytes());
    }

    fn read_felt(&self, path: &[u8]) -> Result<Option<F>, String> {
        match self.host.read_store(path, 32) {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(format!("bad felt at {}", String::from_utf8_lossy(path)));
                }
                let mut felt = ZERO;
                felt.copy_from_slice(&bytes);
                Ok(Some(felt))
            }
        }
    }

    fn write_felt(&mut self, path: &[u8], value: &F) {
        self.host.write_store(path, value);
    }

    fn write_marker(&mut self, path: &[u8]) {
        self.host.write_store(path, &[1]);
    }

    fn has_marker(&self, path: &[u8]) -> bool {
        self.host.read_store(path, 1).is_some()
    }

    fn write_key_at_index(&mut self, prefix: &[u8], index: u64, key: &F) {
        let path = indexed_path(prefix, index);
        self.host.write_store(&path, key);
    }

    fn write_account_key_at_index(&mut self, index: u64, addr: &str) {
        let path = indexed_path(PATH_BALANCE_INDEX_PREFIX, index);
        self.host.write_store(&path, addr.as_bytes());
    }
}

impl<H: Host> LedgerState for DurableLedgerState<'_, H> {
    fn auth_domain(&self) -> Result<F, String> {
        self.read_felt(PATH_AUTH_DOMAIN)?
            .ok_or_else(|| "missing auth_domain".into())
    }

    fn balance(&self, addr: &str) -> Result<u64, String> {
        Ok(self.read_u64(&balance_path(addr))?.unwrap_or(0))
    }

    fn set_balance(&mut self, addr: &str, amount: u64) -> Result<(), String> {
        let path = balance_path(addr);
        if self.host.read_store(&path, 8).is_none() {
            let index = self.read_u64(PATH_BALANCE_ACCOUNT_COUNT)?.unwrap_or(0);
            self.write_account_key_at_index(index, addr);
            self.write_u64(PATH_BALANCE_ACCOUNT_COUNT, index + 1);
        }
        self.write_u64(&path, amount);
        Ok(())
    }

    fn has_valid_root(&self, root: &F) -> Result<bool, String> {
        Ok(self.has_marker(&root_marker_path(root)))
    }

    fn has_nullifier(&self, nf: &F) -> Result<bool, String> {
        Ok(self.has_marker(&nullifier_path(nf)))
    }

    fn insert_nullifier(&mut self, nf: F) -> Result<(), String> {
        let path = nullifier_path(&nf);
        if !self.has_marker(&path) {
            let index = self.read_u64(PATH_NULLIFIER_COUNT)?.unwrap_or(0);
            self.write_marker(&path);
            self.write_key_at_index(PATH_NULLIFIER_INDEX_PREFIX, index, &nf);
            self.write_u64(PATH_NULLIFIER_COUNT, index + 1);
        }
        Ok(())
    }

    fn append_note(&mut self, cm: F, enc: EncryptedNote) -> Result<usize, String> {
        let count = self.read_u64(PATH_TREE_SIZE)?.unwrap_or(0);
        if count >= (1u64 << DEPTH) {
            return Err(format!("Merkle tree full: 2^{} leaves", DEPTH));
        }

        let encoded = encode_published_note(&cm, &enc)?;
        self.host.write_store(&note_path(count), &encoded);

        let mut current = cm;
        let mut index = count;
        for level in 0..DEPTH {
            if index & 1 == 0 {
                self.write_felt(&branch_path(level), &current);
                current = hash_merkle(&current, &self.zero_hashes[level]);
            } else {
                let left = self
                    .read_felt(&branch_path(level))?
                    .ok_or_else(|| format!("missing Merkle frontier at level {}", level))?;
                current = hash_merkle(&left, &current);
            }
            index >>= 1;
        }

        self.write_felt(PATH_TREE_ROOT, &current);
        self.write_u64(PATH_TREE_SIZE, count + 1);
        usize::try_from(count).map_err(|_| "note index does not fit in usize".into())
    }

    fn snapshot_root(&mut self) -> Result<(), String> {
        let root = self
            .read_felt(PATH_TREE_ROOT)?
            .ok_or_else(|| "missing tree root".to_string())?;
        let path = root_marker_path(&root);
        if !self.has_marker(&path) {
            let index = self.read_u64(PATH_VALID_ROOT_COUNT)?.unwrap_or(0);
            self.write_marker(&path);
            self.write_key_at_index(PATH_VALID_ROOT_INDEX_PREFIX, index, &root);
            self.write_u64(PATH_VALID_ROOT_COUNT, index + 1);
        }
        Ok(())
    }
}

fn indexed_path(prefix: &[u8], index: u64) -> Vec<u8> {
    let mut path = Vec::with_capacity(prefix.len() + 16);
    path.extend_from_slice(prefix);
    path.extend_from_slice(format!("{:016x}", index).as_bytes());
    path
}

fn note_path(index: u64) -> Vec<u8> {
    indexed_path(PATH_NOTE_PREFIX, index)
}

fn branch_path(level: usize) -> Vec<u8> {
    let mut path = Vec::with_capacity(PATH_TREE_BRANCH_PREFIX.len() + 2);
    path.extend_from_slice(PATH_TREE_BRANCH_PREFIX);
    path.extend_from_slice(format!("{:02x}", level).as_bytes());
    path
}

fn root_marker_path(root: &F) -> Vec<u8> {
    let mut path = Vec::with_capacity(PATH_VALID_ROOT_PREFIX.len() + 64);
    path.extend_from_slice(PATH_VALID_ROOT_PREFIX);
    path.extend_from_slice(hex::encode(root).as_bytes());
    path
}

fn nullifier_path(nf: &F) -> Vec<u8> {
    let mut path = Vec::with_capacity(PATH_NULLIFIER_PREFIX.len() + 64);
    path.extend_from_slice(PATH_NULLIFIER_PREFIX);
    path.extend_from_slice(hex::encode(nf).as_bytes());
    path
}

fn balance_path(addr: &str) -> Vec<u8> {
    let mut path = Vec::with_capacity(PATH_BALANCE_PREFIX.len() + addr.len() * 2);
    path.extend_from_slice(PATH_BALANCE_PREFIX);
    path.extend_from_slice(hex::encode(addr.as_bytes()).as_bytes());
    path
}

pub fn run_with_host<H: Host>(host: &mut H) {
    let mut saw_input = false;
    while let Some(input) = host.next_input() {
        saw_input = true;
        process_input(host, &input);
    }

    if !saw_input {
        host.write_debug("tzel-rollup-kernel: no inbox messages\n");
    }
}

pub fn read_stats<H: Host>(host: &H) -> KernelStats {
    KernelStats {
        raw_input_count: read_u64(host, PATH_RAW_INPUT_COUNT).unwrap_or(0),
        raw_input_bytes: read_u64(host, PATH_RAW_INPUT_BYTES).unwrap_or(0),
        last_input_level: read_i32(host, PATH_LAST_INPUT_LEVEL),
        last_input_id: read_i32(host, PATH_LAST_INPUT_ID),
        last_input_len: read_u32(host, PATH_LAST_INPUT_LEN),
    }
}

pub fn read_last_input<H: Host>(host: &H) -> Option<InputMessage> {
    let stats = read_stats(host);
    let len = usize::try_from(stats.last_input_len?).ok()?;
    let payload = host.read_store(PATH_LAST_INPUT_PAYLOAD, len)?;
    Some(InputMessage {
        level: stats.last_input_level?,
        id: stats.last_input_id?,
        payload,
    })
}

pub fn read_ledger<H: Host>(host: &H) -> Result<Ledger, String> {
    let auth_domain = match host.read_store(PATH_AUTH_DOMAIN, 32) {
        Some(bytes) => {
            if bytes.len() != 32 {
                return Err("bad persisted auth_domain".into());
            }
            let mut f = ZERO;
            f.copy_from_slice(&bytes);
            f
        }
        None => default_auth_domain(),
    };

    let tree_size = read_u64(host, PATH_TREE_SIZE).unwrap_or(0);
    let nullifier_count = read_u64(host, PATH_NULLIFIER_COUNT).unwrap_or(0);
    let valid_root_count = read_u64(host, PATH_VALID_ROOT_COUNT).unwrap_or(0);
    let balance_count = read_u64(host, PATH_BALANCE_ACCOUNT_COUNT).unwrap_or(0);

    let mut ledger = Ledger::with_auth_domain(auth_domain);
    ledger.tree.leaves.clear();
    ledger.nullifiers.clear();
    ledger.valid_roots.clear();
    ledger.balances.clear();
    ledger.memos.clear();

    for i in 0..tree_size {
        let (cm, enc) = decode_published_note(
            &host.read_store(&note_path(i), MAX_LEDGER_STATE_BYTES)
                .ok_or_else(|| format!("missing persisted note {}", i))?,
        )?;
        ledger.tree.leaves.push(cm);
        ledger.memos.push((cm, enc));
    }

    for i in 0..nullifier_count {
        let path = indexed_path(PATH_NULLIFIER_INDEX_PREFIX, i);
        let bytes = host
            .read_store(&path, 32)
            .ok_or_else(|| format!("missing persisted nullifier {}", i))?;
        if bytes.len() != 32 {
            return Err(format!("bad persisted nullifier {}", i));
        }
        let mut nf = ZERO;
        nf.copy_from_slice(&bytes);
        ledger.nullifiers.insert(nf);
    }

    for i in 0..valid_root_count {
        let path = indexed_path(PATH_VALID_ROOT_INDEX_PREFIX, i);
        let bytes = host
            .read_store(&path, 32)
            .ok_or_else(|| format!("missing persisted root {}", i))?;
        if bytes.len() != 32 {
            return Err(format!("bad persisted root {}", i));
        }
        let mut root = ZERO;
        root.copy_from_slice(&bytes);
        ledger.valid_roots.insert(root);
    }

    for i in 0..balance_count {
        let key_path = indexed_path(PATH_BALANCE_INDEX_PREFIX, i);
        let key_bytes = host
            .read_store(&key_path, MAX_INPUT_BYTES)
            .ok_or_else(|| format!("missing persisted balance key {}", i))?;
        let addr =
            String::from_utf8(key_bytes).map_err(|_| "stored balance key is not UTF-8".to_string())?;
        let amount = read_u64(host, &balance_path(&addr)).unwrap_or(0);
        ledger.balances.insert(addr, amount);
    }

    Ok(ledger)
}

pub fn read_verifier_config<H: Host>(host: &H) -> Result<Option<KernelVerifierConfig>, String> {
    let Some(bytes) = host.read_store(PATH_VERIFIER_CONFIG, MAX_INPUT_BYTES) else {
        return Ok(None);
    };
    decode_kernel_verifier_config(&bytes).map(Some)
}

pub fn read_last_result<H: Host>(host: &H) -> Option<KernelResult> {
    let bytes = host.read_store(PATH_LAST_RESULT, MAX_INPUT_BYTES)?;
    decode_kernel_result(&bytes).ok()
}

fn process_input<H: Host>(host: &mut H, input: &InputMessage) {
    increment_u64(host, PATH_RAW_INPUT_COUNT, 1);
    increment_u64(host, PATH_RAW_INPUT_BYTES, input.payload.len() as u64);
    host.write_store(PATH_LAST_INPUT_LEVEL, &input.level.to_le_bytes());
    host.write_store(PATH_LAST_INPUT_ID, &input.id.to_le_bytes());
    host.write_store(
        PATH_LAST_INPUT_LEN,
        &u32::try_from(input.payload.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    host.write_store(PATH_LAST_INPUT_PAYLOAD, &input.payload);

    host.write_debug(&format!(
        "tzel-rollup-kernel: inbox level={} id={} bytes={}\n",
        input.level,
        input.id,
        input.payload.len()
    ));

    let result = apply_input_message(host, input);
    match encode_kernel_result(&result) {
        Ok(encoded) => host.write_store(PATH_LAST_RESULT, &encoded),
        Err(e) => host.write_debug(&format!(
            "tzel-rollup-kernel: failed to encode result: {}\n",
            e
        )),
    }
}

fn apply_input_message<H: Host>(host: &mut H, input: &InputMessage) -> KernelResult {
    let message = match decode_kernel_inbox_message(&input.payload) {
        Ok(message) => message,
        Err(e) => {
            let msg = format!("invalid inbox message: {}", e);
            host.write_debug(&format!("tzel-rollup-kernel: {}\n", msg));
            return KernelResult::Error { message: msg };
        }
    };

    let mut ledger = match DurableLedgerState::new(host) {
        Ok(ledger) => ledger,
        Err(e) => {
            ledger_debug(host, &e);
            return KernelResult::Error { message: e };
        }
    };

    let result: Result<KernelResult, String> = match message {
        KernelInboxMessage::ConfigureVerifier(config) => configure_verifier(&mut ledger, &config)
            .map(|_| KernelResult::Configured),
        KernelInboxMessage::Fund(req) => apply_fund(&mut ledger, &req.addr, req.amount).map(|_| KernelResult::Fund),
        KernelInboxMessage::Shield(req) => (|| -> Result<KernelResult, String> {
            validate_transition_proof(ledger.host, &req.proof, tzel_core::CircuitKind::Shield)?;
            let req = host_shield_req_for_transition(&req);
            apply_shield(&mut ledger, &req).map(KernelResult::Shield)
        })(),
        KernelInboxMessage::Transfer(req) => (|| -> Result<KernelResult, String> {
            validate_transition_proof(ledger.host, &req.proof, tzel_core::CircuitKind::Transfer)?;
            let req = host_transfer_req_for_transition(&req);
            apply_transfer(&mut ledger, &req).map(KernelResult::Transfer)
        })(),
        KernelInboxMessage::Unshield(req) => (|| -> Result<KernelResult, String> {
            validate_transition_proof(ledger.host, &req.proof, tzel_core::CircuitKind::Unshield)?;
            let req = host_unshield_req_for_transition(&req);
            apply_unshield(&mut ledger, &req).map(KernelResult::Unshield)
        })(),
    };

    match result {
        Ok(success) => success,
        Err(message) => {
            ledger_debug(host, &format!("transition failed: {}", message));
            KernelResult::Error { message }
        }
    }
}

fn load_verifier<H: Host>(host: &H) -> Result<DirectProofVerifier, String> {
    let config = read_verifier_config(host)?
        .ok_or_else(|| "proof verifier is not configured".to_string())?;
    DirectProofVerifier::from_kernel_config(&config)
}

#[cfg(not(test))]
fn host_shield_req_for_transition(
    req: &tzel_core::kernel_wire::KernelShieldReq,
) -> tzel_core::ShieldReq {
    kernel_shield_req_to_host(req)
}

#[cfg(test)]
fn host_shield_req_for_transition(
    req: &tzel_core::kernel_wire::KernelShieldReq,
) -> tzel_core::ShieldReq {
    let mut host_req = kernel_shield_req_to_host(req);
    if req.proof.proof_bytes == b"kernel-test-skip-verify" {
        host_req.proof = tzel_core::Proof::TrustMeBro;
    }
    host_req
}

#[cfg(not(test))]
fn host_transfer_req_for_transition(
    req: &tzel_core::kernel_wire::KernelTransferReq,
) -> tzel_core::TransferReq {
    kernel_transfer_req_to_host(req)
}

#[cfg(test)]
fn host_transfer_req_for_transition(
    req: &tzel_core::kernel_wire::KernelTransferReq,
) -> tzel_core::TransferReq {
    let mut host_req = kernel_transfer_req_to_host(req);
    if req.proof.proof_bytes == b"kernel-test-skip-verify" {
        host_req.proof = tzel_core::Proof::TrustMeBro;
    }
    host_req
}

#[cfg(not(test))]
fn host_unshield_req_for_transition(
    req: &tzel_core::kernel_wire::KernelUnshieldReq,
) -> tzel_core::UnshieldReq {
    kernel_unshield_req_to_host(req)
}

#[cfg(test)]
fn host_unshield_req_for_transition(
    req: &tzel_core::kernel_wire::KernelUnshieldReq,
) -> tzel_core::UnshieldReq {
    let mut host_req = kernel_unshield_req_to_host(req);
    if req.proof.proof_bytes == b"kernel-test-skip-verify" {
        host_req.proof = tzel_core::Proof::TrustMeBro;
    }
    host_req
}

#[cfg(not(test))]
fn validate_transition_proof<H: Host>(
    host: &H,
    proof: &tzel_core::kernel_wire::KernelStarkProof,
    circuit: tzel_core::CircuitKind,
) -> Result<(), String> {
    let verifier = load_verifier(host)?;
    verifier.validate_kernel(proof, circuit)
}

#[cfg(test)]
fn validate_transition_proof<H: Host>(
    host: &H,
    proof: &tzel_core::kernel_wire::KernelStarkProof,
    circuit: tzel_core::CircuitKind,
) -> Result<(), String> {
    if proof.proof_bytes == b"kernel-test-skip-verify" {
        return Ok(());
    }
    let verifier = load_verifier(host)?;
    verifier.validate_kernel(proof, circuit)
}

fn configure_verifier<H: Host>(
    ledger: &mut DurableLedgerState<'_, H>,
    config: &KernelVerifierConfig,
) -> Result<(), String> {
    DirectProofVerifier::from_kernel_config(config)?;

    if !ledger.is_pristine()? && ledger.auth_domain()? != config.auth_domain {
        return Err("cannot change auth_domain after ledger state exists".into());
    }

    ledger.write_felt(PATH_AUTH_DOMAIN, &config.auth_domain);
    let encoded = encode_kernel_verifier_config(config)?;
    ledger.host.write_store(PATH_VERIFIER_CONFIG, &encoded);
    Ok(())
}

fn ledger_debug<H: Host>(host: &mut H, message: &str) {
    host.write_debug(&format!("tzel-rollup-kernel: {}\n", message));
}

fn increment_u64<H: Host>(host: &mut H, path: &[u8], delta: u64) {
    let next = read_u64(host, path).unwrap_or(0).saturating_add(delta);
    host.write_store(path, &next.to_le_bytes());
}

fn read_u64<H: Host>(host: &H, path: &[u8]) -> Option<u64> {
    let bytes = host.read_store(path, 8)?;
    if bytes.len() != 8 {
        return None;
    }
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u32<H: Host>(host: &H, path: &[u8]) -> Option<u32> {
    let bytes = host.read_store(path, 4)?;
    if bytes.len() != 4 {
        return None;
    }
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_i32<H: Host>(host: &H, path: &[u8]) -> Option<i32> {
    let bytes = host.read_store(path, 4)?;
    if bytes.len() != 4 {
        return None;
    }
    Some(i32::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(target_arch = "wasm32")]
mod wasm_host {
    use super::{run_with_host, Host, InputMessage, MAX_INPUT_BYTES};

    #[repr(C)]
    struct ReadInputMessageInfo {
        level: i32,
        id: i32,
    }

    #[link(wasm_import_module = "smart_rollup_core")]
    extern "C" {
        fn read_input(
            message_info: *mut ReadInputMessageInfo,
            dst: *mut u8,
            max_bytes: usize,
        ) -> i32;
        fn write_debug(src: *const u8, num_bytes: usize);
        fn store_read(
            path: *const u8,
            path_len: usize,
            offset: usize,
            dst: *mut u8,
            num_bytes: usize,
        ) -> i32;
        fn store_write(
            path: *const u8,
            path_len: usize,
            offset: usize,
            src: *const u8,
            num_bytes: usize,
        ) -> i32;
    }

    pub struct WasmHost;

    impl Host for WasmHost {
        fn next_input(&mut self) -> Option<InputMessage> {
            let mut info = ReadInputMessageInfo { level: 0, id: 0 };
            let mut buffer = vec![0u8; MAX_INPUT_BYTES];
            let written =
                unsafe { read_input(&mut info as *mut _, buffer.as_mut_ptr(), buffer.len()) };
            if written <= 0 {
                return None;
            }

            let len = usize::try_from(written).ok()?;
            buffer.truncate(len);
            Some(InputMessage {
                level: info.level,
                id: info.id,
                payload: buffer,
            })
        }

        fn read_store(&self, path: &[u8], max_bytes: usize) -> Option<Vec<u8>> {
            let mut buffer = vec![0u8; max_bytes];
            let read = unsafe {
                store_read(
                    path.as_ptr(),
                    path.len(),
                    0,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            };
            if read < 0 {
                return None;
            }
            let len = usize::try_from(read).ok()?;
            buffer.truncate(len);
            Some(buffer)
        }

        fn write_store(&mut self, path: &[u8], value: &[u8]) {
            let rc =
                unsafe { store_write(path.as_ptr(), path.len(), 0, value.as_ptr(), value.len()) };
            if rc < 0 {
                self.write_debug("tzel-rollup-kernel: store_write failed\n");
            }
        }

        fn write_debug(&mut self, message: &str) {
            unsafe { write_debug(message.as_ptr(), message.len()) }
        }
    }

    #[no_mangle]
    pub extern "C" fn kernel_run() {
        let mut host = WasmHost;
        run_with_host(&mut host);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::{ml_kem_768, KeyExport};
    use std::collections::{HashMap, VecDeque};
    use tzel_core::{
        build_auth_tree, default_auth_domain, derive_account, derive_address, derive_ask,
        derive_kem_keys, derive_nk_spend, derive_nk_tag, encrypt_note_deterministic,
        kernel_wire::{
            encode_kernel_inbox_message, KernelInboxMessage, KernelShieldReq, KernelStarkProof,
            KernelTransferReq, KernelUnshieldReq, KernelVerifierConfig,
        },
        commit, derive_rcm, owner_tag, FundReq, PaymentAddress, ProgramHashes,
        ShieldResp, TransferResp, UnshieldResp, ZERO,
    };

    #[derive(Default)]
    struct MockHost {
        inputs: VecDeque<InputMessage>,
        store: HashMap<Vec<u8>, Vec<u8>>,
        debug: String,
    }

    impl MockHost {
        fn with_inputs(inputs: Vec<InputMessage>) -> Self {
            Self {
                inputs: inputs.into(),
                ..Self::default()
            }
        }
    }

    impl Host for MockHost {
        fn next_input(&mut self) -> Option<InputMessage> {
            self.inputs.pop_front()
        }

        fn read_store(&self, path: &[u8], max_bytes: usize) -> Option<Vec<u8>> {
            let value = self.store.get(path)?;
            Some(value[..value.len().min(max_bytes)].to_vec())
        }

        fn write_store(&mut self, path: &[u8], value: &[u8]) {
            self.store.insert(path.to_vec(), value.to_vec());
        }

        fn write_debug(&mut self, message: &str) {
            self.debug.push_str(message);
        }
    }

    #[test]
    fn tracks_raw_inbox_stats_and_last_input() {
        let mut host = MockHost::with_inputs(vec![
            InputMessage {
                level: 100,
                id: 0,
                payload: b"alpha".to_vec(),
            },
            InputMessage {
                level: 101,
                id: 3,
                payload: b"beta!".to_vec(),
            },
        ]);

        run_with_host(&mut host);

        let stats = read_stats(&host);
        assert_eq!(stats.raw_input_count, 2);
        assert_eq!(stats.raw_input_bytes, 10);
        assert_eq!(stats.last_input_level, Some(101));
        assert_eq!(stats.last_input_id, Some(3));
        assert_eq!(stats.last_input_len, Some(5));
        assert_eq!(
            read_last_input(&host),
            Some(InputMessage {
                level: 101,
                id: 3,
                payload: b"beta!".to_vec(),
            })
        );
        assert!(host.debug.contains("level=100"));
        assert!(host.debug.contains("level=101"));
    }

    #[test]
    fn resumes_from_existing_durable_state() {
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 7,
            id: 2,
            payload: vec![1, 2, 3, 4],
        }]);
        host.store
            .insert(PATH_RAW_INPUT_COUNT.to_vec(), 9u64.to_le_bytes().to_vec());
        host.store
            .insert(PATH_RAW_INPUT_BYTES.to_vec(), 20u64.to_le_bytes().to_vec());

        run_with_host(&mut host);

        let stats = read_stats(&host);
        assert_eq!(stats.raw_input_count, 10);
        assert_eq!(stats.raw_input_bytes, 24);
        assert_eq!(read_last_input(&host).unwrap().payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn logs_when_inbox_is_empty() {
        let mut host = MockHost::default();

        run_with_host(&mut host);

        let stats = read_stats(&host);
        assert_eq!(stats.raw_input_count, 0);
        assert_eq!(stats.raw_input_bytes, 0);
        assert!(host.debug.contains("no inbox messages"));
    }

    #[test]
    fn applies_fund_message_to_shared_ledger_state() {
        let message = encode_kernel_inbox_message(&KernelInboxMessage::Fund(FundReq {
            addr: "alice".into(),
            amount: 75,
        }))
        .unwrap();
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 1,
            id: 0,
            payload: message,
        }]);

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.auth_domain, default_auth_domain());
        assert_eq!(ledger.balances.get("alice"), Some(&75));
        match read_last_result(&host).unwrap() {
            KernelResult::Fund => {}
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn applies_shield_message_with_shared_ledger_logic() {
        let mut host = MockHost::default();
        {
            let mut state = DurableLedgerState::new(&mut host).unwrap();
            apply_fund(&mut state, "alice", 50).unwrap();
        }

        let config = KernelVerifierConfig {
            auth_domain: default_auth_domain(),
            verified_program_hashes: sample_program_hashes(),
        };
        host.write_store(
            PATH_VERIFIER_CONFIG,
            &encode_kernel_verifier_config(&config).unwrap(),
        );

        let address = sample_payment_address();
        let shield_req = KernelShieldReq {
            sender: "alice".into(),
            v: 50,
            address,
            memo: None,
            proof: sample_kernel_test_proof(),
            client_cm: ZERO,
            client_enc: None,
        };
        let message = encode_kernel_inbox_message(&KernelInboxMessage::Shield(shield_req)).unwrap();
        host.inputs.push_back(InputMessage {
            level: 2,
            id: 1,
            payload: message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.balances.get("alice"), Some(&0));
        assert_eq!(ledger.tree.leaves.len(), 1);
        match read_last_result(&host).unwrap() {
            KernelResult::Shield(ShieldResp { index, .. }) => assert_eq!(index, 0),
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn applies_transfer_message_with_frontier_and_marker_storage() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);

        let address = sample_payment_address();
        let enc_1 = sample_encrypted_note(&address, 11, [0x11; 32], b"one");
        let enc_2 = sample_encrypted_note(&address, 12, [0x12; 32], b"two");
        let cm_1 = sample_commitment(&address, 11, [0x11; 32]);
        let cm_2 = sample_commitment(&address, 12, [0x12; 32]);
        let nf = sample_felt(0x91);
        let root = read_ledger(&host).unwrap().tree.root();

        let req = KernelTransferReq {
            root,
            nullifiers: vec![nf],
            cm_1,
            cm_2,
            enc_1: enc_1.clone(),
            enc_2: enc_2.clone(),
            proof: sample_kernel_test_proof(),
        };
        let message = encode_kernel_inbox_message(&KernelInboxMessage::Transfer(req)).unwrap();
        host.inputs.push_back(InputMessage {
            level: 5,
            id: 0,
            payload: message,
        });

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Transfer(TransferResp { index_1, index_2 }) => {
                assert_eq!((index_1, index_2), (0, 1))
            }
            KernelResult::Error { message } => {
                panic!("transfer failed: {} | debug: {}", message, host.debug)
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.tree.leaves, vec![cm_1, cm_2]);
        assert!(ledger.nullifiers.contains(&nf));
        assert!(host.store.contains_key(&note_path(0)));
        assert!(host.store.contains_key(&note_path(1)));
        assert!(host.store.contains_key(&nullifier_path(&nf)));
        assert!(host.store.contains_key(&branch_path(0)));
        assert!(host.store.contains_key(&PATH_TREE_ROOT.to_vec()));
        assert!(!host.store.contains_key(b"/tzel/v1/state/ledger.json".as_slice()));
    }

    #[test]
    fn applies_unshield_message_with_change_and_balance_update() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);

        let address = sample_payment_address();
        let enc_change = sample_encrypted_note(&address, 7, [0x21; 32], b"change");
        let cm_change = sample_commitment(&address, 7, [0x21; 32]);
        let nf = sample_felt(0xA2);
        let root = read_ledger(&host).unwrap().tree.root();

        let req = KernelUnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 33,
            recipient: "bob".into(),
            cm_change,
            enc_change: Some(enc_change.clone()),
            proof: sample_kernel_test_proof(),
        };
        let message = encode_kernel_inbox_message(&KernelInboxMessage::Unshield(req)).unwrap();
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 1,
            payload: message,
        });

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Unshield(UnshieldResp { change_index }) => {
                assert_eq!(change_index, Some(0))
            }
            KernelResult::Error { message } => {
                panic!("unshield failed: {} | debug: {}", message, host.debug)
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.balances.get("bob"), Some(&33));
        assert_eq!(ledger.tree.leaves, vec![cm_change]);
        assert!(ledger.nullifiers.contains(&nf));
        assert!(host.store.contains_key(&balance_path("bob")));
        assert!(host.store.contains_key(&nullifier_path(&nf)));
        assert!(host.store.contains_key(&note_path(0)));
    }

    #[test]
    fn rejects_auth_domain_reconfiguration_after_state_exists() {
        let mut host = MockHost::default();
        {
            let mut state = DurableLedgerState::new(&mut host).unwrap();
            apply_fund(&mut state, "alice", 1).unwrap();
        }

        let new_domain = sample_felt(0x44);
        let config = KernelVerifierConfig {
            auth_domain: new_domain,
            verified_program_hashes: sample_program_hashes(),
        };
        let message =
            encode_kernel_inbox_message(&KernelInboxMessage::ConfigureVerifier(config)).unwrap();
        host.inputs.push_back(InputMessage {
            level: 7,
            id: 2,
            payload: message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_ne!(ledger.auth_domain, new_domain);
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("cannot change auth_domain"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_missing_verifier_configuration_for_proof_messages() {
        let shield_req = KernelShieldReq {
            sender: "alice".into(),
            v: 50,
            address: sample_payment_address(),
            memo: None,
            proof: sample_verified_kernel_proof(),
            client_cm: ZERO,
            client_enc: None,
        };
        let message = encode_kernel_inbox_message(&KernelInboxMessage::Shield(shield_req)).unwrap();
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 3,
            id: 2,
            payload: message,
        }]);

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.tree.leaves.is_empty());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("proof verifier is not configured"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn records_error_for_invalid_wire_message_without_mutating_ledger() {
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 4,
            id: 7,
            payload: vec![0xFF, 0x00, 0x01],
        }]);

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.balances.is_empty());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("invalid inbox message"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_invalid_stark_proof_shape_before_transition() {
        let config = KernelVerifierConfig {
            auth_domain: default_auth_domain(),
            verified_program_hashes: sample_program_hashes(),
        };
        let verifier = DirectProofVerifier::from_kernel_config(&config).unwrap();

        let proof = KernelStarkProof {
            proof_bytes: vec![0x00, 0x11, 0x22],
            output_preimage: vec![[9u8; 32], [10u8; 32]],
            verify_meta: serde_json::json!({"proof_config": {"foo": 1}}),
        };

        let err = verifier
            .validate_kernel(&proof, tzel_core::CircuitKind::Transfer)
            .unwrap_err();
        assert!(
            err.contains("invalid verify_meta") || err.contains("proof bundle missing verify_meta"),
            "unexpected verifier error: {}",
            err
        );
    }

    fn sample_payment_address() -> PaymentAddress {
        let mut master_sk = [0u8; 32];
        master_sk[0] = 7;
        let account = derive_account(&master_sk);
        let d_j = derive_address(&account.incoming_seed, 0);
        let ask_j = derive_ask(&account.ask_base, 0);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_spend = derive_nk_spend(&account.nk, &d_j);
        let nk_tag = derive_nk_tag(&nk_spend);
        let (ek_v, _, ek_d, _) = derive_kem_keys(&account.incoming_seed, 0);
        PaymentAddress {
            d_j,
            auth_root,
            nk_tag,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        }
    }

    fn install_test_verifier(host: &mut MockHost) {
        let config = KernelVerifierConfig {
            auth_domain: default_auth_domain(),
            verified_program_hashes: sample_program_hashes(),
        };
        host.write_store(
            PATH_VERIFIER_CONFIG,
            &encode_kernel_verifier_config(&config).unwrap(),
        );
    }

    fn sample_program_hashes() -> ProgramHashes {
        ProgramHashes {
            shield: [1u8; 32],
            transfer: [2u8; 32],
            unshield: [3u8; 32],
        }
    }

    fn sample_kernel_test_proof() -> KernelStarkProof {
        KernelStarkProof {
            proof_bytes: b"kernel-test-skip-verify".to_vec(),
            output_preimage: vec![],
            verify_meta: serde_json::Value::Null,
        }
    }

    fn sample_verified_kernel_proof() -> KernelStarkProof {
        KernelStarkProof {
            proof_bytes: vec![0x00, 0x11, 0x22],
            output_preimage: vec![[9u8; 32], [10u8; 32]],
            verify_meta: serde_json::json!({"proof_config": {"foo": 1}}),
        }
    }

    fn sample_felt(fill: u8) -> F {
        let mut out = [fill; 32];
        out[31] &= 0x07;
        out
    }

    fn sample_encrypted_note(
        address: &PaymentAddress,
        value: u64,
        rseed: F,
        memo: &[u8],
    ) -> EncryptedNote {
        let ek_v = ml_kem_768::EncapsulationKey::new(
            address.ek_v.as_slice().try_into().expect("ek_v size"),
        )
        .expect("valid ek_v");
        let ek_d = ml_kem_768::EncapsulationKey::new(
            address.ek_d.as_slice().try_into().expect("ek_d size"),
        )
        .expect("valid ek_d");
        encrypt_note_deterministic(
            value,
            &rseed,
            Some(memo),
            &ek_v,
            &ek_d,
            &[0x55; 32],
            &[0x66; 32],
        )
    }

    fn sample_commitment(address: &PaymentAddress, value: u64, rseed: F) -> F {
        commit(
            &address.d_j,
            value,
            &derive_rcm(&rseed),
            &owner_tag(&address.auth_root, &address.nk_tag),
        )
    }
}
