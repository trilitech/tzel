//! Minimal Tezos smart-rollup kernel scaffold for TzEL.
//!
//! This first cut is intentionally narrow:
//! - raw host-function bindings instead of the Tezos Rust SDK
//! - durable-state helpers that are easy to unit test on the host
//! - inbox-driven state transitions using the shared Rust `Ledger`
//! - direct proof verification through the shared verifier crate

#[cfg(target_arch = "wasm32")]
fn tzel_kernel_getrandom_unsupported(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(tzel_kernel_getrandom_unsupported);

use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{
    contract::Contract as TezosContract,
    entrypoint::Entrypoint as TezosEntrypoint,
    inbox::{
        ExternalMessageFrame, InboxMessage as TezosInboxMessage,
        InternalInboxMessage as TezosInternalInboxMessage,
    },
    michelson::{
        ticket::FA2_1Ticket, MichelsonBytes, MichelsonContract, MichelsonInt, MichelsonOption,
        MichelsonPair,
    },
    outbox::{OutboxMessage as TezosOutboxMessage, OutboxMessageTransaction},
};
use tzel_core::{
    apply_deposit, apply_transfer,
    canonical_wire::{decode_published_note, encode_published_note},
    default_auth_domain, hash, hash_merkle,
    kernel_wire::{
        decode_kernel_inbox_message, decode_kernel_result, decode_kernel_verifier_config,
        encode_kernel_result, encode_kernel_verifier_config, kernel_bridge_config_sighash,
        kernel_shield_req_to_host, kernel_transfer_req_to_host, kernel_unshield_req_to_host,
        kernel_verifier_config_sighash, KernelBridgeConfig, KernelDalPayloadKind,
        KernelDalPayloadPointer, KernelInboxMessage, KernelResult, KernelSignedBridgeConfig,
        KernelSignedVerifierConfig, KernelVerifierConfig, KERNEL_BRIDGE_CONFIG_KEY_INDEX,
        KERNEL_VERIFIER_CONFIG_KEY_INDEX,
    },
    prepare_shield, prepare_unshield, required_tx_fee_for_private_tx_count,
    verify_wots_signature_against_leaf, EncryptedNote, Ledger, LedgerState,
    ShieldResp, UnshieldResp, WithdrawalRecord, DEPTH, F, ZERO,
};
#[cfg(any(test, debug_assertions))]
use tzel_core::{auth_leaf_hash, derive_auth_pub_seed};
#[cfg(feature = "proof-verifier")]
use tzel_verifier::DirectProofVerifier;

pub const MAX_INPUT_BYTES: usize = 16 * 1024;
pub const MAX_LEDGER_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESULT_ERROR_MESSAGE_BYTES: usize = 4096;
const MAX_DAL_PAYLOAD_BYTES: usize = 512 * 1024;

#[cfg(not(feature = "proof-verifier"))]
#[derive(Debug, Clone)]
struct DirectProofVerifier;

#[cfg(not(feature = "proof-verifier"))]
impl DirectProofVerifier {
    fn from_kernel_config(_config: &KernelVerifierConfig) -> Result<Self, String> {
        Err("kernel built without proof verifier support".into())
    }

    fn validate_kernel(
        &self,
        _proof: &tzel_core::kernel_wire::KernelStarkProof,
        _circuit: tzel_core::CircuitKind,
    ) -> Result<(), String> {
        Err("kernel built without proof verifier support".into())
    }
}

const PATH_RAW_INPUT_COUNT: &[u8] = b"/tzel/v1/stats/raw_input_count";
const PATH_RAW_INPUT_BYTES: &[u8] = b"/tzel/v1/stats/raw_input_bytes";
const PATH_LAST_INPUT_LEVEL: &[u8] = b"/tzel/v1/state/last_input_level";
const PATH_LAST_INPUT_ID: &[u8] = b"/tzel/v1/state/last_input_id";
const PATH_LAST_INPUT_LEN: &[u8] = b"/tzel/v1/state/last_input_len";
const PATH_LAST_INPUT_PAYLOAD: &[u8] = b"/tzel/v1/state/last_input_payload";
const PATH_PRIVATE_TX_FEE_LEVEL: &[u8] = b"/tzel/v1/state/fees/private_tx_level";
const PATH_PRIVATE_TX_COUNT_IN_LEVEL: &[u8] = b"/tzel/v1/state/fees/private_tx_count_in_level";
const PATH_AUTH_DOMAIN: &[u8] = b"/tzel/v1/state/auth_domain";
const PATH_TREE_SIZE: &[u8] = b"/tzel/v1/state/tree/size";
const PATH_TREE_ROOT: &[u8] = b"/tzel/v1/state/tree/root";
const PATH_NULLIFIER_COUNT: &[u8] = b"/tzel/v1/state/nullifiers/count";
const PATH_VALID_ROOT_COUNT: &[u8] = b"/tzel/v1/state/roots/count";
const PATH_WITHDRAWAL_COUNT: &[u8] = b"/tzel/v1/state/withdrawals/count";
const PATH_BRIDGE_TICKETER: &[u8] = b"/tzel/v1/state/bridge/ticketer";
const PATH_VERIFIER_CONFIG: &[u8] = b"/tzel/v1/state/verifier_config.bin";
const PATH_LAST_RESULT: &[u8] = b"/tzel/v1/state/last_result.bin";
const PATH_TREE_BRANCH_PREFIX: &[u8] = b"/tzel/v1/state/tree/branch/";
const PATH_NOTE_PREFIX: &[u8] = b"/tzel/v1/state/notes/";
const PATH_NOTE_LEN_SUFFIX: &[u8] = b"/len";
const PATH_NOTE_CHUNK_PREFIX: &[u8] = b"/chunk/";
const PATH_NULLIFIER_PREFIX: &[u8] = b"/tzel/v1/state/nullifiers/by-key/";
const PATH_NULLIFIER_INDEX_PREFIX: &[u8] = b"/tzel/v1/state/nullifiers/index/";
const PATH_VALID_ROOT_PREFIX: &[u8] = b"/tzel/v1/state/roots/by-key/";
const PATH_VALID_ROOT_INDEX_PREFIX: &[u8] = b"/tzel/v1/state/roots/index/";
const PATH_WITHDRAWAL_PREFIX: &[u8] = b"/tzel/v1/state/withdrawals/index/";
/// Per-pool deposit balance keyed by `deposit_pubkey_hash`. Each L1 ticket
/// addressed to `deposit:<hex(pubkey_hash)>` credits the pool (creating it
/// if absent); each shield debits it. Multiple deposits to the same
/// pubkey_hash aggregate. A pool whose balance reaches zero is removed from
/// storage to bound durable footprint.
const PATH_DEPOSIT_BALANCE_PREFIX: &[u8] = b"/tzel/v1/state/deposits/balance/";
/// Single-byte marker set by `apply_deposit` on the very first L1 ticket.
/// Never cleared; used by `is_pristine` to refuse verifier reconfigurations
/// once any deposit has been observed (the freeze rule).
const PATH_DEPOSIT_EVER_RECEIVED: &[u8] = b"/tzel/v1/state/deposits/ever_received";
/// Replay-protection set for shield commitments. Each successful shield
/// records `client_cm` here; a subsequent shield carrying the same
/// `client_cm` is rejected before any state mutation. Without this,
/// anyone could top up a drained pool and replay a victim's shield
/// proof — the kernel would mint a duplicate of the recipient's note
/// at a fresh tree position (independently spendable, since nullifiers
/// are per-position) at the dust-attacker's expense. Value at the path
/// is a single-byte marker.
const PATH_APPLIED_SHIELD_PREFIX: &[u8] = b"/tzel/v1/state/shields/applied_cm/";
const MAX_STORE_STRING_BYTES: usize = 256;
const MAX_STORE_BINARY_BYTES: usize = 1024;
const MAX_STORED_INPUT_PAYLOAD_BYTES: usize = 2048;
const MAX_NOTE_CHUNK_BYTES: usize = 1024;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DalParameters {
    pub number_of_slots: u64,
    pub attestation_lag: u64,
    pub slot_size: u64,
    pub page_size: u64,
}

type BridgeDepositTicket = FA2_1Ticket;
type BridgeDepositPayload = MichelsonPair<MichelsonBytes, BridgeDepositTicket>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedBridgeDeposit {
    ticketer: String,
    recipient: String,
    amount: u64,
}

#[derive(Clone, Debug)]
enum ParsedRollupMessage {
    Kernel(KernelInboxMessage),
    Deposit(ParsedBridgeDeposit),
    Ignore,
}

pub trait Host {
    fn next_input(&mut self) -> Option<InputMessage>;
    fn read_store(&self, path: &[u8], max_bytes: usize) -> Option<Vec<u8>>;
    fn write_store(&mut self, path: &[u8], value: &[u8]);
    fn write_output(&mut self, value: &[u8]) -> Result<(), String>;
    fn write_debug(&mut self, message: &str);
    fn rollup_address(&self) -> Vec<u8>;
    fn reveal_dal_parameters(&self) -> Result<DalParameters, String>;
    fn reveal_dal_page(
        &self,
        published_level: i32,
        slot_index: u8,
        page_index: u16,
        max_bytes: usize,
    ) -> Result<Vec<u8>, String>;
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
        if self.host.read_store(PATH_WITHDRAWAL_COUNT, 8).is_none() {
            self.write_u64(PATH_WITHDRAWAL_COUNT, 0);
        }
        if self.host.read_store(PATH_VALID_ROOT_COUNT, 8).is_none() {
            let root = self
                .read_felt(PATH_TREE_ROOT)?
                .unwrap_or(self.zero_hashes[DEPTH]);
            self.write_marker(&root_marker_path(&root));
            self.write_key_at_index(PATH_VALID_ROOT_INDEX_PREFIX, 0, &root);
            self.write_u64(PATH_VALID_ROOT_COUNT, 1);
        }
        Ok(())
    }

    fn is_pristine(&self) -> Result<bool, String> {
        Ok(self.read_u64(PATH_TREE_SIZE)?.unwrap_or(0) == 0
            && self.read_u64(PATH_NULLIFIER_COUNT)?.unwrap_or(0) == 0
            && self
                .host
                .read_store(PATH_DEPOSIT_EVER_RECEIVED, 1)
                .is_none())
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

    fn read_string(&self, path: &[u8], max_bytes: usize) -> Result<Option<String>, String> {
        match self
            .host
            .read_store(path, max_bytes.min(MAX_STORE_STRING_BYTES))
        {
            None => Ok(None),
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| format!("invalid UTF-8 at {}", String::from_utf8_lossy(path))),
        }
    }

    fn write_string(&mut self, path: &[u8], value: &str) {
        self.host.write_store(path, value.as_bytes());
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

    fn write_withdrawal_at_index(&mut self, index: u64, record: &WithdrawalRecord) {
        let path = indexed_path(PATH_WITHDRAWAL_PREFIX, index);
        self.host
            .write_store(&path, &encode_withdrawal_record(record));
    }

    fn current_private_tx_count_in_level(&self) -> Result<u64, String> {
        let Some(current_level) = read_i32(self.host, PATH_LAST_INPUT_LEVEL) else {
            return Ok(0);
        };
        let Some(stored_level) = read_i32(self.host, PATH_PRIVATE_TX_FEE_LEVEL) else {
            return Ok(0);
        };
        if stored_level != current_level {
            return Ok(0);
        }
        Ok(self.read_u64(PATH_PRIVATE_TX_COUNT_IN_LEVEL)?.unwrap_or(0))
    }
}

impl<H: Host> LedgerState for DurableLedgerState<'_, H> {
    fn auth_domain(&self) -> Result<F, String> {
        self.read_felt(PATH_AUTH_DOMAIN)?
            .ok_or_else(|| "missing auth_domain".into())
    }

    fn required_tx_fee(&self) -> Result<u64, String> {
        Ok(required_tx_fee_for_private_tx_count(
            self.current_private_tx_count_in_level()?,
        ))
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

    fn ensure_note_capacity(&self, additional: usize) -> Result<(), String> {
        let count = self.read_u64(PATH_TREE_SIZE)?.unwrap_or(0);
        let additional = u64::try_from(additional)
            .map_err(|_| "note capacity does not fit in u64".to_string())?;
        let limit = 1u64 << DEPTH;
        let next = count
            .checked_add(additional)
            .ok_or_else(|| "Merkle tree size overflow".to_string())?;
        if next > limit {
            return Err(format!("Merkle tree full: 2^{} leaves", DEPTH));
        }
        Ok(())
    }

    fn append_note(&mut self, cm: F, enc: EncryptedNote) -> Result<usize, String> {
        let count = self.read_u64(PATH_TREE_SIZE)?.unwrap_or(0);
        if count >= (1u64 << DEPTH) {
            return Err(format!("Merkle tree full: 2^{} leaves", DEPTH));
        }

        let encoded = encode_published_note(&cm, &enc)?;
        write_note_payload(self.host, count, &encoded);

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

    fn enqueue_withdrawal(&mut self, recipient: &str, amount: u64) -> Result<usize, String> {
        let index = self.read_u64(PATH_WITHDRAWAL_COUNT)?.unwrap_or(0);
        self.write_withdrawal_at_index(
            index,
            &WithdrawalRecord {
                recipient: recipient.to_string(),
                amount,
            },
        );
        self.write_u64(PATH_WITHDRAWAL_COUNT, index + 1);
        usize::try_from(index).map_err(|_| "withdrawal index does not fit in usize".into())
    }

    fn note_private_tx_applied(&mut self) {
        let Some(current_level) = read_i32(self.host, PATH_LAST_INPUT_LEVEL) else {
            return;
        };
        let next = self.current_private_tx_count_in_level().unwrap_or(0) + 1;
        self.host
            .write_store(PATH_PRIVATE_TX_FEE_LEVEL, &current_level.to_le_bytes());
        self.host
            .write_store(PATH_PRIVATE_TX_COUNT_IN_LEVEL, &next.to_le_bytes());
    }

    fn deposit_balance(&self, pubkey_hash: &F) -> Result<Option<u64>, String> {
        let path = deposit_balance_path(pubkey_hash);
        match self.host.read_store(&path, 8) {
            None => Ok(None),
            // Empty bytes = best-effort-deleted (pool was drained).
            Some(bytes) if bytes.is_empty() => Ok(None),
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(format!(
                        "bad u64 at {}",
                        String::from_utf8_lossy(&path)
                    ));
                }
                Ok(Some(u64::from_le_bytes(bytes.try_into().unwrap())))
            }
        }
    }

    fn credit_deposit(&mut self, pubkey_hash: &F, amount: u64) -> Result<(), String> {
        let path = deposit_balance_path(pubkey_hash);
        // Empty bytes indicate a previously fully-drained pool (the WASM
        // PVM has no native delete; `apply_durable_shield_commit` writes
        // an empty value as the closest analogue). Treat that the same
        // as "absent" so the pool can be redeposited; only complain if
        // the entry has a non-empty, non-u64 length, which would be
        // genuine durable-store corruption.
        let current = match self.host.read_store(&path, 8) {
            None => 0u64,
            Some(bytes) if bytes.is_empty() => 0u64,
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(format!(
                        "bad u64 at {}",
                        String::from_utf8_lossy(&path)
                    ));
                }
                u64::from_le_bytes(bytes.try_into().unwrap())
            }
        };
        let next = current
            .checked_add(amount)
            .ok_or_else(|| "deposit balance overflow".to_string())?;
        self.host.write_store(&path, &next.to_le_bytes());
        // First-deposit-ever marker (used by is_pristine for the freeze rule).
        if self
            .host
            .read_store(PATH_DEPOSIT_EVER_RECEIVED, 1)
            .is_none()
        {
            self.host.write_store(PATH_DEPOSIT_EVER_RECEIVED, &[1]);
        }
        Ok(())
    }

    fn debit_deposit(&mut self, pubkey_hash: &F, amount: u64) -> Result<(), String> {
        let path = deposit_balance_path(pubkey_hash);
        let raw = self.host.read_store(&path, 8).ok_or_else(|| {
            format!(
                "deposit pool {} does not exist",
                hex::encode(pubkey_hash)
            )
        })?;
        if raw.is_empty() {
            // Pool was previously drained (best-effort delete via empty
            // write). Treat as if the entry were absent.
            return Err(format!(
                "deposit pool {} does not exist",
                hex::encode(pubkey_hash)
            ));
        }
        if raw.len() != 8 {
            return Err(format!("bad u64 at {}", String::from_utf8_lossy(&path)));
        }
        let current = u64::from_le_bytes(raw.try_into().unwrap());
        if current < amount {
            return Err(format!(
                "deposit pool {} balance {} too small to debit {}",
                hex::encode(pubkey_hash),
                current,
                amount
            ));
        }
        let next = current - amount;
        if next == 0 {
            // Best-effort delete: WASM PVM does not expose a delete; writing
            // an empty value is the closest thing. Wallets reading this key
            // see an empty (non-u64-shaped) read, which they treat as None.
            // Production durable-store sweeps periodically reclaim such keys.
            self.host.write_store(&path, &[]);
        } else {
            self.host.write_store(&path, &next.to_le_bytes());
        }
        Ok(())
    }

    fn has_applied_shield(&self, client_cm: &F) -> Result<bool, String> {
        Ok(self.has_marker(&applied_shield_path(client_cm)))
    }

    fn mark_applied_shield(&mut self, client_cm: F) -> Result<(), String> {
        // Note: the kernel-side outbox-emitting shield path
        // (`apply_durable_shield_commit`) writes this marker directly so
        // the apply step stays infallible. This trait method is wired
        // for symmetry / tests that exercise the generic
        // `commit_prepared_shield`.
        self.write_marker(&applied_shield_path(&client_cm));
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

fn note_length_path(index: u64) -> Vec<u8> {
    let mut path = note_path(index);
    path.extend_from_slice(PATH_NOTE_LEN_SUFFIX);
    path
}

fn note_chunk_path(index: u64, chunk_index: usize) -> Vec<u8> {
    let mut path = note_path(index);
    path.extend_from_slice(PATH_NOTE_CHUNK_PREFIX);
    path.extend_from_slice(format!("{:08x}", chunk_index).as_bytes());
    path
}

fn write_note_payload<H: Host>(host: &mut H, index: u64, encoded: &[u8]) {
    if encoded.len() <= MAX_NOTE_CHUNK_BYTES {
        host.write_store(&note_path(index), encoded);
        return;
    }

    host.write_store(
        &note_length_path(index),
        &(encoded.len() as u64).to_le_bytes(),
    );
    for (chunk_index, chunk) in encoded.chunks(MAX_NOTE_CHUNK_BYTES).enumerate() {
        host.write_store(&note_chunk_path(index, chunk_index), chunk);
    }
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

/// Path for the per-pool deposit balance keyed by `pubkey_hash`. Encoded as
/// the prefix followed by the lowercase hex of the pubkey_hash; the value at
/// this path is a u64 little-endian. An empty value (zero-length read) is
/// treated as "pool fully drained, key unreachable" — consumers should
/// behave as if the key were absent.
pub fn deposit_balance_path(pubkey_hash: &F) -> Vec<u8> {
    let mut path = Vec::with_capacity(PATH_DEPOSIT_BALANCE_PREFIX.len() + 64);
    path.extend_from_slice(PATH_DEPOSIT_BALANCE_PREFIX);
    path.extend_from_slice(hex::encode(pubkey_hash).as_bytes());
    path
}

fn applied_shield_path(client_cm: &F) -> Vec<u8> {
    let mut path = Vec::with_capacity(PATH_APPLIED_SHIELD_PREFIX.len() + 64);
    path.extend_from_slice(PATH_APPLIED_SHIELD_PREFIX);
    path.extend_from_slice(hex::encode(client_cm).as_bytes());
    path
}


fn encode_withdrawal_record(record: &WithdrawalRecord) -> Vec<u8> {
    let recipient = record.recipient.as_bytes();
    let mut bytes = Vec::with_capacity(12 + recipient.len());
    bytes.extend_from_slice(&record.amount.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(recipient.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    bytes.extend_from_slice(recipient);
    bytes
}

fn decode_withdrawal_record(bytes: &[u8]) -> Result<WithdrawalRecord, String> {
    if bytes.len() < 12 {
        return Err("withdrawal record too short".into());
    }
    let amount = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let recipient_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if bytes.len() != 12 + recipient_len {
        return Err("withdrawal record length mismatch".into());
    }
    let recipient = String::from_utf8(bytes[12..].to_vec())
        .map_err(|_| "withdrawal recipient is not UTF-8".to_string())?;
    Ok(WithdrawalRecord { recipient, amount })
}

fn encode_withdrawal_outbox_message(
    ticketer: &str,
    record: &WithdrawalRecord,
) -> Result<Vec<u8>, String> {
    let ticketer = TezosContract::from_b58check(ticketer)
        .map_err(|_| "invalid bridge ticketer contract".to_string())?;
    let recipient = TezosContract::from_b58check(&record.recipient)
        .map_err(|_| "invalid withdrawal recipient contract".to_string())?;
    let params = MichelsonPair(
        MichelsonContract(recipient),
        BridgeDepositTicket::new(
            ticketer.clone(),
            MichelsonPair(MichelsonInt::from(0i32), MichelsonOption(None)),
            record.amount,
        )
        .map_err(|e| format!("failed to build withdrawal ticket: {}", e))?,
    );
    let message = TezosOutboxMessage::AtomicTransactionBatch(
        vec![OutboxMessageTransaction {
            parameters: params,
            destination: ticketer,
            entrypoint: TezosEntrypoint::try_from("burn".to_string())
                .map_err(|_| "invalid burn entrypoint".to_string())?,
        }]
        .into(),
    );
    let mut bytes = Vec::new();
    message
        .bin_write(&mut bytes)
        .map_err(|e| format!("failed to encode withdrawal outbox message: {}", e))?;
    Ok(bytes)
}

fn decode_rollup_message(
    bytes: &[u8],
    current_rollup: &[u8],
) -> Result<ParsedRollupMessage, String> {
    let (rest, inbox) = TezosInboxMessage::<BridgeDepositPayload>::parse(bytes)
        .map_err(|_| "invalid rollup inbox message: failed to parse TezosInboxMessage frame".to_string())?;
    if !rest.is_empty() {
        return Err(
            "invalid rollup inbox message: trailing bytes after TezosInboxMessage frame".into(),
        );
    }
    match inbox {
        TezosInboxMessage::Internal(TezosInternalInboxMessage::Transfer(transfer)) => {
            if transfer.destination.hash().as_ref().as_slice() != current_rollup {
                Ok(ParsedRollupMessage::Ignore)
            } else {
                Ok(ParsedRollupMessage::Deposit(parse_bridge_deposit(
                    transfer,
                )?))
            }
        }
        TezosInboxMessage::Internal(_) => Ok(ParsedRollupMessage::Ignore),
        TezosInboxMessage::External(payload) => {
            match ExternalMessageFrame::parse(payload) {
                Ok(ExternalMessageFrame::Targetted { address, contents }) => {
                    if address.hash().as_ref().as_slice() != current_rollup {
                        Ok(ParsedRollupMessage::Ignore)
                    } else {
                        decode_kernel_inbox_message(contents)
                            .map(ParsedRollupMessage::Kernel)
                    }
                }
                Err(_) => Ok(ParsedRollupMessage::Ignore),
            }
        }
    }
}

fn parse_bridge_deposit(
    transfer: tezos_smart_rollup_encoding::inbox::Transfer<BridgeDepositPayload>,
) -> Result<ParsedBridgeDeposit, String> {
    let recipient = String::from_utf8((transfer.payload.0).0)
        .map_err(|_| "deposit receiver is not UTF-8".to_string())?;
    let ticket = transfer.payload.1;
    let creator = ticket.creator().0.to_b58check();
    let ticketer = transfer.sender.to_base58_check();
    if creator != ticketer {
        return Err("deposit ticket creator does not match transfer sender".into());
    }
    let token_id = ticket.contents().0 .0.clone();
    if token_id != MichelsonInt::from(0i32).0 {
        return Err("deposit ticket token_id must be 0".into());
    }
    if ticket.contents().1 .0.is_some() {
        return Err("deposit ticket metadata must be None".into());
    }
    let amount = ticket
        .amount_as::<u64, _>()
        .map_err(|_| "deposit amount does not fit in u64".to_string())?;
    Ok(ParsedBridgeDeposit {
        ticketer,
        recipient,
        amount,
    })
}

fn validate_bridge_deposit<H: Host>(
    ledger: &DurableLedgerState<'_, H>,
    deposit: &ParsedBridgeDeposit,
) -> Result<(), String> {
    let configured = ledger
        .read_string(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)?
        .ok_or_else(|| "bridge ticketer is not configured".to_string())?;
    if configured != deposit.ticketer {
        return Err("deposit sent from unexpected ticketer".into());
    }
    if !tzel_core::is_deposit_recipient_string(&deposit.recipient) {
        return Err(
            "deposit receiver must be a canonical deposit balance key: deposit:<32-byte lowercase hex of intent>"
                .into(),
        );
    }
    // Intent-bound deposits commit to the auth_domain that was current when
    // the wallet computed the intent. If the verifier (and therefore the
    // canonical auth_domain) is not yet locked, a later first-config could
    // install a different auth_domain and permanently strand the deposit.
    if read_verifier_config(ledger.host)?.is_none() {
        return Err(
            "bridge deposits not accepted before verifier configuration".into(),
        );
    }
    Ok(())
}

fn bounded_error_message(message: impl Into<String>) -> String {
    let mut message = message.into();
    if message.len() > MAX_RESULT_ERROR_MESSAGE_BYTES {
        let suffix = "... [truncated]";
        let keep = MAX_RESULT_ERROR_MESSAGE_BYTES.saturating_sub(suffix.len());
        message.truncate(keep);
        message.push_str(suffix);
    }
    message
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

pub fn read_private_tx_count_in_current_level<H: Host>(host: &H) -> u64 {
    let Some(current_level) = read_i32(host, PATH_LAST_INPUT_LEVEL) else {
        return 0;
    };
    let Some(stored_level) = read_i32(host, PATH_PRIVATE_TX_FEE_LEVEL) else {
        return 0;
    };
    if stored_level != current_level {
        return 0;
    }
    read_u64(host, PATH_PRIVATE_TX_COUNT_IN_LEVEL).unwrap_or(0)
}

pub fn read_required_tx_fee<H: Host>(host: &H) -> u64 {
    required_tx_fee_for_private_tx_count(read_private_tx_count_in_current_level(host))
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
    let withdrawal_count = read_u64(host, PATH_WITHDRAWAL_COUNT).unwrap_or(0);

    let mut ledger = Ledger::with_auth_domain(auth_domain);
    ledger.tree.leaves.clear();
    ledger.nullifiers.clear();
    ledger.valid_roots.clear();
    ledger.memos.clear();
    ledger.withdrawals.clear();
    ledger.deposit_balances.clear();
    // Deposit balances are NOT enumerated here: the durable layout has no
    // balance index (intentionally — bounded storage), so callers that want
    // to see a specific pool must probe `deposit_balance_path(pubkey_hash)`
    // via `host.read_store(...)` directly.

    for i in 0..tree_size {
        let note_bytes =
            read_persisted_note(host, i).ok_or_else(|| format!("missing persisted note {}", i))?;
        let (cm, enc) = decode_published_note(&note_bytes)?;
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

    for i in 0..withdrawal_count {
        let path = indexed_path(PATH_WITHDRAWAL_PREFIX, i);
        let bytes = host
            .read_store(&path, MAX_STORE_BINARY_BYTES)
            .ok_or_else(|| format!("missing persisted withdrawal {}", i))?;
        ledger.withdrawals.push(decode_withdrawal_record(&bytes)?);
    }

    Ok(ledger)
}

fn read_persisted_note<H: Host>(host: &H, index: u64) -> Option<Vec<u8>> {
    if let Some(bytes) = host.read_store(&note_path(index), MAX_LEDGER_STATE_BYTES) {
        return Some(bytes);
    }

    let len_bytes = host.read_store(&note_length_path(index), 8)?;
    if len_bytes.len() != 8 {
        return None;
    }
    let total_len = usize::try_from(u64::from_le_bytes(len_bytes.try_into().ok()?)).ok()?;
    if total_len > MAX_LEDGER_STATE_BYTES {
        return None;
    }
    let chunk_count = total_len.div_ceil(MAX_NOTE_CHUNK_BYTES);
    let mut bytes = Vec::with_capacity(total_len);
    for chunk_index in 0..chunk_count {
        let chunk = host.read_store(&note_chunk_path(index, chunk_index), MAX_NOTE_CHUNK_BYTES)?;
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != total_len {
        return None;
    }
    Some(bytes)
}

pub fn read_verifier_config<H: Host>(host: &H) -> Result<Option<KernelVerifierConfig>, String> {
    let Some(bytes) = host.read_store(PATH_VERIFIER_CONFIG, MAX_STORE_BINARY_BYTES) else {
        return Ok(None);
    };
    decode_kernel_verifier_config(&bytes).map(Some)
}

pub fn read_last_result<H: Host>(host: &H) -> Option<KernelResult> {
    let bytes = host.read_store(PATH_LAST_RESULT, MAX_INPUT_BYTES)?;
    decode_kernel_result(&bytes).ok()
}

fn dal_payload_kind_name(kind: &KernelDalPayloadKind) -> &'static str {
    match kind {
        KernelDalPayloadKind::ConfigureVerifier => "configure-verifier",
        KernelDalPayloadKind::ConfigureBridge => "configure-bridge",
        KernelDalPayloadKind::Shield => "shield",
        KernelDalPayloadKind::Transfer => "transfer",
        KernelDalPayloadKind::Unshield => "unshield",
    }
}

fn fetch_kernel_message_from_dal<H: Host>(
    host: &H,
    pointer: &KernelDalPayloadPointer,
) -> Result<KernelInboxMessage, String> {
    if pointer.chunks.is_empty() {
        return Err("DAL pointer message requires at least one chunk".into());
    }
    let payload_len = usize::try_from(pointer.payload_len)
        .map_err(|_| "DAL payload length does not fit in usize".to_string())?;
    if payload_len == 0 {
        return Err("DAL payload length must be non-zero".into());
    }
    if payload_len > MAX_DAL_PAYLOAD_BYTES {
        return Err(format!(
            "DAL payload too large: {} > {}",
            payload_len, MAX_DAL_PAYLOAD_BYTES
        ));
    }

    let params = host.reveal_dal_parameters()?;
    if params.number_of_slots == 0 {
        return Err("DAL parameters reported zero slots".into());
    }
    if params.slot_size == 0 || params.page_size == 0 {
        return Err("DAL parameters reported zero-sized slots or pages".into());
    }

    let declared_total = pointer.chunks.iter().try_fold(0usize, |acc, chunk| {
        let len = usize::try_from(chunk.payload_len)
            .map_err(|_| "DAL chunk payload length does not fit in usize".to_string())?;
        acc.checked_add(len)
            .ok_or_else(|| "DAL chunk lengths overflow usize".to_string())
    })?;
    if declared_total != payload_len {
        return Err(format!(
            "DAL chunk lengths do not sum to payload length: {} != {}",
            declared_total, payload_len
        ));
    }

    let slot_size = usize::try_from(params.slot_size)
        .map_err(|_| "DAL slot size does not fit in usize".to_string())?;
    let page_size = usize::try_from(params.page_size)
        .map_err(|_| "DAL page size does not fit in usize".to_string())?;
    let mut payload = Vec::with_capacity(payload_len);

    for (index, chunk) in pointer.chunks.iter().enumerate() {
        let chunk_len = usize::try_from(chunk.payload_len)
            .map_err(|_| format!("DAL chunk {} length does not fit in usize", index))?;
        if chunk_len == 0 {
            return Err(format!("DAL chunk {} has zero payload length", index));
        }
        if chunk_len > slot_size {
            return Err(format!(
                "DAL chunk {} length {} exceeds slot size {}",
                index, chunk_len, slot_size
            ));
        }
        if u64::from(chunk.slot_index) >= params.number_of_slots {
            return Err(format!(
                "DAL chunk {} slot index {} exceeds number_of_slots {}",
                index, chunk.slot_index, params.number_of_slots
            ));
        }
        let published_level = i32::try_from(chunk.published_level).map_err(|_| {
            format!(
                "DAL chunk {} published level {} does not fit in i32",
                index, chunk.published_level
            )
        })?;
        let page_count = chunk_len.div_ceil(page_size);
        let mut chunk_bytes = Vec::with_capacity(page_count.saturating_mul(page_size));
        for page_index in 0..page_count {
            let page = host.reveal_dal_page(
                published_level,
                chunk.slot_index,
                u16::try_from(page_index)
                    .map_err(|_| format!("DAL chunk {} page index overflow", index))?,
                page_size,
            )?;
            if page.len() > page_size {
                return Err(format!(
                    "DAL chunk {} page {} exceeds page size {}",
                    index, page_index, page_size
                ));
            }
            chunk_bytes.extend_from_slice(&page);
        }
        if chunk_bytes.len() < chunk_len {
            return Err(format!(
                "DAL chunk {} truncated: need {} bytes, got {}",
                index,
                chunk_len,
                chunk_bytes.len()
            ));
        }
        if chunk_bytes[chunk_len..].iter().any(|byte| *byte != 0) {
            return Err(format!(
                "DAL chunk {} trailing padding contains non-zero data",
                index
            ));
        }
        payload.extend_from_slice(&chunk_bytes[..chunk_len]);
    }

    if payload.len() != payload_len {
        return Err(format!(
            "DAL payload length mismatch after reassembly: {} != {}",
            payload.len(),
            payload_len
        ));
    }
    if hash(&payload) != pointer.payload_hash {
        return Err("DAL payload hash mismatch".into());
    }

    let message = decode_kernel_inbox_message(&payload)?;
    match (&pointer.kind, &message) {
        (KernelDalPayloadKind::ConfigureVerifier, KernelInboxMessage::ConfigureVerifier(_))
        | (KernelDalPayloadKind::ConfigureBridge, KernelInboxMessage::ConfigureBridge(_))
        | (KernelDalPayloadKind::Shield, KernelInboxMessage::Shield(_))
        | (KernelDalPayloadKind::Transfer, KernelInboxMessage::Transfer(_))
        | (KernelDalPayloadKind::Unshield, KernelInboxMessage::Unshield(_)) => Ok(message),
        (_, KernelInboxMessage::DalPointer(_)) => {
            Err("nested DAL pointer messages are not supported".into())
        }
        _ => Err(format!(
            "DAL payload kind mismatch: pointer declared {}, decoded {:?}",
            dal_payload_kind_name(&pointer.kind),
            message
        )),
    }
}

fn apply_kernel_message<H: Host>(
    ledger: &mut DurableLedgerState<'_, H>,
    message: KernelInboxMessage,
) -> Result<KernelResult, String> {
    match message {
        KernelInboxMessage::ConfigureVerifier(config) => {
            authenticate_verifier_config(&config)?;
            configure_verifier(ledger, &config.config).map(|_| KernelResult::Configured)
        }
        KernelInboxMessage::ConfigureBridge(config) => {
            authenticate_bridge_config(&config)?;
            configure_bridge(ledger, &config.config).map(|_| KernelResult::Configured)
        }
        KernelInboxMessage::Shield(req) => {
            validate_transition_proof(ledger.host, &req.proof, tzel_core::CircuitKind::Shield)?;
            let req = host_shield_req_for_transition(&req);
            let prepared = prepare_shield(ledger, &req)?;
            let commit = prepare_durable_shield_commit(ledger, &prepared)?;
            Ok(KernelResult::Shield(apply_durable_shield_commit(
                ledger, commit,
            )))
        }
        KernelInboxMessage::Transfer(req) => {
            validate_transition_proof(ledger.host, &req.proof, tzel_core::CircuitKind::Transfer)?;
            let req = host_transfer_req_for_transition(&req);
            apply_transfer(ledger, &req).map(KernelResult::Transfer)
        }
        KernelInboxMessage::Unshield(req) => {
            validate_transition_proof(ledger.host, &req.proof, tzel_core::CircuitKind::Unshield)?;
            let req = host_unshield_req_for_transition(&req);
            let prepared = prepare_unshield(ledger, &req)?;
            let outbox = prepare_unshield_outbox(ledger, &prepared)?;
            let commit = prepare_durable_unshield_commit(ledger, &prepared)?;
            ledger.host.write_output(&outbox)?;
            Ok(KernelResult::Unshield(apply_durable_unshield_commit(
                ledger, commit,
            )))
        }
        KernelInboxMessage::DalPointer(pointer) => {
            let nested = fetch_kernel_message_from_dal(ledger.host, &pointer)?;
            if matches!(nested, KernelInboxMessage::DalPointer(_)) {
                return Err("nested DAL pointer messages are not supported".into());
            }
            apply_kernel_message(ledger, nested)
        }
    }
}

fn prepare_unshield_outbox<H: Host>(
    ledger: &mut DurableLedgerState<'_, H>,
    req: &tzel_core::PreparedUnshield,
) -> Result<Vec<u8>, String> {
    let ticketer = ledger
        .read_string(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)?
        .ok_or_else(|| "bridge ticketer is not configured".to_string())?;
    encode_withdrawal_outbox_message(
        &ticketer,
        &WithdrawalRecord {
            recipient: req.recipient().to_string(),
            amount: req.amount(),
        },
    )
}

struct PreparedDurableUnshieldCommit {
    encoded_notes: Vec<(u64, Vec<u8>)>,
    branch_values: Vec<(usize, F)>,
    new_tree_root: F,
    new_tree_size: u64,
    nullifier_start_index: u64,
    nullifiers: Vec<F>,
    withdrawal_index: u64,
    withdrawal_record: WithdrawalRecord,
    root_marker: Option<(u64, F)>,
    response: UnshieldResp,
}

/// Validate that the in-memory frontier `branches` is consistent with a
/// commitment tree of size `tree_size`. The append-only frontier MUST hold
/// `Some(_)` at every level where bit `level` of `tree_size` is set (those
/// are the levels with a "live" left child waiting for its right child).
/// Slots above the highest live level are best-effort: they may contain
/// stale `Some(_)` values from earlier subtree completions and are never
/// consulted before being overwritten. This function only flags missing
/// live frontier nodes — it never inspects stale-but-set slots.
fn assert_frontier_matches_tree_size(branches: &[Option<F>], tree_size: u64) -> Result<(), String> {
    let mut bits = tree_size;
    for level in 0..DEPTH {
        if bits & 1 == 1 && branches[level].is_none() {
            return Err(format!(
                "corrupted Merkle frontier: tree_size {} requires live left child at level {} but durable slot is empty",
                tree_size, level
            ));
        }
        bits >>= 1;
    }
    Ok(())
}

fn simulate_frontier_append(
    zero_hashes: &[F],
    branches: &mut [Option<F>],
    start_index: u64,
    cm: F,
) -> Result<F, String> {
    let mut current = cm;
    let mut index = start_index;
    for level in 0..DEPTH {
        if index & 1 == 0 {
            branches[level] = Some(current);
            current = hash_merkle(&current, &zero_hashes[level]);
        } else {
            let left = branches[level]
                .ok_or_else(|| format!("missing Merkle frontier at level {}", level))?;
            current = hash_merkle(&left, &current);
        }
        index >>= 1;
    }
    Ok(current)
}

fn prepare_durable_unshield_commit<H: Host>(
    ledger: &mut DurableLedgerState<'_, H>,
    prepared: &tzel_core::PreparedUnshield,
) -> Result<PreparedDurableUnshieldCommit, String> {
    let mut encoded_notes = Vec::new();
    let mut branches = (0..DEPTH)
        .map(|level| ledger.read_felt(&branch_path(level)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut tree_size = ledger.read_u64(PATH_TREE_SIZE)?.unwrap_or(0);
    assert_frontier_matches_tree_size(&branches, tree_size)?;
    let change_index = if let Some((cm, enc)) = prepared.change_note() {
        let index = tree_size;
        encoded_notes.push((index, encode_published_note(cm, enc)?));
        let _ = simulate_frontier_append(&ledger.zero_hashes, &mut branches, index, *cm)?;
        tree_size += 1;
        Some(usize::try_from(index).map_err(|_| "note index does not fit in usize".to_string())?)
    } else {
        None
    };
    let (producer_cm, producer_enc) = prepared.producer_note();
    let producer_index_u64 = tree_size;
    encoded_notes.push((
        producer_index_u64,
        encode_published_note(producer_cm, producer_enc)?,
    ));
    let next_root = simulate_frontier_append(
        &ledger.zero_hashes,
        &mut branches,
        producer_index_u64,
        *producer_cm,
    )?;
    tree_size += 1;

    let nullifier_start_index = ledger.read_u64(PATH_NULLIFIER_COUNT)?.unwrap_or(0);
    let withdrawal_index = ledger.read_u64(PATH_WITHDRAWAL_COUNT)?.unwrap_or(0);
    let root_marker = if ledger.has_marker(&root_marker_path(&next_root)) {
        None
    } else {
        Some((
            ledger.read_u64(PATH_VALID_ROOT_COUNT)?.unwrap_or(0),
            next_root,
        ))
    };

    let producer_index = usize::try_from(producer_index_u64)
        .map_err(|_| "note index does not fit in usize".to_string())?;
    Ok(PreparedDurableUnshieldCommit {
        encoded_notes,
        branch_values: branches
            .into_iter()
            .enumerate()
            .filter_map(|(level, value)| value.map(|felt| (level, felt)))
            .collect(),
        new_tree_root: next_root,
        new_tree_size: tree_size,
        nullifier_start_index,
        nullifiers: prepared.nullifiers().to_vec(),
        withdrawal_index,
        withdrawal_record: WithdrawalRecord {
            recipient: prepared.recipient().to_string(),
            amount: prepared.amount(),
        },
        root_marker,
        response: UnshieldResp {
            change_index,
            producer_index,
        },
    })
}

/// Apply the staged durable writes for an unshield. SAFETY-CRITICAL: this
/// function MUST remain infallible — it runs after `host.write_output(...)`
/// has already emitted the L1 outbox transfer, so any failure here would
/// reproduce the H1 atomicity bug (outbox observed on L1 without the matching
/// rollup state mutation, enabling double-withdrawal). Every call site must
/// either be a `Host::write_store` (declared infallible by the trait) or a
/// pure-local update. Do NOT introduce any operation that returns `Result` —
/// route fallible work into `prepare_durable_unshield_commit` instead.
fn apply_durable_unshield_commit<H: Host>(
    ledger: &mut DurableLedgerState<'_, H>,
    commit: PreparedDurableUnshieldCommit,
) -> UnshieldResp {
    for (index, encoded) in &commit.encoded_notes {
        write_note_payload(ledger.host, *index, encoded);
    }
    for (level, felt) in &commit.branch_values {
        ledger.write_felt(&branch_path(*level), felt);
    }
    ledger.write_felt(PATH_TREE_ROOT, &commit.new_tree_root);
    ledger.write_u64(PATH_TREE_SIZE, commit.new_tree_size);

    let mut nullifier_index = commit.nullifier_start_index;
    for nf in &commit.nullifiers {
        let path = nullifier_path(nf);
        ledger.write_marker(&path);
        ledger.write_key_at_index(PATH_NULLIFIER_INDEX_PREFIX, nullifier_index, nf);
        nullifier_index += 1;
    }
    ledger.write_u64(PATH_NULLIFIER_COUNT, nullifier_index);

    ledger.write_withdrawal_at_index(commit.withdrawal_index, &commit.withdrawal_record);
    ledger.write_u64(PATH_WITHDRAWAL_COUNT, commit.withdrawal_index + 1);

    if let Some((root_index, root)) = &commit.root_marker {
        let path = root_marker_path(root);
        ledger.write_marker(&path);
        ledger.write_key_at_index(PATH_VALID_ROOT_INDEX_PREFIX, *root_index, root);
        ledger.write_u64(PATH_VALID_ROOT_COUNT, root_index + 1);
    }

    ledger.note_private_tx_applied();
    commit.response
}

/// All staged durable writes for a shield, precomputed in
/// `prepare_durable_shield_commit` so the apply step is infallible.
struct PreparedDurableShieldCommit {
    /// Encoded notes (recipient, then producer) keyed by tree index.
    encoded_notes: Vec<(u64, Vec<u8>)>,
    /// Updated frontier branches (level, felt).
    branch_values: Vec<(usize, F)>,
    new_tree_root: F,
    new_tree_size: u64,
    /// Path of the deposit-pool balance entry for `pubkey_hash`.
    balance_path: Vec<u8>,
    /// New balance value to write. If zero, the apply step writes empty
    /// bytes (best-effort delete) so the entry doesn't accumulate.
    new_balance: u64,
    /// Optional new valid-root marker (only if the resulting root is fresh).
    root_marker: Option<(u64, F)>,
    /// Path of the replay-protection marker for this shield's
    /// `client_cm`. The apply step records a single-byte value here so a
    /// replay submitting the same proof is rejected by the prepare step.
    applied_shield_path: Vec<u8>,
    response: ShieldResp,
}

/// Validate the deposit-pool balance (must exist and be at least `debit`)
/// and precompute every durable write the shield will perform. Read-only on
/// the store. The returned struct is then consumed by the infallible apply.
fn prepare_durable_shield_commit<H: Host>(
    ledger: &mut DurableLedgerState<'_, H>,
    prepared: &tzel_core::PreparedShield,
) -> Result<PreparedDurableShieldCommit, String> {
    // 1. Validate the pool balance without mutating.
    let balance_path = deposit_balance_path(prepared.pubkey_hash());
    let balance_bytes = ledger.host.read_store(&balance_path, 8).ok_or_else(|| {
        format!(
            "no deposit pool for pubkey_hash {}; submit an L1 bridge deposit first",
            hex::encode(prepared.pubkey_hash())
        )
    })?;
    if balance_bytes.is_empty() {
        // Best-effort-deleted pool — treat as missing.
        return Err(format!(
            "no deposit pool for pubkey_hash {}; submit an L1 bridge deposit first",
            hex::encode(prepared.pubkey_hash())
        ));
    }
    if balance_bytes.len() != 8 {
        return Err(format!(
            "bad u64 at {}",
            String::from_utf8_lossy(&balance_path)
        ));
    }
    let balance = u64::from_le_bytes(balance_bytes.try_into().unwrap());
    if balance < prepared.debit() {
        return Err(format!(
            "deposit pool {} balance {} too small for v + fee + producer_fee = {}",
            hex::encode(prepared.pubkey_hash()),
            balance,
            prepared.debit()
        ));
    }
    let new_balance = balance - prepared.debit();

    // 2. Reject shield replays. The kernel records each successfully
    // applied shield's `client_cm`; if the same `client_cm` arrives
    // again, the request is the replay of an earlier proof. Without
    // this, an attacker could top up a drained pool (or mirror the
    // original deposit into any aggregating top-up) and resubmit the
    // victim's old proof, minting a duplicate of their note at a
    // fresh tree position — independently spendable since nullifiers
    // are per-position, doubling the recipient's shielded balance at
    // the dust-attacker's expense.
    let (client_cm_marker_check, _) = prepared.client_note();
    let applied_shield_path = applied_shield_path(client_cm_marker_check);
    if ledger.has_marker(&applied_shield_path) {
        return Err(format!(
            "shield replay: cm {} already applied",
            hex::encode(client_cm_marker_check)
        ));
    }

    // 3. Plan the tree appends. Read frontier, simulate two appends.
    let mut branches = (0..DEPTH)
        .map(|level| ledger.read_felt(&branch_path(level)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut tree_size = ledger.read_u64(PATH_TREE_SIZE)?.unwrap_or(0);
    assert_frontier_matches_tree_size(&branches, tree_size)?;

    let (client_cm, client_enc) = prepared.client_note();
    let client_index_u64 = tree_size;
    let mut encoded_notes = Vec::with_capacity(2);
    encoded_notes.push((client_index_u64, encode_published_note(client_cm, client_enc)?));
    let _ = simulate_frontier_append(
        &ledger.zero_hashes,
        &mut branches,
        client_index_u64,
        *client_cm,
    )?;
    tree_size += 1;
    let client_index = usize::try_from(client_index_u64)
        .map_err(|_| "note index does not fit in usize".to_string())?;

    let (producer_cm, producer_enc) = prepared.producer_note();
    let producer_index_u64 = tree_size;
    encoded_notes.push((
        producer_index_u64,
        encode_published_note(producer_cm, producer_enc)?,
    ));
    let next_root = simulate_frontier_append(
        &ledger.zero_hashes,
        &mut branches,
        producer_index_u64,
        *producer_cm,
    )?;
    tree_size += 1;
    let producer_index = usize::try_from(producer_index_u64)
        .map_err(|_| "note index does not fit in usize".to_string())?;

    // 4. Plan the valid-root marker.
    let root_marker = if ledger.has_marker(&root_marker_path(&next_root)) {
        None
    } else {
        Some((
            ledger.read_u64(PATH_VALID_ROOT_COUNT)?.unwrap_or(0),
            next_root,
        ))
    };

    Ok(PreparedDurableShieldCommit {
        encoded_notes,
        branch_values: branches
            .into_iter()
            .enumerate()
            .filter_map(|(level, value)| value.map(|felt| (level, felt)))
            .collect(),
        new_tree_root: next_root,
        new_tree_size: tree_size,
        balance_path,
        new_balance,
        root_marker,
        applied_shield_path,
        response: ShieldResp {
            cm: *client_cm,
            index: client_index,
            producer_cm: *producer_cm,
            producer_index,
        },
    })
}

/// Apply the staged durable writes for a shield. SAFETY-CRITICAL: this
/// function MUST remain infallible — once it starts mutating, the balance
/// debit makes the operation effectively irreversible (the user's claim is
/// taken). Every call here is either a `Host::write_store` (declared
/// infallible by the trait) or a pure-local update. Do NOT introduce
/// fallible operations; route fallible work into
/// `prepare_durable_shield_commit` instead.
fn apply_durable_shield_commit<H: Host>(
    ledger: &mut DurableLedgerState<'_, H>,
    commit: PreparedDurableShieldCommit,
) -> ShieldResp {
    // Debit the deposit pool. Zero balance triggers a best-effort delete
    // (empty value) to bound durable footprint.
    if commit.new_balance == 0 {
        ledger.host.write_store(&commit.balance_path, &[]);
    } else {
        ledger
            .host
            .write_store(&commit.balance_path, &commit.new_balance.to_le_bytes());
    }

    // Record the replay-protection marker for this shield's `client_cm`.
    // Set BEFORE the tree appends so a future prepare step that probes
    // the marker observes the post-apply state.
    ledger.write_marker(&commit.applied_shield_path);

    // Append the two notes and update frontier / tree size / tree root.
    for (index, encoded) in &commit.encoded_notes {
        write_note_payload(ledger.host, *index, encoded);
    }
    for (level, felt) in &commit.branch_values {
        ledger.write_felt(&branch_path(*level), felt);
    }
    ledger.write_felt(PATH_TREE_ROOT, &commit.new_tree_root);
    ledger.write_u64(PATH_TREE_SIZE, commit.new_tree_size);

    if let Some((root_index, root)) = &commit.root_marker {
        let path = root_marker_path(root);
        ledger.write_marker(&path);
        ledger.write_key_at_index(PATH_VALID_ROOT_INDEX_PREFIX, *root_index, root);
        ledger.write_u64(PATH_VALID_ROOT_COUNT, root_index + 1);
    }

    ledger.note_private_tx_applied();
    commit.response
}

fn process_input<H: Host>(host: &mut H, input: &InputMessage) {
    let stored_payload_len = input.payload.len().min(MAX_STORED_INPUT_PAYLOAD_BYTES);
    increment_u64(host, PATH_RAW_INPUT_COUNT, 1);
    increment_u64(host, PATH_RAW_INPUT_BYTES, input.payload.len() as u64);
    host.write_store(PATH_LAST_INPUT_LEVEL, &input.level.to_le_bytes());
    host.write_store(PATH_LAST_INPUT_ID, &input.id.to_le_bytes());
    host.write_store(
        PATH_LAST_INPUT_LEN,
        &u32::try_from(stored_payload_len)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    host.write_store(
        PATH_LAST_INPUT_PAYLOAD,
        &input.payload[..stored_payload_len],
    );

    host.write_debug(&format!(
        "tzel-rollup-kernel: inbox level={} id={} bytes={}\n",
        input.level,
        input.id,
        input.payload.len()
    ));

    if let Some(result) = apply_input_message(host, input) {
        match encode_kernel_result(&result) {
            Ok(encoded) => host.write_store(PATH_LAST_RESULT, &encoded),
            Err(e) => host.write_debug(&format!(
                "tzel-rollup-kernel: failed to encode result: {}\n",
                e
            )),
        }
    }
}

fn apply_input_message<H: Host>(host: &mut H, input: &InputMessage) -> Option<KernelResult> {
    let current_rollup = host.rollup_address();
    let message = match decode_rollup_message(&input.payload, current_rollup.as_slice()) {
        Ok(message) => message,
        Err(e) => {
            let msg = bounded_error_message(format!("invalid inbox message: {}", e));
            host.write_debug(&format!("tzel-rollup-kernel: {}\n", msg));
            return Some(KernelResult::Error { message: msg });
        }
    };

    if matches!(message, ParsedRollupMessage::Ignore) {
        return None;
    }

    let mut ledger = match DurableLedgerState::new(host) {
        Ok(ledger) => ledger,
        Err(e) => {
            ledger_debug(host, &e);
            return Some(KernelResult::Error {
                message: bounded_error_message(e),
            });
        }
    };

    let result: Result<KernelResult, String> = match message {
        ParsedRollupMessage::Ignore => unreachable!("ignored messages are handled above"),
        ParsedRollupMessage::Deposit(req) => (|| -> Result<KernelResult, String> {
            validate_bridge_deposit(&ledger, &req)?;
            apply_deposit(&mut ledger, &req.recipient, req.amount).map(|_| KernelResult::Deposit)
        })(),
        ParsedRollupMessage::Kernel(message) => apply_kernel_message(&mut ledger, message),
    };

    match result {
        Ok(success) => Some(success),
        Err(message) => {
            let message = bounded_error_message(message);
            ledger_debug(host, &format!("transition failed: {}", message));
            Some(KernelResult::Error { message })
        }
    }
}

fn load_verifier<H: Host>(host: &H) -> Result<DirectProofVerifier, String> {
    let config = read_verifier_config(host)?
        .ok_or_else(|| "proof verifier is not configured".to_string())?;
    DirectProofVerifier::from_kernel_config(&config)
}

fn parse_compiled_felt_hex(hex_value: &str, label: &str) -> Result<F, String> {
    let bytes = hex::decode(hex_value)
        .map_err(|e| format!("invalid {} hex in kernel build: {}", label, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "invalid {} length in kernel build: got {} bytes, expected 32",
            label,
            bytes.len()
        ));
    }
    let mut felt = [0u8; 32];
    felt.copy_from_slice(&bytes);
    Ok(felt)
}

#[cfg(any(test, debug_assertions))]
fn dev_config_admin_ask() -> F {
    hash(b"tzel-dev-rollup-config-admin")
}

fn compiled_config_admin_pub_seed() -> Result<F, String> {
    if let Some(hex_value) = option_env!("TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX") {
        return parse_compiled_felt_hex(hex_value, "TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX");
    }
    #[cfg(any(test, debug_assertions))]
    {
        return Ok(derive_auth_pub_seed(&dev_config_admin_ask()));
    }
    #[allow(unreachable_code)]
    Err("kernel built without TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX".into())
}

fn compiled_verifier_config_leaf() -> Result<F, String> {
    if let Some(hex_value) = option_env!("TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX") {
        return parse_compiled_felt_hex(hex_value, "TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX");
    }
    #[cfg(any(test, debug_assertions))]
    {
        return Ok(auth_leaf_hash(
            &dev_config_admin_ask(),
            KERNEL_VERIFIER_CONFIG_KEY_INDEX,
        ));
    }
    #[allow(unreachable_code)]
    Err("kernel built without TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX".into())
}

fn compiled_bridge_config_leaf() -> Result<F, String> {
    if let Some(hex_value) = option_env!("TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX") {
        return parse_compiled_felt_hex(hex_value, "TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX");
    }
    #[cfg(any(test, debug_assertions))]
    {
        return Ok(auth_leaf_hash(
            &dev_config_admin_ask(),
            KERNEL_BRIDGE_CONFIG_KEY_INDEX,
        ));
    }
    #[allow(unreachable_code)]
    Err("kernel built without TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX".into())
}

fn authenticate_verifier_config(config: &KernelSignedVerifierConfig) -> Result<(), String> {
    let pub_seed = compiled_config_admin_pub_seed()?;
    let expected_leaf = compiled_verifier_config_leaf()?;
    let sighash = kernel_verifier_config_sighash(&config.config)?;
    verify_wots_signature_against_leaf(
        &sighash,
        &pub_seed,
        KERNEL_VERIFIER_CONFIG_KEY_INDEX,
        &config.signature,
        &expected_leaf,
    )
}

fn authenticate_bridge_config(config: &KernelSignedBridgeConfig) -> Result<(), String> {
    let pub_seed = compiled_config_admin_pub_seed()?;
    let expected_leaf = compiled_bridge_config_leaf()?;
    let sighash = kernel_bridge_config_sighash(&config.config)?;
    verify_wots_signature_against_leaf(
        &sighash,
        &pub_seed,
        KERNEL_BRIDGE_CONFIG_KEY_INDEX,
        &config.signature,
        &expected_leaf,
    )
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
    #[cfg(feature = "proof-verifier")]
    DirectProofVerifier::from_kernel_config(config)?;

    let existing = read_verifier_config(ledger.host)?;
    if let Some(existing) = existing {
        // auth_domain is frozen on first install. Any attempt to change it
        // after the first config — even on a pristine ledger — is rejected,
        // because in-flight deposits compute intent against the auth_domain
        // they read from rollup HEAD and submit irreversible L1 tickets.
        // Allowing a reconfig in the in-flight window would silently strand
        // those deposits.
        if existing.auth_domain != config.auth_domain {
            return Err(
                "auth_domain is frozen after first verifier configuration; \
                 changing it would strand any in-flight bridge deposit"
                    .into(),
            );
        }
        // Other verifier-config fields (program hashes) may still be reconfigured
        // while the ledger is pristine — auth_domain is the only field whose
        // change has a deposit-stranding risk.
        if existing != *config && !ledger.is_pristine()? {
            return Err("cannot change verifier configuration after ledger state exists".into());
        }
    } else if !ledger.is_pristine()? {
        // First-time verifier config installs the canonical auth_domain.
        // Bridge deposits are blocked before configuration (see
        // `validate_bridge_deposit`) precisely because intent-bound deposits
        // commit to that auth_domain; reaching this branch with non-pristine
        // state would mean a deposit slipped through, which we never permit.
        return Err("cannot configure verifier after ledger state exists".into());
    }

    ledger.write_felt(PATH_AUTH_DOMAIN, &config.auth_domain);
    let encoded = encode_kernel_verifier_config(config)?;
    ledger.host.write_store(PATH_VERIFIER_CONFIG, &encoded);
    Ok(())
}

fn configure_bridge<H: Host>(
    ledger: &mut DurableLedgerState<'_, H>,
    config: &KernelBridgeConfig,
) -> Result<(), String> {
    let ticketer = TezosContract::from_b58check(&config.ticketer)
        .map_err(|_| "bridge ticketer must be a valid L1 contract".to_string())?;
    if !matches!(ticketer, TezosContract::Originated(_)) {
        return Err("bridge ticketer must be a KT1 contract".into());
    }

    let existing = ledger.read_string(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)?;
    if !ledger.is_pristine()? && existing.as_deref() != Some(config.ticketer.as_str()) {
        return Err("cannot change bridge ticketer after ledger state exists".into());
    }

    ledger.write_string(PATH_BRIDGE_TICKETER, &config.ticketer);
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
    use super::{run_with_host, DalParameters, Host, InputMessage, MAX_INPUT_BYTES};

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
        fn write_output(src: *const u8, num_bytes: usize) -> i32;
        fn reveal_metadata(dst: *mut u8, max_bytes: usize) -> i32;
        fn reveal(
            payload_addr: *const u8,
            payload_len: usize,
            destination_addr: *mut u8,
            max_bytes: usize,
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

        fn write_output(&mut self, value: &[u8]) -> Result<(), String> {
            let rc = unsafe { write_output(value.as_ptr(), value.len()) };
            if rc < 0 {
                return Err("write_output failed".into());
            }
            Ok(())
        }

        fn write_debug(&mut self, message: &str) {
            unsafe { write_debug(message.as_ptr(), message.len()) }
        }

        fn rollup_address(&self) -> Vec<u8> {
            let mut metadata = [0u8; 24];
            let written = unsafe { reveal_metadata(metadata.as_mut_ptr(), metadata.len()) };
            assert_eq!(written, metadata.len() as i32, "reveal_metadata failed");
            metadata[..20].to_vec()
        }

        fn reveal_dal_parameters(&self) -> Result<DalParameters, String> {
            let payload = [3u8];
            let mut raw = [0u8; 32];
            let written =
                unsafe { reveal(payload.as_ptr(), payload.len(), raw.as_mut_ptr(), raw.len()) };
            if written != raw.len() as i32 {
                return Err(format!(
                    "reveal DAL parameters failed: expected {} bytes, got {}",
                    raw.len(),
                    written
                ));
            }
            let read_u64_be = |bytes: &[u8]| -> Result<u64, String> {
                let signed = i64::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| "bad DAL parameter width".to_string())?,
                );
                u64::try_from(signed).map_err(|_| "DAL parameter was negative".to_string())
            };
            Ok(DalParameters {
                number_of_slots: read_u64_be(&raw[0..8])?,
                attestation_lag: read_u64_be(&raw[8..16])?,
                slot_size: read_u64_be(&raw[16..24])?,
                page_size: read_u64_be(&raw[24..32])?,
            })
        }

        fn reveal_dal_page(
            &self,
            published_level: i32,
            slot_index: u8,
            page_index: u16,
            max_bytes: usize,
        ) -> Result<Vec<u8>, String> {
            let page_index = i16::try_from(page_index)
                .map_err(|_| "DAL page index does not fit in i16".to_string())?;
            let payload: Vec<u8> = [
                &[2u8][..],
                published_level.to_be_bytes().as_ref(),
                &[slot_index],
                page_index.to_be_bytes().as_ref(),
            ]
            .concat();
            let mut buffer = vec![0u8; max_bytes];
            let written = unsafe {
                reveal(
                    payload.as_ptr(),
                    payload.len(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            };
            if written < 0 {
                return Err("reveal DAL page failed".into());
            }
            let len = usize::try_from(written)
                .map_err(|_| "reveal DAL page returned invalid size".to_string())?;
            buffer.truncate(len);
            Ok(buffer)
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
    use tezos_data_encoding_05::nom::NomReader as _;
    use tezos_smart_rollup_encoding::{
        contract::Contract as TezosContract,
        inbox::{
            InboxMessage as TezosInboxMessage, InternalInboxMessage as TezosInternalInboxMessage,
            Transfer as TezosTransfer,
        },
        michelson::{
            ticket::FA2_1Ticket, MichelsonBytes, MichelsonContract, MichelsonInt, MichelsonOption,
            MichelsonPair, MichelsonUnit,
        },
        outbox::OutboxMessage as TezosOutboxMessage,
        public_key_hash::PublicKeyHash,
        smart_rollup::SmartRollupAddress,
    };
    use tzel_core::kernel_wire::KernelDalChunkPointer;
    use tzel_core::{
        commit, default_auth_domain, deposit_recipient_string, derive_account, derive_address,
        derive_ask, derive_auth_pub_seed, derive_kem_keys, derive_nk_spend, derive_nk_tag,
        derive_rcm, encrypt_note_deterministic, felt_tag, hash, hash_two,
        kernel_wire::{
            encode_kernel_inbox_message, sign_kernel_bridge_config, sign_kernel_verifier_config,
            KernelBridgeConfig, KernelInboxMessage, KernelShieldReq, KernelStarkProof,
            KernelTransferReq, KernelUnshieldReq, KernelVerifierConfig,
        },
        owner_tag, PaymentAddress, ProgramHashes, ShieldResp,
        TransferResp, UnshieldResp, MIN_TX_FEE, ZERO,
    };

    /// Test-only deterministic pubkey_hash derived from a label. The
    /// real `pubkey_hash = H(0x04, auth_domain, auth_root,
    /// auth_pub_seed, blind)`; these tests don't exercise the wallet-
    /// side derivation, so an opaque label-derived F suffices as the
    /// pool key.
    fn pubkey_hash_from_label(label: &str) -> tzel_core::F {
        tzel_core::hash(label.as_bytes())
    }

    #[derive(Default)]
    struct MockHost {
        inputs: VecDeque<InputMessage>,
        store: HashMap<Vec<u8>, Vec<u8>>,
        outputs: Vec<Vec<u8>>,
        debug: String,
        fail_output: Option<String>,
        rollup_address: Option<Vec<u8>>,
        dal_parameters: Option<DalParameters>,
        dal_pages: HashMap<(i32, u8, u16), Vec<u8>>,
    }

    impl MockHost {
        fn with_inputs(inputs: Vec<InputMessage>) -> Self {
            Self {
                inputs: inputs.into(),
                ..Self::default()
            }
        }

        fn effective_rollup_address(&self) -> Vec<u8> {
            self.rollup_address
                .clone()
                .unwrap_or_else(|| sample_rollup_address().hash().as_ref().clone())
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

        fn write_output(&mut self, value: &[u8]) -> Result<(), String> {
            if let Some(message) = self.fail_output.take() {
                return Err(message);
            }
            self.outputs.push(value.to_vec());
            Ok(())
        }

        fn write_debug(&mut self, message: &str) {
            self.debug.push_str(message);
        }

        fn rollup_address(&self) -> Vec<u8> {
            self.effective_rollup_address()
        }

        fn reveal_dal_parameters(&self) -> Result<DalParameters, String> {
            self.dal_parameters
                .clone()
                .ok_or_else(|| "mock DAL parameters are not configured".to_string())
        }

        fn reveal_dal_page(
            &self,
            published_level: i32,
            slot_index: u8,
            page_index: u16,
            max_bytes: usize,
        ) -> Result<Vec<u8>, String> {
            let Some(page) = self
                .dal_pages
                .get(&(published_level, slot_index, page_index))
            else {
                return Ok(Vec::new());
            };
            Ok(page[..page.len().min(max_bytes)].to_vec())
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
    fn truncates_oversized_last_input_payload_store() {
        let payload = vec![0xAA; MAX_STORED_INPUT_PAYLOAD_BYTES + 17];
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 9,
            id: 4,
            payload: payload.clone(),
        }]);

        run_with_host(&mut host);

        let stats = read_stats(&host);
        assert_eq!(stats.raw_input_count, 1);
        assert_eq!(stats.raw_input_bytes, payload.len() as u64);
        assert_eq!(
            stats.last_input_len,
            Some(MAX_STORED_INPUT_PAYLOAD_BYTES as u32)
        );
        assert_eq!(
            read_last_input(&host).unwrap().payload,
            payload[..MAX_STORED_INPUT_PAYLOAD_BYTES].to_vec()
        );
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
    fn ignores_protocol_and_foreign_targeted_messages() {
        let mut host = MockHost::default();
        let mut sol = Vec::new();
        TezosInboxMessage::<MichelsonUnit>::Internal(TezosInternalInboxMessage::StartOfLevel)
            .serialize(&mut sol)
            .unwrap();
        host.inputs.push_back(InputMessage {
            level: 1,
            id: 0,
            payload: sol,
        });
        host.inputs.push_back(InputMessage {
            level: 1,
            id: 1,
            payload: encode_external_kernel_message_for_rollup(
                sample_other_rollup_address(),
                &signed_bridge_message(KernelBridgeConfig {
                    ticketer: sample_ticketer().into(),
                }),
            ),
        });
        host.inputs.push_back(InputMessage {
            level: 1,
            id: 2,
            payload: encode_ticket_deposit_message_for_rollup(
                "alice",
                10,
                sample_other_rollup_address(),
            ),
        });

        run_with_host(&mut host);

        assert!(read_last_result(&host).is_none());
        assert!(!host.debug.contains("invalid inbox message"));
        assert!(!host.debug.contains("transition failed"));
    }

    #[test]
    fn truncates_oversized_targeted_decode_errors() {
        let mut host = MockHost::default();
        let mut framed = Vec::new();
        ExternalMessageFrame::Targetted {
            address: sample_rollup_address(),
            contents: vec![0xAA; MAX_INPUT_BYTES],
        }
        .bin_write(&mut framed)
        .unwrap();
        let mut payload = Vec::new();
        TezosInboxMessage::<MichelsonUnit>::External(framed.as_slice())
            .serialize(&mut payload)
            .unwrap();
        host.inputs.push_back(InputMessage {
            level: 2,
            id: 0,
            payload,
        });

        run_with_host(&mut host);

        let KernelResult::Error { message } = read_last_result(&host).unwrap() else {
            panic!("expected error result");
        };
        assert!(message.len() <= MAX_RESULT_ERROR_MESSAGE_BYTES);
        assert!(message.contains("truncated"));
    }

    #[test]
    fn applies_ticket_deposit_message_to_shared_ledger_state() {
        let mut host = MockHost::default();
        install_test_bridge(&mut host);
        install_test_verifier(&mut host);
        host.inputs.push_back(InputMessage {
            level: 1,
            id: 0,
            payload: encode_ticket_deposit_message(
                &deposit_recipient_string(&pubkey_hash_from_label("alice")),
                75,
            ),
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.auth_domain, default_auth_domain());
        // Probe the durable balance entry directly: read_ledger does not
        // enumerate deposit balances (no index by design — bounded
        // storage), so callers verify specific pools by path.
        let balance_path = deposit_balance_path(&pubkey_hash_from_label("alice"));
        let bytes = host.read_store(&balance_path, 8).expect("balance entry");
        let balance = u64::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(balance, 75);
        match read_last_result(&host).unwrap() {
            KernelResult::Deposit => {}
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn applies_shield_message_with_shared_ledger_logic() {
        let mut host = MockHost::default();
        let producer_fee = 1;
        let v = 50u64;

        let config = KernelVerifierConfig {
            auth_domain: default_auth_domain(),
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        host.write_store(
            PATH_VERIFIER_CONFIG,
            &encode_kernel_verifier_config(&config).unwrap(),
        );

        let address = sample_payment_address();
        let producer_rseed = sample_felt(0x31);
        let producer_enc = sample_encrypted_note(&address, producer_fee, producer_rseed, b"dal");
        let producer_cm = sample_commitment(&address, producer_fee, producer_rseed);
        let client_rseed = sample_felt(0x32);
        let client_enc = sample_encrypted_note(&address, v, client_rseed, b"shield");
        let client_cm = sample_commitment(&address, v, client_rseed);
        let blind = sample_felt(0x33);
        let pubkey_hash = tzel_core::deposit_pubkey_hash(
            &config.auth_domain,
            &address.auth_root,
            &address.auth_pub_seed,
            &blind,
        );
        {
            let mut state = DurableLedgerState::new(&mut host).unwrap();
            apply_deposit(
                &mut state,
                &deposit_recipient_string(&pubkey_hash),
                v + producer_fee + MIN_TX_FEE,
            )
            .unwrap();
        }
        let shield_req = KernelShieldReq {
            pubkey_hash,
            fee: MIN_TX_FEE,
            producer_fee,
            v,
            proof: sample_kernel_test_proof(),
            client_cm,
            client_enc,
            producer_cm,
            producer_enc,
        };
        let message = encode_external_kernel_message(&KernelInboxMessage::Shield(shield_req));
        host.inputs.push_back(InputMessage {
            level: 2,
            id: 1,
            payload: message,
        });

        run_with_host(&mut host);

        // Pool was fully drained by the shield — durable balance entry is
        // either absent or empty (kernel writes empty bytes to bound storage).
        let balance_path = deposit_balance_path(&pubkey_hash);
        let after_shield = host.read_store(&balance_path, 8);
        assert!(after_shield.as_ref().map(|b| b.is_empty()).unwrap_or(true));
        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.tree.leaves.len(), 2);
        match read_last_result(&host).unwrap() {
            KernelResult::Shield(ShieldResp {
                index,
                producer_cm: result_producer_cm,
                producer_index,
                ..
            }) => {
                assert_eq!(index, 0);
                assert_eq!(result_producer_cm, producer_cm);
                assert_eq!(producer_index, 1);
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_chunked_note_lengths_beyond_ledger_limit() {
        let mut host = MockHost::default();
        host.write_store(
            &note_length_path(0),
            &((MAX_LEDGER_STATE_BYTES as u64) + 1).to_le_bytes(),
        );
        assert!(read_persisted_note(&host, 0).is_none());
    }

    #[test]
    fn applies_configure_verifier_message_from_dal_pointer() {
        let mut host = MockHost::default();
        let config = KernelVerifierConfig {
            auth_domain: sample_felt(0x41),
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        let payload =
            encode_kernel_inbox_message(&signed_verifier_message(config.clone())).unwrap();
        let pointer = KernelDalPayloadPointer {
            kind: KernelDalPayloadKind::ConfigureVerifier,
            chunks: vec![install_mock_dal_payload(
                &mut host, 101, 1, 64, 8192, &payload,
            )],
            payload_len: payload.len() as u64,
            payload_hash: hash(&payload),
        };
        host.inputs.push_back(InputMessage {
            level: 13,
            id: 0,
            payload: encode_external_kernel_message(&KernelInboxMessage::DalPointer(pointer)),
        });

        run_with_host(&mut host);

        let verifier = read_verifier_config(&host)
            .expect("verifier config read")
            .expect("verifier config persisted");
        assert_eq!(verifier.auth_domain, config.auth_domain);
        assert_eq!(
            verifier.verified_program_hashes,
            config.verified_program_hashes
        );
        assert!(matches!(
            read_last_result(&host).unwrap(),
            KernelResult::Configured
        ));
    }

    #[test]
    fn applies_configure_bridge_message_from_dal_pointer() {
        let mut host = MockHost::default();
        let config = KernelBridgeConfig {
            ticketer: sample_ticketer().into(),
        };
        let payload = encode_kernel_inbox_message(&signed_bridge_message(config.clone())).unwrap();
        let pointer = KernelDalPayloadPointer {
            kind: KernelDalPayloadKind::ConfigureBridge,
            chunks: vec![install_mock_dal_payload(
                &mut host, 101, 2, 64, 8192, &payload,
            )],
            payload_len: payload.len() as u64,
            payload_hash: hash(&payload),
        };
        host.inputs.push_back(InputMessage {
            level: 14,
            id: 0,
            payload: encode_external_kernel_message(&KernelInboxMessage::DalPointer(pointer)),
        });

        run_with_host(&mut host);

        assert_eq!(
            host.read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
                .expect("ticketer stored"),
            sample_ticketer().as_bytes()
        );
        assert!(matches!(
            read_last_result(&host).unwrap(),
            KernelResult::Configured
        ));
    }

    #[test]
    fn rejects_dal_pointer_hash_mismatch_without_mutating_state() {
        // This test exercises the DAL-pointer hash-mismatch path. The shield
        // payload is an opaque vehicle here; the DAL hash check fires before
        // the kernel even decodes shield consensus rules.
        let mut host = MockHost::default();
        let producer_fee = 1;

        let address = sample_payment_address();
        let producer_rseed = sample_felt(0x34);
        let producer_enc = sample_encrypted_note(&address, producer_fee, producer_rseed, b"dal");
        let producer_cm = sample_commitment(&address, producer_fee, producer_rseed);
        let client_rseed = sample_felt(0x35);
        let client_enc = sample_encrypted_note(&address, 50, client_rseed, b"shield");
        let client_cm = sample_commitment(&address, 50, client_rseed);
        let payload = encode_external_kernel_message(&KernelInboxMessage::Shield(KernelShieldReq {
            pubkey_hash: pubkey_hash_from_label("alice"),
            fee: MIN_TX_FEE,
            producer_fee,
            v: 50,
            proof: sample_kernel_test_proof(),
            client_cm,
            client_enc,
            producer_cm,
            producer_enc,
        }));
        let mut bad_hash = hash(&payload);
        bad_hash[0] ^= 0xFF;
        let pointer = KernelDalPayloadPointer {
            kind: KernelDalPayloadKind::Shield,
            chunks: vec![install_mock_dal_payload(
                &mut host, 101, 4, 64, 8192, &payload,
            )],
            payload_len: payload.len() as u64,
            payload_hash: bad_hash,
        };
        host.inputs.push_back(InputMessage {
            level: 16,
            id: 0,
            payload: encode_external_kernel_message(&KernelInboxMessage::DalPointer(pointer)),
        });

        run_with_host(&mut host);

        let _ = producer_fee;
        // DAL hash mismatch: kernel rejects, no balance entry mutated.
        let balance_path =
            deposit_balance_path(&pubkey_hash_from_label("alice"));
        assert!(host.read_store(&balance_path, 8).is_none());
        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.tree.leaves.is_empty());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("DAL payload hash mismatch"))
            }
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
        let enc_3 = sample_encrypted_note(&address, 1, [0x13; 32], b"dal");
        let cm_1 = sample_commitment(&address, 11, [0x11; 32]);
        let cm_2 = sample_commitment(&address, 12, [0x12; 32]);
        let cm_3 = sample_commitment(&address, 1, [0x13; 32]);
        let nf = sample_felt(0x91);
        let root = read_ledger(&host).unwrap().tree.root();

        let req = KernelTransferReq {
            root,
            nullifiers: vec![nf],
            fee: MIN_TX_FEE,
            cm_1,
            cm_2,
            cm_3,
            enc_1: enc_1.clone(),
            enc_2: enc_2.clone(),
            enc_3: enc_3.clone(),
            proof: sample_kernel_test_proof(),
        };
        let message = encode_external_kernel_message(&KernelInboxMessage::Transfer(req));
        host.inputs.push_back(InputMessage {
            level: 5,
            id: 0,
            payload: message,
        });

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Transfer(TransferResp {
                index_1,
                index_2,
                index_3,
            }) => {
                assert_eq!((index_1, index_2, index_3), (0, 1, 2))
            }
            KernelResult::Error { message } => {
                panic!("transfer failed: {} | debug: {}", message, host.debug)
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.tree.leaves, vec![cm_1, cm_2, cm_3]);
        assert!(ledger.nullifiers.contains(&nf));
        assert!(read_persisted_note(&host, 0).is_some());
        assert!(read_persisted_note(&host, 1).is_some());
        assert!(read_persisted_note(&host, 2).is_some());
        assert!(host.store.contains_key(&nullifier_path(&nf)));
        assert!(host.store.contains_key(&branch_path(0)));
        assert!(host.store.contains_key(&PATH_TREE_ROOT.to_vec()));
        assert!(!host
            .store
            .contains_key(b"/tzel/v1/state/ledger.json".as_slice()));
    }

    #[test]
    fn rejects_transfer_with_duplicate_public_nullifiers_before_state_change() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);

        let address = sample_payment_address();
        let enc_1 = sample_encrypted_note(&address, 11, [0x31; 32], b"one");
        let enc_2 = sample_encrypted_note(&address, 12, [0x32; 32], b"two");
        let enc_3 = sample_encrypted_note(&address, 1, [0x33; 32], b"dal");
        let cm_1 = sample_commitment(&address, 11, [0x31; 32]);
        let cm_2 = sample_commitment(&address, 12, [0x32; 32]);
        let cm_3 = sample_commitment(&address, 1, [0x33; 32]);
        let nf = sample_felt(0x93);
        let root = read_ledger(&host).unwrap().tree.root();

        let req = KernelTransferReq {
            root,
            nullifiers: vec![nf, nf],
            fee: MIN_TX_FEE,
            cm_1,
            cm_2,
            cm_3,
            enc_1,
            enc_2,
            enc_3,
            proof: sample_kernel_test_proof(),
        };
        let message = encode_external_kernel_message(&KernelInboxMessage::Transfer(req));
        host.inputs.push_back(InputMessage {
            level: 5,
            id: 1,
            payload: message,
        });

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => assert!(message.contains("duplicate nullifier")),
            other => panic!("unexpected rollup result: {:?}", other),
        }

        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.tree.leaves.is_empty());
        assert!(ledger.nullifiers.is_empty());
        assert!(!host.store.contains_key(&nullifier_path(&nf)));
        assert!(read_persisted_note(&host, 0).is_none());
    }

    #[test]
    fn applies_unshield_message_with_change_and_records_withdrawal() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);
        install_test_bridge(&mut host);

        let address = sample_payment_address();
        let enc_change = sample_encrypted_note(&address, 7, [0x21; 32], b"change");
        let enc_fee = sample_encrypted_note(&address, 1, [0x22; 32], b"dal");
        let cm_change = sample_commitment(&address, 7, [0x21; 32]);
        let cm_fee = sample_commitment(&address, 1, [0x22; 32]);
        let nf = sample_felt(0xA2);
        let root = read_ledger(&host).unwrap().tree.root();
        let recipient = sample_l1_receiver().to_string();

        let req = KernelUnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 33,
            fee: MIN_TX_FEE,
            recipient: recipient.clone(),
            cm_change,
            enc_change: Some(enc_change.clone()),
            cm_fee,
            enc_fee: enc_fee.clone(),
            proof: sample_kernel_test_proof(),
        };
        let message = encode_external_kernel_message(&KernelInboxMessage::Unshield(req));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 1,
            payload: message,
        });

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Unshield(UnshieldResp {
                change_index,
                producer_index,
            }) => {
                assert_eq!(change_index, Some(0));
                assert_eq!(producer_index, 1);
            }
            KernelResult::Error { message } => {
                panic!("unshield failed: {} | debug: {}", message, host.debug)
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(
            ledger.withdrawals,
            vec![WithdrawalRecord {
                recipient: recipient.clone(),
                amount: 33,
            }]
        );
        assert_eq!(ledger.tree.leaves, vec![cm_change, cm_fee]);
        assert!(ledger.nullifiers.contains(&nf));
        assert!(host.store.contains_key(&nullifier_path(&nf)));
        assert!(read_persisted_note(&host, 0).is_some());
        assert!(read_persisted_note(&host, 1).is_some());
        assert_eq!(host.outputs.len(), 1);
    }

    #[test]
    fn rejects_unshield_with_duplicate_public_nullifiers_before_state_change() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);
        install_test_bridge(&mut host);

        let address = sample_payment_address();
        let enc_change = sample_encrypted_note(&address, 7, [0x41; 32], b"change");
        let enc_fee = sample_encrypted_note(&address, 1, [0x42; 32], b"dal");
        let cm_change = sample_commitment(&address, 7, [0x41; 32]);
        let cm_fee = sample_commitment(&address, 1, [0x42; 32]);
        let nf = sample_felt(0xA3);
        let root = read_ledger(&host).unwrap().tree.root();
        let recipient = sample_l1_receiver().to_string();

        let req = KernelUnshieldReq {
            root,
            nullifiers: vec![nf, nf],
            v_pub: 33,
            fee: MIN_TX_FEE,
            recipient: recipient.clone(),
            cm_change,
            enc_change: Some(enc_change),
            cm_fee,
            enc_fee,
            proof: sample_kernel_test_proof(),
        };
        let message = encode_external_kernel_message(&KernelInboxMessage::Unshield(req));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 2,
            payload: message,
        });

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => assert!(message.contains("duplicate nullifier")),
            other => panic!("unexpected rollup result: {:?}", other),
        }

        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.withdrawals.is_empty());
        assert!(ledger.tree.leaves.is_empty());
        assert!(ledger.nullifiers.is_empty());
        assert!(!host.store.contains_key(&nullifier_path(&nf)));
        assert!(read_persisted_note(&host, 0).is_none());
        assert!(host.outputs.is_empty());
    }

    #[test]
    fn rejects_unshield_to_invalid_l1_recipient() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);
        install_test_bridge(&mut host);

        let address = sample_payment_address();
        let enc_fee = sample_encrypted_note(&address, 1, [0x52; 32], b"dal");
        let cm_fee = sample_commitment(&address, 1, [0x52; 32]);
        let nf = sample_felt(0xA4);
        let root = read_ledger(&host).unwrap().tree.root();

        let req = KernelUnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 33,
            fee: MIN_TX_FEE,
            recipient: "bob".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: sample_kernel_test_proof(),
        };
        let message = encode_external_kernel_message(&KernelInboxMessage::Unshield(req));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 24,
            payload: message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.withdrawals.is_empty());
        assert!(ledger.tree.leaves.is_empty());
        assert!(ledger.nullifiers.is_empty());
        assert!(host.outputs.is_empty());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("invalid L1 withdrawal recipient"));
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn unshield_whitespace_padded_l1_recipient_is_normalized() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);
        install_test_bridge(&mut host);

        let address = sample_payment_address();
        let enc_fee = sample_encrypted_note(&address, 1, [0x53; 32], b"dal");
        let cm_fee = sample_commitment(&address, 1, [0x53; 32]);
        let nf = sample_felt(0xAB);
        let root = read_ledger(&host).unwrap().tree.root();
        let message =
            encode_external_kernel_message(&KernelInboxMessage::Unshield(sample_kernel_unshield_req(
                root,
                vec![nf],
                33,
                " tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx ",
                ZERO,
                None,
                cm_fee,
                enc_fee,
            )));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 25,
            payload: message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(
            ledger.withdrawals,
            vec![WithdrawalRecord {
                recipient: sample_l1_receiver().into(),
                amount: 33,
            }]
        );
        assert!(ledger.nullifiers.contains(&nf));
        assert_eq!(host.outputs.len(), 1);
        match read_last_result(&host).unwrap() {
            KernelResult::Unshield(UnshieldResp {
                change_index,
                producer_index,
            }) => {
                assert_eq!(change_index, None);
                assert_eq!(producer_index, 0);
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn applies_unshield_message_and_emits_outbox_payload() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);
        install_test_bridge(&mut host);

        let address = sample_payment_address();
        let enc_change = sample_encrypted_note(&address, 7, [0x21; 32], b"change");
        let enc_fee = sample_encrypted_note(&address, 1, [0x22; 32], b"dal");
        let cm_change = sample_commitment(&address, 7, [0x21; 32]);
        let cm_fee = sample_commitment(&address, 1, [0x22; 32]);
        let nf = sample_felt(0xA5);
        let root = read_ledger(&host).unwrap().tree.root();

        let message =
            encode_external_kernel_message(&KernelInboxMessage::Unshield(sample_kernel_unshield_req(
                root,
                vec![nf],
                33,
                sample_l1_receiver(),
                cm_change,
                Some(enc_change.clone()),
                cm_fee,
                enc_fee.clone(),
            )));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 2,
            payload: message,
        });

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Unshield(UnshieldResp {
                change_index,
                producer_index,
            }) => {
                assert_eq!(change_index, Some(0));
                assert_eq!(producer_index, 1);
            }
            KernelResult::Error { message } => {
                panic!("unshield failed: {} | debug: {}", message, host.debug)
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(
            ledger.withdrawals,
            vec![WithdrawalRecord {
                recipient: sample_l1_receiver().into(),
                amount: 33,
            }]
        );
        assert_eq!(ledger.tree.leaves, vec![cm_change, cm_fee]);
        assert!(ledger.nullifiers.contains(&nf));
        assert_eq!(host.outputs.len(), 1);
        let outbox = decode_test_withdrawal_outbox(&host.outputs[0]);
        let batch = match outbox {
            TezosOutboxMessage::AtomicTransactionBatch(batch) => batch,
        };
        assert_eq!(batch.len(), 1);
        let tx = &batch[0];
        assert_eq!(tx.destination.to_b58check(), sample_ticketer());
        assert_eq!(tx.entrypoint.name(), "burn");
        assert_eq!(tx.parameters.0 .0.to_b58check(), sample_l1_receiver());
        assert_eq!(tx.parameters.1.creator().0.to_b58check(), sample_ticketer());
        assert_eq!(tx.parameters.1.amount_as::<u64, _>().unwrap(), 33);
    }

    #[test]
    fn unshield_output_failure_does_not_mutate_ledger() {
        let mut host = MockHost::default();
        host.fail_output = Some("outbox full".into());
        install_test_verifier(&mut host);
        install_test_bridge(&mut host);

        let address = sample_payment_address();
        let enc_fee = sample_encrypted_note(&address, 1, [0x31; 32], b"dal");
        let cm_fee = sample_commitment(&address, 1, [0x31; 32]);
        let nf = sample_felt(0xA6);
        let root = read_ledger(&host).unwrap().tree.root();
        let message =
            encode_external_kernel_message(&KernelInboxMessage::Unshield(sample_kernel_unshield_req(
                root,
                vec![nf],
                33,
                sample_l1_receiver(),
                ZERO,
                None,
                cm_fee,
                enc_fee,
            )));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 3,
            payload: message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.withdrawals.is_empty());
        assert!(ledger.tree.leaves.is_empty());
        assert!(ledger.nullifiers.is_empty());
        assert!(host.outputs.is_empty());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => assert!(message.contains("outbox full")),
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn unshield_bad_withdrawal_count_does_not_emit_output_or_mutate_ledger() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);
        install_test_bridge(&mut host);

        let address = sample_payment_address();
        let enc_fee = sample_encrypted_note(&address, 1, [0x34; 32], b"dal");
        let cm_fee = sample_commitment(&address, 1, [0x34; 32]);
        let nf = sample_felt(0xA8);
        let root = read_ledger(&host).unwrap().tree.root();
        host.write_store(PATH_WITHDRAWAL_COUNT, &[0x01]);
        let message =
            encode_external_kernel_message(&KernelInboxMessage::Unshield(sample_kernel_unshield_req(
                root,
                vec![nf],
                33,
                sample_l1_receiver(),
                ZERO,
                None,
                cm_fee,
                enc_fee,
            )));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 30,
            payload: message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.withdrawals.is_empty());
        assert!(ledger.tree.leaves.is_empty());
        assert!(ledger.nullifiers.is_empty());
        assert!(!host.store.contains_key(&nullifier_path(&nf)));
        assert!(read_persisted_note(&host, 0).is_none());
        assert!(host.outputs.is_empty());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("bad u64 at /tzel/v1/state/withdrawals/count"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn unshield_invalid_l1_recipient_does_not_mutate_ledger() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);
        install_test_bridge(&mut host);

        let address = sample_payment_address();
        let enc_fee = sample_encrypted_note(&address, 1, [0x32; 32], b"dal");
        let cm_fee = sample_commitment(&address, 1, [0x32; 32]);
        let nf = sample_felt(0xA7);
        let root = read_ledger(&host).unwrap().tree.root();
        let message =
            encode_external_kernel_message(&KernelInboxMessage::Unshield(sample_kernel_unshield_req(
                root,
                vec![nf],
                33,
                "not-a-contract",
                ZERO,
                None,
                cm_fee,
                enc_fee,
            )));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 4,
            payload: message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.withdrawals.is_empty());
        assert!(ledger.tree.leaves.is_empty());
        assert!(ledger.nullifiers.is_empty());
        assert!(host.outputs.is_empty());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("invalid L1 withdrawal recipient"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn unshield_missing_frontier_does_not_emit_output_or_partial_commit() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);
        install_test_bridge(&mut host);

        let address = sample_payment_address();
        let first_enc_fee = sample_encrypted_note(&address, 1, [0x35; 32], b"dal-1");
        let first_cm_fee = sample_commitment(&address, 1, [0x35; 32]);
        let first_nf = sample_felt(0xA9);
        let first_message =
            encode_external_kernel_message(&KernelInboxMessage::Unshield(sample_kernel_unshield_req(
                read_ledger(&host).unwrap().tree.root(),
                vec![first_nf],
                33,
                sample_l1_receiver(),
                ZERO,
                None,
                first_cm_fee,
                first_enc_fee,
            )));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 31,
            payload: first_message,
        });
        run_with_host(&mut host);
        assert_eq!(host.outputs.len(), 1);

        let second_root = read_ledger(&host).unwrap().tree.root();
        host.store.remove(&branch_path(0));
        let second_enc_fee = sample_encrypted_note(&address, 1, [0x36; 32], b"dal-2");
        let second_cm_fee = sample_commitment(&address, 1, [0x36; 32]);
        let second_nf = sample_felt(0xAA);
        let second_message =
            encode_external_kernel_message(&KernelInboxMessage::Unshield(sample_kernel_unshield_req(
                second_root,
                vec![second_nf],
                34,
                sample_l1_receiver(),
                ZERO,
                None,
                second_cm_fee,
                second_enc_fee,
            )));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 32,
            payload: second_message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(
            ledger.withdrawals,
            vec![WithdrawalRecord {
                recipient: sample_l1_receiver().into(),
                amount: 33,
            }]
        );
        assert_eq!(ledger.tree.leaves.len(), 1);
        assert!(ledger.nullifiers.contains(&first_nf));
        assert!(!ledger.nullifiers.contains(&second_nf));
        assert!(!host.store.contains_key(&nullifier_path(&second_nf)));
        assert!(read_persisted_note(&host, 1).is_none());
        assert_eq!(host.outputs.len(), 1);
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => assert!(
                message.contains("corrupted Merkle frontier")
                    && message.contains("level 0"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn unshield_requires_bridge_configuration_even_with_valid_proof() {
        let mut host = MockHost::default();
        install_test_verifier(&mut host);

        let address = sample_payment_address();
        let enc_fee = sample_encrypted_note(&address, 1, [0x33; 32], b"dal");
        let cm_fee = sample_commitment(&address, 1, [0x33; 32]);
        let nf = sample_felt(0xA8);
        let root = read_ledger(&host).unwrap().tree.root();
        let message =
            encode_external_kernel_message(&KernelInboxMessage::Unshield(sample_kernel_unshield_req(
                root,
                vec![nf],
                33,
                sample_l1_receiver(),
                ZERO,
                None,
                cm_fee,
                enc_fee,
            )));
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 5,
            payload: message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert!(ledger.withdrawals.is_empty());
        assert!(ledger.tree.leaves.is_empty());
        assert!(ledger.nullifiers.is_empty());
        assert!(host.outputs.is_empty());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("bridge ticketer is not configured"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn configures_bridge_ticketer_via_kernel_message() {
        let mut host = MockHost::default();
        let message = encode_external_kernel_message(&signed_bridge_message(KernelBridgeConfig {
            ticketer: sample_ticketer().into(),
        }));
        host.inputs.push_back(InputMessage {
            level: 1,
            id: 0,
            payload: message,
        });

        run_with_host(&mut host);

        let persisted = host
            .read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .expect("bridge ticketer persisted");
        assert_eq!(String::from_utf8(persisted).unwrap(), sample_ticketer());
        assert!(matches!(
            read_last_result(&host).unwrap(),
            KernelResult::Configured
        ));
    }

    #[test]
    fn configures_bridge_ticketer_via_wrapped_external_message() {
        let mut host = MockHost::default();
        host.inputs.push_back(InputMessage {
            level: 1,
            id: 5,
            payload: encode_external_kernel_message(&signed_bridge_message(KernelBridgeConfig {
                ticketer: sample_ticketer().into(),
            })),
        });

        run_with_host(&mut host);

        let persisted = host
            .read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .expect("bridge ticketer persisted");
        assert_eq!(String::from_utf8(persisted).unwrap(), sample_ticketer());
        assert!(matches!(
            read_last_result(&host).unwrap(),
            KernelResult::Configured
        ));
    }

    #[test]
    fn rejects_auth_domain_reconfiguration_after_state_exists() {
        let mut host = MockHost::default();
        let original = KernelVerifierConfig {
            auth_domain: sample_felt(0x33),
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 1,
            payload: encode_external_kernel_message(&signed_verifier_message(original.clone())),
        });
        run_with_host(&mut host);
        {
            let mut state = DurableLedgerState::new(&mut host).unwrap();
            apply_deposit(&mut state, &deposit_recipient_string(&pubkey_hash_from_label("alice")), 1).unwrap();
        }

        let new_domain = sample_felt(0x44);
        let reconfigured = KernelVerifierConfig {
            auth_domain: new_domain,
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        let message = encode_external_kernel_message(&signed_verifier_message(reconfigured));
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
                assert!(
                    message.contains("auth_domain is frozen"),
                    "unexpected error: {}",
                    message
                )
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn configures_auth_domain_on_pristine_ledger() {
        let mut host = MockHost::default();
        let new_domain = sample_felt(0x55);
        let config = KernelVerifierConfig {
            auth_domain: new_domain,
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        let message = encode_external_kernel_message(&signed_verifier_message(config));
        host.inputs.push_back(InputMessage {
            level: 8,
            id: 1,
            payload: message,
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.auth_domain, new_domain);
        assert!(matches!(
            read_last_result(&host).unwrap(),
            KernelResult::Configured
        ));
    }

    #[test]
    fn auth_domain_is_frozen_after_first_configuration_even_on_pristine_ledger() {
        // Freezing auth_domain after the first install closes a deposit-stranding
        // race: a wallet that read auth_domain D and submitted an L1 ticket
        // computed with D would otherwise be silently broken if an admin
        // reconfigured to D' before the ticket lands.
        let mut host = MockHost::default();
        let initial_domain = sample_felt(0x55);
        let initial = KernelVerifierConfig {
            auth_domain: initial_domain,
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        host.inputs.push_back(InputMessage {
            level: 1,
            id: 0,
            payload: encode_external_kernel_message(&signed_verifier_message(initial)),
        });
        // Reconfigure the program hashes only — same auth_domain — should
        // succeed (still pristine).
        let new_hashes = ProgramHashes {
            shield: hash(b"new-shield"),
            transfer: hash(b"new-transfer"),
            unshield: hash(b"new-unshield"),
        };
        let same_domain_new_hashes = KernelVerifierConfig {
            auth_domain: initial_domain,
            verified_program_hashes: new_hashes.clone(),
            operator_producer_owner_tag: ZERO,
        };
        host.inputs.push_back(InputMessage {
            level: 2,
            id: 0,
            payload: encode_external_kernel_message(&signed_verifier_message(
                same_domain_new_hashes.clone(),
            )),
        });
        // Reconfigure with a different auth_domain — must be rejected by
        // the freeze rule even though the ledger is still pristine.
        let new_domain = sample_felt(0x66);
        let different_domain = KernelVerifierConfig {
            auth_domain: new_domain,
            verified_program_hashes: new_hashes,
            operator_producer_owner_tag: ZERO,
        };
        host.inputs.push_back(InputMessage {
            level: 3,
            id: 0,
            payload: encode_external_kernel_message(&signed_verifier_message(different_domain)),
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(
            ledger.auth_domain, initial_domain,
            "auth_domain must remain frozen after first install"
        );
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => assert!(
                message.contains("auth_domain is frozen"),
                "unexpected error: {}",
                message
            ),
            other => panic!("expected freeze error, got: {:?}", other),
        }
    }

    #[test]
    fn rejects_bridge_deposit_before_verifier_configuration() {
        let mut host = MockHost::default();
        install_test_bridge(&mut host);
        let deposit_key = deposit_recipient_string(&pubkey_hash_from_label("alice"));

        host.inputs.push_back(InputMessage {
            level: 8,
            id: 1,
            payload: encode_ticket_deposit_message(&deposit_key, 12),
        });

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => assert!(
                message.contains("bridge deposits not accepted before verifier configuration"),
                "unexpected error: {}",
                message
            ),
            other => panic!("expected error result, got {:?}", other),
        }
    }

    #[test]
    fn accepts_bridge_deposit_after_verifier_configuration() {
        let mut host = MockHost::default();
        install_test_bridge(&mut host);
        let deposit_key = deposit_recipient_string(&pubkey_hash_from_label("alice"));
        let config = KernelVerifierConfig {
            auth_domain: sample_felt(0x57),
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };

        host.inputs.push_back(InputMessage {
            level: 8,
            id: 1,
            payload: encode_external_kernel_message(&signed_verifier_message(config.clone())),
        });
        host.inputs.push_back(InputMessage {
            level: 9,
            id: 2,
            payload: encode_ticket_deposit_message(&deposit_key, 12),
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.auth_domain, config.auth_domain);
        let balance_path =
            deposit_balance_path(&pubkey_hash_from_label("alice"));
        let bytes = host.read_store(&balance_path, 8).expect("balance entry");
        assert_eq!(u64::from_le_bytes(bytes.try_into().unwrap()), 12);
        assert!(matches!(
            read_last_result(&host).unwrap(),
            KernelResult::Deposit
        ));
    }

    #[test]
    fn rejects_unauthenticated_verifier_configuration_on_pristine_ledger() {
        let mut signed = sign_kernel_verifier_config(
            &sample_config_admin_ask(),
            KernelVerifierConfig {
                auth_domain: sample_felt(0x56),
                verified_program_hashes: sample_program_hashes(),
                operator_producer_owner_tag: ZERO,
            },
        )
        .unwrap();
        signed.config.auth_domain[0] ^= 0x01;

        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 8,
            id: 1,
            payload: encode_external_kernel_message(&KernelInboxMessage::ConfigureVerifier(signed)),
        }]);

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.auth_domain, default_auth_domain());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("configuration signature verification failed"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_verifier_hash_reconfiguration_after_state_exists() {
        let mut host = MockHost::default();
        let original = KernelVerifierConfig {
            auth_domain: default_auth_domain(),
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        host.inputs.push_back(InputMessage {
            level: 6,
            id: 1,
            payload: encode_external_kernel_message(&signed_verifier_message(original.clone())),
        });
        run_with_host(&mut host);
        {
            let mut state = DurableLedgerState::new(&mut host).unwrap();
            apply_deposit(&mut state, &deposit_recipient_string(&pubkey_hash_from_label("alice")), 1).unwrap();
        }
        let mut changed_hashes = original.verified_program_hashes;
        changed_hashes.transfer = sample_felt(0x99);
        host.inputs.push_back(InputMessage {
            level: 8,
            id: 3,
            payload: encode_external_kernel_message(&signed_verifier_message(KernelVerifierConfig {
                auth_domain: original.auth_domain,
                verified_program_hashes: changed_hashes,
                operator_producer_owner_tag: ZERO,
            })),
        });

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.auth_domain, original.auth_domain);
        // Pre-existing balance remains; reconfiguration was rejected.
        let balance_path =
            deposit_balance_path(&pubkey_hash_from_label("alice"));
        let bytes = host.read_store(&balance_path, 8).expect("balance entry");
        assert_eq!(u64::from_le_bytes(bytes.try_into().unwrap()), 1);
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("cannot change verifier configuration"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_unauthenticated_bridge_configuration_on_pristine_ledger() {
        let mut signed = sign_kernel_bridge_config(
            &sample_config_admin_ask(),
            KernelBridgeConfig {
                ticketer: sample_ticketer().into(),
            },
        )
        .unwrap();
        signed.config.ticketer = "KT1XnKX3m3GGdcRGi8HAY3N3H6LrZb6bS4wQ".into();

        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 5,
            id: 1,
            payload: encode_external_kernel_message(&KernelInboxMessage::ConfigureBridge(signed)),
        }]);

        run_with_host(&mut host);

        assert!(host
            .read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .is_none());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("configuration signature verification failed"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_missing_verifier_configuration_for_proof_messages() {
        let address = sample_payment_address();
        let producer_fee = 1;
        let producer_rseed = sample_felt(0x36);
        let producer_enc = sample_encrypted_note(&address, producer_fee, producer_rseed, b"dal");
        let producer_cm = sample_commitment(&address, producer_fee, producer_rseed);
        let client_rseed = sample_felt(0x37);
        let client_enc = sample_encrypted_note(&address, 50, client_rseed, b"shield");
        let client_cm = sample_commitment(&address, 50, client_rseed);
        let shield_req = KernelShieldReq {
            pubkey_hash: pubkey_hash_from_label("alice"),
            fee: MIN_TX_FEE,
            producer_fee,
            v: 50,
            proof: sample_verified_kernel_proof(),
            client_cm,
            client_enc,
            producer_cm,
            producer_enc,
        };
        let message = encode_external_kernel_message(&KernelInboxMessage::Shield(shield_req));
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

        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("invalid inbox message"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[cfg(not(feature = "proof-verifier"))]
    #[test]
    fn rejects_verified_proofs_when_kernel_build_lacks_verifier_support() {
        let config = KernelVerifierConfig {
            auth_domain: sample_felt(0x55),
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        let mut host = MockHost::with_inputs(vec![
            InputMessage {
                level: 8,
                id: 1,
                payload: encode_external_kernel_message(&signed_verifier_message(config.clone())),
            },
            InputMessage {
                level: 9,
                id: 2,
                payload: encode_external_kernel_message(&KernelInboxMessage::Shield(
                    KernelShieldReq {
                        pubkey_hash: pubkey_hash_from_label("alice"),
                        v: 50,
                        fee: MIN_TX_FEE,
                        producer_fee: 1,
                        proof: sample_verified_kernel_proof(),
                        client_cm: sample_felt(0x71),
                        client_enc: sample_encrypted_note(
                            &sample_payment_address(),
                            50,
                            sample_felt(0x72),
                            b"alice-recipient",
                        ),
                        producer_cm: sample_felt(0x73),
                        producer_enc: sample_encrypted_note(
                            &sample_payment_address(),
                            1,
                            sample_felt(0x74),
                            b"alice-producer",
                        ),
                    },
                )),
            },
        ]);

        run_with_host(&mut host);

        let ledger = read_ledger(&host).unwrap();
        assert_eq!(ledger.auth_domain, config.auth_domain);
        assert!(ledger.tree.leaves.is_empty());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("kernel built without proof verifier support"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[cfg(feature = "proof-verifier")]
    #[test]
    fn rejects_invalid_stark_proof_shape_before_transition() {
        let config = KernelVerifierConfig {
            auth_domain: default_auth_domain(),
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        let verifier = DirectProofVerifier::from_kernel_config(&config).unwrap();

        let proof = KernelStarkProof {
            proof_bytes: vec![0x00, 0x11, 0x22],
            output_preimage: vec![[9u8; 32], [10u8; 32]],
        };

        let err = verifier
            .validate_kernel(&proof, tzel_core::CircuitKind::Transfer)
            .unwrap_err();
        assert!(
            err.contains("invalid output_preimage")
                || err.contains("zstd decompress")
                || err.contains("circuit verification FAILED"),
            "unexpected verifier error: {}",
            err
        );
    }

    #[test]
    fn rejects_deposit_from_unexpected_ticketer() {
        let mut host = MockHost::default();
        install_test_bridge(&mut host);
        host.inputs.push_back(InputMessage {
            level: 9,
            id: 0,
            payload: encode_custom_ticket_deposit_message(
                b"alice".to_vec(),
                12,
                sample_other_ticketer(),
                sample_other_ticketer(),
                0,
                None,
                sample_rollup_address(),
            ),
        });

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("unexpected ticketer"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_ticket_deposit_before_bridge_configuration() {
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 9,
            id: 9,
            payload: encode_ticket_deposit_message("alice", 12),
        }]);

        run_with_host(&mut host);

        assert!(host
            .read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .is_none());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("bridge ticketer is not configured"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_ticket_deposit_with_nonzero_token_id() {
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 10,
            id: 1,
            payload: encode_custom_ticket_deposit_message(
                b"alice".to_vec(),
                12,
                sample_ticketer(),
                sample_ticketer(),
                1,
                None,
                sample_rollup_address(),
            ),
        }]);

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("token_id must be 0"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_ticket_deposit_with_creator_sender_mismatch() {
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 10,
            id: 4,
            payload: encode_custom_ticket_deposit_message(
                b"alice".to_vec(),
                12,
                sample_other_ticketer(),
                sample_ticketer(),
                0,
                None,
                sample_rollup_address(),
            ),
        }]);

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("creator does not match transfer sender"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_ticket_deposit_with_metadata() {
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 10,
            id: 2,
            payload: encode_custom_ticket_deposit_message(
                b"alice".to_vec(),
                12,
                sample_ticketer(),
                sample_ticketer(),
                0,
                Some(vec![0xAA]),
                sample_rollup_address(),
            ),
        }]);

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("metadata must be None"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_ticket_deposit_with_non_utf8_recipient() {
        let mut host = MockHost::with_inputs(vec![InputMessage {
            level: 10,
            id: 3,
            payload: encode_custom_ticket_deposit_message(
                vec![0xFF, 0xFE],
                12,
                sample_ticketer(),
                sample_ticketer(),
                0,
                None,
                sample_rollup_address(),
            ),
        }]);

        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("receiver is not UTF-8"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_implicit_bridge_ticketer_configuration() {
        let mut host = MockHost::default();
        let message = encode_external_kernel_message(&signed_bridge_message(KernelBridgeConfig {
            ticketer: sample_l1_receiver().into(),
        }));
        host.inputs.push_back(InputMessage {
            level: 11,
            id: 0,
            payload: message,
        });

        run_with_host(&mut host);

        assert!(host
            .read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .is_none());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("must be a KT1 contract"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn rejects_bridge_ticketer_reconfiguration_after_state_exists() {
        let mut host = MockHost::default();
        install_test_bridge(&mut host);
        {
            let mut state = DurableLedgerState::new(&mut host).unwrap();
            apply_deposit(&mut state, &deposit_recipient_string(&pubkey_hash_from_label("alice")), 3).unwrap();
        }

        let message = encode_external_kernel_message(&signed_bridge_message(KernelBridgeConfig {
            ticketer: sample_other_ticketer().into(),
        }));
        host.inputs.push_back(InputMessage {
            level: 12,
            id: 0,
            payload: message,
        });

        run_with_host(&mut host);

        let persisted = host
            .read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .expect("bridge ticketer persists");
        assert_eq!(String::from_utf8(persisted).unwrap(), sample_ticketer());
        match read_last_result(&host).unwrap() {
            KernelResult::Error { message } => {
                assert!(message.contains("cannot change bridge ticketer"))
            }
            other => panic!("unexpected rollup result: {:?}", other),
        }
    }

    #[test]
    fn allows_bridge_ticketer_reconfiguration_to_same_value_after_state_exists() {
        let mut host = MockHost::default();
        install_test_bridge(&mut host);
        {
            let mut state = DurableLedgerState::new(&mut host).unwrap();
            apply_deposit(&mut state, &deposit_recipient_string(&pubkey_hash_from_label("alice")), 3).unwrap();
        }

        let message = encode_external_kernel_message(&signed_bridge_message(KernelBridgeConfig {
            ticketer: sample_ticketer().into(),
        }));
        host.inputs.push_back(InputMessage {
            level: 12,
            id: 1,
            payload: message,
        });

        run_with_host(&mut host);

        let persisted = host
            .read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .expect("bridge ticketer persists");
        assert_eq!(String::from_utf8(persisted).unwrap(), sample_ticketer());
        // Pre-existing pool balance remained through bridge reconfiguration.
        let balance_path =
            deposit_balance_path(&pubkey_hash_from_label("alice"));
        assert!(host.read_store(&balance_path, 8).is_some());
        assert!(matches!(
            read_last_result(&host).unwrap(),
            KernelResult::Configured
        ));
    }

    #[test]
    fn dust_deposit_to_same_pubkey_hash_aggregates_balance() {
        // Two L1 ticket deposits to the same `deposit:<pubkey_hash>`
        // recipient aggregate into one balance pool. Under the deposit-pool
        // design, dust no longer creates a separate "slot" — it just adds
        // to the user's pool balance, which the user (sole holder of the
        // auth tree) can drain in a single shield.
        let mut host = MockHost::default();
        install_test_bridge(&mut host);
        install_test_verifier(&mut host);
        let pubkey_hash = pubkey_hash_from_label("alice");
        let recipient = deposit_recipient_string(&pubkey_hash);
        host.inputs.push_back(InputMessage {
            level: 13,
            id: 0,
            payload: encode_ticket_deposit_message(&recipient, 100_000),
        });
        host.inputs.push_back(InputMessage {
            level: 13,
            id: 1,
            payload: encode_ticket_deposit_message(&recipient, 1),
        });

        run_with_host(&mut host);

        // Single aggregated balance: 100_000 + 1.
        let balance_path = deposit_balance_path(&pubkey_hash);
        let bytes = host.read_store(&balance_path, 8).expect("balance entry");
        assert_eq!(u64::from_le_bytes(bytes.try_into().unwrap()), 100_001);
    }

    #[test]
    fn pool_can_be_redeposited_after_full_drain() {
        // Regression: when a pool is drained to 0, the kernel writes an
        // empty value at the balance path as a best-effort delete on the
        // WASM PVM (which has no native delete primitive). A subsequent
        // L1 deposit to that pool must treat the empty read as absence
        // and credit a fresh balance, not error out with `bad u64 at ...`.
        let mut host = MockHost::default();
        install_test_bridge(&mut host);
        install_test_verifier(&mut host);
        let pubkey_hash = pubkey_hash_from_label("alice");
        let balance_path = deposit_balance_path(&pubkey_hash);

        // Simulate the post-drain state: the apply step writes empty bytes.
        host.write_store(&balance_path, &[]);
        // Same shape `read_ledger` and the wallet treat as None.
        assert_eq!(host.read_store(&balance_path, 8).map(|b| b.len()), Some(0));

        // A fresh L1 ticket deposit to the drained pool must succeed.
        let recipient = deposit_recipient_string(&pubkey_hash);
        host.inputs.push_back(InputMessage {
            level: 14,
            id: 0,
            payload: encode_ticket_deposit_message(&recipient, 7_777),
        });
        run_with_host(&mut host);

        match read_last_result(&host).unwrap() {
            KernelResult::Deposit => {}
            other => panic!("redeposit after drain should succeed: {:?}", other),
        }
        let bytes = host
            .read_store(&balance_path, 8)
            .expect("balance entry after redeposit");
        assert_eq!(u64::from_le_bytes(bytes.try_into().unwrap()), 7_777);
    }

    #[test]
    fn withdrawal_record_roundtrip_and_decode_guards() {
        let record = WithdrawalRecord {
            recipient: sample_l1_receiver().into(),
            amount: 33,
        };
        let encoded = encode_withdrawal_record(&record);
        assert_eq!(decode_withdrawal_record(&encoded).unwrap(), record);

        assert!(decode_withdrawal_record(&encoded[..11])
            .unwrap_err()
            .contains("too short"));

        let mut bad_len = encoded.clone();
        bad_len[8..12].copy_from_slice(&(999u32).to_le_bytes());
        assert!(decode_withdrawal_record(&bad_len)
            .unwrap_err()
            .contains("length mismatch"));

        let mut bad_utf8 = encode_withdrawal_record(&WithdrawalRecord {
            recipient: "ok".into(),
            amount: 1,
        });
        bad_utf8[12] = 0xFF;
        assert!(decode_withdrawal_record(&bad_utf8)
            .unwrap_err()
            .contains("not UTF-8"));
    }

    #[test]
    fn read_ledger_rejects_bad_persisted_auth_domain_length() {
        let mut host = MockHost::default();
        host.write_store(PATH_AUTH_DOMAIN, &[1u8; 31]);

        let err = match read_ledger(&host) {
            Ok(_) => panic!("bad auth_domain must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("bad persisted auth_domain"));
    }

    #[test]
    fn read_ledger_rejects_missing_persisted_note() {
        let mut host = MockHost::default();
        host.write_store(PATH_TREE_SIZE, &1u64.to_le_bytes());

        let err = match read_ledger(&host) {
            Ok(_) => panic!("missing persisted note must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("missing persisted note 0"));
    }

    #[test]
    fn read_ledger_rejects_bad_persisted_nullifier_width() {
        let mut host = MockHost::default();
        host.write_store(PATH_NULLIFIER_COUNT, &1u64.to_le_bytes());
        host.write_store(&indexed_path(PATH_NULLIFIER_INDEX_PREFIX, 0), &[7u8; 31]);

        let err = match read_ledger(&host) {
            Ok(_) => panic!("bad persisted nullifier width must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("bad persisted nullifier 0"));
    }

    #[test]
    fn read_ledger_rejects_bad_persisted_root_width() {
        let mut host = MockHost::default();
        host.write_store(PATH_VALID_ROOT_COUNT, &1u64.to_le_bytes());
        host.write_store(&indexed_path(PATH_VALID_ROOT_INDEX_PREFIX, 0), &[9u8; 31]);

        let err = match read_ledger(&host) {
            Ok(_) => panic!("bad persisted root width must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("bad persisted root 0"));
    }

    #[test]
    fn read_ledger_rejects_missing_persisted_withdrawal() {
        let mut host = MockHost::default();
        host.write_store(PATH_WITHDRAWAL_COUNT, &1u64.to_le_bytes());

        let err = match read_ledger(&host) {
            Ok(_) => panic!("missing persisted withdrawal must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("missing persisted withdrawal 0"));
    }

    #[test]
    fn read_ledger_rejects_bad_persisted_withdrawal_record() {
        let mut host = MockHost::default();
        host.write_store(PATH_WITHDRAWAL_COUNT, &1u64.to_le_bytes());
        host.write_store(&indexed_path(PATH_WITHDRAWAL_PREFIX, 0), &[1u8; 11]);

        let err = match read_ledger(&host) {
            Ok(_) => panic!("bad persisted withdrawal record must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("withdrawal record too short"));
    }

    #[test]
    fn read_last_input_returns_none_when_payload_is_missing() {
        let mut host = MockHost::default();
        host.write_store(PATH_LAST_INPUT_LEVEL, &7i32.to_le_bytes());
        host.write_store(PATH_LAST_INPUT_ID, &3i32.to_le_bytes());
        host.write_store(PATH_LAST_INPUT_LEN, &4u32.to_le_bytes());

        assert!(read_last_input(&host).is_none());
    }

    #[test]
    fn read_verifier_config_rejects_invalid_bytes() {
        let mut host = MockHost::default();
        host.write_store(PATH_VERIFIER_CONFIG, &[0x01, 0x02, 0x03]);

        assert!(read_verifier_config(&host).is_err());
    }

    #[test]
    fn read_last_result_ignores_invalid_bytes() {
        let mut host = MockHost::default();
        host.write_store(PATH_LAST_RESULT, &[0xFF, 0x00, 0xAA]);

        assert!(read_last_result(&host).is_none());
    }

    fn sample_payment_address() -> PaymentAddress {
        let mut master_sk = [0u8; 32];
        master_sk[0] = 7;
        let account = derive_account(&master_sk);
        let d_j = derive_address(&account.incoming_seed, 0);
        let ask_j = derive_ask(&account.ask_base, 0);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let auth_root = hash_two(&felt_tag(b"kernel-auth"), &hash_two(&d_j, &auth_pub_seed));
        let nk_spend = derive_nk_spend(&account.nk, &d_j);
        let nk_tag = derive_nk_tag(&nk_spend);
        let (ek_v, _, ek_d, _) = derive_kem_keys(&account.incoming_seed, 0);
        PaymentAddress {
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        }
    }

    fn install_test_verifier(host: &mut MockHost) {
        let config = KernelVerifierConfig {
            auth_domain: default_auth_domain(),
            verified_program_hashes: sample_program_hashes(),
            operator_producer_owner_tag: ZERO,
        };
        host.write_store(
            PATH_VERIFIER_CONFIG,
            &encode_kernel_verifier_config(&config).unwrap(),
        );
    }

    fn sample_ticketer() -> &'static str {
        "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc"
    }

    fn sample_other_ticketer() -> &'static str {
        "KT1RJ6PbjHpwc3M5rw5s2Nbmefwbuwbdxton"
    }

    fn sample_l1_receiver() -> &'static str {
        "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx"
    }

    fn sample_l1_source() -> PublicKeyHash {
        PublicKeyHash::from_b58check("tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN").unwrap()
    }

    fn sample_kernel_unshield_req(
        root: F,
        nullifiers: Vec<F>,
        v_pub: u64,
        recipient: &str,
        cm_change: F,
        enc_change: Option<EncryptedNote>,
        cm_fee: F,
        enc_fee: EncryptedNote,
    ) -> KernelUnshieldReq {
        KernelUnshieldReq {
            root,
            nullifiers,
            v_pub,
            fee: MIN_TX_FEE,
            recipient: recipient.into(),
            cm_change,
            enc_change,
            cm_fee,
            enc_fee,
            proof: sample_kernel_test_proof(),
        }
    }

    fn sample_rollup_address() -> SmartRollupAddress {
        SmartRollupAddress::from_b58check("sr1UNDWPUYVeomgG15wn5jSw689EJ4RNnVQa").unwrap()
    }

    fn sample_other_rollup_address() -> SmartRollupAddress {
        SmartRollupAddress::from_b58check("sr1UXY5i5Z1sF8xd8ZUyzur827MAaFWREzvj").unwrap()
    }

    fn install_test_bridge(host: &mut MockHost) {
        let message = encode_external_kernel_message(&signed_bridge_message(KernelBridgeConfig {
            ticketer: sample_ticketer().into(),
        }));
        host.inputs.push_back(InputMessage {
            level: 0,
            id: 0,
            payload: message,
        });
        run_with_host(host);
    }

    fn install_mock_dal_payload(
        host: &mut MockHost,
        published_level: i32,
        slot_index: u8,
        page_size: usize,
        slot_size: usize,
        payload: &[u8],
    ) -> KernelDalChunkPointer {
        install_mock_dal_payload_chunks(
            host,
            &[(published_level, slot_index)],
            page_size,
            slot_size,
            payload,
        )
        .into_iter()
        .next()
        .expect("single DAL chunk")
    }

    fn install_mock_dal_payload_chunks(
        host: &mut MockHost,
        chunk_specs: &[(i32, u8)],
        page_size: usize,
        slot_size: usize,
        payload: &[u8],
    ) -> Vec<KernelDalChunkPointer> {
        assert!(page_size > 0);
        assert!(slot_size > 0);
        host.dal_parameters = Some(DalParameters {
            number_of_slots: chunk_specs
                .iter()
                .map(|(_, slot_index)| u64::from(*slot_index))
                .max()
                .unwrap_or(0)
                + 1,
            attestation_lag: 8,
            slot_size: slot_size as u64,
            page_size: page_size as u64,
        });

        let mut pointers = Vec::new();
        let mut offset = 0usize;
        for (chunk_index, (published_level, slot_index)) in chunk_specs.iter().enumerate() {
            if offset >= payload.len() {
                break;
            }
            let remaining = payload.len() - offset;
            let chunk_len = remaining.min(slot_size);
            let chunk = &payload[offset..offset + chunk_len];
            let page_count = chunk_len.div_ceil(page_size);
            for page_index in 0..page_count {
                let start = page_index * page_size;
                let end = (start + page_size).min(chunk_len);
                let mut page = vec![0u8; page_size];
                page[..end - start].copy_from_slice(&chunk[start..end]);
                host.dal_pages.insert(
                    (
                        *published_level,
                        *slot_index,
                        u16::try_from(page_index).expect("page index fits in u16"),
                    ),
                    page,
                );
            }
            pointers.push(KernelDalChunkPointer {
                published_level: u64::try_from(*published_level)
                    .expect("published level must be non-negative"),
                slot_index: *slot_index,
                payload_len: chunk_len as u64,
            });
            offset += chunk_len;
            if chunk_index + 1 == chunk_specs.len() && offset < payload.len() {
                panic!("insufficient DAL chunk specs for payload");
            }
        }
        if offset < payload.len() {
            panic!("insufficient DAL chunk specs for payload");
        }
        pointers
    }

    fn encode_ticket_deposit_message(recipient: &str, amount: u64) -> Vec<u8> {
        encode_ticket_deposit_message_for_rollup(recipient, amount, sample_rollup_address())
    }

    fn encode_ticket_deposit_message_for_rollup(
        recipient: &str,
        amount: u64,
        destination: SmartRollupAddress,
    ) -> Vec<u8> {
        encode_custom_ticket_deposit_message(
            recipient.as_bytes().to_vec(),
            amount,
            sample_ticketer(),
            sample_ticketer(),
            0,
            None,
            destination,
        )
    }

    fn encode_custom_ticket_deposit_message(
        recipient: Vec<u8>,
        amount: u64,
        creator_ticketer: &str,
        sender_ticketer: &str,
        token_id: i32,
        metadata: Option<Vec<u8>>,
        destination: SmartRollupAddress,
    ) -> Vec<u8> {
        let creator = TezosContract::from_b58check(creator_ticketer).unwrap();
        let sender_contract = TezosContract::from_b58check(sender_ticketer).unwrap();
        let sender = match sender_contract {
            TezosContract::Originated(kt1) => kt1,
            TezosContract::Implicit(_) => panic!("ticketer must be KT1"),
        };
        let payload = MichelsonPair(
            MichelsonBytes(recipient),
            FA2_1Ticket::new(
                creator,
                MichelsonPair(
                    MichelsonInt::from(token_id),
                    MichelsonOption(metadata.map(MichelsonBytes)),
                ),
                amount,
            )
            .unwrap(),
        );
        let transfer = TezosTransfer {
            payload,
            sender,
            source: sample_l1_source(),
            destination,
        };
        let mut bytes = Vec::new();
        TezosInboxMessage::Internal(TezosInternalInboxMessage::Transfer(transfer))
            .serialize(&mut bytes)
            .unwrap();
        bytes
    }

    fn encode_external_kernel_message(message: &KernelInboxMessage) -> Vec<u8> {
        encode_external_kernel_message_for_rollup(sample_rollup_address(), message)
    }

    fn encode_external_kernel_message_for_rollup(
        rollup: SmartRollupAddress,
        message: &KernelInboxMessage,
    ) -> Vec<u8> {
        let payload = tzel_core::kernel_wire::encode_kernel_inbox_message(message).unwrap();
        let mut framed = Vec::new();
        ExternalMessageFrame::Targetted {
            address: rollup,
            contents: payload.as_slice(),
        }
        .bin_write(&mut framed)
        .unwrap();
        let mut bytes = Vec::new();
        TezosInboxMessage::<MichelsonUnit>::External(framed.as_slice())
            .serialize(&mut bytes)
            .unwrap();
        bytes
    }

    fn decode_test_withdrawal_outbox(
        bytes: &[u8],
    ) -> TezosOutboxMessage<MichelsonPair<MichelsonContract, FA2_1Ticket>> {
        let (rest, decoded) =
            TezosOutboxMessage::<MichelsonPair<MichelsonContract, FA2_1Ticket>>::nom_read(bytes)
                .expect("valid outbox encoding");
        assert!(rest.is_empty(), "outbox encoding should consume all bytes");
        decoded
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
        }
    }

    fn sample_verified_kernel_proof() -> KernelStarkProof {
        KernelStarkProof {
            proof_bytes: vec![0x00, 0x11, 0x22],
            output_preimage: vec![[9u8; 32], [10u8; 32]],
        }
    }

    fn sample_felt(fill: u8) -> F {
        let mut out = [fill; 32];
        out[31] &= 0x07;
        out
    }

    fn sample_config_admin_ask() -> F {
        hash(b"tzel-dev-rollup-config-admin")
    }

    fn signed_bridge_message(config: KernelBridgeConfig) -> KernelInboxMessage {
        KernelInboxMessage::ConfigureBridge(
            sign_kernel_bridge_config(&sample_config_admin_ask(), config).unwrap(),
        )
    }

    fn signed_verifier_message(config: KernelVerifierConfig) -> KernelInboxMessage {
        KernelInboxMessage::ConfigureVerifier(
            sign_kernel_verifier_config(&sample_config_admin_ask(), config).unwrap(),
        )
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
            &owner_tag(&address.auth_root, &address.auth_pub_seed, &address.nk_tag),
        )
    }
}
