use crate::canonical_wire::{
    decode_tze, encode_tze, felt_to_wire, u16_to_wire, u64_to_wire, wire_to_felt, wire_to_u16,
    wire_to_u64, WireEncryptedNote, WireFelt, WirePaymentAddress, WireU16Le, WireU64Le,
};
use crate::{
    hash, wots_sign, EncryptedNote, PaymentAddress, ProgramHashes, Proof, ShieldReq, ShieldResp,
    TransferReq, TransferResp, UnshieldReq, UnshieldResp, WithdrawReq, WithdrawResp,
    ENCRYPTED_NOTE_BYTES, F, ML_KEM768_CIPHERTEXT_BYTES, NOTE_AEAD_NONCE_BYTES,
};
use tezos_data_encoding::enc::BinWriter;
use tezos_data_encoding::encoding::HasEncoding;
use tezos_data_encoding::nom::NomReader;

// v10: KernelDalPayloadKind gained ConfigureVerifier (tag 3) and
//      ConfigureBridge (tag 4) variants.
pub const KERNEL_WIRE_VERSION: u16 = 10;
pub const KERNEL_VERIFIER_CONFIG_KEY_INDEX: u32 = 0;
pub const KERNEL_BRIDGE_CONFIG_KEY_INDEX: u32 = 1;
const MAX_ACCOUNT_ID_BYTES: usize = 1024;
const MAX_MEMO_BYTES: usize = 4096;
const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;
const MAX_OUTPUT_PREIMAGE_ITEMS: usize = 1024;
const MAX_VERIFY_META_BYTES: usize = 8 * 1024 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 4096;
const MAX_DAL_CHUNK_POINTERS: usize = 256;
const MAX_DAL_CHUNK_LIST_BYTES: usize = 64 * 1024;
const MAX_ENCODED_NOTE_WIRE_BYTES: usize =
    (ML_KEM768_CIPHERTEXT_BYTES * 2) + NOTE_AEAD_NONCE_BYTES + ENCRYPTED_NOTE_BYTES + 32;
const MAX_ENCODED_PROOF_WIRE_BYTES: usize =
    MAX_PROOF_BYTES + MAX_VERIFY_META_BYTES + (MAX_OUTPUT_PREIMAGE_ITEMS * 64) + 4096;
const MAX_ENCODED_NULLIFIER_LIST_BYTES: usize = 256 * 1024;
const MAX_TRANSFER_PAYLOAD_BYTES: usize =
    (5 * 32) + MAX_ENCODED_PROOF_WIRE_BYTES + (3 * MAX_ENCODED_NOTE_WIRE_BYTES) + 65536;
const MAX_UNSHIELD_PAYLOAD_BYTES: usize =
    (4 * 32) + MAX_ENCODED_PROOF_WIRE_BYTES + (2 * MAX_ENCODED_NOTE_WIRE_BYTES) + 65536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVerifierConfig {
    pub auth_domain: F,
    pub verified_program_hashes: ProgramHashes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSignedVerifierConfig {
    pub config: KernelVerifierConfig,
    pub signature: Vec<F>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelBridgeConfig {
    pub ticketer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSignedBridgeConfig {
    pub config: KernelBridgeConfig,
    pub signature: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct KernelStarkProof {
    pub proof_bytes: Vec<u8>,
    pub output_preimage: Vec<F>,
    pub verify_meta: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct KernelShieldReq {
    pub sender: String,
    pub fee: u64,
    pub v: u64,
    pub producer_fee: u64,
    pub address: PaymentAddress,
    pub memo: Option<String>,
    pub proof: KernelStarkProof,
    pub client_cm: F,
    pub client_enc: Option<EncryptedNote>,
    pub producer_cm: F,
    pub producer_enc: Option<EncryptedNote>,
}

#[derive(Debug, Clone)]
pub struct KernelTransferReq {
    pub root: F,
    pub nullifiers: Vec<F>,
    pub fee: u64,
    pub cm_1: F,
    pub cm_2: F,
    pub cm_3: F,
    pub enc_1: EncryptedNote,
    pub enc_2: EncryptedNote,
    pub enc_3: EncryptedNote,
    pub proof: KernelStarkProof,
}

#[derive(Debug, Clone)]
pub struct KernelUnshieldReq {
    pub root: F,
    pub nullifiers: Vec<F>,
    pub v_pub: u64,
    pub fee: u64,
    pub recipient: String,
    pub cm_change: F,
    pub enc_change: Option<EncryptedNote>,
    pub cm_fee: F,
    pub enc_fee: EncryptedNote,
    pub proof: KernelStarkProof,
}

#[derive(Debug, Clone)]
pub struct KernelWithdrawReq {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelDalPayloadKind {
    Shield,
    Transfer,
    Unshield,
    /// Admin configuration of the STARK verifier.  Carried via DAL because
    /// the WOTS-signed payload exceeds `sc_rollup_message_size_limit`
    /// (4096 bytes).  See the size sentinel in the `tests` module.
    ConfigureVerifier,
    /// Admin configuration of the bridge ticketer.  Also WOTS-signed and
    /// therefore oversized for the L1 inbox — routed via DAL for the same
    /// reason.
    ConfigureBridge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelDalChunkPointer {
    pub published_level: u64,
    pub slot_index: u8,
    pub payload_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelDalPayloadPointer {
    pub kind: KernelDalPayloadKind,
    pub chunks: Vec<KernelDalChunkPointer>,
    pub payload_len: u64,
    pub payload_hash: F,
}

#[derive(Debug, Clone)]
pub enum KernelInboxMessage {
    ConfigureVerifier(KernelSignedVerifierConfig),
    ConfigureBridge(KernelSignedBridgeConfig),
    Shield(KernelShieldReq),
    Transfer(KernelTransferReq),
    Unshield(KernelUnshieldReq),
    Withdraw(KernelWithdrawReq),
    DalPointer(KernelDalPayloadPointer),
}

#[derive(Debug, Clone)]
pub enum KernelResult {
    Configured,
    Deposit,
    Shield(ShieldResp),
    Transfer(TransferResp),
    Unshield(UnshieldResp),
    Withdraw(WithdrawResp),
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireProgramHashes {
    shield: WireFelt,
    transfer: WireFelt,
    unshield: WireFelt,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireFeltList {
    #[encoding(dynamic)]
    items: Vec<WireFelt>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireEncodedNote {
    #[encoding(dynamic = "MAX_ENCODED_NOTE_WIRE_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireEncodedProof {
    #[encoding(dynamic = "MAX_ENCODED_PROOF_WIRE_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireEncodedFeltList {
    #[encoding(dynamic = "MAX_ENCODED_NULLIFIER_LIST_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireEncodedDalChunkList {
    #[encoding(dynamic = "MAX_DAL_CHUNK_LIST_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WireStarkProof {
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelVerifierConfig {
    auth_domain: WireFelt,
    verified_program_hashes: WireProgramHashes,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireSignedKernelVerifierConfig {
    config: WireKernelVerifierConfig,
    signature: WireEncodedFeltList,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelBridgeConfig {
    #[encoding(string = "MAX_ACCOUNT_ID_BYTES")]
    ticketer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireSignedKernelBridgeConfig {
    config: WireKernelBridgeConfig,
    signature: WireEncodedFeltList,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelShieldReq {
    #[encoding(string = "MAX_ACCOUNT_ID_BYTES")]
    sender: String,
    fee: WireU64Le,
    v: WireU64Le,
    producer_fee: WireU64Le,
    address: WirePaymentAddress,
    #[encoding(string = "MAX_MEMO_BYTES")]
    memo: Option<String>,
    proof: WireEncodedProof,
    client_cm: WireFelt,
    client_enc: Option<WireEncryptedNote>,
    producer_cm: WireFelt,
    producer_enc: Option<WireEncryptedNote>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireShieldResp {
    cm: WireFelt,
    index: WireU64Le,
    producer_cm: WireFelt,
    producer_index: WireU64Le,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelTransferReq {
    #[encoding(dynamic = "MAX_TRANSFER_PAYLOAD_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireTransferResp {
    index_1: WireU64Le,
    index_2: WireU64Le,
    index_3: WireU64Le,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelUnshieldReq {
    #[encoding(dynamic = "MAX_UNSHIELD_PAYLOAD_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelWithdrawReq {
    #[encoding(string = "MAX_ACCOUNT_ID_BYTES")]
    sender: String,
    #[encoding(string = "MAX_ACCOUNT_ID_BYTES")]
    recipient: String,
    amount: WireU64Le,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
#[encoding(tags = "u8")]
// Tag assignments here are independent of `WireKernelInboxMessage` below:
// a `KernelDalPayloadKind` labels a *DAL-routed* message by category,
// whereas `WireKernelInboxMessage` tags every kernel inbox message
// including ones that never transit through DAL (Withdraw, DalPointer).
// Do not assume numeric correspondence between the two spaces.
enum WireKernelDalPayloadKind {
    #[encoding(tag = 0)]
    Shield,
    #[encoding(tag = 1)]
    Transfer,
    #[encoding(tag = 2)]
    Unshield,
    #[encoding(tag = 3)]
    ConfigureVerifier,
    #[encoding(tag = 4)]
    ConfigureBridge,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelDalChunkPointer {
    published_level: WireU64Le,
    slot_index: u8,
    payload_len: WireU64Le,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelDalChunkList {
    #[encoding(dynamic = "MAX_DAL_CHUNK_POINTERS")]
    items: Vec<WireKernelDalChunkPointer>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelDalPayloadPointer {
    kind: WireKernelDalPayloadKind,
    chunks: WireEncodedDalChunkList,
    payload_hash: WireFelt,
    payload_len: WireU64Le,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireUnshieldResp {
    change_index: Option<WireU64Le>,
    producer_index: WireU64Le,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireWithdrawResp {
    withdrawal_index: WireU64Le,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireErrorMessage {
    #[encoding(string = "MAX_ERROR_MESSAGE_BYTES")]
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireAccountId {
    #[encoding(string = "MAX_ACCOUNT_ID_BYTES")]
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireOptionalEncodedNote {
    note: Option<WireEncodedNote>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
#[encoding(tags = "u8")]
enum WireKernelInboxMessage {
    #[encoding(tag = 0)]
    ConfigureVerifier(WireSignedKernelVerifierConfig),
    #[encoding(tag = 1)]
    ConfigureBridge(WireSignedKernelBridgeConfig),
    #[encoding(tag = 2)]
    Shield(WireKernelShieldReq),
    #[encoding(tag = 3)]
    Transfer(WireKernelTransferReq),
    #[encoding(tag = 4)]
    Unshield(WireKernelUnshieldReq),
    #[encoding(tag = 5)]
    Withdraw(WireKernelWithdrawReq),
    #[encoding(tag = 6)]
    DalPointer(WireKernelDalPayloadPointer),
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelInboxEnvelope {
    version: WireU16Le,
    message: WireKernelInboxMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
#[encoding(tags = "u8")]
enum WireKernelResult {
    #[encoding(tag = 0)]
    Configured,
    #[encoding(tag = 1)]
    Deposit,
    #[encoding(tag = 2)]
    Shield(WireShieldResp),
    #[encoding(tag = 3)]
    Transfer(WireTransferResp),
    #[encoding(tag = 4)]
    Unshield(WireUnshieldResp),
    #[encoding(tag = 5)]
    Withdraw(WireWithdrawResp),
    #[encoding(tag = 255)]
    Error(WireErrorMessage),
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelResultEnvelope {
    version: WireU16Le,
    result: WireKernelResult,
}

pub fn encode_kernel_inbox_message(message: &KernelInboxMessage) -> Result<Vec<u8>, String> {
    encode_tze(&WireKernelInboxEnvelope {
        version: u16_to_wire(KERNEL_WIRE_VERSION),
        message: match message {
            KernelInboxMessage::ConfigureVerifier(cfg) => {
                WireKernelInboxMessage::ConfigureVerifier(signed_config_to_wire(cfg)?)
            }
            KernelInboxMessage::ConfigureBridge(cfg) => {
                WireKernelInboxMessage::ConfigureBridge(signed_bridge_config_to_wire(cfg)?)
            }
            KernelInboxMessage::Shield(req) => {
                WireKernelInboxMessage::Shield(kernel_shield_req_to_wire(req)?)
            }
            KernelInboxMessage::Transfer(req) => {
                WireKernelInboxMessage::Transfer(kernel_transfer_req_to_wire(req)?)
            }
            KernelInboxMessage::Unshield(req) => {
                WireKernelInboxMessage::Unshield(kernel_unshield_req_to_wire(req)?)
            }
            KernelInboxMessage::Withdraw(req) => {
                WireKernelInboxMessage::Withdraw(kernel_withdraw_req_to_wire(req))
            }
            KernelInboxMessage::DalPointer(pointer) => {
                WireKernelInboxMessage::DalPointer(kernel_dal_payload_pointer_to_wire(pointer)?)
            }
        },
    })
}

pub fn decode_kernel_inbox_message(bytes: &[u8]) -> Result<KernelInboxMessage, String> {
    let wire: WireKernelInboxEnvelope = decode_tze(bytes)?;
    let version = wire_to_u16(wire.version)?;
    if version != KERNEL_WIRE_VERSION {
        return Err(format!(
            "unsupported kernel inbox wire version: got {}, expected {}",
            version, KERNEL_WIRE_VERSION
        ));
    }
    match wire.message {
        WireKernelInboxMessage::ConfigureVerifier(cfg) => Ok(
            KernelInboxMessage::ConfigureVerifier(signed_config_from_wire(cfg)?),
        ),
        WireKernelInboxMessage::ConfigureBridge(cfg) => Ok(KernelInboxMessage::ConfigureBridge(
            signed_bridge_config_from_wire(cfg)?,
        )),
        WireKernelInboxMessage::Shield(req) => Ok(KernelInboxMessage::Shield(
            kernel_shield_req_from_wire(req)?,
        )),
        WireKernelInboxMessage::Transfer(req) => Ok(KernelInboxMessage::Transfer(
            kernel_transfer_req_from_wire(req)?,
        )),
        WireKernelInboxMessage::Unshield(req) => Ok(KernelInboxMessage::Unshield(
            kernel_unshield_req_from_wire(req)?,
        )),
        WireKernelInboxMessage::Withdraw(req) => Ok(KernelInboxMessage::Withdraw(
            kernel_withdraw_req_from_wire(req)?,
        )),
        WireKernelInboxMessage::DalPointer(pointer) => Ok(KernelInboxMessage::DalPointer(
            kernel_dal_payload_pointer_from_wire(pointer)?,
        )),
    }
}

pub fn encode_kernel_result(result: &KernelResult) -> Result<Vec<u8>, String> {
    encode_tze(&WireKernelResultEnvelope {
        version: u16_to_wire(KERNEL_WIRE_VERSION),
        result: match result {
            KernelResult::Configured => WireKernelResult::Configured,
            KernelResult::Deposit => WireKernelResult::Deposit,
            KernelResult::Shield(resp) => WireKernelResult::Shield(shield_resp_to_wire(resp)?),
            KernelResult::Transfer(resp) => {
                WireKernelResult::Transfer(transfer_resp_to_wire(resp)?)
            }
            KernelResult::Unshield(resp) => {
                WireKernelResult::Unshield(unshield_resp_to_wire(resp)?)
            }
            KernelResult::Withdraw(resp) => {
                WireKernelResult::Withdraw(withdraw_resp_to_wire(resp)?)
            }
            KernelResult::Error { message } => WireKernelResult::Error(WireErrorMessage {
                message: message.clone(),
            }),
        },
    })
}

pub fn decode_kernel_result(bytes: &[u8]) -> Result<KernelResult, String> {
    let wire: WireKernelResultEnvelope = decode_tze(bytes)?;
    let version = wire_to_u16(wire.version)?;
    if version != KERNEL_WIRE_VERSION {
        return Err(format!(
            "unsupported kernel result wire version: got {}, expected {}",
            version, KERNEL_WIRE_VERSION
        ));
    }
    match wire.result {
        WireKernelResult::Configured => Ok(KernelResult::Configured),
        WireKernelResult::Deposit => Ok(KernelResult::Deposit),
        WireKernelResult::Shield(resp) => Ok(KernelResult::Shield(shield_resp_from_wire(resp)?)),
        WireKernelResult::Transfer(resp) => {
            Ok(KernelResult::Transfer(transfer_resp_from_wire(resp)?))
        }
        WireKernelResult::Unshield(resp) => {
            Ok(KernelResult::Unshield(unshield_resp_from_wire(resp)?))
        }
        WireKernelResult::Withdraw(resp) => {
            Ok(KernelResult::Withdraw(withdraw_resp_from_wire(resp)?))
        }
        WireKernelResult::Error(err) => Ok(KernelResult::Error {
            message: err.message,
        }),
    }
}

pub fn encode_kernel_verifier_config(config: &KernelVerifierConfig) -> Result<Vec<u8>, String> {
    encode_tze(&config_to_wire(config))
}

pub fn kernel_verifier_config_sighash(config: &KernelVerifierConfig) -> Result<F, String> {
    let encoded = encode_kernel_verifier_config(config)?;
    let mut payload = b"tzel-config-verifier".to_vec();
    payload.extend_from_slice(&encoded);
    Ok(hash(&payload))
}

pub fn kernel_bridge_config_sighash(config: &KernelBridgeConfig) -> Result<F, String> {
    let encoded = encode_tze(&bridge_config_to_wire(config))?;
    let mut payload = b"tzel-config-bridge".to_vec();
    payload.extend_from_slice(&encoded);
    Ok(hash(&payload))
}

pub fn sign_kernel_verifier_config(
    ask: &F,
    config: KernelVerifierConfig,
) -> Result<KernelSignedVerifierConfig, String> {
    let sighash = kernel_verifier_config_sighash(&config)?;
    Ok(KernelSignedVerifierConfig {
        config,
        signature: wots_sign(ask, KERNEL_VERIFIER_CONFIG_KEY_INDEX, &sighash).0,
    })
}

pub fn sign_kernel_bridge_config(
    ask: &F,
    config: KernelBridgeConfig,
) -> Result<KernelSignedBridgeConfig, String> {
    let sighash = kernel_bridge_config_sighash(&config)?;
    Ok(KernelSignedBridgeConfig {
        config,
        signature: wots_sign(ask, KERNEL_BRIDGE_CONFIG_KEY_INDEX, &sighash).0,
    })
}

pub fn decode_kernel_verifier_config(bytes: &[u8]) -> Result<KernelVerifierConfig, String> {
    let wire: WireKernelVerifierConfig = decode_tze(bytes)?;
    config_from_wire(wire)
}

fn decode_tze_prefix<'a, T>(bytes: &'a [u8]) -> Result<(&'a [u8], T), String>
where
    T: NomReader<'a>,
{
    T::nom_read(bytes).map_err(|e| format!("tezos_data_encoding read failed: {:?}", e))
}

fn take_u32_be_len(bytes: &mut &[u8], label: &str) -> Result<usize, String> {
    let raw = take_bytes(bytes, 4, label)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(raw);
    Ok(u32::from_be_bytes(buf) as usize)
}

fn take_bytes<'a>(bytes: &mut &'a [u8], len: usize, label: &str) -> Result<&'a [u8], String> {
    if bytes.len() < len {
        return Err(format!(
            "kernel proof payload truncated while reading {}: need {} bytes, have {}",
            label,
            len,
            bytes.len()
        ));
    }
    let (head, tail) = bytes.split_at(len);
    *bytes = tail;
    Ok(head)
}

pub fn kernel_proof_to_host(proof: &KernelStarkProof) -> Proof {
    Proof::Stark {
        proof_bytes: proof.proof_bytes.clone(),
        output_preimage: proof.output_preimage.clone(),
        verify_meta: Some(proof.verify_meta.clone()),
    }
}

pub fn kernel_shield_req_to_host(req: &KernelShieldReq) -> ShieldReq {
    ShieldReq {
        sender: req.sender.clone(),
        fee: req.fee,
        v: req.v,
        producer_fee: req.producer_fee,
        address: req.address.clone(),
        memo: req.memo.clone(),
        proof: kernel_proof_to_host(&req.proof),
        client_cm: req.client_cm,
        client_enc: req.client_enc.clone(),
        producer_cm: req.producer_cm,
        producer_enc: req.producer_enc.clone(),
    }
}

pub fn kernel_transfer_req_to_host(req: &KernelTransferReq) -> TransferReq {
    TransferReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        fee: req.fee,
        cm_1: req.cm_1,
        cm_2: req.cm_2,
        cm_3: req.cm_3,
        enc_1: req.enc_1.clone(),
        enc_2: req.enc_2.clone(),
        enc_3: req.enc_3.clone(),
        proof: kernel_proof_to_host(&req.proof),
    }
}

pub fn kernel_unshield_req_to_host(req: &KernelUnshieldReq) -> UnshieldReq {
    UnshieldReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        v_pub: req.v_pub,
        fee: req.fee,
        recipient: req.recipient.clone(),
        cm_change: req.cm_change,
        enc_change: req.enc_change.clone(),
        cm_fee: req.cm_fee,
        enc_fee: req.enc_fee.clone(),
        proof: kernel_proof_to_host(&req.proof),
    }
}

pub fn kernel_withdraw_req_to_host(req: &KernelWithdrawReq) -> WithdrawReq {
    WithdrawReq {
        sender: req.sender.clone(),
        recipient: req.recipient.clone(),
        amount: req.amount,
    }
}

fn config_to_wire(config: &KernelVerifierConfig) -> WireKernelVerifierConfig {
    WireKernelVerifierConfig {
        auth_domain: felt_to_wire(&config.auth_domain),
        verified_program_hashes: program_hashes_to_wire(&config.verified_program_hashes),
    }
}

fn signed_config_to_wire(
    config: &KernelSignedVerifierConfig,
) -> Result<WireSignedKernelVerifierConfig, String> {
    Ok(WireSignedKernelVerifierConfig {
        config: config_to_wire(&config.config),
        signature: encoded_felt_list_to_wire(&config.signature)?,
    })
}

fn config_from_wire(wire: WireKernelVerifierConfig) -> Result<KernelVerifierConfig, String> {
    Ok(KernelVerifierConfig {
        auth_domain: wire_to_felt(wire.auth_domain)?,
        verified_program_hashes: program_hashes_from_wire(wire.verified_program_hashes)?,
    })
}

fn signed_config_from_wire(
    wire: WireSignedKernelVerifierConfig,
) -> Result<KernelSignedVerifierConfig, String> {
    Ok(KernelSignedVerifierConfig {
        config: config_from_wire(wire.config)?,
        signature: encoded_felt_list_from_wire(wire.signature)?,
    })
}

fn bridge_config_to_wire(config: &KernelBridgeConfig) -> WireKernelBridgeConfig {
    WireKernelBridgeConfig {
        ticketer: config.ticketer.clone(),
    }
}

fn signed_bridge_config_to_wire(
    config: &KernelSignedBridgeConfig,
) -> Result<WireSignedKernelBridgeConfig, String> {
    Ok(WireSignedKernelBridgeConfig {
        config: bridge_config_to_wire(&config.config),
        signature: encoded_felt_list_to_wire(&config.signature)?,
    })
}

fn bridge_config_from_wire(wire: WireKernelBridgeConfig) -> Result<KernelBridgeConfig, String> {
    Ok(KernelBridgeConfig {
        ticketer: wire.ticketer,
    })
}

fn signed_bridge_config_from_wire(
    wire: WireSignedKernelBridgeConfig,
) -> Result<KernelSignedBridgeConfig, String> {
    Ok(KernelSignedBridgeConfig {
        config: bridge_config_from_wire(wire.config)?,
        signature: encoded_felt_list_from_wire(wire.signature)?,
    })
}

fn kernel_dal_payload_kind_to_wire(kind: &KernelDalPayloadKind) -> WireKernelDalPayloadKind {
    match kind {
        KernelDalPayloadKind::Shield => WireKernelDalPayloadKind::Shield,
        KernelDalPayloadKind::Transfer => WireKernelDalPayloadKind::Transfer,
        KernelDalPayloadKind::Unshield => WireKernelDalPayloadKind::Unshield,
        KernelDalPayloadKind::ConfigureVerifier => WireKernelDalPayloadKind::ConfigureVerifier,
        KernelDalPayloadKind::ConfigureBridge => WireKernelDalPayloadKind::ConfigureBridge,
    }
}

fn kernel_dal_payload_kind_from_wire(
    kind: WireKernelDalPayloadKind,
) -> Result<KernelDalPayloadKind, String> {
    Ok(match kind {
        WireKernelDalPayloadKind::Shield => KernelDalPayloadKind::Shield,
        WireKernelDalPayloadKind::Transfer => KernelDalPayloadKind::Transfer,
        WireKernelDalPayloadKind::Unshield => KernelDalPayloadKind::Unshield,
        WireKernelDalPayloadKind::ConfigureVerifier => KernelDalPayloadKind::ConfigureVerifier,
        WireKernelDalPayloadKind::ConfigureBridge => KernelDalPayloadKind::ConfigureBridge,
    })
}

fn kernel_dal_chunk_pointer_to_wire(pointer: &KernelDalChunkPointer) -> WireKernelDalChunkPointer {
    WireKernelDalChunkPointer {
        published_level: u64_to_wire(pointer.published_level),
        slot_index: pointer.slot_index,
        payload_len: u64_to_wire(pointer.payload_len),
    }
}

fn kernel_dal_chunk_pointer_from_wire(
    wire: WireKernelDalChunkPointer,
) -> Result<KernelDalChunkPointer, String> {
    Ok(KernelDalChunkPointer {
        published_level: wire_to_u64(wire.published_level)?,
        slot_index: wire.slot_index,
        payload_len: wire_to_u64(wire.payload_len)?,
    })
}

fn kernel_dal_payload_pointer_to_wire(
    pointer: &KernelDalPayloadPointer,
) -> Result<WireKernelDalPayloadPointer, String> {
    if pointer.chunks.is_empty() {
        return Err("kernel DAL pointer requires at least one chunk".into());
    }
    if pointer.chunks.len() > MAX_DAL_CHUNK_POINTERS {
        return Err(format!(
            "kernel DAL pointer has too many chunks: {} > {}",
            pointer.chunks.len(),
            MAX_DAL_CHUNK_POINTERS
        ));
    }
    let chunks = pointer
        .chunks
        .iter()
        .map(kernel_dal_chunk_pointer_to_wire)
        .collect::<Vec<_>>();
    Ok(WireKernelDalPayloadPointer {
        kind: kernel_dal_payload_kind_to_wire(&pointer.kind),
        chunks: WireEncodedDalChunkList {
            bytes: encode_tze(&WireKernelDalChunkList { items: chunks })?,
        },
        payload_hash: felt_to_wire(&pointer.payload_hash),
        payload_len: u64_to_wire(pointer.payload_len),
    })
}

fn kernel_dal_payload_pointer_from_wire(
    wire: WireKernelDalPayloadPointer,
) -> Result<KernelDalPayloadPointer, String> {
    let chunks: WireKernelDalChunkList = decode_tze(&wire.chunks.bytes)?;
    if chunks.items.is_empty() {
        return Err("kernel DAL pointer requires at least one chunk".into());
    }
    if chunks.items.len() > MAX_DAL_CHUNK_POINTERS {
        return Err(format!(
            "kernel DAL pointer has too many chunks: {} > {}",
            chunks.items.len(),
            MAX_DAL_CHUNK_POINTERS
        ));
    }
    Ok(KernelDalPayloadPointer {
        kind: kernel_dal_payload_kind_from_wire(wire.kind)?,
        chunks: chunks
            .items
            .into_iter()
            .map(kernel_dal_chunk_pointer_from_wire)
            .collect::<Result<Vec<_>, _>>()?,
        payload_hash: wire_to_felt(wire.payload_hash)?,
        payload_len: wire_to_u64(wire.payload_len)?,
    })
}

fn program_hashes_to_wire(hashes: &ProgramHashes) -> WireProgramHashes {
    WireProgramHashes {
        shield: felt_to_wire(&hashes.shield),
        transfer: felt_to_wire(&hashes.transfer),
        unshield: felt_to_wire(&hashes.unshield),
    }
}

fn program_hashes_from_wire(wire: WireProgramHashes) -> Result<ProgramHashes, String> {
    Ok(ProgramHashes {
        shield: wire_to_felt(wire.shield)?,
        transfer: wire_to_felt(wire.transfer)?,
        unshield: wire_to_felt(wire.unshield)?,
    })
}

fn payment_address_to_wire(address: &PaymentAddress) -> WirePaymentAddress {
    WirePaymentAddress {
        d_j: felt_to_wire(&address.d_j),
        auth_root: felt_to_wire(&address.auth_root),
        auth_pub_seed: felt_to_wire(&address.auth_pub_seed),
        nk_tag: felt_to_wire(&address.nk_tag),
        ek_v: address.ek_v.clone(),
        ek_d: address.ek_d.clone(),
    }
}

fn payment_address_from_wire(wire: WirePaymentAddress) -> Result<PaymentAddress, String> {
    Ok(PaymentAddress {
        d_j: wire_to_felt(wire.d_j)?,
        auth_root: wire_to_felt(wire.auth_root)?,
        auth_pub_seed: wire_to_felt(wire.auth_pub_seed)?,
        nk_tag: wire_to_felt(wire.nk_tag)?,
        ek_v: wire.ek_v,
        ek_d: wire.ek_d,
    })
}

fn encrypted_note_to_wire(enc: &EncryptedNote) -> Result<WireEncryptedNote, String> {
    enc.validate()?;
    Ok(WireEncryptedNote {
        ct_d: enc.ct_d.clone(),
        tag: u16_to_wire(enc.tag),
        ct_v: enc.ct_v.clone(),
        nonce: enc.nonce.clone(),
        encrypted_data: enc.encrypted_data.clone(),
    })
}

fn encrypted_note_from_wire(wire: WireEncryptedNote) -> Result<EncryptedNote, String> {
    let enc = EncryptedNote {
        ct_d: wire.ct_d,
        tag: wire_to_u16(wire.tag)?,
        ct_v: wire.ct_v,
        nonce: wire.nonce,
        encrypted_data: wire.encrypted_data,
    };
    enc.validate()?;
    Ok(enc)
}

fn kernel_proof_to_wire(proof: &KernelStarkProof) -> Result<WireStarkProof, String> {
    if proof.proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(format!(
            "proof too large for kernel wire: {} > {}",
            proof.proof_bytes.len(),
            MAX_PROOF_BYTES
        ));
    }
    if proof.output_preimage.len() > MAX_OUTPUT_PREIMAGE_ITEMS {
        return Err(format!(
            "output_preimage too long for kernel wire: {} > {}",
            proof.output_preimage.len(),
            MAX_OUTPUT_PREIMAGE_ITEMS
        ));
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(proof.proof_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&proof.proof_bytes);
    bytes.extend_from_slice(&(proof.output_preimage.len() as u32).to_be_bytes());
    for felt in &proof.output_preimage {
        bytes.extend_from_slice(felt);
    }
    if proof.verify_meta.len() > MAX_VERIFY_META_BYTES {
        return Err(format!(
            "verify_meta too large for kernel wire: {} > {}",
            proof.verify_meta.len(),
            MAX_VERIFY_META_BYTES
        ));
    }
    bytes.extend_from_slice(&(proof.verify_meta.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&proof.verify_meta);
    Ok(WireStarkProof { bytes })
}

fn kernel_proof_from_wire(proof: WireStarkProof) -> Result<KernelStarkProof, String> {
    let mut rest = proof.bytes.as_slice();

    let proof_len = take_u32_be_len(&mut rest, "proof_bytes length")?;
    if proof_len > MAX_PROOF_BYTES {
        return Err(format!(
            "proof too large for kernel wire: {} > {}",
            proof_len, MAX_PROOF_BYTES
        ));
    }
    let proof_bytes = take_bytes(&mut rest, proof_len, "proof_bytes")?.to_vec();

    let output_preimage_len = take_u32_be_len(&mut rest, "output_preimage length")?;
    if output_preimage_len > MAX_OUTPUT_PREIMAGE_ITEMS {
        return Err(format!(
            "output_preimage too long for kernel wire: {} > {}",
            output_preimage_len, MAX_OUTPUT_PREIMAGE_ITEMS
        ));
    }
    let mut output_preimage = Vec::with_capacity(output_preimage_len);
    for _ in 0..output_preimage_len {
        let felt_bytes = take_bytes(&mut rest, 32, "output_preimage felt")?;
        let mut felt = [0u8; 32];
        felt.copy_from_slice(felt_bytes);
        output_preimage.push(felt);
    }

    let verify_meta_len = take_u32_be_len(&mut rest, "verify_meta length")?;
    if verify_meta_len > MAX_VERIFY_META_BYTES {
        return Err(format!(
            "verify_meta too large for kernel wire: {} > {}",
            verify_meta_len, MAX_VERIFY_META_BYTES
        ));
    }
    let verify_meta = take_bytes(&mut rest, verify_meta_len, "verify_meta")?.to_vec();

    if !rest.is_empty() {
        return Err(format!(
            "kernel proof payload left {} trailing bytes",
            rest.len()
        ));
    }
    Ok(KernelStarkProof {
        proof_bytes,
        output_preimage,
        verify_meta,
    })
}

fn encoded_note_to_wire(enc: &EncryptedNote) -> Result<WireEncodedNote, String> {
    Ok(WireEncodedNote {
        bytes: encode_tze(&encrypted_note_to_wire(enc)?)?,
    })
}

fn encoded_note_from_wire(wire: WireEncodedNote) -> Result<EncryptedNote, String> {
    let inner: WireEncryptedNote = decode_tze(&wire.bytes)?;
    encrypted_note_from_wire(inner)
}

fn encoded_proof_to_wire(proof: &KernelStarkProof) -> Result<WireEncodedProof, String> {
    Ok(WireEncodedProof {
        bytes: kernel_proof_to_wire(proof)?.bytes,
    })
}

fn encoded_proof_from_wire(wire: WireEncodedProof) -> Result<KernelStarkProof, String> {
    kernel_proof_from_wire(WireStarkProof { bytes: wire.bytes })
}

fn encoded_felt_list_to_wire(values: &[F]) -> Result<WireEncodedFeltList, String> {
    Ok(WireEncodedFeltList {
        bytes: encode_tze(&WireFeltList {
            items: values.iter().map(felt_to_wire).collect(),
        })?,
    })
}

fn encoded_felt_list_from_wire(wire: WireEncodedFeltList) -> Result<Vec<F>, String> {
    let inner: WireFeltList = decode_tze(&wire.bytes)?;
    inner
        .items
        .into_iter()
        .map(wire_to_felt)
        .collect::<Result<Vec<_>, _>>()
}

fn kernel_shield_req_to_wire(req: &KernelShieldReq) -> Result<WireKernelShieldReq, String> {
    Ok(WireKernelShieldReq {
        sender: req.sender.clone(),
        fee: u64_to_wire(req.fee),
        v: u64_to_wire(req.v),
        producer_fee: u64_to_wire(req.producer_fee),
        address: payment_address_to_wire(&req.address),
        memo: req.memo.clone(),
        proof: encoded_proof_to_wire(&req.proof)?,
        client_cm: felt_to_wire(&req.client_cm),
        client_enc: req
            .client_enc
            .as_ref()
            .map(encrypted_note_to_wire)
            .transpose()?,
        producer_cm: felt_to_wire(&req.producer_cm),
        producer_enc: req
            .producer_enc
            .as_ref()
            .map(encrypted_note_to_wire)
            .transpose()?,
    })
}

fn kernel_shield_req_from_wire(wire: WireKernelShieldReq) -> Result<KernelShieldReq, String> {
    Ok(KernelShieldReq {
        sender: wire.sender,
        fee: wire_to_u64(wire.fee)?,
        v: wire_to_u64(wire.v)?,
        producer_fee: wire_to_u64(wire.producer_fee)?,
        address: payment_address_from_wire(wire.address)?,
        memo: wire.memo,
        proof: encoded_proof_from_wire(wire.proof)?,
        client_cm: wire_to_felt(wire.client_cm)?,
        client_enc: wire.client_enc.map(encrypted_note_from_wire).transpose()?,
        producer_cm: wire_to_felt(wire.producer_cm)?,
        producer_enc: wire
            .producer_enc
            .map(encrypted_note_from_wire)
            .transpose()?,
    })
}

fn shield_resp_to_wire(resp: &ShieldResp) -> Result<WireShieldResp, String> {
    Ok(WireShieldResp {
        cm: felt_to_wire(&resp.cm),
        index: u64_to_wire(
            resp.index
                .try_into()
                .map_err(|_| "shield index does not fit in u64".to_string())?,
        ),
        producer_cm: felt_to_wire(&resp.producer_cm),
        producer_index: u64_to_wire(
            resp.producer_index
                .try_into()
                .map_err(|_| "shield producer_index does not fit in u64".to_string())?,
        ),
    })
}

fn shield_resp_from_wire(wire: WireShieldResp) -> Result<ShieldResp, String> {
    Ok(ShieldResp {
        cm: wire_to_felt(wire.cm)?,
        index: wire_to_u64(wire.index)?
            .try_into()
            .map_err(|_| "shield index does not fit in usize".to_string())?,
        producer_cm: wire_to_felt(wire.producer_cm)?,
        producer_index: wire_to_u64(wire.producer_index)?
            .try_into()
            .map_err(|_| "shield producer_index does not fit in usize".to_string())?,
    })
}

fn kernel_transfer_req_to_wire(req: &KernelTransferReq) -> Result<WireKernelTransferReq, String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.root))?);
    bytes.extend_from_slice(&encode_tze(&encoded_felt_list_to_wire(&req.nullifiers)?)?);
    bytes.extend_from_slice(&encode_tze(&u64_to_wire(req.fee))?);
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.cm_1))?);
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.cm_2))?);
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.cm_3))?);
    bytes.extend_from_slice(&encode_tze(&encoded_proof_to_wire(&req.proof)?)?);
    bytes.extend_from_slice(&encode_tze(&encoded_note_to_wire(&req.enc_1)?)?);
    bytes.extend_from_slice(&encode_tze(&encoded_note_to_wire(&req.enc_2)?)?);
    bytes.extend_from_slice(&encode_tze(&encoded_note_to_wire(&req.enc_3)?)?);
    Ok(WireKernelTransferReq { bytes })
}

fn kernel_transfer_req_from_wire(wire: WireKernelTransferReq) -> Result<KernelTransferReq, String> {
    let (rest, root) = decode_tze_prefix::<WireFelt>(&wire.bytes)?;
    let (rest, nullifiers) = decode_tze_prefix::<WireEncodedFeltList>(rest)?;
    let (rest, fee) = decode_tze_prefix::<WireU64Le>(rest)?;
    let (rest, cm_1) = decode_tze_prefix::<WireFelt>(rest)?;
    let (rest, cm_2) = decode_tze_prefix::<WireFelt>(rest)?;
    let (rest, cm_3) = decode_tze_prefix::<WireFelt>(rest)?;
    let (rest, proof) = decode_tze_prefix::<WireEncodedProof>(rest)?;
    let (rest, enc_1) = decode_tze_prefix::<WireEncodedNote>(rest)?;
    let (rest, enc_2) = decode_tze_prefix::<WireEncodedNote>(rest)?;
    let (rest, enc_3) = decode_tze_prefix::<WireEncodedNote>(rest)?;
    if !rest.is_empty() {
        return Err(format!(
            "kernel transfer payload left {} trailing bytes",
            rest.len()
        ));
    }
    Ok(KernelTransferReq {
        root: wire_to_felt(root)?,
        nullifiers: encoded_felt_list_from_wire(nullifiers)?,
        fee: wire_to_u64(fee)?,
        cm_1: wire_to_felt(cm_1)?,
        cm_2: wire_to_felt(cm_2)?,
        cm_3: wire_to_felt(cm_3)?,
        proof: encoded_proof_from_wire(proof)?,
        enc_1: encoded_note_from_wire(enc_1)?,
        enc_2: encoded_note_from_wire(enc_2)?,
        enc_3: encoded_note_from_wire(enc_3)?,
    })
}

fn transfer_resp_to_wire(resp: &TransferResp) -> Result<WireTransferResp, String> {
    Ok(WireTransferResp {
        index_1: u64_to_wire(
            resp.index_1
                .try_into()
                .map_err(|_| "transfer index_1 does not fit in u64".to_string())?,
        ),
        index_2: u64_to_wire(
            resp.index_2
                .try_into()
                .map_err(|_| "transfer index_2 does not fit in u64".to_string())?,
        ),
        index_3: u64_to_wire(
            resp.index_3
                .try_into()
                .map_err(|_| "transfer index_3 does not fit in u64".to_string())?,
        ),
    })
}

fn transfer_resp_from_wire(wire: WireTransferResp) -> Result<TransferResp, String> {
    Ok(TransferResp {
        index_1: wire_to_u64(wire.index_1)?
            .try_into()
            .map_err(|_| "transfer index_1 does not fit in usize".to_string())?,
        index_2: wire_to_u64(wire.index_2)?
            .try_into()
            .map_err(|_| "transfer index_2 does not fit in usize".to_string())?,
        index_3: wire_to_u64(wire.index_3)?
            .try_into()
            .map_err(|_| "transfer index_3 does not fit in usize".to_string())?,
    })
}

fn kernel_unshield_req_to_wire(req: &KernelUnshieldReq) -> Result<WireKernelUnshieldReq, String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.root))?);
    bytes.extend_from_slice(&encode_tze(&encoded_felt_list_to_wire(&req.nullifiers)?)?);
    bytes.extend_from_slice(&encode_tze(&u64_to_wire(req.v_pub))?);
    bytes.extend_from_slice(&encode_tze(&u64_to_wire(req.fee))?);
    bytes.extend_from_slice(&encode_tze(&WireAccountId {
        value: req.recipient.clone(),
    })?);
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.cm_change))?);
    bytes.extend_from_slice(&encode_tze(&encoded_proof_to_wire(&req.proof)?)?);
    bytes.extend_from_slice(&encode_tze(&WireOptionalEncodedNote {
        note: req
            .enc_change
            .as_ref()
            .map(encoded_note_to_wire)
            .transpose()?,
    })?);
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.cm_fee))?);
    bytes.extend_from_slice(&encode_tze(&encoded_note_to_wire(&req.enc_fee)?)?);
    Ok(WireKernelUnshieldReq { bytes })
}

fn kernel_unshield_req_from_wire(wire: WireKernelUnshieldReq) -> Result<KernelUnshieldReq, String> {
    let (rest, root) = decode_tze_prefix::<WireFelt>(&wire.bytes)?;
    let (rest, nullifiers) = decode_tze_prefix::<WireEncodedFeltList>(rest)?;
    let (rest, v_pub) = decode_tze_prefix::<WireU64Le>(rest)?;
    let (rest, fee) = decode_tze_prefix::<WireU64Le>(rest)?;
    let (rest, recipient) = decode_tze_prefix::<WireAccountId>(rest)?;
    let (rest, cm_change) = decode_tze_prefix::<WireFelt>(rest)?;
    let (rest, proof) = decode_tze_prefix::<WireEncodedProof>(rest)?;
    let (rest, enc_change) = decode_tze_prefix::<WireOptionalEncodedNote>(rest)?;
    let (rest, cm_fee) = decode_tze_prefix::<WireFelt>(rest)?;
    let (rest, enc_fee) = decode_tze_prefix::<WireEncodedNote>(rest)?;
    if !rest.is_empty() {
        return Err(format!(
            "kernel unshield payload left {} trailing bytes",
            rest.len()
        ));
    }
    Ok(KernelUnshieldReq {
        root: wire_to_felt(root)?,
        nullifiers: encoded_felt_list_from_wire(nullifiers)?,
        v_pub: wire_to_u64(v_pub)?,
        fee: wire_to_u64(fee)?,
        recipient: recipient.value,
        cm_change: wire_to_felt(cm_change)?,
        proof: encoded_proof_from_wire(proof)?,
        enc_change: enc_change.note.map(encoded_note_from_wire).transpose()?,
        cm_fee: wire_to_felt(cm_fee)?,
        enc_fee: encoded_note_from_wire(enc_fee)?,
    })
}

fn unshield_resp_to_wire(resp: &UnshieldResp) -> Result<WireUnshieldResp, String> {
    Ok(WireUnshieldResp {
        change_index: resp
            .change_index
            .map(|index| {
                index
                    .try_into()
                    .map(u64_to_wire)
                    .map_err(|_| "change index does not fit in u64".to_string())
            })
            .transpose()?,
        producer_index: u64_to_wire(
            resp.producer_index
                .try_into()
                .map_err(|_| "producer index does not fit in u64".to_string())?,
        ),
    })
}

fn unshield_resp_from_wire(wire: WireUnshieldResp) -> Result<UnshieldResp, String> {
    Ok(UnshieldResp {
        change_index: wire
            .change_index
            .map(|index| {
                wire_to_u64(index)?
                    .try_into()
                    .map_err(|_| "change index does not fit in usize".to_string())
            })
            .transpose()?,
        producer_index: wire_to_u64(wire.producer_index)?
            .try_into()
            .map_err(|_| "producer index does not fit in usize".to_string())?,
    })
}

fn kernel_withdraw_req_to_wire(req: &KernelWithdrawReq) -> WireKernelWithdrawReq {
    WireKernelWithdrawReq {
        sender: req.sender.clone(),
        recipient: req.recipient.clone(),
        amount: u64_to_wire(req.amount),
    }
}

fn kernel_withdraw_req_from_wire(wire: WireKernelWithdrawReq) -> Result<KernelWithdrawReq, String> {
    Ok(KernelWithdrawReq {
        sender: wire.sender,
        recipient: wire.recipient,
        amount: wire_to_u64(wire.amount)?,
    })
}

fn withdraw_resp_to_wire(resp: &WithdrawResp) -> Result<WireWithdrawResp, String> {
    Ok(WireWithdrawResp {
        withdrawal_index: u64_to_wire(
            resp.withdrawal_index
                .try_into()
                .map_err(|_| "withdrawal index does not fit in u64".to_string())?,
        ),
    })
}

fn withdraw_resp_from_wire(wire: WireWithdrawResp) -> Result<WithdrawResp, String> {
    Ok(WithdrawResp {
        withdrawal_index: wire_to_u64(wire.withdrawal_index)?
            .try_into()
            .map_err(|_| "withdrawal index does not fit in usize".to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_wire::ML_KEM768_ENCAPSULATION_KEY_BYTES;
    use crate::{DETECT_K, ZERO};
    use proptest::prelude::*;

    fn small_string(max_len: usize) -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                Just('a'),
                Just('b'),
                Just('c'),
                Just('x'),
                Just('y'),
                Just('z'),
                Just('0'),
                Just('1'),
                Just('2'),
                Just('-'),
                Just('_'),
                Just(' '),
            ],
            0..=max_len,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    fn arb_felt() -> impl Strategy<Value = F> {
        prop::array::uniform32(any::<u8>())
    }

    fn arb_encrypted_note() -> impl Strategy<Value = EncryptedNote> {
        (
            prop::collection::vec(any::<u8>(), ML_KEM768_CIPHERTEXT_BYTES),
            0u16..((1u16) << DETECT_K),
            prop::collection::vec(any::<u8>(), ML_KEM768_CIPHERTEXT_BYTES),
            prop::collection::vec(any::<u8>(), NOTE_AEAD_NONCE_BYTES),
            prop::collection::vec(any::<u8>(), ENCRYPTED_NOTE_BYTES),
        )
            .prop_map(|(ct_d, tag, ct_v, nonce, encrypted_data)| EncryptedNote {
                ct_d,
                tag,
                ct_v,
                nonce,
                encrypted_data,
            })
    }

    fn arb_payment_address() -> impl Strategy<Value = PaymentAddress> {
        (
            arb_felt(),
            arb_felt(),
            arb_felt(),
            arb_felt(),
            prop::collection::vec(any::<u8>(), ML_KEM768_ENCAPSULATION_KEY_BYTES),
            prop::collection::vec(any::<u8>(), ML_KEM768_ENCAPSULATION_KEY_BYTES),
        )
            .prop_map(|(d_j, auth_root, auth_pub_seed, nk_tag, ek_v, ek_d)| {
                PaymentAddress {
                    d_j,
                    auth_root,
                    auth_pub_seed,
                    nk_tag,
                    ek_v,
                    ek_d,
                }
            })
    }

    fn arb_verify_meta() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..64)
    }

    fn arb_kernel_stark_proof() -> impl Strategy<Value = KernelStarkProof> {
        (
            prop::collection::vec(any::<u8>(), 0..128),
            prop::collection::vec(arb_felt(), 0..8),
            arb_verify_meta(),
        )
            .prop_map(
                |(proof_bytes, output_preimage, verify_meta)| KernelStarkProof {
                    proof_bytes,
                    output_preimage,
                    verify_meta,
                },
            )
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_shield_request() {
        let message = KernelInboxMessage::Shield(KernelShieldReq {
            sender: "alice".into(),
            fee: 3,
            v: 42,
            producer_fee: 5,
            address: sample_payment_address(),
            memo: Some("hello".into()),
            proof: sample_kernel_stark_proof(),
            client_cm: ZERO,
            client_enc: None,
            producer_cm: [9u8; 32],
            producer_enc: Some(sample_encrypted_note(0x77)),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Shield(req) => {
                assert_eq!(req.sender, "alice");
                assert_eq!(req.fee, 3);
                assert_eq!(req.v, 42);
                assert_eq!(req.producer_fee, 5);
                assert_eq!(req.memo.as_deref(), Some("hello"));
                assert_eq!(
                    req.proof.proof_bytes,
                    sample_kernel_stark_proof().proof_bytes
                );
                assert_eq!(req.address.d_j, sample_payment_address().d_j);
                assert_eq!(req.producer_cm, [9u8; 32]);
                assert_eq!(
                    req.producer_enc.as_ref().map(|enc| &enc.ct_d),
                    Some(&sample_encrypted_note(0x77).ct_d)
                );
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_binary_stark_proof() {
        let message = KernelInboxMessage::Transfer(KernelTransferReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32], [3u8; 32]],
            fee: 9,
            cm_1: [4u8; 32],
            cm_2: [5u8; 32],
            cm_3: [6u8; 32],
            enc_1: sample_encrypted_note(0x11),
            enc_2: sample_encrypted_note(0x22),
            enc_3: sample_encrypted_note(0x33),
            proof: sample_kernel_stark_proof(),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Transfer(req) => {
                assert_eq!(
                    req.proof.proof_bytes,
                    sample_kernel_stark_proof().proof_bytes
                );
                assert_eq!(
                    req.proof.output_preimage,
                    sample_kernel_stark_proof().output_preimage
                );
                assert_eq!(
                    req.proof.verify_meta,
                    sample_kernel_stark_proof().verify_meta
                );
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
    }

    #[test]
    fn encoded_note_wrapper_roundtrips() {
        let enc = sample_encrypted_note(0x44);
        let wire = encoded_note_to_wire(&enc).unwrap();
        let encoded = encode_tze(&wire).unwrap();
        let decoded_wire: WireEncodedNote = decode_tze(&encoded).unwrap();
        let decoded = encoded_note_from_wire(decoded_wire).unwrap();
        assert_eq!(decoded.ct_d, enc.ct_d);
        assert_eq!(decoded.tag, enc.tag);
        assert_eq!(decoded.ct_v, enc.ct_v);
        assert_eq!(decoded.encrypted_data, enc.encrypted_data);
    }

    #[test]
    fn encoded_proof_wrapper_roundtrips_for_stark() {
        let proof = sample_kernel_stark_proof();
        let wire = encoded_proof_to_wire(&proof).unwrap();
        let encoded = encode_tze(&wire).unwrap();
        let decoded_wire: WireEncodedProof = decode_tze(&encoded).unwrap();
        let decoded = encoded_proof_from_wire(decoded_wire).unwrap();
        assert_eq!(decoded.proof_bytes, proof.proof_bytes);
        assert_eq!(decoded.output_preimage, proof.output_preimage);
        assert_eq!(decoded.verify_meta, proof.verify_meta);
    }

    #[test]
    fn encoded_proof_wrapper_roundtrips_for_high_bit_verify_meta() {
        let proof = KernelStarkProof {
            proof_bytes: vec![0xb1, 0xd0, 0x46, 0xe2],
            output_preimage: vec![[0x11; 32], [0x22; 32]],
            verify_meta: vec![0xf7, 0xc3, 0x0c, 0x6e, 0x48, 0xb5, 0x22, 0x26],
        };
        let wire = encoded_proof_to_wire(&proof).unwrap();
        let encoded = encode_tze(&wire).unwrap();
        let decoded_wire: WireEncodedProof = decode_tze(&encoded).unwrap();
        let decoded = encoded_proof_from_wire(decoded_wire).unwrap();
        assert_eq!(decoded.proof_bytes, proof.proof_bytes);
        assert_eq!(decoded.output_preimage, proof.output_preimage);
        assert_eq!(decoded.verify_meta, proof.verify_meta);
    }

    #[test]
    fn kernel_shield_roundtrips_for_high_bit_verify_meta() {
        let proof = KernelStarkProof {
            proof_bytes: vec![0xb1, 0xd0, 0x46, 0xe2],
            output_preimage: vec![[0x11; 32], [0x22; 32]],
            verify_meta: vec![0xf7, 0xc3, 0x0c, 0x6e, 0x48, 0xb5, 0x22, 0x26],
        };
        let message = KernelInboxMessage::Shield(KernelShieldReq {
            sender: "alice".to_string(),
            fee: 1,
            v: 7,
            producer_fee: 3,
            address: sample_payment_address(),
            memo: None,
            proof,
            client_cm: [0x44; 32],
            client_enc: None,
            producer_cm: [0x55; 32],
            producer_enc: Some(sample_encrypted_note(0x56)),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        let KernelInboxMessage::Shield(decoded) = decoded else {
            panic!("decoded wrong kernel message variant");
        };
        assert_eq!(
            decoded.proof.verify_meta,
            vec![0xf7, 0xc3, 0x0c, 0x6e, 0x48, 0xb5, 0x22, 0x26]
        );
    }

    #[test]
    fn kernel_shield_roundtrips_for_larger_stark_proof_payloads() {
        let proof = KernelStarkProof {
            proof_bytes: (0..70).map(|i| (0x80u8).wrapping_add(i as u8)).collect(),
            output_preimage: vec![[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]],
            verify_meta: (0..32).map(|i| (0xf0u8).wrapping_add(i as u8)).collect(),
        };
        let message = KernelInboxMessage::Shield(KernelShieldReq {
            sender: "alice".to_string(),
            fee: 2,
            v: 7,
            producer_fee: 4,
            address: sample_payment_address(),
            memo: None,
            proof: proof.clone(),
            client_cm: [0x44; 32],
            client_enc: None,
            producer_cm: [0x66; 32],
            producer_enc: Some(sample_encrypted_note(0x67)),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        let KernelInboxMessage::Shield(decoded) = decoded else {
            panic!("decoded wrong kernel message variant");
        };
        assert_eq!(decoded.proof.proof_bytes, proof.proof_bytes);
        assert_eq!(decoded.proof.output_preimage, proof.output_preimage);
        assert_eq!(decoded.proof.verify_meta, proof.verify_meta);
    }

    #[test]
    fn encoded_proof_wrapper_roundtrips_for_larger_stark_proof_payloads() {
        let proof = KernelStarkProof {
            proof_bytes: (0..70).map(|i| (0x80u8).wrapping_add(i as u8)).collect(),
            output_preimage: vec![[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]],
            verify_meta: (0..32).map(|i| (0xf0u8).wrapping_add(i as u8)).collect(),
        };
        let wire = encoded_proof_to_wire(&proof).unwrap();
        let encoded = encode_tze(&wire).unwrap();
        let decoded_wire: WireEncodedProof = decode_tze(&encoded).unwrap();
        let decoded = encoded_proof_from_wire(decoded_wire).unwrap();
        assert_eq!(decoded.proof_bytes, proof.proof_bytes);
        assert_eq!(decoded.output_preimage, proof.output_preimage);
        assert_eq!(decoded.verify_meta, proof.verify_meta);
    }

    #[test]
    fn wire_felt_list_roundtrips() {
        let wire = WireFeltList {
            items: vec![felt_to_wire(&[1u8; 32]), felt_to_wire(&[2u8; 32])],
        };
        let encoded = encode_tze(&wire).unwrap();
        let decoded: WireFeltList = decode_tze(&encoded).unwrap();
        assert_eq!(decoded, wire);
    }

    #[test]
    fn kernel_transfer_wire_struct_roundtrips() {
        let req = KernelTransferReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32], [3u8; 32]],
            fee: 11,
            cm_1: [4u8; 32],
            cm_2: [5u8; 32],
            cm_3: [6u8; 32],
            enc_1: sample_encrypted_note(0x11),
            enc_2: sample_encrypted_note(0x22),
            enc_3: sample_encrypted_note(0x33),
            proof: sample_kernel_stark_proof(),
        };
        let wire = kernel_transfer_req_to_wire(&req).unwrap();
        let encoded = encode_tze(&wire).unwrap();
        let decoded: WireKernelTransferReq = decode_tze(&encoded).unwrap();
        let host = kernel_transfer_req_from_wire(decoded).unwrap();
        assert_eq!(host.root, req.root);
        assert_eq!(host.nullifiers, req.nullifiers);
        assert_eq!(host.fee, req.fee);
        assert_eq!(host.cm_1, req.cm_1);
        assert_eq!(host.cm_2, req.cm_2);
        assert_eq!(host.cm_3, req.cm_3);
        assert_eq!(host.enc_1.ct_d, req.enc_1.ct_d);
        assert_eq!(host.enc_1.tag, req.enc_1.tag);
        assert_eq!(host.enc_1.ct_v, req.enc_1.ct_v);
        assert_eq!(host.enc_1.encrypted_data, req.enc_1.encrypted_data);
        assert_eq!(host.enc_2.ct_d, req.enc_2.ct_d);
        assert_eq!(host.enc_2.tag, req.enc_2.tag);
        assert_eq!(host.enc_2.ct_v, req.enc_2.ct_v);
        assert_eq!(host.enc_2.encrypted_data, req.enc_2.encrypted_data);
        assert_eq!(host.enc_3.ct_d, req.enc_3.ct_d);
        assert_eq!(host.enc_3.tag, req.enc_3.tag);
        assert_eq!(host.enc_3.ct_v, req.enc_3.ct_v);
        assert_eq!(host.enc_3.encrypted_data, req.enc_3.encrypted_data);
        assert_eq!(host.proof.proof_bytes, req.proof.proof_bytes);
    }

    #[test]
    fn kernel_transfer_payload_fields_roundtrip_individually() {
        let req = KernelTransferReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32], [3u8; 32]],
            fee: 12,
            cm_1: [4u8; 32],
            cm_2: [5u8; 32],
            cm_3: [6u8; 32],
            enc_1: sample_encrypted_note(0x11),
            enc_2: sample_encrypted_note(0x22),
            enc_3: sample_encrypted_note(0x33),
            proof: sample_kernel_stark_proof(),
        };
        let wire = kernel_transfer_req_to_wire(&req).unwrap();
        let (rest, root) = decode_tze_prefix::<WireFelt>(&wire.bytes).unwrap();
        assert_eq!(wire_to_felt(root).unwrap(), req.root);
        let (rest, nullifiers) = decode_tze_prefix::<WireEncodedFeltList>(rest).unwrap();
        let decoded_nullifiers = encoded_felt_list_from_wire(nullifiers).unwrap();
        assert_eq!(decoded_nullifiers, req.nullifiers);
        let (rest, fee) = decode_tze_prefix::<WireU64Le>(rest).unwrap();
        assert_eq!(wire_to_u64(fee).unwrap(), req.fee);
        let (rest, cm_1) = decode_tze_prefix::<WireFelt>(rest).unwrap();
        assert_eq!(wire_to_felt(cm_1).unwrap(), req.cm_1);
        let (rest, cm_2) = decode_tze_prefix::<WireFelt>(rest).unwrap();
        assert_eq!(wire_to_felt(cm_2).unwrap(), req.cm_2);
        let (rest, cm_3) = decode_tze_prefix::<WireFelt>(rest).unwrap();
        assert_eq!(wire_to_felt(cm_3).unwrap(), req.cm_3);
        let (rest, proof) = decode_tze_prefix::<WireEncodedProof>(rest).unwrap();
        let decoded_proof = encoded_proof_from_wire(proof).unwrap();
        assert_eq!(decoded_proof.proof_bytes, req.proof.proof_bytes);
        let (rest, enc_1) = decode_tze_prefix::<WireEncodedNote>(rest).unwrap();
        let decoded_enc_1 = encoded_note_from_wire(enc_1).unwrap();
        assert_eq!(decoded_enc_1.ct_d, req.enc_1.ct_d);
        let (rest, enc_2) = decode_tze_prefix::<WireEncodedNote>(rest).unwrap();
        let decoded_enc_2 = encoded_note_from_wire(enc_2).unwrap();
        assert_eq!(decoded_enc_2.ct_d, req.enc_2.ct_d);
        let (rest, enc_3) = decode_tze_prefix::<WireEncodedNote>(rest).unwrap();
        let decoded_enc_3 = encoded_note_from_wire(enc_3).unwrap();
        assert_eq!(decoded_enc_3.ct_d, req.enc_3.ct_d);
        assert!(rest.is_empty());
    }

    #[test]
    fn kernel_unshield_wire_struct_roundtrips() {
        let req = KernelUnshieldReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32]],
            v_pub: 33,
            fee: 4,
            recipient: "bob".into(),
            cm_change: [4u8; 32],
            enc_change: Some(sample_encrypted_note(0x33)),
            cm_fee: [5u8; 32],
            enc_fee: sample_encrypted_note(0x44),
            proof: sample_kernel_stark_proof(),
        };
        let wire = kernel_unshield_req_to_wire(&req).unwrap();
        let encoded = encode_tze(&wire).unwrap();
        let decoded: WireKernelUnshieldReq = decode_tze(&encoded).unwrap();
        let host = kernel_unshield_req_from_wire(decoded).unwrap();
        assert_eq!(host.root, req.root);
        assert_eq!(host.nullifiers, req.nullifiers);
        assert_eq!(host.v_pub, req.v_pub);
        assert_eq!(host.fee, req.fee);
        assert_eq!(host.recipient, req.recipient);
        assert_eq!(host.cm_change, req.cm_change);
        assert_eq!(host.cm_fee, req.cm_fee);
        let host_change = host.enc_change.expect("missing decoded change note");
        let req_change = req.enc_change.expect("missing original change note");
        assert_eq!(host_change.ct_d, req_change.ct_d);
        assert_eq!(host_change.tag, req_change.tag);
        assert_eq!(host_change.ct_v, req_change.ct_v);
        assert_eq!(host_change.encrypted_data, req_change.encrypted_data);
        assert_eq!(host.enc_fee.ct_d, req.enc_fee.ct_d);
        assert_eq!(host.enc_fee.tag, req.enc_fee.tag);
        assert_eq!(host.enc_fee.ct_v, req.enc_fee.ct_v);
        assert_eq!(host.enc_fee.encrypted_data, req.enc_fee.encrypted_data);
        assert_eq!(host.proof.proof_bytes, req.proof.proof_bytes);
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_transfer_request() {
        let message = KernelInboxMessage::Transfer(KernelTransferReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32]],
            fee: 5,
            cm_1: [4u8; 32],
            cm_2: [5u8; 32],
            cm_3: [6u8; 32],
            enc_1: sample_encrypted_note(0x11),
            enc_2: sample_encrypted_note(0x22),
            enc_3: sample_encrypted_note(0x33),
            proof: sample_kernel_stark_proof(),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Transfer(req) => {
                assert_eq!(
                    req.proof.proof_bytes,
                    sample_kernel_stark_proof().proof_bytes
                );
                assert_eq!(req.root, [1u8; 32]);
                assert_eq!(req.nullifiers, vec![[2u8; 32]]);
                assert_eq!(req.fee, 5);
                assert_eq!(req.cm_1, [4u8; 32]);
                assert_eq!(req.cm_2, [5u8; 32]);
                assert_eq!(req.cm_3, [6u8; 32]);
                assert_eq!(req.enc_1.ct_d, sample_encrypted_note(0x11).ct_d);
                assert_eq!(req.enc_2.ct_v, sample_encrypted_note(0x22).ct_v);
                assert_eq!(req.enc_3.tag, sample_encrypted_note(0x33).tag);
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_unshield_request() {
        let message = KernelInboxMessage::Unshield(KernelUnshieldReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32]],
            v_pub: 33,
            fee: 6,
            recipient: "bob".into(),
            cm_change: [4u8; 32],
            enc_change: Some(sample_encrypted_note(0x33)),
            cm_fee: [5u8; 32],
            enc_fee: sample_encrypted_note(0x44),
            proof: sample_kernel_stark_proof(),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Unshield(req) => {
                assert_eq!(
                    req.proof.proof_bytes,
                    sample_kernel_stark_proof().proof_bytes
                );
                assert_eq!(req.root, [1u8; 32]);
                assert_eq!(req.nullifiers, vec![[2u8; 32]]);
                assert_eq!(req.v_pub, 33);
                assert_eq!(req.fee, 6);
                assert_eq!(req.recipient, "bob");
                assert_eq!(req.cm_change, [4u8; 32]);
                assert_eq!(req.cm_fee, [5u8; 32]);
                assert_eq!(
                    req.enc_change.as_ref().unwrap().encrypted_data,
                    sample_encrypted_note(0x33).encrypted_data
                );
                assert_eq!(req.enc_fee.ct_d, sample_encrypted_note(0x44).ct_d);
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_withdraw_request() {
        let message = KernelInboxMessage::Withdraw(KernelWithdrawReq {
            sender: "alice".into(),
            recipient: "tz1-target".into(),
            amount: 33,
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Withdraw(req) => {
                assert_eq!(req.sender, "alice");
                assert_eq!(req.recipient, "tz1-target");
                assert_eq!(req.amount, 33);
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_dal_pointer() {
        let message = KernelInboxMessage::DalPointer(KernelDalPayloadPointer {
            kind: KernelDalPayloadKind::Transfer,
            chunks: vec![
                KernelDalChunkPointer {
                    published_level: 101,
                    slot_index: 3,
                    payload_len: 4096,
                },
                KernelDalChunkPointer {
                    published_level: 102,
                    slot_index: 7,
                    payload_len: 512,
                },
            ],
            payload_len: 4608,
            payload_hash: [0xA5; 32],
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        let KernelInboxMessage::DalPointer(pointer) = decoded else {
            panic!("unexpected decoded message");
        };
        assert_eq!(pointer.kind, KernelDalPayloadKind::Transfer);
        assert_eq!(pointer.chunks.len(), 2);
        assert_eq!(pointer.chunks[0].published_level, 101);
        assert_eq!(pointer.chunks[0].slot_index, 3);
        assert_eq!(pointer.chunks[0].payload_len, 4096);
        assert_eq!(pointer.chunks[1].published_level, 102);
        assert_eq!(pointer.chunks[1].slot_index, 7);
        assert_eq!(pointer.chunks[1].payload_len, 512);
        assert_eq!(pointer.payload_len, 4608);
        assert_eq!(pointer.payload_hash, [0xA5; 32]);
    }

    fn sample_payment_address() -> PaymentAddress {
        let mut d_j = [0x11u8; 32];
        d_j[31] &= 0x07;
        let mut auth_root = [0x22u8; 32];
        auth_root[31] &= 0x07;
        let mut auth_pub_seed = [0x33u8; 32];
        auth_pub_seed[31] &= 0x07;
        let mut nk_tag = [0x44u8; 32];
        nk_tag[31] &= 0x07;
        PaymentAddress {
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag,
            ek_v: vec![0x55; ML_KEM768_ENCAPSULATION_KEY_BYTES],
            ek_d: vec![0x66; ML_KEM768_ENCAPSULATION_KEY_BYTES],
        }
    }

    fn sample_encrypted_note(fill: u8) -> EncryptedNote {
        EncryptedNote {
            ct_d: vec![fill; crate::ML_KEM768_CIPHERTEXT_BYTES],
            tag: 17,
            ct_v: vec![fill ^ 0x5a; crate::ML_KEM768_CIPHERTEXT_BYTES],
            nonce: vec![fill.wrapping_add(2); crate::NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![fill.wrapping_add(1); crate::ENCRYPTED_NOTE_BYTES],
        }
    }

    fn sample_kernel_stark_proof() -> KernelStarkProof {
        KernelStarkProof {
            proof_bytes: vec![0xaa, 0xbb, 0xcc],
            output_preimage: vec![[7u8; 32], [8u8; 32]],
            verify_meta: vec![1, 2, 3, 4],
        }
    }

    proptest! {
        #[test]
        fn prop_kernel_shield_roundtrip_preserves_fields(
            sender in small_string(32),
            memo in prop::option::of(small_string(64)),
            fee in any::<u64>(),
            v in any::<u64>(),
            producer_fee in 1u64..u64::MAX,
            address in arb_payment_address(),
            proof in arb_kernel_stark_proof(),
            client_cm in arb_felt(),
            client_enc in prop::option::of(arb_encrypted_note()),
            producer_cm in arb_felt(),
            producer_enc in arb_encrypted_note(),
        ) {
            let message = KernelInboxMessage::Shield(KernelShieldReq {
                sender: sender.clone(),
                fee,
                v,
                producer_fee,
                address: address.clone(),
                memo: memo.clone(),
                proof: proof.clone(),
                client_cm,
                client_enc: client_enc.clone(),
                producer_cm,
                producer_enc: Some(producer_enc.clone()),
            });

            let encoded = encode_kernel_inbox_message(&message).unwrap();
            let decoded = decode_kernel_inbox_message(&encoded).unwrap();
            let KernelInboxMessage::Shield(req) = decoded else {
                panic!("decoded wrong kernel message variant");
            };
            prop_assert_eq!(req.sender, sender);
            prop_assert_eq!(req.fee, fee);
            prop_assert_eq!(req.v, v);
            prop_assert_eq!(req.producer_fee, producer_fee);
            prop_assert_eq!(req.memo, memo);
            prop_assert_eq!(req.address.d_j, address.d_j);
            prop_assert_eq!(req.address.auth_root, address.auth_root);
            prop_assert_eq!(req.address.auth_pub_seed, address.auth_pub_seed);
            prop_assert_eq!(req.address.nk_tag, address.nk_tag);
            prop_assert_eq!(req.address.ek_v, address.ek_v);
            prop_assert_eq!(req.address.ek_d, address.ek_d);
            prop_assert_eq!(req.client_cm, client_cm);
            prop_assert_eq!(req.client_enc.is_some(), client_enc.is_some());
            prop_assert_eq!(req.producer_cm, producer_cm);
            prop_assert_eq!(
                req.producer_enc.as_ref().map(|enc| &enc.ct_d),
                Some(&producer_enc.ct_d)
            );
            if let (Some(actual), Some(expected)) = (req.client_enc.as_ref(), client_enc.as_ref()) {
                prop_assert_eq!(&actual.ct_d, &expected.ct_d);
                prop_assert_eq!(actual.tag, expected.tag);
                prop_assert_eq!(&actual.ct_v, &expected.ct_v);
                prop_assert_eq!(&actual.encrypted_data, &expected.encrypted_data);
            }
            prop_assert_eq!(req.proof.proof_bytes, proof.proof_bytes);
            prop_assert_eq!(req.proof.output_preimage, proof.output_preimage);
            prop_assert_eq!(req.proof.verify_meta, proof.verify_meta);
        }

        #[test]
        fn prop_kernel_transfer_roundtrip_preserves_fields(
            root in arb_felt(),
            nullifiers in prop::collection::vec(arb_felt(), 0..8),
            fee in any::<u64>(),
            cm_1 in arb_felt(),
            cm_2 in arb_felt(),
            cm_3 in arb_felt(),
            enc_1 in arb_encrypted_note(),
            enc_2 in arb_encrypted_note(),
            enc_3 in arb_encrypted_note(),
            proof in arb_kernel_stark_proof(),
        ) {
            let req = KernelTransferReq {
                root,
                nullifiers: nullifiers.clone(),
                fee,
                cm_1,
                cm_2,
                cm_3,
                enc_1: enc_1.clone(),
                enc_2: enc_2.clone(),
                enc_3: enc_3.clone(),
                proof: proof.clone(),
            };

            let wire = kernel_transfer_req_to_wire(&req).unwrap();
            let decoded = kernel_transfer_req_from_wire(wire).unwrap();
            prop_assert_eq!(decoded.root, root);
            prop_assert_eq!(decoded.nullifiers, nullifiers);
            prop_assert_eq!(decoded.fee, fee);
            prop_assert_eq!(decoded.cm_1, cm_1);
            prop_assert_eq!(decoded.cm_2, cm_2);
            prop_assert_eq!(decoded.cm_3, cm_3);
            prop_assert_eq!(decoded.enc_1.ct_d, enc_1.ct_d);
            prop_assert_eq!(decoded.enc_1.tag, enc_1.tag);
            prop_assert_eq!(decoded.enc_1.ct_v, enc_1.ct_v);
            prop_assert_eq!(decoded.enc_1.encrypted_data, enc_1.encrypted_data);
            prop_assert_eq!(decoded.enc_2.ct_d, enc_2.ct_d);
            prop_assert_eq!(decoded.enc_2.tag, enc_2.tag);
            prop_assert_eq!(decoded.enc_2.ct_v, enc_2.ct_v);
            prop_assert_eq!(decoded.enc_2.encrypted_data, enc_2.encrypted_data);
            prop_assert_eq!(decoded.enc_3.ct_d, enc_3.ct_d);
            prop_assert_eq!(decoded.enc_3.tag, enc_3.tag);
            prop_assert_eq!(decoded.enc_3.ct_v, enc_3.ct_v);
            prop_assert_eq!(decoded.enc_3.encrypted_data, enc_3.encrypted_data);
            prop_assert_eq!(decoded.proof.proof_bytes, proof.proof_bytes);
            prop_assert_eq!(decoded.proof.output_preimage, proof.output_preimage);
            prop_assert_eq!(decoded.proof.verify_meta, proof.verify_meta);
        }

        #[test]
        fn prop_kernel_unshield_roundtrip_preserves_fields(
            root in arb_felt(),
            nullifiers in prop::collection::vec(arb_felt(), 0..8),
            v_pub in any::<u64>(),
            fee in any::<u64>(),
            recipient in small_string(32),
            cm_change in arb_felt(),
            enc_change in prop::option::of(arb_encrypted_note()),
            cm_fee in arb_felt(),
            enc_fee in arb_encrypted_note(),
            proof in arb_kernel_stark_proof(),
        ) {
            let req = KernelUnshieldReq {
                root,
                nullifiers: nullifiers.clone(),
                v_pub,
                fee,
                recipient: recipient.clone(),
                cm_change,
                enc_change: enc_change.clone(),
                cm_fee,
                enc_fee: enc_fee.clone(),
                proof: proof.clone(),
            };

            let wire = kernel_unshield_req_to_wire(&req).unwrap();
            let decoded = kernel_unshield_req_from_wire(wire).unwrap();
            prop_assert_eq!(decoded.root, root);
            prop_assert_eq!(decoded.nullifiers, nullifiers);
            prop_assert_eq!(decoded.v_pub, v_pub);
            prop_assert_eq!(decoded.fee, fee);
            prop_assert_eq!(decoded.recipient, recipient);
            prop_assert_eq!(decoded.cm_change, cm_change);
            prop_assert_eq!(decoded.cm_fee, cm_fee);
            prop_assert_eq!(decoded.enc_change.is_some(), enc_change.is_some());
            if let (Some(actual), Some(expected)) = (decoded.enc_change.as_ref(), enc_change.as_ref()) {
                prop_assert_eq!(&actual.ct_d, &expected.ct_d);
                prop_assert_eq!(actual.tag, expected.tag);
                prop_assert_eq!(&actual.ct_v, &expected.ct_v);
                prop_assert_eq!(&actual.encrypted_data, &expected.encrypted_data);
            }
            prop_assert_eq!(decoded.enc_fee.ct_d, enc_fee.ct_d);
            prop_assert_eq!(decoded.enc_fee.tag, enc_fee.tag);
            prop_assert_eq!(decoded.enc_fee.ct_v, enc_fee.ct_v);
            prop_assert_eq!(decoded.enc_fee.encrypted_data, enc_fee.encrypted_data);
            prop_assert_eq!(decoded.proof.proof_bytes, proof.proof_bytes);
            prop_assert_eq!(decoded.proof.output_preimage, proof.output_preimage);
            prop_assert_eq!(decoded.proof.verify_meta, proof.verify_meta);
        }

        #[test]
        fn prop_kernel_result_roundtrip_preserves_payload(
            shield_cm in arb_felt(),
            shield_index in 0u64..10_000,
            producer_cm in arb_felt(),
            producer_index in 0u64..10_000,
            transfer_index_1 in 0u64..10_000,
            transfer_index_2 in 0u64..10_000,
            transfer_index_3 in 0u64..10_000,
            change_index in prop::option::of(0u64..10_000),
            producer_note_index in 0u64..10_000,
            message in small_string(64),
        ) {
            let cases = [
                KernelResult::Configured,
                KernelResult::Deposit,
                KernelResult::Shield(ShieldResp {
                    cm: shield_cm,
                    index: shield_index as usize,
                    producer_cm,
                    producer_index: producer_index as usize,
                }),
                KernelResult::Transfer(TransferResp {
                    index_1: transfer_index_1 as usize,
                    index_2: transfer_index_2 as usize,
                    index_3: transfer_index_3 as usize,
                }),
                KernelResult::Unshield(UnshieldResp {
                    change_index: change_index.map(|x| x as usize),
                    producer_index: producer_note_index as usize,
                }),
                KernelResult::Withdraw(WithdrawResp {
                    withdrawal_index: transfer_index_1 as usize,
                }),
                KernelResult::Error { message: message.clone() },
            ];

            for result in cases {
                let encoded = encode_kernel_result(&result).unwrap();
                let decoded = decode_kernel_result(&encoded).unwrap();
                match (decoded, &result) {
                    (KernelResult::Configured, KernelResult::Configured)
                    | (KernelResult::Deposit, KernelResult::Deposit) => {}
                    (KernelResult::Shield(actual), KernelResult::Shield(expected)) => {
                        prop_assert_eq!(actual.cm, expected.cm);
                        prop_assert_eq!(actual.index, expected.index);
                        prop_assert_eq!(actual.producer_cm, expected.producer_cm);
                        prop_assert_eq!(actual.producer_index, expected.producer_index);
                    }
                    (KernelResult::Transfer(actual), KernelResult::Transfer(expected)) => {
                        prop_assert_eq!(actual.index_1, expected.index_1);
                        prop_assert_eq!(actual.index_2, expected.index_2);
                        prop_assert_eq!(actual.index_3, expected.index_3);
                    }
                    (KernelResult::Unshield(actual), KernelResult::Unshield(expected)) => {
                        prop_assert_eq!(actual.change_index, expected.change_index);
                        prop_assert_eq!(actual.producer_index, expected.producer_index);
                    }
                    (KernelResult::Withdraw(actual), KernelResult::Withdraw(expected)) => {
                        prop_assert_eq!(actual.withdrawal_index, expected.withdrawal_index);
                    }
                    (KernelResult::Error { message: actual }, KernelResult::Error { message: expected }) => {
                        prop_assert_eq!(&actual, expected);
                    }
                    (actual, expected) => prop_assert!(false, "decoded result variant mismatch: {:?} vs {:?}", actual, expected),
                }
            }
        }

        #[test]
        fn prop_signed_kernel_verifier_config_roundtrip_preserves_fields(
            auth_domain in arb_felt(),
            shield in arb_felt(),
            transfer in arb_felt(),
            unshield in arb_felt(),
            ask in arb_felt(),
        ) {
            let config = KernelVerifierConfig {
                auth_domain,
                verified_program_hashes: ProgramHashes {
                    shield,
                    transfer,
                    unshield,
                },
            };

            let signed = sign_kernel_verifier_config(&ask, config).unwrap();
            let encoded = encode_kernel_inbox_message(&KernelInboxMessage::ConfigureVerifier(
                signed.clone(),
            ))
            .unwrap();
            let decoded = decode_kernel_inbox_message(&encoded).unwrap();
            let KernelInboxMessage::ConfigureVerifier(decoded) = decoded else {
                prop_assert!(false, "decoded message variant mismatch");
                unreachable!();
            };
            prop_assert_eq!(decoded, signed);
        }

        #[test]
        fn prop_kernel_proof_to_host_preserves_stark_payload(
            proof in arb_kernel_stark_proof(),
        ) {
            let host = kernel_proof_to_host(&proof);
            let Proof::Stark {
                proof_bytes,
                output_preimage,
                verify_meta,
            } = host else {
                prop_assert!(false, "kernel proof must convert to Proof::Stark");
                unreachable!();
            };
            prop_assert_eq!(proof_bytes, proof.proof_bytes);
            prop_assert_eq!(output_preimage, proof.output_preimage);
            prop_assert_eq!(verify_meta, Some(proof.verify_meta));
        }

        #[test]
        fn prop_kernel_requests_to_host_preserve_fields(
            sender in small_string(32),
            memo in prop::option::of(small_string(64)),
            recipient in small_string(32),
            root in arb_felt(),
            nullifiers in prop::collection::vec(arb_felt(), 0..8),
            cm_1 in arb_felt(),
            cm_2 in arb_felt(),
            cm_3 in arb_felt(),
            cm_change in arb_felt(),
            cm_fee in arb_felt(),
            client_cm in arb_felt(),
            fee in any::<u64>(),
            value in any::<u64>(),
            producer_fee in 1u64..u64::MAX,
            address in arb_payment_address(),
            proof in arb_kernel_stark_proof(),
            enc_1 in arb_encrypted_note(),
            enc_2 in arb_encrypted_note(),
            enc_3 in arb_encrypted_note(),
            enc_change in prop::option::of(arb_encrypted_note()),
            enc_fee in arb_encrypted_note(),
            client_enc in prop::option::of(arb_encrypted_note()),
            producer_enc in arb_encrypted_note(),
        ) {
            let shield = KernelShieldReq {
                sender: sender.clone(),
                fee,
                v: value,
                producer_fee,
                address: address.clone(),
                memo: memo.clone(),
                proof: proof.clone(),
                client_cm,
                client_enc: client_enc.clone(),
                producer_cm: cm_fee,
                producer_enc: Some(producer_enc.clone()),
            };
            let shield_host = kernel_shield_req_to_host(&shield);
            prop_assert_eq!(shield_host.sender, sender);
            prop_assert_eq!(shield_host.fee, fee);
            prop_assert_eq!(shield_host.v, value);
            prop_assert_eq!(shield_host.producer_fee, producer_fee);
            prop_assert_eq!(shield_host.address.d_j, address.d_j);
            prop_assert_eq!(shield_host.memo, memo);
            prop_assert_eq!(shield_host.client_cm, client_cm);
            prop_assert_eq!(shield_host.client_enc.is_some(), client_enc.is_some());
            prop_assert_eq!(shield_host.producer_cm, cm_fee);
            prop_assert_eq!(
                shield_host.producer_enc.as_ref().map(|enc| &enc.ct_d),
                Some(&producer_enc.ct_d)
            );

            let transfer = KernelTransferReq {
                root,
                nullifiers: nullifiers.clone(),
                fee,
                cm_1,
                cm_2,
                cm_3,
                enc_1: enc_1.clone(),
                enc_2: enc_2.clone(),
                enc_3: enc_3.clone(),
                proof: proof.clone(),
            };
            let transfer_host = kernel_transfer_req_to_host(&transfer);
            let transfer_nullifiers = transfer_host.nullifiers.clone();
            prop_assert_eq!(transfer_host.root, root);
            prop_assert_eq!(&transfer_nullifiers, &nullifiers);
            prop_assert_eq!(transfer_host.fee, fee);
            prop_assert_eq!(transfer_host.cm_1, cm_1);
            prop_assert_eq!(transfer_host.cm_2, cm_2);
            prop_assert_eq!(transfer_host.cm_3, cm_3);
            prop_assert_eq!(transfer_host.enc_1.ct_d, enc_1.ct_d);
            prop_assert_eq!(transfer_host.enc_2.ct_v, enc_2.ct_v);
            prop_assert_eq!(transfer_host.enc_3.tag, enc_3.tag);

            let unshield = KernelUnshieldReq {
                root,
                nullifiers: transfer_nullifiers.clone(),
                v_pub: value,
                fee,
                recipient: recipient.clone(),
                cm_change,
                enc_change: enc_change.clone(),
                cm_fee,
                enc_fee: enc_fee.clone(),
                proof,
            };
            let unshield_host = kernel_unshield_req_to_host(&unshield);
            prop_assert_eq!(unshield_host.root, root);
            prop_assert_eq!(&unshield_host.nullifiers, &transfer_nullifiers);
            prop_assert_eq!(unshield_host.v_pub, value);
            prop_assert_eq!(unshield_host.fee, fee);
            prop_assert_eq!(unshield_host.recipient, recipient);
            prop_assert_eq!(unshield_host.cm_change, cm_change);
            prop_assert_eq!(unshield_host.cm_fee, cm_fee);
            prop_assert_eq!(unshield_host.enc_change.is_some(), enc_change.is_some());
            prop_assert_eq!(unshield_host.enc_fee.ct_d, enc_fee.ct_d);
        }

        #[test]
        fn prop_transfer_payload_rejects_trailing_bytes(
            req_root in arb_felt(),
            nullifiers in prop::collection::vec(arb_felt(), 0..6),
            fee in any::<u64>(),
            cm_1 in arb_felt(),
            cm_2 in arb_felt(),
            cm_3 in arb_felt(),
            enc_1 in arb_encrypted_note(),
            enc_2 in arb_encrypted_note(),
            enc_3 in arb_encrypted_note(),
            proof in arb_kernel_stark_proof(),
            trailing in prop::collection::vec(any::<u8>(), 1..8),
        ) {
            let req = KernelTransferReq {
                root: req_root,
                nullifiers,
                fee,
                cm_1,
                cm_2,
                cm_3,
                enc_1,
                enc_2,
                enc_3,
                proof,
            };
            let mut wire = kernel_transfer_req_to_wire(&req).unwrap();
            wire.bytes.extend_from_slice(&trailing);
            let err = kernel_transfer_req_from_wire(wire).unwrap_err();
            prop_assert!(err.contains("trailing bytes"));
        }

        #[test]
        fn prop_transfer_payload_rejects_truncation(
            req_root in arb_felt(),
            nullifiers in prop::collection::vec(arb_felt(), 0..6),
            fee in any::<u64>(),
            cm_1 in arb_felt(),
            cm_2 in arb_felt(),
            cm_3 in arb_felt(),
            enc_1 in arb_encrypted_note(),
            enc_2 in arb_encrypted_note(),
            enc_3 in arb_encrypted_note(),
            proof in arb_kernel_stark_proof(),
            cut in 1usize..8,
        ) {
            let req = KernelTransferReq {
                root: req_root,
                nullifiers,
                fee,
                cm_1,
                cm_2,
                cm_3,
                enc_1,
                enc_2,
                enc_3,
                proof,
            };
            let mut wire = kernel_transfer_req_to_wire(&req).unwrap();
            prop_assume!(wire.bytes.len() > cut);
            wire.bytes.truncate(wire.bytes.len() - cut);
            let err = kernel_transfer_req_from_wire(wire).unwrap_err();
            prop_assert!(err.contains("read failed") || err.contains("trailing bytes"));
        }

        #[test]
        fn prop_unshield_payload_rejects_trailing_bytes(
            req_root in arb_felt(),
            nullifiers in prop::collection::vec(arb_felt(), 0..6),
            v_pub in any::<u64>(),
            fee in any::<u64>(),
            recipient in small_string(32),
            cm_change in arb_felt(),
            enc_change in prop::option::of(arb_encrypted_note()),
            cm_fee in arb_felt(),
            enc_fee in arb_encrypted_note(),
            proof in arb_kernel_stark_proof(),
            trailing in prop::collection::vec(any::<u8>(), 1..8),
        ) {
            let req = KernelUnshieldReq {
                root: req_root,
                nullifiers,
                v_pub,
                fee,
                recipient,
                cm_change,
                enc_change,
                cm_fee,
                enc_fee,
                proof,
            };
            let mut wire = kernel_unshield_req_to_wire(&req).unwrap();
            wire.bytes.extend_from_slice(&trailing);
            let err = kernel_unshield_req_from_wire(wire).unwrap_err();
            prop_assert!(err.contains("trailing bytes"));
        }

        #[test]
        fn prop_unshield_payload_rejects_truncation(
            req_root in arb_felt(),
            nullifiers in prop::collection::vec(arb_felt(), 0..6),
            v_pub in any::<u64>(),
            fee in any::<u64>(),
            recipient in small_string(32),
            cm_change in arb_felt(),
            enc_change in prop::option::of(arb_encrypted_note()),
            cm_fee in arb_felt(),
            enc_fee in arb_encrypted_note(),
            proof in arb_kernel_stark_proof(),
            cut in 1usize..8,
        ) {
            let req = KernelUnshieldReq {
                root: req_root,
                nullifiers,
                v_pub,
                fee,
                recipient,
                cm_change,
                enc_change,
                cm_fee,
                enc_fee,
                proof,
            };
            let mut wire = kernel_unshield_req_to_wire(&req).unwrap();
            prop_assume!(wire.bytes.len() > cut);
            wire.bytes.truncate(wire.bytes.len() - cut);
            let err = kernel_unshield_req_from_wire(wire).unwrap_err();
            prop_assert!(err.contains("read failed") || err.contains("trailing bytes"));
        }
    }

    #[test]
    fn decode_kernel_inbox_message_rejects_wrong_version() {
        let bytes = encode_tze(&WireKernelInboxEnvelope {
            version: u16_to_wire(KERNEL_WIRE_VERSION + 1),
            message: WireKernelInboxMessage::ConfigureBridge(WireSignedKernelBridgeConfig {
                config: WireKernelBridgeConfig {
                    ticketer: "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc".into(),
                },
                signature: WireEncodedFeltList { bytes: Vec::new() },
            }),
        })
        .unwrap();
        let err = decode_kernel_inbox_message(&bytes).unwrap_err();
        assert!(err.contains("unsupported kernel inbox wire version"));
    }

    #[test]
    fn decode_kernel_result_rejects_wrong_version() {
        let bytes = encode_tze(&WireKernelResultEnvelope {
            version: u16_to_wire(KERNEL_WIRE_VERSION + 1),
            result: WireKernelResult::Deposit,
        })
        .unwrap();
        let err = decode_kernel_result(&bytes).unwrap_err();
        assert!(err.contains("unsupported kernel result wire version"));
    }

    #[test]
    fn kernel_proof_to_wire_rejects_oversized_output_preimage() {
        let proof = KernelStarkProof {
            proof_bytes: vec![1, 2, 3],
            output_preimage: vec![[9u8; 32]; MAX_OUTPUT_PREIMAGE_ITEMS + 1],
            verify_meta: vec![1, 2, 3],
        };
        let err = kernel_proof_to_wire(&proof).unwrap_err();
        assert!(err.contains("output_preimage too long for kernel wire"));
    }

    #[test]
    fn kernel_proof_from_wire_preserves_verify_meta_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(3u32).to_be_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        bytes.extend_from_slice(&(1u32).to_be_bytes());
        bytes.extend_from_slice(&ZERO);
        bytes.extend_from_slice(&(4u32).to_be_bytes());
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let proof = kernel_proof_from_wire(WireStarkProof { bytes }).unwrap();
        assert_eq!(proof.verify_meta, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn encoded_note_to_wire_rejects_invalid_note() {
        let err = encoded_note_to_wire(&EncryptedNote {
            ct_d: vec![0; ML_KEM768_CIPHERTEXT_BYTES - 1],
            tag: 0,
            ct_v: vec![0; ML_KEM768_CIPHERTEXT_BYTES],
            nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![0; ENCRYPTED_NOTE_BYTES],
        })
        .unwrap_err();
        assert!(err.contains("bad ct_d length"));
    }

    // ──────────────────────────────────────────────────────────────────
    // Size sentinels for admin config messages.
    //
    // These tests lock the serialized byte length of a typical
    // `ConfigureVerifier` / `ConfigureBridge` `KernelInboxMessage`.  They
    // are expected to pass in the current tree; they exist to trigger a
    // review when the encoding changes (new field in the config, WOTS
    // parameter change, struct reshuffling, etc.).
    //
    // Why the byte budget matters:
    // - Messages routed through the L1 inbox are subject to the protocol
    //   constant `sc_rollup_message_size_limit = 4096`.
    // - Messages routed through DAL can go up to `MAX_DAL_PAYLOAD_BYTES`
    //   (several hundred kB), and the kernel recovers the payload via a
    //   `DalPointer` whose routable kinds are enumerated in
    //   `KernelDalPayloadKind`.
    //
    // If a sentinel below breaks:
    //   1. Read the new size from the assertion output.
    //   2. If it still exceeds 4096 bytes: confirm that the corresponding
    //      `KernelDalPayloadKind` variant and the match arm in
    //      `tezos/rollup-kernel/src/lib.rs::fetch_kernel_message_from_dal`
    //      still exist.  Otherwise the message becomes impossible to
    //      deliver to the kernel.
    //   3. If it now fits in 4096 bytes: the DAL route remains correct
    //      but also becomes optional for this message type.
    //   4. Update the `EXPECTED_*` constant to the new value.
    // ──────────────────────────────────────────────────────────────────

    /// The L1 smart-rollup external message size limit, as defined by the
    /// Tezos protocol (`Constants_repr.sc_rollup_message_size_limit`).
    /// Duplicated here because this crate does not depend on the protocol.
    const L1_INBOX_MESSAGE_LIMIT: usize = 4096;

    #[test]
    fn configure_verifier_serialized_size_sentinel() {
        const EXPECTED_SIZE: usize = 4923;

        let ask = crate::hash(b"tzel-dev-rollup-config-admin");
        let config = KernelVerifierConfig {
            auth_domain: [0xAA; 32],
            verified_program_hashes: ProgramHashes {
                shield: [0xBB; 32],
                transfer: [0xCC; 32],
                unshield: [0xDD; 32],
            },
        };
        let signed = sign_kernel_verifier_config(&ask, config)
            .expect("sign verifier config");
        let encoded = encode_kernel_inbox_message(
            &KernelInboxMessage::ConfigureVerifier(signed),
        )
        .expect("encode configure-verifier message");

        assert_eq!(
            encoded.len(),
            EXPECTED_SIZE,
            "ConfigureVerifier serialized size changed — see module comment",
        );
        assert!(
            encoded.len() > L1_INBOX_MESSAGE_LIMIT,
            "ConfigureVerifier now fits in L1 inbox ({} <= {}); the DAL \
             route can remain but is no longer required",
            encoded.len(),
            L1_INBOX_MESSAGE_LIMIT,
        );
    }

    #[test]
    fn configure_bridge_serialized_size_sentinel() {
        const EXPECTED_SIZE: usize = 4835;

        // A typical KT1 Tezos contract address (36 characters).
        let ticketer = "KT1Fq8fPi2NjhWUXtcXBggbL6zFjZctGkmso".to_string();

        let ask = crate::hash(b"tzel-dev-rollup-config-admin");
        let signed = sign_kernel_bridge_config(&ask, KernelBridgeConfig { ticketer })
            .expect("sign bridge config");
        let encoded = encode_kernel_inbox_message(
            &KernelInboxMessage::ConfigureBridge(signed),
        )
        .expect("encode configure-bridge message");

        assert_eq!(
            encoded.len(),
            EXPECTED_SIZE,
            "ConfigureBridge serialized size changed — see module comment",
        );
        assert!(
            encoded.len() > L1_INBOX_MESSAGE_LIMIT,
            "ConfigureBridge now fits in L1 inbox ({} <= {}); the DAL \
             route can remain but is no longer required",
            encoded.len(),
            L1_INBOX_MESSAGE_LIMIT,
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // Variant-exhaustive framed-size invariant.
    //
    // The two sentinels above lock exact byte counts for the admin
    // config messages.  This test is broader: for **every** variant of
    // `KernelInboxMessage`, it checks the on-wire size (after wrapping
    // in `ExternalMessageFrame::Targetted` — the actual bytes
    // `octez-client send smart rollup message` transmits) against the
    // routing the kernel + tooling assume for that variant.
    //
    // Why it exists in addition to the sentinels:
    //   - It measures the **framed** size.  The protocol caps the
    //     framed bytes at `sc_rollup_message_size_limit = 4096`, and
    //     the frame adds 21 bytes (1 tag + 20 bytes rollup-address
    //     hash) on top of `encode_kernel_inbox_message`.  A message
    //     that sits just below 4096 unframed can still be rejected by
    //     the L1 inbox.
    //   - It is **exhaustive on `KernelInboxMessage` at compile time**
    //     via `required_routing`.  When a future commit adds a new
    //     variant (mirroring 2c45d9c, which added WOTS signatures that
    //     silently grew `Configure*` past 4096 without any test
    //     failing), the author is forced to classify the new variant
    //     as `FitsL1` or `RequiresDal` — there is no `_ =>` arm to
    //     hide behind.
    //   - It is **two-sided**: a variant that shrinks below 4096 after
    //     being classified `RequiresDal` also fails the test, flagging
    //     a dead DAL path that should be either kept intentionally or
    //     removed.
    //
    // When this test fails:
    //   - The assertion message tells you which variant broke which
    //     direction.  Either rebuild the representative instance to
    //     match today's size, update the `required_routing`
    //     classification, or prune the DAL routing for a variant that
    //     no longer needs it.
    // ──────────────────────────────────────────────────────────────────

    #[derive(Debug, PartialEq, Eq)]
    enum Routing {
        /// Framed size must stay `<= L1_INBOX_MESSAGE_LIMIT` — the
        /// message is routed directly through the L1 rollup inbox.
        FitsL1,
        /// Framed size must stay `> L1_INBOX_MESSAGE_LIMIT` — the
        /// message is chunked and routed via DAL, then referenced from
        /// L1 via a `DalPointer`.  If a `RequiresDal` variant ever
        /// shrinks to fit in L1, the DAL routing for it becomes dead
        /// code and the classification needs to be reconsidered.
        RequiresDal,
    }

    fn required_routing(message: &KernelInboxMessage) -> Routing {
        // Exhaustive match on purpose: any new `KernelInboxMessage`
        // variant MUST be classified here, forcing the author to
        // decide whether it fits in L1 or needs DAL chunking.
        match message {
            KernelInboxMessage::ConfigureVerifier(_)
            | KernelInboxMessage::ConfigureBridge(_) => Routing::RequiresDal,
            KernelInboxMessage::Shield(_)
            | KernelInboxMessage::Transfer(_)
            | KernelInboxMessage::Unshield(_) => Routing::RequiresDal,
            KernelInboxMessage::Withdraw(_) => Routing::FitsL1,
            KernelInboxMessage::DalPointer(_) => Routing::FitsL1,
        }
    }

    /// Frame overhead added by `ExternalMessageFrame::Targetted` on
    /// top of the raw `encode_kernel_inbox_message` bytes when
    /// `octez-client send smart rollup message` injects a payload.
    ///
    /// Layout:
    ///   - 1 byte for the `Targetted` tag
    ///   - 20 bytes for the `SmartRollupHash` (no length prefix on
    ///     wire; the type is fixed-size)
    ///
    /// Verified empirically against the hex output of
    /// `octez_kernel_message dal-pointer …` on a valid sr1 address.
    /// Replicated here to avoid dragging
    /// `tezos-smart-rollup-encoding` (which pins a different
    /// `tezos_data_encoding` major than `core`'s direct dep) into
    /// this crate's test deps.
    const EXTERNAL_MESSAGE_FRAME_OVERHEAD: usize = 21;

    /// Return the on-wire size the L1 inbox sees for this message,
    /// i.e. `encode_kernel_inbox_message(...).len()` plus the fixed
    /// `ExternalMessageFrame::Targetted` overhead.  This is the
    /// value subject to `sc_rollup_message_size_limit = 4096`.
    fn framed_len(message: &KernelInboxMessage) -> usize {
        let payload = encode_kernel_inbox_message(message).expect("encode message");
        payload.len() + EXTERNAL_MESSAGE_FRAME_OVERHEAD
    }

    /// A proof large enough to push Shield/Transfer/Unshield over the
    /// L1 size limit once framed.  Production STARK proofs are
    /// hundreds of kilobytes; 4096 bytes of filler is the cheapest
    /// size that makes the RequiresDal classification hold
    /// unambiguously while staying well below `MAX_PROOF_BYTES`.
    fn oversize_kernel_stark_proof() -> KernelStarkProof {
        KernelStarkProof {
            proof_bytes: vec![0xaa; 4096],
            output_preimage: vec![[7u8; 32]],
            verify_meta: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn inbox_size_invariant_covers_all_variants() {
        let ask = crate::hash(b"tzel-dev-rollup-config-admin");

        let configure_verifier = KernelInboxMessage::ConfigureVerifier(
            sign_kernel_verifier_config(
                &ask,
                KernelVerifierConfig {
                    auth_domain: [0xAA; 32],
                    verified_program_hashes: ProgramHashes {
                        shield: [0xBB; 32],
                        transfer: [0xCC; 32],
                        unshield: [0xDD; 32],
                    },
                },
            )
            .expect("sign verifier"),
        );
        let configure_bridge = KernelInboxMessage::ConfigureBridge(
            sign_kernel_bridge_config(
                &ask,
                KernelBridgeConfig {
                    ticketer: "KT1Fq8fPi2NjhWUXtcXBggbL6zFjZctGkmso".to_string(),
                },
            )
            .expect("sign bridge"),
        );
        let shield = KernelInboxMessage::Shield(KernelShieldReq {
            sender: "alice".into(),
            fee: 100,
            v: 400,
            producer_fee: 1,
            address: sample_payment_address(),
            memo: None,
            proof: oversize_kernel_stark_proof(),
            client_cm: ZERO,
            client_enc: None,
            producer_cm: [0; 32],
            producer_enc: Some(sample_encrypted_note(0x42)),
        });
        let transfer = KernelInboxMessage::Transfer(KernelTransferReq {
            root: [1; 32],
            nullifiers: vec![[2; 32]],
            fee: 100,
            cm_1: [4; 32],
            cm_2: [5; 32],
            cm_3: [6; 32],
            enc_1: sample_encrypted_note(0x11),
            enc_2: sample_encrypted_note(0x22),
            enc_3: sample_encrypted_note(0x33),
            proof: oversize_kernel_stark_proof(),
        });
        let unshield = KernelInboxMessage::Unshield(KernelUnshieldReq {
            root: [1; 32],
            nullifiers: vec![[2; 32]],
            v_pub: 100,
            fee: 100,
            recipient: "alice".into(),
            cm_change: [3; 32],
            enc_change: None,
            cm_fee: [4; 32],
            enc_fee: sample_encrypted_note(0x11),
            proof: oversize_kernel_stark_proof(),
        });
        let withdraw = KernelInboxMessage::Withdraw(KernelWithdrawReq {
            sender: "alice".into(),
            recipient: "tz1target".into(),
            amount: 42,
        });
        let dal_pointer = KernelInboxMessage::DalPointer(KernelDalPayloadPointer {
            kind: KernelDalPayloadKind::Shield,
            chunks: vec![KernelDalChunkPointer {
                published_level: 100,
                slot_index: 0,
                payload_len: 4096,
            }],
            payload_len: 4096,
            payload_hash: [0xA5; 32],
        });

        let cases: [(&str, &KernelInboxMessage); 7] = [
            ("ConfigureVerifier", &configure_verifier),
            ("ConfigureBridge", &configure_bridge),
            ("Shield", &shield),
            ("Transfer", &transfer),
            ("Unshield", &unshield),
            ("Withdraw", &withdraw),
            ("DalPointer", &dal_pointer),
        ];

        for (name, message) in cases {
            let expected = required_routing(message);
            let size = framed_len(message);
            match expected {
                Routing::FitsL1 => assert!(
                    size <= L1_INBOX_MESSAGE_LIMIT,
                    "{}: classified FitsL1 but framed size {} > {}; either the \
                     message grew past the L1 limit and needs a DAL route, or \
                     the classification in `required_routing` is wrong",
                    name,
                    size,
                    L1_INBOX_MESSAGE_LIMIT,
                ),
                Routing::RequiresDal => assert!(
                    size > L1_INBOX_MESSAGE_LIMIT,
                    "{}: classified RequiresDal but framed size {} <= {}; the \
                     message now fits in L1, making the DAL routing for this \
                     variant dead code — either downgrade to FitsL1 (and prune \
                     the DAL plumbing) or grow the representative instance",
                    name,
                    size,
                    L1_INBOX_MESSAGE_LIMIT,
                ),
            }
        }
    }
}
