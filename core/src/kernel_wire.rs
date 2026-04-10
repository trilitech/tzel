use crate::canonical_wire::{
    decode_tze, encode_tze, felt_to_wire, u16_to_wire, u64_to_wire, wire_to_felt, wire_to_u16,
    wire_to_u64, WireEncryptedNote, WireFelt, WirePaymentAddress, WireU16Le, WireU64Le,
};
use crate::{
    EncryptedNote, ENCRYPTED_NOTE_BYTES, F, FundReq, ML_KEM768_CIPHERTEXT_BYTES, PaymentAddress,
    ProgramHashes, Proof, ShieldReq, ShieldResp, TransferReq, TransferResp, UnshieldReq,
    UnshieldResp,
};
use tezos_data_encoding::enc::BinWriter;
use tezos_data_encoding::encoding::HasEncoding;
use tezos_data_encoding::nom::NomReader;

pub const KERNEL_WIRE_VERSION: u16 = 1;
const MAX_ACCOUNT_ID_BYTES: usize = 1024;
const MAX_MEMO_BYTES: usize = 4096;
const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;
const MAX_OUTPUT_PREIMAGE_ITEMS: usize = 1024;
const MAX_VERIFY_META_BYTES: usize = 8 * 1024 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 4096;
const MAX_ENCODED_NOTE_WIRE_BYTES: usize =
    (ML_KEM768_CIPHERTEXT_BYTES * 2) + ENCRYPTED_NOTE_BYTES + 32;
const MAX_ENCODED_PROOF_WIRE_BYTES: usize =
    MAX_PROOF_BYTES + MAX_VERIFY_META_BYTES + (MAX_OUTPUT_PREIMAGE_ITEMS * 64) + 4096;
const MAX_ENCODED_NULLIFIER_LIST_BYTES: usize = 256 * 1024;
const MAX_TRANSFER_PAYLOAD_BYTES: usize =
    (4 * 32) + MAX_ENCODED_PROOF_WIRE_BYTES + (2 * MAX_ENCODED_NOTE_WIRE_BYTES) + 65536;
const MAX_UNSHIELD_PAYLOAD_BYTES: usize =
    (3 * 32) + MAX_ENCODED_PROOF_WIRE_BYTES + MAX_ENCODED_NOTE_WIRE_BYTES + 65536;

#[derive(Debug, Clone)]
pub struct KernelVerifierConfig {
    pub auth_domain: F,
    pub verified_program_hashes: ProgramHashes,
}

#[derive(Debug, Clone)]
pub struct KernelStarkProof {
    pub proof_bytes: Vec<u8>,
    pub output_preimage: Vec<F>,
    pub verify_meta: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct KernelShieldReq {
    pub sender: String,
    pub v: u64,
    pub address: PaymentAddress,
    pub memo: Option<String>,
    pub proof: KernelStarkProof,
    pub client_cm: F,
    pub client_enc: Option<EncryptedNote>,
}

#[derive(Debug, Clone)]
pub struct KernelTransferReq {
    pub root: F,
    pub nullifiers: Vec<F>,
    pub cm_1: F,
    pub cm_2: F,
    pub enc_1: EncryptedNote,
    pub enc_2: EncryptedNote,
    pub proof: KernelStarkProof,
}

#[derive(Debug, Clone)]
pub struct KernelUnshieldReq {
    pub root: F,
    pub nullifiers: Vec<F>,
    pub v_pub: u64,
    pub recipient: String,
    pub cm_change: F,
    pub enc_change: Option<EncryptedNote>,
    pub proof: KernelStarkProof,
}

#[derive(Debug, Clone)]
pub enum KernelInboxMessage {
    ConfigureVerifier(KernelVerifierConfig),
    Fund(FundReq),
    Shield(KernelShieldReq),
    Transfer(KernelTransferReq),
    Unshield(KernelUnshieldReq),
}

#[derive(Debug, Clone)]
pub enum KernelResult {
    Configured,
    Fund,
    Shield(ShieldResp),
    Transfer(TransferResp),
    Unshield(UnshieldResp),
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireProgramHashes {
    shield: WireFelt,
    transfer: WireFelt,
    unshield: WireFelt,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireVerifyMetaJson {
    #[encoding(dynamic, bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireOutputPreimage {
    #[encoding(dynamic)]
    items: Vec<WireFelt>,
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
struct WireStarkProof {
    #[encoding(dynamic = "MAX_PROOF_BYTES", bytes)]
    proof_bytes: Vec<u8>,
    output_preimage: WireOutputPreimage,
    #[encoding(dynamic = "MAX_VERIFY_META_BYTES")]
    verify_meta: WireVerifyMetaJson,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelVerifierConfig {
    auth_domain: WireFelt,
    verified_program_hashes: WireProgramHashes,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireFundReq {
    #[encoding(string = "MAX_ACCOUNT_ID_BYTES")]
    addr: String,
    amount: WireU64Le,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelShieldReq {
    #[encoding(string = "MAX_ACCOUNT_ID_BYTES")]
    sender: String,
    v: WireU64Le,
    address: WirePaymentAddress,
    #[encoding(string = "MAX_MEMO_BYTES")]
    memo: Option<String>,
    proof: WireStarkProof,
    client_cm: WireFelt,
    client_enc: Option<WireEncryptedNote>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireShieldResp {
    cm: WireFelt,
    index: WireU64Le,
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
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelUnshieldReq {
    #[encoding(dynamic = "MAX_UNSHIELD_PAYLOAD_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireUnshieldResp {
    change_index: Option<WireU64Le>,
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
    ConfigureVerifier(WireKernelVerifierConfig),
    #[encoding(tag = 1)]
    Fund(WireFundReq),
    #[encoding(tag = 2)]
    Shield(WireKernelShieldReq),
    #[encoding(tag = 3)]
    Transfer(WireKernelTransferReq),
    #[encoding(tag = 4)]
    Unshield(WireKernelUnshieldReq),
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
    Fund,
    #[encoding(tag = 2)]
    Shield(WireShieldResp),
    #[encoding(tag = 3)]
    Transfer(WireTransferResp),
    #[encoding(tag = 4)]
    Unshield(WireUnshieldResp),
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
                WireKernelInboxMessage::ConfigureVerifier(config_to_wire(cfg))
            }
            KernelInboxMessage::Fund(req) => WireKernelInboxMessage::Fund(fund_req_to_wire(req)),
            KernelInboxMessage::Shield(req) => {
                WireKernelInboxMessage::Shield(kernel_shield_req_to_wire(req)?)
            }
            KernelInboxMessage::Transfer(req) => {
                WireKernelInboxMessage::Transfer(kernel_transfer_req_to_wire(req)?)
            }
            KernelInboxMessage::Unshield(req) => {
                WireKernelInboxMessage::Unshield(kernel_unshield_req_to_wire(req)?)
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
        WireKernelInboxMessage::ConfigureVerifier(cfg) => {
            Ok(KernelInboxMessage::ConfigureVerifier(config_from_wire(cfg)?))
        }
        WireKernelInboxMessage::Fund(req) => Ok(KernelInboxMessage::Fund(fund_req_from_wire(req)?)),
        WireKernelInboxMessage::Shield(req) => {
            Ok(KernelInboxMessage::Shield(kernel_shield_req_from_wire(req)?))
        }
        WireKernelInboxMessage::Transfer(req) => {
            Ok(KernelInboxMessage::Transfer(kernel_transfer_req_from_wire(req)?))
        }
        WireKernelInboxMessage::Unshield(req) => {
            Ok(KernelInboxMessage::Unshield(kernel_unshield_req_from_wire(req)?))
        }
    }
}

pub fn encode_kernel_result(result: &KernelResult) -> Result<Vec<u8>, String> {
    encode_tze(&WireKernelResultEnvelope {
        version: u16_to_wire(KERNEL_WIRE_VERSION),
        result: match result {
            KernelResult::Configured => WireKernelResult::Configured,
            KernelResult::Fund => WireKernelResult::Fund,
            KernelResult::Shield(resp) => WireKernelResult::Shield(shield_resp_to_wire(resp)?),
            KernelResult::Transfer(resp) => {
                WireKernelResult::Transfer(transfer_resp_to_wire(resp)?)
            }
            KernelResult::Unshield(resp) => {
                WireKernelResult::Unshield(unshield_resp_to_wire(resp)?)
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
        WireKernelResult::Fund => Ok(KernelResult::Fund),
        WireKernelResult::Shield(resp) => Ok(KernelResult::Shield(shield_resp_from_wire(resp)?)),
        WireKernelResult::Transfer(resp) => {
            Ok(KernelResult::Transfer(transfer_resp_from_wire(resp)?))
        }
        WireKernelResult::Unshield(resp) => {
            Ok(KernelResult::Unshield(unshield_resp_from_wire(resp)?))
        }
        WireKernelResult::Error(err) => Ok(KernelResult::Error {
            message: err.message,
        }),
    }
}

pub fn encode_kernel_verifier_config(config: &KernelVerifierConfig) -> Result<Vec<u8>, String> {
    encode_tze(&config_to_wire(config))
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
        v: req.v,
        address: req.address.clone(),
        memo: req.memo.clone(),
        proof: kernel_proof_to_host(&req.proof),
        client_cm: req.client_cm,
        client_enc: req.client_enc.clone(),
    }
}

pub fn kernel_transfer_req_to_host(req: &KernelTransferReq) -> TransferReq {
    TransferReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        cm_1: req.cm_1,
        cm_2: req.cm_2,
        enc_1: req.enc_1.clone(),
        enc_2: req.enc_2.clone(),
        proof: kernel_proof_to_host(&req.proof),
    }
}

pub fn kernel_unshield_req_to_host(req: &KernelUnshieldReq) -> UnshieldReq {
    UnshieldReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        v_pub: req.v_pub,
        recipient: req.recipient.clone(),
        cm_change: req.cm_change,
        enc_change: req.enc_change.clone(),
        proof: kernel_proof_to_host(&req.proof),
    }
}

fn config_to_wire(config: &KernelVerifierConfig) -> WireKernelVerifierConfig {
    WireKernelVerifierConfig {
        auth_domain: felt_to_wire(&config.auth_domain),
        verified_program_hashes: program_hashes_to_wire(&config.verified_program_hashes),
    }
}

fn config_from_wire(wire: WireKernelVerifierConfig) -> Result<KernelVerifierConfig, String> {
    Ok(KernelVerifierConfig {
        auth_domain: wire_to_felt(wire.auth_domain)?,
        verified_program_hashes: program_hashes_from_wire(wire.verified_program_hashes)?,
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
        nk_tag: felt_to_wire(&address.nk_tag),
        ek_v: address.ek_v.clone(),
        ek_d: address.ek_d.clone(),
    }
}

fn payment_address_from_wire(wire: WirePaymentAddress) -> Result<PaymentAddress, String> {
    Ok(PaymentAddress {
        d_j: wire_to_felt(wire.d_j)?,
        auth_root: wire_to_felt(wire.auth_root)?,
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
        encrypted_data: enc.encrypted_data.clone(),
    })
}

fn encrypted_note_from_wire(wire: WireEncryptedNote) -> Result<EncryptedNote, String> {
    let enc = EncryptedNote {
        ct_d: wire.ct_d,
        tag: wire_to_u16(wire.tag)?,
        ct_v: wire.ct_v,
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
    let verify_meta = serde_json::to_vec(&proof.verify_meta)
        .map(|bytes| WireVerifyMetaJson { bytes })
        .map_err(|e| format!("verify_meta JSON serialization failed: {}", e))?;
    Ok(WireStarkProof {
        proof_bytes: proof.proof_bytes.clone(),
        output_preimage: WireOutputPreimage {
            items: proof.output_preimage.iter().map(felt_to_wire).collect(),
        },
        verify_meta,
    })
}

fn kernel_proof_from_wire(proof: WireStarkProof) -> Result<KernelStarkProof, String> {
    if proof.proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(format!(
            "proof too large for kernel wire: {} > {}",
            proof.proof_bytes.len(),
            MAX_PROOF_BYTES
        ));
    }
    if proof.output_preimage.items.len() > MAX_OUTPUT_PREIMAGE_ITEMS {
        return Err(format!(
            "output_preimage too long for kernel wire: {} > {}",
            proof.output_preimage.items.len(),
            MAX_OUTPUT_PREIMAGE_ITEMS
        ));
    }
    Ok(KernelStarkProof {
        proof_bytes: proof.proof_bytes,
        output_preimage: proof
            .output_preimage
            .items
            .into_iter()
            .map(wire_to_felt)
            .collect::<Result<Vec<_>, _>>()?,
        verify_meta: serde_json::from_slice(&proof.verify_meta.bytes)
            .map_err(|e| format!("verify_meta JSON parse failed: {}", e))?,
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
        bytes: encode_tze(&kernel_proof_to_wire(proof)?)?,
    })
}

fn encoded_proof_from_wire(wire: WireEncodedProof) -> Result<KernelStarkProof, String> {
    let inner: WireStarkProof = decode_tze(&wire.bytes)?;
    kernel_proof_from_wire(inner)
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

fn fund_req_to_wire(req: &FundReq) -> WireFundReq {
    WireFundReq {
        addr: req.addr.clone(),
        amount: u64_to_wire(req.amount),
    }
}

fn fund_req_from_wire(wire: WireFundReq) -> Result<FundReq, String> {
    Ok(FundReq {
        addr: wire.addr,
        amount: wire_to_u64(wire.amount)?,
    })
}

fn kernel_shield_req_to_wire(req: &KernelShieldReq) -> Result<WireKernelShieldReq, String> {
    Ok(WireKernelShieldReq {
        sender: req.sender.clone(),
        v: u64_to_wire(req.v),
        address: payment_address_to_wire(&req.address),
        memo: req.memo.clone(),
        proof: kernel_proof_to_wire(&req.proof)?,
        client_cm: felt_to_wire(&req.client_cm),
        client_enc: req.client_enc.as_ref().map(encrypted_note_to_wire).transpose()?,
    })
}

fn kernel_shield_req_from_wire(wire: WireKernelShieldReq) -> Result<KernelShieldReq, String> {
    Ok(KernelShieldReq {
        sender: wire.sender,
        v: wire_to_u64(wire.v)?,
        address: payment_address_from_wire(wire.address)?,
        memo: wire.memo,
        proof: kernel_proof_from_wire(wire.proof)?,
        client_cm: wire_to_felt(wire.client_cm)?,
        client_enc: wire.client_enc.map(encrypted_note_from_wire).transpose()?,
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
    })
}

fn shield_resp_from_wire(wire: WireShieldResp) -> Result<ShieldResp, String> {
    Ok(ShieldResp {
        cm: wire_to_felt(wire.cm)?,
        index: wire_to_u64(wire.index)?
            .try_into()
            .map_err(|_| "shield index does not fit in usize".to_string())?,
    })
}

fn kernel_transfer_req_to_wire(req: &KernelTransferReq) -> Result<WireKernelTransferReq, String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.root))?);
    bytes.extend_from_slice(&encode_tze(&encoded_felt_list_to_wire(&req.nullifiers)?)?);
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.cm_1))?);
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.cm_2))?);
    bytes.extend_from_slice(&encode_tze(&encoded_proof_to_wire(&req.proof)?)?);
    bytes.extend_from_slice(&encode_tze(&encoded_note_to_wire(&req.enc_1)?)?);
    bytes.extend_from_slice(&encode_tze(&encoded_note_to_wire(&req.enc_2)?)?);
    Ok(WireKernelTransferReq { bytes })
}

fn kernel_transfer_req_from_wire(wire: WireKernelTransferReq) -> Result<KernelTransferReq, String> {
    let (rest, root) = decode_tze_prefix::<WireFelt>(&wire.bytes)?;
    let (rest, nullifiers) = decode_tze_prefix::<WireEncodedFeltList>(rest)?;
    let (rest, cm_1) = decode_tze_prefix::<WireFelt>(rest)?;
    let (rest, cm_2) = decode_tze_prefix::<WireFelt>(rest)?;
    let (rest, proof) = decode_tze_prefix::<WireEncodedProof>(rest)?;
    let (rest, enc_1) = decode_tze_prefix::<WireEncodedNote>(rest)?;
    let (rest, enc_2) = decode_tze_prefix::<WireEncodedNote>(rest)?;
    if !rest.is_empty() {
        return Err(format!(
            "kernel transfer payload left {} trailing bytes",
            rest.len()
        ));
    }
    Ok(KernelTransferReq {
        root: wire_to_felt(root)?,
        nullifiers: encoded_felt_list_from_wire(nullifiers)?,
        cm_1: wire_to_felt(cm_1)?,
        cm_2: wire_to_felt(cm_2)?,
        proof: encoded_proof_from_wire(proof)?,
        enc_1: encoded_note_from_wire(enc_1)?,
        enc_2: encoded_note_from_wire(enc_2)?,
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
    })
}

fn kernel_unshield_req_to_wire(req: &KernelUnshieldReq) -> Result<WireKernelUnshieldReq, String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.root))?);
    bytes.extend_from_slice(&encode_tze(&encoded_felt_list_to_wire(&req.nullifiers)?)?);
    bytes.extend_from_slice(&encode_tze(&u64_to_wire(req.v_pub))?);
    bytes.extend_from_slice(&encode_tze(&WireAccountId {
        value: req.recipient.clone(),
    })?);
    bytes.extend_from_slice(&encode_tze(&felt_to_wire(&req.cm_change))?);
    bytes.extend_from_slice(&encode_tze(&encoded_proof_to_wire(&req.proof)?)?);
    bytes.extend_from_slice(&encode_tze(&WireOptionalEncodedNote {
        note: req.enc_change.as_ref().map(encoded_note_to_wire).transpose()?,
    })?);
    Ok(WireKernelUnshieldReq { bytes })
}

fn kernel_unshield_req_from_wire(wire: WireKernelUnshieldReq) -> Result<KernelUnshieldReq, String> {
    let (rest, root) = decode_tze_prefix::<WireFelt>(&wire.bytes)?;
    let (rest, nullifiers) = decode_tze_prefix::<WireEncodedFeltList>(rest)?;
    let (rest, v_pub) = decode_tze_prefix::<WireU64Le>(rest)?;
    let (rest, recipient) = decode_tze_prefix::<WireAccountId>(rest)?;
    let (rest, cm_change) = decode_tze_prefix::<WireFelt>(rest)?;
    let (rest, proof) = decode_tze_prefix::<WireEncodedProof>(rest)?;
    let (rest, enc_change) = decode_tze_prefix::<WireOptionalEncodedNote>(rest)?;
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
        recipient: recipient.value,
        cm_change: wire_to_felt(cm_change)?,
        proof: encoded_proof_from_wire(proof)?,
        enc_change: enc_change.note.map(encoded_note_from_wire).transpose()?,
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build_auth_tree, derive_account, derive_address, derive_ask, derive_kem_keys,
        derive_nk_spend, derive_nk_tag, ZERO,
    };
    use ml_kem::KeyExport;

    #[test]
    fn kernel_inbox_roundtrip_preserves_shield_request() {
        let message = KernelInboxMessage::Shield(KernelShieldReq {
            sender: "alice".into(),
            v: 42,
            address: sample_payment_address(),
            memo: Some("hello".into()),
            proof: sample_kernel_stark_proof(),
            client_cm: ZERO,
            client_enc: None,
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Shield(req) => {
                assert_eq!(req.sender, "alice");
                assert_eq!(req.v, 42);
                assert_eq!(req.memo.as_deref(), Some("hello"));
                assert_eq!(req.proof.proof_bytes, sample_kernel_stark_proof().proof_bytes);
                assert_eq!(req.address.d_j, sample_payment_address().d_j);
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_binary_stark_proof() {
        let message = KernelInboxMessage::Transfer(KernelTransferReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32], [3u8; 32]],
            cm_1: [4u8; 32],
            cm_2: [5u8; 32],
            enc_1: sample_encrypted_note(0x11),
            enc_2: sample_encrypted_note(0x22),
            proof: sample_kernel_stark_proof(),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Transfer(req) => {
                assert_eq!(req.proof.proof_bytes, sample_kernel_stark_proof().proof_bytes);
                assert_eq!(
                    req.proof.output_preimage,
                    sample_kernel_stark_proof().output_preimage
                );
                assert_eq!(req.proof.verify_meta, sample_kernel_stark_proof().verify_meta);
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
            cm_1: [4u8; 32],
            cm_2: [5u8; 32],
            enc_1: sample_encrypted_note(0x11),
            enc_2: sample_encrypted_note(0x22),
            proof: sample_kernel_stark_proof(),
        };
        let wire = kernel_transfer_req_to_wire(&req).unwrap();
        let encoded = encode_tze(&wire).unwrap();
        let decoded: WireKernelTransferReq = decode_tze(&encoded).unwrap();
        let host = kernel_transfer_req_from_wire(decoded).unwrap();
        assert_eq!(host.root, req.root);
        assert_eq!(host.nullifiers, req.nullifiers);
        assert_eq!(host.cm_1, req.cm_1);
        assert_eq!(host.cm_2, req.cm_2);
        assert_eq!(host.enc_1.ct_d, req.enc_1.ct_d);
        assert_eq!(host.enc_1.tag, req.enc_1.tag);
        assert_eq!(host.enc_1.ct_v, req.enc_1.ct_v);
        assert_eq!(host.enc_1.encrypted_data, req.enc_1.encrypted_data);
        assert_eq!(host.enc_2.ct_d, req.enc_2.ct_d);
        assert_eq!(host.enc_2.tag, req.enc_2.tag);
        assert_eq!(host.enc_2.ct_v, req.enc_2.ct_v);
        assert_eq!(host.enc_2.encrypted_data, req.enc_2.encrypted_data);
        assert_eq!(host.proof.proof_bytes, req.proof.proof_bytes);
    }

    #[test]
    fn kernel_transfer_payload_fields_roundtrip_individually() {
        let req = KernelTransferReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32], [3u8; 32]],
            cm_1: [4u8; 32],
            cm_2: [5u8; 32],
            enc_1: sample_encrypted_note(0x11),
            enc_2: sample_encrypted_note(0x22),
            proof: sample_kernel_stark_proof(),
        };
        let wire = kernel_transfer_req_to_wire(&req).unwrap();
        let (rest, root) = decode_tze_prefix::<WireFelt>(&wire.bytes).unwrap();
        assert_eq!(wire_to_felt(root).unwrap(), req.root);
        let (rest, nullifiers) = decode_tze_prefix::<WireEncodedFeltList>(rest).unwrap();
        let decoded_nullifiers = encoded_felt_list_from_wire(nullifiers).unwrap();
        assert_eq!(decoded_nullifiers, req.nullifiers);
        let (rest, cm_1) = decode_tze_prefix::<WireFelt>(rest).unwrap();
        assert_eq!(wire_to_felt(cm_1).unwrap(), req.cm_1);
        let (rest, cm_2) = decode_tze_prefix::<WireFelt>(rest).unwrap();
        assert_eq!(wire_to_felt(cm_2).unwrap(), req.cm_2);
        let (rest, proof) = decode_tze_prefix::<WireEncodedProof>(rest).unwrap();
        let decoded_proof = encoded_proof_from_wire(proof).unwrap();
        assert_eq!(decoded_proof.proof_bytes, req.proof.proof_bytes);
        let (rest, enc_1) = decode_tze_prefix::<WireEncodedNote>(rest).unwrap();
        let decoded_enc_1 = encoded_note_from_wire(enc_1).unwrap();
        assert_eq!(decoded_enc_1.ct_d, req.enc_1.ct_d);
        let (rest, enc_2) = decode_tze_prefix::<WireEncodedNote>(rest).unwrap();
        let decoded_enc_2 = encoded_note_from_wire(enc_2).unwrap();
        assert_eq!(decoded_enc_2.ct_d, req.enc_2.ct_d);
        assert!(rest.is_empty());
    }

    #[test]
    fn kernel_unshield_wire_struct_roundtrips() {
        let req = KernelUnshieldReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32]],
            v_pub: 33,
            recipient: "bob".into(),
            cm_change: [4u8; 32],
            enc_change: Some(sample_encrypted_note(0x33)),
            proof: sample_kernel_stark_proof(),
        };
        let wire = kernel_unshield_req_to_wire(&req).unwrap();
        let encoded = encode_tze(&wire).unwrap();
        let decoded: WireKernelUnshieldReq = decode_tze(&encoded).unwrap();
        let host = kernel_unshield_req_from_wire(decoded).unwrap();
        assert_eq!(host.root, req.root);
        assert_eq!(host.nullifiers, req.nullifiers);
        assert_eq!(host.v_pub, req.v_pub);
        assert_eq!(host.recipient, req.recipient);
        assert_eq!(host.cm_change, req.cm_change);
        let host_change = host.enc_change.expect("missing decoded change note");
        let req_change = req.enc_change.expect("missing original change note");
        assert_eq!(host_change.ct_d, req_change.ct_d);
        assert_eq!(host_change.tag, req_change.tag);
        assert_eq!(host_change.ct_v, req_change.ct_v);
        assert_eq!(host_change.encrypted_data, req_change.encrypted_data);
        assert_eq!(host.proof.proof_bytes, req.proof.proof_bytes);
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_transfer_request() {
        let message = KernelInboxMessage::Transfer(KernelTransferReq {
            root: [1u8; 32],
            nullifiers: vec![[2u8; 32]],
            cm_1: [4u8; 32],
            cm_2: [5u8; 32],
            enc_1: sample_encrypted_note(0x11),
            enc_2: sample_encrypted_note(0x22),
            proof: sample_kernel_stark_proof(),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Transfer(req) => {
                assert_eq!(req.proof.proof_bytes, sample_kernel_stark_proof().proof_bytes);
                assert_eq!(req.root, [1u8; 32]);
                assert_eq!(req.nullifiers, vec![[2u8; 32]]);
                assert_eq!(req.cm_1, [4u8; 32]);
                assert_eq!(req.cm_2, [5u8; 32]);
                assert_eq!(req.enc_1.ct_d, sample_encrypted_note(0x11).ct_d);
                assert_eq!(req.enc_2.ct_v, sample_encrypted_note(0x22).ct_v);
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
            recipient: "bob".into(),
            cm_change: [4u8; 32],
            enc_change: Some(sample_encrypted_note(0x33)),
            proof: sample_kernel_stark_proof(),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Unshield(req) => {
                assert_eq!(req.proof.proof_bytes, sample_kernel_stark_proof().proof_bytes);
                assert_eq!(req.root, [1u8; 32]);
                assert_eq!(req.nullifiers, vec![[2u8; 32]]);
                assert_eq!(req.v_pub, 33);
                assert_eq!(req.recipient, "bob");
                assert_eq!(req.cm_change, [4u8; 32]);
                assert_eq!(
                    req.enc_change.as_ref().unwrap().encrypted_data,
                    sample_encrypted_note(0x33).encrypted_data
                );
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
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

    fn sample_encrypted_note(fill: u8) -> EncryptedNote {
        EncryptedNote {
            ct_d: vec![fill; crate::ML_KEM768_CIPHERTEXT_BYTES],
            tag: 17,
            ct_v: vec![fill ^ 0x5a; crate::ML_KEM768_CIPHERTEXT_BYTES],
            encrypted_data: vec![fill.wrapping_add(1); crate::ENCRYPTED_NOTE_BYTES],
        }
    }

    fn sample_kernel_stark_proof() -> KernelStarkProof {
        KernelStarkProof {
            proof_bytes: vec![0xaa, 0xbb, 0xcc],
            output_preimage: vec![[7u8; 32], [8u8; 32]],
            verify_meta: serde_json::json!({"proof_config": {"foo": 1}}),
        }
    }
}
