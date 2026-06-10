use crate::canonical_wire::{
    decode_tze, encode_tze, felt_to_wire, u16_to_wire, u64_to_wire, wire_to_felt, wire_to_u16,
    wire_to_u64, WireEncryptedNote, WireFelt, WireU16Le, WireU64Le,
};
use crate::{
    hash, wots_sign, EncryptedNote, ProgramHashes, Proof, ShieldReq, ShieldResp, TransferReq,
    TransferResp, UnshieldReq, UnshieldResp, ENCRYPTED_NOTE_BYTES, F, ML_KEM768_CIPHERTEXT_BYTES,
    NOTE_AEAD_NONCE_BYTES, OUTGOING_RECOVERY_CT_BYTES,
};
use tezos_data_encoding::enc::BinWriter;
use tezos_data_encoding::encoding::HasEncoding;
use tezos_data_encoding::nom::NomReader;

/// v18 adds the DAL-free submission messages (`StageChunk`, `SubmitOps`);
/// the v17 DAL-pointer path is still encodable and is deleted in track W2.
// TODO(W2): tezos/tzel_orchestrator.mligo pins `kernel_wire_version_le = 0x1100`
// (v17) in its framing; bump it to 0x1200 when the kernel switches to v18-only.
pub const KERNEL_WIRE_VERSION: u16 = 18;
pub const KERNEL_VERIFIER_CONFIG_KEY_INDEX: u32 = 0;
pub const KERNEL_BRIDGE_CONFIG_KEY_INDEX: u32 = 1;
const MAX_ACCOUNT_ID_BYTES: usize = 1024;
const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;
const MAX_OUTPUT_PREIMAGE_ITEMS: usize = 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 4096;
const MAX_DAL_CHUNK_POINTERS: usize = 256;
const MAX_DAL_CHUNK_LIST_BYTES: usize = 64 * 1024;
const MAX_ENCODED_NOTE_WIRE_BYTES: usize = (ML_KEM768_CIPHERTEXT_BYTES * 2)
    + NOTE_AEAD_NONCE_BYTES
    + ENCRYPTED_NOTE_BYTES
    + OUTGOING_RECOVERY_CT_BYTES
    + 32;
const MAX_ENCODED_PROOF_WIRE_BYTES: usize =
    MAX_PROOF_BYTES + (MAX_OUTPUT_PREIMAGE_ITEMS * 64) + 4096;
const MAX_ENCODED_NULLIFIER_LIST_BYTES: usize = 256 * 1024;
const MAX_TRANSFER_PAYLOAD_BYTES: usize =
    (5 * 32) + MAX_ENCODED_PROOF_WIRE_BYTES + (3 * MAX_ENCODED_NOTE_WIRE_BYTES) + 65536;
const MAX_UNSHIELD_PAYLOAD_BYTES: usize =
    (4 * 32) + MAX_ENCODED_PROOF_WIRE_BYTES + (2 * MAX_ENCODED_NOTE_WIRE_BYTES) + 65536;

// --- v18 DAL-free submission bounds (docs/SNARK-SUBMISSION-DESIGN.md) ---
/// Max payload bytes carried by a single `StageChunk` (~3.9 KiB after the
/// 4096-byte inbox framing overhead).
pub const MAX_STAGE_CHUNK_BYTES: usize = 3900;
/// The 1-commitment gnark wrap proof is 388 bytes; bound with headroom for
/// VK/commitment-shape rotation.
pub const MAX_GROTH16_PROOF_BYTES: usize = 1024;
/// Max ops declared by one `SubmitOps` (one mv tree of depth 4).
pub const MAX_BATCH_OPS: usize = 16;
/// Max mv aggregation tree depth bindable by `SubmitOps` (2^4 = 16 leaves).
pub const MAX_TREE_DEPTH: u8 = 4;
/// Max staged-note references per declared op (shield: 2, transfer: 3,
/// unshield: ≤ 2 — headroom for future shapes).
pub const MAX_STAGED_NOTE_REFS_PER_OP: usize = 8;
/// M31 values are < 2^31 - 1 (mirrors `MvNodePublics::check_m31` in
/// verifier/src/snark.rs).
const M31_LANE_LIMIT: u32 = (1 << 31) - 1;
const TREE_ROOTS_COUNT: usize = 4;
const MAX_STAGED_NOTE_LIST_BYTES: usize = 4096;
const MAX_LEAF_SLOT_LIST_BYTES: usize = 4096;
const MAX_OP_DECL_LIST_BYTES: usize = MAX_BATCH_OPS
    * ((MAX_OUTPUT_PREIMAGE_ITEMS * 32) + MAX_ENCODED_NULLIFIER_LIST_BYTES + 8192);

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
}

/// Shield message: drains `v + fee + producer_fee` mutez from the deposit
/// pool keyed by `pubkey_hash`. Both notes are fully constructed client-side
/// and the server has no role in fabricating them. The shield's STARK proof
/// includes an in-circuit WOTS+ signature under the recipient's auth tree
/// (matching `pubkey_hash = H(auth_domain, auth_root, auth_pub_seed, blind)`),
/// authorizing this specific draw.
#[derive(Debug, Clone)]
pub struct KernelShieldReq {
    pub pubkey_hash: F,
    pub fee: u64,
    pub v: u64,
    pub producer_fee: u64,
    pub proof: KernelStarkProof,
    pub client_cm: F,
    pub client_enc: EncryptedNote,
    pub producer_cm: F,
    pub producer_enc: EncryptedNote,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelDalPayloadKind {
    ConfigureVerifier,
    ConfigureBridge,
    Shield,
    Transfer,
    Unshield,
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

/// One inbox-sized slice of an oversized payload (encrypted notes, large
/// op-decl lists). The kernel reassembles chunks keyed by
/// `(sender, staging_id)` and seals the entry once `hash(reassembled)`
/// matches `payload_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelStageChunk {
    pub staging_id: u64,
    pub chunk_index: u16,
    pub chunk_count: u16,
    /// Hash of the FULL reassembled payload (not of this chunk).
    pub payload_hash: F,
    pub bytes: Vec<u8>,
}

/// Reference to a sealed staging entry holding an op's encrypted notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelStagedNoteRef {
    pub staging_id: u64,
    pub payload_hash: F,
}

/// Op-specific PUBLIC fields, mirroring the v17 request structs minus the
/// per-op proof (covered by the batch Groth16 wrap) and minus the inline
/// encrypted notes (carried as staged refs on [`KernelOpDecl`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelOpDeclBody {
    Shield {
        pubkey_hash: F,
        fee: u64,
        v: u64,
        producer_fee: u64,
        client_cm: F,
        producer_cm: F,
    },
    Transfer {
        root: F,
        nullifiers: Vec<F>,
        fee: u64,
        cm_1: F,
        cm_2: F,
        cm_3: F,
    },
    Unshield {
        root: F,
        nullifiers: Vec<F>,
        v_pub: u64,
        fee: u64,
        recipient: String,
        cm_change: F,
        cm_fee: F,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelOpDecl {
    /// The op's bootloader output preimage (leaf-statement derivation input).
    pub output_preimage: Vec<F>,
    /// Sealed staging refs carrying the op's encrypted notes, in the same
    /// order the v17 requests carried them inline.
    pub staged_notes: Vec<KernelStagedNoteRef>,
    pub body: KernelOpDeclBody,
}

/// One leaf of the aggregation tree binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelLeafSlot {
    /// Leaf backed by `ops[index]` (re-derived from its output preimage).
    DeclaredOp(u8),
    /// Padding / sibling leaf: lanes supplied as-is (M31 range-checked).
    Opaque { root: [u32; 8], outputs: [u32; 8] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelTreeBinding {
    /// Tree depth; the tree has 2^depth leaves.
    pub depth: u8,
    /// Exactly 2^depth entries, left to right.
    pub leaf_slots: Vec<KernelLeafSlot>,
}

/// DAL-free batched submission: N declared ops bound to one mv-root Groth16
/// wrap proof. A batch of size 1 IS the single-op mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSubmitOps {
    pub ops: Vec<KernelOpDecl>,
    /// gnark wrap proof over the mv ROOT (388 bytes for the 1-commitment
    /// shape; bounded by [`MAX_GROTH16_PROOF_BYTES`]).
    pub groth16_proof: Vec<u8>,
    /// Wrap public inputs: `TreeRoots[0..4]` (preprocessed root first).
    pub tree_roots: [[u8; 32]; 4],
    /// Wrap public inputs: `OutHash` lanes.
    pub out_hash: [u32; 8],
    pub binding: KernelTreeBinding,
}

#[derive(Debug, Clone)]
pub enum KernelInboxMessage {
    ConfigureVerifier(KernelSignedVerifierConfig),
    ConfigureBridge(KernelSignedBridgeConfig),
    Shield(KernelShieldReq),
    Transfer(KernelTransferReq),
    Unshield(KernelUnshieldReq),
    DalPointer(KernelDalPayloadPointer),
    StageChunk(KernelStageChunk),
    SubmitOps(KernelSubmitOps),
}

/// Result of a successfully processed `StageChunk` message (W2 staging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelStagedResp {
    pub staging_id: u64,
    /// Distinct chunk indices staged so far for this entry.
    pub received: u16,
    pub chunk_count: u16,
    /// True once all chunks arrived and `hash(reassembled)` matched the
    /// declared `payload_hash` — the entry is now referenceable by
    /// `SubmitOps` staged-note refs.
    pub sealed: bool,
}

#[derive(Debug, Clone)]
pub enum KernelResult {
    Configured,
    Deposit,
    Shield(ShieldResp),
    Transfer(TransferResp),
    Unshield(UnshieldResp),
    Staged(KernelStagedResp),
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
    pubkey_hash: WireFelt,
    fee: WireU64Le,
    v: WireU64Le,
    producer_fee: WireU64Le,
    proof: WireEncodedProof,
    client_cm: WireFelt,
    client_enc: WireEncryptedNote,
    producer_cm: WireFelt,
    producer_enc: WireEncryptedNote,
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
#[encoding(tags = "u8")]
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
struct WireKernelStageChunk {
    staging_id: WireU64Le,
    chunk_index: WireU16Le,
    chunk_count: WireU16Le,
    payload_hash: WireFelt,
    #[encoding(dynamic = "MAX_STAGE_CHUNK_BYTES", bytes)]
    bytes: Vec<u8>,
}

/// 8 M31 lanes as 32 bytes of u32-LE values.
#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireM31Lanes {
    #[encoding(sized = "32", bytes)]
    bytes: Vec<u8>,
}

/// The wrap circuit's 4 `TreeRoots`, 4 × 32 raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireTreeRoots {
    #[encoding(sized = "128", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireGroth16Proof {
    #[encoding(dynamic = "MAX_GROTH16_PROOF_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelStagedNoteRef {
    staging_id: WireU64Le,
    payload_hash: WireFelt,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelStagedNoteRefList {
    #[encoding(dynamic = "MAX_STAGED_NOTE_LIST_BYTES")]
    items: Vec<WireKernelStagedNoteRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireEncodedStagedNoteRefList {
    #[encoding(dynamic = "MAX_STAGED_NOTE_LIST_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelShieldOpDecl {
    pubkey_hash: WireFelt,
    fee: WireU64Le,
    v: WireU64Le,
    producer_fee: WireU64Le,
    client_cm: WireFelt,
    producer_cm: WireFelt,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelTransferOpDecl {
    root: WireFelt,
    nullifiers: WireEncodedFeltList,
    fee: WireU64Le,
    cm_1: WireFelt,
    cm_2: WireFelt,
    cm_3: WireFelt,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelUnshieldOpDecl {
    root: WireFelt,
    nullifiers: WireEncodedFeltList,
    v_pub: WireU64Le,
    fee: WireU64Le,
    recipient: WireAccountId,
    cm_change: WireFelt,
    cm_fee: WireFelt,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
#[encoding(tags = "u8")]
enum WireKernelOpDeclBody {
    #[encoding(tag = 0)]
    Shield(WireKernelShieldOpDecl),
    #[encoding(tag = 1)]
    Transfer(WireKernelTransferOpDecl),
    #[encoding(tag = 2)]
    Unshield(WireKernelUnshieldOpDecl),
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelOpDecl {
    output_preimage: WireEncodedFeltList,
    staged_notes: WireEncodedStagedNoteRefList,
    body: WireKernelOpDeclBody,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelOpDeclList {
    #[encoding(dynamic = "MAX_OP_DECL_LIST_BYTES")]
    items: Vec<WireKernelOpDecl>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireEncodedOpDeclList {
    #[encoding(dynamic = "MAX_OP_DECL_LIST_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelDeclaredOpSlot {
    index: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelOpaqueLeaf {
    root: WireM31Lanes,
    outputs: WireM31Lanes,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
#[encoding(tags = "u8")]
enum WireKernelLeafSlot {
    #[encoding(tag = 0)]
    DeclaredOp(WireKernelDeclaredOpSlot),
    #[encoding(tag = 1)]
    Opaque(WireKernelOpaqueLeaf),
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelLeafSlotList {
    #[encoding(dynamic = "MAX_LEAF_SLOT_LIST_BYTES")]
    items: Vec<WireKernelLeafSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireEncodedLeafSlotList {
    #[encoding(dynamic = "MAX_LEAF_SLOT_LIST_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelTreeBinding {
    depth: u8,
    leaf_slots: WireEncodedLeafSlotList,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelSubmitOps {
    ops: WireEncodedOpDeclList,
    groth16_proof: WireGroth16Proof,
    tree_roots: WireTreeRoots,
    out_hash: WireM31Lanes,
    binding: WireKernelTreeBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireUnshieldResp {
    change_index: Option<WireU64Le>,
    producer_index: WireU64Le,
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
    #[encoding(tag = 6)]
    DalPointer(WireKernelDalPayloadPointer),
    #[encoding(tag = 7)]
    StageChunk(WireKernelStageChunk),
    #[encoding(tag = 8)]
    SubmitOps(WireKernelSubmitOps),
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelInboxEnvelope {
    version: WireU16Le,
    message: WireKernelInboxMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireKernelStagedResp {
    staging_id: WireU64Le,
    received: WireU16Le,
    chunk_count: WireU16Le,
    /// 0 = open, 1 = sealed.
    sealed: u8,
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
    Staged(WireKernelStagedResp),
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
            KernelInboxMessage::DalPointer(pointer) => {
                WireKernelInboxMessage::DalPointer(kernel_dal_payload_pointer_to_wire(pointer)?)
            }
            KernelInboxMessage::StageChunk(chunk) => {
                WireKernelInboxMessage::StageChunk(kernel_stage_chunk_to_wire(chunk)?)
            }
            KernelInboxMessage::SubmitOps(submit) => {
                WireKernelInboxMessage::SubmitOps(kernel_submit_ops_to_wire(submit)?)
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
        WireKernelInboxMessage::DalPointer(pointer) => Ok(KernelInboxMessage::DalPointer(
            kernel_dal_payload_pointer_from_wire(pointer)?,
        )),
        WireKernelInboxMessage::StageChunk(chunk) => Ok(KernelInboxMessage::StageChunk(
            kernel_stage_chunk_from_wire(chunk)?,
        )),
        WireKernelInboxMessage::SubmitOps(submit) => Ok(KernelInboxMessage::SubmitOps(
            kernel_submit_ops_from_wire(submit)?,
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
            KernelResult::Staged(resp) => WireKernelResult::Staged(WireKernelStagedResp {
                staging_id: u64_to_wire(resp.staging_id),
                received: u16_to_wire(resp.received),
                chunk_count: u16_to_wire(resp.chunk_count),
                sealed: u8::from(resp.sealed),
            }),
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
        WireKernelResult::Staged(resp) => {
            let sealed = match resp.sealed {
                0 => false,
                1 => true,
                other => {
                    return Err(format!("invalid staged result sealed flag: {}", other));
                }
            };
            Ok(KernelResult::Staged(KernelStagedResp {
                staging_id: wire_to_u64(resp.staging_id)?,
                received: wire_to_u16(resp.received)?,
                chunk_count: wire_to_u16(resp.chunk_count)?,
                sealed,
            }))
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
    }
}

pub fn kernel_shield_req_to_host(req: &KernelShieldReq) -> ShieldReq {
    ShieldReq {
        pubkey_hash: req.pubkey_hash,
        fee: req.fee,
        v: req.v,
        producer_fee: req.producer_fee,
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
        KernelDalPayloadKind::ConfigureVerifier => WireKernelDalPayloadKind::ConfigureVerifier,
        KernelDalPayloadKind::ConfigureBridge => WireKernelDalPayloadKind::ConfigureBridge,
        KernelDalPayloadKind::Shield => WireKernelDalPayloadKind::Shield,
        KernelDalPayloadKind::Transfer => WireKernelDalPayloadKind::Transfer,
        KernelDalPayloadKind::Unshield => WireKernelDalPayloadKind::Unshield,
    }
}

fn kernel_dal_payload_kind_from_wire(
    kind: WireKernelDalPayloadKind,
) -> Result<KernelDalPayloadKind, String> {
    Ok(match kind {
        WireKernelDalPayloadKind::ConfigureVerifier => KernelDalPayloadKind::ConfigureVerifier,
        WireKernelDalPayloadKind::ConfigureBridge => KernelDalPayloadKind::ConfigureBridge,
        WireKernelDalPayloadKind::Shield => KernelDalPayloadKind::Shield,
        WireKernelDalPayloadKind::Transfer => KernelDalPayloadKind::Transfer,
        WireKernelDalPayloadKind::Unshield => KernelDalPayloadKind::Unshield,
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

// --- v18 StageChunk / SubmitOps conversions + structural validation ---

fn check_m31_lanes(what: &str, lanes: &[u32; 8]) -> Result<(), String> {
    if let Some(lane) = lanes.iter().find(|l| **l >= M31_LANE_LIMIT) {
        return Err(format!("{what} lane not an M31 value: {lane}"));
    }
    Ok(())
}

fn m31_lanes_to_wire(lanes: &[u32; 8]) -> WireM31Lanes {
    let mut bytes = Vec::with_capacity(32);
    for lane in lanes {
        bytes.extend_from_slice(&lane.to_le_bytes());
    }
    WireM31Lanes { bytes }
}

fn wire_to_m31_lanes(wire: WireM31Lanes) -> Result<[u32; 8], String> {
    if wire.bytes.len() != 32 {
        return Err(format!(
            "bad M31 lanes length: got {} bytes, expected 32",
            wire.bytes.len()
        ));
    }
    let mut lanes = [0u32; 8];
    for (i, lane) in lanes.iter_mut().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&wire.bytes[i * 4..(i + 1) * 4]);
        *lane = u32::from_le_bytes(buf);
    }
    Ok(lanes)
}

fn tree_roots_to_wire(roots: &[[u8; 32]; TREE_ROOTS_COUNT]) -> WireTreeRoots {
    let mut bytes = Vec::with_capacity(TREE_ROOTS_COUNT * 32);
    for root in roots {
        bytes.extend_from_slice(root);
    }
    WireTreeRoots { bytes }
}

fn wire_to_tree_roots(wire: WireTreeRoots) -> Result<[[u8; 32]; TREE_ROOTS_COUNT], String> {
    if wire.bytes.len() != TREE_ROOTS_COUNT * 32 {
        return Err(format!(
            "bad tree_roots length: got {} bytes, expected {}",
            wire.bytes.len(),
            TREE_ROOTS_COUNT * 32
        ));
    }
    let mut roots = [[0u8; 32]; TREE_ROOTS_COUNT];
    for (i, root) in roots.iter_mut().enumerate() {
        root.copy_from_slice(&wire.bytes[i * 32..(i + 1) * 32]);
    }
    Ok(roots)
}

fn validate_kernel_stage_chunk(chunk: &KernelStageChunk) -> Result<(), String> {
    if chunk.chunk_count == 0 {
        return Err("stage chunk requires chunk_count >= 1".into());
    }
    if chunk.chunk_index >= chunk.chunk_count {
        return Err(format!(
            "stage chunk index out of range: {} >= {}",
            chunk.chunk_index, chunk.chunk_count
        ));
    }
    if chunk.bytes.len() > MAX_STAGE_CHUNK_BYTES {
        return Err(format!(
            "stage chunk too large: {} > {}",
            chunk.bytes.len(),
            MAX_STAGE_CHUNK_BYTES
        ));
    }
    Ok(())
}

fn kernel_stage_chunk_to_wire(chunk: &KernelStageChunk) -> Result<WireKernelStageChunk, String> {
    validate_kernel_stage_chunk(chunk)?;
    Ok(WireKernelStageChunk {
        staging_id: u64_to_wire(chunk.staging_id),
        chunk_index: u16_to_wire(chunk.chunk_index),
        chunk_count: u16_to_wire(chunk.chunk_count),
        payload_hash: felt_to_wire(&chunk.payload_hash),
        bytes: chunk.bytes.clone(),
    })
}

fn kernel_stage_chunk_from_wire(wire: WireKernelStageChunk) -> Result<KernelStageChunk, String> {
    let chunk = KernelStageChunk {
        staging_id: wire_to_u64(wire.staging_id)?,
        chunk_index: wire_to_u16(wire.chunk_index)?,
        chunk_count: wire_to_u16(wire.chunk_count)?,
        payload_hash: wire_to_felt(wire.payload_hash)?,
        bytes: wire.bytes,
    };
    validate_kernel_stage_chunk(&chunk)?;
    Ok(chunk)
}

fn validate_kernel_op_decl(index: usize, op: &KernelOpDecl) -> Result<(), String> {
    if op.output_preimage.len() > MAX_OUTPUT_PREIMAGE_ITEMS {
        return Err(format!(
            "op {} output_preimage too long: {} > {}",
            index,
            op.output_preimage.len(),
            MAX_OUTPUT_PREIMAGE_ITEMS
        ));
    }
    if op.staged_notes.len() > MAX_STAGED_NOTE_REFS_PER_OP {
        return Err(format!(
            "op {} has too many staged note refs: {} > {}",
            index,
            op.staged_notes.len(),
            MAX_STAGED_NOTE_REFS_PER_OP
        ));
    }
    Ok(())
}

fn validate_kernel_submit_ops(submit: &KernelSubmitOps) -> Result<(), String> {
    if submit.ops.is_empty() {
        return Err("submit-ops requires at least one op".into());
    }
    if submit.ops.len() > MAX_BATCH_OPS {
        return Err(format!(
            "submit-ops has too many ops: {} > {}",
            submit.ops.len(),
            MAX_BATCH_OPS
        ));
    }
    for (index, op) in submit.ops.iter().enumerate() {
        validate_kernel_op_decl(index, op)?;
    }
    if submit.groth16_proof.is_empty() {
        return Err("submit-ops requires a non-empty groth16 proof".into());
    }
    if submit.groth16_proof.len() > MAX_GROTH16_PROOF_BYTES {
        return Err(format!(
            "submit-ops groth16 proof too large: {} > {}",
            submit.groth16_proof.len(),
            MAX_GROTH16_PROOF_BYTES
        ));
    }
    check_m31_lanes("submit-ops out_hash", &submit.out_hash)?;
    let binding = &submit.binding;
    if binding.depth == 0 || binding.depth > MAX_TREE_DEPTH {
        return Err(format!(
            "tree binding depth out of range: {} not in 1..={}",
            binding.depth, MAX_TREE_DEPTH
        ));
    }
    let expected_slots = 1usize << binding.depth;
    if binding.leaf_slots.len() != expected_slots {
        return Err(format!(
            "tree binding has {} leaf slots, expected 2^{} = {}",
            binding.leaf_slots.len(),
            binding.depth,
            expected_slots
        ));
    }
    let mut referenced = vec![false; submit.ops.len()];
    for (slot_index, slot) in binding.leaf_slots.iter().enumerate() {
        match slot {
            KernelLeafSlot::DeclaredOp(op_index) => {
                let op_index = *op_index as usize;
                if op_index >= submit.ops.len() {
                    return Err(format!(
                        "leaf slot {} declares op {} but only {} ops are declared",
                        slot_index,
                        op_index,
                        submit.ops.len()
                    ));
                }
                referenced[op_index] = true;
            }
            KernelLeafSlot::Opaque { root, outputs } => {
                check_m31_lanes(&format!("opaque leaf {slot_index} root"), root)?;
                check_m31_lanes(&format!("opaque leaf {slot_index} outputs"), outputs)?;
            }
        }
    }
    if let Some(op_index) = referenced.iter().position(|r| !r) {
        return Err(format!(
            "declared op {} is not referenced by any leaf slot",
            op_index
        ));
    }
    Ok(())
}

fn kernel_op_decl_body_to_wire(body: &KernelOpDeclBody) -> Result<WireKernelOpDeclBody, String> {
    Ok(match body {
        KernelOpDeclBody::Shield {
            pubkey_hash,
            fee,
            v,
            producer_fee,
            client_cm,
            producer_cm,
        } => WireKernelOpDeclBody::Shield(WireKernelShieldOpDecl {
            pubkey_hash: felt_to_wire(pubkey_hash),
            fee: u64_to_wire(*fee),
            v: u64_to_wire(*v),
            producer_fee: u64_to_wire(*producer_fee),
            client_cm: felt_to_wire(client_cm),
            producer_cm: felt_to_wire(producer_cm),
        }),
        KernelOpDeclBody::Transfer {
            root,
            nullifiers,
            fee,
            cm_1,
            cm_2,
            cm_3,
        } => WireKernelOpDeclBody::Transfer(WireKernelTransferOpDecl {
            root: felt_to_wire(root),
            nullifiers: encoded_felt_list_to_wire(nullifiers)?,
            fee: u64_to_wire(*fee),
            cm_1: felt_to_wire(cm_1),
            cm_2: felt_to_wire(cm_2),
            cm_3: felt_to_wire(cm_3),
        }),
        KernelOpDeclBody::Unshield {
            root,
            nullifiers,
            v_pub,
            fee,
            recipient,
            cm_change,
            cm_fee,
        } => WireKernelOpDeclBody::Unshield(WireKernelUnshieldOpDecl {
            root: felt_to_wire(root),
            nullifiers: encoded_felt_list_to_wire(nullifiers)?,
            v_pub: u64_to_wire(*v_pub),
            fee: u64_to_wire(*fee),
            recipient: WireAccountId {
                value: recipient.clone(),
            },
            cm_change: felt_to_wire(cm_change),
            cm_fee: felt_to_wire(cm_fee),
        }),
    })
}

fn kernel_op_decl_body_from_wire(wire: WireKernelOpDeclBody) -> Result<KernelOpDeclBody, String> {
    Ok(match wire {
        WireKernelOpDeclBody::Shield(decl) => KernelOpDeclBody::Shield {
            pubkey_hash: wire_to_felt(decl.pubkey_hash)?,
            fee: wire_to_u64(decl.fee)?,
            v: wire_to_u64(decl.v)?,
            producer_fee: wire_to_u64(decl.producer_fee)?,
            client_cm: wire_to_felt(decl.client_cm)?,
            producer_cm: wire_to_felt(decl.producer_cm)?,
        },
        WireKernelOpDeclBody::Transfer(decl) => KernelOpDeclBody::Transfer {
            root: wire_to_felt(decl.root)?,
            nullifiers: encoded_felt_list_from_wire(decl.nullifiers)?,
            fee: wire_to_u64(decl.fee)?,
            cm_1: wire_to_felt(decl.cm_1)?,
            cm_2: wire_to_felt(decl.cm_2)?,
            cm_3: wire_to_felt(decl.cm_3)?,
        },
        WireKernelOpDeclBody::Unshield(decl) => KernelOpDeclBody::Unshield {
            root: wire_to_felt(decl.root)?,
            nullifiers: encoded_felt_list_from_wire(decl.nullifiers)?,
            v_pub: wire_to_u64(decl.v_pub)?,
            fee: wire_to_u64(decl.fee)?,
            recipient: decl.recipient.value,
            cm_change: wire_to_felt(decl.cm_change)?,
            cm_fee: wire_to_felt(decl.cm_fee)?,
        },
    })
}

fn kernel_op_decl_to_wire(op: &KernelOpDecl) -> Result<WireKernelOpDecl, String> {
    let staged_notes = op
        .staged_notes
        .iter()
        .map(|note| WireKernelStagedNoteRef {
            staging_id: u64_to_wire(note.staging_id),
            payload_hash: felt_to_wire(&note.payload_hash),
        })
        .collect::<Vec<_>>();
    Ok(WireKernelOpDecl {
        output_preimage: encoded_felt_list_to_wire(&op.output_preimage)?,
        staged_notes: WireEncodedStagedNoteRefList {
            bytes: encode_tze(&WireKernelStagedNoteRefList {
                items: staged_notes,
            })?,
        },
        body: kernel_op_decl_body_to_wire(&op.body)?,
    })
}

fn kernel_op_decl_from_wire(wire: WireKernelOpDecl) -> Result<KernelOpDecl, String> {
    let staged_notes: WireKernelStagedNoteRefList = decode_tze(&wire.staged_notes.bytes)?;
    Ok(KernelOpDecl {
        output_preimage: encoded_felt_list_from_wire(wire.output_preimage)?,
        staged_notes: staged_notes
            .items
            .into_iter()
            .map(|note| {
                Ok(KernelStagedNoteRef {
                    staging_id: wire_to_u64(note.staging_id)?,
                    payload_hash: wire_to_felt(note.payload_hash)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        body: kernel_op_decl_body_from_wire(wire.body)?,
    })
}

fn kernel_leaf_slot_to_wire(slot: &KernelLeafSlot) -> WireKernelLeafSlot {
    match slot {
        KernelLeafSlot::DeclaredOp(index) => {
            WireKernelLeafSlot::DeclaredOp(WireKernelDeclaredOpSlot { index: *index })
        }
        KernelLeafSlot::Opaque { root, outputs } => {
            WireKernelLeafSlot::Opaque(WireKernelOpaqueLeaf {
                root: m31_lanes_to_wire(root),
                outputs: m31_lanes_to_wire(outputs),
            })
        }
    }
}

fn kernel_leaf_slot_from_wire(wire: WireKernelLeafSlot) -> Result<KernelLeafSlot, String> {
    Ok(match wire {
        WireKernelLeafSlot::DeclaredOp(slot) => KernelLeafSlot::DeclaredOp(slot.index),
        WireKernelLeafSlot::Opaque(leaf) => KernelLeafSlot::Opaque {
            root: wire_to_m31_lanes(leaf.root)?,
            outputs: wire_to_m31_lanes(leaf.outputs)?,
        },
    })
}

fn kernel_submit_ops_to_wire(submit: &KernelSubmitOps) -> Result<WireKernelSubmitOps, String> {
    validate_kernel_submit_ops(submit)?;
    let ops = submit
        .ops
        .iter()
        .map(kernel_op_decl_to_wire)
        .collect::<Result<Vec<_>, _>>()?;
    let leaf_slots = submit
        .binding
        .leaf_slots
        .iter()
        .map(kernel_leaf_slot_to_wire)
        .collect::<Vec<_>>();
    Ok(WireKernelSubmitOps {
        ops: WireEncodedOpDeclList {
            bytes: encode_tze(&WireKernelOpDeclList { items: ops })?,
        },
        groth16_proof: WireGroth16Proof {
            bytes: submit.groth16_proof.clone(),
        },
        tree_roots: tree_roots_to_wire(&submit.tree_roots),
        out_hash: m31_lanes_to_wire(&submit.out_hash),
        binding: WireKernelTreeBinding {
            depth: submit.binding.depth,
            leaf_slots: WireEncodedLeafSlotList {
                bytes: encode_tze(&WireKernelLeafSlotList { items: leaf_slots })?,
            },
        },
    })
}

fn kernel_submit_ops_from_wire(wire: WireKernelSubmitOps) -> Result<KernelSubmitOps, String> {
    let ops: WireKernelOpDeclList = decode_tze(&wire.ops.bytes)?;
    let leaf_slots: WireKernelLeafSlotList = decode_tze(&wire.binding.leaf_slots.bytes)?;
    let submit = KernelSubmitOps {
        ops: ops
            .items
            .into_iter()
            .map(kernel_op_decl_from_wire)
            .collect::<Result<Vec<_>, _>>()?,
        groth16_proof: wire.groth16_proof.bytes,
        tree_roots: wire_to_tree_roots(wire.tree_roots)?,
        out_hash: wire_to_m31_lanes(wire.out_hash)?,
        binding: KernelTreeBinding {
            depth: wire.binding.depth,
            leaf_slots: leaf_slots
                .items
                .into_iter()
                .map(kernel_leaf_slot_from_wire)
                .collect::<Result<Vec<_>, _>>()?,
        },
    };
    validate_kernel_submit_ops(&submit)?;
    Ok(submit)
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

fn encrypted_note_to_wire(enc: &EncryptedNote) -> Result<WireEncryptedNote, String> {
    enc.validate()?;
    Ok(WireEncryptedNote {
        ct_d: enc.ct_d.clone(),
        tag: u16_to_wire(enc.tag),
        ct_v: enc.ct_v.clone(),
        nonce: enc.nonce.clone(),
        encrypted_data: enc.encrypted_data.clone(),
        outgoing_ct: enc.outgoing_ct.clone(),
    })
}

fn encrypted_note_from_wire(wire: WireEncryptedNote) -> Result<EncryptedNote, String> {
    let enc = EncryptedNote {
        ct_d: wire.ct_d,
        tag: wire_to_u16(wire.tag)?,
        ct_v: wire.ct_v,
        nonce: wire.nonce,
        encrypted_data: wire.encrypted_data,
        outgoing_ct: wire.outgoing_ct,
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

    if !rest.is_empty() {
        return Err(format!(
            "kernel proof payload left {} trailing bytes",
            rest.len()
        ));
    }
    Ok(KernelStarkProof {
        proof_bytes,
        output_preimage,
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
        pubkey_hash: felt_to_wire(&req.pubkey_hash),
        fee: u64_to_wire(req.fee),
        v: u64_to_wire(req.v),
        producer_fee: u64_to_wire(req.producer_fee),
        proof: encoded_proof_to_wire(&req.proof)?,
        client_cm: felt_to_wire(&req.client_cm),
        client_enc: encrypted_note_to_wire(&req.client_enc)?,
        producer_cm: felt_to_wire(&req.producer_cm),
        producer_enc: encrypted_note_to_wire(&req.producer_enc)?,
    })
}

fn kernel_shield_req_from_wire(wire: WireKernelShieldReq) -> Result<KernelShieldReq, String> {
    Ok(KernelShieldReq {
        pubkey_hash: wire_to_felt(wire.pubkey_hash)?,
        fee: wire_to_u64(wire.fee)?,
        v: wire_to_u64(wire.v)?,
        producer_fee: wire_to_u64(wire.producer_fee)?,
        proof: encoded_proof_from_wire(wire.proof)?,
        client_cm: wire_to_felt(wire.client_cm)?,
        client_enc: encrypted_note_from_wire(wire.client_enc)?,
        producer_cm: wire_to_felt(wire.producer_cm)?,
        producer_enc: encrypted_note_from_wire(wire.producer_enc)?,
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

#[cfg(test)]
mod tests {
    use super::*;
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
            prop::collection::vec(any::<u8>(), OUTGOING_RECOVERY_CT_BYTES),
        )
            .prop_map(|(ct_d, tag, ct_v, nonce, encrypted_data, outgoing_ct)| {
                EncryptedNote {
                    ct_d,
                    tag,
                    ct_v,
                    nonce,
                    encrypted_data,
                    outgoing_ct,
                }
            })
    }

    fn arb_kernel_stark_proof() -> impl Strategy<Value = KernelStarkProof> {
        (
            prop::collection::vec(any::<u8>(), 0..128),
            prop::collection::vec(arb_felt(), 0..8),
        )
            .prop_map(|(proof_bytes, output_preimage)| KernelStarkProof {
                proof_bytes,
                output_preimage,
            })
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_shield_request() {
        let pubkey_hash = [0x42; 32];
        let client_cm = [0x55; 32];
        let message = KernelInboxMessage::Shield(KernelShieldReq {
            pubkey_hash,
            fee: 3,
            v: 42,
            producer_fee: 5,
            proof: sample_kernel_stark_proof(),
            client_cm,
            client_enc: sample_encrypted_note(0x66),
            producer_cm: [9u8; 32],
            producer_enc: sample_encrypted_note(0x77),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        match decoded {
            KernelInboxMessage::Shield(req) => {
                assert_eq!(req.pubkey_hash, pubkey_hash);
                assert_eq!(req.fee, 3);
                assert_eq!(req.v, 42);
                assert_eq!(req.producer_fee, 5);
                assert_eq!(
                    req.proof.proof_bytes,
                    sample_kernel_stark_proof().proof_bytes
                );
                assert_eq!(req.client_cm, client_cm);
                assert_eq!(req.client_enc.ct_d, sample_encrypted_note(0x66).ct_d);
                assert_eq!(req.producer_cm, [9u8; 32]);
                assert_eq!(req.producer_enc.ct_d, sample_encrypted_note(0x77).ct_d);
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
    }

    #[test]
    fn kernel_shield_roundtrips_for_larger_stark_proof_payloads() {
        let proof = KernelStarkProof {
            proof_bytes: (0..70).map(|i| (0x80u8).wrapping_add(i as u8)).collect(),
            output_preimage: vec![[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]],
        };
        let message = KernelInboxMessage::Shield(KernelShieldReq {
            pubkey_hash: [0x42; 32],
            fee: 2,
            v: 7,
            producer_fee: 4,
            proof: proof.clone(),
            client_cm: [0x44; 32],
            client_enc: sample_encrypted_note(0x55),
            producer_cm: [0x66; 32],
            producer_enc: sample_encrypted_note(0x67),
        });
        let encoded = encode_kernel_inbox_message(&message).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        let KernelInboxMessage::Shield(decoded) = decoded else {
            panic!("decoded wrong kernel message variant");
        };
        assert_eq!(decoded.proof.proof_bytes, proof.proof_bytes);
        assert_eq!(decoded.proof.output_preimage, proof.output_preimage);
    }

    #[test]
    fn encoded_proof_wrapper_roundtrips_for_larger_stark_proof_payloads() {
        let proof = KernelStarkProof {
            proof_bytes: (0..70).map(|i| (0x80u8).wrapping_add(i as u8)).collect(),
            output_preimage: vec![[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]],
        };
        let wire = encoded_proof_to_wire(&proof).unwrap();
        let encoded = encode_tze(&wire).unwrap();
        let decoded_wire: WireEncodedProof = decode_tze(&encoded).unwrap();
        let decoded = encoded_proof_from_wire(decoded_wire).unwrap();
        assert_eq!(decoded.proof_bytes, proof.proof_bytes);
        assert_eq!(decoded.output_preimage, proof.output_preimage);
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
    fn kernel_inbox_roundtrip_preserves_dal_pointer() {
        let message = KernelInboxMessage::DalPointer(KernelDalPayloadPointer {
            kind: KernelDalPayloadKind::ConfigureVerifier,
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
        assert_eq!(pointer.kind, KernelDalPayloadKind::ConfigureVerifier);
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

    fn sample_encrypted_note(fill: u8) -> EncryptedNote {
        EncryptedNote {
            ct_d: vec![fill; crate::ML_KEM768_CIPHERTEXT_BYTES],
            tag: 17,
            ct_v: vec![fill ^ 0x5a; crate::ML_KEM768_CIPHERTEXT_BYTES],
            nonce: vec![fill.wrapping_add(2); crate::NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![fill.wrapping_add(1); crate::ENCRYPTED_NOTE_BYTES],
            outgoing_ct: vec![fill.wrapping_add(3); crate::OUTGOING_RECOVERY_CT_BYTES],
        }
    }

    fn sample_kernel_stark_proof() -> KernelStarkProof {
        KernelStarkProof {
            proof_bytes: vec![0xaa, 0xbb, 0xcc],
            output_preimage: vec![[7u8; 32], [8u8; 32]],
        }
    }

    proptest! {
        #[test]
        fn prop_kernel_shield_roundtrip_preserves_fields(
            pubkey_hash in arb_felt(),
            fee in any::<u64>(),
            v in any::<u64>(),
            producer_fee in 1u64..u64::MAX,
            proof in arb_kernel_stark_proof(),
            client_cm in arb_felt(),
            client_enc in arb_encrypted_note(),
            producer_cm in arb_felt(),
            producer_enc in arb_encrypted_note(),
        ) {
            let message = KernelInboxMessage::Shield(KernelShieldReq {
                pubkey_hash,
                fee,
                v,
                producer_fee,
                proof: proof.clone(),
                client_cm,
                client_enc: client_enc.clone(),
                producer_cm,
                producer_enc: producer_enc.clone(),
            });

            let encoded = encode_kernel_inbox_message(&message).unwrap();
            let decoded = decode_kernel_inbox_message(&encoded).unwrap();
            let KernelInboxMessage::Shield(req) = decoded else {
                panic!("decoded wrong kernel message variant");
            };
            prop_assert_eq!(req.pubkey_hash, pubkey_hash);
            prop_assert_eq!(req.fee, fee);
            prop_assert_eq!(req.v, v);
            prop_assert_eq!(req.producer_fee, producer_fee);
            prop_assert_eq!(req.client_cm, client_cm);
            prop_assert_eq!(&req.client_enc.ct_d, &client_enc.ct_d);
            prop_assert_eq!(req.client_enc.tag, client_enc.tag);
            prop_assert_eq!(&req.client_enc.ct_v, &client_enc.ct_v);
            prop_assert_eq!(&req.client_enc.encrypted_data, &client_enc.encrypted_data);
            prop_assert_eq!(req.producer_cm, producer_cm);
            prop_assert_eq!(&req.producer_enc.ct_d, &producer_enc.ct_d);
            prop_assert_eq!(req.proof.proof_bytes, proof.proof_bytes);
            prop_assert_eq!(req.proof.output_preimage, proof.output_preimage);
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
            } = host else {
                prop_assert!(false, "kernel proof must convert to Proof::Stark");
                unreachable!();
            };
            prop_assert_eq!(proof_bytes, proof.proof_bytes);
            prop_assert_eq!(output_preimage, proof.output_preimage);
        }

        #[test]
        fn prop_kernel_requests_to_host_preserve_fields(
            pubkey_hash in arb_felt(),
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
            proof in arb_kernel_stark_proof(),
            enc_1 in arb_encrypted_note(),
            enc_2 in arb_encrypted_note(),
            enc_3 in arb_encrypted_note(),
            enc_change in prop::option::of(arb_encrypted_note()),
            enc_fee in arb_encrypted_note(),
            client_enc in arb_encrypted_note(),
            producer_enc in arb_encrypted_note(),
        ) {
            let shield = KernelShieldReq {
                pubkey_hash,
                fee,
                v: value,
                producer_fee,
                proof: proof.clone(),
                client_cm,
                client_enc: client_enc.clone(),
                producer_cm: cm_fee,
                producer_enc: producer_enc.clone(),
            };
            let shield_host = kernel_shield_req_to_host(&shield);
            prop_assert_eq!(shield_host.pubkey_hash, pubkey_hash);
            prop_assert_eq!(shield_host.fee, fee);
            prop_assert_eq!(shield_host.v, value);
            prop_assert_eq!(shield_host.producer_fee, producer_fee);
            prop_assert_eq!(shield_host.client_cm, client_cm);
            prop_assert_eq!(
                &shield_host.client_enc.ct_d,
                &client_enc.ct_d
            );
            prop_assert_eq!(shield_host.producer_cm, cm_fee);
            prop_assert_eq!(
                &shield_host.producer_enc.ct_d,
                &producer_enc.ct_d
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
    fn kernel_result_roundtrip_preserves_staged_resp() {
        for sealed in [false, true] {
            let result = KernelResult::Staged(KernelStagedResp {
                staging_id: 0x0123_4567_89AB_CDEF,
                received: 2,
                chunk_count: 3,
                sealed,
            });
            let bytes = encode_kernel_result(&result).unwrap();
            let decoded = decode_kernel_result(&bytes).unwrap();
            match decoded {
                KernelResult::Staged(resp) => {
                    assert_eq!(resp.staging_id, 0x0123_4567_89AB_CDEF);
                    assert_eq!(resp.received, 2);
                    assert_eq!(resp.chunk_count, 3);
                    assert_eq!(resp.sealed, sealed);
                }
                other => panic!("unexpected decoded result: {:?}", other),
            }
        }
    }

    #[test]
    fn decode_kernel_result_rejects_invalid_staged_sealed_flag() {
        let bytes = encode_tze(&WireKernelResultEnvelope {
            version: u16_to_wire(KERNEL_WIRE_VERSION),
            result: WireKernelResult::Staged(WireKernelStagedResp {
                staging_id: u64_to_wire(7),
                received: u16_to_wire(1),
                chunk_count: u16_to_wire(1),
                sealed: 2,
            }),
        })
        .unwrap();
        let err = decode_kernel_result(&bytes).unwrap_err();
        assert!(err.contains("invalid staged result sealed flag"));
    }

    #[test]
    fn kernel_proof_to_wire_rejects_oversized_output_preimage() {
        let proof = KernelStarkProof {
            proof_bytes: vec![1, 2, 3],
            output_preimage: vec![[9u8; 32]; MAX_OUTPUT_PREIMAGE_ITEMS + 1],
        };
        let err = kernel_proof_to_wire(&proof).unwrap_err();
        assert!(err.contains("output_preimage too long for kernel wire"));
    }

    #[test]
    fn kernel_proof_from_wire_rejects_trailing_metadata_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(3u32).to_be_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        bytes.extend_from_slice(&(1u32).to_be_bytes());
        bytes.extend_from_slice(&ZERO);
        bytes.extend_from_slice(&(4u32).to_be_bytes());
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let err = kernel_proof_from_wire(WireStarkProof { bytes }).unwrap_err();
        assert!(err.contains("trailing bytes"));
    }

    #[test]
    fn encoded_note_to_wire_rejects_invalid_note() {
        let err = encoded_note_to_wire(&EncryptedNote {
            ct_d: vec![0; ML_KEM768_CIPHERTEXT_BYTES - 1],
            tag: 0,
            ct_v: vec![0; ML_KEM768_CIPHERTEXT_BYTES],
            nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![0; ENCRYPTED_NOTE_BYTES],
            outgoing_ct: vec![0; OUTGOING_RECOVERY_CT_BYTES],
        })
        .unwrap_err();
        assert!(err.contains("bad ct_d length"));
    }

    // --- v18 StageChunk / SubmitOps ---

    fn sample_stage_chunk() -> KernelStageChunk {
        KernelStageChunk {
            staging_id: 0xDEAD_BEEF_0042,
            chunk_index: 1,
            chunk_count: 2,
            payload_hash: [0xA5; 32],
            bytes: vec![0x5C; 1200],
        }
    }

    fn sample_shield_op_decl() -> KernelOpDecl {
        KernelOpDecl {
            output_preimage: vec![[0x11; 32], [0x12; 32], [0x13; 32]],
            staged_notes: vec![
                KernelStagedNoteRef {
                    staging_id: 1,
                    payload_hash: [0xA1; 32],
                },
                KernelStagedNoteRef {
                    staging_id: 2,
                    payload_hash: [0xA2; 32],
                },
            ],
            body: KernelOpDeclBody::Shield {
                pubkey_hash: [0x42; 32],
                fee: 3,
                v: 42,
                producer_fee: 5,
                client_cm: [0x55; 32],
                producer_cm: [0x56; 32],
            },
        }
    }

    fn sample_transfer_op_decl() -> KernelOpDecl {
        KernelOpDecl {
            output_preimage: vec![[0x21; 32]],
            staged_notes: vec![
                KernelStagedNoteRef {
                    staging_id: 3,
                    payload_hash: [0xB1; 32],
                },
                KernelStagedNoteRef {
                    staging_id: 4,
                    payload_hash: [0xB2; 32],
                },
                KernelStagedNoteRef {
                    staging_id: 5,
                    payload_hash: [0xB3; 32],
                },
            ],
            body: KernelOpDeclBody::Transfer {
                root: [0x01; 32],
                nullifiers: vec![[0x02; 32], [0x03; 32]],
                fee: 9,
                cm_1: [0x04; 32],
                cm_2: [0x05; 32],
                cm_3: [0x06; 32],
            },
        }
    }

    fn sample_unshield_op_decl() -> KernelOpDecl {
        KernelOpDecl {
            output_preimage: vec![[0x31; 32], [0x32; 32]],
            staged_notes: vec![KernelStagedNoteRef {
                staging_id: 6,
                payload_hash: [0xC1; 32],
            }],
            body: KernelOpDeclBody::Unshield {
                root: [0x07; 32],
                nullifiers: vec![[0x08; 32]],
                v_pub: 33,
                fee: 6,
                recipient: "tz1bob".into(),
                cm_change: [0x09; 32],
                cm_fee: [0x0A; 32],
            },
        }
    }

    fn opaque_leaf(seed: u32) -> KernelLeafSlot {
        KernelLeafSlot::Opaque {
            root: [seed; 8],
            outputs: [seed + 1; 8],
        }
    }

    fn sample_submit_ops_single() -> KernelSubmitOps {
        KernelSubmitOps {
            ops: vec![sample_shield_op_decl()],
            groth16_proof: vec![0xC3; 388],
            tree_roots: [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]],
            out_hash: [7u32; 8],
            binding: KernelTreeBinding {
                depth: 2,
                leaf_slots: vec![
                    KernelLeafSlot::DeclaredOp(0),
                    opaque_leaf(100),
                    opaque_leaf(200),
                    opaque_leaf(300),
                ],
            },
        }
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_stage_chunk() {
        let chunk = sample_stage_chunk();
        let encoded =
            encode_kernel_inbox_message(&KernelInboxMessage::StageChunk(chunk.clone())).unwrap();
        assert!(encoded.len() <= 4096, "stage chunk message exceeds inbox cap");
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        let KernelInboxMessage::StageChunk(decoded) = decoded else {
            panic!("unexpected decoded message");
        };
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_submit_ops_single_op_depth_2() {
        let submit = sample_submit_ops_single();
        let encoded =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit.clone())).unwrap();
        assert!(
            encoded.len() <= 4096,
            "single-op submit-ops must fit one inbox message, got {} bytes",
            encoded.len()
        );
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        let KernelInboxMessage::SubmitOps(decoded) = decoded else {
            panic!("unexpected decoded message");
        };
        assert_eq!(decoded, submit);
    }

    #[test]
    fn kernel_inbox_roundtrip_preserves_submit_ops_four_op_batch() {
        let submit = KernelSubmitOps {
            ops: vec![
                sample_shield_op_decl(),
                sample_transfer_op_decl(),
                sample_unshield_op_decl(),
                sample_transfer_op_decl(),
            ],
            groth16_proof: vec![0xD4; 388],
            tree_roots: [[5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32]],
            out_hash: [0, 1, 2, 3, 4, 5, 6, (1 << 31) - 2],
            binding: KernelTreeBinding {
                depth: 2,
                leaf_slots: vec![
                    KernelLeafSlot::DeclaredOp(0),
                    KernelLeafSlot::DeclaredOp(1),
                    KernelLeafSlot::DeclaredOp(2),
                    KernelLeafSlot::DeclaredOp(3),
                ],
            },
        };
        let encoded =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit.clone())).unwrap();
        let decoded = decode_kernel_inbox_message(&encoded).unwrap();
        let KernelInboxMessage::SubmitOps(decoded) = decoded else {
            panic!("unexpected decoded message");
        };
        assert_eq!(decoded, submit);
    }

    #[test]
    fn stage_chunk_rejects_zero_chunk_count() {
        let mut chunk = sample_stage_chunk();
        chunk.chunk_index = 0;
        chunk.chunk_count = 0;
        let err = encode_kernel_inbox_message(&KernelInboxMessage::StageChunk(chunk)).unwrap_err();
        assert!(err.contains("chunk_count >= 1"));
    }

    #[test]
    fn stage_chunk_rejects_index_not_below_count() {
        let mut chunk = sample_stage_chunk();
        chunk.chunk_index = 2;
        chunk.chunk_count = 2;
        let err = encode_kernel_inbox_message(&KernelInboxMessage::StageChunk(chunk)).unwrap_err();
        assert!(err.contains("index out of range"));
    }

    #[test]
    fn stage_chunk_rejects_oversized_bytes() {
        let mut chunk = sample_stage_chunk();
        chunk.bytes = vec![0xFF; MAX_STAGE_CHUNK_BYTES + 1];
        let err = encode_kernel_inbox_message(&KernelInboxMessage::StageChunk(chunk)).unwrap_err();
        assert!(err.contains("stage chunk too large"));
    }

    #[test]
    fn submit_ops_rejects_zero_ops() {
        let mut submit = sample_submit_ops_single();
        submit.ops.clear();
        submit.binding.leaf_slots[0] = opaque_leaf(50);
        let err =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit)).unwrap_err();
        assert!(err.contains("at least one op"));
    }

    #[test]
    fn submit_ops_rejects_bad_depth() {
        for depth in [0u8, MAX_TREE_DEPTH + 1] {
            let mut submit = sample_submit_ops_single();
            submit.binding.depth = depth;
            let err = encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit))
                .unwrap_err();
            assert!(err.contains("depth out of range"), "depth {depth}: {err}");
        }
    }

    #[test]
    fn submit_ops_rejects_leaf_slot_count_mismatch() {
        let mut submit = sample_submit_ops_single();
        submit.binding.leaf_slots.pop();
        let err =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit)).unwrap_err();
        assert!(err.contains("expected 2^2 = 4"));
    }

    #[test]
    fn submit_ops_rejects_dangling_declared_op_index() {
        let mut submit = sample_submit_ops_single();
        submit.binding.leaf_slots[1] = KernelLeafSlot::DeclaredOp(7);
        let err =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit)).unwrap_err();
        assert!(err.contains("declares op 7"));
    }

    #[test]
    fn submit_ops_rejects_unreferenced_op() {
        let mut submit = sample_submit_ops_single();
        submit.ops.push(sample_transfer_op_decl());
        // ops[1] exists but no leaf slot declares it.
        let err =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit)).unwrap_err();
        assert!(err.contains("op 1 is not referenced"));
    }

    #[test]
    fn submit_ops_rejects_non_m31_opaque_lane() {
        let mut submit = sample_submit_ops_single();
        // (1 << 31) - 1 is the first non-M31 value (boundary).
        submit.binding.leaf_slots[2] = KernelLeafSlot::Opaque {
            root: [0, 0, 0, (1 << 31) - 1, 0, 0, 0, 0],
            outputs: [0u32; 8],
        };
        let err =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit)).unwrap_err();
        assert!(err.contains("not an M31 value"));
    }

    #[test]
    fn submit_ops_rejects_non_m31_out_hash_lane() {
        let mut submit = sample_submit_ops_single();
        submit.out_hash[0] = u32::MAX;
        let err =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit)).unwrap_err();
        assert!(err.contains("out_hash") && err.contains("not an M31 value"));
    }

    #[test]
    fn submit_ops_rejects_oversized_groth16_proof() {
        let mut submit = sample_submit_ops_single();
        submit.groth16_proof = vec![0xEE; MAX_GROTH16_PROOF_BYTES + 1];
        let err =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit)).unwrap_err();
        assert!(err.contains("groth16 proof too large"));
    }

    #[test]
    fn submit_ops_rejects_too_many_ops() {
        let mut submit = sample_submit_ops_single();
        submit.ops = vec![sample_shield_op_decl(); MAX_BATCH_OPS + 1];
        let err =
            encode_kernel_inbox_message(&KernelInboxMessage::SubmitOps(submit)).unwrap_err();
        assert!(err.contains("too many ops"));
    }

    #[test]
    fn kernel_submit_ops_from_wire_revalidates_depth() {
        // Decode-side validation: a structurally valid wire blob with a bad
        // depth must be rejected by `kernel_submit_ops_from_wire` too.
        let mut wire = kernel_submit_ops_to_wire(&sample_submit_ops_single()).unwrap();
        wire.binding.depth = 9;
        let err = kernel_submit_ops_from_wire(wire).unwrap_err();
        assert!(err.contains("depth out of range"));
    }

    #[test]
    fn kernel_submit_ops_from_wire_revalidates_m31_lanes() {
        let mut wire = kernel_submit_ops_to_wire(&sample_submit_ops_single()).unwrap();
        let bad_lanes = WireM31Lanes {
            bytes: vec![0xFF; 32],
        };
        wire.binding.leaf_slots = WireEncodedLeafSlotList {
            bytes: encode_tze(&WireKernelLeafSlotList {
                items: vec![
                    WireKernelLeafSlot::DeclaredOp(WireKernelDeclaredOpSlot { index: 0 }),
                    WireKernelLeafSlot::Opaque(WireKernelOpaqueLeaf {
                        root: bad_lanes.clone(),
                        outputs: bad_lanes.clone(),
                    }),
                    WireKernelLeafSlot::Opaque(WireKernelOpaqueLeaf {
                        root: bad_lanes.clone(),
                        outputs: bad_lanes.clone(),
                    }),
                    WireKernelLeafSlot::Opaque(WireKernelOpaqueLeaf {
                        root: bad_lanes.clone(),
                        outputs: bad_lanes,
                    }),
                ],
            })
            .unwrap(),
        };
        let err = kernel_submit_ops_from_wire(wire).unwrap_err();
        assert!(err.contains("not an M31 value"));
    }
}
