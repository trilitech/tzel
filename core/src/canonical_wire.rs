use crate::{
    EncryptedNote, NoteMemo, PaymentAddress, ENCRYPTED_NOTE_BYTES, F, ML_KEM768_CIPHERTEXT_BYTES,
    NOTE_AEAD_NONCE_BYTES,
};
use ml_kem::KeyExport;
#[cfg(not(target_arch = "wasm32"))]
use serde_json::json;
use tezos_data_encoding::enc::BinWriter;
use tezos_data_encoding::encoding::HasEncoding;
use tezos_data_encoding::nom::NomReader;

pub const CANONICAL_WIRE_VERSION: u16 = 2;
pub const FELT252_BYTES: usize = 32;
pub const ML_KEM768_ENCAPSULATION_KEY_BYTES: usize = 1184;

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
pub(crate) struct WireFelt {
    #[encoding(sized = "FELT252_BYTES", bytes)]
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
pub(crate) struct WireU64Le {
    #[encoding(sized = "8", bytes)]
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
pub(crate) struct WireU16Le {
    #[encoding(sized = "2", bytes)]
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
pub(crate) struct WirePaymentAddress {
    pub(crate) d_j: WireFelt,
    pub(crate) auth_root: WireFelt,
    pub(crate) auth_pub_seed: WireFelt,
    pub(crate) nk_tag: WireFelt,
    #[encoding(sized = "ML_KEM768_ENCAPSULATION_KEY_BYTES", bytes)]
    pub(crate) ek_v: Vec<u8>,
    #[encoding(sized = "ML_KEM768_ENCAPSULATION_KEY_BYTES", bytes)]
    pub(crate) ek_d: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
pub(crate) struct WireEncryptedNote {
    #[encoding(sized = "ML_KEM768_CIPHERTEXT_BYTES", bytes)]
    pub(crate) ct_d: Vec<u8>,
    pub(crate) tag: WireU16Le,
    #[encoding(sized = "ML_KEM768_CIPHERTEXT_BYTES", bytes)]
    pub(crate) ct_v: Vec<u8>,
    #[encoding(sized = "NOTE_AEAD_NONCE_BYTES", bytes)]
    pub(crate) nonce: Vec<u8>,
    #[encoding(sized = "ENCRYPTED_NOTE_BYTES", bytes)]
    pub(crate) encrypted_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
pub(crate) struct WireNoteMemo {
    pub(crate) index: WireU64Le,
    pub(crate) cm: WireFelt,
    pub(crate) enc: WireEncryptedNote,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
pub(crate) struct WirePublishedNote {
    pub(crate) cm: WireFelt,
    pub(crate) enc: WireEncryptedNote,
}

pub(crate) fn felt_to_wire(f: &F) -> WireFelt {
    WireFelt { bytes: f.to_vec() }
}

pub(crate) fn wire_to_felt(w: WireFelt) -> Result<F, String> {
    if w.bytes.len() != FELT252_BYTES {
        return Err(format!(
            "bad felt length: got {} bytes, expected {}",
            w.bytes.len(),
            FELT252_BYTES
        ));
    }
    let mut out = [0u8; FELT252_BYTES];
    out.copy_from_slice(&w.bytes);
    Ok(out)
}

pub(crate) fn encode_tze<T: BinWriter>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    value
        .bin_write(&mut out)
        .map_err(|e| format!("tezos_data_encoding write failed: {:?}", e))?;
    Ok(out)
}

pub(crate) fn u64_to_wire(v: u64) -> WireU64Le {
    WireU64Le {
        bytes: v.to_le_bytes().to_vec(),
    }
}

pub(crate) fn wire_to_u64(w: WireU64Le) -> Result<u64, String> {
    if w.bytes.len() != 8 {
        return Err(format!(
            "bad u64 length: got {} bytes, expected 8",
            w.bytes.len()
        ));
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(&w.bytes);
    Ok(u64::from_le_bytes(out))
}

pub(crate) fn u16_to_wire(v: u16) -> WireU16Le {
    WireU16Le {
        bytes: v.to_le_bytes().to_vec(),
    }
}

pub(crate) fn wire_to_u16(w: WireU16Le) -> Result<u16, String> {
    if w.bytes.len() != 2 {
        return Err(format!(
            "bad u16 length: got {} bytes, expected 2",
            w.bytes.len()
        ));
    }
    let mut out = [0u8; 2];
    out.copy_from_slice(&w.bytes);
    Ok(u16::from_le_bytes(out))
}

pub(crate) fn decode_tze<T>(bytes: &[u8]) -> Result<T, String>
where
    for<'a> T: NomReader<'a>,
{
    let (rest, decoded) =
        T::nom_read(bytes).map_err(|e| format!("tezos_data_encoding read failed: {:?}", e))?;
    if !rest.is_empty() {
        return Err(format!(
            "tezos_data_encoding decode left {} trailing bytes",
            rest.len()
        ));
    }
    Ok(decoded)
}

pub fn encode_payment_address(addr: &PaymentAddress) -> Result<Vec<u8>, String> {
    encode_tze(&WirePaymentAddress {
        d_j: felt_to_wire(&addr.d_j),
        auth_root: felt_to_wire(&addr.auth_root),
        auth_pub_seed: felt_to_wire(&addr.auth_pub_seed),
        nk_tag: felt_to_wire(&addr.nk_tag),
        ek_v: addr.ek_v.clone(),
        ek_d: addr.ek_d.clone(),
    })
}

pub fn decode_payment_address(bytes: &[u8]) -> Result<PaymentAddress, String> {
    let wire: WirePaymentAddress = decode_tze(bytes)?;
    Ok(PaymentAddress {
        d_j: wire_to_felt(wire.d_j)?,
        auth_root: wire_to_felt(wire.auth_root)?,
        auth_pub_seed: wire_to_felt(wire.auth_pub_seed)?,
        nk_tag: wire_to_felt(wire.nk_tag)?,
        ek_v: wire.ek_v,
        ek_d: wire.ek_d,
    })
}

pub fn encode_encrypted_note(enc: &EncryptedNote) -> Result<Vec<u8>, String> {
    enc.validate()?;
    encode_tze(&WireEncryptedNote {
        ct_d: enc.ct_d.clone(),
        tag: u16_to_wire(enc.tag),
        ct_v: enc.ct_v.clone(),
        nonce: enc.nonce.clone(),
        encrypted_data: enc.encrypted_data.clone(),
    })
}

pub fn decode_encrypted_note(bytes: &[u8]) -> Result<EncryptedNote, String> {
    let wire: WireEncryptedNote = decode_tze(bytes)?;
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

pub fn encode_note_memo(note: &NoteMemo) -> Result<Vec<u8>, String> {
    encode_tze(&WireNoteMemo {
        index: u64_to_wire(
            note.index
                .try_into()
                .map_err(|_| format!("note index {} does not fit in u64", note.index))?,
        ),
        cm: felt_to_wire(&note.cm),
        enc: WireEncryptedNote {
            ct_d: note.enc.ct_d.clone(),
            tag: u16_to_wire(note.enc.tag),
            ct_v: note.enc.ct_v.clone(),
            nonce: note.enc.nonce.clone(),
            encrypted_data: note.enc.encrypted_data.clone(),
        },
    })
}

pub fn decode_note_memo(bytes: &[u8]) -> Result<NoteMemo, String> {
    let wire: WireNoteMemo = decode_tze(bytes)?;
    let index: usize = wire_to_u64(wire.index)?
        .try_into()
        .map_err(|_| "note index does not fit in usize".to_string())?;
    let enc = EncryptedNote {
        ct_d: wire.enc.ct_d,
        tag: wire_to_u16(wire.enc.tag)?,
        ct_v: wire.enc.ct_v,
        nonce: wire.enc.nonce,
        encrypted_data: wire.enc.encrypted_data,
    };
    enc.validate()?;
    Ok(NoteMemo {
        index,
        cm: wire_to_felt(wire.cm)?,
        enc,
    })
}

pub fn encode_published_note(cm: &F, enc: &EncryptedNote) -> Result<Vec<u8>, String> {
    enc.validate()?;
    encode_tze(&WirePublishedNote {
        cm: felt_to_wire(cm),
        enc: WireEncryptedNote {
            ct_d: enc.ct_d.clone(),
            tag: u16_to_wire(enc.tag),
            ct_v: enc.ct_v.clone(),
            nonce: enc.nonce.clone(),
            encrypted_data: enc.encrypted_data.clone(),
        },
    })
}

pub fn decode_published_note(bytes: &[u8]) -> Result<(F, EncryptedNote), String> {
    let wire: WirePublishedNote = decode_tze(bytes)?;
    let enc = EncryptedNote {
        ct_d: wire.enc.ct_d,
        tag: wire_to_u16(wire.enc.tag)?,
        ct_v: wire.enc.ct_v,
        nonce: wire.enc.nonce,
        encrypted_data: wire.enc.encrypted_data,
    };
    enc.validate()?;
    Ok((wire_to_felt(wire.cm)?, enc))
}

pub fn ml_kem_768_public_key_size() -> usize {
    let seed = [0u8; 64];
    let (ek, _) = crate::kem_keygen_from_seed(&seed);
    ek.to_bytes().len()
}

const VECTOR_ADDRESS_INDEX: u32 = 0;
const VECTOR_NOTE_VALUE: u64 = 77;
const VECTOR_NULLIFIER_POS: u64 = 42;
const VECTOR_DETECT_EPHEMERAL: [u8; 32] = [0x11; 32];
const VECTOR_VIEW_EPHEMERAL: [u8; 32] = [0x22; 32];
const VECTOR_MEMO: &[u8] = b"canonical-wire-vector";
const VECTOR_AUTH_ROOT_HEX: &str =
    "e912b13056ff9b95542bdf9086d8082e2df9a915a12c6111ee0313fa0ad28507";

fn sample_felt(fill: u8) -> F {
    let mut out = [fill; 32];
    out[31] &= 0x07;
    out
}

fn hex_to_felt(s: &str) -> F {
    let bytes = hex::decode(s).expect("valid felt hex");
    assert_eq!(bytes.len(), 32, "felt hex must decode to 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn sample_data() -> (PaymentAddress, EncryptedNote, F, NoteMemo, F, F, u64) {
    let mut master_sk = crate::ZERO;
    master_sk[..8].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
    let acc = crate::derive_account(&master_sk);
    let j = VECTOR_ADDRESS_INDEX;
    let d_j = crate::derive_address(&acc.incoming_seed, j);
    let ask_j = crate::derive_ask(&acc.ask_base, j);
    let auth_root = hex_to_felt(VECTOR_AUTH_ROOT_HEX);
    let auth_pub_seed = crate::derive_auth_pub_seed(&ask_j);
    let nk_spend = crate::derive_nk_spend(&acc.nk, &d_j);
    let nk_tag = crate::derive_nk_tag(&nk_spend);
    let (ek_v, _, ek_d, _) = crate::derive_kem_keys(&acc.incoming_seed, j);
    let address = PaymentAddress {
        d_j,
        auth_root,
        auth_pub_seed,
        nk_tag,
        ek_v: ek_v.to_bytes().to_vec(),
        ek_d: ek_d.to_bytes().to_vec(),
    };

    let v = VECTOR_NOTE_VALUE;
    let rseed = sample_felt(0x42);
    let enc = crate::encrypt_note_deterministic(
        v,
        &rseed,
        Some(VECTOR_MEMO),
        &ek_v,
        &ek_d,
        &VECTOR_DETECT_EPHEMERAL,
        &VECTOR_VIEW_EPHEMERAL,
    );
    let cm = crate::commit(
        &address.d_j,
        v,
        &crate::derive_rcm(&rseed),
        &crate::owner_tag(&address.auth_root, &address.auth_pub_seed, &address.nk_tag),
    );
    let nf = crate::nullifier(&nk_spend, &cm, VECTOR_NULLIFIER_POS);
    let note_memo = NoteMemo {
        index: VECTOR_NULLIFIER_POS as usize,
        cm,
        enc: enc.clone(),
    };
    (address, enc, cm, note_memo, nf, rseed, v)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_canonical_wire_v1_json() -> String {
    let mut master_sk = crate::ZERO;
    master_sk[..8].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
    let (address, enc, cm, note_memo, nf, rseed, v) = sample_data();
    let payment_address_tze = encode_payment_address(&address).unwrap();
    let encrypted_note_tze = encode_encrypted_note(&enc).unwrap();
    let published_note_tze = encode_published_note(&cm, &enc).unwrap();
    let note_memo_tze = encode_note_memo(&note_memo).unwrap();

    serde_json::to_string_pretty(&json!({
        "version": CANONICAL_WIRE_VERSION,
        "inputs": {
            "master_sk": hex::encode(master_sk),
            "address_index": VECTOR_ADDRESS_INDEX,
            "value": VECTOR_NOTE_VALUE,
            "rseed": hex::encode(rseed),
            "memo_hex": hex::encode(VECTOR_MEMO),
            "detect_ephemeral": hex::encode(VECTOR_DETECT_EPHEMERAL),
            "view_ephemeral": hex::encode(VECTOR_VIEW_EPHEMERAL),
            "nullifier_pos": VECTOR_NULLIFIER_POS,
        },
        "payment_address": {
            "d_j": hex::encode(address.d_j),
            "auth_root": hex::encode(address.auth_root),
            "auth_pub_seed": hex::encode(address.auth_pub_seed),
            "nk_tag": hex::encode(address.nk_tag),
            "ek_v": hex::encode(address.ek_v),
            "ek_d": hex::encode(address.ek_d),
            "canonical_hex": hex::encode(payment_address_tze),
        },
        "encrypted_note": {
            "ct_d": hex::encode(&enc.ct_d),
            "tag": enc.tag,
            "ct_v": hex::encode(&enc.ct_v),
            "encrypted_data": hex::encode(&enc.encrypted_data),
            "memo_ct_hash": hex::encode(crate::memo_ct_hash(&enc)),
            "canonical_hex": hex::encode(encrypted_note_tze),
        },
        "published_note": {
            "cm": hex::encode(cm),
            "canonical_hex": hex::encode(published_note_tze),
        },
        "note_memo": {
            "index": note_memo.index,
            "cm": hex::encode(note_memo.cm),
            "canonical_hex": hex::encode(note_memo_tze),
        },
        "derived": {
            "rseed": hex::encode(rseed),
            "value": v,
            "nullifier": hex::encode(nf),
        }
    }))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_public_key_size_constant() {
        assert_eq!(
            ml_kem_768_public_key_size(),
            ML_KEM768_ENCAPSULATION_KEY_BYTES
        );
    }

    #[test]
    fn test_payment_address_roundtrip() {
        let (address, _, _, _, _, _, _) = sample_data();
        let bytes = encode_payment_address(&address).expect("address should encode");
        let decoded = decode_payment_address(&bytes).expect("address should decode");
        assert_eq!(decoded.d_j, address.d_j);
        assert_eq!(decoded.auth_root, address.auth_root);
        assert_eq!(decoded.auth_pub_seed, address.auth_pub_seed);
        assert_eq!(decoded.nk_tag, address.nk_tag);
        assert_eq!(decoded.ek_v, address.ek_v);
        assert_eq!(decoded.ek_d, address.ek_d);
    }

    #[test]
    fn test_encrypted_note_roundtrip() {
        let (_, enc, _, _, _, _, _) = sample_data();
        let bytes = encode_encrypted_note(&enc).expect("note should encode");
        let decoded = decode_encrypted_note(&bytes).expect("note should decode");
        assert_eq!(decoded.ct_d, enc.ct_d);
        assert_eq!(decoded.tag, enc.tag);
        assert_eq!(decoded.ct_v, enc.ct_v);
        assert_eq!(decoded.encrypted_data, enc.encrypted_data);
    }

    #[test]
    fn test_note_memo_roundtrip() {
        let (_, _, _, note_memo, _, _, _) = sample_data();
        let bytes = encode_note_memo(&note_memo).expect("note memo should encode");
        let decoded = decode_note_memo(&bytes).expect("note memo should decode");
        assert_eq!(decoded.index, note_memo.index);
        assert_eq!(decoded.cm, note_memo.cm);
        assert_eq!(decoded.enc.ct_d, note_memo.enc.ct_d);
        assert_eq!(decoded.enc.tag, note_memo.enc.tag);
        assert_eq!(decoded.enc.ct_v, note_memo.enc.ct_v);
        assert_eq!(decoded.enc.encrypted_data, note_memo.enc.encrypted_data);
    }

    #[test]
    fn test_published_note_roundtrip() {
        let (_, enc, cm, _, _, _, _) = sample_data();
        let bytes = encode_published_note(&cm, &enc).expect("published note should encode");
        let (decoded_cm, decoded_enc) =
            decode_published_note(&bytes).expect("published note should decode");
        assert_eq!(decoded_cm, cm);
        assert_eq!(decoded_enc.ct_d, enc.ct_d);
        assert_eq!(decoded_enc.tag, enc.tag);
        assert_eq!(decoded_enc.ct_v, enc.ct_v);
        assert_eq!(decoded_enc.encrypted_data, enc.encrypted_data);
    }

    #[test]
    fn test_canonical_vectors_match_file() {
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../specs/test_vectors/canonical_wire_v1.json"
        ))
        .trim_end_matches('\n');
        assert_eq!(generate_canonical_wire_v1_json(), expected);
    }
}
