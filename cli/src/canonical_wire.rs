use crate::{
    ENCRYPTED_NOTE_BYTES, EncryptedNote, F, ML_KEM768_CIPHERTEXT_BYTES, NoteMemo, PaymentAddress,
};
use ml_kem::KeyExport;
use tezos_data_encoding::enc::BinWriter;
use tezos_data_encoding::encoding::HasEncoding;
use tezos_data_encoding::nom::NomReader;

pub const CANONICAL_WIRE_VERSION: u16 = 1;
pub const FELT252_BYTES: usize = 32;
pub const ML_KEM768_ENCAPSULATION_KEY_BYTES: usize = 1184;

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireFelt {
    #[encoding(sized = "FELT252_BYTES", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireU64Le {
    #[encoding(sized = "8", bytes)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WirePaymentAddress {
    d_j: WireFelt,
    auth_root: WireFelt,
    nk_tag: WireFelt,
    #[encoding(sized = "ML_KEM768_ENCAPSULATION_KEY_BYTES", bytes)]
    ek_v: Vec<u8>,
    #[encoding(sized = "ML_KEM768_ENCAPSULATION_KEY_BYTES", bytes)]
    ek_d: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireEncryptedNote {
    #[encoding(sized = "ML_KEM768_CIPHERTEXT_BYTES", bytes)]
    ct_d: Vec<u8>,
    tag: u16,
    #[encoding(sized = "ML_KEM768_CIPHERTEXT_BYTES", bytes)]
    ct_v: Vec<u8>,
    #[encoding(sized = "ENCRYPTED_NOTE_BYTES", bytes)]
    encrypted_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WireNoteMemo {
    index: WireU64Le,
    cm: WireFelt,
    enc: WireEncryptedNote,
}

#[derive(Debug, Clone, PartialEq, Eq, HasEncoding, NomReader, BinWriter)]
struct WirePublishedNote {
    cm: WireFelt,
    enc: WireEncryptedNote,
}

fn felt_to_wire(f: &F) -> WireFelt {
    WireFelt { bytes: f.to_vec() }
}

fn wire_to_felt(w: WireFelt) -> Result<F, String> {
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

fn encode_tze<T: BinWriter>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    value
        .bin_write(&mut out)
        .map_err(|e| format!("tezos_data_encoding write failed: {:?}", e))?;
    Ok(out)
}

fn u64_to_wire(v: u64) -> WireU64Le {
    WireU64Le {
        bytes: v.to_le_bytes().to_vec(),
    }
}

fn wire_to_u64(w: WireU64Le) -> Result<u64, String> {
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

fn decode_tze<T>(bytes: &[u8]) -> Result<T, String>
where
    for<'a> T: NomReader<'a>,
{
    let (rest, decoded) = T::nom_read(bytes)
        .map_err(|e| format!("tezos_data_encoding read failed: {:?}", e))?;
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
        nk_tag: wire_to_felt(wire.nk_tag)?,
        ek_v: wire.ek_v,
        ek_d: wire.ek_d,
    })
}

pub fn encode_encrypted_note(enc: &EncryptedNote) -> Result<Vec<u8>, String> {
    enc.validate()?;
    encode_tze(&WireEncryptedNote {
        ct_d: enc.ct_d.clone(),
        tag: enc.tag,
        ct_v: enc.ct_v.clone(),
        encrypted_data: enc.encrypted_data.clone(),
    })
}

pub fn decode_encrypted_note(bytes: &[u8]) -> Result<EncryptedNote, String> {
    let wire: WireEncryptedNote = decode_tze(bytes)?;
    let enc = EncryptedNote {
        ct_d: wire.ct_d,
        tag: wire.tag,
        ct_v: wire.ct_v,
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
            tag: note.enc.tag,
            ct_v: note.enc.ct_v.clone(),
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
        tag: wire.enc.tag,
        ct_v: wire.enc.ct_v,
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
            tag: enc.tag,
            ct_v: enc.ct_v.clone(),
            encrypted_data: enc.encrypted_data.clone(),
        },
    })
}

pub fn decode_published_note(bytes: &[u8]) -> Result<(F, EncryptedNote), String> {
    let wire: WirePublishedNote = decode_tze(bytes)?;
    let enc = EncryptedNote {
        ct_d: wire.enc.ct_d,
        tag: wire.enc.tag,
        ct_v: wire.enc.ct_v,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ZERO, build_auth_tree, commit, derive_account, derive_address, derive_ask, derive_nk_spend,
        derive_nk_tag, derive_rcm, encrypt_note_deterministic, memo_ct_hash, nullifier, owner_tag,
    };
    use serde_json::json;

    const VECTOR_ADDRESS_INDEX: u32 = 0;
    const VECTOR_NOTE_VALUE: u64 = 77;
    const VECTOR_NULLIFIER_POS: u64 = 42;
    const VECTOR_DETECT_EPHEMERAL: [u8; 32] = [0x11; 32];
    const VECTOR_VIEW_EPHEMERAL: [u8; 32] = [0x22; 32];
    const VECTOR_MEMO: &[u8] = b"canonical-wire-vector";

    fn sample_felt(fill: u8) -> F {
        let mut out = [fill; 32];
        out[31] &= 0x07;
        out
    }

    fn sample_data() -> (PaymentAddress, EncryptedNote, F, NoteMemo, F, F, u64) {
        let mut master_sk = ZERO;
        master_sk[..8].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
        let acc = derive_account(&master_sk);
        let j = VECTOR_ADDRESS_INDEX;
        let d_j = derive_address(&acc.incoming_seed, j);
        let ask_j = derive_ask(&acc.ask_base, j);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_spend = derive_nk_spend(&acc.nk, &d_j);
        let nk_tag = derive_nk_tag(&nk_spend);
        let (ek_v, _, ek_d, _) = crate::derive_kem_keys(&acc.incoming_seed, j);
        let address = PaymentAddress {
            d_j,
            auth_root,
            nk_tag,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };

        let v = VECTOR_NOTE_VALUE;
        let rseed = sample_felt(0x42);
        let enc = encrypt_note_deterministic(
            v,
            &rseed,
            Some(VECTOR_MEMO),
            &ek_v,
            &ek_d,
            &VECTOR_DETECT_EPHEMERAL,
            &VECTOR_VIEW_EPHEMERAL,
        );
        let cm = commit(
            &address.d_j,
            v,
            &derive_rcm(&rseed),
            &owner_tag(&address.auth_root, &address.nk_tag),
        );
        let nf = nullifier(&nk_spend, &cm, VECTOR_NULLIFIER_POS);
        let note_memo = NoteMemo {
            index: VECTOR_NULLIFIER_POS as usize,
            cm,
            enc: enc.clone(),
        };
        (address, enc, cm, note_memo, nf, rseed, v)
    }

    fn vector_json() -> String {
        let mut master_sk = ZERO;
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
                "memo_ct_hash": hex::encode(memo_ct_hash(&enc)),
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
            "/../test_vectors/canonical_wire_v1.json"
        ))
        .trim_end_matches('\n');
        assert_eq!(vector_json(), expected);
    }
}
