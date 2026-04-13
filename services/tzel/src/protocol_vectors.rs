use crate::canonical_wire::{
    encode_encrypted_note, encode_note_memo, encode_payment_address, encode_published_note,
};
use crate::{
    auth_key_seed, build_auth_tree, commit, derive_account, derive_address, derive_ask,
    derive_auth_pub_seed, derive_kem_detect_seed, derive_kem_keys, derive_kem_view_seed,
    derive_nk_spend, derive_nk_tag, derive_note_aead_nonce, derive_rcm, hash, hash_merkle,
    hash_two, kem_keygen_from_seed, memo_ct_hash, nullifier, owner_tag, sighash_fold, wots_pk,
    wots_pk_to_leaf, wots_sign, Account, EncryptedNote, NoteMemo, PaymentAddress, DETECT_K,
    ENCRYPTED_NOTE_BYTES, F, ML_KEM768_CIPHERTEXT_BYTES, NOTE_AEAD_NONCE_BYTES, ZERO,
};
use blake2s_simd::Params;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ml_kem::{kem::TryDecapsulate, KeyExport};
use serde_json::{json, Value};

const MASTER_SK_INT: u64 = 12_345;
const WIRE_INDEX: u64 = 42;

fn raw_blake2s(data: &[u8], personal: Option<&[u8; 8]>) -> [u8; 32] {
    let mut params = Params::new();
    params.hash_length(32);
    if let Some(personal) = personal {
        params.personal(personal);
    }
    let digest = params.hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn hex_bytes(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes.as_ref())
}

fn hex_felt(f: &F) -> String {
    hex::encode(f)
}

fn felt_of_u64(n: u64) -> F {
    let mut out = ZERO;
    out[..8].copy_from_slice(&n.to_le_bytes());
    out
}

fn memo_none() -> Vec<u8> {
    let mut out = vec![0u8; crate::MEMO_SIZE];
    out[0] = 0xF6;
    out
}

fn memo_text(s: &str) -> Vec<u8> {
    let mut out = vec![0u8; crate::MEMO_SIZE];
    let bytes = s.as_bytes();
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn encrypt_with_shared_secret(
    ss_v_raw: &[u8; 32],
    v: u64,
    rseed: &F,
    memo: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let key = raw_blake2s(ss_v_raw, None);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let mut plaintext = Vec::with_capacity(8 + 32 + crate::MEMO_SIZE);
    plaintext.extend_from_slice(&v.to_le_bytes());
    plaintext.extend_from_slice(rseed);
    plaintext.extend_from_slice(memo);
    let nonce = derive_note_aead_nonce(&key, &plaintext);
    let encrypted_data = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .unwrap();
    (nonce.to_vec(), encrypted_data)
}

fn detection_tag_from_ss(ss_d: &[u8]) -> u16 {
    let tag_hash = hash(ss_d);
    u16::from_le_bytes([tag_hash[0], tag_hash[1]]) & ((1 << DETECT_K) - 1)
}

fn account() -> (F, Account) {
    let master_sk = felt_of_u64(MASTER_SK_INT);
    (master_sk, derive_account(&master_sk))
}

fn merkle_root(depth: usize, leaves: &[F]) -> F {
    let mut zero_hashes = vec![ZERO];
    for level in 0..depth {
        zero_hashes.push(hash_merkle(&zero_hashes[level], &zero_hashes[level]));
    }

    let mut level_nodes = leaves.to_vec();
    for level in 0..depth {
        let mut next = Vec::new();
        let mut i = 0;
        loop {
            let left = if i < level_nodes.len() {
                level_nodes[i]
            } else {
                zero_hashes[level]
            };
            let right = if i + 1 < level_nodes.len() {
                level_nodes[i + 1]
            } else {
                zero_hashes[level]
            };
            next.push(hash_merkle(&left, &right));
            i += 2;
            if i >= level_nodes.len() && !next.is_empty() {
                break;
            }
        }
        level_nodes = next;
    }

    if level_nodes.is_empty() {
        zero_hashes[depth]
    } else {
        level_nodes[0]
    }
}

#[derive(Clone)]
struct AddressRecord {
    j: u32,
    d_j: F,
    nk_spend: F,
    nk_tag: F,
    auth_root: F,
    auth_pub_seed: F,
    owner_tag: F,
}

fn address_record(account: &Account, j: u32) -> AddressRecord {
    let d_j = derive_address(&account.incoming_seed, j);
    let ask_j = derive_ask(&account.ask_base, j);
    let auth_root = build_auth_tree(&ask_j);
    let auth_pub_seed = derive_auth_pub_seed(&ask_j);
    let nk_spend = derive_nk_spend(&account.nk, &d_j);
    let nk_tag = derive_nk_tag(&nk_spend);
    let owner_tag = owner_tag(&auth_root, &auth_pub_seed, &nk_tag);
    AddressRecord {
        j,
        d_j,
        nk_spend,
        nk_tag,
        auth_root,
        auth_pub_seed,
        owner_tag,
    }
}

fn j0_payment_address(account: &Account) -> PaymentAddress {
    let record = address_record(account, 0);
    let (ek_v, _, ek_d, _) = derive_kem_keys(&account.incoming_seed, 0);
    PaymentAddress {
        d_j: record.d_j,
        auth_root: record.auth_root,
        auth_pub_seed: record.auth_pub_seed,
        nk_tag: record.nk_tag,
        ek_v: ek_v.to_bytes().to_vec(),
        ek_d: ek_d.to_bytes().to_vec(),
    }
}

#[cfg(test)]
fn wire_fixture_payment_address() -> PaymentAddress {
    PaymentAddress {
        d_j: felt_of_u64(1),
        auth_root: felt_of_u64(2),
        auth_pub_seed: felt_of_u64(3),
        nk_tag: felt_of_u64(4),
        ek_v: vec![0xA5; crate::canonical_wire::ML_KEM768_ENCAPSULATION_KEY_BYTES],
        ek_d: vec![0x5A; crate::canonical_wire::ML_KEM768_ENCAPSULATION_KEY_BYTES],
    }
}

fn deterministic_wire_note() -> EncryptedNote {
    let ct_d: Vec<u8> = (0..ML_KEM768_CIPHERTEXT_BYTES)
        .map(|i| (i % 256) as u8)
        .collect();
    let ct_v: Vec<u8> = (0..ML_KEM768_CIPHERTEXT_BYTES)
        .map(|i| ((i + 50) % 256) as u8)
        .collect();
    let encrypted_data: Vec<u8> = (0..ENCRYPTED_NOTE_BYTES)
        .map(|i| ((i + 100) % 256) as u8)
        .collect();
    EncryptedNote {
        ct_d,
        tag: 42,
        ct_v,
        nonce: vec![0xAA; NOTE_AEAD_NONCE_BYTES],
        encrypted_data,
    }
}

pub fn generate_protocol_v1_value() -> Value {
    let (master_sk, account) = account();
    let view_root = crate::derive_view_root(&account.incoming_seed);
    let detect_root = crate::derive_detect_root(&account.incoming_seed);
    let dsk = hash_two(&crate::tag_dsk(), &account.incoming_seed);
    let address_records: Vec<AddressRecord> =
        (0..=2u32).map(|j| address_record(&account, j)).collect();
    let addr_j0 = address_records
        .iter()
        .find(|record| record.j == 0)
        .expect("protocol vectors should include address 0")
        .clone();

    let blake2s = {
        let long_input = vec![b'x'; 200];
        let cases: Vec<(Vec<u8>, Option<[u8; 8]>)> = vec![
            (Vec::new(), None),
            (b"abc".to_vec(), None),
            (b"test".to_vec(), Some(*b"mrklSP__")),
            (b"test".to_vec(), Some(*b"nulfSP__")),
            (b"test".to_vec(), Some(*b"cmmtSP__")),
            (b"test".to_vec(), Some(*b"nkspSP__")),
            (b"test".to_vec(), Some(*b"nktgSP__")),
            (b"test".to_vec(), Some(*b"ownrSP__")),
            (b"test".to_vec(), Some(*b"wotsSP__")),
            (b"test".to_vec(), Some(*b"sighSP__")),
            (b"test".to_vec(), Some(*b"memoSP__")),
            (long_input.clone(), None),
            (long_input, Some(*b"mrklSP__")),
        ];
        Value::Array(
            cases
                .into_iter()
                .map(|(input, personal)| {
                    let output = raw_blake2s(&input, personal.as_ref());
                    json!({
                        "input": hex_bytes(&input),
                        "personal": personal.map(|p| String::from_utf8_lossy(&p).to_string()).unwrap_or_default(),
                        "output": hex_bytes(output),
                    })
                })
                .collect(),
        )
    };

    let key_hierarchy = json!({
        "master_sk": hex_felt(&master_sk),
        "nk": hex_felt(&account.nk),
        "ask_base": hex_felt(&account.ask_base),
        "dsk": hex_felt(&dsk),
        "incoming_seed": hex_felt(&account.incoming_seed),
        "view_root": hex_felt(&view_root),
        "detect_root": hex_felt(&detect_root),
    });

    let addresses = Value::Array(
        address_records
            .iter()
            .map(|record| {
                json!({
                    "j": record.j,
                    "d_j": hex_felt(&record.d_j),
                    "nk_spend": hex_felt(&record.nk_spend),
                    "nk_tag": hex_felt(&record.nk_tag),
                    "auth_root": hex_felt(&record.auth_root),
                    "auth_pub_seed": hex_felt(&record.auth_pub_seed),
                    "owner_tag": hex_felt(&record.owner_tag),
                })
            })
            .collect(),
    );

    let mlkem_seeds = Value::Array(
        [0u32, 1]
            .into_iter()
            .flat_map(|j| {
                let view_seed = derive_kem_view_seed(&account.incoming_seed, j);
                let detect_seed = derive_kem_detect_seed(&account.incoming_seed, j);
                [
                    json!({
                        "kind": "view",
                        "root": hex_felt(&view_root),
                        "j": j,
                        "seed": hex_bytes(view_seed),
                    }),
                    json!({
                        "kind": "detect",
                        "root": hex_felt(&detect_root),
                        "j": j,
                        "seed": hex_bytes(detect_seed),
                    }),
                ]
            })
            .collect(),
    );

    let mlkem_keygen = Value::Array(
        [0u32, 1]
            .into_iter()
            .map(|j| {
                let view_seed = derive_kem_view_seed(&account.incoming_seed, j);
                let detect_seed = derive_kem_detect_seed(&account.incoming_seed, j);
                let (ek_v, _dk_v) = kem_keygen_from_seed(&view_seed);
                let (ek_d, _dk_d) = kem_keygen_from_seed(&detect_seed);
                json!({
                    "j": j,
                    "view_seed": hex_bytes(view_seed),
                    "ek_v": hex_bytes(ek_v.to_bytes()),
                    "detect_seed": hex_bytes(detect_seed),
                    "ek_d": hex_bytes(ek_d.to_bytes()),
                })
            })
            .collect(),
    );

    let view_seed_j0 = derive_kem_view_seed(&account.incoming_seed, 0);
    let detect_seed_j0 = derive_kem_detect_seed(&account.incoming_seed, 0);
    let (ek_v_j0, dk_v_j0) = kem_keygen_from_seed(&view_seed_j0);
    let (ek_d_j0, _dk_d_j0) = kem_keygen_from_seed(&detect_seed_j0);

    let mlkem_encaps_derand = {
        let cases: [[u8; 32]; 3] = [[0u8; 32], [0xffu8; 32], raw_blake2s(b"encaps-coins", None)];
        Value::Array(
            cases
                .into_iter()
                .enumerate()
                .map(|(case, coins)| {
                    let coins_arr = ml_kem::array::Array::from(coins);
                    let (ct, ss) = ek_v_j0.encapsulate_deterministic(&coins_arr);
                    let ss_check = dk_v_j0.try_decapsulate(&ct).unwrap();
                    assert_eq!(ss.as_slice(), ss_check.as_slice());
                    json!({
                        "case": case,
                        "ek": hex_bytes(ek_v_j0.to_bytes()),
                        "coins": hex_bytes(coins),
                        "ss": hex_bytes(ss.as_slice()),
                        "ct": hex_bytes(ct.as_slice()),
                    })
                })
                .collect(),
        )
    };

    let chacha20 = {
        let cases = [
            (
                0usize,
                raw_blake2s(b"key-0", None),
                1000u64,
                felt_of_u64(42),
                memo_none(),
            ),
            (
                1usize,
                raw_blake2s(b"key-1", None),
                0u64,
                ZERO,
                memo_text("hello"),
            ),
        ];
        Value::Array(
            cases
                .into_iter()
                .map(|(case, ss_v, v, rseed, memo)| {
                    let (nonce, encrypted_data) =
                        encrypt_with_shared_secret(&ss_v, v, &rseed, &memo);
                    json!({
                        "case": case,
                        "ss_v": hex_bytes(ss_v),
                        "v": v.to_string(),
                        "rseed": hex_felt(&rseed),
                        "memo": hex_bytes(&memo),
                        "nonce": hex_bytes(&nonce),
                        "encrypted_data": hex_bytes(encrypted_data),
                    })
                })
                .collect(),
        )
    };

    let detection_tags = {
        let labels = ["ss-0", "ss-1", "ss-2", "all-zeros"];
        Value::Array(
            labels
                .into_iter()
                .enumerate()
                .map(|(case, label)| {
                    let ss_d = raw_blake2s(label.as_bytes(), None);
                    json!({
                        "case": case,
                        "ss_d": hex_bytes(ss_d),
                        "tag": detection_tag_from_ss(&ss_d),
                    })
                })
                .collect(),
        )
    };

    let memo_ct_hash_value = {
        let ct_d: Vec<u8> = (0..ML_KEM768_CIPHERTEXT_BYTES)
            .map(|i| (i % 256) as u8)
            .collect();
        let ct_v: Vec<u8> = (0..ML_KEM768_CIPHERTEXT_BYTES)
            .map(|i| ((i + 100) % 256) as u8)
            .collect();
        let encrypted_data: Vec<u8> = (0..ENCRYPTED_NOTE_BYTES)
            .map(|i| ((i + 200) % 256) as u8)
            .collect();
        let enc = EncryptedNote {
            ct_d: ct_d.clone(),
            tag: 42,
            ct_v: ct_v.clone(),
            nonce: vec![0xCC; NOTE_AEAD_NONCE_BYTES],
            encrypted_data: encrypted_data.clone(),
        };
        json!({
            "ct_d": hex_bytes(ct_d),
            "tag": 42,
            "ct_v": hex_bytes(ct_v),
            "nonce": hex_bytes(&enc.nonce),
            "encrypted_data": hex_bytes(encrypted_data),
            "memo_ct_hash": hex_felt(&memo_ct_hash(&enc)),
        })
    };

    let cross_impl_encrypt = {
        let coins_v = raw_blake2s(b"view-encaps-coins", None);
        let coins_d = raw_blake2s(b"detect-encaps-coins", None);
        let (ct_v, ss_v) = ek_v_j0.encapsulate_deterministic(&ml_kem::array::Array::from(coins_v));
        let (ct_d, ss_d) = ek_d_j0.encapsulate_deterministic(&ml_kem::array::Array::from(coins_d));
        let v = 42_000u64;
        let rseed = felt_of_u64(777);
        let memo = memo_text("cross-impl test");
        let (nonce, encrypted_data) =
            encrypt_with_shared_secret(ss_v.as_slice().try_into().unwrap(), v, &rseed, &memo);
        let enc = EncryptedNote {
            ct_d: ct_d.to_vec(),
            tag: detection_tag_from_ss(ss_d.as_slice()),
            ct_v: ct_v.to_vec(),
            nonce: nonce.clone(),
            encrypted_data: encrypted_data.clone(),
        };
        json!({
            "master_sk": hex_felt(&master_sk),
            "view_seed": hex_bytes(view_seed_j0),
            "detect_seed": hex_bytes(detect_seed_j0),
            "ek_v": hex_bytes(ek_v_j0.to_bytes()),
            "ek_d": hex_bytes(ek_d_j0.to_bytes()),
            "coins_v": hex_bytes(coins_v),
            "coins_d": hex_bytes(coins_d),
            "ss_v": hex_bytes(ss_v.as_slice()),
            "ss_d": hex_bytes(ss_d.as_slice()),
            "ct_v": hex_bytes(ct_v.as_slice()),
            "ct_d": hex_bytes(ct_d.as_slice()),
            "v": v.to_string(),
            "rseed": hex_felt(&rseed),
            "memo": hex_bytes(&memo),
            "nonce": hex_bytes(&nonce),
            "encrypted_data": hex_bytes(&encrypted_data),
            "tag": enc.tag,
            "memo_ct_hash": hex_felt(&memo_ct_hash(&enc)),
        })
    };

    let wots = {
        let sighash = hash(b"test-sighash");
        Value::Array(
            [42u64, 100, 999]
                .into_iter()
                .map(|ask_value| {
                    let ask_j = felt_of_u64(ask_value);
                    let key_idx = 0u32;
                    let auth_pub_seed = derive_auth_pub_seed(&ask_j);
                    let seed = auth_key_seed(&ask_j, key_idx);
                    let pk = wots_pk(&ask_j, key_idx);
                    let signature = wots_sign(&ask_j, key_idx, &sighash).0;
                    json!({
                        "ask_j": hex_felt(&ask_j),
                        "key_idx": key_idx,
                        "seed": hex_felt(&seed),
                        "auth_pub_seed": hex_felt(&auth_pub_seed),
                        "leaf": hex_felt(&wots_pk_to_leaf(&auth_pub_seed, key_idx, &pk)),
                        "sighash": hex_felt(&sighash),
                        "signature": signature.iter().map(hex_felt).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        )
    };

    let merkle = {
        let cases: Vec<(usize, Vec<u64>)> = vec![
            (3, vec![1, 2, 3, 4]),
            (4, vec![10, 20, 30]),
            (3, vec![1]),
            (4, (1..=16).collect()),
            (3, vec![]),
        ];
        Value::Array(
            cases
                .into_iter()
                .map(|(depth, leaf_values)| {
                    let leaves: Vec<F> = leaf_values.iter().copied().map(felt_of_u64).collect();
                    json!({
                        "depth": depth,
                        "leaves": leaves.iter().map(hex_felt).collect::<Vec<_>>(),
                        "root": hex_felt(&merkle_root(depth, &leaves)),
                    })
                })
                .collect(),
        )
    };

    let notes = {
        let cases = [(1000u64, 777u64, 0u64), (0, 1, 5), (999_999, 42, 100)];
        Value::Array(
            cases
                .into_iter()
                .map(|(v, rseed_i, pos)| {
                    let rseed = felt_of_u64(rseed_i);
                    let rcm = derive_rcm(&rseed);
                    let cm = commit(&addr_j0.d_j, v, &rcm, &addr_j0.owner_tag);
                    json!({
                        "d_j": hex_felt(&addr_j0.d_j),
                        "v": v.to_string(),
                        "rseed": hex_felt(&rseed),
                        "auth_root": hex_felt(&addr_j0.auth_root),
                        "auth_pub_seed": hex_felt(&addr_j0.auth_pub_seed),
                        "nk_tag": hex_felt(&addr_j0.nk_tag),
                        "rcm": hex_felt(&rcm),
                        "owner_tag": hex_felt(&addr_j0.owner_tag),
                        "cm": hex_felt(&cm),
                        "nk_spend": hex_felt(&addr_j0.nk_spend),
                        "pos": pos,
                        "nf": hex_felt(&nullifier(&addr_j0.nk_spend, &cm, pos)),
                    })
                })
                .collect(),
        )
    };

    let sighash = {
        let transfer_items = vec![
            felt_of_u64(0x01),
            hash(b"domain"),
            hash(b"root"),
            hash(b"nf0"),
            hash(b"cm1"),
            hash(b"cm2"),
            ZERO,
            ZERO,
        ];
        let unshield_items = vec![
            felt_of_u64(0x02),
            hash(b"domain"),
            hash(b"root"),
            hash(b"nf0"),
            felt_of_u64(5000),
            hash(b"bob"),
            ZERO,
            ZERO,
        ];
        let cases = vec![
            vec![felt_of_u64(1), felt_of_u64(2), felt_of_u64(3)],
            transfer_items,
            unshield_items,
        ];
        Value::Array(
            cases
                .into_iter()
                .map(|items| {
                    let mut acc = items[0];
                    for item in &items[1..] {
                        acc = sighash_fold(&acc, item);
                    }
                    json!({
                        "items": items.iter().map(hex_felt).collect::<Vec<_>>(),
                        "result": hex_felt(&acc),
                    })
                })
                .collect(),
        )
    };

    let account_ids = {
        let weird = "a]very+long/identifier\0with\nnulls";
        Value::Array(
            ["alice", "bob", "", weird]
                .into_iter()
                .map(|s| {
                    json!({
                        "string": s,
                        "id": hex_felt(&hash(s.as_bytes())),
                    })
                })
                .collect(),
        )
    };

    let wire_encoding = {
        let payment_address = j0_payment_address(&account);
        let enc = deterministic_wire_note();
        let cm = hash(b"wire-test-cm");
        let note_memo = NoteMemo {
            index: WIRE_INDEX as usize,
            cm,
            enc: enc.clone(),
        };
        json!({
            "payment_address": hex_bytes(encode_payment_address(&payment_address).unwrap()),
            "encrypted_note": hex_bytes(encode_encrypted_note(&enc).unwrap()),
            "published_note": hex_bytes(encode_published_note(&cm, &enc).unwrap()),
            "note_memo": hex_bytes(encode_note_memo(&note_memo).unwrap()),
        })
    };

    json!({
        "blake2s": blake2s,
        "key_hierarchy": key_hierarchy,
        "addresses": addresses,
        "mlkem_seeds": mlkem_seeds,
        "mlkem_keygen": mlkem_keygen,
        "mlkem_encaps_derand": mlkem_encaps_derand,
        "chacha20": chacha20,
        "detection_tags": detection_tags,
        "memo_ct_hash": memo_ct_hash_value,
        "cross_impl_encrypt": cross_impl_encrypt,
        "wots": wots,
        "merkle": merkle,
        "notes": notes,
        "sighash": sighash,
        "account_ids": account_ids,
        "wire_encoding": wire_encoding,
    })
}

pub fn generate_protocol_v1_json() -> String {
    serde_json::to_string_pretty(&generate_protocol_v1_value()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tzel_core::{canonical_wire::*, MEMO_SIZE};

    #[test]
    fn test_protocol_vectors_file_is_self_consistent() {
        let generated: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/ocaml_vectors/protocol_v1.json"
        )))
        .expect("checked-in protocol vectors should parse");

        let top = generated.as_object().unwrap();
        let expected_keys = [
            "blake2s",
            "key_hierarchy",
            "addresses",
            "mlkem_seeds",
            "mlkem_keygen",
            "mlkem_encaps_derand",
            "chacha20",
            "detection_tags",
            "memo_ct_hash",
            "cross_impl_encrypt",
            "wots",
            "merkle",
            "notes",
            "sighash",
            "account_ids",
            "wire_encoding",
        ];
        for key in expected_keys {
            assert!(top.contains_key(key), "missing section {}", key);
        }

        assert_eq!(
            generated["key_hierarchy"]["master_sk"],
            Value::String(hex_felt(&felt_of_u64(MASTER_SK_INT)))
        );
        assert_eq!(generated["addresses"].as_array().unwrap().len(), 3);
        assert_eq!(generated["mlkem_seeds"].as_array().unwrap().len(), 4);
        assert_eq!(generated["mlkem_keygen"].as_array().unwrap().len(), 2);
        assert_eq!(
            generated["mlkem_encaps_derand"].as_array().unwrap().len(),
            3
        );
        assert_eq!(generated["wots"].as_array().unwrap().len(), 3);

        assert_eq!(
            generated["mlkem_keygen"][0]["view_seed"],
            generated["mlkem_seeds"][0]["seed"]
        );
        assert_eq!(
            generated["mlkem_keygen"][0]["detect_seed"],
            generated["mlkem_seeds"][1]["seed"]
        );
        assert_eq!(
            generated["cross_impl_encrypt"]["view_seed"],
            generated["mlkem_keygen"][0]["view_seed"]
        );
        assert_eq!(
            generated["cross_impl_encrypt"]["detect_seed"],
            generated["mlkem_keygen"][0]["detect_seed"]
        );
        assert_eq!(
            generated["cross_impl_encrypt"]["ek_v"],
            generated["mlkem_keygen"][0]["ek_v"]
        );
        assert_eq!(
            generated["cross_impl_encrypt"]["ek_d"],
            generated["mlkem_keygen"][0]["ek_d"]
        );
    }

    #[test]
    fn test_merkle_root_handles_empty_and_sparse_prefixes() {
        let zero1 = hash_merkle(&ZERO, &ZERO);
        let zero2 = hash_merkle(&zero1, &zero1);
        assert_eq!(merkle_root(2, &[]), zero2);

        let leaves = [felt_of_u64(1), felt_of_u64(2), felt_of_u64(3)];
        let level0_left = hash_merkle(&leaves[0], &leaves[1]);
        let level0_right = hash_merkle(&leaves[2], &ZERO);
        let expected = hash_merkle(&level0_left, &level0_right);
        assert_eq!(merkle_root(2, &leaves), expected);
    }

    #[test]
    fn test_memo_helpers_have_expected_fixed_format() {
        let none = memo_none();
        let text = memo_text("hi");

        assert_eq!(none.len(), MEMO_SIZE);
        assert_eq!(text.len(), MEMO_SIZE);
        assert_eq!(none[0], 0xF6);
        assert_eq!(&text[..2], b"hi");
        assert!(text[2..].iter().all(|b| *b == 0));
    }

    #[test]
    fn test_detection_tag_is_masked_and_deterministic() {
        let ss = [0x42u8; 32];
        let tag1 = detection_tag_from_ss(&ss);
        let tag2 = detection_tag_from_ss(&ss);
        assert_eq!(tag1, tag2);
        assert!(tag1 < (1 << DETECT_K));
    }

    #[test]
    fn test_wire_helpers_roundtrip_deterministic_fixture_values() {
        let address = wire_fixture_payment_address();
        let addr_bytes = encode_payment_address(&address).expect("address should encode");
        assert_eq!(
            decode_payment_address(&addr_bytes)
                .expect("address should decode")
                .d_j,
            address.d_j
        );

        let enc = deterministic_wire_note();
        let enc_bytes = encode_encrypted_note(&enc).expect("note should encode");
        assert_eq!(
            decode_encrypted_note(&enc_bytes)
                .expect("note should decode")
                .encrypted_data,
            enc.encrypted_data
        );

        let note_memo = NoteMemo {
            index: WIRE_INDEX as usize,
            cm: hash_two(&felt_of_u64(7), &felt_of_u64(8)),
            enc: enc.clone(),
        };
        let memo_bytes = encode_note_memo(&note_memo).expect("memo should encode");
        assert_eq!(
            decode_note_memo(&memo_bytes)
                .expect("memo should decode")
                .index,
            note_memo.index
        );

        let published =
            encode_published_note(&note_memo.cm, &enc).expect("published note should encode");
        let (decoded_cm, decoded_enc) =
            decode_published_note(&published).expect("published note should decode");
        assert_eq!(decoded_cm, note_memo.cm);
        assert_eq!(decoded_enc.tag, enc.tag);
    }
}
