//! TzEL core protocol/state library.

pub mod canonical_wire;
pub mod kernel_wire;
pub mod operator_api;

use blake2s_simd::Params;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ml_kem::kem::TryDecapsulate;
use ml_kem::ml_kem_768;
#[cfg(not(target_arch = "wasm32"))]
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ═══════════════════════════════════════════════════════════════════════
// Core types
// ═══════════════════════════════════════════════════════════════════════

pub type F = [u8; 32];
pub const ZERO: F = [0u8; 32];
pub const DETECT_K: usize = 10;
pub const ML_KEM768_CIPHERTEXT_BYTES: usize = 1088;
pub const NOTE_AEAD_NONCE_BYTES: usize = 12;
pub const ENCRYPTED_NOTE_BYTES: usize = 8 + 32 + MEMO_SIZE + 16;
pub const MAX_VALID_ROOTS: usize = 4096;

/// Generate a random valid felt252 (251-bit value).
#[cfg(not(target_arch = "wasm32"))]
pub fn random_felt() -> F {
    let mut rng = rand::rng();
    let mut f: F = rng.random();
    f[31] &= 0x07; // truncate to 251 bits
    f
}
pub const MEMO_SIZE: usize = 1024;
/// Must match TREE_DEPTH in merkle.cairo (default Scarb feature: depth48).
pub const DEPTH: usize = 48;

// ═══════════════════════════════════════════════════════════════════════
// Serde helpers — hex encoding for F and Vec<u8>
// ═══════════════════════════════════════════════════════════════════════

pub mod hex_f {
    use super::F;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(f: &F, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(f))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<F, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut f = [0u8; 32];
        f.copy_from_slice(&bytes);
        Ok(f)
    }
}

pub mod hex_f_vec {
    use super::F;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<F>, s: S) -> Result<S::Ok, S::Error> {
        let hexes: Vec<String> = v.iter().map(|f| hex::encode(f)).collect();
        hexes.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<F>, D::Error> {
        let hexes: Vec<String> = Vec::deserialize(d)?;
        hexes
            .iter()
            .map(|s| {
                let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes"));
                }
                let mut f = [0u8; 32];
                f.copy_from_slice(&bytes);
                Ok(f)
            })
            .collect()
    }
}

pub mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod hex_bytes_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match b {
            Some(bytes) => s.serialize_some(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let maybe = Option::<String>::deserialize(d)?;
        maybe
            .map(|s| hex::decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// BLAKE2s hashing — personalized, 251-bit truncated
// ═══════════════════════════════════════════════════════════════════════

pub(crate) fn blake2s(personal: &[u8; 8], data: &[u8]) -> F {
    let digest = Params::new().hash_length(32).personal(personal).hash(data);
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07;
    out
}

pub(crate) fn blake2s_generic(data: &[u8]) -> F {
    let digest = Params::new().hash_length(32).hash(data);
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07;
    out
}

pub fn hash(data: &[u8]) -> F {
    blake2s_generic(data)
}

pub(crate) fn blake2s_parts(parts: &[&F]) -> F {
    let mut state = Params::new().hash_length(32).to_state();
    for part in parts {
        state.update(&part[..]);
    }
    let digest = state.finalize();
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07;
    out
}

pub(crate) fn blake2s_parts_personalized(personal: &[u8; 8], parts: &[&F]) -> F {
    let mut state = Params::new().hash_length(32).personal(personal).to_state();
    for part in parts {
        state.update(&part[..]);
    }
    let digest = state.finalize();
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07;
    out
}

pub fn hash_two(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    hash(&buf)
}

pub fn hash_merkle(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    blake2s(b"mrklSP__", &buf)
}

fn hash_commit_raw(data: &[u8]) -> F {
    blake2s(b"cmmtSP__", data)
}

pub fn derive_rcm(rseed: &F) -> F {
    let mut tag = ZERO;
    tag[0] = 0x6D;
    tag[1] = 0x63;
    tag[2] = 0x72;
    hash_two(&hash(&tag), rseed)
}

pub fn derive_nk_spend(nk: &F, d_j: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(nk);
    buf[32..].copy_from_slice(d_j);
    blake2s(b"nkspSP__", &buf)
}

pub fn derive_nk_tag(nk_spend: &F) -> F {
    blake2s(b"nktgSP__", nk_spend)
}

pub fn owner_tag(auth_root: &F, auth_pub_seed: &F, nk_tag: &F) -> F {
    blake2s_parts_personalized(b"ownrSP__", &[auth_root, auth_pub_seed, nk_tag])
}

pub fn commit(d_j: &F, v: u64, rcm: &F, otag: &F) -> F {
    let mut buf = [0u8; 128];
    buf[..32].copy_from_slice(d_j);
    // Canonical commitment encoding stores v as a u64 in bytes [32..40).
    // Bytes [40..64) are intentionally zero.
    buf[32..40].copy_from_slice(&v.to_le_bytes());
    buf[64..96].copy_from_slice(rcm);
    buf[96..128].copy_from_slice(otag);
    hash_commit_raw(&buf)
}

pub fn nullifier(nk_spend: &F, cm: &F, pos: u64) -> F {
    let mut buf1 = [0u8; 64];
    buf1[..32].copy_from_slice(cm);
    let mut pos_f = ZERO;
    pos_f[..8].copy_from_slice(&pos.to_le_bytes());
    buf1[32..].copy_from_slice(&pos_f);
    let cm_pos = blake2s(b"nulfSP__", &buf1);
    let mut buf2 = [0u8; 64];
    buf2[..32].copy_from_slice(nk_spend);
    buf2[32..].copy_from_slice(&cm_pos);
    blake2s(b"nulfSP__", &buf2)
}

/// Sighash fold: H_sighash(a, b) using "sighSP__" personalization.
pub fn sighash_fold(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    blake2s(b"sighSP__", &buf)
}

/// Development default for spend-authorization domain binding.
/// Production deployments should override this with a unique per-deployment value.
pub fn default_auth_domain() -> F {
    hash(b"tzel-auth-domain-local-dev-v1")
}

/// Compute transfer sighash from public outputs.
pub fn transfer_sighash(
    auth_domain: &F,
    root: &F,
    nullifiers: &[F],
    cm_1: &F,
    cm_2: &F,
    mh_1: &F,
    mh_2: &F,
) -> F {
    // Circuit-type tag 0x01 for transfer
    let mut type_tag = ZERO;
    type_tag[0] = 0x01;
    let mut sh = sighash_fold(&type_tag, auth_domain);
    sh = sighash_fold(&sh, root);
    for nf in nullifiers {
        sh = sighash_fold(&sh, nf);
    }
    sh = sighash_fold(&sh, cm_1);
    sh = sighash_fold(&sh, cm_2);
    sh = sighash_fold(&sh, mh_1);
    sh = sighash_fold(&sh, mh_2);
    sh
}

/// Compute unshield sighash from public outputs.
pub fn unshield_sighash(
    auth_domain: &F,
    root: &F,
    nullifiers: &[F],
    v_pub: u64,
    recipient: &F,
    cm_change: &F,
    mh_change: &F,
) -> F {
    // Circuit-type tag 0x02 for unshield
    let mut type_tag = ZERO;
    type_tag[0] = 0x02;
    let mut sh = sighash_fold(&type_tag, auth_domain);
    sh = sighash_fold(&sh, root);
    for nf in nullifiers {
        sh = sighash_fold(&sh, nf);
    }
    let mut v_felt = ZERO;
    v_felt[..8].copy_from_slice(&v_pub.to_le_bytes());
    sh = sighash_fold(&sh, &v_felt);
    sh = sighash_fold(&sh, recipient);
    sh = sighash_fold(&sh, cm_change);
    sh = sighash_fold(&sh, mh_change);
    sh
}

/// Hash of all encrypted note data — binds the full on-chain note to the proof.
/// Covers detection ciphertext, tag, viewing ciphertext, and encrypted payload.
/// A relayer cannot swap any component without invalidating the hash.
pub fn memo_ct_hash(enc: &EncryptedNote) -> F {
    let mut buf = Vec::with_capacity(
        enc.ct_d.len() + 2 + enc.ct_v.len() + enc.nonce.len() + enc.encrypted_data.len(),
    );
    buf.extend_from_slice(&enc.ct_d);
    buf.extend_from_slice(&enc.tag.to_le_bytes());
    buf.extend_from_slice(&enc.ct_v);
    buf.extend_from_slice(&enc.nonce);
    buf.extend_from_slice(&enc.encrypted_data);
    blake2s(b"memoSP__", &buf)
}

pub fn derive_note_aead_nonce(aead_key: &F, plaintext: &[u8]) -> [u8; NOTE_AEAD_NONCE_BYTES] {
    let mut input = Vec::with_capacity(aead_key.len() + plaintext.len());
    input.extend_from_slice(aead_key);
    input.extend_from_slice(plaintext);
    let digest = blake2s(b"mnonSP__", &input);
    let mut nonce = [0u8; NOTE_AEAD_NONCE_BYTES];
    nonce.copy_from_slice(&digest[..NOTE_AEAD_NONCE_BYTES]);
    nonce
}

pub fn short(f: &F) -> String {
    hex::encode(&f[..4])
}

pub fn u64_to_felt(v: u64) -> F {
    let mut felt = ZERO;
    felt[..8].copy_from_slice(&v.to_le_bytes());
    felt
}

pub fn felt_to_u64(f: &F) -> Result<u64, String> {
    if f[8..].iter().any(|&b| b != 0) {
        return Err("felt does not fit in u64".into());
    }
    Ok(u64::from_le_bytes(f[..8].try_into().unwrap()))
}

pub fn felt_to_usize(f: &F) -> Result<usize, String> {
    felt_to_u64(f)?
        .try_into()
        .map_err(|_| "felt does not fit in usize".to_string())
}

// ═══════════════════════════════════════════════════════════════════════
// Key derivation
// ═══════════════════════════════════════════════════════════════════════

pub fn felt_tag(s: &[u8]) -> F {
    let mut val = 0u128;
    for &b in s {
        val = (val << 8) | b as u128;
    }
    let mut f = ZERO;
    let le = val.to_le_bytes();
    f[..16].copy_from_slice(&le);
    f
}

pub fn tag_dsk() -> F {
    felt_tag(b"dsk")
}

#[derive(Clone)]
pub struct Account {
    pub nk: F,
    pub ask_base: F,
    pub incoming_seed: F,
}

pub fn derive_account(master_sk: &F) -> Account {
    let spend_seed = hash_two(&felt_tag(b"spend"), master_sk);
    Account {
        nk: hash_two(&felt_tag(b"nk"), &spend_seed),
        ask_base: hash_two(&felt_tag(b"ask"), &spend_seed),
        incoming_seed: hash_two(&felt_tag(b"incoming"), master_sk),
    }
}

pub fn derive_address(incoming_seed: &F, j: u32) -> F {
    let dsk = hash_two(&tag_dsk(), incoming_seed);
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&j.to_le_bytes());
    hash_two(&dsk, &idx)
}

pub fn derive_ask(ask_base: &F, j: u32) -> F {
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&j.to_le_bytes());
    hash_two(ask_base, &idx)
}

// ═══════════════════════════════════════════════════════════════════════
// Auth key tree — XMSS-style WOTS+ tree with explicit pub_seed
// ═══════════════════════════════════════════════════════════════════════

pub const AUTH_DEPTH: usize = 16;
pub const AUTH_TREE_SIZE: usize = 1 << AUTH_DEPTH; // 65536
pub const WOTS_W: usize = 4;
pub const WOTS_CHAINS: usize = 133; // 128 msg + 5 checksum

const TAG_XMSS_CHAIN_U64: u64 = 0x0068632D73736D78;
const TAG_XMSS_LTREE_U64: u64 = 0x00746C2D73736D78;
const TAG_XMSS_TREE_U64: u64 = 0x0072742D73736D78;

fn felt_from_u32(v: u32) -> F {
    let mut out = ZERO;
    out[..4].copy_from_slice(&v.to_le_bytes());
    out
}

pub fn auth_key_seed(ask_j: &F, key_idx: u32) -> F {
    blake2s_parts(&[&felt_tag(b"xmss-sk"), ask_j, &felt_from_u32(key_idx)])
}

pub fn derive_auth_pub_seed(ask_j: &F) -> F {
    blake2s_parts(&[&felt_tag(b"xmss-ps"), ask_j])
}

fn wots_sk_chain(ask_j: &F, key_idx: u32, chain_idx: u32) -> F {
    let root = auth_key_seed(ask_j, key_idx);
    hash_two(&root, &felt_from_u32(chain_idx))
}

pub fn pack_adrs(tag: u64, key_idx: u32, a: u32, b: u32, c: u32) -> F {
    let mut out = ZERO;
    out[..8].copy_from_slice(&tag.to_le_bytes());
    out[8..12].copy_from_slice(&key_idx.to_le_bytes());
    out[12..16].copy_from_slice(&a.to_le_bytes());
    out[16..20].copy_from_slice(&b.to_le_bytes());
    out[20..24].copy_from_slice(&c.to_le_bytes());
    out[31] &= 0x07;
    out
}

pub fn hash1_wots(data: &F) -> F {
    blake2s(b"wotsSP__", data)
}

pub fn hash_chain(x: &F, n: usize) -> F {
    let mut current = *x;
    for _ in 0..n {
        current = hash1_wots(&current);
    }
    current
}

fn wots_digits(msg_hash: &F) -> Vec<u32> {
    let mut digits: Vec<usize> = Vec::new();
    for byte in msg_hash.iter() {
        let mut b = *byte;
        for _ in 0..4 {
            digits.push((b & 3) as usize);
            b >>= 2;
        }
    }
    let checksum: usize = digits.iter().map(|d| WOTS_W - 1 - d).sum();
    let mut cs = checksum;
    for _ in 0..5 {
        digits.push(cs & 3);
        cs >>= 2;
    }
    digits.truncate(WOTS_CHAINS);
    digits.into_iter().map(|d| d as u32).collect()
}

fn xmss_chain_step(x: &F, pub_seed: &F, key_idx: u32, chain_idx: u32, step: u32) -> F {
    let adrs = pack_adrs(TAG_XMSS_CHAIN_U64, key_idx, chain_idx, step, 0);
    blake2s_parts(&[pub_seed, &adrs, x])
}

fn xmss_hash_chain(
    x: &F,
    pub_seed: &F,
    key_idx: u32,
    chain_idx: u32,
    start: usize,
    steps: usize,
) -> F {
    let mut current = *x;
    for step in start..(start + steps) {
        current = xmss_chain_step(&current, pub_seed, key_idx, chain_idx, step as u32);
    }
    current
}

fn xmss_node_hash(
    pub_seed: &F,
    tag: u64,
    key_idx: u32,
    level: u32,
    node_idx: u32,
    left: &F,
    right: &F,
) -> F {
    let adrs = pack_adrs(tag, key_idx, level, node_idx, 0);
    blake2s_parts(&[pub_seed, &adrs, left, right])
}

pub fn xmss_ltree_node_hash(
    pub_seed: &F,
    key_idx: u32,
    level: u32,
    node_idx: u32,
    left: &F,
    right: &F,
) -> F {
    xmss_node_hash(
        pub_seed,
        TAG_XMSS_LTREE_U64,
        key_idx,
        level,
        node_idx,
        left,
        right,
    )
}

pub fn xmss_tree_node_hash(pub_seed: &F, level: u32, node_idx: u32, left: &F, right: &F) -> F {
    xmss_node_hash(pub_seed, TAG_XMSS_TREE_U64, 0, level, node_idx, left, right)
}

pub fn wots_pk(ask_j: &F, key_idx: u32) -> Vec<F> {
    let pub_seed = derive_auth_pub_seed(ask_j);
    (0..WOTS_CHAINS)
        .map(|j| {
            let sk = wots_sk_chain(ask_j, key_idx, j as u32);
            xmss_hash_chain(&sk, &pub_seed, key_idx, j as u32, 0, WOTS_W - 1)
        })
        .collect()
}

pub fn wots_pk_to_leaf(pub_seed: &F, key_idx: u32, pk: &[F]) -> F {
    let mut level = 0u32;
    let mut current = pk.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut node_idx = 0u32;
        for pair in current.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0]);
            } else {
                next.push(xmss_ltree_node_hash(
                    pub_seed, key_idx, level, node_idx, &pair[0], &pair[1],
                ));
                node_idx += 1;
            }
        }
        current = next;
        level += 1;
    }
    current[0]
}

pub fn auth_leaf_hash_with_pub_seed(ask_j: &F, pub_seed: &F, key_idx: u32) -> F {
    let mut current = [ZERO; WOTS_CHAINS];
    for (chain_idx, slot) in current.iter_mut().enumerate() {
        let sk = wots_sk_chain(ask_j, key_idx, chain_idx as u32);
        *slot = xmss_hash_chain(&sk, pub_seed, key_idx, chain_idx as u32, 0, WOTS_W - 1);
    }

    let mut level = 0u32;
    let mut len = WOTS_CHAINS;
    while len > 1 {
        let mut write = 0usize;
        let mut read = 0usize;
        let mut node_idx = 0u32;
        while read < len {
            if read + 1 == len {
                current[write] = current[read];
            } else {
                current[write] = xmss_ltree_node_hash(
                    pub_seed,
                    key_idx,
                    level,
                    node_idx,
                    &current[read],
                    &current[read + 1],
                );
                node_idx += 1;
            }
            write += 1;
            read += 2;
        }
        len = write;
        level += 1;
    }
    current[0]
}

pub fn auth_leaf_hash(ask_j: &F, key_idx: u32) -> F {
    let pub_seed = derive_auth_pub_seed(ask_j);
    auth_leaf_hash_with_pub_seed(ask_j, &pub_seed, key_idx)
}

pub fn wots_sign(ask_j: &F, key_idx: u32, msg_hash: &F) -> (Vec<F>, Vec<F>, Vec<u32>) {
    let pub_seed = derive_auth_pub_seed(ask_j);
    let digits = wots_digits(msg_hash);
    let sig: Vec<F> = (0..WOTS_CHAINS)
        .map(|j| {
            let sk = wots_sk_chain(ask_j, key_idx, j as u32);
            xmss_hash_chain(&sk, &pub_seed, key_idx, j as u32, 0, digits[j] as usize)
        })
        .collect();
    let pk = wots_pk(ask_j, key_idx);
    (sig, pk, digits)
}

pub fn recover_wots_pk(msg_hash: &F, pub_seed: &F, key_idx: u32, sig: &[F]) -> Vec<F> {
    let digits = wots_digits(msg_hash);
    sig.iter()
        .zip(digits.iter())
        .enumerate()
        .map(|(chain_idx, (sig_part, digit))| {
            xmss_hash_chain(
                sig_part,
                pub_seed,
                key_idx,
                chain_idx as u32,
                *digit as usize,
                (WOTS_W - 1) - (*digit as usize),
            )
        })
        .collect()
}

pub fn xmss_subtree_root(ask_j: &F, pub_seed: &F, start: u32, height: usize) -> F {
    if height == AUTH_DEPTH && start == 0 {
        assert_full_xmss_rebuild_allowed("xmss_subtree_root");
    }
    if height == 0 {
        return wots_pk_to_leaf(pub_seed, start, &wots_pk(ask_j, start));
    }
    let split = 1u32 << (height - 1);
    let left = xmss_subtree_root(ask_j, pub_seed, start, height - 1);
    let right = xmss_subtree_root(ask_j, pub_seed, start + split, height - 1);
    xmss_tree_node_hash(
        pub_seed,
        (height - 1) as u32,
        start >> height,
        &left,
        &right,
    )
}

fn xmss_root_and_path_inner(
    ask_j: &F,
    pub_seed: &F,
    start: u32,
    height: usize,
    target: u32,
) -> (F, Option<Vec<F>>) {
    if height == AUTH_DEPTH && start == 0 {
        assert_full_xmss_rebuild_allowed("xmss_root_and_path_inner");
    }
    if height == 0 {
        let leaf = wots_pk_to_leaf(pub_seed, start, &wots_pk(ask_j, start));
        let path = (start == target).then(Vec::new);
        return (leaf, path);
    }

    let split = 1u32 << (height - 1);
    let mid = start + split;
    let (left, left_path) = if target < mid {
        xmss_root_and_path_inner(ask_j, pub_seed, start, height - 1, target)
    } else {
        (xmss_subtree_root(ask_j, pub_seed, start, height - 1), None)
    };
    let (right, right_path) = if target >= mid {
        xmss_root_and_path_inner(ask_j, pub_seed, mid, height - 1, target)
    } else {
        (xmss_subtree_root(ask_j, pub_seed, mid, height - 1), None)
    };

    let root = xmss_tree_node_hash(
        pub_seed,
        (height - 1) as u32,
        start >> height,
        &left,
        &right,
    );

    let path = if let Some(mut path) = left_path {
        path.push(right);
        Some(path)
    } else if let Some(mut path) = right_path {
        path.push(left);
        Some(path)
    } else {
        None
    };

    (root, path)
}

pub fn build_auth_tree(ask_j: &F) -> F {
    assert_full_xmss_rebuild_allowed("build_auth_tree");
    let pub_seed = derive_auth_pub_seed(ask_j);
    xmss_subtree_root(ask_j, &pub_seed, 0, AUTH_DEPTH)
}

pub fn auth_tree_path(ask_j: &F, index: usize) -> Vec<F> {
    assert_full_xmss_rebuild_allowed("auth_tree_path");
    let pub_seed = derive_auth_pub_seed(ask_j);
    let (_, path) = xmss_root_and_path_inner(ask_j, &pub_seed, 0, AUTH_DEPTH, index as u32);
    path.expect("target leaf must be within auth tree")
}

pub fn auth_root_and_path(ask_j: &F, index: usize) -> (F, Vec<F>) {
    assert_full_xmss_rebuild_allowed("auth_root_and_path");
    let pub_seed = derive_auth_pub_seed(ask_j);
    let (root, path) = xmss_root_and_path_inner(ask_j, &pub_seed, 0, AUTH_DEPTH, index as u32);
    (root, path.expect("target leaf must be within auth tree"))
}

fn assert_full_xmss_rebuild_allowed(op: &str) {
    if std::env::var_os("TZEL_TRAP_FULL_XMSS_REBUILDS").is_some()
        && std::env::var_os("TZEL_ALLOW_FULL_XMSS_REBUILD").is_none()
    {
        panic!(
            "unexpected full depth-{} XMSS rebuild via {} — default tests must use fixed fixtures or small-depth helpers",
            AUTH_DEPTH, op
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ML-KEM-768 encryption + detection
// ═══════════════════════════════════════════════════════════════════════

pub type Ek = ml_kem_768::EncapsulationKey;
pub type Dk = ml_kem_768::DecapsulationKey;

fn ct_eq_u16(a: u16, b: u16) -> bool {
    let x = a ^ b;
    let mut diff = 0u8;
    diff |= x as u8;
    diff |= (x >> 8) as u8;
    diff == 0
}

pub fn kem_keygen_from_seed(seed: &[u8; 64]) -> (Ek, Dk) {
    let seed_arr = ml_kem::array::Array::from(*seed);
    let dk = ml_kem_768::DecapsulationKey::from_seed(seed_arr);
    let ek = dk.encapsulation_key().clone();
    (ek, dk)
}

/// Derive the incoming viewing root from incoming_seed.
pub fn derive_view_root(incoming_seed: &F) -> F {
    hash_two(&felt_tag(b"view"), incoming_seed)
}

/// Derive the detection root from incoming_seed.
/// Holders of detect_root can derive detection keys only, not viewing keys.
pub fn derive_detect_root(incoming_seed: &F) -> F {
    let view_root = derive_view_root(incoming_seed);
    hash_two(&felt_tag(b"detect"), &view_root)
}

/// Derive per-address ML-KEM viewing keypair from incoming_seed and address index j.
/// Each address gets unique ek_v_j / dk_v_j so that addresses are unlinkable.
pub fn derive_kem_view_seed(incoming_seed: &F, j: u32) -> [u8; 64] {
    let view_seed = derive_view_root(incoming_seed);
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&j.to_le_bytes());
    let h1 = hash_two(&felt_tag(b"mlkem-v"), &view_seed);
    let h2 = hash_two(&h1, &idx);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h2);
    // Second half: hash again with different domain for full 64 bytes
    let h3 = hash_two(&felt_tag(b"mlkem-v2"), &h2);
    out[32..].copy_from_slice(&h3);
    out
}

/// Derive per-address ML-KEM detection keypair from incoming_seed and address index j.
/// Each address gets unique ek_d_j / dk_d_j so that addresses are unlinkable.
pub fn derive_kem_detect_seed(incoming_seed: &F, j: u32) -> [u8; 64] {
    let det_seed = derive_detect_root(incoming_seed);
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&j.to_le_bytes());
    let h1 = hash_two(&felt_tag(b"mlkem-d"), &det_seed);
    let h2 = hash_two(&h1, &idx);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h2);
    let h3 = hash_two(&felt_tag(b"mlkem-d2"), &h2);
    out[32..].copy_from_slice(&h3);
    out
}

/// Derive per-address ML-KEM key pairs (view + detect) from incoming_seed and address index.
pub fn derive_kem_keys(incoming_seed: &F, j: u32) -> (Ek, Dk, Ek, Dk) {
    let sv = derive_kem_view_seed(incoming_seed, j);
    let sd = derive_kem_detect_seed(incoming_seed, j);
    let (ek_v, dk_v) = kem_keygen_from_seed(&sv);
    let (ek_d, dk_d) = kem_keygen_from_seed(&sd);
    (ek_v, dk_v, ek_d, dk_d)
}

/// Derive detection-only ML-KEM keypair from a detection root and address index.
pub fn derive_kem_detect_keys_from_root(detect_root: &F, j: u32) -> (Ek, Dk) {
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&j.to_le_bytes());
    let h1 = hash_two(&felt_tag(b"mlkem-d"), detect_root);
    let h2 = hash_two(&h1, &idx);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h2);
    let h3 = hash_two(&felt_tag(b"mlkem-d2"), &h2);
    out[32..].copy_from_slice(&h3);
    kem_keygen_from_seed(&out)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedNote {
    #[serde(with = "hex_bytes")]
    pub ct_d: Vec<u8>,
    pub tag: u16,
    #[serde(with = "hex_bytes")]
    pub ct_v: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub encrypted_data: Vec<u8>,
}

impl EncryptedNote {
    pub fn validate(&self) -> Result<(), String> {
        if self.ct_d.len() != ML_KEM768_CIPHERTEXT_BYTES {
            return Err(format!(
                "bad ct_d length: got {} bytes, expected {}",
                self.ct_d.len(),
                ML_KEM768_CIPHERTEXT_BYTES
            ));
        }
        if self.ct_v.len() != ML_KEM768_CIPHERTEXT_BYTES {
            return Err(format!(
                "bad ct_v length: got {} bytes, expected {}",
                self.ct_v.len(),
                ML_KEM768_CIPHERTEXT_BYTES
            ));
        }
        if self.nonce.len() != NOTE_AEAD_NONCE_BYTES {
            return Err(format!(
                "bad nonce length: got {} bytes, expected {}",
                self.nonce.len(),
                NOTE_AEAD_NONCE_BYTES
            ));
        }
        if self.encrypted_data.len() != ENCRYPTED_NOTE_BYTES {
            return Err(format!(
                "bad encrypted_data length: got {} bytes, expected {}",
                self.encrypted_data.len(),
                ENCRYPTED_NOTE_BYTES
            ));
        }
        if (self.tag as usize) >= (1 << DETECT_K) {
            return Err(format!(
                "bad detection tag: got {}, expected low {} bits only",
                self.tag, DETECT_K
            ));
        }
        Ok(())
    }
}

pub fn encrypt_note(
    v: u64,
    rseed: &F,
    user_memo: Option<&[u8]>,
    ek_v: &Ek,
    ek_d: &Ek,
) -> EncryptedNote {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (v, rseed, user_memo, ek_v, ek_d);
        unreachable!("encrypt_note is not available on wasm32; use client-provided shield notes");
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let detect_ephemeral: [u8; 32] = rand::rng().random();
        let view_ephemeral: [u8; 32] = rand::rng().random();
        let detect_m = ml_kem::array::Array::from(detect_ephemeral);
        let view_m = ml_kem::array::Array::from(view_ephemeral);
        let (ct_d, ss_d): (ml_kem_768::Ciphertext, _) = ek_d.encapsulate_deterministic(&detect_m);
        let tag_hash = hash(ss_d.as_slice());
        let tag = u16::from_le_bytes([tag_hash[0], tag_hash[1]]) & ((1 << DETECT_K) - 1);

        let mut plaintext = Vec::with_capacity(8 + 32 + MEMO_SIZE);
        plaintext.extend_from_slice(&v.to_le_bytes());
        plaintext.extend_from_slice(rseed);
        let mut memo_padded = vec![0u8; MEMO_SIZE];
        match user_memo {
            Some(m) => {
                let len = m.len().min(MEMO_SIZE);
                memo_padded[..len].copy_from_slice(&m[..len]);
            }
            None => {
                memo_padded[0] = 0xF6;
            }
        }
        plaintext.extend_from_slice(&memo_padded);

        let (ct_v, ss_v): (ml_kem_768::Ciphertext, _) = ek_v.encapsulate_deterministic(&view_m);
        let key = hash(ss_v.as_slice());
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = derive_note_aead_nonce(&key, &plaintext);
        let encrypted_data = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .unwrap();

        EncryptedNote {
            ct_d: ct_d.to_vec(),
            tag,
            ct_v: ct_v.to_vec(),
            nonce: nonce.to_vec(),
            encrypted_data,
        }
    }
}

pub fn encrypt_note_deterministic(
    v: u64,
    rseed: &F,
    user_memo: Option<&[u8]>,
    ek_v: &Ek,
    ek_d: &Ek,
    detect_ephemeral: &[u8; 32],
    view_ephemeral: &[u8; 32],
) -> EncryptedNote {
    let detect_m = ml_kem::array::Array::from(*detect_ephemeral);
    let view_m = ml_kem::array::Array::from(*view_ephemeral);
    let (ct_d, ss_d): (ml_kem_768::Ciphertext, _) = ek_d.encapsulate_deterministic(&detect_m);
    let tag_hash = hash(ss_d.as_slice());
    let tag = u16::from_le_bytes([tag_hash[0], tag_hash[1]]) & ((1 << DETECT_K) - 1);

    let mut plaintext = Vec::with_capacity(8 + 32 + MEMO_SIZE);
    plaintext.extend_from_slice(&v.to_le_bytes());
    plaintext.extend_from_slice(rseed);
    let mut memo_padded = vec![0u8; MEMO_SIZE];
    match user_memo {
        Some(m) => {
            let len = m.len().min(MEMO_SIZE);
            memo_padded[..len].copy_from_slice(&m[..len]);
        }
        None => {
            memo_padded[0] = 0xF6;
        }
    }
    plaintext.extend_from_slice(&memo_padded);

    let (ct_v, ss_v): (ml_kem_768::Ciphertext, _) = ek_v.encapsulate_deterministic(&view_m);
    let key = hash(ss_v.as_slice());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = derive_note_aead_nonce(&key, &plaintext);
    let encrypted_data = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .unwrap();

    EncryptedNote {
        ct_d: ct_d.to_vec(),
        tag,
        ct_v: ct_v.to_vec(),
        nonce: nonce.to_vec(),
        encrypted_data,
    }
}

pub fn detect(enc: &EncryptedNote, dk_d: &Dk) -> bool {
    let Ok(ct) = ml_kem_768::Ciphertext::try_from(enc.ct_d.as_slice()) else {
        return false;
    };
    // For correctly-sized ciphertexts the ml-kem API's decapsulation path is infallible.
    let ss = dk_d.try_decapsulate(&ct).unwrap();
    let tag_hash = hash(ss.as_slice());
    let computed = u16::from_le_bytes([tag_hash[0], tag_hash[1]]) & ((1 << DETECT_K) - 1);
    ct_eq_u16(computed, enc.tag)
}

pub fn decrypt_memo(enc: &EncryptedNote, dk_v: &Dk) -> Option<(u64, F, Vec<u8>)> {
    let ct = ml_kem_768::Ciphertext::try_from(enc.ct_v.as_slice()).ok()?;
    let ss = dk_v.try_decapsulate(&ct).ok()?;
    let key = hash(ss.as_slice());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let pt = cipher
        .decrypt(
            Nonce::from_slice(enc.nonce.as_slice()),
            enc.encrypted_data.as_slice(),
        )
        .ok()?;
    if pt.len() != 8 + 32 + MEMO_SIZE {
        return None;
    }
    let v = u64::from_le_bytes(pt[..8].try_into().unwrap());
    let mut rseed = ZERO;
    rseed.copy_from_slice(&pt[8..40]);
    let user_memo = pt[40..].to_vec();
    Some((v, rseed, user_memo))
}

// ═══════════════════════════════════════════════════════════════════════
// Merkle tree
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub leaves: Vec<F>,
    zero_hashes: Vec<F>,
}

impl MerkleTree {
    pub fn new() -> Self {
        let mut z = vec![ZERO];
        for i in 0..DEPTH {
            z.push(hash_merkle(&z[i], &z[i]));
        }
        Self {
            leaves: vec![],
            zero_hashes: z,
        }
    }

    pub fn from_leaves(leaves: Vec<F>) -> Self {
        let mut tree = Self::new();
        tree.leaves = leaves;
        tree
    }

    pub fn append(&mut self, leaf: F) -> usize {
        let i = self.leaves.len();
        assert!(
            i < (1u64 << DEPTH) as usize,
            "Merkle tree full: 2^{} leaves",
            DEPTH
        );
        self.leaves.push(leaf);
        i
    }

    pub fn root(&self) -> F {
        self.compute_level(0, &self.leaves)
    }

    fn compute_level(&self, depth: usize, level: &[F]) -> F {
        if depth == DEPTH {
            return if level.is_empty() {
                self.zero_hashes[DEPTH]
            } else {
                level[0]
            };
        }
        let mut next = vec![];
        let mut i = 0;
        loop {
            let left = if i < level.len() {
                level[i]
            } else {
                self.zero_hashes[depth]
            };
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                self.zero_hashes[depth]
            };
            next.push(hash_merkle(&left, &right));
            i += 2;
            if i >= level.len() && !next.is_empty() {
                break;
            }
        }
        self.compute_level(depth + 1, &next)
    }

    pub fn auth_path(&self, index: usize) -> (Vec<F>, F) {
        let mut level = self.leaves.clone();
        let mut siblings = vec![];
        let mut idx = index;
        for d in 0..DEPTH {
            let sib_idx = idx ^ 1;
            siblings.push(if sib_idx < level.len() {
                level[sib_idx]
            } else {
                self.zero_hashes[d]
            });
            let mut next = vec![];
            let mut i = 0;
            loop {
                let left = if i < level.len() {
                    level[i]
                } else {
                    self.zero_hashes[d]
                };
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    self.zero_hashes[d]
                };
                next.push(hash_merkle(&left, &right));
                i += 2;
                if i >= level.len() {
                    break;
                }
            }
            level = next;
            idx /= 2;
        }
        (siblings, level[0])
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Note (wallet-side)
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Serialize, Deserialize)]
pub struct Note {
    #[serde(with = "hex_f")]
    pub nk_spend: F,
    #[serde(with = "hex_f")]
    pub nk_tag: F,
    #[serde(with = "hex_f")]
    pub auth_root: F,
    #[serde(with = "hex_f")]
    pub d_j: F,
    pub v: u64,
    #[serde(with = "hex_f")]
    pub rseed: F,
    #[serde(with = "hex_f")]
    pub cm: F,
    pub index: usize,
    pub addr_index: u32, // which address j this note belongs to
}

// ═══════════════════════════════════════════════════════════════════════
// Proof enum
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Proof {
    TrustMeBro,
    Stark {
        /// Hex-encoded zstd-compressed circuit proof bytes.
        #[serde(with = "hex_bytes")]
        proof_bytes: Vec<u8>,
        /// Public outputs (raw felt252 values) — the circuit commits to these.
        #[serde(with = "hex_f_vec")]
        output_preimage: Vec<F>,
        /// Verification metadata as a typed binary blob.
        #[serde(default, with = "hex_bytes_opt")]
        verify_meta: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootloaderTaskOutput<'a> {
    pub program_hash: &'a F,
    pub public_outputs: &'a [F],
}

/// Parse the privacy bootloader output preimage for the common TzEL case:
/// exactly one authenticated Cairo task.
pub fn parse_single_task_output_preimage(
    output_preimage: &[F],
) -> Result<BootloaderTaskOutput<'_>, String> {
    if output_preimage.len() < 3 {
        return Err("output_preimage too short for bootloader prefix".into());
    }

    let n_tasks = felt_to_usize(&output_preimage[0])
        .map_err(|_| "invalid bootloader task count".to_string())?;
    if n_tasks != 1 {
        return Err(format!(
            "expected exactly 1 bootloader task, got {}",
            n_tasks
        ));
    }

    let task_output_size = felt_to_usize(&output_preimage[1])
        .map_err(|_| "invalid bootloader task output size".to_string())?;
    if task_output_size < 2 {
        return Err(format!(
            "bootloader task output too short: {} < 2",
            task_output_size
        ));
    }

    let expected_total_len = 1usize
        .checked_add(task_output_size)
        .ok_or_else(|| "bootloader task output size overflow".to_string())?;
    if output_preimage.len() != expected_total_len {
        return Err(format!(
            "output_preimage length mismatch: {} != {}",
            output_preimage.len(),
            expected_total_len
        ));
    }

    Ok(BootloaderTaskOutput {
        program_hash: &output_preimage[2],
        public_outputs: &output_preimage[3..],
    })
}

/// Validate that the verified bootloader output preimage corresponds to the
/// expected TzEL circuit executable, not just any Cairo task.
pub fn validate_single_task_program_hash<'a>(
    output_preimage: &'a [F],
    expected_program_hash: &F,
) -> Result<&'a [F], String> {
    let parsed = parse_single_task_output_preimage(output_preimage)?;
    if parsed.program_hash != expected_program_hash {
        return Err(format!(
            "unexpected circuit program hash: got {}, expected {}",
            hex::encode(parsed.program_hash),
            hex::encode(expected_program_hash),
        ));
    }
    Ok(parsed.public_outputs)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramHashes {
    #[serde(with = "hex_f")]
    pub shield: F,
    #[serde(with = "hex_f")]
    pub transfer: F,
    #[serde(with = "hex_f")]
    pub unshield: F,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitKind {
    Shield,
    Transfer,
    Unshield,
}

impl CircuitKind {
    pub fn name(self) -> &'static str {
        match self {
            CircuitKind::Shield => "shield",
            CircuitKind::Transfer => "transfer",
            CircuitKind::Unshield => "unshield",
        }
    }

    pub fn executable_filename(self) -> &'static str {
        match self {
            CircuitKind::Shield => "run_shield.executable.json",
            CircuitKind::Transfer => "run_transfer.executable.json",
            CircuitKind::Unshield => "run_unshield.executable.json",
        }
    }

    pub fn expected_program_hash<'a>(self, hashes: &'a ProgramHashes) -> &'a F {
        match self {
            CircuitKind::Shield => &hashes.shield,
            CircuitKind::Transfer => &hashes.transfer,
            CircuitKind::Unshield => &hashes.unshield,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositReq {
    #[serde(alias = "addr")]
    pub recipient: String,
    pub amount: u64,
}

pub type FundReq = DepositReq;

/// Payment address — everything a sender needs to create a note for the recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentAddress {
    #[serde(with = "hex_f")]
    pub d_j: F,
    #[serde(with = "hex_f")]
    pub auth_root: F,
    #[serde(with = "hex_f")]
    pub auth_pub_seed: F,
    #[serde(with = "hex_f")]
    pub nk_tag: F,
    #[serde(with = "hex_bytes")]
    pub ek_v: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ek_d: Vec<u8>,
}

impl PaymentAddress {
    pub fn to_bech32m(&self) -> String {
        let mut payload = Vec::with_capacity(4 * 32 + self.ek_v.len() + self.ek_d.len());
        payload.extend_from_slice(&self.d_j);
        payload.extend_from_slice(&self.auth_root);
        payload.extend_from_slice(&self.auth_pub_seed);
        payload.extend_from_slice(&self.nk_tag);
        payload.extend_from_slice(&self.ek_v);
        payload.extend_from_slice(&self.ek_d);
        let hrp = bech32::Hrp::parse("tzel").expect("valid hrp");
        bech32::encode::<bech32::NoChecksum>(hrp, &payload).expect("bech32 encode")
    }

    pub fn from_bech32m(s: &str) -> Result<Self, String> {
        use bech32::primitives::decode::CheckedHrpstring;
        let checked = CheckedHrpstring::new::<bech32::NoChecksum>(s)
            .map_err(|e| e.to_string())?;
        let hrp = checked.hrp();
        if hrp != bech32::Hrp::parse("tzel").expect("valid hrp") {
            return Err(format!("unexpected hrp: {}", hrp));
        }
        let payload: Vec<u8> = checked.byte_iter().collect();
        let min_len = 4 * 32;
        if payload.len() < min_len {
            return Err(format!("payload too short: {} bytes", payload.len()));
        }
        let mut off = 0;
        let read_f = |buf: &[u8], o: &mut usize| -> Result<F, String> {
            if buf.len() < *o + 32 {
                return Err("payload truncated".into());
            }
            let mut f = [0u8; 32];
            f.copy_from_slice(&buf[*o..*o + 32]);
            *o += 32;
            Ok(f)
        };
        let d_j = read_f(&payload, &mut off)?;
        let auth_root = read_f(&payload, &mut off)?;
        let auth_pub_seed = read_f(&payload, &mut off)?;
        let nk_tag = read_f(&payload, &mut off)?;
        let ek_len = (payload.len() - off) / 2;
        if ek_len * 2 + off != payload.len() {
            return Err("payload length is not symmetric for ek_v/ek_d".into());
        }
        let ek_v = payload[off..off + ek_len].to_vec();
        let ek_d = payload[off + ek_len..].to_vec();
        Ok(PaymentAddress { d_j, auth_root, auth_pub_seed, nk_tag, ek_v, ek_d })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldReq {
    pub sender: String,
    pub v: u64,
    pub address: PaymentAddress,
    pub memo: Option<String>,
    pub proof: Proof,
    /// When using real proofs, the client provides its own commitment and encrypted note.
    /// The ledger uses these instead of generating its own.
    #[serde(default, with = "hex_f")]
    pub client_cm: F,
    #[serde(default)]
    pub client_enc: Option<EncryptedNote>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldResp {
    #[serde(with = "hex_f")]
    pub cm: F,
    pub index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferReq {
    #[serde(with = "hex_f")]
    pub root: F,
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
    #[serde(with = "hex_f")]
    pub cm_1: F,
    #[serde(with = "hex_f")]
    pub cm_2: F,
    pub enc_1: EncryptedNote,
    pub enc_2: EncryptedNote,
    pub proof: Proof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferResp {
    pub index_1: usize,
    pub index_2: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnshieldReq {
    #[serde(with = "hex_f")]
    pub root: F,
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
    pub v_pub: u64,
    pub recipient: String,
    #[serde(with = "hex_f")]
    pub cm_change: F,
    pub enc_change: Option<EncryptedNote>,
    pub proof: Proof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnshieldResp {
    pub change_index: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawReq {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawResp {
    pub withdrawal_index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawalRecord {
    pub recipient: String,
    pub amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteMemo {
    pub index: usize,
    #[serde(with = "hex_f")]
    pub cm: F,
    pub enc: EncryptedNote,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotesFeedResp {
    pub notes: Vec<NoteMemo>,
    pub next_cursor: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeInfoResp {
    #[serde(with = "hex_f")]
    pub root: F,
    pub size: usize,
    pub depth: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePathResp {
    #[serde(with = "hex_f_vec")]
    pub siblings: Vec<F>,
    #[serde(with = "hex_f")]
    pub root: F,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifiersResp {
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceResp {
    pub balances: HashMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigResp {
    #[serde(with = "hex_f")]
    pub auth_domain: F,
}

// ═══════════════════════════════════════════════════════════════════════
// Ledger state
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Serialize, Deserialize)]
pub struct Ledger {
    pub auth_domain: F,
    pub tree: MerkleTree,
    pub nullifiers: HashSet<F>,
    pub balances: HashMap<String, u64>,
    pub valid_roots: HashSet<F>,
    #[serde(default)]
    pub root_history: VecDeque<F>,
    pub memos: Vec<(F, EncryptedNote)>,
    pub withdrawals: Vec<WithdrawalRecord>,
}

pub trait LedgerState {
    fn auth_domain(&self) -> Result<F, String>;
    fn balance(&self, addr: &str) -> Result<u64, String>;
    fn set_balance(&mut self, addr: &str, amount: u64) -> Result<(), String>;
    fn has_valid_root(&self, root: &F) -> Result<bool, String>;
    fn has_nullifier(&self, nf: &F) -> Result<bool, String>;
    fn insert_nullifier(&mut self, nf: F) -> Result<(), String>;
    fn append_note(&mut self, cm: F, enc: EncryptedNote) -> Result<usize, String>;
    fn snapshot_root(&mut self) -> Result<(), String>;
    fn enqueue_withdrawal(&mut self, recipient: &str, amount: u64) -> Result<usize, String>;
}

impl Ledger {
    pub fn new() -> Self {
        Self::with_auth_domain(default_auth_domain())
    }

    pub fn with_auth_domain(auth_domain: F) -> Self {
        let tree = MerkleTree::new();
        let mut roots = HashSet::new();
        let root = tree.root();
        roots.insert(root);
        let mut root_history = VecDeque::new();
        root_history.push_back(root);
        Self {
            auth_domain,
            tree,
            nullifiers: HashSet::new(),
            balances: HashMap::new(),
            valid_roots: roots,
            root_history,
            memos: vec![],
            withdrawals: vec![],
        }
    }

    fn record_valid_root_with_limit(&mut self, root: F, max_valid_roots: usize) {
        if self.valid_roots.contains(&root) {
            if self.root_history.is_empty() {
                self.root_history.push_back(root);
            }
            return;
        }
        self.valid_roots.insert(root);
        self.root_history.push_back(root);
        while self.root_history.len() > max_valid_roots {
            let oldest = self
                .root_history
                .pop_front()
                .expect("root history length checked above");
            self.valid_roots.remove(&oldest);
        }
    }

    fn snapshot_root_local(&mut self) {
        self.record_valid_root_with_limit(self.tree.root(), MAX_VALID_ROOTS);
    }

    fn post_note_local(&mut self, cm: F, enc: EncryptedNote) {
        self.memos.push((cm, enc));
    }

    pub fn deposit(&mut self, recipient: &str, amount: u64) -> Result<(), String> {
        apply_deposit(self, recipient, amount)
    }

    pub fn fund(&mut self, addr: &str, amount: u64) -> Result<(), String> {
        self.deposit(addr, amount)
    }

    pub fn shield(&mut self, req: &ShieldReq) -> Result<ShieldResp, String> {
        apply_shield(self, req)
    }

    pub fn transfer(&mut self, req: &TransferReq) -> Result<TransferResp, String> {
        apply_transfer(self, req)
    }

    pub fn unshield(&mut self, req: &UnshieldReq) -> Result<UnshieldResp, String> {
        apply_unshield(self, req)
    }

    pub fn withdraw(&mut self, req: &WithdrawReq) -> Result<WithdrawResp, String> {
        apply_withdraw(self, req)
    }
}

impl LedgerState for Ledger {
    fn auth_domain(&self) -> Result<F, String> {
        Ok(self.auth_domain)
    }

    fn balance(&self, addr: &str) -> Result<u64, String> {
        Ok(self.balances.get(addr).copied().unwrap_or(0))
    }

    fn set_balance(&mut self, addr: &str, amount: u64) -> Result<(), String> {
        self.balances.insert(addr.to_string(), amount);
        Ok(())
    }

    fn has_valid_root(&self, root: &F) -> Result<bool, String> {
        Ok(self.valid_roots.contains(root))
    }

    fn has_nullifier(&self, nf: &F) -> Result<bool, String> {
        Ok(self.nullifiers.contains(nf))
    }

    fn insert_nullifier(&mut self, nf: F) -> Result<(), String> {
        self.nullifiers.insert(nf);
        Ok(())
    }

    fn append_note(&mut self, cm: F, enc: EncryptedNote) -> Result<usize, String> {
        let index = self.tree.append(cm);
        self.post_note_local(cm, enc);
        Ok(index)
    }

    fn snapshot_root(&mut self) -> Result<(), String> {
        self.snapshot_root_local();
        Ok(())
    }

    fn enqueue_withdrawal(&mut self, recipient: &str, amount: u64) -> Result<usize, String> {
        let index = self.withdrawals.len();
        self.withdrawals.push(WithdrawalRecord {
            recipient: recipient.to_string(),
            amount,
        });
        Ok(index)
    }
}

pub fn apply_deposit<S: LedgerState>(
    state: &mut S,
    recipient: &str,
    amount: u64,
) -> Result<(), String> {
    let next = state
        .balance(recipient)?
        .checked_add(amount)
        .ok_or_else(|| "public balance overflow".to_string())?;
    state.set_balance(recipient, next)
}

pub fn apply_fund<S: LedgerState>(state: &mut S, addr: &str, amount: u64) -> Result<(), String> {
    apply_deposit(state, addr, amount)
}

pub fn apply_shield<S: LedgerState>(state: &mut S, req: &ShieldReq) -> Result<ShieldResp, String> {
    let bal = state.balance(&req.sender)?;
    if bal < req.v {
        return Err("insufficient balance".into());
    }
    if let Some(ref enc) = req.client_enc {
        enc.validate()
            .map_err(|e| format!("invalid client encrypted note: {}", e))?;
    }

    match &req.proof {
        Proof::TrustMeBro => {}
        Proof::Stark {
            proof_bytes: _,
            output_preimage,
            verify_meta: _,
        } => {
            if req.client_cm == ZERO {
                return Err(
                    "Stark proof requires client_cm (cannot use server-generated cm)".into(),
                );
            }
            if req.client_enc.is_none() {
                return Err(
                    "Stark proof requires client_enc (cannot use server-generated note)".into(),
                );
            }
            if output_preimage.len() < 4 {
                return Err("shield output_preimage too short".into());
            }
            let tail_start = output_preimage.len() - 4;
            let tail = &output_preimage[tail_start..];
            if tail[0] != u64_to_felt(req.v) {
                return Err("proof v_pub mismatch".into());
            }
            if tail[1] != req.client_cm {
                return Err("proof cm mismatch".into());
            }
            if tail[2] != hash(req.sender.as_bytes()) {
                return Err("proof sender mismatch".into());
            }
            if let Some(ref enc) = req.client_enc {
                let mh = memo_ct_hash(enc);
                if tail[3] != mh {
                    return Err("proof memo_ct_hash mismatch".into());
                }
            }
        }
    }

    let (cm, enc) = if req.client_cm != ZERO && req.client_enc.is_some() {
        (req.client_cm, req.client_enc.clone().unwrap())
    } else {
        #[cfg(target_arch = "wasm32")]
        {
            return Err(
                "shield on wasm requires client_cm and client_enc (kernel cannot fabricate encrypted notes)".into(),
            );
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let ek_v = ml_kem_768::EncapsulationKey::new(
                req.address
                    .ek_v
                    .as_slice()
                    .try_into()
                    .map_err(|_| "bad ek_v length")?,
            )
            .map_err(|_| "invalid ek_v")?;
            let ek_d = ml_kem_768::EncapsulationKey::new(
                req.address
                    .ek_d
                    .as_slice()
                    .try_into()
                    .map_err(|_| "bad ek_d length")?,
            )
            .map_err(|_| "invalid ek_d")?;
            let rseed = random_felt();
            let rcm = derive_rcm(&rseed);
            let otag = owner_tag(
                &req.address.auth_root,
                &req.address.auth_pub_seed,
                &req.address.nk_tag,
            );
            let cm = commit(&req.address.d_j, req.v, &rcm, &otag);
            let memo_bytes = req.memo.as_ref().map(|s| s.as_bytes());
            (cm, encrypt_note(req.v, &rseed, memo_bytes, &ek_v, &ek_d))
        }
    };

    state.set_balance(&req.sender, bal - req.v)?;
    let index = state.append_note(cm, enc)?;
    state.snapshot_root()?;
    Ok(ShieldResp { cm, index })
}

pub fn apply_transfer<S: LedgerState>(
    state: &mut S,
    req: &TransferReq,
) -> Result<TransferResp, String> {
    let n = req.nullifiers.len();
    if n == 0 || n > 7 {
        return Err("bad nullifier count".into());
    }
    req.enc_1
        .validate()
        .map_err(|e| format!("invalid output note 1: {}", e))?;
    req.enc_2
        .validate()
        .map_err(|e| format!("invalid output note 2: {}", e))?;
    if !state.has_valid_root(&req.root)? {
        return Err("invalid root".into());
    }
    for nf in &req.nullifiers {
        if state.has_nullifier(nf)? {
            return Err(format!("nullifier {} already spent", short(nf)));
        }
    }
    for i in 0..n {
        for j in i + 1..n {
            if req.nullifiers[i] == req.nullifiers[j] {
                return Err("duplicate nullifier".into());
            }
        }
    }

    match &req.proof {
        Proof::TrustMeBro => {}
        Proof::Stark {
            proof_bytes: _,
            output_preimage,
            verify_meta: _,
        } => {
            let expected_tail_len = 2 + n + 4;
            if output_preimage.len() < expected_tail_len {
                return Err(format!(
                    "output_preimage too short: {} < {}",
                    output_preimage.len(),
                    expected_tail_len
                ));
            }
            let tail_start = output_preimage.len() - expected_tail_len;
            let tail = &output_preimage[tail_start..];

            if tail[0] != state.auth_domain()? {
                return Err("proof auth_domain mismatch".into());
            }
            if tail[1] != req.root {
                return Err("proof root mismatch".into());
            }
            for (i, nf) in req.nullifiers.iter().enumerate() {
                if tail[2 + i] != *nf {
                    return Err(format!("proof nullifier {} mismatch", i));
                }
            }
            let cm1_pos = 2 + n;
            if tail[cm1_pos] != req.cm_1 {
                return Err("proof cm_1 mismatch".into());
            }
            if tail[cm1_pos + 1] != req.cm_2 {
                return Err("proof cm_2 mismatch".into());
            }
            let mh_1 = memo_ct_hash(&req.enc_1);
            let mh_2 = memo_ct_hash(&req.enc_2);
            if tail[cm1_pos + 2] != mh_1 {
                return Err("proof memo_ct_hash_1 mismatch — encrypted note tampered".into());
            }
            if tail[cm1_pos + 3] != mh_2 {
                return Err("proof memo_ct_hash_2 mismatch — encrypted note tampered".into());
            }
        }
    }

    let index_1 = state.append_note(req.cm_1, req.enc_1.clone())?;
    let index_2 = state.append_note(req.cm_2, req.enc_2.clone())?;
    for nf in &req.nullifiers {
        state.insert_nullifier(*nf)?;
    }
    state.snapshot_root()?;
    Ok(TransferResp { index_1, index_2 })
}

pub fn apply_unshield<S: LedgerState>(
    state: &mut S,
    req: &UnshieldReq,
) -> Result<UnshieldResp, String> {
    let n = req.nullifiers.len();
    if n == 0 || n > 7 {
        return Err("bad nullifier count".into());
    }
    match (req.cm_change == ZERO, req.enc_change.as_ref()) {
        (true, Some(_)) => {
            return Err("change note data provided with zero cm_change".into());
        }
        (false, Some(enc)) => {
            enc.validate()
                .map_err(|e| format!("invalid change note: {}", e))?;
        }
        _ => {}
    }
    if !state.has_valid_root(&req.root)? {
        return Err("invalid root".into());
    }
    for nf in &req.nullifiers {
        if state.has_nullifier(nf)? {
            return Err(format!("nullifier {} already spent", short(nf)));
        }
    }
    for i in 0..n {
        for j in i + 1..n {
            if req.nullifiers[i] == req.nullifiers[j] {
                return Err("duplicate nullifier".into());
            }
        }
    }

    match &req.proof {
        Proof::TrustMeBro => {}
        Proof::Stark {
            proof_bytes: _,
            output_preimage,
            verify_meta: _,
        } => {
            let expected_tail_len = 2 + n + 4;
            if output_preimage.len() < expected_tail_len {
                return Err("output_preimage too short".into());
            }
            let tail_start = output_preimage.len() - expected_tail_len;
            let tail = &output_preimage[tail_start..];

            if tail[0] != state.auth_domain()? {
                return Err("proof auth_domain mismatch".into());
            }
            if tail[1] != req.root {
                return Err("proof root mismatch".into());
            }
            for (i, nf) in req.nullifiers.iter().enumerate() {
                if tail[2 + i] != *nf {
                    return Err(format!("proof nullifier {} mismatch", i));
                }
            }
            if tail[2 + n] != u64_to_felt(req.v_pub) {
                return Err("proof v_pub mismatch".into());
            }
            if tail[3 + n] != hash(req.recipient.as_bytes()) {
                return Err("proof recipient mismatch".into());
            }
            if tail[4 + n] != req.cm_change {
                return Err("proof cm_change mismatch".into());
            }
            if let Some(ref enc) = req.enc_change {
                let mh = memo_ct_hash(enc);
                if tail[5 + n] != mh {
                    return Err("proof memo_ct_hash_change mismatch".into());
                }
            } else if tail[5 + n] != ZERO {
                return Err("proof memo_ct_hash_change should be 0 when no change".into());
            }
        }
    }

    let next_balance = state
        .balance(&req.recipient)?
        .checked_add(req.v_pub)
        .ok_or_else(|| "public balance overflow".to_string())?;

    let change_index = if req.cm_change != ZERO {
        let enc = req
            .enc_change
            .as_ref()
            .ok_or("change cm without encrypted note")?;
        Some(state.append_note(req.cm_change, enc.clone())?)
    } else {
        None
    };

    for nf in &req.nullifiers {
        state.insert_nullifier(*nf)?;
    }
    state.set_balance(&req.recipient, next_balance)?;
    state.snapshot_root()?;
    Ok(UnshieldResp { change_index })
}

pub fn apply_withdraw<S: LedgerState>(
    state: &mut S,
    req: &WithdrawReq,
) -> Result<WithdrawResp, String> {
    let balance = state.balance(&req.sender)?;
    if balance < req.amount {
        return Err("insufficient balance".into());
    }
    let withdrawal_index = state.enqueue_withdrawal(&req.recipient, req.amount)?;
    state.set_balance(&req.sender, balance - req.amount)?;
    Ok(WithdrawResp { withdrawal_index })
}

// ═══════════════════════════════════════════════════════════════════════
// Tests — cross-implementation verification against Cairo
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::KeyExport;
    use proptest::prelude::*;
    use serde::{Deserialize, Serialize};
    use std::sync::OnceLock;

    fn truncate_felt(mut f: F) -> F {
        f[31] &= 0x07;
        f
    }

    fn u(v: u64) -> F {
        u64_to_felt(v)
    }

    fn recompute_root_from_path(leaf: F, index: usize, siblings: &[F]) -> F {
        let mut current = leaf;
        let mut idx = index;
        for sibling in siblings {
            current = if idx & 1 == 0 {
                hash_merkle(&current, sibling)
            } else {
                hash_merkle(sibling, &current)
            };
            idx >>= 1;
        }
        current
    }

    fn sample_account(seed_byte: u8) -> Account {
        let mut master_sk = ZERO;
        master_sk[0] = seed_byte;
        derive_account(&master_sk)
    }

    #[derive(Deserialize)]
    struct WalletFixture {
        #[serde(with = "hex_f")]
        master_sk: F,
        addresses: Vec<WalletFixtureAddress>,
    }

    #[derive(Deserialize)]
    struct WalletFixtureAddress {
        index: u32,
        #[serde(with = "hex_f")]
        d_j: F,
        #[serde(with = "hex_f")]
        auth_root: F,
        #[serde(with = "hex_f")]
        auth_pub_seed: F,
        #[serde(with = "hex_f")]
        nk_tag: F,
        bds: WalletFixtureBds,
    }

    #[derive(Deserialize)]
    struct WalletFixtureBds {
        #[serde(with = "hex_f_vec")]
        auth_path: Vec<F>,
    }

    #[derive(Clone)]
    struct XmssFixture {
        account: Account,
        address: PaymentAddress,
        dk_v: Dk,
        dk_d: Dk,
        nk_spend: F,
        auth_path: Vec<F>,
    }

    fn xmss_fixture() -> &'static XmssFixture {
        static FIXTURE: OnceLock<XmssFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let fixture: WalletFixture = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../apps/wallet/testdata/base_wallet_bds.json"
            )))
            .expect("wallet BDS fixture should deserialize");
            let addr = fixture
                .addresses
                .first()
                .expect("wallet fixture should contain address 0");
            assert_eq!(addr.index, 0, "wallet fixture should start at address 0");

            let account = derive_account(&fixture.master_sk);
            let derived_d_j = derive_address(&account.incoming_seed, addr.index);
            assert_eq!(derived_d_j, addr.d_j, "fixture d_j drifted");

            let ask_j = derive_ask(&account.ask_base, addr.index);
            let derived_pub_seed = derive_auth_pub_seed(&ask_j);
            assert_eq!(
                derived_pub_seed, addr.auth_pub_seed,
                "fixture auth_pub_seed drifted"
            );

            let nk_spend = derive_nk_spend(&account.nk, &addr.d_j);
            let nk_tag = derive_nk_tag(&nk_spend);
            assert_eq!(nk_tag, addr.nk_tag, "fixture nk_tag drifted");

            let (ek_v, dk_v, ek_d, dk_d) = derive_kem_keys(&account.incoming_seed, addr.index);
            let address = PaymentAddress {
                d_j: addr.d_j,
                auth_root: addr.auth_root,
                auth_pub_seed: addr.auth_pub_seed,
                nk_tag: addr.nk_tag,
                ek_v: ek_v.to_bytes().to_vec(),
                ek_d: ek_d.to_bytes().to_vec(),
            };

            XmssFixture {
                account,
                address,
                dk_v,
                dk_d,
                nk_spend,
                auth_path: addr.bds.auth_path.clone(),
            }
        })
    }

    fn sample_address_bundle(_seed_byte: u8, j: u32) -> (Account, PaymentAddress, Dk, Dk, F) {
        assert_eq!(j, 0, "test helper only supports address index 0");
        let fixture = xmss_fixture();
        (
            fixture.account.clone(),
            fixture.address.clone(),
            fixture.dk_v.clone(),
            fixture.dk_d.clone(),
            fixture.nk_spend,
        )
    }

    fn load_ek(bytes: &[u8]) -> Ek {
        Ek::new(
            bytes
                .try_into()
                .expect("fixed-size encapsulation key bytes"),
        )
        .expect("valid ML-KEM encapsulation key")
    }

    fn deterministic_note(
        addr: &PaymentAddress,
        v: u64,
        rseed: F,
        memo: Option<&[u8]>,
    ) -> (EncryptedNote, F) {
        let ek_v = load_ek(&addr.ek_v);
        let ek_d = load_ek(&addr.ek_d);
        let enc =
            encrypt_note_deterministic(v, &rseed, memo, &ek_v, &ek_d, &[0x11; 32], &[0x22; 32]);
        let rcm = derive_rcm(&rseed);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &addr.nk_tag);
        let cm = commit(&addr.d_j, v, &rcm, &otag);
        (enc, cm)
    }

    fn fake_stark(output_preimage: Vec<F>) -> Proof {
        Proof::Stark {
            proof_bytes: vec![1],
            output_preimage,
            verify_meta: None,
        }
    }

    fn shielded_note_setup(
        seed_byte: u8,
        sender: &str,
        amount: u64,
    ) -> (Ledger, PaymentAddress, F, ShieldResp) {
        let (_acc, addr, _dk_v, _dk_d, nk_spend) = sample_address_bundle(seed_byte, 0);
        let mut ledger = Ledger::new();
        ledger.fund(sender, amount * 2).unwrap();
        let resp = ledger
            .shield(&ShieldReq {
                sender: sender.into(),
                v: amount,
                address: addr.clone(),
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
            })
            .unwrap();
        (ledger, addr, nk_spend, resp)
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct HexSerdeFixture {
        #[serde(with = "hex_f")]
        f: F,
        #[serde(with = "hex_f_vec")]
        fs: Vec<F>,
        #[serde(with = "hex_bytes")]
        bytes: Vec<u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct U64MaxCommitmentFixture {
        #[serde(with = "hex_f")]
        d_j: F,
        #[serde(with = "hex_f")]
        rcm: F,
        #[serde(with = "hex_f")]
        owner_tag: F,
        #[serde(with = "hex_f")]
        value_felt: F,
        #[serde(with = "hex_f")]
        cm: F,
    }

    fn u64_max_commitment_fixture() -> &'static U64MaxCommitmentFixture {
        static FIXTURE: std::sync::OnceLock<U64MaxCommitmentFixture> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../specs/test_vectors/commitment_u64_max_v1.json"
            )))
            .expect("u64 max commitment fixture should parse")
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn prop_u64_felt_roundtrip(v in any::<u64>()) {
            let felt = u64_to_felt(v);
            prop_assert_eq!(felt_to_u64(&felt).unwrap(), v);
            prop_assert_eq!(felt_to_usize(&felt).unwrap(), v as usize);
        }

        #[test]
        fn prop_nullifier_depends_on_position(
            nk_spend in prop::array::uniform32(any::<u8>()),
            cm in prop::array::uniform32(any::<u8>()),
            pos_1 in any::<u64>(),
            pos_2 in any::<u64>(),
        ) {
            prop_assume!(pos_1 != pos_2);
            let nk_spend = truncate_felt(nk_spend);
            let cm = truncate_felt(cm);
            prop_assert_ne!(
                nullifier(&nk_spend, &cm, pos_1),
                nullifier(&nk_spend, &cm, pos_2)
            );
        }

        #[test]
        fn prop_commit_changes_with_rseed(
            d_j in prop::array::uniform32(any::<u8>()),
            otag in prop::array::uniform32(any::<u8>()),
            rseed_1 in prop::array::uniform32(any::<u8>()),
            rseed_2 in prop::array::uniform32(any::<u8>()),
            v in any::<u64>(),
        ) {
            prop_assume!(rseed_1 != rseed_2);
            let d_j = truncate_felt(d_j);
            let otag = truncate_felt(otag);
            let rseed_1 = truncate_felt(rseed_1);
            let rseed_2 = truncate_felt(rseed_2);
            prop_assert_ne!(
                commit(&d_j, v, &derive_rcm(&rseed_1), &otag),
                commit(&d_j, v, &derive_rcm(&rseed_2), &otag)
            );
        }

        #[test]
        fn prop_nullifier_depends_on_nk_spend_and_cm(
            nk_spend_1 in prop::array::uniform32(any::<u8>()),
            nk_spend_2 in prop::array::uniform32(any::<u8>()),
            cm_1 in prop::array::uniform32(any::<u8>()),
            cm_2 in prop::array::uniform32(any::<u8>()),
            pos in any::<u64>(),
        ) {
            let nk_spend_1 = truncate_felt(nk_spend_1);
            let nk_spend_2 = truncate_felt(nk_spend_2);
            let cm_1 = truncate_felt(cm_1);
            let cm_2 = truncate_felt(cm_2);
            prop_assume!(nk_spend_1 != nk_spend_2 || cm_1 != cm_2);
            prop_assert_ne!(
                nullifier(&nk_spend_1, &cm_1, pos),
                nullifier(&nk_spend_2, &cm_2, pos)
            );
        }

        #[test]
        fn prop_merkle_auth_path_reconstructs_root(
            leaves in prop::collection::vec(prop::array::uniform32(any::<u8>()), 1..8),
            raw_idx in any::<usize>(),
        ) {
            let leaves: Vec<F> = leaves.into_iter().map(truncate_felt).collect();
            let tree = MerkleTree::from_leaves(leaves.clone());
            let idx = raw_idx % leaves.len();
            let (siblings, root) = tree.auth_path(idx);
            prop_assert_eq!(recompute_root_from_path(leaves[idx], idx, &siblings), root);
        }
    }

    #[test]
    fn test_hex_serde_helpers_roundtrip() {
        let fixture = HexSerdeFixture {
            f: truncate_felt([0xAB; 32]),
            fs: vec![truncate_felt([0x11; 32]), truncate_felt([0x22; 32])],
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let json = serde_json::to_string(&fixture).unwrap();
        let decoded: HexSerdeFixture = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, fixture);
    }

    #[test]
    fn test_felt_helpers_and_tag_encoding() {
        let mut too_large = ZERO;
        too_large[8] = 1;
        assert!(felt_to_u64(&too_large).is_err());
        assert!(felt_to_usize(&too_large).is_err());

        let tag = felt_tag(b"spend");
        let mut expected = ZERO;
        expected[..16].copy_from_slice(&0x7370656e64u128.to_le_bytes());
        assert_eq!(tag, expected);
    }

    #[test]
    fn test_kem_detect_keys_from_root_match_full_derivation() {
        let acc = sample_account(0x44);
        let (ek_v, dk_v, ek_d_full, dk_d_full) = derive_kem_keys(&acc.incoming_seed, 3);
        let detect_root = derive_detect_root(&acc.incoming_seed);
        let (ek_d_root, dk_d_root) = derive_kem_detect_keys_from_root(&detect_root, 3);

        assert_eq!(ek_d_full.to_bytes(), ek_d_root.to_bytes());

        let rseed = u(42);
        let enc = encrypt_note_deterministic(
            77,
            &rseed,
            Some(b"det-root"),
            &ek_v,
            &ek_d_full,
            &[0x33; 32],
            &[0x44; 32],
        );
        assert!(detect(&enc, &dk_d_full));
        assert!(detect(&enc, &dk_d_root));
        let (value, decrypted_rseed, memo) = decrypt_memo(&enc, &dk_v).unwrap();
        assert_eq!(value, 77);
        assert_eq!(decrypted_rseed, rseed);
        assert_eq!(&memo[..8], b"det-root");
    }

    #[test]
    fn test_encrypted_note_validate_rejects_bad_sizes_and_tag() {
        let (_acc, addr, _dk_v, _dk_d, _nk_spend) = sample_address_bundle(0x31, 0);
        let (enc, _cm) = deterministic_note(&addr, 10, u(3), Some(b"validate"));
        enc.validate().unwrap();

        let mut bad_ct_d = enc.clone();
        bad_ct_d.ct_d.pop();
        assert!(bad_ct_d.validate().unwrap_err().contains("ct_d length"));

        let mut bad_ct_v = enc.clone();
        bad_ct_v.ct_v.pop();
        assert!(bad_ct_v.validate().unwrap_err().contains("ct_v length"));

        let mut bad_payload = enc.clone();
        bad_payload.encrypted_data.pop();
        assert!(bad_payload
            .validate()
            .unwrap_err()
            .contains("encrypted_data length"));

        let mut bad_tag = enc;
        bad_tag.tag = 1 << DETECT_K;
        assert!(bad_tag
            .validate()
            .unwrap_err()
            .contains("bad detection tag"));
    }

    #[test]
    fn test_wots_signature_recovers_authenticated_leaf() {
        let fixture = xmss_fixture();
        let ask_j = derive_ask(&fixture.account.ask_base, 0);
        let pub_seed = derive_auth_pub_seed(&ask_j);
        let key_idx = 0u32;
        let msg_hash = hash(b"bind-this-signature");

        let (sig, pk, digits) = wots_sign(&ask_j, key_idx, &msg_hash);
        let recovered_pk = recover_wots_pk(&msg_hash, &pub_seed, key_idx, &sig);

        assert_eq!(recovered_pk, pk);
        assert_eq!(digits, wots_digits(&msg_hash));

        let leaf = wots_pk_to_leaf(&pub_seed, key_idx, &recovered_pk);
        assert_eq!(leaf, auth_leaf_hash(&ask_j, key_idx));

        let auth_root = fixture.address.auth_root;
        let path = fixture.auth_path.clone();
        let mut current = leaf;
        let mut idx = key_idx;
        for (level, sibling) in path.iter().enumerate() {
            let node_idx = idx / 2;
            current = if idx & 1 == 0 {
                xmss_node_hash(
                    &pub_seed,
                    TAG_XMSS_TREE_U64,
                    0,
                    level as u32,
                    node_idx,
                    &current,
                    sibling,
                )
            } else {
                xmss_node_hash(
                    &pub_seed,
                    TAG_XMSS_TREE_U64,
                    0,
                    level as u32,
                    node_idx,
                    sibling,
                    &current,
                )
            };
            idx /= 2;
        }
        assert_eq!(current, auth_root);
    }

    fn assert_wots_signature_recovers_leaf_at(key_idx: u32) {
        let fixture = xmss_fixture();
        let ask_j = derive_ask(&fixture.account.ask_base, 0);
        let pub_seed = derive_auth_pub_seed(&ask_j);
        let msg_hash = hash(b"high-index-wots-regression");

        let (sig, pk, digits) = wots_sign(&ask_j, key_idx, &msg_hash);
        let recovered_pk = recover_wots_pk(&msg_hash, &pub_seed, key_idx, &sig);

        assert_eq!(recovered_pk, pk);
        assert_eq!(digits, wots_digits(&msg_hash));
        assert_eq!(
            wots_pk_to_leaf(&pub_seed, key_idx, &recovered_pk),
            auth_leaf_hash(&ask_j, key_idx)
        );
    }

    #[test]
    fn test_wots_signature_recovers_authenticated_leaf_at_high_indices() {
        assert_wots_signature_recovers_leaf_at(256);
        assert_wots_signature_recovers_leaf_at(u16::MAX as u32);
    }

    #[test]
    fn test_encrypt_note_roundtrip_recomputes_commitment() {
        let (_acc, addr, dk_v, dk_d, _nk_spend) = sample_address_bundle(0x66, 0);
        let rseed = u(99);
        let (enc, cm) = deterministic_note(&addr, 4242, rseed, Some(b"hello"));

        assert!(detect(&enc, &dk_d));
        let (value, decrypted_rseed, memo) = decrypt_memo(&enc, &dk_v).unwrap();
        assert_eq!(value, 4242);
        assert_eq!(decrypted_rseed, rseed);
        assert_eq!(&memo[..5], b"hello");

        let rcm = derive_rcm(&decrypted_rseed);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &addr.nk_tag);
        let recomputed = commit(&addr.d_j, value, &rcm, &otag);
        assert_eq!(recomputed, cm);
    }

    #[test]
    fn test_u64_max_commitment_fixture_matches_rust_commit_layout() {
        let fixture = u64_max_commitment_fixture();
        assert_eq!(
            fixture.value_felt,
            u64_to_felt(u64::MAX),
            "fixture should encode the canonical low-8-byte u64::MAX layout"
        );
        assert_eq!(
            commit(&fixture.d_j, u64::MAX, &fixture.rcm, &fixture.owner_tag),
            fixture.cm
        );
    }

    #[test]
    fn test_parse_single_task_output_preimage_and_program_hash_validation() {
        let output_preimage = vec![u(1), u(6), u(12345), u(11), u(22), u(33), u(44)];
        let parsed = parse_single_task_output_preimage(&output_preimage).unwrap();
        assert_eq!(parsed.program_hash, &u(12345));
        assert_eq!(parsed.public_outputs, &output_preimage[3..]);
        assert_eq!(
            validate_single_task_program_hash(&output_preimage, &u(12345)).unwrap(),
            &output_preimage[3..]
        );
        assert!(
            validate_single_task_program_hash(&output_preimage, &u(54321))
                .unwrap_err()
                .contains("unexpected circuit program hash")
        );
    }

    fn blake2s_personalized_iv(personal: &[u8; 8]) -> [u32; 8] {
        const RFC_BLAKE2S_IV: [u32; 8] = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
            0x5BE0CD19,
        ];

        let mut param = [0u8; 32];
        param[0] = 32;
        param[2] = 1;
        param[3] = 1;
        param[24..32].copy_from_slice(personal);

        let mut iv = RFC_BLAKE2S_IV;
        for (word_idx, word) in iv.iter_mut().enumerate() {
            let base = word_idx * 4;
            let param_word = u32::from_le_bytes([
                param[base],
                param[base + 1],
                param[base + 2],
                param[base + 3],
            ]);
            *word ^= param_word;
        }
        iv
    }

    #[test]
    fn test_cairo_precomputed_blake2s_ivs_match_parameter_block_derivation() {
        let cases = [
            (
                *b"\0\0\0\0\0\0\0\0",
                [
                    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x1F83D9AB, 0x5BE0CD19,
                ],
            ),
            (
                *b"mrklSP__",
                [
                    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x73E8ABC6, 0x04BF9D4A,
                ],
            ),
            (
                *b"nulfSP__",
                [
                    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x79EFACC5, 0x04BF9D4A,
                ],
            ),
            (
                *b"cmmtSP__",
                [
                    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x6BEEB4C8, 0x04BF9D4A,
                ],
            ),
            (
                *b"nkspSP__",
                [
                    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x6FF0B2C5, 0x04BF9D4A,
                ],
            ),
            (
                *b"nktgSP__",
                [
                    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x78F7B2C5, 0x04BF9D4A,
                ],
            ),
            (
                *b"ownrSP__",
                [
                    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x6DEDAEC4, 0x04BF9D4A,
                ],
            ),
            (
                *b"wotsSP__",
                [
                    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x6CF7B6DC, 0x04BF9D4A,
                ],
            ),
            (
                *b"sighSP__",
                [
                    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x77E4B0D8, 0x04BF9D4A,
                ],
            ),
        ];

        for (personal, expected) in cases {
            assert_eq!(
                blake2s_personalized_iv(&personal),
                expected,
                "{:?}",
                personal
            );
        }
    }

    #[test]
    fn test_transfer_and_unshield_sighash_are_bound_to_public_fields() {
        let auth_domain = u(1);
        let root = u(2);
        let nullifiers = vec![u(3), u(4)];
        let cm_1 = u(5);
        let cm_2 = u(6);
        let mh_1 = u(7);
        let mh_2 = u(8);
        let recipient = u(9);

        let transfer =
            transfer_sighash(&auth_domain, &root, &nullifiers, &cm_1, &cm_2, &mh_1, &mh_2);
        assert_ne!(
            transfer,
            transfer_sighash(&u(10), &root, &nullifiers, &cm_1, &cm_2, &mh_1, &mh_2)
        );
        assert_ne!(
            transfer,
            transfer_sighash(
                &auth_domain,
                &u(20),
                &nullifiers,
                &cm_1,
                &cm_2,
                &mh_1,
                &mh_2
            )
        );
        assert_ne!(
            transfer,
            transfer_sighash(
                &auth_domain,
                &root,
                &[u(3), u(40)],
                &cm_1,
                &cm_2,
                &mh_1,
                &mh_2
            )
        );
        assert_ne!(
            transfer,
            transfer_sighash(
                &auth_domain,
                &root,
                &[u(4), u(3)],
                &cm_1,
                &cm_2,
                &mh_1,
                &mh_2
            )
        );
        assert_ne!(
            transfer,
            transfer_sighash(
                &auth_domain,
                &root,
                &nullifiers,
                &u(50),
                &cm_2,
                &mh_1,
                &mh_2
            )
        );
        assert_ne!(
            transfer,
            transfer_sighash(
                &auth_domain,
                &root,
                &nullifiers,
                &cm_1,
                &u(60),
                &mh_1,
                &mh_2
            )
        );
        assert_ne!(
            transfer,
            transfer_sighash(
                &auth_domain,
                &root,
                &nullifiers,
                &cm_1,
                &cm_2,
                &u(70),
                &mh_2
            )
        );
        assert_ne!(
            transfer,
            transfer_sighash(
                &auth_domain,
                &root,
                &nullifiers,
                &cm_1,
                &cm_2,
                &mh_1,
                &u(80)
            )
        );

        let unshield = unshield_sighash(
            &auth_domain,
            &root,
            &nullifiers,
            12,
            &recipient,
            &cm_1,
            &mh_1,
        );
        assert_ne!(
            unshield,
            unshield_sighash(
                &auth_domain,
                &root,
                &nullifiers,
                13,
                &recipient,
                &cm_1,
                &mh_1
            )
        );
        assert_ne!(
            unshield,
            unshield_sighash(&auth_domain, &root, &nullifiers, 12, &u(10), &cm_1, &mh_1)
        );
        assert_ne!(
            unshield,
            unshield_sighash(
                &auth_domain,
                &u(20),
                &nullifiers,
                12,
                &recipient,
                &cm_1,
                &mh_1
            )
        );
        assert_ne!(
            unshield,
            unshield_sighash(
                &auth_domain,
                &root,
                &[u(4), u(3)],
                12,
                &recipient,
                &cm_1,
                &mh_1
            )
        );
        assert_ne!(
            unshield,
            unshield_sighash(
                &auth_domain,
                &root,
                &nullifiers,
                12,
                &recipient,
                &u(11),
                &mh_1
            )
        );
        assert_ne!(
            unshield,
            unshield_sighash(
                &auth_domain,
                &root,
                &nullifiers,
                12,
                &recipient,
                &cm_1,
                &u(12)
            )
        );
    }

    #[test]
    fn test_apply_shield_stark_path_updates_balance_and_tree() {
        let (_acc, addr, _dk_v, _dk_d, _nk_spend) = sample_address_bundle(0x71, 0);
        let mut ledger = Ledger::new();
        ledger.fund("alice", 200).unwrap();

        let (enc, cm) = deterministic_note(&addr, 125, u(15), Some(b"shield"));
        let memo_hash = memo_ct_hash(&enc);
        let root_before = ledger.tree.root();

        let resp = apply_shield(
            &mut ledger,
            &ShieldReq {
                sender: "alice".into(),
                v: 125,
                address: addr.clone(),
                memo: None,
                proof: fake_stark(vec![u(125), cm, hash(b"alice"), memo_hash]),
                client_cm: cm,
                client_enc: Some(enc.clone()),
            },
        )
        .unwrap();

        assert_eq!(resp.cm, cm);
        assert_eq!(resp.index, 0);
        assert_eq!(ledger.balance("alice").unwrap(), 75);
        assert_eq!(ledger.memos.len(), 1);
        assert_ne!(ledger.tree.root(), root_before);
        assert!(ledger.valid_roots.contains(&ledger.tree.root()));
    }

    #[test]
    fn test_apply_transfer_stark_path_appends_outputs_and_consumes_nullifier() {
        let (mut ledger, addr, nk_spend, shield_resp) = shielded_note_setup(0x72, "alice", 90);
        let root = ledger.tree.root();
        let auth_domain = ledger.auth_domain;
        let nf = nullifier(&nk_spend, &shield_resp.cm, shield_resp.index as u64);
        let (enc_1, cm_1) = deterministic_note(&addr, 40, u(21), Some(b"out-1"));
        let (enc_2, cm_2) = deterministic_note(&addr, 50, u(22), Some(b"out-2"));

        let resp = apply_transfer(
            &mut ledger,
            &TransferReq {
                root,
                nullifiers: vec![nf],
                cm_1,
                cm_2,
                enc_1: enc_1.clone(),
                enc_2: enc_2.clone(),
                proof: fake_stark(vec![
                    auth_domain,
                    root,
                    nf,
                    cm_1,
                    cm_2,
                    memo_ct_hash(&enc_1),
                    memo_ct_hash(&enc_2),
                ]),
            },
        )
        .unwrap();

        assert_eq!(resp.index_1, 1);
        assert_eq!(resp.index_2, 2);
        assert!(ledger.nullifiers.contains(&nf));
        assert_eq!(ledger.memos.len(), 3);
        assert!(ledger.valid_roots.contains(&ledger.tree.root()));
    }

    #[test]
    fn test_apply_transfer_rejects_bad_memo_hash_without_mutation() {
        let (mut ledger, addr, nk_spend, shield_resp) = shielded_note_setup(0x73, "alice", 90);
        let root = ledger.tree.root();
        let auth_domain = ledger.auth_domain;
        let nf = nullifier(&nk_spend, &shield_resp.cm, shield_resp.index as u64);
        let (enc_1, cm_1) = deterministic_note(&addr, 40, u(31), Some(b"out-1"));
        let (enc_2, cm_2) = deterministic_note(&addr, 50, u(32), Some(b"out-2"));

        let memos_before = ledger.memos.len();
        let roots_before = ledger.valid_roots.len();
        let nullifiers_before = ledger.nullifiers.len();
        let leaves_before = ledger.tree.leaves.clone();

        let err = apply_transfer(
            &mut ledger,
            &TransferReq {
                root,
                nullifiers: vec![nf],
                cm_1,
                cm_2,
                enc_1,
                enc_2,
                proof: fake_stark(vec![auth_domain, root, nf, cm_1, cm_2, ZERO, ZERO]),
            },
        )
        .unwrap_err();

        assert!(err.contains("memo_ct_hash_1 mismatch"));
        assert_eq!(ledger.memos.len(), memos_before);
        assert_eq!(ledger.valid_roots.len(), roots_before);
        assert_eq!(ledger.nullifiers.len(), nullifiers_before);
        assert_eq!(ledger.tree.leaves, leaves_before);
    }

    #[test]
    fn test_apply_unshield_stark_path_with_change_updates_balance_and_note() {
        let (mut ledger, addr, nk_spend, shield_resp) = shielded_note_setup(0x74, "alice", 80);
        let root = ledger.tree.root();
        let auth_domain = ledger.auth_domain;
        let nf = nullifier(&nk_spend, &shield_resp.cm, shield_resp.index as u64);
        let (enc_change, cm_change) = deterministic_note(&addr, 30, u(41), Some(b"change"));

        let resp = apply_unshield(
            &mut ledger,
            &UnshieldReq {
                root,
                nullifiers: vec![nf],
                v_pub: 50,
                recipient: "bob".into(),
                cm_change,
                enc_change: Some(enc_change.clone()),
                proof: fake_stark(vec![
                    auth_domain,
                    root,
                    nf,
                    u(50),
                    hash(b"bob"),
                    cm_change,
                    memo_ct_hash(&enc_change),
                ]),
            },
        )
        .unwrap();

        assert_eq!(resp.change_index, Some(1));
        assert_eq!(ledger.balance("bob").unwrap(), 50);
        assert!(ledger.nullifiers.contains(&nf));
        assert_eq!(ledger.memos.len(), 2);
        assert!(ledger.valid_roots.contains(&ledger.tree.root()));
    }

    #[test]
    fn test_apply_unshield_rejects_balance_overflow_without_mutation() {
        let (mut ledger, _addr, nk_spend, shield_resp) = shielded_note_setup(0x75, "alice", 80);
        ledger.set_balance("bob", u64::MAX).unwrap();
        let root = ledger.tree.root();
        let nf = nullifier(&nk_spend, &shield_resp.cm, shield_resp.index as u64);
        let leaves_before = ledger.tree.leaves.clone();
        let memos_before = ledger.memos.len();

        let err = apply_unshield(
            &mut ledger,
            &UnshieldReq {
                root,
                nullifiers: vec![nf],
                v_pub: 1,
                recipient: "bob".into(),
                cm_change: ZERO,
                enc_change: None,
                proof: Proof::TrustMeBro,
            },
        )
        .unwrap_err();

        assert!(err.contains("public balance overflow"));
        assert_eq!(ledger.balance("bob").unwrap(), u64::MAX);
        assert!(!ledger.nullifiers.contains(&nf));
        assert_eq!(ledger.tree.leaves, leaves_before);
        assert_eq!(ledger.memos.len(), memos_before);
    }

    #[test]
    fn test_apply_withdraw_moves_transparent_balance_into_withdrawal_queue() {
        let mut ledger = Ledger::new();
        ledger.deposit("bob", 44).unwrap();

        let resp = apply_withdraw(
            &mut ledger,
            &WithdrawReq {
                sender: "bob".into(),
                recipient: "tz1-target".into(),
                amount: 33,
            },
        )
        .unwrap();

        assert_eq!(resp.withdrawal_index, 0);
        assert_eq!(ledger.balance("bob").unwrap(), 11);
        assert_eq!(
            ledger.withdrawals,
            vec![WithdrawalRecord {
                recipient: "tz1-target".into(),
                amount: 33,
            }]
        );
    }

    #[test]
    fn test_apply_withdraw_rejects_insufficient_balance_without_mutation() {
        let mut ledger = Ledger::new();
        ledger.deposit("bob", 10).unwrap();

        let err = apply_withdraw(
            &mut ledger,
            &WithdrawReq {
                sender: "bob".into(),
                recipient: "tz1-target".into(),
                amount: 11,
            },
        )
        .unwrap_err();

        assert!(err.contains("insufficient balance"));
        assert_eq!(ledger.balance("bob").unwrap(), 10);
        assert!(ledger.withdrawals.is_empty());
    }

    #[test]
    fn test_valid_root_history_prunes_oldest_anchor() {
        let mut ledger = Ledger::new();
        let initial_root = ledger.tree.root();

        ledger.record_valid_root_with_limit(u(101), 3);
        ledger.record_valid_root_with_limit(u(102), 3);
        assert!(ledger.valid_roots.contains(&initial_root));
        ledger.record_valid_root_with_limit(u(103), 3);

        assert!(!ledger.valid_roots.contains(&initial_root));
        assert!(ledger.valid_roots.contains(&u(101)));
        assert!(ledger.valid_roots.contains(&u(102)));
        assert!(ledger.valid_roots.contains(&u(103)));
        assert_eq!(ledger.root_history.len(), 3);
        assert_eq!(ledger.valid_roots.len(), 3);
    }

    #[test]
    fn test_payment_address_bech32m_roundtrip() {
        let seed = [0xab_u8; 32];
        let (ek_v, _dk_v, ek_d, _dk_d) = derive_kem_keys(&seed, 0);
        let addr = PaymentAddress {
            d_j: [0x01; 32],
            auth_root: [0x02; 32],
            auth_pub_seed: [0x03; 32],
            nk_tag: [0x04; 32],
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };
        let encoded = addr.to_bech32m();
        assert!(encoded.starts_with("tzel1"));
        let decoded = PaymentAddress::from_bech32m(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }
}
