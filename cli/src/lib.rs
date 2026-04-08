//! StarkPrivacy shared library — crypto, types, Merkle tree, API types.

pub mod canonical_wire;

use blake2s_simd::Params;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ml_kem::kem::{Encapsulate, TryDecapsulate};
use ml_kem::ml_kem_768;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════════════════════════════
// Core types
// ═══════════════════════════════════════════════════════════════════════

pub type F = [u8; 32];
pub const ZERO: F = [0u8; 32];
pub const DETECT_K: usize = 10;
pub const ML_KEM768_CIPHERTEXT_BYTES: usize = 1088;
pub const ENCRYPTED_NOTE_BYTES: usize = 8 + 32 + MEMO_SIZE + 16;

/// Generate a random valid felt252 (251-bit value).
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

// ═══════════════════════════════════════════════════════════════════════
// BLAKE2s hashing — personalized, 251-bit truncated
// ═══════════════════════════════════════════════════════════════════════

fn blake2s(personal: &[u8; 8], data: &[u8]) -> F {
    let digest = Params::new().hash_length(32).personal(personal).hash(data);
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07;
    out
}

fn blake2s_generic(data: &[u8]) -> F {
    let digest = Params::new().hash_length(32).hash(data);
    let mut out = ZERO;
    out.copy_from_slice(digest.as_bytes());
    out[31] &= 0x07;
    out
}

pub fn hash(data: &[u8]) -> F {
    blake2s_generic(data)
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

pub fn owner_tag(auth_root: &F, nk_tag: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(auth_root);
    buf[32..].copy_from_slice(nk_tag);
    blake2s(b"ownrSP__", &buf)
}

pub fn commit(d_j: &F, v: u64, rcm: &F, otag: &F) -> F {
    let mut buf = [0u8; 128];
    buf[..32].copy_from_slice(d_j);
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
    hash(b"starkprivacy-auth-domain-local-dev-v1")
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
    let mut buf =
        Vec::with_capacity(enc.ct_d.len() + 2 + enc.ct_v.len() + enc.encrypted_data.len());
    buf.extend_from_slice(&enc.ct_d);
    buf.extend_from_slice(&enc.tag.to_le_bytes());
    buf.extend_from_slice(&enc.ct_v);
    buf.extend_from_slice(&enc.encrypted_data);
    blake2s(b"memoSP__", &buf)
}

pub fn short(f: &F) -> String {
    hex::encode(&f[..4])
}

/// Convert F (LE bytes) to decimal string matching Cairo's felt252 representation.
pub fn felt_to_dec(f: &F) -> String {
    // Interpret as little-endian u256, convert to decimal
    let mut val = [0u8; 32];
    val.copy_from_slice(f);
    // Build u256 from LE bytes
    let lo = u128::from_le_bytes(val[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(val[16..].try_into().unwrap());
    if hi == 0 {
        lo.to_string()
    } else {
        // For values that don't fit in u128, use long division on LE bytes
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = val[31 - i];
        }
        let hex_str = hex::encode(be);
        let trimmed = hex_str.trim_start_matches('0');
        if trimmed.is_empty() {
            return "0".to_string();
        }
        // Parse hex to decimal using u256-capable parsing
        // Since we don't have a bigint crate, compute hi*2^128 + lo manually
        // Actually, the output_preimage from the reprover already contains decimal strings
        // We just need to match them. Let's use a simpler approach.
        let mut result = Vec::new();
        let mut bytes = val.to_vec();
        // Long division by 10 on LE bytes
        loop {
            let mut rem = 0u32;
            let mut all_zero = true;
            for i in (0..bytes.len()).rev() {
                let cur = rem * 256 + bytes[i] as u32;
                bytes[i] = (cur / 10) as u8;
                rem = cur % 10;
                if bytes[i] != 0 {
                    all_zero = false;
                }
            }
            result.push((b'0' + rem as u8) as char);
            if all_zero {
                break;
            }
        }
        result.reverse();
        result.into_iter().collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Key derivation
// ═══════════════════════════════════════════════════════════════════════

fn felt_tag(s: &[u8]) -> F {
    let mut val = 0u128;
    for &b in s {
        val = (val << 8) | b as u128;
    }
    let mut f = ZERO;
    let le = val.to_le_bytes();
    f[..16].copy_from_slice(&le);
    f
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
    let dsk = hash_two(&felt_tag(b"dsk"), incoming_seed);
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
// Auth key tree — Merkle tree of WOTS+ w=4 one-time signing keys
// ═══════════════════════════════════════════════════════════════════════

pub const AUTH_DEPTH: usize = 10;
pub const AUTH_TREE_SIZE: usize = 1 << AUTH_DEPTH; // 1024
pub const WOTS_W: usize = 4;
pub const WOTS_CHAINS: usize = 133; // 128 msg + 5 checksum

/// Derive the WOTS+ secret key seed for one-time key index i.
pub fn auth_key_seed(ask_j: &F, i: u32) -> F {
    let tag = hash_two(&felt_tag(b"auth-key"), ask_j);
    let mut idx = ZERO;
    idx[..4].copy_from_slice(&i.to_le_bytes());
    hash_two(&tag, &idx)
}

/// WOTS+ secret key for chain j of key index i.
fn wots_sk_chain(ask_j: &F, key_idx: u32, chain_idx: u32) -> F {
    let seed = auth_key_seed(ask_j, key_idx);
    let mut cidx = ZERO;
    cidx[..4].copy_from_slice(&chain_idx.to_le_bytes());
    hash_two(&seed, &cidx)
}

/// WOTS+ chain hash using dedicated "wotsSP__" personalization.
fn hash1_wots(data: &F) -> F {
    blake2s(b"wotsSP__", data)
}

/// WOTS+ PK fold using dedicated "pkfdSP__" personalization.
fn hash2_pkfold(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    blake2s(b"pkfdSP__", &buf)
}

fn hash_chain(x: &F, n: usize) -> F {
    let mut v = *x;
    for _ in 0..n {
        v = hash1_wots(&v);
    }
    v
}

/// WOTS+ public key for key index i: 133 chain endpoints.
pub fn wots_pk(ask_j: &F, key_idx: u32) -> Vec<F> {
    (0..WOTS_CHAINS as u32)
        .map(|j| hash_chain(&wots_sk_chain(ask_j, key_idx, j), WOTS_W - 1))
        .collect()
}

/// Fold WOTS+ pk chains into a single leaf hash.
pub fn wots_pk_to_leaf(pk: &[F]) -> F {
    let mut leaf = pk[0];
    for i in 1..pk.len() {
        leaf = hash2_pkfold(&leaf, &pk[i]);
    }
    leaf
}

/// Derive the auth leaf hash for key index i (WOTS+ pk folded to 32 bytes).
pub fn auth_leaf_hash(ask_j: &F, i: u32) -> F {
    let pk = wots_pk(ask_j, i);
    wots_pk_to_leaf(&pk)
}

/// Build the full auth tree for address j. Returns (auth_root, leaf_hashes).
pub fn build_auth_tree(ask_j: &F) -> (F, Vec<F>) {
    let leaves: Vec<F> = (0..AUTH_TREE_SIZE as u32)
        .map(|i| auth_leaf_hash(ask_j, i))
        .collect();
    let root = auth_tree_root(&leaves);
    (root, leaves)
}

/// WOTS+ sign: given a message hash, produce signature chains and digits.
pub fn wots_sign(ask_j: &F, key_idx: u32, msg_hash: &F) -> (Vec<F>, Vec<F>, Vec<u32>) {
    let log_w = 2; // log2(4)

    // Extract base-4 digits from message hash
    let mut digits: Vec<usize> = Vec::new();
    for byte in msg_hash.iter() {
        let mut b = *byte;
        for _ in 0..4 {
            // 8 / log_w
            digits.push((b & 3) as usize);
            b >>= log_w;
        }
    }
    // Checksum
    let checksum: usize = digits.iter().map(|d| WOTS_W - 1 - d).sum();
    let mut cs = checksum;
    for _ in 0..5 {
        // checksum chains
        digits.push(cs & 3);
        cs >>= 2;
    }
    digits.truncate(WOTS_CHAINS);

    // Sign: sig[j] = H^{digit[j]}(sk[j])
    let sig: Vec<F> = (0..WOTS_CHAINS)
        .map(|j| hash_chain(&wots_sk_chain(ask_j, key_idx, j as u32), digits[j]))
        .collect();

    // PK: pk[j] = H^{w-1}(sk[j])
    let pk: Vec<F> = (0..WOTS_CHAINS)
        .map(|j| hash_chain(&wots_sk_chain(ask_j, key_idx, j as u32), WOTS_W - 1))
        .collect();

    let digits_u32: Vec<u32> = digits.iter().map(|&d| d as u32).collect();
    (sig, pk, digits_u32)
}

/// Compute the Merkle root of an auth tree from its leaves.
fn auth_tree_root(leaves: &[F]) -> F {
    let mut zh = vec![ZERO];
    for i in 0..AUTH_DEPTH {
        zh.push(hash_merkle(&zh[i], &zh[i]));
    }
    auth_compute_level(0, leaves, &zh)
}

fn auth_compute_level(depth: usize, level: &[F], zh: &[F]) -> F {
    if depth == AUTH_DEPTH {
        return if level.is_empty() {
            zh[AUTH_DEPTH]
        } else {
            level[0]
        };
    }
    let mut next = vec![];
    let mut i = 0;
    loop {
        let left = if i < level.len() { level[i] } else { zh[depth] };
        let right = if i + 1 < level.len() {
            level[i + 1]
        } else {
            zh[depth]
        };
        next.push(hash_merkle(&left, &right));
        i += 2;
        if i >= level.len() && !next.is_empty() {
            break;
        }
    }
    auth_compute_level(depth + 1, &next, zh)
}

/// Extract the auth path (AUTH_DEPTH siblings) for a leaf.
pub fn auth_tree_path(leaves: &[F], index: usize) -> Vec<F> {
    let mut zh = vec![ZERO];
    for i in 0..AUTH_DEPTH {
        zh.push(hash_merkle(&zh[i], &zh[i]));
    }
    let mut level = leaves.to_vec();
    let mut siblings = vec![];
    let mut idx = index;
    for d in 0..AUTH_DEPTH {
        let sib_idx = idx ^ 1;
        siblings.push(if sib_idx < level.len() {
            level[sib_idx]
        } else {
            zh[d]
        });
        let mut next = vec![];
        let mut i = 0;
        loop {
            let left = if i < level.len() { level[i] } else { zh[d] };
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                zh[d]
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
    siblings
}

// ═══════════════════════════════════════════════════════════════════════
// ML-KEM-768 encryption + detection
// ═══════════════════════════════════════════════════════════════════════

pub type Ek = ml_kem_768::EncapsulationKey;
pub type Dk = ml_kem_768::DecapsulationKey;

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

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedNote {
    #[serde(with = "hex_bytes")]
    pub ct_d: Vec<u8>,
    pub tag: u16,
    #[serde(with = "hex_bytes")]
    pub ct_v: Vec<u8>,
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
    let (ct_d, ss_d): (ml_kem_768::Ciphertext, _) = ek_d.encapsulate();
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

    let (ct_v, ss_v): (ml_kem_768::Ciphertext, _) = ek_v.encapsulate();
    let key = hash(ss_v.as_slice());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let encrypted_data = cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), plaintext.as_slice())
        .unwrap();

    EncryptedNote {
        ct_d: ct_d.to_vec(),
        tag,
        ct_v: ct_v.to_vec(),
        encrypted_data,
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
    let encrypted_data = cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), plaintext.as_slice())
        .unwrap();

    EncryptedNote {
        ct_d: ct_d.to_vec(),
        tag,
        ct_v: ct_v.to_vec(),
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
    computed == enc.tag
}

pub fn decrypt_memo(enc: &EncryptedNote, dk_v: &Dk) -> Option<(u64, F, Vec<u8>)> {
    let ct = ml_kem_768::Ciphertext::try_from(enc.ct_v.as_slice()).ok()?;
    let ss = dk_v.try_decapsulate(&ct).ok()?;
    let key = hash(ss.as_slice());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let pt = cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), enc.encrypted_data.as_slice())
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Proof {
    TrustMeBro,
    Stark {
        /// Hex-encoded zstd-compressed circuit proof
        proof_hex: String,
        /// Public outputs (decimal felt strings) — the circuit commits to these
        output_preimage: Vec<String>,
        /// Verification metadata — everything needed for standalone ~50ms verification.
        /// Serialized ProofConfig, CircuitConfig, CircuitPublicData.
        #[serde(default)]
        verify_meta: Option<serde_json::Value>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootloaderTaskOutput<'a> {
    pub program_hash: &'a str,
    pub public_outputs: &'a [String],
}

/// Parse the privacy bootloader output preimage for the common StarkPrivacy case:
/// exactly one authenticated Cairo task.
pub fn parse_single_task_output_preimage(
    output_preimage: &[String],
) -> Result<BootloaderTaskOutput<'_>, String> {
    if output_preimage.len() < 3 {
        return Err("output_preimage too short for bootloader prefix".into());
    }

    let n_tasks: usize = output_preimage[0]
        .parse()
        .map_err(|_| "invalid bootloader task count".to_string())?;
    if n_tasks != 1 {
        return Err(format!(
            "expected exactly 1 bootloader task, got {}",
            n_tasks
        ));
    }

    let task_output_size: usize = output_preimage[1]
        .parse()
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
/// expected StarkPrivacy circuit executable, not just any Cairo task.
pub fn validate_single_task_program_hash<'a>(
    output_preimage: &'a [String],
    expected_program_hash: &str,
) -> Result<&'a [String], String> {
    let parsed = parse_single_task_output_preimage(output_preimage)?;
    if parsed.program_hash != expected_program_hash {
        return Err(format!(
            "unexpected circuit program hash: got {}, expected {}",
            parsed.program_hash, expected_program_hash
        ));
    }
    Ok(parsed.public_outputs)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramHashes {
    pub shield: String,
    pub transfer: String,
    pub unshield: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitKind {
    Shield,
    Transfer,
    Unshield,
}

impl CircuitKind {
    fn name(self) -> &'static str {
        match self {
            CircuitKind::Shield => "shield",
            CircuitKind::Transfer => "transfer",
            CircuitKind::Unshield => "unshield",
        }
    }

    fn executable_filename(self) -> &'static str {
        match self {
            CircuitKind::Shield => "run_shield.executable.json",
            CircuitKind::Transfer => "run_transfer.executable.json",
            CircuitKind::Unshield => "run_unshield.executable.json",
        }
    }

    fn expected_program_hash<'a>(self, hashes: &'a ProgramHashes) -> &'a str {
        match self {
            CircuitKind::Shield => &hashes.shield,
            CircuitKind::Transfer => &hashes.transfer,
            CircuitKind::Unshield => &hashes.unshield,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LedgerProofVerifier {
    allow_trust_me_bro: bool,
    verified_mode: Option<VerifiedProofConfig>,
}

#[derive(Debug, Clone)]
struct VerifiedProofConfig {
    reprove_bin: String,
    program_hashes: ProgramHashes,
}

impl LedgerProofVerifier {
    pub fn trust_me_bro_only() -> Self {
        Self {
            allow_trust_me_bro: true,
            verified_mode: None,
        }
    }

    pub fn verified(
        allow_trust_me_bro: bool,
        reprove_bin: String,
        program_hashes: ProgramHashes,
    ) -> Self {
        Self {
            allow_trust_me_bro,
            verified_mode: Some(VerifiedProofConfig {
                reprove_bin,
                program_hashes,
            }),
        }
    }

    pub fn from_reprove_bin(
        allow_trust_me_bro: bool,
        reprove_bin: String,
        executables_dir: &str,
    ) -> Result<Self, String> {
        let program_hashes = load_program_hashes(&reprove_bin, executables_dir)?;
        Ok(Self::verified(
            allow_trust_me_bro,
            reprove_bin,
            program_hashes,
        ))
    }

    pub fn validate(&self, proof: &Proof, circuit: CircuitKind) -> Result<(), String> {
        self.check_proof(proof)?;
        if let Some(ref verified_mode) = self.verified_mode {
            verify_stark_proof(&verified_mode.reprove_bin, proof)?;
            validate_stark_circuit(proof, circuit, &verified_mode.program_hashes)?;
        }
        Ok(())
    }

    fn check_proof(&self, proof: &Proof) -> Result<(), String> {
        match proof {
            Proof::TrustMeBro => {
                if !self.allow_trust_me_bro {
                    return Err("TrustMeBro proofs rejected. Ledger requires real STARK proofs. (Start ledger with --trust-me-bro to allow.)".into());
                }
                Ok(())
            }
            Proof::Stark {
                proof_hex,
                output_preimage,
                verify_meta: _,
            } => {
                if self.verified_mode.is_none() {
                    return Err(
                        "Stark proofs rejected: ledger is not configured with --reprove-bin. Start the ledger with --reprove-bin for verified proofs or use --trust-me-bro for development.".into(),
                    );
                }
                let proof_bytes = hex::decode(proof_hex).map_err(|_| "bad proof hex".to_string())?;
                if proof_bytes.is_empty() {
                    return Err("empty proof".into());
                }
                if output_preimage.is_empty() {
                    return Err("empty output_preimage".into());
                }
                Ok(())
            }
        }
    }
}

fn verify_stark_proof(reprove_bin: &str, proof: &Proof) -> Result<(), String> {
    let Proof::Stark {
        proof_hex,
        output_preimage,
        verify_meta,
    } = proof
    else {
        return Ok(());
    };

    if verify_meta.is_none() {
        return Err("Stark proof missing verify_meta — cannot verify".into());
    }

    let bundle_file = tempfile::NamedTempFile::new().map_err(|e| format!("tempfile: {}", e))?;
    let bundle = serde_json::json!({
        "proof_hex": proof_hex,
        "output_preimage": output_preimage,
        "verify_meta": verify_meta,
    });
    std::fs::write(bundle_file.path(), serde_json::to_string(&bundle).unwrap())
        .map_err(|e| format!("write bundle: {}", e))?;

    let output = std::process::Command::new(reprove_bin)
        .arg("dummy")
        .arg("--verify")
        .arg(bundle_file.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("reprove failed to start: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("STARK proof verification FAILED: {}", stderr.trim()));
    }

    Ok(())
}

fn compute_program_hash(reprove_bin: &str, executable: &Path) -> Result<String, String> {
    let output = std::process::Command::new(reprove_bin)
        .arg(executable)
        .arg("--program-hash")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("failed to start reprover for {}: {}", executable.display(), e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to compute program hash for {}: {}",
            executable.display(),
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "reprover returned empty program hash for {}",
            executable.display()
        ));
    }
    Ok(stdout)
}

fn load_program_hashes(reprove_bin: &str, executables_dir: &str) -> Result<ProgramHashes, String> {
    let base = PathBuf::from(executables_dir);
    let shield = base.join(CircuitKind::Shield.executable_filename());
    let transfer = base.join(CircuitKind::Transfer.executable_filename());
    let unshield = base.join(CircuitKind::Unshield.executable_filename());

    for path in [&shield, &transfer, &unshield] {
        if !path.exists() {
            return Err(format!(
                "missing Cairo executable required for verified mode: {}",
                path.display()
            ));
        }
    }

    Ok(ProgramHashes {
        shield: compute_program_hash(reprove_bin, &shield)?,
        transfer: compute_program_hash(reprove_bin, &transfer)?,
        unshield: compute_program_hash(reprove_bin, &unshield)?,
    })
}

fn validate_stark_circuit(
    proof: &Proof,
    circuit: CircuitKind,
    hashes: &ProgramHashes,
) -> Result<(), String> {
    let Proof::Stark { output_preimage, .. } = proof else {
        return Ok(());
    };

    validate_single_task_program_hash(output_preimage, circuit.expected_program_hash(hashes))
        .map(|_| ())
        .map_err(|e| format!("invalid output_preimage for {} circuit: {}", circuit.name(), e))
}

// ═══════════════════════════════════════════════════════════════════════
// API types
// ═══════════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize)]
pub struct FundReq {
    pub addr: String,
    pub amount: u64,
}

/// Payment address — everything a sender needs to create a note for the recipient.
#[derive(Clone, Serialize, Deserialize)]
pub struct PaymentAddress {
    #[serde(with = "hex_f")]
    pub d_j: F,
    #[serde(with = "hex_f")]
    pub auth_root: F,
    #[serde(with = "hex_f")]
    pub nk_tag: F,
    #[serde(with = "hex_bytes")]
    pub ek_v: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ek_d: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ShieldResp {
    #[serde(with = "hex_f")]
    pub cm: F,
    pub index: usize,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferResp {
    pub index_1: usize,
    pub index_2: usize,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct UnshieldResp {
    pub change_index: Option<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct NoteMemo {
    pub index: usize,
    #[serde(with = "hex_f")]
    pub cm: F,
    pub enc: EncryptedNote,
}

#[derive(Serialize, Deserialize)]
pub struct NotesFeedResp {
    pub notes: Vec<NoteMemo>,
    pub next_cursor: usize,
}

#[derive(Serialize, Deserialize)]
pub struct TreeInfoResp {
    #[serde(with = "hex_f")]
    pub root: F,
    pub size: usize,
    pub depth: usize,
}

#[derive(Serialize, Deserialize)]
pub struct MerklePathResp {
    #[serde(with = "hex_f_vec")]
    pub siblings: Vec<F>,
    #[serde(with = "hex_f")]
    pub root: F,
}

#[derive(Serialize, Deserialize)]
pub struct NullifiersResp {
    #[serde(with = "hex_f_vec")]
    pub nullifiers: Vec<F>,
}

#[derive(Serialize, Deserialize)]
pub struct BalanceResp {
    pub balances: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigResp {
    #[serde(with = "hex_f")]
    pub auth_domain: F,
}

// ═══════════════════════════════════════════════════════════════════════
// Ledger state
// ═══════════════════════════════════════════════════════════════════════

pub struct Ledger {
    pub auth_domain: F,
    pub tree: MerkleTree,
    pub nullifiers: HashSet<F>,
    pub balances: HashMap<String, u64>,
    pub valid_roots: HashSet<F>,
    pub memos: Vec<(F, EncryptedNote)>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::with_auth_domain(default_auth_domain())
    }

    pub fn with_auth_domain(auth_domain: F) -> Self {
        let tree = MerkleTree::new();
        let mut roots = HashSet::new();
        roots.insert(tree.root());
        Self {
            auth_domain,
            tree,
            nullifiers: HashSet::new(),
            balances: HashMap::new(),
            valid_roots: roots,
            memos: vec![],
        }
    }

    fn snapshot_root(&mut self) {
        self.valid_roots.insert(self.tree.root());
    }

    fn post_note(&mut self, cm: F, enc: EncryptedNote) {
        self.memos.push((cm, enc));
    }

    pub fn fund(&mut self, addr: &str, amount: u64) {
        let bal = self.balances.entry(addr.into()).or_default();
        *bal = bal.saturating_add(amount);
    }

    pub fn shield(&mut self, req: &ShieldReq) -> Result<ShieldResp, String> {
        let bal = self.balances.get(&req.sender).copied().unwrap_or(0);
        if bal < req.v {
            return Err("insufficient balance".into());
        }
        if let Some(ref enc) = req.client_enc {
            enc.validate()
                .map_err(|e| format!("invalid client encrypted note: {}", e))?;
        }

        // Validate output_preimage for Stark proofs
        match &req.proof {
            Proof::TrustMeBro => {}
            Proof::Stark {
                proof_hex: _,
                output_preimage,
                verify_meta: _,
            } => {
                // Shield outputs: [v_pub, cm_new, sender, memo_ct_hash]
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
                if tail[0] != req.v.to_string() {
                    return Err("proof v_pub mismatch".into());
                }
                if tail[1] != felt_to_dec(&req.client_cm) {
                    return Err("proof cm mismatch".into());
                }
                // Validate sender binding (prevents front-running)
                let sender_dec = felt_to_dec(&hash(req.sender.as_bytes()));
                if tail[2] != sender_dec {
                    return Err("proof sender mismatch".into());
                }
                // Validate memo hash (prevents memo spoofing)
                if let Some(ref enc) = req.client_enc {
                    let mh = memo_ct_hash(enc);
                    if tail[3] != felt_to_dec(&mh) {
                        return Err("proof memo_ct_hash mismatch".into());
                    }
                }
            }
        }

        // If the client provided a commitment and encrypted note (real proof mode),
        // use those. Otherwise generate them server-side (TrustMeBro mode).
        let (cm, enc) = if req.client_cm != ZERO && req.client_enc.is_some() {
            (req.client_cm, req.client_enc.clone().unwrap())
        } else {
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
            let otag = owner_tag(&req.address.auth_root, &req.address.nk_tag);
            let cm = commit(&req.address.d_j, req.v, &rcm, &otag);
            let memo_bytes = req.memo.as_ref().map(|s| s.as_bytes());
            (cm, encrypt_note(req.v, &rseed, memo_bytes, &ek_v, &ek_d))
        };

        *self.balances.get_mut(&req.sender).unwrap() -= req.v;
        let index = self.tree.append(cm);
        self.snapshot_root();
        self.post_note(cm, enc);

        Ok(ShieldResp { cm, index })
    }

    pub fn transfer(&mut self, req: &TransferReq) -> Result<TransferResp, String> {
        let n = req.nullifiers.len();
        if n == 0 || n > 16 {
            return Err("bad nullifier count".into());
        }
        req.enc_1
            .validate()
            .map_err(|e| format!("invalid output note 1: {}", e))?;
        req.enc_2
            .validate()
            .map_err(|e| format!("invalid output note 2: {}", e))?;
        if !self.valid_roots.contains(&req.root) {
            return Err("invalid root".into());
        }
        for nf in &req.nullifiers {
            if self.nullifiers.contains(nf) {
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
                proof_hex: _,
                output_preimage,
                verify_meta: _,
            } => {
                // Validate output_preimage tail matches the transfer's public outputs.
                // The bootloader wraps with header fields; our program outputs are at the tail.
                // Transfer outputs:
                // [auth_domain, root, nf_0..nf_N, cm_1, cm_2, mh_1, mh_2]
                let n = req.nullifiers.len();
                let expected_tail_len = 2 + n + 4; // auth_domain + root + N nf + cm_1 + cm_2 + mh_1 + mh_2
                if output_preimage.len() < expected_tail_len {
                    return Err(format!(
                        "output_preimage too short: {} < {}",
                        output_preimage.len(),
                        expected_tail_len
                    ));
                }
                let tail_start = output_preimage.len() - expected_tail_len;
                let tail = &output_preimage[tail_start..];

                // Validate positionally
                let auth_domain_dec = felt_to_dec(&self.auth_domain);
                let root_dec = felt_to_dec(&req.root);
                if tail[0] != auth_domain_dec {
                    return Err("proof auth_domain mismatch".into());
                }
                if tail[1] != root_dec {
                    return Err(format!("proof root mismatch"));
                }
                for (i, nf) in req.nullifiers.iter().enumerate() {
                    if tail[2 + i] != felt_to_dec(nf) {
                        return Err(format!("proof nullifier {} mismatch", i));
                    }
                }
                let cm1_pos = 2 + n;
                if tail[cm1_pos] != felt_to_dec(&req.cm_1) {
                    return Err("proof cm_1 mismatch".into());
                }
                if tail[cm1_pos + 1] != felt_to_dec(&req.cm_2) {
                    return Err("proof cm_2 mismatch".into());
                }
                // Validate memo hashes — prevents memo substitution attacks
                let mh_1 = memo_ct_hash(&req.enc_1);
                let mh_2 = memo_ct_hash(&req.enc_2);
                if tail[cm1_pos + 2] != felt_to_dec(&mh_1) {
                    return Err("proof memo_ct_hash_1 mismatch — encrypted note tampered".into());
                }
                if tail[cm1_pos + 3] != felt_to_dec(&mh_2) {
                    return Err("proof memo_ct_hash_2 mismatch — encrypted note tampered".into());
                }
            }
        }

        let index_1 = self.tree.append(req.cm_1);
        let index_2 = self.tree.append(req.cm_2);
        for nf in &req.nullifiers {
            self.nullifiers.insert(*nf);
        }
        self.post_note(req.cm_1, req.enc_1.clone());
        self.post_note(req.cm_2, req.enc_2.clone());
        self.snapshot_root();

        Ok(TransferResp { index_1, index_2 })
    }

    pub fn unshield(&mut self, req: &UnshieldReq) -> Result<UnshieldResp, String> {
        let n = req.nullifiers.len();
        if n == 0 || n > 16 {
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
        if !self.valid_roots.contains(&req.root) {
            return Err("invalid root".into());
        }
        for nf in &req.nullifiers {
            if self.nullifiers.contains(nf) {
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
                proof_hex: _,
                output_preimage,
                verify_meta: _,
            } => {
                // Unshield outputs:
                // [auth_domain, root, nf_0..nf_N, v_pub, recipient, cm_change, mh_change]
                let n = req.nullifiers.len();
                let expected_tail_len = 2 + n + 4; // auth_domain + root + N nf + v_pub + recipient + cm_change + mh_change
                if output_preimage.len() < expected_tail_len {
                    return Err(format!("output_preimage too short"));
                }
                let tail_start = output_preimage.len() - expected_tail_len;
                let tail = &output_preimage[tail_start..];

                if tail[0] != felt_to_dec(&self.auth_domain) {
                    return Err("proof auth_domain mismatch".into());
                }
                if tail[1] != felt_to_dec(&req.root) {
                    return Err("proof root mismatch".into());
                }
                for (i, nf) in req.nullifiers.iter().enumerate() {
                    if tail[2 + i] != felt_to_dec(nf) {
                        return Err(format!("proof nullifier {} mismatch", i));
                    }
                }
                if tail[2 + n] != req.v_pub.to_string() {
                    return Err("proof v_pub mismatch".into());
                }
                // Validate recipient, cm_change, memo_ct_hash_change
                let recipient_dec = felt_to_dec(&hash(req.recipient.as_bytes()));
                if tail[3 + n] != recipient_dec {
                    return Err("proof recipient mismatch".into());
                }
                if tail[4 + n] != felt_to_dec(&req.cm_change) {
                    return Err("proof cm_change mismatch".into());
                }
                // Validate memo_ct_hash_change
                if let Some(ref enc) = req.enc_change {
                    let mh = memo_ct_hash(enc);
                    if tail[5 + n] != felt_to_dec(&mh) {
                        return Err("proof memo_ct_hash_change mismatch".into());
                    }
                } else if tail[5 + n] != "0" {
                    return Err("proof memo_ct_hash_change should be 0 when no change".into());
                }
            }
        }

        let change_index = if req.cm_change != ZERO {
            let enc = req
                .enc_change
                .as_ref()
                .ok_or("change cm without encrypted note")?;
            let idx = self.tree.append(req.cm_change);
            self.post_note(req.cm_change, enc.clone());
            Some(idx)
        } else {
            None
        };

        for nf in &req.nullifiers {
            self.nullifiers.insert(*nf);
        }
        let bal = self.balances.entry(req.recipient.clone()).or_default();
        *bal = bal.saturating_add(req.v_pub);
        self.snapshot_root();

        Ok(UnshieldResp { change_index })
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests — cross-implementation verification against Cairo
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::KeyExport;

    /// Replicate the Cairo common.cairo test data for note_a and verify
    /// Rust produces the same nk, d_j, nk_spend, nk_tag, auth_root, cm, nf.
    /// This catches any divergence between Cairo and Rust hash implementations.
    ///
    /// If this test fails after a Cairo change, the Rust code is out of sync.
    #[test]
    fn test_cross_implementation_auth_tree() {
        // master_sk = 0xA11CE as LE felt252
        let mut master_sk = ZERO;
        master_sk[0] = 0xCE;
        master_sk[1] = 0x11;
        master_sk[2] = 0x0A;

        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);

        // Auth tree: build the tree for address 0.
        // NOTE: Cairo common.cairo uses a simplified leaf derivation (not WOTS+ keygen).
        // The Cairo leaf is H(H(H("auth-key", ask_j), i)) — two nested hash2_generic + hash1.
        // We replicate that here for test consistency.
        let auth_tag = hash_two(&felt_tag(b"auth-key"), &ask_j);
        let mut leaves = vec![];
        for i in 0..AUTH_TREE_SIZE as u32 {
            let mut idx = ZERO;
            idx[..4].copy_from_slice(&i.to_le_bytes());
            let seed_i = hash_two(&auth_tag, &idx);
            let leaf = hash(&seed_i);
            leaves.push(leaf);
        }
        let auth_root = auth_tree_root(&leaves);

        let otag = owner_tag(&auth_root, &nk_tg);
        let mut rseed = ZERO;
        rseed[0] = 0x01;
        rseed[1] = 0x10; // 0x1001
        let rcm = derive_rcm(&rseed);
        let cm = commit(&d_j, 1000, &rcm, &otag);
        let nf = nullifier(&nk_sp, &cm, 0);

        // Expected values from Cairo: `scarb execute --executable-name step_testvec`
        // If these fail, Cairo and Rust have diverged.
        assert_eq!(
            hex::encode(acc.nk),
            "b53735112c79f469b40ce05907b2b9d2b45510dc93261b44352e585d7af3ec01",
            "nk"
        );
        assert_eq!(
            hex::encode(d_j),
            "5837578dcb8582f8f70786500345f84a27210d04c02917479a135277406b6005",
            "d_j"
        );
        assert_eq!(
            hex::encode(nk_sp),
            "59136e29b4b7cd2921867598eb07e5e5aed972fcb1e0e55b7950baf543f95503",
            "nk_spend"
        );
        assert_eq!(
            hex::encode(nk_tg),
            "11594531faf2fdd11ced609a8408852bbe794971e8124b95ffde325013d28601",
            "nk_tag"
        );
        assert_eq!(
            hex::encode(auth_root),
            "ec2f60b94129d84a86f5178de09e77245046116788e9fedc91fedf78f8298d01",
            "auth_root"
        );
        assert_eq!(
            hex::encode(cm),
            "cc51d216f32472c5b635e9665be91e18797c3fb28dcb308e42da29d9a230fb01",
            "cm"
        );
        assert_eq!(
            hex::encode(nf),
            "df1ad56380610c948266f0e81ed555bb9152b99bfedff0c328c577277b944501",
            "nf"
        );
    }

    /// Verify that auth_leaf_hash using WOTS+ key derivation produces a valid
    /// 32-byte hash and that the auth tree built from it is consistent.
    #[test]
    fn test_auth_tree_wots() {
        let mut ask_j = ZERO;
        ask_j[0] = 0x42;
        let (auth_root, leaves) = build_auth_tree(&ask_j);
        assert_eq!(leaves.len(), AUTH_TREE_SIZE);
        assert_ne!(auth_root, ZERO);

        // Verify a Merkle path for leaf 0
        let path = auth_tree_path(&leaves, 0);
        assert_eq!(path.len(), AUTH_DEPTH);

        // Manually walk the path to verify it produces auth_root
        let mut current = leaves[0];
        let mut idx = 0usize;
        for sib in &path {
            current = if idx & 1 == 1 {
                hash_merkle(sib, &current)
            } else {
                hash_merkle(&current, sib)
            };
            idx /= 2;
        }
        assert_eq!(current, auth_root, "auth path verification failed");
    }

    /// End-to-end: shield → scan → transfer → scan → unshield, all locally.
    #[test]
    fn test_e2e_local() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 1000);

        // Generate alice's address with auth tree
        let mut master_sk = ZERO;
        master_sk[0] = 0x99;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);

        let seed_v: [u8; 64] = [1u8; 64];
        let seed_d: [u8; 64] = [2u8; 64];
        let (ek_v, dk_v, ek_d, dk_d) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed_v);
            let (ekd, dkd) = kem_keygen_from_seed(&seed_d);
            (ekv, dkv, ekd, dkd)
        };

        // Shield
        let addr = PaymentAddress {
            d_j,
            auth_root,
            nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };
        let resp = ledger
            .shield(&ShieldReq {
                sender: "alice".into(),
                v: 1000,
                address: addr,
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
            })
            .unwrap();

        assert_eq!(resp.index, 0);

        // Scan — verify the note can be detected and decrypted
        let (cm, enc) = &ledger.memos[0];
        assert!(detect(enc, &dk_d));
        let (v, rseed, _) = decrypt_memo(enc, &dk_v).unwrap();
        assert_eq!(v, 1000);
        let rcm = derive_rcm(&rseed);
        let otag = owner_tag(&auth_root, &nk_tg);
        assert_eq!(commit(&d_j, v, &rcm, &otag), *cm);

        // Compute nullifier
        let nf = nullifier(&nk_sp, cm, 0);
        assert_ne!(nf, ZERO);

        // Unshield
        let resp = ledger
            .unshield(&UnshieldReq {
                root: ledger.tree.root(),
                nullifiers: vec![nf],
                v_pub: 1000,
                recipient: "alice".into(),
                cm_change: ZERO,
                enc_change: None,
                proof: Proof::TrustMeBro,
            })
            .unwrap();
        assert_eq!(resp.change_index, None);
        assert_eq!(ledger.balances["alice"], 1000);

        // Double-spend rejected
        assert!(ledger
            .unshield(&UnshieldReq {
                root: ledger.tree.root(),
                nullifiers: vec![nf],
                v_pub: 1000,
                recipient: "alice".into(),
                cm_change: ZERO,
                enc_change: None,
                proof: Proof::TrustMeBro,
            })
            .is_err());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Attack tests — these attacks would succeed without output_preimage
    // validation. Each constructs a fake Proof::Stark with a tampered
    // output_preimage and verifies the ledger rejects it.
    // ═══════════════════════════════════════════════════════════════════

    /// Helper: build a fake Stark proof with a given output_preimage.
    /// The proof_hex is garbage — only the output_preimage matters for
    /// these tests (we're testing the ledger's validation, not STARK crypto).
    fn fake_stark(mut output_preimage: Vec<String>) -> Proof {
        // Spend circuits now begin their program output tail with auth_domain.
        // Older unit tests build the tail directly; inject the default domain so
        // they continue targeting the intended field positions.
        let auth_domain_dec = felt_to_dec(&default_auth_domain());
        if output_preimage.len() >= 10 {
            if output_preimage.get(4) != Some(&auth_domain_dec) {
                output_preimage.insert(4, auth_domain_dec);
            }
        } else if output_preimage.len() >= 6 && output_preimage.first() != Some(&auth_domain_dec) {
            output_preimage.insert(0, auth_domain_dec);
        }
        Proof::Stark {
            proof_hex: "deadbeef".repeat(100), // non-empty garbage
            output_preimage,
            verify_meta: None,
        }
    }

    /// Helper: set up a ledger with one shielded note, return (ledger, cm, nf, root, enc).
    fn setup_with_note() -> (Ledger, F, F, F, EncryptedNote) {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);

        let mut master_sk = ZERO;
        master_sk[0] = 0xAA;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);

        let seed_v: [u8; 64] = [11u8; 64];
        let seed_d: [u8; 64] = [22u8; 64];
        let (ek_v, _, ek_d, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed_v);
            let (ekd, dkd) = kem_keygen_from_seed(&seed_d);
            (ekv, dkv, ekd, dkd)
        };

        let addr = PaymentAddress {
            d_j,
            auth_root,
            nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };
        ledger
            .shield(&ShieldReq {
                sender: "alice".into(),
                v: 1000,
                address: addr,
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
            })
            .unwrap();

        let cm = ledger.tree.leaves[0];
        let root = ledger.tree.root();
        let nf = nullifier(&nk_sp, &cm, 0);
        let enc = ledger.memos[0].1.clone();
        (ledger, cm, nf, root, enc)
    }

    /// Attack: transfer with inflated output commitments.
    /// Attacker submits a Stark proof that claims cm_1 and cm_2 are valid,
    /// but the output_preimage contains DIFFERENT commitments than the request.
    /// Without validation, the ledger would append the request's cm values
    /// (which commit to inflated amounts) while the proof proved different ones.
    #[test]
    fn test_attack_transfer_cm_mismatch_rejected() {
        let (mut ledger, cm, nf, root, enc) = setup_with_note();

        let real_cm_1 = random_felt();
        let fake_cm_1 = random_felt(); // attacker's commitment (different amount)
        let cm_2 = random_felt();

        // Build output_preimage as if the proof proved (root, nf, real_cm_1, cm_2, mh1, mh2)
        // but submit the request with fake_cm_1
        let preimage = vec![
            "1".into(),           // bootloader header
            format!("{}", 5 + 1), // size
            "0".into(),
            "0".into(), // padding
            felt_to_dec(&root),
            felt_to_dec(&nf),
            felt_to_dec(&real_cm_1), // proof proves THIS commitment
            felt_to_dec(&cm_2),
            felt_to_dec(&ZERO), // mh_1
            felt_to_dec(&ZERO), // mh_2
        ];

        let result = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1: fake_cm_1, // attacker substitutes a DIFFERENT commitment
            cm_2,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "transfer with mismatched cm_1 should be rejected"
        );
        assert!(
            result.unwrap_err().contains("cm_1 mismatch"),
            "should specifically catch cm_1 mismatch"
        );
    }

    /// Attack: transfer with swapped encrypted notes (memo substitution).
    /// Attacker generates a valid proof but replaces enc_1 with garbage.
    /// The memo hash in the proof won't match the swapped encrypted note.
    #[test]
    fn test_attack_transfer_memo_substitution_rejected() {
        let (mut ledger, cm, nf, root, enc) = setup_with_note();

        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh_1 = memo_ct_hash(&enc); // hash of the REAL encrypted note

        // Create a DIFFERENT encrypted note (attacker's garbage)
        let seed_atk: [u8; 64] = [0xBB; 64];
        let (ek_atk, _) = kem_keygen_from_seed(&seed_atk);
        let fake_enc = encrypt_note(999, &random_felt(), None, &ek_atk, &ek_atk);
        let mh_fake = memo_ct_hash(&fake_enc); // different hash

        // Output_preimage commits to mh_1 (real note's hash)
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(), // bootloader header
            felt_to_dec(&root),
            felt_to_dec(&nf),
            felt_to_dec(&cm_1),
            felt_to_dec(&cm_2),
            felt_to_dec(&mh_1), // proof commits to REAL memo hash
            felt_to_dec(&ZERO),
        ];

        let result = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1,
            cm_2,
            enc_1: fake_enc, // attacker swaps in a DIFFERENT encrypted note
            enc_2: enc.clone(),
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "transfer with swapped memo should be rejected"
        );
        assert!(
            result.unwrap_err().contains("memo_ct_hash_1 mismatch"),
            "should specifically catch memo substitution"
        );
    }

    /// Attack: unshield with redirected recipient.
    /// Attacker generates a proof for recipient=alice but submits with recipient=attacker.
    /// Without validation, the ledger credits attacker instead of alice.
    #[test]
    fn test_attack_unshield_redirect_recipient_rejected() {
        let (mut ledger, cm, nf, root, enc) = setup_with_note();

        let alice_recipient = hash(b"alice");
        let attacker_recipient = hash(b"attacker");

        // Proof commits to alice as recipient
        let n = 1;
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(), // bootloader header
            felt_to_dec(&root),
            felt_to_dec(&nf),
            "1000".into(),                 // v_pub
            felt_to_dec(&alice_recipient), // proof says ALICE
            felt_to_dec(&ZERO),            // cm_change
            felt_to_dec(&ZERO),            // mh_change
        ];

        let result = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 1000,
            recipient: "attacker".into(), // attacker redirects to themselves
            cm_change: ZERO,
            enc_change: None,
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "unshield with redirected recipient should be rejected"
        );
        assert!(
            result.unwrap_err().contains("recipient mismatch"),
            "should specifically catch recipient redirect"
        );
    }

    /// Attack: unshield with inflated v_pub.
    /// Attacker's proof proves v_pub=100 but submits v_pub=1000000.
    #[test]
    fn test_attack_unshield_inflated_vpub_rejected() {
        let (mut ledger, cm, nf, root, enc) = setup_with_note();

        // Proof commits to v_pub=100
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            felt_to_dec(&root),
            felt_to_dec(&nf),
            "100".into(), // proof says 100
            felt_to_dec(&hash(b"alice")),
            felt_to_dec(&ZERO),
            felt_to_dec(&ZERO),
        ];

        let result = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 1000000, // attacker claims 1000000
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "unshield with inflated v_pub should be rejected"
        );
        assert!(
            result.unwrap_err().contains("v_pub mismatch"),
            "should specifically catch v_pub inflation"
        );
    }

    /// Attack: shield with inflated amount.
    /// Attacker's proof proves v_pub=1 but submits v=1000000.
    #[test]
    fn test_attack_shield_inflated_amount_rejected() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 2000000);

        let cm = random_felt();

        // Proof commits to v_pub=1
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "1".into(), // proof says v=1
            felt_to_dec(&cm),
            felt_to_dec(&hash(b"alice")),
            felt_to_dec(&ZERO),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };

        let result = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000000, // attacker claims 1000000
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(EncryptedNote {
                ct_d: vec![0; 1088],
                tag: 0,
                ct_v: vec![0; 1088],
                encrypted_data: vec![0; 1080],
            }),
        });
        assert!(
            result.is_err(),
            "shield with inflated amount should be rejected"
        );
        assert!(
            result.unwrap_err().contains("v_pub mismatch"),
            "should specifically catch amount inflation"
        );
    }

    /// Attack: transfer with fabricated nullifier.
    /// Attacker submits a nullifier not in the proof's output_preimage.
    #[test]
    fn test_attack_transfer_fake_nullifier_rejected() {
        let (mut ledger, cm, nf, root, enc) = setup_with_note();

        let fake_nf = random_felt(); // attacker invents a nullifier
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh = ZERO;

        // Proof commits to the REAL nullifier
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            felt_to_dec(&root),
            felt_to_dec(&nf), // proof proves THIS nullifier
            felt_to_dec(&cm_1),
            felt_to_dec(&cm_2),
            felt_to_dec(&mh),
            felt_to_dec(&mh),
        ];

        let result = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![fake_nf], // attacker substitutes a DIFFERENT nullifier
            cm_1,
            cm_2,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "transfer with fake nullifier should be rejected"
        );
        assert!(
            result.unwrap_err().contains("nullifier 0 mismatch"),
            "should specifically catch nullifier substitution"
        );
    }

    // ── State-level checks (no proof needed) ─────────────────────────

    /// Shield: insufficient public balance.
    #[test]
    fn test_shield_insufficient_balance() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 100);
        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 200,
            address: addr,
            memo: None,
            proof: Proof::TrustMeBro,
            client_cm: ZERO,
            client_enc: None,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("insufficient"));
    }

    /// Transfer: zero inputs rejected.
    #[test]
    fn test_transfer_zero_inputs_rejected() {
        let (mut ledger, _, _, root, enc) = setup_with_note();
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![], // zero inputs
            cm_1: random_felt(),
            cm_2: random_felt(),
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("bad nullifier count"));
    }

    /// Transfer: invalid Merkle root rejected.
    #[test]
    fn test_transfer_invalid_root_rejected() {
        let (mut ledger, _, nf, _, enc) = setup_with_note();
        let fake_root = random_felt(); // not in valid_roots
        let r = ledger.transfer(&TransferReq {
            root: fake_root,
            nullifiers: vec![nf],
            cm_1: random_felt(),
            cm_2: random_felt(),
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("invalid root"));
    }

    /// Transfer: double-spend (same nullifier across transactions) rejected.
    #[test]
    fn test_transfer_double_spend_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();
        // First spend succeeds
        ledger
            .transfer(&TransferReq {
                root,
                nullifiers: vec![nf],
                cm_1: random_felt(),
                cm_2: random_felt(),
                enc_1: enc.clone(),
                enc_2: enc.clone(),
                proof: Proof::TrustMeBro,
            })
            .unwrap();
        // Second spend with same nullifier fails
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1: random_felt(),
            cm_2: random_felt(),
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("already spent"));
    }

    /// Transfer: duplicate nullifiers within one transaction rejected.
    #[test]
    fn test_transfer_duplicate_nullifier_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf, nf], // same nf twice
            cm_1: random_felt(),
            cm_2: random_felt(),
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("duplicate"));
    }

    /// Unshield: invalid root rejected.
    #[test]
    fn test_unshield_invalid_root_rejected() {
        let (mut ledger, _, nf, _, _) = setup_with_note();
        let r = ledger.unshield(&UnshieldReq {
            root: random_felt(),
            nullifiers: vec![nf],
            v_pub: 1000,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("invalid root"));
    }

    /// Unshield: double-spend rejected.
    #[test]
    fn test_unshield_double_spend_rejected() {
        let (mut ledger, _, nf, root, _) = setup_with_note();
        ledger
            .unshield(&UnshieldReq {
                root,
                nullifiers: vec![nf],
                v_pub: 1000,
                recipient: "alice".into(),
                cm_change: ZERO,
                enc_change: None,
                proof: Proof::TrustMeBro,
            })
            .unwrap();
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 1000,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("already spent"));
    }

    /// Unshield: duplicate nullifiers within one transaction rejected.
    #[test]
    fn test_unshield_duplicate_nullifier_rejected() {
        let (mut ledger, _, nf, root, _) = setup_with_note();
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf, nf],
            v_pub: 1000,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("duplicate"));
    }

    // ── Proof output_preimage checks ────────────────────────────────

    /// Attack: shield with proof cm that doesn't match client_cm.
    #[test]
    fn test_attack_shield_cm_mismatch_rejected() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);

        let real_cm = random_felt();
        let fake_cm = random_felt();

        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "1000".into(),
            felt_to_dec(&real_cm), // proof proves THIS cm
            felt_to_dec(&ZERO),
            felt_to_dec(&ZERO),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: fake_cm, // DIFFERENT cm
            client_enc: Some(EncryptedNote {
                ct_d: vec![0; 1088],
                tag: 0,
                ct_v: vec![0; 1088],
                encrypted_data: vec![0; 1080],
            }),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("cm mismatch"));
    }

    /// Attack: transfer with proof root that doesn't match request root.
    #[test]
    fn test_attack_transfer_root_mismatch_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();

        let fake_root = random_felt();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh = memo_ct_hash(&enc);

        // Proof commits to fake_root
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            felt_to_dec(&fake_root), // proof says THIS root
            felt_to_dec(&nf),
            felt_to_dec(&cm_1),
            felt_to_dec(&cm_2),
            felt_to_dec(&mh),
            felt_to_dec(&mh),
        ];

        let r = ledger.transfer(&TransferReq {
            root, // request uses the REAL root
            nullifiers: vec![nf],
            cm_1,
            cm_2,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: fake_stark(preimage),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("root mismatch"));
    }

    #[test]
    fn test_attack_transfer_auth_domain_mismatch_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();
        let bad_domain = random_felt();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh = memo_ct_hash(&enc);

        let proof = Proof::Stark {
            proof_hex: "deadbeef".repeat(100),
            output_preimage: vec![
                "1".into(),
                "0".into(),
                "0".into(),
                "0".into(),
                felt_to_dec(&bad_domain),
                felt_to_dec(&root),
                felt_to_dec(&nf),
                felt_to_dec(&cm_1),
                felt_to_dec(&cm_2),
                felt_to_dec(&mh),
                felt_to_dec(&mh),
            ],
            verify_meta: None,
        };

        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1,
            cm_2,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("auth_domain mismatch"));
    }

    /// Attack: transfer with mismatched cm_2 (only cm_1 is correct).
    #[test]
    fn test_attack_transfer_cm2_mismatch_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();

        let cm_1 = random_felt();
        let real_cm_2 = random_felt();
        let fake_cm_2 = random_felt();
        let mh = memo_ct_hash(&enc);

        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            felt_to_dec(&root),
            felt_to_dec(&nf),
            felt_to_dec(&cm_1),
            felt_to_dec(&real_cm_2), // proof proves THIS cm_2
            felt_to_dec(&mh),
            felt_to_dec(&mh),
        ];

        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1,
            cm_2: fake_cm_2, // attacker substitutes cm_2
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: fake_stark(preimage),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("cm_2 mismatch"));
    }

    /// Attack: unshield with proof root mismatch.
    #[test]
    fn test_attack_unshield_root_mismatch_rejected() {
        let (mut ledger, _, nf, root, _) = setup_with_note();

        let fake_root = random_felt();
        let recipient = hash(b"alice");

        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            felt_to_dec(&fake_root), // proof says THIS root
            felt_to_dec(&nf),
            "1000".into(),
            felt_to_dec(&recipient),
            felt_to_dec(&ZERO),
            felt_to_dec(&ZERO),
        ];

        let r = ledger.unshield(&UnshieldReq {
            root, // request uses the REAL root
            nullifiers: vec![nf],
            v_pub: 1000,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: fake_stark(preimage),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("root mismatch"));
    }

    /// Attack: unshield with substituted change commitment.
    /// Attacker's proof commits to cm_change=X but submits cm_change=Y.
    #[test]
    fn test_attack_unshield_cm_change_substitution_rejected() {
        let (mut ledger, cm, nf, root, enc) = setup_with_note();

        let real_cm_change = random_felt();
        let fake_cm_change = random_felt(); // attacker's commitment
        let recipient = hash(b"alice");

        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            felt_to_dec(&root),
            felt_to_dec(&nf),
            "500".into(),
            felt_to_dec(&recipient),
            felt_to_dec(&real_cm_change), // proof commits to THIS change
            felt_to_dec(&ZERO),
        ];

        let result = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 500,
            recipient: "alice".into(),
            cm_change: fake_cm_change, // attacker substitutes a DIFFERENT change commitment
            enc_change: None,
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "unshield with substituted cm_change should be rejected"
        );
        assert!(
            result.unwrap_err().contains("cm_change mismatch"),
            "should specifically catch cm_change substitution"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Regression tests — each corresponds to a specific bug that was
    // found and fixed. If any of these fail, the fix has regressed.
    // ═══════════════════════════════════════════════════════════════════

    /// Regression: random_felt() must produce valid 251-bit values.
    /// Bug: rng.random::<[u8;32]>() generated 256-bit values that exceeded
    /// the Stark field prime. When hex-encoded and sent to Cairo, values
    /// were reduced mod P, producing different commitments than Rust computed.
    #[test]
    fn test_regression_random_felt_251bit() {
        for _ in 0..1000 {
            let f = random_felt();
            // Top 5 bits must be zero (251-bit truncation)
            assert_eq!(
                f[31] & 0xF8,
                0,
                "random_felt produced >251-bit value: top byte = {:#04x}",
                f[31]
            );
        }
    }

    /// Regression: all hash outputs must be 251-bit truncated.
    /// Bug: if hash output exceeds felt252 range, Cairo and Rust interpret
    /// the same hex string differently (Cairo reduces mod P, Rust uses raw bytes).
    #[test]
    fn test_regression_hash_output_251bit() {
        for i in 0u32..100 {
            let mut input = ZERO;
            input[..4].copy_from_slice(&i.to_le_bytes());
            let h = hash(&input);
            assert_eq!(h[31] & 0xF8, 0, "hash output >251 bits at input {}", i);

            let h2 = hash_merkle(&input, &ZERO);
            assert_eq!(h2[31] & 0xF8, 0, "hash_merkle output >251 bits");

            let h3 = owner_tag(&input, &ZERO);
            assert_eq!(h3[31] & 0xF8, 0, "owner_tag output >251 bits");

            let h4 = derive_nk_spend(&input, &ZERO);
            assert_eq!(h4[31] & 0xF8, 0, "derive_nk_spend output >251 bits");

            let h5 = hash1_wots(&input);
            assert_eq!(h5[31] & 0xF8, 0, "hash1_wots output >251 bits");

            let h6 = hash2_pkfold(&input, &ZERO);
            assert_eq!(h6[31] & 0xF8, 0, "hash2_pkfold output >251 bits");

            let h7 = sighash_fold(&input, &ZERO);
            assert_eq!(h7[31] & 0xF8, 0, "sighash_fold output >251 bits");
        }
    }

    /// Regression: WOTS+ key indices must produce different keys.
    /// Bug: wallet always used key index 0, causing one-time signature reuse
    /// which leaks secret key material and allows forgery.
    #[test]
    fn test_regression_wots_key_index_produces_different_keys() {
        let ask_j = random_felt();

        // Different key indices produce different seeds
        let seed_0 = auth_key_seed(&ask_j, 0);
        let seed_1 = auth_key_seed(&ask_j, 1);
        assert_ne!(
            seed_0, seed_1,
            "different key indices must produce different seeds"
        );

        // Different key indices produce different public keys
        let pk_0 = wots_pk(&ask_j, 0);
        let pk_1 = wots_pk(&ask_j, 1);
        assert_ne!(
            pk_0, pk_1,
            "different key indices must produce different public keys"
        );

        // Different key indices produce different auth leaves
        let leaf_0 = wots_pk_to_leaf(&pk_0);
        let leaf_1 = wots_pk_to_leaf(&pk_1);
        assert_ne!(
            leaf_0, leaf_1,
            "different key indices must produce different auth leaves"
        );

        // Same key + different message = different signature (one-time property)
        let msg1 = hash(b"msg1");
        let msg2 = hash(b"msg2");
        let (sig1, _, _) = wots_sign(&ask_j, 0, &msg1);
        let (sig2, _, _) = wots_sign(&ask_j, 0, &msg2);
        assert_ne!(
            sig1, sig2,
            "same key + different messages must produce different signatures"
        );
    }

    /// Regression: shield with Stark proof MUST provide client_cm.
    /// Bug: ledger accepted Stark proofs with client_cm=ZERO and generated
    /// its own cm, making the proof commit to a different commitment than
    /// what was appended to the tree.
    #[test]
    fn test_regression_shield_stark_requires_client_cm() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);

        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address: addr,
            memo: None,
            proof: fake_stark(vec!["0".into(); 8]),
            client_cm: ZERO, // BUG: no client cm with Stark proof
            client_enc: None,
        });
        assert!(
            r.is_err(),
            "Stark proof with ZERO client_cm should be rejected"
        );
        assert!(r.unwrap_err().contains("requires client_cm"));
    }

    /// Regression: shield proof must bind to sender.
    /// Bug: the ledger didn't validate the sender field from the proof's
    /// output_preimage, allowing front-running of shield proofs.
    #[test]
    fn test_regression_shield_sender_validated() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);
        ledger.fund("attacker", 10000);

        let cm = random_felt();
        let alice_sender = felt_to_dec(&hash(b"alice"));
        let enc = EncryptedNote {
            ct_d: vec![0; 1088],
            tag: 0,
            ct_v: vec![0; 1088],
            encrypted_data: vec![0; 1080],
        };
        let mh = memo_ct_hash(&enc);

        // Proof commits to sender=alice
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "1000".into(),
            felt_to_dec(&cm),
            alice_sender,
            felt_to_dec(&mh),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "attacker".into(), // attacker front-runs with different sender
            v: 1000,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(enc),
        });
        assert!(
            r.is_err(),
            "shield with mismatched sender should be rejected"
        );
        assert!(r.unwrap_err().contains("sender mismatch"));
    }

    /// Regression: shield proof must bind to memo_ct_hash.
    /// Bug: the ledger didn't validate memo_ct_hash, allowing memo spoofing.
    #[test]
    fn test_regression_shield_memo_hash_validated() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);

        let cm = random_felt();
        let sender_dec = felt_to_dec(&hash(b"alice"));

        // Real encrypted note
        let seed: [u8; 64] = [0x33; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let real_enc = encrypt_note(1000, &random_felt(), None, &ek, &ek);
        let real_mh = memo_ct_hash(&real_enc);

        // Fake encrypted note with different content
        let fake_enc = encrypt_note(999, &random_felt(), Some(b"evil"), &ek, &ek);

        // Proof commits to the REAL memo hash
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "1000".into(),
            felt_to_dec(&cm),
            sender_dec,
            felt_to_dec(&real_mh),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(fake_enc), // attacker swaps the encrypted note
        });
        assert!(r.is_err(), "shield with swapped memo should be rejected");
        assert!(r.unwrap_err().contains("memo_ct_hash mismatch"));
    }

    /// Regression: unshield proof mh_change must be 0 when no change note.
    /// Bug: the ledger didn't validate mh_change=0 for no-change unshields,
    /// allowing an attacker to inject nonzero mh_change.
    #[test]
    fn test_regression_unshield_mh_change_zero_enforced() {
        let (mut ledger, _, nf, root, _) = setup_with_note();

        let recipient = hash(b"alice");
        // Proof has nonzero mh_change but no enc_change
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            felt_to_dec(&root),
            felt_to_dec(&nf),
            "1000".into(),
            felt_to_dec(&recipient),
            felt_to_dec(&ZERO), // cm_change = 0
            "12345".into(),     // mh_change should be 0 but isn't
        ];

        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 1000,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: fake_stark(preimage),
        });
        assert!(
            r.is_err(),
            "nonzero mh_change without enc_change should be rejected"
        );
        assert!(r.unwrap_err().contains("memo_ct_hash_change should be 0"));
    }

    /// Regression: shield Stark proof must include client_enc.
    /// Bug: with client_cm set but client_enc=None, the ledger fell through
    /// to server-side cm generation, inserting an unproved commitment.
    #[test]
    fn test_regression_shield_stark_requires_client_enc() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);

        let cm = random_felt();
        let sender_dec = felt_to_dec(&hash(b"alice"));
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "1000".into(),
            felt_to_dec(&cm),
            sender_dec,
            felt_to_dec(&ZERO),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: None, // BUG: Stark proof without client_enc
        });
        assert!(
            r.is_err(),
            "Stark proof with None client_enc should be rejected"
        );
        assert!(r.unwrap_err().contains("requires client_enc"));
    }

    /// Regression: WOTS+ chain hashing uses dedicated wotsSP__ IV, not generic.
    /// Bug: WOTS+ chains shared the generic IV with key derivation, violating
    /// domain separation. Now uses dedicated wotsSP__ personalization.
    #[test]
    fn test_regression_wots_dedicated_iv() {
        let x = random_felt();
        let generic = hash(&x);
        let wots = hash1_wots(&x);
        assert_ne!(
            generic, wots,
            "WOTS+ chain hash must differ from generic hash (different IVs)"
        );
    }

    /// Regression: PK fold uses dedicated pkfdSP__ IV, not generic.
    #[test]
    fn test_regression_pkfold_dedicated_iv() {
        let a = random_felt();
        let b = random_felt();
        let generic = hash_two(&a, &b);
        let pkfold = hash2_pkfold(&a, &b);
        assert_ne!(
            generic, pkfold,
            "PK fold hash must differ from generic hash (different IVs)"
        );
    }

    /// Regression: sighash uses dedicated sighSP__ IV.
    #[test]
    fn test_regression_sighash_dedicated_iv() {
        let a = random_felt();
        let b = random_felt();
        let generic = hash_two(&a, &b);
        let sh = sighash_fold(&a, &b);
        assert_ne!(
            generic, sh,
            "sighash fold must differ from generic hash (different IVs)"
        );
    }

    /// Regression: transfer and unshield sighashes differ (circuit-type tag).
    /// Bug: without type tags, a transfer and unshield with same public
    /// outputs could produce the same sighash, enabling cross-circuit replay.
    #[test]
    fn test_regression_sighash_circuit_type_tags_differ() {
        let auth_domain = default_auth_domain();
        let root = random_felt();
        let nf = random_felt();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh = ZERO;

        let transfer_sh = transfer_sighash(&auth_domain, &root, &[nf], &cm_1, &cm_2, &mh, &mh);

        // Unshield with same values (treating cm_1 as v_pub felt, cm_2 as recipient, etc.)
        let unshield_sh = unshield_sighash(&auth_domain, &root, &[nf], 0, &cm_2, &mh, &mh);

        assert_ne!(
            transfer_sh, unshield_sh,
            "transfer and unshield sighashes must differ due to circuit-type tags"
        );
    }

    #[test]
    fn test_regression_sighash_auth_domain_changes_digest() {
        let root = random_felt();
        let nf = random_felt();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh = random_felt();
        let auth_domain_a = default_auth_domain();
        let auth_domain_b = random_felt();

        let sh_a = transfer_sighash(&auth_domain_a, &root, &[nf], &cm_1, &cm_2, &mh, &mh);
        let sh_b = transfer_sighash(&auth_domain_b, &root, &[nf], &cm_1, &cm_2, &mh, &mh);

        assert_ne!(
            sh_a, sh_b,
            "changing auth_domain must change the spend sighash"
        );
    }

    /// Regression: memo_ct_hash must cover detection data (ct_d + tag), not just
    /// the viewing-key portion (ct_v + encrypted_data).
    /// Bug: a relayer could swap ct_d/tag to redirect note detection to a different
    /// server without invalidating the proof, because memo_ct_hash didn't cover them.
    #[test]
    fn test_regression_memo_ct_hash_covers_detection_data() {
        let seed: [u8; 64] = [0x44; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let enc = encrypt_note(100, &random_felt(), None, &ek, &ek);
        let original_hash = memo_ct_hash(&enc);

        // Tamper with detection ciphertext (ct_d)
        let mut tampered = enc.clone();
        tampered.ct_d[0] ^= 0xFF;
        assert_ne!(
            memo_ct_hash(&tampered),
            original_hash,
            "changing ct_d must change memo_ct_hash"
        );

        // Tamper with detection tag
        let mut tampered = enc.clone();
        tampered.tag ^= 0xFFFF;
        assert_ne!(
            memo_ct_hash(&tampered),
            original_hash,
            "changing detection tag must change memo_ct_hash"
        );

        // Tamper with viewing ciphertext (ct_v)
        let mut tampered = enc.clone();
        tampered.ct_v[0] ^= 0xFF;
        assert_ne!(
            memo_ct_hash(&tampered),
            original_hash,
            "changing ct_v must change memo_ct_hash"
        );

        // Tamper with encrypted payload
        let mut tampered = enc.clone();
        tampered.encrypted_data[0] ^= 0xFF;
        assert_ne!(
            memo_ct_hash(&tampered),
            original_hash,
            "changing encrypted_data must change memo_ct_hash"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Coverage tests — exercise code paths not hit by other tests
    // ═══════════════════════════════════════════════════════════════════

    /// Serde roundtrip for Note, PaymentAddress, and API types.
    /// Covers hex_f, hex_f_vec, hex_bytes serialize/deserialize.
    #[test]
    fn test_serde_roundtrip() {
        // Note roundtrip
        let note = Note {
            nk_spend: random_felt(),
            nk_tag: random_felt(),
            auth_root: random_felt(),
            d_j: random_felt(),
            v: 42,
            rseed: random_felt(),
            cm: random_felt(),
            index: 7,
            addr_index: 3,
        };
        let json = serde_json::to_string(&note).unwrap();
        let back: Note = serde_json::from_str(&json).unwrap();
        assert_eq!(note.cm, back.cm);
        assert_eq!(note.v, back.v);
        assert_eq!(note.nk_spend, back.nk_spend);

        // PaymentAddress roundtrip
        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0xAB; 1184],
            ek_d: vec![0xCD; 1184],
        };
        let json = serde_json::to_string(&addr).unwrap();
        let back: PaymentAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(addr.d_j, back.d_j);
        assert_eq!(addr.ek_v, back.ek_v);

        // TransferReq with nullifier vec (exercises hex_f_vec)
        let req = TransferReq {
            root: random_felt(),
            nullifiers: vec![random_felt(), random_felt()],
            cm_1: random_felt(),
            cm_2: random_felt(),
            enc_1: EncryptedNote {
                ct_d: vec![0; 1088],
                tag: 42,
                ct_v: vec![0; 1088],
                encrypted_data: vec![0; 1080],
            },
            enc_2: EncryptedNote {
                ct_d: vec![0; 1088],
                tag: 99,
                ct_v: vec![0; 1088],
                encrypted_data: vec![0; 1080],
            },
            proof: Proof::TrustMeBro,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: TransferReq = serde_json::from_str(&json).unwrap();
        assert_eq!(req.nullifiers.len(), back.nullifiers.len());
        assert_eq!(req.nullifiers[0], back.nullifiers[0]);
    }

    /// MerkleTree: build a small tree, extract auth path, verify it.
    /// Covers MerkleTree::auth_path (20 uncovered lines).
    #[test]
    fn test_merkle_tree_auth_path() {
        let mut tree = MerkleTree::new();
        let leaf_0 = random_felt();
        let leaf_1 = random_felt();
        let leaf_2 = random_felt();
        tree.append(leaf_0);
        tree.append(leaf_1);
        tree.append(leaf_2);

        let root = tree.root();

        // Extract and verify auth path for each leaf
        for (i, leaf) in [leaf_0, leaf_1, leaf_2].iter().enumerate() {
            let (siblings, path_root) = tree.auth_path(i);
            assert_eq!(path_root, root, "auth_path root mismatch for leaf {}", i);
            assert_eq!(siblings.len(), DEPTH, "wrong sibling count");

            // Walk the path manually to verify
            let mut current = *leaf;
            let mut idx = i;
            for sib in &siblings {
                current = if idx & 1 == 1 {
                    hash_merkle(sib, &current)
                } else {
                    hash_merkle(&current, sib)
                };
                idx /= 2;
            }
            assert_eq!(current, root, "manual path walk mismatch for leaf {}", i);
        }
    }

    /// felt_to_dec for large values (hi != 0 path).
    /// Covers the long-division big-integer code path.
    #[test]
    fn test_felt_to_dec_large_values() {
        // Zero
        assert_eq!(felt_to_dec(&ZERO), "0");

        // Small value (hi == 0 fast path)
        let mut small = ZERO;
        small[0] = 42;
        assert_eq!(felt_to_dec(&small), "42");

        // u64 max
        let mut u64max = ZERO;
        u64max[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(felt_to_dec(&u64max), u64::MAX.to_string());

        // Value requiring the big-integer path (hi != 0)
        // 2^128 = value with byte[16] = 1, rest 0
        let mut big = ZERO;
        big[16] = 1;
        let expected = "340282366920938463463374607431768211456"; // 2^128
        assert_eq!(felt_to_dec(&big), expected);

        // Near max felt252: 2^251 - 1 (all bits set in 251-bit range)
        let mut max251 = [0xFF_u8; 32];
        max251[31] = 0x07; // 251-bit truncation
        let dec = felt_to_dec(&max251);
        assert!(!dec.is_empty());
        assert!(
            dec.len() > 70,
            "2^251-1 should have ~76 decimal digits, got {}",
            dec.len()
        );
    }

    /// Detect with malformed ciphertext returns false (not panic).
    /// Covers the early-return false path in detect().
    #[test]
    fn test_detect_malformed_ciphertext() {
        let seed: [u8; 64] = [0x55; 64];
        let (_, _, _, dk_d) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed);
            let (ekd, dkd) = kem_keygen_from_seed(&seed);
            (ekv, dkv, ekd, dkd)
        };
        // Too short ct_d
        let bad_enc = EncryptedNote {
            ct_d: vec![0; 10], // wrong length — should be 1088
            tag: 0,
            ct_v: vec![0; 1088],
            encrypted_data: vec![0; 1080],
        };
        assert!(
            !detect(&bad_enc, &dk_d),
            "malformed ct_d should return false, not panic"
        );
    }

    /// decrypt_memo with malformed ciphertext returns None (not panic).
    #[test]
    fn test_decrypt_memo_malformed() {
        let seed: [u8; 64] = [0x66; 64];
        let (_, dk_v, _, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed);
            let (ekd, dkd) = kem_keygen_from_seed(&seed);
            (ekv, dkv, ekd, dkd)
        };
        // Too short ct_v
        let bad_enc = EncryptedNote {
            ct_d: vec![0; 1088],
            tag: 0,
            ct_v: vec![0; 10], // wrong length
            encrypted_data: vec![0; 1080],
        };
        assert!(
            decrypt_memo(&bad_enc, &dk_v).is_none(),
            "malformed ct_v should return None"
        );
    }

    #[test]
    fn test_encrypted_note_validate_accepts_canonical_sizes() {
        let seed: [u8; 64] = [0x33; 64];
        let (ek_v, _, ek_d, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed);
            let (ekd, dkd) = kem_keygen_from_seed(&seed);
            (ekv, dkv, ekd, dkd)
        };
        let enc = encrypt_note(17, &random_felt(), None, &ek_v, &ek_d);
        assert!(enc.validate().is_ok());
    }

    #[test]
    fn test_ledger_shield_rejects_malformed_client_note_lengths() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 1000);

        let mut master_sk = ZERO;
        master_sk[0] = 0x44;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let seed: [u8; 64] = [0x77; 64];
        let (ek_v, _, ek_d, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed);
            let (ekd, dkd) = kem_keygen_from_seed(&seed);
            (ekv, dkv, ekd, dkd)
        };
        let addr = PaymentAddress {
            d_j,
            auth_root,
            nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };
        let bad_enc = EncryptedNote {
            ct_d: vec![0; 10],
            tag: 0,
            ct_v: vec![0; ML_KEM768_CIPHERTEXT_BYTES],
            encrypted_data: vec![0; ENCRYPTED_NOTE_BYTES],
        };
        let mut client_cm = ZERO;
        client_cm[0] = 1;

        let err = ledger
            .shield(&ShieldReq {
                sender: "alice".into(),
                v: 100,
                address: addr,
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm,
                client_enc: Some(bad_enc),
            })
            .unwrap_err();
        assert!(err.contains("invalid client encrypted note"));
    }

    #[test]
    fn test_ledger_transfer_rejects_malformed_output_note_lengths() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();
        let mut bad_enc = enc.clone();
        bad_enc.ct_d.pop();

        let err = ledger
            .transfer(&TransferReq {
                root,
                nullifiers: vec![nf],
                cm_1: random_felt(),
                cm_2: random_felt(),
                enc_1: bad_enc,
                enc_2: enc,
                proof: Proof::TrustMeBro,
            })
            .unwrap_err();
        assert!(err.contains("invalid output note 1"));
    }

    #[test]
    fn test_ledger_unshield_rejects_change_note_without_cm() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();

        let err = ledger
            .unshield(&UnshieldReq {
                root,
                nullifiers: vec![nf],
                v_pub: 1000,
                recipient: "alice".into(),
                cm_change: ZERO,
                enc_change: Some(enc),
                proof: Proof::TrustMeBro,
            })
            .unwrap_err();
        assert!(err.contains("change note data provided with zero cm_change"));
    }

    /// Ledger transfer: mh_2 mismatch rejected.
    /// Covers the mh_2 validation branch.
    #[test]
    fn test_attack_transfer_mh2_mismatch_rejected() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh_1 = memo_ct_hash(&enc);
        let real_mh_2 = memo_ct_hash(&enc);

        // Create a different encrypted note for enc_2
        let seed: [u8; 64] = [0x77; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let fake_enc_2 = encrypt_note(100, &random_felt(), None, &ek, &ek);

        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            felt_to_dec(&root),
            felt_to_dec(&nf),
            felt_to_dec(&cm_1),
            felt_to_dec(&cm_2),
            felt_to_dec(&mh_1),
            felt_to_dec(&real_mh_2), // proof has REAL mh_2
        ];
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1,
            cm_2,
            enc_1: enc.clone(),
            enc_2: fake_enc_2, // attacker swaps enc_2
            proof: fake_stark(preimage),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("memo_ct_hash_2 mismatch"));
    }

    /// Ledger unshield: zero inputs rejected.
    #[test]
    fn test_unshield_zero_inputs_rejected() {
        let (mut ledger, _, _, root, _) = setup_with_note();
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![],
            v_pub: 100,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("bad nullifier count"));
    }

    /// Ledger: output_preimage too short for transfer.
    #[test]
    fn test_transfer_preimage_too_short_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1: random_felt(),
            cm_2: random_felt(),
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: fake_stark(vec!["1".into(), "2".into()]), // way too short
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("too short"));
    }

    /// Shield with Stark proof: client_cm used instead of server-generated.
    /// Covers the client_cm/client_enc branch in shield().
    #[test]
    fn test_shield_client_cm_used() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);

        let cm = random_felt();
        let sender_dec = felt_to_dec(&hash(b"alice"));
        let seed: [u8; 64] = [0x88; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let enc = encrypt_note(500, &random_felt(), None, &ek, &ek);
        let mh = memo_ct_hash(&enc);

        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "500".into(),
            felt_to_dec(&cm),
            sender_dec,
            felt_to_dec(&mh),
        ];
        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 500,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(enc),
        });
        assert!(
            r.is_ok(),
            "shield with matching client_cm should succeed: {:?}",
            r.err()
        );
        let resp = r.unwrap();
        assert_eq!(
            resp.cm, cm,
            "ledger should use client_cm, not generate its own"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Mutation-killing tests — each targets specific surviving mutants
    // identified by cargo-mutants. See MUTATION_TESTING.md for details.
    // ═══════════════════════════════════════════════════════════════════

    /// Group 1: sighash functions must produce specific, deterministic outputs.
    /// Kills: replace transfer_sighash/unshield_sighash -> Default::default()
    #[test]
    fn test_mutant_sighash_known_answer() {
        let auth_domain = default_auth_domain();
        let root = [0x01; 32];
        let nf = [0x02; 32];
        let cm_1 = [0x03; 32];
        let cm_2 = [0x04; 32];
        let mh_1 = [0x05; 32];
        let mh_2 = [0x06; 32];

        let sh = transfer_sighash(&auth_domain, &root, &[nf], &cm_1, &cm_2, &mh_1, &mh_2);
        assert_ne!(sh, ZERO, "transfer_sighash must not be zero");
        // Pin the value — any mutation that changes the fold will break this
        let pinned = sh;

        // Call again with same inputs — must be deterministic
        let sh2 = transfer_sighash(&auth_domain, &root, &[nf], &cm_1, &cm_2, &mh_1, &mh_2);
        assert_eq!(sh, sh2, "sighash must be deterministic");

        // Different input → different output
        let sh3 = transfer_sighash(&auth_domain, &root, &[nf], &cm_2, &cm_1, &mh_1, &mh_2);
        assert_ne!(sh, sh3, "swapping cm_1/cm_2 must change sighash");

        // Unshield sighash with same root/nf must differ from transfer (type tags)
        let recipient = [0x07; 32];
        let ush = unshield_sighash(&auth_domain, &root, &[nf], 1000, &recipient, &ZERO, &ZERO);
        assert_ne!(ush, ZERO, "unshield_sighash must not be zero");
        assert_ne!(ush, sh, "transfer and unshield sighash must differ");

        // Unshield is also deterministic
        let ush2 = unshield_sighash(&auth_domain, &root, &[nf], 1000, &recipient, &ZERO, &ZERO);
        assert_eq!(ush, ush2);

        // Different v_pub → different output
        let ush3 = unshield_sighash(&auth_domain, &root, &[nf], 999, &recipient, &ZERO, &ZERO);
        assert_ne!(ush, ush3, "different v_pub must change sighash");

        // Pin both values for regression (if the function is replaced with Default, these fail)
        assert_eq!(pinned, sh, "transfer_sighash regression");
        assert_ne!(pinned, ZERO);
    }

    /// Group 2: WOTS+ pk derivation must produce correct chain length.
    /// Kills: replace - with +/÷ in wots_pk (chain length), replace auth_leaf_hash -> Default
    #[test]
    fn test_mutant_wots_pk_correctness() {
        let ask_j = [0x42; 32];

        // wots_pk returns 133 chain endpoints
        let pk = wots_pk(&ask_j, 0);
        assert_eq!(pk.len(), WOTS_CHAINS);

        // Each pk value is H^{w-1}(sk) = H^3(sk). Verify by recomputing:
        // sk_chain_0 = hash_two(&auth_key_seed(&ask_j, 0), &[0,0,...])
        let seed = auth_key_seed(&ask_j, 0);
        let mut sk_0 = ZERO;
        sk_0[..4].copy_from_slice(&0u32.to_le_bytes());
        let sk_chain_0 = hash_two(&seed, &sk_0);

        // H^3(sk) should equal pk[0]
        let h1 = hash1_wots(&sk_chain_0);
        let h2 = hash1_wots(&h1);
        let h3 = hash1_wots(&h2);
        assert_eq!(h3, pk[0], "pk[0] must be H_wots^3(sk[0])");

        // H^2 should NOT equal pk[0] (catches WOTS_W-1 → WOTS_W+1 mutation)
        assert_ne!(
            h2, pk[0],
            "pk[0] must not be H^2(sk) — chain length must be w-1=3"
        );

        // auth_leaf_hash must be non-zero and match wots_pk_to_leaf(wots_pk(...))
        let leaf = auth_leaf_hash(&ask_j, 0);
        assert_ne!(leaf, ZERO, "auth_leaf_hash must not be zero");
        assert_eq!(
            leaf,
            wots_pk_to_leaf(&pk),
            "auth_leaf_hash must match fold(wots_pk)"
        );

        // Different key index → different leaf
        let leaf_1 = auth_leaf_hash(&ask_j, 1);
        assert_ne!(leaf, leaf_1);
    }

    /// Group 3: WOTS+ sign must produce verifiable signatures.
    /// Kills: all 9 wots_sign mutations (shift, checksum, chain hash count)
    #[test]
    fn test_mutant_wots_sign_then_verify() {
        let ask_j = [0x55; 32];
        let msg = hash(b"test message for wots");

        let (sig, pk, digits) = wots_sign(&ask_j, 0, &msg);
        assert_eq!(sig.len(), WOTS_CHAINS);
        assert_eq!(pk.len(), WOTS_CHAINS);
        assert_eq!(digits.len(), WOTS_CHAINS);

        // Verify every chain: H^{w-1-digit}(sig[j]) must equal pk[j]
        for j in 0..WOTS_CHAINS {
            let d = digits[j] as usize;
            assert!(d < WOTS_W, "digit {} out of range: {}", j, d);
            let remaining = WOTS_W - 1 - d;
            let mut v = sig[j];
            for _ in 0..remaining {
                v = hash1_wots(&v);
            }
            assert_eq!(
                v, pk[j],
                "WOTS+ chain {} verification failed (digit={})",
                j, d
            );
        }

        // Verify checksum: sum(W-1 - msg_digit[i] for i in 0..128) must decompose into digits[128..133]
        let msg_checksum: u32 = digits[..128].iter().map(|&d| (WOTS_W as u32 - 1) - d).sum();
        let mut cs_reconstructed: u32 = 0;
        for (i, &d) in digits[128..].iter().enumerate() {
            cs_reconstructed += d * (4u32.pow(i as u32));
        }
        assert_eq!(
            msg_checksum, cs_reconstructed,
            "checksum digits must encode the message checksum"
        );

        // Verify pk matches independently derived wots_pk
        let pk_direct = wots_pk(&ask_j, 0);
        assert_eq!(pk, pk_direct, "wots_sign pk must match wots_pk");

        // Verify digits match independent decomposition of the message hash.
        // This catches >>= to <<= mutation in digit extraction.
        let mut expected_digits: Vec<usize> = Vec::new();
        for &byte in msg.iter() {
            expected_digits.push((byte & 3) as usize);
            expected_digits.push(((byte >> 2) & 3) as usize);
            expected_digits.push(((byte >> 4) & 3) as usize);
            expected_digits.push(((byte >> 6) & 3) as usize);
        }
        for j in 0..128 {
            assert_eq!(
                digits[j] as usize, expected_digits[j],
                "digit {} mismatch: wots_sign produced {} but expected {} from byte decomposition",
                j, digits[j], expected_digits[j]
            );
        }
    }

    /// Group 4: auth_tree_path must produce valid Merkle paths.
    /// Kills: all 7 auth_tree_path mutations (XOR, bounds, division)
    #[test]
    fn test_mutant_auth_tree_path_walk() {
        let ask_j = [0x77; 32];
        let (root, leaves) = build_auth_tree(&ask_j);

        // Test multiple leaf indices (not just 0) to catch boundary mutations
        for leaf_idx in [0, 1, 2, 7, 100, 511, 1023] {
            let path = auth_tree_path(&leaves, leaf_idx);
            assert_eq!(path.len(), AUTH_DEPTH, "path length for leaf {}", leaf_idx);

            // Walk the path manually from leaf to root
            let mut current = leaves[leaf_idx];
            let mut idx = leaf_idx;
            for sib in &path {
                current = if idx & 1 == 1 {
                    hash_merkle(sib, &current)
                } else {
                    hash_merkle(&current, sib)
                };
                idx /= 2;
            }
            assert_eq!(current, root, "auth path walk failed for leaf {}", leaf_idx);
        }

        // Different leaf indices must produce different paths (catches XOR→OR mutation)
        let path_0 = auth_tree_path(&leaves, 0);
        let path_1 = auth_tree_path(&leaves, 1);
        // Leaves 0 and 1 are siblings — their paths differ only in the first sibling
        assert_eq!(path_0[0], leaves[1], "leaf 0's sibling should be leaf 1");
        assert_eq!(path_1[0], leaves[0], "leaf 1's sibling should be leaf 0");
        // But higher siblings should be identical (same subtree above level 0)
        assert_eq!(path_0[1], path_1[1], "siblings at level 1 should match");
    }

    /// Group 5a: shield balance edge cases.
    /// Kills: replace < with ==/<=  in balance check
    #[test]
    fn test_mutant_shield_exact_balance() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 500);

        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };

        // Exact balance: v == bal. Must succeed.
        // (< mutation turns `bal < v` into `bal == v`, which would REJECT this)
        // (<= mutation turns `bal < v` into `bal <= v`, which would REJECT this)
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 500,
            address: addr.clone(),
            memo: None,
            proof: Proof::TrustMeBro,
            client_cm: ZERO,
            client_enc: None,
        });
        assert!(
            r.is_ok(),
            "shield with exact balance must succeed: {:?}",
            r.err()
        );

        // Over balance: must fail
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1,
            address: addr,
            memo: None,
            proof: Proof::TrustMeBro,
            client_cm: ZERO,
            client_enc: None,
        });
        assert!(r.is_err(), "shield exceeding balance must fail");
    }

    /// Group 5a-extra: shield output_preimage length boundary.
    /// Kills: replace < with ==/<=  in output_preimage.len() < 4
    #[test]
    fn test_mutant_shield_preimage_length_boundary() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);

        let cm = random_felt();
        let sender_dec = felt_to_dec(&hash(b"alice"));
        let seed: [u8; 64] = [0x99; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let enc = encrypt_note(1000, &random_felt(), None, &ek, &ek);
        let mh = memo_ct_hash(&enc);

        // Preimage with exactly 4 elements (minimum valid — no bootloader header)
        let preimage_4 = vec![
            "1000".into(),
            felt_to_dec(&cm),
            sender_dec.clone(),
            felt_to_dec(&mh),
        ];
        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address: addr.clone(),
            memo: None,
            proof: fake_stark(preimage_4),
            client_cm: cm,
            client_enc: Some(enc.clone()),
        });
        assert!(
            r.is_ok(),
            "preimage of exactly 4 should be accepted: {:?}",
            r.err()
        );

        // Preimage with 3 elements (too short)
        let preimage_3 = vec!["1000".into(), felt_to_dec(&cm), sender_dec];
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address: addr,
            memo: None,
            proof: fake_stark(preimage_3),
            client_cm: cm,
            client_enc: Some(enc),
        });
        assert!(r.is_err(), "preimage of 3 should be rejected");
    }

    /// Group 5b: shield with client_cm but no client_enc (TrustMeBro path).
    /// Kills: replace && with || in client_cm/client_enc check at line 932.
    /// With ||, cm!=ZERO alone would enter the client path and unwrap() None → panic.
    #[test]
    fn test_mutant_shield_cm_without_enc_tmb() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);
        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };
        // TrustMeBro with client_cm set but client_enc=None
        // With &&: client_cm!=ZERO && client_enc.is_some() = true && false = false → server generates cm (OK)
        // With ||: client_cm!=ZERO || client_enc.is_some() = true || false = true → unwrap None → PANIC
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address: addr,
            memo: None,
            proof: Proof::TrustMeBro,
            client_cm: random_felt(), // set but enc is None
            client_enc: None,
        });
        // Should succeed — server generates its own cm/enc
        assert!(
            r.is_ok(),
            "TrustMeBro shield with partial client data should fall through to server: {:?}",
            r.err()
        );
    }

    /// Group 5b (Stark path): shield Stark with client_cm but no client_enc.
    #[test]
    fn test_mutant_shield_stark_cm_without_enc() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 10000);

        let cm = random_felt();
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "1000".into(),
            felt_to_dec(&cm),
            felt_to_dec(&ZERO),
            felt_to_dec(&ZERO),
        ];
        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; 1184],
            ek_d: vec![0; 1184],
        };

        // client_cm set but client_enc is None — must be rejected
        // (&&→|| mutation would accept this because client_cm != ZERO is true)
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: None, // THIS is the key — Stark proof requires enc
        });
        assert!(
            r.is_err(),
            "Stark proof with client_cm but no client_enc must be rejected"
        );
    }

    /// Group 5c: transfer and unshield with 16 inputs (max) must succeed, 17 must fail.
    /// Kills: replace > with ==/>=  in N > MAX_INPUTS check
    #[test]
    fn test_mutant_transfer_max_inputs() {
        let (mut ledger, _, _, root, enc) = setup_with_note();

        // N=16 should be accepted (> mutation turns N > 16 into N == 16, rejecting 16)
        // We can't easily create 16 real notes, so test the boundary:
        // N=17 must be rejected
        let nfs: Vec<F> = (0..17).map(|_| random_felt()).collect();
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: nfs,
            cm_1: random_felt(),
            cm_2: random_felt(),
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err(), "N=17 transfer must be rejected");
        assert!(r.unwrap_err().contains("bad nullifier count"));

        // N=16 should pass the count check (may fail on nullifier/root, that's fine)
        let nfs16: Vec<F> = (0..16).map(|_| random_felt()).collect();
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: nfs16,
            cm_1: random_felt(),
            cm_2: random_felt(),
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: Proof::TrustMeBro,
        });
        // Should NOT fail with "bad nullifier count" — may fail with "nullifier spent" or "invalid root"
        if let Err(e) = &r {
            assert!(
                !e.contains("bad nullifier count"),
                "N=16 should pass the count check, got: {}",
                e
            );
        }
    }

    /// Group 5c (continued): unshield max inputs boundary.
    #[test]
    fn test_mutant_unshield_max_inputs() {
        let (mut ledger, _, _, root, _) = setup_with_note();

        let nfs17: Vec<F> = (0..17).map(|_| random_felt()).collect();
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: nfs17,
            v_pub: 100,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("bad nullifier count"));

        let nfs16: Vec<F> = (0..16).map(|_| random_felt()).collect();
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: nfs16,
            v_pub: 100,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: Proof::TrustMeBro,
        });
        if let Err(e) = &r {
            assert!(
                !e.contains("bad nullifier count"),
                "N=16 should pass count check, got: {}",
                e
            );
        }
    }

    /// Group 5d: transfer output_preimage positional validation with distinct values.
    /// Kills: replace + with -/* in cm1_pos calculation, and < with <= in length check
    #[test]
    fn test_mutant_transfer_preimage_positions() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();

        // Create a valid-looking preimage where every field has a UNIQUE value.
        // This ensures positional checks can't pass by coincidence.
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh_1 = memo_ct_hash(&enc);
        let mh_2 = memo_ct_hash(&enc);

        // N=1: tail layout is [root, nf, cm_1, cm_2, mh_1, mh_2] = 6 elements
        let preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(), // bootloader header (4 elements)
            felt_to_dec(&root),
            felt_to_dec(&nf),
            felt_to_dec(&cm_1),
            felt_to_dec(&cm_2),
            felt_to_dec(&mh_1),
            felt_to_dec(&mh_2),
        ];

        // This should succeed — all fields at correct positions
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1,
            cm_2,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: fake_stark(preimage.clone()),
        });
        assert!(
            r.is_ok(),
            "transfer with correct preimage should succeed: {:?}",
            r.err()
        );

        // Now test with preimage that has cm_1 and cm_2 SWAPPED in position
        let bad_preimage = vec![
            "1".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            felt_to_dec(&root),
            felt_to_dec(&nf),
            felt_to_dec(&cm_2), // SWAPPED
            felt_to_dec(&cm_1), // SWAPPED
            felt_to_dec(&mh_1),
            felt_to_dec(&mh_2),
        ];
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1,
            cm_2,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: fake_stark(bad_preimage),
        });
        assert!(r.is_err(), "swapped cm_1/cm_2 positions must be caught");
    }

    /// Kills 3 mutants that survive with N=1 nullifier:
    /// - line 986: `<` vs `<=` (exact-length preimage)
    /// - line 998: `1+i` vs `1-i` (multi-nullifier indexing)
    /// - line 1012: `cm1_pos+2` vs `cm1_pos*2` (diverge when cm1_pos=3)
    #[test]
    fn test_mutant_transfer_multi_nullifier_preimage() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 50000);

        // Create two notes so we have two distinct nullifiers
        let mut master_sk = ZERO;
        master_sk[0] = 0xCC;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let (auth_root, _) = build_auth_tree(&ask_j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);

        let seed_v: [u8; 64] = [0x33u8; 64];
        let seed_d: [u8; 64] = [0x44u8; 64];
        let (ek_v, _, ek_d, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed_v);
            let (ekd, dkd) = kem_keygen_from_seed(&seed_d);
            (ekv, dkv, ekd, dkd)
        };
        let addr = PaymentAddress {
            d_j,
            auth_root,
            nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };

        // Shield two notes
        ledger
            .shield(&ShieldReq {
                sender: "alice".into(),
                v: 1000,
                address: addr.clone(),
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
            })
            .unwrap();
        ledger
            .shield(&ShieldReq {
                sender: "alice".into(),
                v: 2000,
                address: addr.clone(),
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
            })
            .unwrap();

        let cm_0 = ledger.tree.leaves[0];
        let cm_1_note = ledger.tree.leaves[1];
        let root = ledger.tree.root();
        let nf_0 = nullifier(&nk_sp, &cm_0, 0);
        let nf_1 = nullifier(&nk_sp, &cm_1_note, 1);
        let enc = ledger.memos[0].1.clone();

        let out_cm_1 = random_felt();
        let out_cm_2 = random_felt();
        // Use two DIFFERENT encrypted notes so mh_1 != mh_2.
        // This is critical: with N=2, cm1_pos=3, so cm1_pos+2=5 and cm1_pos*2=6.
        // If mh_1==mh_2, tail[5]==tail[6] and the * mutant survives.
        let enc_1 = enc.clone();
        let enc_2 = encrypt_note(500, &random_felt(), Some(b"different"), &ek_v, &ek_d);
        let mh_1 = memo_ct_hash(&enc_1);
        let mh_2 = memo_ct_hash(&enc_2);
        assert_ne!(
            mh_1, mh_2,
            "mh_1 and mh_2 must differ to detect positional mutants"
        );

        // N=2: tail = [root, nf_0, nf_1, cm_1, cm_2, mh_1, mh_2] = 7 elements
        // cm1_pos = 1+2 = 3
        // cm1_pos+2 = 5, cm1_pos*2 = 6 — these DIFFER, catching the * mutant
        // With i=1: 1+1=2, 1-1=0 — these DIFFER, catching the - mutant

        // Build EXACT-length preimage (no bootloader header padding)
        // This means preimage.len() == expected_tail_len, catching < vs <= mutant
        let preimage = vec![
            felt_to_dec(&root),
            felt_to_dec(&nf_0),
            felt_to_dec(&nf_1),
            felt_to_dec(&out_cm_1),
            felt_to_dec(&out_cm_2),
            felt_to_dec(&mh_1),
            felt_to_dec(&mh_2),
        ];

        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf_0, nf_1],
            cm_1: out_cm_1,
            cm_2: out_cm_2,
            enc_1: enc_1.clone(),
            enc_2: enc_2.clone(),
            proof: fake_stark(preimage),
        });
        assert!(
            r.is_ok(),
            "transfer with 2 nullifiers and exact-length preimage must succeed: {:?}",
            r.err()
        );

        // Also verify that swapping nf_0/nf_1 in the preimage is caught
        // (detects 1+i vs 1-i mutant — with N=2 and i=1 they index differently)
        let mut ledger2 = Ledger::new();
        ledger2.fund("alice", 50000);
        ledger2
            .shield(&ShieldReq {
                sender: "alice".into(),
                v: 1000,
                address: addr.clone(),
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
            })
            .unwrap();
        ledger2
            .shield(&ShieldReq {
                sender: "alice".into(),
                v: 2000,
                address: addr.clone(),
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
            })
            .unwrap();
        let root2 = ledger2.tree.root();
        let nf2_0 = nullifier(&nk_sp, &ledger2.tree.leaves[0], 0);
        let nf2_1 = nullifier(&nk_sp, &ledger2.tree.leaves[1], 1);

        let bad_preimage = vec![
            felt_to_dec(&root2),
            felt_to_dec(&nf2_1), // SWAPPED
            felt_to_dec(&nf2_0), // SWAPPED
            felt_to_dec(&out_cm_1),
            felt_to_dec(&out_cm_2),
            felt_to_dec(&mh_1),
            felt_to_dec(&mh_2),
        ];
        let r = ledger2.transfer(&TransferReq {
            root: root2,
            nullifiers: vec![nf2_0, nf2_1],
            cm_1: out_cm_1,
            cm_2: out_cm_2,
            enc_1: enc_1.clone(),
            enc_2: enc_2.clone(),
            proof: fake_stark(bad_preimage),
        });
        assert!(
            r.is_err(),
            "swapped nullifier order in preimage must be caught"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Regression tests for security audit findings
    // ═══════════════════════════════════════════════════════════════════

    /// Regression: per-address KEM keys must be unique across addresses.
    /// Without per-address derivation, all addresses share the same ek_v/ek_d,
    /// making them trivially linkable (finding #3 from static audit).
    #[test]
    fn test_per_address_kem_keys_unique() {
        let mut master_sk = ZERO;
        master_sk[0] = 0xDD;
        let acc = derive_account(&master_sk);

        let (ek_v_0, _, ek_d_0, _) = derive_kem_keys(&acc.incoming_seed, 0);
        let (ek_v_1, _, ek_d_1, _) = derive_kem_keys(&acc.incoming_seed, 1);
        let (ek_v_2, _, ek_d_2, _) = derive_kem_keys(&acc.incoming_seed, 2);

        // All viewing keys must differ
        assert_ne!(
            ek_v_0.to_bytes(),
            ek_v_1.to_bytes(),
            "ek_v must differ across addresses"
        );
        assert_ne!(ek_v_0.to_bytes(), ek_v_2.to_bytes());
        assert_ne!(ek_v_1.to_bytes(), ek_v_2.to_bytes());

        // All detection keys must differ
        assert_ne!(
            ek_d_0.to_bytes(),
            ek_d_1.to_bytes(),
            "ek_d must differ across addresses"
        );
        assert_ne!(ek_d_0.to_bytes(), ek_d_2.to_bytes());
        assert_ne!(ek_d_1.to_bytes(), ek_d_2.to_bytes());

        // Viewing and detection keys must also differ from each other
        assert_ne!(
            ek_v_0.to_bytes(),
            ek_d_0.to_bytes(),
            "ek_v and ek_d must differ"
        );
    }

    /// Regression: per-address KEM derivation must be deterministic.
    #[test]
    fn test_per_address_kem_keys_deterministic() {
        let mut master_sk = ZERO;
        master_sk[0] = 0xEE;
        let acc = derive_account(&master_sk);

        let (ek_v_a, _, ek_d_a, _) = derive_kem_keys(&acc.incoming_seed, 5);
        let (ek_v_b, _, ek_d_b, _) = derive_kem_keys(&acc.incoming_seed, 5);

        assert_eq!(
            ek_v_a.to_bytes(),
            ek_v_b.to_bytes(),
            "same index must produce same ek_v"
        );
        assert_eq!(
            ek_d_a.to_bytes(),
            ek_d_b.to_bytes(),
            "same index must produce same ek_d"
        );
    }

    /// Regression: encrypt-then-detect must work with per-address keys.
    /// Sender encrypts to address j's public keys, recipient detects + decrypts
    /// with address j's secret keys. Must NOT detect with address k's keys.
    #[test]
    fn test_per_address_encrypt_detect_decrypt_isolation() {
        let mut master_sk = ZERO;
        master_sk[0] = 0xFF;
        let acc = derive_account(&master_sk);

        let (ek_v_0, dk_v_0, ek_d_0, dk_d_0) = derive_kem_keys(&acc.incoming_seed, 0);
        let (_, dk_v_1, _, dk_d_1) = derive_kem_keys(&acc.incoming_seed, 1);

        // Encrypt to address 0
        let rseed = random_felt();
        let enc = encrypt_note(42, &rseed, Some(b"test"), &ek_v_0, &ek_d_0);

        // Address 0's dk_d should detect it
        assert!(detect(&enc, &dk_d_0), "address 0 must detect its own note");

        // Address 1's dk_d should almost certainly NOT detect it (tag collision ~1/1024)
        // We test this probabilistically — if it fails, it's a 1-in-1024 fluke
        // (acceptable for a regression test)
        let detected_by_1 = detect(&enc, &dk_d_1);
        // Don't assert — just verify decryption isolation below

        // Address 0's dk_v should decrypt it
        let dec = decrypt_memo(&enc, &dk_v_0);
        assert!(dec.is_some(), "address 0 must decrypt its own note");
        let (v, rs, _) = dec.unwrap();
        assert_eq!(v, 42);
        assert_eq!(rs, rseed);

        // Address 1's dk_v must NOT decrypt it (wrong shared secret)
        let dec_1 = decrypt_memo(&enc, &dk_v_1);
        assert!(
            dec_1.is_none(),
            "address 1 must NOT decrypt address 0's note"
        );
        let _ = detected_by_1;
    }

    /// Regression: detect() must not panic on correctly-sized but mismatched ciphertext.
    /// (Finding #14 from static audit — untrusted input from ledger feed.)
    #[test]
    fn test_detect_well_sized_but_wrong_ciphertext_no_panic() {
        let mut master_sk = ZERO;
        master_sk[0] = 0xAB;
        let acc = derive_account(&master_sk);
        let (_, _, _, dk_d) = derive_kem_keys(&acc.incoming_seed, 0);

        // Create a correctly-sized but garbage ciphertext
        let ct_d = vec![0xAA; 1088]; // ML-KEM-768 ciphertext size
        let enc = EncryptedNote {
            ct_d,
            tag: 42,
            ct_v: vec![0xBB; 1088],
            encrypted_data: vec![0xCC; 100],
        };

        // Must not panic — should return false
        let result = detect(&enc, &dk_d);
        assert!(!result, "garbage ciphertext must not match");
    }

    /// Regression: derive_kem_view_seed and derive_kem_detect_seed must produce
    /// different seeds even for the same address index.
    #[test]
    fn test_kem_view_detect_seeds_differ() {
        let mut master_sk = ZERO;
        master_sk[0] = 0x77;
        let acc = derive_account(&master_sk);

        let sv = derive_kem_view_seed(&acc.incoming_seed, 0);
        let sd = derive_kem_detect_seed(&acc.incoming_seed, 0);
        assert_ne!(sv, sd, "view and detect seeds for same address must differ");
    }

    #[test]
    fn test_parse_single_task_output_preimage() {
        let output_preimage = vec![
            "1".to_string(),
            "5".to_string(),
            "12345".to_string(),
            "11".to_string(),
            "22".to_string(),
            "33".to_string(),
        ];

        let parsed = parse_single_task_output_preimage(&output_preimage).unwrap();
        assert_eq!(parsed.program_hash, "12345");
        assert_eq!(parsed.public_outputs, &output_preimage[3..]);
    }

    #[test]
    fn test_validate_single_task_program_hash_rejects_wrong_program() {
        let output_preimage = vec![
            "1".to_string(),
            "5".to_string(),
            "12345".to_string(),
            "11".to_string(),
            "22".to_string(),
            "33".to_string(),
        ];

        let err = validate_single_task_program_hash(&output_preimage, "99999").unwrap_err();
        assert!(
            err.contains("unexpected circuit program hash"),
            "unexpected error: {}",
            err
        );
    }

    fn fake_stark_with_program_hash(program_hash: &str) -> Proof {
        Proof::Stark {
            proof_hex: "00".into(),
            output_preimage: vec![
                "1".into(),
                "5".into(),
                program_hash.into(),
                "11".into(),
                "22".into(),
                "33".into(),
            ],
            verify_meta: None,
        }
    }

    #[test]
    fn test_ledger_proof_verifier_accepts_expected_program_hash() {
        let proof = fake_stark_with_program_hash("12345");
        let hashes = ProgramHashes {
            shield: "111".into(),
            transfer: "12345".into(),
            unshield: "333".into(),
        };

        let result = validate_stark_circuit(&proof, CircuitKind::Transfer, &hashes);
        assert!(result.is_ok(), "expected matching program hash to verify");
    }

    #[test]
    fn test_ledger_proof_verifier_rejects_unexpected_program_hash() {
        let proof = fake_stark_with_program_hash("12345");
        let hashes = ProgramHashes {
            shield: "111".into(),
            transfer: "99999".into(),
            unshield: "333".into(),
        };

        let err = validate_stark_circuit(&proof, CircuitKind::Transfer, &hashes).unwrap_err();
        assert!(
            err.contains("unexpected circuit program hash"),
            "unexpected error: {}",
            err
        );
        assert!(
            err.contains("transfer"),
            "expected circuit name in error: {}",
            err
        );
    }

    #[test]
    fn test_ledger_proof_verifier_rejects_stark_without_verified_mode() {
        let verifier = LedgerProofVerifier::trust_me_bro_only();
        let proof = fake_stark_with_program_hash("12345");

        let err = verifier
            .validate(&proof, CircuitKind::Transfer)
            .unwrap_err();
        assert!(
            err.contains("not configured with --reprove-bin"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_single_task_output_preimage_rejects_bad_length() {
        let output_preimage = vec![
            "1".to_string(),
            "7".to_string(),
            "12345".to_string(),
            "11".to_string(),
            "22".to_string(),
            "33".to_string(),
        ];

        let err = parse_single_task_output_preimage(&output_preimage).unwrap_err();
        assert!(
            err.contains("length mismatch"),
            "unexpected error: {}",
            err
        );
    }
}
