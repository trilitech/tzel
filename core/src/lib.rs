//! TzEL core protocol/state library.

pub mod canonical_wire;
pub mod kernel_wire;

use blake2s_simd::Params;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ml_kem::kem::{Encapsulate, TryDecapsulate};
use ml_kem::ml_kem_768;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
pub fn hash1_wots(data: &F) -> F {
    blake2s(b"wotsSP__", data)
}

/// WOTS+ PK fold using dedicated "pkfdSP__" personalization.
pub fn hash2_pkfold(a: &F, b: &F) -> F {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    blake2s(b"pkfdSP__", &buf)
}

pub fn hash_chain(x: &F, n: usize) -> F {
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
pub fn auth_tree_root(leaves: &[F]) -> F {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
        /// Verification metadata — everything needed for standalone ~50ms verification.
        /// Serialized ProofConfig, CircuitConfig, CircuitPublicData.
        #[serde(default)]
        verify_meta: Option<serde_json::Value>,
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
pub struct FundReq {
    pub addr: String,
    pub amount: u64,
}

/// Payment address — everything a sender needs to create a note for the recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub memos: Vec<(F, EncryptedNote)>,
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

    fn snapshot_root_local(&mut self) {
        self.valid_roots.insert(self.tree.root());
    }

    fn post_note_local(&mut self, cm: F, enc: EncryptedNote) {
        self.memos.push((cm, enc));
    }

    pub fn fund(&mut self, addr: &str, amount: u64) -> Result<(), String> {
        apply_fund(self, addr, amount)
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
}

pub fn apply_fund<S: LedgerState>(state: &mut S, addr: &str, amount: u64) -> Result<(), String> {
    let next = state
        .balance(addr)?
        .checked_add(amount)
        .ok_or_else(|| "public balance overflow".to_string())?;
    state.set_balance(addr, next)
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
                return Err("Stark proof requires client_cm (cannot use server-generated cm)".into());
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
    if n == 0 || n > 16 {
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

// ═══════════════════════════════════════════════════════════════════════
// Tests — cross-implementation verification against Cairo
// ═══════════════════════════════════════════════════════════════════════
