//! StarkPrivacy shared library — crypto, types, Merkle tree, API types.

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

/// Compute transfer sighash from public outputs.
pub fn transfer_sighash(root: &F, nullifiers: &[F], cm_1: &F, cm_2: &F, mh_1: &F, mh_2: &F) -> F {
    // Circuit-type tag 0x01 for transfer
    let mut type_tag = ZERO; type_tag[0] = 0x01;
    let mut sh = sighash_fold(&type_tag, root);
    for nf in nullifiers { sh = sighash_fold(&sh, nf); }
    sh = sighash_fold(&sh, cm_1);
    sh = sighash_fold(&sh, cm_2);
    sh = sighash_fold(&sh, mh_1);
    sh = sighash_fold(&sh, mh_2);
    sh
}

/// Compute unshield sighash from public outputs.
pub fn unshield_sighash(root: &F, nullifiers: &[F], v_pub: u64, recipient: &F, cm_change: &F, mh_change: &F) -> F {
    // Circuit-type tag 0x02 for unshield
    let mut type_tag = ZERO; type_tag[0] = 0x02;
    let mut sh = sighash_fold(&type_tag, root);
    for nf in nullifiers { sh = sighash_fold(&sh, nf); }
    let mut v_felt = ZERO;
    v_felt[..8].copy_from_slice(&v_pub.to_le_bytes());
    sh = sighash_fold(&sh, &v_felt);
    sh = sighash_fold(&sh, recipient);
    sh = sighash_fold(&sh, cm_change);
    sh = sighash_fold(&sh, mh_change);
    sh
}

pub fn memo_ct_hash(enc: &EncryptedNote) -> F {
    let mut buf = Vec::with_capacity(enc.ct_v.len() + enc.encrypted_data.len());
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
        for i in 0..32 { be[i] = val[31 - i]; }
        let hex_str = hex::encode(be);
        let trimmed = hex_str.trim_start_matches('0');
        if trimmed.is_empty() { return "0".to_string(); }
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
                if bytes[i] != 0 { all_zero = false; }
            }
            result.push((b'0' + rem as u8) as char);
            if all_zero { break; }
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
    for _ in 0..n { v = hash1_wots(&v); }
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
        for _ in 0..4 { // 8 / log_w
            digits.push((b & 3) as usize);
            b >>= log_w;
        }
    }
    // Checksum
    let checksum: usize = digits.iter().map(|d| WOTS_W - 1 - d).sum();
    let mut cs = checksum;
    for _ in 0..5 { // checksum chains
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
        return if level.is_empty() { zh[AUTH_DEPTH] } else { level[0] };
    }
    let mut next = vec![];
    let mut i = 0;
    loop {
        let left = if i < level.len() { level[i] } else { zh[depth] };
        let right = if i + 1 < level.len() { level[i + 1] } else { zh[depth] };
        next.push(hash_merkle(&left, &right));
        i += 2;
        if i >= level.len() && !next.is_empty() { break; }
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
        siblings.push(if sib_idx < level.len() { level[sib_idx] } else { zh[d] });
        let mut next = vec![];
        let mut i = 0;
        loop {
            let left = if i < level.len() { level[i] } else { zh[d] };
            let right = if i + 1 < level.len() { level[i + 1] } else { zh[d] };
            next.push(hash_merkle(&left, &right));
            i += 2;
            if i >= level.len() { break; }
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

pub fn detect(enc: &EncryptedNote, dk_d: &Dk) -> bool {
    let Ok(ct) = ml_kem_768::Ciphertext::try_from(enc.ct_d.as_slice()) else {
        return false;
    };
    let ss = dk_d
        .try_decapsulate(&ct)
        .expect("ML-KEM decaps is infallible");
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
    pub addr_index: u32,  // which address j this note belongs to
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

// ═══════════════════════════════════════════════════════════════════════
// Ledger state
// ═══════════════════════════════════════════════════════════════════════

pub struct Ledger {
    pub tree: MerkleTree,
    pub nullifiers: HashSet<F>,
    pub balances: HashMap<String, u64>,
    pub valid_roots: HashSet<F>,
    pub memos: Vec<(F, EncryptedNote)>,
}

impl Ledger {
    pub fn new() -> Self {
        let tree = MerkleTree::new();
        let mut roots = HashSet::new();
        roots.insert(tree.root());
        Self {
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

        // Validate output_preimage for Stark proofs
        match &req.proof {
            Proof::TrustMeBro => {}
            Proof::Stark { proof_hex: _, output_preimage, verify_meta: _ } => {
                // Shield outputs: [v_pub, cm_new, sender, memo_ct_hash]
                if req.client_cm == ZERO {
                    return Err("Stark proof requires client_cm (cannot use server-generated cm)".into());
                }
                if req.client_enc.is_none() {
                    return Err("Stark proof requires client_enc (cannot use server-generated note)".into());
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
                req.address.ek_v.as_slice().try_into().map_err(|_| "bad ek_v length")?,
            ).map_err(|_| "invalid ek_v")?;
            let ek_d = ml_kem_768::EncapsulationKey::new(
                req.address.ek_d.as_slice().try_into().map_err(|_| "bad ek_d length")?,
            ).map_err(|_| "invalid ek_d")?;
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
            Proof::Stark { proof_hex: _, output_preimage, verify_meta: _ } => {
                // Validate output_preimage tail matches the transfer's public outputs.
                // The bootloader wraps with header fields; our program outputs are at the tail.
                // Transfer outputs: [root, nf_0..nf_N, cm_1, cm_2, mh_1, mh_2]
                let n = req.nullifiers.len();
                let expected_tail_len = 1 + n + 4; // root + N nf + cm_1 + cm_2 + mh_1 + mh_2
                if output_preimage.len() < expected_tail_len {
                    return Err(format!("output_preimage too short: {} < {}", output_preimage.len(), expected_tail_len));
                }
                let tail_start = output_preimage.len() - expected_tail_len;
                let tail = &output_preimage[tail_start..];

                // Validate positionally
                let root_dec = felt_to_dec(&req.root);
                if tail[0] != root_dec {
                    return Err(format!("proof root mismatch"));
                }
                for (i, nf) in req.nullifiers.iter().enumerate() {
                    if tail[1 + i] != felt_to_dec(nf) {
                        return Err(format!("proof nullifier {} mismatch", i));
                    }
                }
                let cm1_pos = 1 + n;
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
            Proof::Stark { proof_hex: _, output_preimage, verify_meta: _ } => {
                // Unshield outputs: [root, nf_0..nf_N, v_pub, recipient, cm_change, mh_change]
                let n = req.nullifiers.len();
                let expected_tail_len = 1 + n + 4; // root + N nf + v_pub + recipient + cm_change + mh_change
                if output_preimage.len() < expected_tail_len {
                    return Err(format!("output_preimage too short"));
                }
                let tail_start = output_preimage.len() - expected_tail_len;
                let tail = &output_preimage[tail_start..];

                if tail[0] != felt_to_dec(&req.root) {
                    return Err("proof root mismatch".into());
                }
                for (i, nf) in req.nullifiers.iter().enumerate() {
                    if tail[1 + i] != felt_to_dec(nf) {
                        return Err(format!("proof nullifier {} mismatch", i));
                    }
                }
                if tail[1 + n] != req.v_pub.to_string() {
                    return Err("proof v_pub mismatch".into());
                }
                // Validate recipient, cm_change, memo_ct_hash_change
                let recipient_dec = felt_to_dec(&hash(req.recipient.as_bytes()));
                if tail[2 + n] != recipient_dec {
                    return Err("proof recipient mismatch".into());
                }
                if tail[3 + n] != felt_to_dec(&req.cm_change) {
                    return Err("proof cm_change mismatch".into());
                }
                // Validate memo_ct_hash_change
                if let Some(ref enc) = req.enc_change {
                    let mh = memo_ct_hash(enc);
                    if tail[4 + n] != felt_to_dec(&mh) {
                        return Err("proof memo_ct_hash_change mismatch".into());
                    }
                } else if tail[4 + n] != "0" {
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
        master_sk[0] = 0xCE; master_sk[1] = 0x11; master_sk[2] = 0x0A;

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
        rseed[0] = 0x01; rseed[1] = 0x10; // 0x1001
        let rcm = derive_rcm(&rseed);
        let cm = commit(&d_j, 1000, &rcm, &otag);
        let nf = nullifier(&nk_sp, &cm, 0);

        // Expected values from Cairo: `scarb execute --executable-name step_testvec`
        // If these fail, Cairo and Rust have diverged.
        assert_eq!(hex::encode(acc.nk), "b53735112c79f469b40ce05907b2b9d2b45510dc93261b44352e585d7af3ec01", "nk");
        assert_eq!(hex::encode(d_j), "5837578dcb8582f8f70786500345f84a27210d04c02917479a135277406b6005", "d_j");
        assert_eq!(hex::encode(nk_sp), "59136e29b4b7cd2921867598eb07e5e5aed972fcb1e0e55b7950baf543f95503", "nk_spend");
        assert_eq!(hex::encode(nk_tg), "11594531faf2fdd11ced609a8408852bbe794971e8124b95ffde325013d28601", "nk_tag");
        assert_eq!(hex::encode(auth_root), "ec2f60b94129d84a86f5178de09e77245046116788e9fedc91fedf78f8298d01", "auth_root");
        assert_eq!(hex::encode(cm), "cc51d216f32472c5b635e9665be91e18797c3fb28dcb308e42da29d9a230fb01", "cm");
        assert_eq!(hex::encode(nf), "df1ad56380610c948266f0e81ed555bb9152b99bfedff0c328c577277b944501", "nf");
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
        let resp = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000,
            address: addr,
            memo: None,
            proof: Proof::TrustMeBro,
            client_cm: ZERO,
            client_enc: None,
        }).unwrap();

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
        let resp = ledger.unshield(&UnshieldReq {
            root: ledger.tree.root(),
            nullifiers: vec![nf],
            v_pub: 1000,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: Proof::TrustMeBro,
        }).unwrap();
        assert_eq!(resp.change_index, None);
        assert_eq!(ledger.balances["alice"], 1000);

        // Double-spend rejected
        assert!(ledger.unshield(&UnshieldReq {
            root: ledger.tree.root(),
            nullifiers: vec![nf],
            v_pub: 1000,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            proof: Proof::TrustMeBro,
        }).is_err());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Attack tests — these attacks would succeed without output_preimage
    // validation. Each constructs a fake Proof::Stark with a tampered
    // output_preimage and verifies the ledger rejects it.
    // ═══════════════════════════════════════════════════════════════════

    /// Helper: build a fake Stark proof with a given output_preimage.
    /// The proof_hex is garbage — only the output_preimage matters for
    /// these tests (we're testing the ledger's validation, not STARK crypto).
    fn fake_stark(output_preimage: Vec<String>) -> Proof {
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
            d_j, auth_root, nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };
        ledger.shield(&ShieldReq {
            sender: "alice".into(), v: 1000, address: addr,
            memo: None, proof: Proof::TrustMeBro,
            client_cm: ZERO, client_enc: None,
        }).unwrap();

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
            "1".into(), // bootloader header
            format!("{}", 5 + 1), // size
            "0".into(), "0".into(), // padding
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
        assert!(result.is_err(), "transfer with mismatched cm_1 should be rejected");
        assert!(result.unwrap_err().contains("cm_1 mismatch"),
            "should specifically catch cm_1 mismatch");
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
            "1".into(), "0".into(), "0".into(), "0".into(), // bootloader header
            felt_to_dec(&root),
            felt_to_dec(&nf),
            felt_to_dec(&cm_1),
            felt_to_dec(&cm_2),
            felt_to_dec(&mh_1),    // proof commits to REAL memo hash
            felt_to_dec(&ZERO),
        ];

        let result = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            cm_1, cm_2,
            enc_1: fake_enc, // attacker swaps in a DIFFERENT encrypted note
            enc_2: enc.clone(),
            proof: fake_stark(preimage),
        });
        assert!(result.is_err(), "transfer with swapped memo should be rejected");
        assert!(result.unwrap_err().contains("memo_ct_hash_1 mismatch"),
            "should specifically catch memo substitution");
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
            "1".into(), "0".into(), "0".into(), "0".into(), // bootloader header
            felt_to_dec(&root),
            felt_to_dec(&nf),
            "1000".into(), // v_pub
            felt_to_dec(&alice_recipient), // proof says ALICE
            felt_to_dec(&ZERO), // cm_change
            felt_to_dec(&ZERO), // mh_change
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
        assert!(result.is_err(), "unshield with redirected recipient should be rejected");
        assert!(result.unwrap_err().contains("recipient mismatch"),
            "should specifically catch recipient redirect");
    }

    /// Attack: unshield with inflated v_pub.
    /// Attacker's proof proves v_pub=100 but submits v_pub=1000000.
    #[test]
    fn test_attack_unshield_inflated_vpub_rejected() {
        let (mut ledger, cm, nf, root, enc) = setup_with_note();

        // Proof commits to v_pub=100
        let preimage = vec![
            "1".into(), "0".into(), "0".into(), "0".into(),
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
        assert!(result.is_err(), "unshield with inflated v_pub should be rejected");
        assert!(result.unwrap_err().contains("v_pub mismatch"),
            "should specifically catch v_pub inflation");
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
            "1".into(), "0".into(), "0".into(), "0".into(),
            "1".into(), // proof says v=1
            felt_to_dec(&cm),
            felt_to_dec(&hash(b"alice")),
            felt_to_dec(&ZERO),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(), auth_root: random_felt(), nk_tag: random_felt(),
            ek_v: vec![0; 1184], ek_d: vec![0; 1184],
        };

        let result = ledger.shield(&ShieldReq {
            sender: "alice".into(),
            v: 1000000, // attacker claims 1000000
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(EncryptedNote {
                ct_d: vec![0; 1088], tag: 0,
                ct_v: vec![0; 1088], encrypted_data: vec![0; 1080],
            }),
        });
        assert!(result.is_err(), "shield with inflated amount should be rejected");
        assert!(result.unwrap_err().contains("v_pub mismatch"),
            "should specifically catch amount inflation");
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
            "1".into(), "0".into(), "0".into(), "0".into(),
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
            cm_1, cm_2,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            proof: fake_stark(preimage),
        });
        assert!(result.is_err(), "transfer with fake nullifier should be rejected");
        assert!(result.unwrap_err().contains("nullifier 0 mismatch"),
            "should specifically catch nullifier substitution");
    }

    // ── State-level checks (no proof needed) ─────────────────────────

    /// Shield: insufficient public balance.
    #[test]
    fn test_shield_insufficient_balance() {
        let mut ledger = Ledger::new();
        ledger.fund("alice", 100);
        let addr = PaymentAddress {
            d_j: random_felt(), auth_root: random_felt(), nk_tag: random_felt(),
            ek_v: vec![0; 1184], ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(), v: 200, address: addr, memo: None,
            proof: Proof::TrustMeBro, client_cm: ZERO, client_enc: None,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("insufficient"));
    }

    /// Transfer: zero inputs rejected.
    #[test]
    fn test_transfer_zero_inputs_rejected() {
        let (mut ledger, _, _, root, enc) = setup_with_note();
        let r = ledger.transfer(&TransferReq {
            root, nullifiers: vec![], // zero inputs
            cm_1: random_felt(), cm_2: random_felt(),
            enc_1: enc.clone(), enc_2: enc.clone(),
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
            root: fake_root, nullifiers: vec![nf],
            cm_1: random_felt(), cm_2: random_felt(),
            enc_1: enc.clone(), enc_2: enc.clone(),
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
        ledger.transfer(&TransferReq {
            root, nullifiers: vec![nf],
            cm_1: random_felt(), cm_2: random_felt(),
            enc_1: enc.clone(), enc_2: enc.clone(),
            proof: Proof::TrustMeBro,
        }).unwrap();
        // Second spend with same nullifier fails
        let r = ledger.transfer(&TransferReq {
            root, nullifiers: vec![nf],
            cm_1: random_felt(), cm_2: random_felt(),
            enc_1: enc.clone(), enc_2: enc.clone(),
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
            root, nullifiers: vec![nf, nf], // same nf twice
            cm_1: random_felt(), cm_2: random_felt(),
            enc_1: enc.clone(), enc_2: enc.clone(),
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
            root: random_felt(), nullifiers: vec![nf],
            v_pub: 1000, recipient: "alice".into(),
            cm_change: ZERO, enc_change: None,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("invalid root"));
    }

    /// Unshield: double-spend rejected.
    #[test]
    fn test_unshield_double_spend_rejected() {
        let (mut ledger, _, nf, root, _) = setup_with_note();
        ledger.unshield(&UnshieldReq {
            root, nullifiers: vec![nf], v_pub: 1000,
            recipient: "alice".into(), cm_change: ZERO, enc_change: None,
            proof: Proof::TrustMeBro,
        }).unwrap();
        let r = ledger.unshield(&UnshieldReq {
            root, nullifiers: vec![nf], v_pub: 1000,
            recipient: "alice".into(), cm_change: ZERO, enc_change: None,
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
            root, nullifiers: vec![nf, nf],
            v_pub: 1000, recipient: "alice".into(),
            cm_change: ZERO, enc_change: None,
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
            "1".into(), "0".into(), "0".into(), "0".into(),
            "1000".into(),
            felt_to_dec(&real_cm), // proof proves THIS cm
            felt_to_dec(&ZERO),
            felt_to_dec(&ZERO),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(), auth_root: random_felt(), nk_tag: random_felt(),
            ek_v: vec![0; 1184], ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(), v: 1000, address: addr, memo: None,
            proof: fake_stark(preimage),
            client_cm: fake_cm, // DIFFERENT cm
            client_enc: Some(EncryptedNote {
                ct_d: vec![0; 1088], tag: 0,
                ct_v: vec![0; 1088], encrypted_data: vec![0; 1080],
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
            "1".into(), "0".into(), "0".into(), "0".into(),
            felt_to_dec(&fake_root), // proof says THIS root
            felt_to_dec(&nf),
            felt_to_dec(&cm_1), felt_to_dec(&cm_2),
            felt_to_dec(&mh), felt_to_dec(&mh),
        ];

        let r = ledger.transfer(&TransferReq {
            root, // request uses the REAL root
            nullifiers: vec![nf],
            cm_1, cm_2,
            enc_1: enc.clone(), enc_2: enc.clone(),
            proof: fake_stark(preimage),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("root mismatch"));
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
            "1".into(), "0".into(), "0".into(), "0".into(),
            felt_to_dec(&root), felt_to_dec(&nf),
            felt_to_dec(&cm_1),
            felt_to_dec(&real_cm_2), // proof proves THIS cm_2
            felt_to_dec(&mh), felt_to_dec(&mh),
        ];

        let r = ledger.transfer(&TransferReq {
            root, nullifiers: vec![nf],
            cm_1,
            cm_2: fake_cm_2, // attacker substitutes cm_2
            enc_1: enc.clone(), enc_2: enc.clone(),
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
            "1".into(), "0".into(), "0".into(), "0".into(),
            felt_to_dec(&fake_root), // proof says THIS root
            felt_to_dec(&nf),
            "1000".into(),
            felt_to_dec(&recipient),
            felt_to_dec(&ZERO), felt_to_dec(&ZERO),
        ];

        let r = ledger.unshield(&UnshieldReq {
            root, // request uses the REAL root
            nullifiers: vec![nf], v_pub: 1000,
            recipient: "alice".into(),
            cm_change: ZERO, enc_change: None,
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
            "1".into(), "0".into(), "0".into(), "0".into(),
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
        assert!(result.is_err(), "unshield with substituted cm_change should be rejected");
        assert!(result.unwrap_err().contains("cm_change mismatch"),
            "should specifically catch cm_change substitution");
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
            assert_eq!(f[31] & 0xF8, 0, "random_felt produced >251-bit value: top byte = {:#04x}", f[31]);
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
        assert_ne!(seed_0, seed_1, "different key indices must produce different seeds");

        // Different key indices produce different public keys
        let pk_0 = wots_pk(&ask_j, 0);
        let pk_1 = wots_pk(&ask_j, 1);
        assert_ne!(pk_0, pk_1, "different key indices must produce different public keys");

        // Different key indices produce different auth leaves
        let leaf_0 = wots_pk_to_leaf(&pk_0);
        let leaf_1 = wots_pk_to_leaf(&pk_1);
        assert_ne!(leaf_0, leaf_1, "different key indices must produce different auth leaves");

        // Same key + different message = different signature (one-time property)
        let msg1 = hash(b"msg1");
        let msg2 = hash(b"msg2");
        let (sig1, _, _) = wots_sign(&ask_j, 0, &msg1);
        let (sig2, _, _) = wots_sign(&ask_j, 0, &msg2);
        assert_ne!(sig1, sig2, "same key + different messages must produce different signatures");
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
            d_j: random_felt(), auth_root: random_felt(), nk_tag: random_felt(),
            ek_v: vec![0; 1184], ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(), v: 1000, address: addr, memo: None,
            proof: fake_stark(vec!["0".into(); 8]),
            client_cm: ZERO, // BUG: no client cm with Stark proof
            client_enc: None,
        });
        assert!(r.is_err(), "Stark proof with ZERO client_cm should be rejected");
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
            ct_d: vec![0; 1088], tag: 0,
            ct_v: vec![0; 1088], encrypted_data: vec![0; 1080],
        };
        let mh = memo_ct_hash(&enc);

        // Proof commits to sender=alice
        let preimage = vec![
            "1".into(), "0".into(), "0".into(), "0".into(),
            "1000".into(), felt_to_dec(&cm), alice_sender, felt_to_dec(&mh),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(), auth_root: random_felt(), nk_tag: random_felt(),
            ek_v: vec![0; 1184], ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "attacker".into(), // attacker front-runs with different sender
            v: 1000, address: addr, memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(enc),
        });
        assert!(r.is_err(), "shield with mismatched sender should be rejected");
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
            "1".into(), "0".into(), "0".into(), "0".into(),
            "1000".into(), felt_to_dec(&cm), sender_dec, felt_to_dec(&real_mh),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(), auth_root: random_felt(), nk_tag: random_felt(),
            ek_v: vec![0; 1184], ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(), v: 1000, address: addr, memo: None,
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
            "1".into(), "0".into(), "0".into(), "0".into(),
            felt_to_dec(&root), felt_to_dec(&nf),
            "1000".into(), felt_to_dec(&recipient),
            felt_to_dec(&ZERO), // cm_change = 0
            "12345".into(), // mh_change should be 0 but isn't
        ];

        let r = ledger.unshield(&UnshieldReq {
            root, nullifiers: vec![nf], v_pub: 1000,
            recipient: "alice".into(),
            cm_change: ZERO, enc_change: None,
            proof: fake_stark(preimage),
        });
        assert!(r.is_err(), "nonzero mh_change without enc_change should be rejected");
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
            "1".into(), "0".into(), "0".into(), "0".into(),
            "1000".into(), felt_to_dec(&cm), sender_dec, felt_to_dec(&ZERO),
        ];

        let addr = PaymentAddress {
            d_j: random_felt(), auth_root: random_felt(), nk_tag: random_felt(),
            ek_v: vec![0; 1184], ek_d: vec![0; 1184],
        };
        let r = ledger.shield(&ShieldReq {
            sender: "alice".into(), v: 1000, address: addr, memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: None, // BUG: Stark proof without client_enc
        });
        assert!(r.is_err(), "Stark proof with None client_enc should be rejected");
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
        assert_ne!(generic, wots,
            "WOTS+ chain hash must differ from generic hash (different IVs)");
    }

    /// Regression: PK fold uses dedicated pkfdSP__ IV, not generic.
    #[test]
    fn test_regression_pkfold_dedicated_iv() {
        let a = random_felt();
        let b = random_felt();
        let generic = hash_two(&a, &b);
        let pkfold = hash2_pkfold(&a, &b);
        assert_ne!(generic, pkfold,
            "PK fold hash must differ from generic hash (different IVs)");
    }

    /// Regression: sighash uses dedicated sighSP__ IV.
    #[test]
    fn test_regression_sighash_dedicated_iv() {
        let a = random_felt();
        let b = random_felt();
        let generic = hash_two(&a, &b);
        let sh = sighash_fold(&a, &b);
        assert_ne!(generic, sh,
            "sighash fold must differ from generic hash (different IVs)");
    }

    /// Regression: transfer and unshield sighashes differ (circuit-type tag).
    /// Bug: without type tags, a transfer and unshield with same public
    /// outputs could produce the same sighash, enabling cross-circuit replay.
    #[test]
    fn test_regression_sighash_circuit_type_tags_differ() {
        let root = random_felt();
        let nf = random_felt();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh = ZERO;

        let transfer_sh = transfer_sighash(&root, &[nf], &cm_1, &cm_2, &mh, &mh);

        // Unshield with same values (treating cm_1 as v_pub felt, cm_2 as recipient, etc.)
        let mut v_pub_felt = ZERO;
        v_pub_felt[..32].copy_from_slice(&cm_1); // reuse same bytes
        let unshield_sh = unshield_sighash(&root, &[nf], 0, &cm_2, &mh, &mh);

        assert_ne!(transfer_sh, unshield_sh,
            "transfer and unshield sighashes must differ due to circuit-type tags");
    }

}
