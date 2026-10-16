//! TzEL Multiasset Privacy Circuits on leanVM (`Shield`, `Transfer N->4`, `Unshield`):
//! - Personalized BLAKE2s-256 IVs (`mrklSP__`, `nulfSP__`, `cmmtSP__`, `nktgSP__`, `ownrSP__`, `sighSP__`)
//! - 251-bit felt truncation (`w[3] &= 0x07FF_FFFF_FFFF_FFFF`)
//! - 133-chain `w = 4` WOTS+ with L-tree and depth-16 XMSS auth tree
//! - Depth-48 commitment Merkle tree
//! - 2-accumulator per-asset balance (`ASSET_TEZ` and `primary_non_tez_asset`)
#![no_std]

use thiserror::Error;

/// A 256-bit value (or 251-bit TzEL felt) represented as four little-endian 64-bit words.
pub type Felt = [u64; 4];

/// Canonical tez asset tag (`0`).
pub const ASSET_TEZ: Felt = [0; 4];

/// Zero felt (`0`).
pub const ZERO: Felt = [0; 4];

/// Canonical leanVM program hash committed for TzEL `Shield` (`OpTag::ExactShield`).
pub const PROGRAM_HASH_SHIELD: Felt = [
    0x545A_454C_5F53_4844,
    0x4C45_414E_564D_5F31,
    0x0000_0000_0000_0001,
    0x0100_0000_0000_0000,
];

/// Canonical leanVM program hash committed for TzEL `Transfer` (`OpTag::ExactTransfer`).
pub const PROGRAM_HASH_TRANSFER: Felt = [
    0x545A_454C_5F58_4652,
    0x4C45_414E_564D_5F31,
    0x0000_0000_0000_0002,
    0x0100_0000_0000_0000,
];

/// Canonical leanVM program hash committed for TzEL `Unshield` (`OpTag::ExactUnshield`).
pub const PROGRAM_HASH_UNSHIELD: Felt = [
    0x545A_454C_5F55_4E53,
    0x4C45_414E_564D_5F31,
    0x0000_0000_0000_0003,
    0x0100_0000_0000_0000,
];

/// Maximum number of inputs in a TzEL JoinSplit (`Transfer` or `Unshield`).
pub const MAX_INPUTS: usize = 5;

/// Opcode tag selecting which circuit the guest executes.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpTag {
    ExactShield = 1,
    ExactTransfer = 2,
    ExactUnshield = 3,
}

impl OpTag {
    #[inline(always)]
    pub const fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(Self::ExactShield),
            2 => Some(Self::ExactTransfer),
            3 => Some(Self::ExactUnshield),
            _ => None,
        }
    }
}

/// Verification error across TzEL multiasset circuits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TzelError {
    #[error("producer fee asset must be ASSET_TEZ")]
    ProducerAssetNotTez,
    #[error("producer fee must be strictly positive")]
    ProducerFeeZero,
    #[error("recipient note commitment mismatch")]
    BadCommitment,
    #[error("producer note commitment mismatch")]
    BadProducerCommitment,
    #[error("deposit pubkey_hash mismatch")]
    BadPubkeyHash,
    #[error("XMSS auth key index out of range")]
    XmssKeyIndexOutOfRange,
    #[error("XMSS authentication root mismatch")]
    XmssAuthRootMismatch,
    #[error("input count out of range (must be 1..=5)")]
    BadInputCount,
    #[error("asset not in {{ASSET_TEZ, primary_non_tez_asset}}")]
    BadAsset,
    #[error("commitment Merkle path index out of range")]
    MerkleIndexOutOfRange,
    #[error("commitment Merkle root mismatch")]
    MerkleRootMismatch,
    #[error("nullifier mismatch")]
    BadNullifier,
    #[error("duplicate nullifier in transaction")]
    DuplicateNullifier,
    #[error("tez accumulator balance mismatch")]
    TezBalanceMismatch,
    #[error("primary non-tez accumulator balance mismatch")]
    PrimaryBalanceMismatch,
    #[error("disabled unshield change slot has non-zero fields")]
    BadDisabledChangeSlot,
    #[error("unshield public withdrawal amount must be strictly positive")]
    PublicAmountZero,
}

#[inline(always)]
pub const fn u64_to_felt(v: u64) -> Felt {
    [v, 0, 0, 0]
}

// ============================================================================
// 1. TzEL-Exact Multiasset Protocol (bit-for-bit identical to tzel-core & Cairo)
// ============================================================================

pub mod exact {
    use super::{ASSET_TEZ, Felt, MAX_INPUTS, TzelError, ZERO, u64_to_felt};
    use leanvm_guest::Words;

    pub const TREE_DEPTH: usize = 48;
    pub const AUTH_DEPTH: usize = 16;
    pub const WOTS_W: u32 = 4;
    pub const WOTS_CHAINS: usize = 133;

    const FELT_HIGH_MASK: u64 = 0x07FF_FFFF_FFFF_FFFF;

    // Personalized BLAKE2s-256 IVs matching `cairo/src/blake_hash.cairo`
    pub const IV_GENERIC: [u64; 4] = [
        0xBB67_AE85_6B08_E647,
        0xA54F_F53A_3C6E_F372,
        0x9B05_688C_510E_527F,
        0x5BE0_CD19_1F83_D9AB,
    ];
    pub const IV_MERKLE: [u64; 4] = [
        0xBB67_AE85_6B08_E647,
        0xA54F_F53A_3C6E_F372,
        0x9B05_688C_510E_527F,
        0x04BF_9D4A_73E8_ABC6,
    ];
    pub const IV_NULLIFIER: [u64; 4] = [
        0xBB67_AE85_6B08_E647,
        0xA54F_F53A_3C6E_F372,
        0x9B05_688C_510E_527F,
        0x04BF_9D4A_79EF_ACC5,
    ];
    pub const IV_COMMIT: [u64; 4] = [
        0xBB67_AE85_6B08_E647,
        0xA54F_F53A_3C6E_F372,
        0x9B05_688C_510E_527F,
        0x04BF_9D4A_6BEE_B4C8,
    ];
    pub const IV_NK_TAG: [u64; 4] = [
        0xBB67_AE85_6B08_E647,
        0xA54F_F53A_3C6E_F372,
        0x9B05_688C_510E_527F,
        0x04BF_9D4A_78F7_B2C5,
    ];
    pub const IV_OWNER: [u64; 4] = [
        0xBB67_AE85_6B08_E647,
        0xA54F_F53A_3C6E_F372,
        0x9B05_688C_510E_527F,
        0x04BF_9D4A_6DED_AEC4,
    ];
    pub const IV_SIGHASH: [u64; 4] = [
        0xBB67_AE85_6B08_E647,
        0xA54F_F53A_3C6E_F372,
        0x9B05_688C_510E_527F,
        0x04BF_9D4A_77E4_B0D8,
    ];

    const TAG_XMSS_CHAIN: u64 = 0x0068_632D_7373_6D78;
    const TAG_XMSS_LTREE: u64 = 0x0074_6C2D_7373_6D78;
    const TAG_XMSS_TREE: u64 = 0x0072_742D_7373_6D78;
    const TAG_RCM: u64 = 0x0072_636D;

    #[inline(always)]
    fn compress(h: &[u64; 4], m: &[u64; 8], t: u64, last: bool) -> [u64; 4] {
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            leanvm_guest::precompile::blake2s_compress(h, m, t, last)
        }
        #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
        {
            leanvm_guest::blake2s_compress(h, m, t, last)
        }
    }

    #[inline(always)]
    const fn mask_felt(mut d: [u64; 4]) -> Felt {
        d[3] &= FELT_HIGH_MASK;
        d
    }

    #[inline(always)]
    pub fn hash1_with_iv(iv: &[u64; 4], a: &Felt) -> Felt {
        let m = [a[0], a[1], a[2], a[3], 0, 0, 0, 0];
        mask_felt(compress(iv, &m, 32, true))
    }

    #[inline(always)]
    pub fn hash1(a: &Felt) -> Felt {
        hash1_with_iv(&IV_GENERIC, a)
    }

    #[inline(always)]
    pub fn hash2_with_iv(iv: &[u64; 4], a: &Felt, b: &Felt) -> Felt {
        let m = [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
        mask_felt(compress(iv, &m, 64, true))
    }

    #[inline(always)]
    pub fn hash2_generic(a: &Felt, b: &Felt) -> Felt {
        hash2_with_iv(&IV_GENERIC, a, b)
    }

    #[inline(always)]
    pub fn hash2_merkle(a: &Felt, b: &Felt) -> Felt {
        hash2_with_iv(&IV_MERKLE, a, b)
    }

    #[inline(always)]
    pub fn hash3_with_iv(iv: &[u64; 4], a: &Felt, b: &Felt, c: &Felt) -> Felt {
        let m1 = [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
        let s1 = compress(iv, &m1, 64, false);
        let m2 = [c[0], c[1], c[2], c[3], 0, 0, 0, 0];
        mask_felt(compress(&s1, &m2, 96, true))
    }

    #[inline(always)]
    pub fn hash3_generic(a: &Felt, b: &Felt, c: &Felt) -> Felt {
        hash3_with_iv(&IV_GENERIC, a, b, c)
    }

    #[inline(always)]
    pub fn hash4_generic(a: &Felt, b: &Felt, c: &Felt, d: &Felt) -> Felt {
        let m1 = [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
        let s1 = compress(&IV_GENERIC, &m1, 64, false);
        let m2 = [c[0], c[1], c[2], c[3], d[0], d[1], d[2], d[3]];
        mask_felt(compress(&s1, &m2, 128, true))
    }

    #[inline(always)]
    pub fn commit(d_j: &Felt, v: u64, asset: &Felt, rcm: &Felt, otag: &Felt) -> Felt {
        let v_felt = u64_to_felt(v);
        let m1 = [d_j[0], d_j[1], d_j[2], d_j[3], v_felt[0], v_felt[1], v_felt[2], v_felt[3]];
        let s1 = compress(&IV_COMMIT, &m1, 64, false);
        let m2 = [asset[0], asset[1], asset[2], asset[3], rcm[0], rcm[1], rcm[2], rcm[3]];
        let s2 = compress(&s1, &m2, 128, false);
        let m3 = [otag[0], otag[1], otag[2], otag[3], 0, 0, 0, 0];
        mask_felt(compress(&s2, &m3, 160, true))
    }

    #[inline(always)]
    pub fn derive_rcm(rseed: &Felt) -> Felt {
        let rcm_tag = hash1(&u64_to_felt(TAG_RCM));
        hash2_generic(&rcm_tag, rseed)
    }

    #[inline(always)]
    pub fn derive_nk_tag(nk_spend: &Felt) -> Felt {
        hash1_with_iv(&IV_NK_TAG, nk_spend)
    }

    #[inline(always)]
    pub fn owner_tag(auth_root: &Felt, auth_pub_seed: &Felt, nk_tag: &Felt) -> Felt {
        hash3_with_iv(&IV_OWNER, auth_root, auth_pub_seed, nk_tag)
    }

    #[inline(always)]
    pub fn nullifier(nk_spend: &Felt, cm: &Felt, pos: u64) -> Felt {
        let cm_pos = hash2_with_iv(&IV_NULLIFIER, cm, &u64_to_felt(pos));
        hash2_with_iv(&IV_NULLIFIER, nk_spend, &cm_pos)
    }

    #[inline(always)]
    pub fn sighash_fold(a: &Felt, b: &Felt) -> Felt {
        hash2_with_iv(&IV_SIGHASH, a, b)
    }

    #[inline(always)]
    pub const fn pack_adrs(tag: u64, key_idx: u32, a: u32, b: u32, c: u32) -> Felt {
        [
            tag,
            (key_idx as u64) | ((a as u64) << 32),
            (b as u64) | ((c as u64) << 32),
            0,
        ]
    }

    #[inline(always)]
    pub fn xmss_chain_step(
        x: &Felt,
        pub_seed: &Felt,
        key_idx: u32,
        chain_idx: u32,
        step: u32,
    ) -> Felt {
        let adrs = pack_adrs(TAG_XMSS_CHAIN, key_idx, chain_idx, step, 0);
        hash3_generic(pub_seed, &adrs, x)
    }

    #[inline(always)]
    pub fn xmss_node_hash(
        pub_seed: &Felt,
        tag: u64,
        key_idx: u32,
        level: u32,
        node_idx: u32,
        left: &Felt,
        right: &Felt,
    ) -> Felt {
        let adrs = pack_adrs(tag, key_idx, level, node_idx, 0);
        hash4_generic(pub_seed, &adrs, left, right)
    }

    pub fn sighash_to_wots_digits(sighash: &Felt) -> [u8; WOTS_CHAINS] {
        let mut digits = [0u8; WOTS_CHAINS];
        let mut checksum: u32 = 0;
        let mut idx = 0;
        for &word in sighash {
            // Two u32s per u64 in little-endian order, 16 base-4 digits each.
            let mut w = word;
            for _ in 0..32 {
                let d = (w & 3) as u32;
                digits[idx] = d as u8;
                checksum += 3 - d;
                w >>= 2;
                idx += 1;
            }
        }
        let mut cs = checksum;
        for i in 0..5 {
            digits[128 + i] = (cs & 3) as u8;
            cs >>= 2;
        }
        digits
    }

    pub fn xmss_ltree(
        pk_tips: &[Felt; WOTS_CHAINS],
        pub_seed: &Felt,
        key_idx_u32: u32,
    ) -> Felt {
        let mut nodes = *pk_tips;
        let mut len = WOTS_CHAINS;
        let mut level: u32 = 0;
        while len > 1 {
            let pairs = len / 2;
            for node_idx in 0..pairs {
                nodes[node_idx] = xmss_node_hash(
                    pub_seed,
                    TAG_XMSS_LTREE,
                    key_idx_u32,
                    level,
                    node_idx as u32,
                    &nodes[2 * node_idx],
                    &nodes[2 * node_idx + 1],
                );
            }
            if len & 1 == 1 {
                nodes[pairs] = nodes[len - 1];
                len = pairs + 1;
            } else {
                len = pairs;
            }
            level += 1;
        }
        nodes[0]
    }

    pub fn xmss_verify(
        sighash: &Felt,
        auth_root: &Felt,
        pub_seed: &Felt,
        key_idx: u64,
        wots_sig: &[Felt; WOTS_CHAINS],
        auth_siblings: &[Felt; AUTH_DEPTH],
    ) -> Result<(), TzelError> {
        if key_idx >= (1u64 << AUTH_DEPTH) {
            return Err(TzelError::XmssKeyIndexOutOfRange);
        }
        let key_idx_u32 = key_idx as u32;
        let digits = sighash_to_wots_digits(sighash);

        let mut nodes = [ZERO; WOTS_CHAINS];
        for j in 0..WOTS_CHAINS {
            let mut cur = wots_sig[j];
            let mut step = u32::from(digits[j]);
            while step < WOTS_W - 1 {
                cur = xmss_chain_step(&cur, pub_seed, key_idx_u32, j as u32, step);
                step += 1;
            }
            nodes[j] = cur;
        }

        let mut current = xmss_ltree(&nodes, pub_seed, key_idx_u32);
        let mut idx = key_idx_u32;
        for (lvl, sibling) in auth_siblings.iter().enumerate() {
            let node_idx = idx >> 1;
            if idx & 1 == 1 {
                current = xmss_node_hash(
                    pub_seed,
                    TAG_XMSS_TREE,
                    0,
                    lvl as u32,
                    node_idx,
                    sibling,
                    &current,
                );
            } else {
                current = xmss_node_hash(
                    pub_seed,
                    TAG_XMSS_TREE,
                    0,
                    lvl as u32,
                    node_idx,
                    &current,
                    sibling,
                );
            }
            idx >>= 1;
        }
        if &current != auth_root {
            return Err(TzelError::XmssAuthRootMismatch);
        }
        Ok(())
    }

    pub fn merkle_verify(
        leaf: &Felt,
        root: &Felt,
        siblings: &[Felt; TREE_DEPTH],
        path_indices: u64,
    ) -> Result<(), TzelError> {
        if path_indices >= (1u64 << TREE_DEPTH) {
            return Err(TzelError::MerkleIndexOutOfRange);
        }
        let mut current = *leaf;
        let mut idx = path_indices;
        for sibling in siblings {
            if idx & 1 == 1 {
                current = hash2_merkle(sibling, &current);
            } else {
                current = hash2_merkle(&current, sibling);
            }
            idx >>= 1;
        }
        if &current != root {
            return Err(TzelError::MerkleRootMismatch);
        }
        Ok(())
    }

    /// TzEL Multiasset Shield Witness (`cairo/src/shield.cairo`).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ShieldTx {
        pub auth_domain: Felt,
        pub pubkey_hash: Felt,
        pub v_note: u64,
        pub fee: u64,
        pub producer_fee: u64,
        pub cm_new: Felt,
        pub cm_producer: Felt,
        pub memo_ct_hash: Felt,
        pub producer_memo_ct_hash: Felt,
        pub auth_root: Felt,
        pub auth_pub_seed: Felt,
        pub nk_tag: Felt,
        pub d_j: Felt,
        pub rseed: Felt,
        pub blind: Felt,
        pub auth_idx: u64,
        pub wots_sig: [Felt; WOTS_CHAINS],
        pub auth_siblings: [Felt; AUTH_DEPTH],
        pub producer_auth_root: Felt,
        pub producer_auth_pub_seed: Felt,
        pub producer_nk_tag: Felt,
        pub producer_d_j: Felt,
        pub producer_rseed: Felt,
        pub asset_new: Felt,
        pub asset_producer: Felt,
    }

    // SAFETY: `repr(C)` of `u64` words throughout with no padding.
    unsafe impl Words for ShieldTx {}

    impl ShieldTx {
        pub fn verify(&self) -> Result<[Felt; 10], TzelError> {
            if self.asset_producer != ASSET_TEZ {
                return Err(TzelError::ProducerAssetNotTez);
            }
            if self.producer_fee == 0 {
                return Err(TzelError::ProducerFeeZero);
            }

            let otag = owner_tag(&self.auth_root, &self.auth_pub_seed, &self.nk_tag);
            let rcm = derive_rcm(&self.rseed);
            if commit(&self.d_j, self.v_note, &self.asset_new, &rcm, &otag) != self.cm_new {
                return Err(TzelError::BadCommitment);
            }

            let prod_otag = owner_tag(
                &self.producer_auth_root,
                &self.producer_auth_pub_seed,
                &self.producer_nk_tag,
            );
            let prod_rcm = derive_rcm(&self.producer_rseed);
            if commit(
                &self.producer_d_j,
                self.producer_fee,
                &self.asset_producer,
                &prod_rcm,
                &prod_otag,
            ) != self.cm_producer
            {
                return Err(TzelError::BadProducerCommitment);
            }

            let mut pkh = sighash_fold(&u64_to_felt(0x04), &self.auth_domain);
            pkh = sighash_fold(&pkh, &self.auth_root);
            pkh = sighash_fold(&pkh, &self.auth_pub_seed);
            pkh = sighash_fold(&pkh, &self.blind);
            if pkh != self.pubkey_hash {
                return Err(TzelError::BadPubkeyHash);
            }

            let mut sighash = sighash_fold(&u64_to_felt(0x03), &self.auth_domain);
            sighash = sighash_fold(&sighash, &self.pubkey_hash);
            sighash = sighash_fold(&sighash, &u64_to_felt(self.v_note));
            sighash = sighash_fold(&sighash, &u64_to_felt(self.fee));
            sighash = sighash_fold(&sighash, &u64_to_felt(self.producer_fee));
            sighash = sighash_fold(&sighash, &self.asset_new);
            sighash = sighash_fold(&sighash, &self.asset_producer);
            sighash = sighash_fold(&sighash, &self.cm_new);
            sighash = sighash_fold(&sighash, &self.cm_producer);
            sighash = sighash_fold(&sighash, &self.memo_ct_hash);
            sighash = sighash_fold(&sighash, &self.producer_memo_ct_hash);

            xmss_verify(
                &sighash,
                &self.auth_root,
                &self.auth_pub_seed,
                self.auth_idx,
                &self.wots_sig,
                &self.auth_siblings,
            )?;

            Ok([
                self.auth_domain,
                self.pubkey_hash,
                u64_to_felt(self.v_note),
                u64_to_felt(self.fee),
                u64_to_felt(self.producer_fee),
                self.cm_new,
                self.cm_producer,
                self.memo_ct_hash,
                self.producer_memo_ct_hash,
                self.asset_new,
            ])
        }
    }

    /// Per-input note witness for `Transfer` and `Unshield`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct InputNoteWitness {
        pub nf: Felt,
        pub nk_spend: Felt,
        pub auth_root: Felt,
        pub auth_pub_seed: Felt,
        pub auth_idx: u64,
        pub d_j: Felt,
        pub v: u64,
        pub rseed: Felt,
        pub cm_path_idx: u64,
        pub asset: Felt,
        pub cm_siblings: [Felt; TREE_DEPTH],
        pub auth_siblings: [Felt; AUTH_DEPTH],
        pub wots_sig: [Felt; WOTS_CHAINS],
    }

    // SAFETY: `repr(C)` of `u64` words throughout with no padding.
    unsafe impl Words for InputNoteWitness {}

    impl InputNoteWitness {
        pub fn verify(
            &self,
            root: &Felt,
            sighash: &Felt,
            primary_non_tez_asset: &Felt,
        ) -> Result<(u128, u128), TzelError> {
            if self.asset != ASSET_TEZ && &self.asset != primary_non_tez_asset {
                return Err(TzelError::BadAsset);
            }
            let nk_tag = derive_nk_tag(&self.nk_spend);
            let otag = owner_tag(&self.auth_root, &self.auth_pub_seed, &nk_tag);
            let rcm = derive_rcm(&self.rseed);
            let cm = commit(&self.d_j, self.v, &self.asset, &rcm, &otag);

            merkle_verify(&cm, root, &self.cm_siblings, self.cm_path_idx)?;
            xmss_verify(
                sighash,
                &self.auth_root,
                &self.auth_pub_seed,
                self.auth_idx,
                &self.wots_sig,
                &self.auth_siblings,
            )?;

            if nullifier(&self.nk_spend, &cm, self.cm_path_idx) != self.nf {
                return Err(TzelError::BadNullifier);
            }
            if self.asset == ASSET_TEZ {
                Ok((u128::from(self.v), 0))
            } else {
                Ok((0, u128::from(self.v)))
            }
        }
    }

    /// Output note witness for `Transfer` (`4` outputs: recipient, change_1, change_2, producer_fee).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct OutputNoteWitness {
        pub cm: Felt,
        pub d_j: Felt,
        pub v: u64,
        pub rseed: Felt,
        pub auth_root: Felt,
        pub auth_pub_seed: Felt,
        pub nk_tag: Felt,
        pub memo_ct_hash: Felt,
        pub asset: Felt,
    }

    // SAFETY: `repr(C)` of `u64` words throughout with no padding.
    unsafe impl Words for OutputNoteWitness {}

    impl OutputNoteWitness {
        pub fn verify(&self, primary_non_tez_asset: &Felt) -> Result<(u128, u128), TzelError> {
            if self.asset != ASSET_TEZ && &self.asset != primary_non_tez_asset {
                return Err(TzelError::BadAsset);
            }
            let rcm = derive_rcm(&self.rseed);
            let otag = owner_tag(&self.auth_root, &self.auth_pub_seed, &self.nk_tag);
            if commit(&self.d_j, self.v, &self.asset, &rcm, &otag) != self.cm {
                return Err(TzelError::BadCommitment);
            }
            if self.asset == ASSET_TEZ {
                Ok((u128::from(self.v), 0))
            } else {
                Ok((0, u128::from(self.v)))
            }
        }
    }

    /// TzEL Multiasset Transfer Header (`cairo/src/transfer.cairo`, `N -> 4`).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TransferHeader {
        pub n_inputs: u64,
        pub auth_domain: Felt,
        pub root: Felt,
        pub fee: u64,
        pub primary_non_tez_asset: Felt,
        pub outputs: [OutputNoteWitness; 4],
    }

    // SAFETY: `repr(C)` of `u64` words throughout with no padding.
    unsafe impl Words for TransferHeader {}

    impl TransferHeader {
        pub fn verify(&self, inputs: &[InputNoteWitness]) -> Result<(), TzelError> {
            let n = inputs.len();
            if n == 0 || n > MAX_INPUTS || n as u64 != self.n_inputs {
                return Err(TzelError::BadInputCount);
            }
            if self.outputs[3].asset != ASSET_TEZ {
                return Err(TzelError::ProducerAssetNotTez);
            }
            if self.outputs[3].v == 0 {
                return Err(TzelError::ProducerFeeZero);
            }

            let mut sighash = sighash_fold(&u64_to_felt(0x01), &self.auth_domain);
            sighash = sighash_fold(&sighash, &self.root);
            for inp in inputs {
                sighash = sighash_fold(&sighash, &inp.nf);
            }
            sighash = sighash_fold(&sighash, &u64_to_felt(self.fee));
            for out in &self.outputs {
                sighash = sighash_fold(&sighash, &out.cm);
            }
            for out in &self.outputs {
                sighash = sighash_fold(&sighash, &out.memo_ct_hash);
            }

            let mut tez_in: u128 = 0;
            let mut primary_in: u128 = 0;
            for i in 0..n {
                for j in 0..i {
                    if inputs[i].nf == inputs[j].nf {
                        return Err(TzelError::DuplicateNullifier);
                    }
                }
                let (t, p) = inputs[i].verify(&self.root, &sighash, &self.primary_non_tez_asset)?;
                tez_in += t;
                primary_in += p;
            }

            let mut tez_out: u128 = 0;
            let mut primary_out: u128 = 0;
            for out in &self.outputs {
                let (t, p) = out.verify(&self.primary_non_tez_asset)?;
                tez_out += t;
                primary_out += p;
            }

            if tez_in != tez_out + u128::from(self.fee) {
                return Err(TzelError::TezBalanceMismatch);
            }
            if primary_in != primary_out {
                return Err(TzelError::PrimaryBalanceMismatch);
            }
            Ok(())
        }
    }

    /// Optional change slot in `Unshield` (`change_1` or `change_2`).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct UnshieldChangeSlot {
        pub has_change: u64,
        pub d_j: Felt,
        pub v: u64,
        pub rseed: Felt,
        pub auth_root: Felt,
        pub auth_pub_seed: Felt,
        pub nk_tag: Felt,
        pub memo_ct_hash: Felt,
        pub asset: Felt,
    }

    // SAFETY: `repr(C)` of `u64` words throughout with no padding.
    unsafe impl Words for UnshieldChangeSlot {}

    impl UnshieldChangeSlot {
        pub fn commitment_or_zero(
            &self,
            primary_non_tez_asset: &Felt,
        ) -> Result<(Felt, u128, u128), TzelError> {
            if self.asset != ASSET_TEZ && &self.asset != primary_non_tez_asset {
                return Err(TzelError::BadAsset);
            }
            if self.has_change != 0 {
                let rcm = derive_rcm(&self.rseed);
                let otag = owner_tag(&self.auth_root, &self.auth_pub_seed, &self.nk_tag);
                let cm = commit(&self.d_j, self.v, &self.asset, &rcm, &otag);
                if self.asset == ASSET_TEZ {
                    Ok((cm, u128::from(self.v), 0))
                } else {
                    Ok((cm, 0, u128::from(self.v)))
                }
            } else {
                if self.v != 0
                    || self.memo_ct_hash != ZERO
                    || self.d_j != ZERO
                    || self.rseed != ZERO
                    || self.auth_root != ZERO
                    || self.auth_pub_seed != ZERO
                    || self.nk_tag != ZERO
                    || self.asset != ZERO
                {
                    return Err(TzelError::BadDisabledChangeSlot);
                }
                Ok((ZERO, 0, 0))
            }
        }
    }

    /// TzEL Multiasset Unshield Header (`cairo/src/unshield.cairo`).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct UnshieldHeader {
        pub n_inputs: u64,
        pub auth_domain: Felt,
        pub root: Felt,
        pub v_pub: u64,
        pub asset_pub: Felt,
        pub fee: u64,
        pub recipient: Felt,
        pub primary_non_tez_asset: Felt,
        pub change_1: UnshieldChangeSlot,
        pub change_2: UnshieldChangeSlot,
        pub fee_note: OutputNoteWitness,
    }

    // SAFETY: `repr(C)` of `u64` words throughout with no padding.
    unsafe impl Words for UnshieldHeader {}

    impl UnshieldHeader {
        pub fn verify(&self, inputs: &[InputNoteWitness]) -> Result<(Felt, Felt, Felt), TzelError> {
            let n = inputs.len();
            if n == 0 || n > MAX_INPUTS || n as u64 != self.n_inputs {
                return Err(TzelError::BadInputCount);
            }
            if self.fee_note.asset != ASSET_TEZ {
                return Err(TzelError::ProducerAssetNotTez);
            }
            if self.fee_note.v == 0 {
                return Err(TzelError::ProducerFeeZero);
            }
            if self.v_pub == 0 {
                return Err(TzelError::PublicAmountZero);
            }
            if self.asset_pub != ASSET_TEZ && self.asset_pub != self.primary_non_tez_asset {
                return Err(TzelError::BadAsset);
            }

            let (cm_change_1, tez_c1, pri_c1) =
                self.change_1.commitment_or_zero(&self.primary_non_tez_asset)?;
            let (cm_change_2, tez_c2, pri_c2) =
                self.change_2.commitment_or_zero(&self.primary_non_tez_asset)?;
            let (tez_fee, _) = self.fee_note.verify(&self.primary_non_tez_asset)?;

            let mut sighash = sighash_fold(&u64_to_felt(0x02), &self.auth_domain);
            sighash = sighash_fold(&sighash, &self.root);
            for inp in inputs {
                sighash = sighash_fold(&sighash, &inp.nf);
            }
            sighash = sighash_fold(&sighash, &u64_to_felt(self.v_pub));
            sighash = sighash_fold(&sighash, &self.asset_pub);
            sighash = sighash_fold(&sighash, &u64_to_felt(self.fee));
            sighash = sighash_fold(&sighash, &self.recipient);
            sighash = sighash_fold(&sighash, &cm_change_1);
            sighash = sighash_fold(&sighash, &self.change_1.memo_ct_hash);
            sighash = sighash_fold(&sighash, &cm_change_2);
            sighash = sighash_fold(&sighash, &self.change_2.memo_ct_hash);
            sighash = sighash_fold(&sighash, &self.fee_note.cm);
            sighash = sighash_fold(&sighash, &self.fee_note.memo_ct_hash);

            let mut tez_in: u128 = 0;
            let mut primary_in: u128 = 0;
            for i in 0..n {
                for j in 0..i {
                    if inputs[i].nf == inputs[j].nf {
                        return Err(TzelError::DuplicateNullifier);
                    }
                }
                let (t, p) = inputs[i].verify(&self.root, &sighash, &self.primary_non_tez_asset)?;
                tez_in += t;
                primary_in += p;
            }

            let mut tez_out = tez_fee + tez_c1 + tez_c2;
            let mut primary_out = pri_c1 + pri_c2;
            if self.asset_pub == ASSET_TEZ {
                tez_out += u128::from(self.v_pub);
            } else {
                primary_out += u128::from(self.v_pub);
            }

            if tez_in != tez_out + u128::from(self.fee) {
                return Err(TzelError::TezBalanceMismatch);
            }
            if primary_in != primary_out {
                return Err(TzelError::PrimaryBalanceMismatch);
            }

            Ok((cm_change_1, cm_change_2, self.fee_note.cm))
        }
    }
}
