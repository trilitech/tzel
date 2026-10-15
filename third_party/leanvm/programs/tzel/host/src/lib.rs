//! Host witness builders, keygen, signing, and test suite for TzEL Multiasset circuits on `leanVM`.

pub use leanvm_guest::Run;
use leanvm_guest::{PublicValues, as_words_unchecked};
pub use tzel_guest::{
    ASSET_TEZ, Felt, OpTag, PROGRAM_HASH_SHIELD, PROGRAM_HASH_TRANSFER, PROGRAM_HASH_UNSHIELD,
    ZERO,
    exact::{
        self, AUTH_DEPTH as EXACT_AUTH_DEPTH, InputNoteWitness, OutputNoteWitness, ShieldTx,
        TREE_DEPTH as EXACT_TREE_DEPTH, TransferHeader, UnshieldChangeSlot, UnshieldHeader,
        WOTS_CHAINS, WOTS_W,
    },
    u64_to_felt,
};

/// Convert a `Felt` (`[u64; 4]` LE) to a 32-byte little-endian array (`tzel_core::F`).
pub fn felt_to_bytes_le(f: &Felt) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in f.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Convert a 32-byte little-endian array (`tzel_core::F`) to a `Felt` (`[u64; 4]` LE).
pub fn felt_from_bytes_le(b: &[u8; 32]) -> Felt {
    std::array::from_fn(|i| u64::from_le_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap()))
}

/// Wrap raw circuit public outputs in the 4-element single-task bootloader header
/// expected by `tzel_core::parse_single_task_output_preimage` and `transition_public_outputs`.
pub fn wrap_bootloader_output_preimage(program_hash: Felt, public_outputs: &[Felt]) -> Vec<Felt> {
    let k = public_outputs.len();
    let mut out = Vec::with_capacity(4 + k);
    out.push(u64_to_felt(1));
    out.push(u64_to_felt((3 + k) as u64));
    out.push(program_hash);
    out.push(u64_to_felt(k as u64));
    out.extend_from_slice(public_outputs);
    out
}

/// Validate the 4-element bootloader header and compute the `leanVM` `PublicValues` digest
/// for a full `output_preimage` slice (`[1, 3 + k, program_hash, k, public_outputs...]`).
pub fn validate_and_digest_preimage(output_preimage: &[Felt]) -> Result<[u64; 4], String> {
    if output_preimage.len() < 5 {
        return Err("output_preimage too short".into());
    }
    let k = output_preimage.len() - 4;
    if output_preimage[0] != u64_to_felt(1) {
        return Err("invalid bootloader task count in output_preimage".into());
    }
    if output_preimage[1] != u64_to_felt((3 + k) as u64) {
        return Err("invalid bootloader task output size in output_preimage".into());
    }
    if output_preimage[3] != u64_to_felt(k as u64) {
        return Err("invalid public output array length in output_preimage".into());
    }
    let prog = output_preimage[2];
    let pub_outs = &output_preimage[4..];
    let is_u64_felt = |f: &Felt| f[1] == 0 && f[2] == 0 && f[3] == 0;
    let valid_prog = if prog == PROGRAM_HASH_SHIELD {
        k == 10
            && is_u64_felt(&pub_outs[2])
            && is_u64_felt(&pub_outs[3])
            && is_u64_felt(&pub_outs[4])
    } else if prog == PROGRAM_HASH_TRANSFER {
        (12..=16).contains(&k) && is_u64_felt(&pub_outs[k - 9])
    } else if prog == PROGRAM_HASH_UNSHIELD {
        (13..=17).contains(&k)
            && is_u64_felt(&pub_outs[k - 10])
            && pub_outs[k - 10][0] > 0
            && is_u64_felt(&pub_outs[k - 8])
    } else {
        false
    };
    if !valid_prog {
        return Err("unknown or mismatched leanVM program hash in output_preimage".into());
    }
    let mut public = PublicValues::new();
    for felt in output_preimage {
        public.commit(felt);
    }
    Ok(public.digest())
}

/// Compute the `leanVM` `PublicValues` digest for an `output_preimage` slice of `Felt`s.
pub fn public_digest_for_preimage(output_preimage: &[Felt]) -> [u64; 4] {
    validate_and_digest_preimage(output_preimage).expect("valid output_preimage")
}

/// Embedded RV64IM guest ELF (`../tzel.elf`).
pub const ELF: &[u8] = include_bytes!("../../tzel.elf");

/// Example non-tez FA2 asset tag (`asset_id != ASSET_TEZ`).
pub const FA2_ASSET_FELT: Felt = [0xFA20_0001_CAFE_BABE, 0x1234_5678_9ABC_DEF0, 0x1111_2222, 0x0123];

// ============================================================================
// 1. TzEL-Exact Host Keygen, Signing, Merkle & Witness Builders
// ============================================================================

const TAG_XMSS_TREE: u64 = 0x0072_742D_7373_6D78;
const TAG_PRF: u64 = 0x0066_7270_7373_6D78;

/// Single-leaf TzEL-Exact XMSS keypair (real leaf at `auth_idx`, deterministic filler siblings).
#[derive(Clone)]
pub struct ExactXmssKey {
    pub sk_seed: Felt,
    pub pub_seed: Felt,
    pub auth_idx: u32,
    pub auth_siblings: [Felt; EXACT_AUTH_DEPTH],
    pub auth_root: Felt,
}

impl ExactXmssKey {
    pub fn generate(seed: u64, auth_idx: u32) -> Self {
        let sk_seed = exact::hash1(&[seed, 0xA11CE, 0, 0]);
        let pub_seed = exact::hash1(&[seed, 0xB0B, 0, 0]);
        let mut pk_tips = [ZERO; WOTS_CHAINS];
        for (c, tip) in pk_tips.iter_mut().enumerate() {
            let sk_c = Self::chain_secret(&sk_seed, &pub_seed, auth_idx, c as u32);
            let mut cur = sk_c;
            for step in 0..(WOTS_W - 1) {
                cur = exact::xmss_chain_step(&cur, &pub_seed, auth_idx, c as u32, step);
            }
            *tip = cur;
        }
        let leaf = exact::xmss_ltree(&pk_tips, &pub_seed, auth_idx);
        let auth_siblings: [Felt; EXACT_AUTH_DEPTH] = std::array::from_fn(|lvl| {
            exact::hash2_generic(&sk_seed, &[0xF111_E000 + lvl as u64, u64::from(auth_idx), 0, 0])
        });
        let mut current = leaf;
        let mut node_idx = auth_idx;
        for (lvl, sib) in auth_siblings.iter().enumerate() {
            let bit = node_idx & 1;
            node_idx >>= 1;
            current = if bit == 0 {
                exact::xmss_node_hash(&pub_seed, TAG_XMSS_TREE, 0, lvl as u32, node_idx, &current, sib)
            } else {
                exact::xmss_node_hash(&pub_seed, TAG_XMSS_TREE, 0, lvl as u32, node_idx, sib, &current)
            };
        }
        Self {
            sk_seed,
            pub_seed,
            auth_idx,
            auth_siblings,
            auth_root: current,
        }
    }

    fn chain_secret(sk_seed: &Felt, pub_seed: &Felt, key_idx: u32, chain_idx: u32) -> Felt {
        let adrs = exact::pack_adrs(TAG_PRF, key_idx, chain_idx, 0, 0);
        exact::hash3_generic(pub_seed, &adrs, sk_seed)
    }

    pub fn sign(&self, sighash: &Felt) -> [Felt; WOTS_CHAINS] {
        let digits = exact::sighash_to_wots_digits(sighash);
        std::array::from_fn(|c| {
            let d = u32::from(digits[c]);
            let mut cur = Self::chain_secret(&self.sk_seed, &self.pub_seed, self.auth_idx, c as u32);
            for step in 0..d {
                cur = exact::xmss_chain_step(&cur, &self.pub_seed, self.auth_idx, c as u32, step);
            }
            cur
        })
    }
}

fn exact_merkle_path(subtree_root_lvl3: &Felt, pos: u64, seed: u64) -> (Felt, [Felt; EXACT_TREE_DEPTH]) {
    let siblings: [Felt; EXACT_TREE_DEPTH] = std::array::from_fn(|lvl| {
        exact::hash1(&[seed, pos, lvl as u64, 0xABCD])
    });
    let mut current = *subtree_root_lvl3;
    let mut idx = pos >> 3;
    for sib in siblings.iter().skip(3) {
        let bit = idx & 1;
        idx >>= 1;
        current = if bit == 0 {
            exact::hash2_merkle(&current, sib)
        } else {
            exact::hash2_merkle(sib, &current)
        };
    }
    (current, siblings)
}

/// Build a valid TzEL-Exact `ShieldTx` witness (`asset_new` can be `ASSET_TEZ` or an FA2 asset).
pub fn build_exact_shield(asset_new: Felt) -> (ShieldTx, Run) {
    let key = ExactXmssKey::generate(101, 7);
    let auth_domain = exact::hash1(&[0xD00D_0001, 0, 0, 0]);
    let nk_spend = exact::hash1(&[0x7777, 1, 0, 0]);
    let nk_tag = exact::derive_nk_tag(&nk_spend);
    let d_j = exact::hash1(&[0x8888, 1, 0, 0]);
    let rseed = exact::hash1(&[0x9999, 1, 0, 0]);
    let blind = exact::hash1(&[0xAAAA, 1, 0, 0]);

    let v_note: u64 = 1_000_000;
    let fee: u64 = 100_000;
    let producer_fee: u64 = 50_000;
    let asset_producer = ASSET_TEZ;

    let otag = exact::owner_tag(&key.auth_root, &key.pub_seed, &nk_tag);
    let rcm = exact::derive_rcm(&rseed);
    let cm_new = exact::commit(&d_j, v_note, &asset_new, &rcm, &otag);

    let producer_auth_root = exact::hash1(&[0xBBBB, 1, 0, 0]);
    let producer_auth_pub_seed = exact::hash1(&[0xBBBB, 2, 0, 0]);
    let producer_nk_tag = exact::hash1(&[0xBBBB, 3, 0, 0]);
    let producer_d_j = exact::hash1(&[0xBBBB, 4, 0, 0]);
    let producer_rseed = exact::hash1(&[0xBBBB, 5, 0, 0]);
    let prod_otag = exact::owner_tag(&producer_auth_root, &producer_auth_pub_seed, &producer_nk_tag);
    let prod_rcm = exact::derive_rcm(&producer_rseed);
    let cm_producer = exact::commit(&producer_d_j, producer_fee, &asset_producer, &prod_rcm, &prod_otag);

    let memo_ct_hash = exact::hash1(&[0xCCCC, 1, 0, 0]);
    let producer_memo_ct_hash = exact::hash1(&[0xCCCC, 2, 0, 0]);

    let mut pubkey_hash = exact::sighash_fold(&u64_to_felt(0x04), &auth_domain);
    pubkey_hash = exact::sighash_fold(&pubkey_hash, &key.auth_root);
    pubkey_hash = exact::sighash_fold(&pubkey_hash, &key.pub_seed);
    pubkey_hash = exact::sighash_fold(&pubkey_hash, &blind);

    let mut sighash = exact::sighash_fold(&u64_to_felt(0x03), &auth_domain);
    sighash = exact::sighash_fold(&sighash, &pubkey_hash);
    sighash = exact::sighash_fold(&sighash, &u64_to_felt(v_note));
    sighash = exact::sighash_fold(&sighash, &u64_to_felt(fee));
    sighash = exact::sighash_fold(&sighash, &u64_to_felt(producer_fee));
    sighash = exact::sighash_fold(&sighash, &asset_new);
    sighash = exact::sighash_fold(&sighash, &asset_producer);
    sighash = exact::sighash_fold(&sighash, &cm_new);
    sighash = exact::sighash_fold(&sighash, &cm_producer);
    sighash = exact::sighash_fold(&sighash, &memo_ct_hash);
    sighash = exact::sighash_fold(&sighash, &producer_memo_ct_hash);

    let wots_sig = key.sign(&sighash);

    let tx = ShieldTx {
        auth_domain,
        pubkey_hash,
        v_note,
        fee,
        producer_fee,
        cm_new,
        cm_producer,
        memo_ct_hash,
        producer_memo_ct_hash,
        auth_root: key.auth_root,
        auth_pub_seed: key.pub_seed,
        nk_tag,
        d_j,
        rseed,
        blind,
        auth_idx: u64::from(key.auth_idx),
        wots_sig,
        auth_siblings: key.auth_siblings,
        producer_auth_root,
        producer_auth_pub_seed,
        producer_nk_tag,
        producer_d_j,
        producer_rseed,
        asset_new,
        asset_producer,
    };

    let out = tx.verify().expect("valid exact shield");
    let mut advice = vec![OpTag::ExactShield as u64];
    advice.extend(unsafe { as_words_unchecked(&tx) });
    let preimage = wrap_bootloader_output_preimage(PROGRAM_HASH_SHIELD, &out);
    (
        tx,
        Run {
            advice,
            expected: public_digest_for_preimage(&preimage),
        },
    )
}

/// Build a valid TzEL-Exact `Transfer (N -> 4)` witness.
/// When `mixed_fa2` is true (`n_inputs >= 2`), input 0 is FA2 (`FA2_ASSET_FELT`) and remaining inputs are `ASSET_TEZ`.
pub fn build_exact_transfer(
    n_inputs: usize,
    mixed_fa2: bool,
) -> (TransferHeader, Vec<InputNoteWitness>, Run) {
    assert!((1..=tzel_guest::MAX_INPUTS).contains(&n_inputs));
    let auth_domain = exact::hash1(&[0xD00D_0002, 0, 0, 0]);
    let fee: u64 = 100_000;
    let producer_fee: u64 = 50_000;
    let primary_non_tez_asset = if mixed_fa2 { FA2_ASSET_FELT } else { ASSET_TEZ };

    // Build inputs first (without signatures yet, since sighash binds all nullifiers & output commitments).
    // If mixed_fa2 && n_inputs >= 2: input 0 has 500_000 FA2, inputs 1..n have 1_000_000 tez each.
    // Otherwise: all inputs have 1_000_000 tez each.
    let mut keys = Vec::with_capacity(n_inputs);
    let mut inputs = Vec::with_capacity(n_inputs);
    let mut tez_in: u64 = 0;
    let mut fa2_in: u64 = 0;

    // Shared Merkle root: we build input 0's path to determine `root`, and for inputs 1..n we set their
    // top sibling so they also fold to the exact same `root` (or build a small binary tree at top levels).
    // Even simpler: a small subtree at top 3 levels (depth 45..48) so all `n_inputs <= 7` share one exact `root`!
    let mut leaf_cms = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let key = ExactXmssKey::generate(200 + i as u64, (10 + i) as u32);
        let nk_spend = exact::hash1(&[0x5000 + i as u64, 0, 0, 0]);
        let nk_tag = exact::derive_nk_tag(&nk_spend);
        let d_j = exact::hash1(&[0x6000 + i as u64, 0, 0, 0]);
        let rseed = exact::hash1(&[0x7000 + i as u64, 0, 0, 0]);
        let (v, asset) = if mixed_fa2 && i + 1 < n_inputs {
            fa2_in += 500_000;
            (500_000u64, FA2_ASSET_FELT)
        } else {
            tez_in += 1_000_000;
            (1_000_000u64, ASSET_TEZ)
        };
        let otag = exact::owner_tag(&key.auth_root, &key.pub_seed, &nk_tag);
        let rcm = exact::derive_rcm(&rseed);
        let cm = exact::commit(&d_j, v, &asset, &rcm, &otag);
        leaf_cms.push((key, nk_spend, d_j, v, rseed, asset, cm));
    }

    // Place leaf `i` at index `i` in a shared depth-48 Merkle tree.
    let mut level_nodes = [ZERO; 8];
    for (i, entry) in leaf_cms.iter().enumerate() {
        level_nodes[i] = entry.6;
    }
    let mut low_siblings = [[ZERO; 3]; 8];
    let mut cur_level = level_nodes.to_vec();
    for lvl in 0..3 {
        for i in 0..8 {
            let idx_at_lvl = i >> lvl;
            low_siblings[i][lvl] = cur_level[idx_at_lvl ^ 1];
        }
        let mut next = Vec::with_capacity(cur_level.len() / 2);
        for pair in cur_level.chunks(2) {
            next.push(exact::hash2_merkle(&pair[0], &pair[1]));
        }
        cur_level = next;
    }
    let subtree_root = cur_level[0];
    let (root, upper_siblings) = exact_merkle_path(&subtree_root, 0, 999);

    for (i, (key, nk_spend, d_j, v, rseed, asset, cm)) in leaf_cms.into_iter().enumerate() {
        let cm_path_idx = i as u64;
        let nf = exact::nullifier(&nk_spend, &cm, cm_path_idx);
        let cm_siblings: [Felt; EXACT_TREE_DEPTH] = std::array::from_fn(|lvl| {
            if lvl < 3 {
                low_siblings[i][lvl]
            } else {
                upper_siblings[lvl]
            }
        });
        keys.push(key.clone());
        inputs.push(InputNoteWitness {
            nf,
            nk_spend,
            auth_root: key.auth_root,
            auth_pub_seed: key.pub_seed,
            auth_idx: u64::from(key.auth_idx),
            d_j,
            v,
            rseed,
            cm_path_idx,
            asset,
            cm_siblings,
            auth_siblings: key.auth_siblings,
            wots_sig: [ZERO; WOTS_CHAINS],
        });
    }

    // Build 4 outputs:
    // If mixed_fa2:
    //   out[0] = recipient FA2 (300_000)
    //   out[1] = change_1 FA2 (fa2_in - 300_000 = 200_000)
    //   out[2] = change_2 tez (tez_in - fee - producer_fee)
    //   out[3] = producer_fee tez (50_000)
    // Else:
    //   out[0] = recipient tez (400_000)
    //   out[1] = change_1 tez (tez_in - 400_000 - fee - producer_fee)
    //   out[2] = change_2 tez (0)
    //   out[3] = producer_fee tez (50_000)
    let out_specs: [(u64, Felt); 4] = if mixed_fa2 {
        [
            (300_000, FA2_ASSET_FELT),
            (fa2_in - 300_000, FA2_ASSET_FELT),
            (tez_in - fee - producer_fee, ASSET_TEZ),
            (producer_fee, ASSET_TEZ),
        ]
    } else {
        [
            (400_000, ASSET_TEZ),
            (tez_in - 400_000 - fee - producer_fee, ASSET_TEZ),
            (0, ASSET_TEZ),
            (producer_fee, ASSET_TEZ),
        ]
    };

    let outputs: [OutputNoteWitness; 4] = std::array::from_fn(|k| {
        let (v, asset) = out_specs[k];
        let d_j = exact::hash1(&[0x8100 + k as u64, 0, 0, 0]);
        let rseed = exact::hash1(&[0x8200 + k as u64, 0, 0, 0]);
        let auth_root = exact::hash1(&[0x8300 + k as u64, 0, 0, 0]);
        let auth_pub_seed = exact::hash1(&[0x8400 + k as u64, 0, 0, 0]);
        let nk_tag = exact::hash1(&[0x8500 + k as u64, 0, 0, 0]);
        let memo_ct_hash = exact::hash1(&[0x8600 + k as u64, 0, 0, 0]);
        let rcm = exact::derive_rcm(&rseed);
        let otag = exact::owner_tag(&auth_root, &auth_pub_seed, &nk_tag);
        let cm = exact::commit(&d_j, v, &asset, &rcm, &otag);
        OutputNoteWitness {
            cm,
            d_j,
            v,
            rseed,
            auth_root,
            auth_pub_seed,
            nk_tag,
            memo_ct_hash,
            asset,
        }
    });

    let mut sighash = exact::sighash_fold(&u64_to_felt(0x01), &auth_domain);
    sighash = exact::sighash_fold(&sighash, &root);
    for inp in &inputs {
        sighash = exact::sighash_fold(&sighash, &inp.nf);
    }
    sighash = exact::sighash_fold(&sighash, &u64_to_felt(fee));
    for out in &outputs {
        sighash = exact::sighash_fold(&sighash, &out.cm);
    }
    for out in &outputs {
        sighash = exact::sighash_fold(&sighash, &out.memo_ct_hash);
    }

    for (inp, key) in inputs.iter_mut().zip(keys.iter()) {
        inp.wots_sig = key.sign(&sighash);
    }

    let hdr = TransferHeader {
        n_inputs: n_inputs as u64,
        auth_domain,
        root,
        fee,
        primary_non_tez_asset,
        outputs,
    };

    hdr.verify(&inputs).expect("valid exact transfer");

    let mut advice = vec![OpTag::ExactTransfer as u64];
    advice.extend(unsafe { as_words_unchecked(&hdr) });
    for inp in &inputs {
        advice.extend(unsafe { as_words_unchecked(inp) });
    }

    let mut pub_outputs = Vec::with_capacity(11 + inputs.len());
    pub_outputs.push(hdr.auth_domain);
    pub_outputs.push(hdr.root);
    for inp in &inputs {
        pub_outputs.push(inp.nf);
    }
    pub_outputs.push(u64_to_felt(hdr.fee));
    for out in &hdr.outputs {
        pub_outputs.push(out.cm);
    }
    for out in &hdr.outputs {
        pub_outputs.push(out.memo_ct_hash);
    }
    let preimage = wrap_bootloader_output_preimage(PROGRAM_HASH_TRANSFER, &pub_outputs);

    (
        hdr,
        inputs,
        Run {
            advice,
            expected: public_digest_for_preimage(&preimage),
        },
    )
}

/// Build a valid TzEL-Exact `Unshield` witness.
pub fn build_exact_unshield(
    n_inputs: usize,
    mixed_fa2: bool,
) -> (UnshieldHeader, Vec<InputNoteWitness>, Run) {
    assert!((1..=tzel_guest::MAX_INPUTS).contains(&n_inputs));
    let auth_domain = exact::hash1(&[0xD00D_0003, 0, 0, 0]);
    let fee: u64 = 100_000;
    let producer_fee: u64 = 50_000;
    let recipient = exact::hash1(&[0xABCD_EF01, 0, 0, 0]);
    let primary_non_tez_asset = if mixed_fa2 { FA2_ASSET_FELT } else { ASSET_TEZ };

    let mut keys = Vec::with_capacity(n_inputs);
    let mut inputs = Vec::with_capacity(n_inputs);
    let mut tez_in: u64 = 0;
    let mut fa2_in: u64 = 0;
    let mut leaf_cms = Vec::with_capacity(n_inputs);

    for i in 0..n_inputs {
        let key = ExactXmssKey::generate(300 + i as u64, (20 + i) as u32);
        let nk_spend = exact::hash1(&[0x9100 + i as u64, 0, 0, 0]);
        let nk_tag = exact::derive_nk_tag(&nk_spend);
        let d_j = exact::hash1(&[0x9200 + i as u64, 0, 0, 0]);
        let rseed = exact::hash1(&[0x9300 + i as u64, 0, 0, 0]);
        let (v, asset) = if mixed_fa2 && i + 1 < n_inputs {
            fa2_in += 500_000;
            (500_000u64, FA2_ASSET_FELT)
        } else {
            tez_in += 1_000_000;
            (1_000_000u64, ASSET_TEZ)
        };
        let otag = exact::owner_tag(&key.auth_root, &key.pub_seed, &nk_tag);
        let rcm = exact::derive_rcm(&rseed);
        let cm = exact::commit(&d_j, v, &asset, &rcm, &otag);
        leaf_cms.push((key, nk_spend, d_j, v, rseed, asset, cm));
    }

    let mut level_nodes = [ZERO; 8];
    for (i, entry) in leaf_cms.iter().enumerate() {
        level_nodes[i] = entry.6;
    }
    let mut low_siblings = [[ZERO; 3]; 8];
    let mut cur_level = level_nodes.to_vec();
    for lvl in 0..3 {
        for i in 0..8 {
            let idx_at_lvl = i >> lvl;
            low_siblings[i][lvl] = cur_level[idx_at_lvl ^ 1];
        }
        let mut next = Vec::with_capacity(cur_level.len() / 2);
        for pair in cur_level.chunks(2) {
            next.push(exact::hash2_merkle(&pair[0], &pair[1]));
        }
        cur_level = next;
    }
    let subtree_root = cur_level[0];
    let (root, upper_siblings) = exact_merkle_path(&subtree_root, 0, 1234);

    for (i, (key, nk_spend, d_j, v, rseed, asset, cm)) in leaf_cms.into_iter().enumerate() {
        let cm_path_idx = i as u64;
        let nf = exact::nullifier(&nk_spend, &cm, cm_path_idx);
        let cm_siblings: [Felt; EXACT_TREE_DEPTH] = std::array::from_fn(|lvl| {
            if lvl < 3 {
                low_siblings[i][lvl]
            } else {
                upper_siblings[lvl]
            }
        });
        keys.push(key.clone());
        inputs.push(InputNoteWitness {
            nf,
            nk_spend,
            auth_root: key.auth_root,
            auth_pub_seed: key.pub_seed,
            auth_idx: u64::from(key.auth_idx),
            d_j,
            v,
            rseed,
            cm_path_idx,
            asset,
            cm_siblings,
            auth_siblings: key.auth_siblings,
            wots_sig: [ZERO; WOTS_CHAINS],
        });
    }

    let (v_pub, asset_pub, change_1, change_2) = if mixed_fa2 {
        let v_pub = 300_000u64;
        let c1 = UnshieldChangeSlot {
            has_change: 1,
            d_j: exact::hash1(&[0xA101, 0, 0, 0]),
            v: fa2_in - v_pub,
            rseed: exact::hash1(&[0xA102, 0, 0, 0]),
            auth_root: exact::hash1(&[0xA103, 0, 0, 0]),
            auth_pub_seed: exact::hash1(&[0xA104, 0, 0, 0]),
            nk_tag: exact::hash1(&[0xA105, 0, 0, 0]),
            memo_ct_hash: exact::hash1(&[0xA106, 0, 0, 0]),
            asset: FA2_ASSET_FELT,
        };
        let c2 = UnshieldChangeSlot {
            has_change: 1,
            d_j: exact::hash1(&[0xA201, 0, 0, 0]),
            v: tez_in - fee - producer_fee,
            rseed: exact::hash1(&[0xA202, 0, 0, 0]),
            auth_root: exact::hash1(&[0xA203, 0, 0, 0]),
            auth_pub_seed: exact::hash1(&[0xA204, 0, 0, 0]),
            nk_tag: exact::hash1(&[0xA205, 0, 0, 0]),
            memo_ct_hash: exact::hash1(&[0xA206, 0, 0, 0]),
            asset: ASSET_TEZ,
        };
        (v_pub, FA2_ASSET_FELT, c1, c2)
    } else {
        let v_pub = 400_000u64;
        let c1 = UnshieldChangeSlot {
            has_change: 1,
            d_j: exact::hash1(&[0xA101, 0, 0, 0]),
            v: tez_in - v_pub - fee - producer_fee,
            rseed: exact::hash1(&[0xA102, 0, 0, 0]),
            auth_root: exact::hash1(&[0xA103, 0, 0, 0]),
            auth_pub_seed: exact::hash1(&[0xA104, 0, 0, 0]),
            nk_tag: exact::hash1(&[0xA105, 0, 0, 0]),
            memo_ct_hash: exact::hash1(&[0xA106, 0, 0, 0]),
            asset: ASSET_TEZ,
        };
        let c2 = UnshieldChangeSlot {
            has_change: 0,
            d_j: ZERO,
            v: 0,
            rseed: ZERO,
            auth_root: ZERO,
            auth_pub_seed: ZERO,
            nk_tag: ZERO,
            memo_ct_hash: ZERO,
            asset: ZERO,
        };
        (v_pub, ASSET_TEZ, c1, c2)
    };

    let fee_d_j = exact::hash1(&[0xA301, 0, 0, 0]);
    let fee_rseed = exact::hash1(&[0xA302, 0, 0, 0]);
    let fee_auth_root = exact::hash1(&[0xA303, 0, 0, 0]);
    let fee_auth_pub_seed = exact::hash1(&[0xA304, 0, 0, 0]);
    let fee_nk_tag = exact::hash1(&[0xA305, 0, 0, 0]);
    let fee_memo_ct_hash = exact::hash1(&[0xA306, 0, 0, 0]);
    let fee_cm = exact::commit(
        &fee_d_j,
        producer_fee,
        &ASSET_TEZ,
        &exact::derive_rcm(&fee_rseed),
        &exact::owner_tag(&fee_auth_root, &fee_auth_pub_seed, &fee_nk_tag),
    );
    let fee_note = OutputNoteWitness {
        cm: fee_cm,
        d_j: fee_d_j,
        v: producer_fee,
        rseed: fee_rseed,
        auth_root: fee_auth_root,
        auth_pub_seed: fee_auth_pub_seed,
        nk_tag: fee_nk_tag,
        memo_ct_hash: fee_memo_ct_hash,
        asset: ASSET_TEZ,
    };

    let (cm_change_1, _, _) = change_1
        .commitment_or_zero(&primary_non_tez_asset)
        .unwrap();
    let (cm_change_2, _, _) = change_2
        .commitment_or_zero(&primary_non_tez_asset)
        .unwrap();

    let mut sighash = exact::sighash_fold(&u64_to_felt(0x02), &auth_domain);
    sighash = exact::sighash_fold(&sighash, &root);
    for inp in &inputs {
        sighash = exact::sighash_fold(&sighash, &inp.nf);
    }
    sighash = exact::sighash_fold(&sighash, &u64_to_felt(v_pub));
    sighash = exact::sighash_fold(&sighash, &asset_pub);
    sighash = exact::sighash_fold(&sighash, &u64_to_felt(fee));
    sighash = exact::sighash_fold(&sighash, &recipient);
    sighash = exact::sighash_fold(&sighash, &cm_change_1);
    sighash = exact::sighash_fold(&sighash, &change_1.memo_ct_hash);
    sighash = exact::sighash_fold(&sighash, &cm_change_2);
    sighash = exact::sighash_fold(&sighash, &change_2.memo_ct_hash);
    sighash = exact::sighash_fold(&sighash, &fee_note.cm);
    sighash = exact::sighash_fold(&sighash, &fee_note.memo_ct_hash);

    for (inp, key) in inputs.iter_mut().zip(keys.iter()) {
        inp.wots_sig = key.sign(&sighash);
    }

    let hdr = UnshieldHeader {
        n_inputs: n_inputs as u64,
        auth_domain,
        root,
        v_pub,
        asset_pub,
        fee,
        recipient,
        primary_non_tez_asset,
        change_1,
        change_2,
        fee_note,
    };

    let (c1, c2, cf) = hdr.verify(&inputs).expect("valid exact unshield");

    let mut advice = vec![OpTag::ExactUnshield as u64];
    advice.extend(unsafe { as_words_unchecked(&hdr) });
    for inp in &inputs {
        advice.extend(unsafe { as_words_unchecked(inp) });
    }

    let mut pub_outputs = Vec::with_capacity(12 + inputs.len());
    pub_outputs.push(hdr.auth_domain);
    pub_outputs.push(hdr.root);
    for inp in &inputs {
        pub_outputs.push(inp.nf);
    }
    pub_outputs.push(u64_to_felt(hdr.v_pub));
    pub_outputs.push(hdr.asset_pub);
    pub_outputs.push(u64_to_felt(hdr.fee));
    pub_outputs.push(hdr.recipient);
    pub_outputs.push(c1);
    pub_outputs.push(hdr.change_1.memo_ct_hash);
    pub_outputs.push(c2);
    pub_outputs.push(hdr.change_2.memo_ct_hash);
    pub_outputs.push(cf);
    pub_outputs.push(hdr.fee_note.memo_ct_hash);
    let preimage = wrap_bootloader_output_preimage(PROGRAM_HASH_UNSHIELD, &pub_outputs);

    (
        hdr,
        inputs,
        Run {
            advice,
            expected: public_digest_for_preimage(&preimage),
        },
    )
}

/// Parse a `BigUintAsHex` string (`"0x..."`) into a little-endian `Felt` (`[u64; 4]`).
pub fn parse_hex_felt(s: &str) -> Result<Felt, String> {
    let body = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    if body.is_empty() || body == "0" {
        return Ok(ZERO);
    }
    if body.len() > 64 {
        return Err(format!("felt hex string too long ({} > 64): {s}", body.len()));
    }
    let padded = format!("{body:0>64}");
    let mut be = [0u8; 32];
    for (i, byte) in be.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex in {s}: {e}"))?;
    }
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    Ok(felt_from_bytes_le(&le))
}

fn felt_to_u64(f: &Felt) -> Result<u64, String> {
    if f[1] != 0 || f[2] != 0 || f[3] != 0 {
        return Err(format!("felt does not fit in u64: {f:?}"));
    }
    Ok(f[0])
}

/// Parse a Cairo `run_shield` `--arguments-file` array into a `leanVM` `Run` and `output_preimage`.
pub fn parse_cairo_shield_args(args: &[String]) -> Result<(Vec<Felt>, Run), String> {
    let felts: Vec<Felt> = args
        .iter()
        .map(|s| parse_hex_felt(s))
        .collect::<Result<_, _>>()?;
    let expected_fields = 16 + WOTS_CHAINS + EXACT_AUTH_DEPTH + 5 + 2;
    if felts.len() != expected_fields + 1 {
        return Err(format!(
            "shield args length mismatch: got {}, expected {}",
            felts.len(),
            expected_fields + 1
        ));
    }
    if felt_to_u64(&felts[0])? as usize != expected_fields {
        return Err(format!(
            "shield declared length mismatch: got {}, expected {}",
            felts[0][0], expected_fields
        ));
    }
    let mut pos = 1;
    let auth_domain = felts[pos];
    pos += 1;
    let pubkey_hash = felts[pos];
    pos += 1;
    let v_note = felt_to_u64(&felts[pos])?;
    pos += 1;
    let fee = felt_to_u64(&felts[pos])?;
    pos += 1;
    let producer_fee = felt_to_u64(&felts[pos])?;
    pos += 1;
    let cm_new = felts[pos];
    pos += 1;
    let cm_producer = felts[pos];
    pos += 1;
    let memo_ct_hash = felts[pos];
    pos += 1;
    let producer_memo_ct_hash = felts[pos];
    pos += 1;
    let auth_root = felts[pos];
    pos += 1;
    let auth_pub_seed = felts[pos];
    pos += 1;
    let nk_tag = felts[pos];
    pos += 1;
    let d_j = felts[pos];
    pos += 1;
    let rseed = felts[pos];
    pos += 1;
    let blind = felts[pos];
    pos += 1;
    let auth_idx = felt_to_u64(&felts[pos])?;
    pos += 1;

    let wots_sig: [Felt; WOTS_CHAINS] = felts[pos..pos + WOTS_CHAINS]
        .try_into()
        .map_err(|_| "wots_sig slice".to_string())?;
    pos += WOTS_CHAINS;
    let auth_siblings: [Felt; EXACT_AUTH_DEPTH] = felts[pos..pos + EXACT_AUTH_DEPTH]
        .try_into()
        .map_err(|_| "auth_siblings slice".to_string())?;
    pos += EXACT_AUTH_DEPTH;

    let producer_auth_root = felts[pos];
    pos += 1;
    let producer_auth_pub_seed = felts[pos];
    pos += 1;
    let producer_nk_tag = felts[pos];
    pos += 1;
    let producer_d_j = felts[pos];
    pos += 1;
    let producer_rseed = felts[pos];
    pos += 1;
    let asset_new = felts[pos];
    pos += 1;
    let asset_producer = felts[pos];

    let tx = ShieldTx {
        auth_domain,
        pubkey_hash,
        v_note,
        fee,
        producer_fee,
        cm_new,
        cm_producer,
        memo_ct_hash,
        producer_memo_ct_hash,
        auth_root,
        auth_pub_seed,
        nk_tag,
        d_j,
        rseed,
        blind,
        auth_idx,
        wots_sig,
        auth_siblings,
        producer_auth_root,
        producer_auth_pub_seed,
        producer_nk_tag,
        producer_d_j,
        producer_rseed,
        asset_new,
        asset_producer,
    };

    let out = tx
        .verify()
        .map_err(|e| format!("shield witness verification failed: {e}"))?;
    let mut advice = vec![OpTag::ExactShield as u64];
    advice.extend(unsafe { as_words_unchecked(&tx) });
    let preimage = wrap_bootloader_output_preimage(PROGRAM_HASH_SHIELD, &out);
    let expected = public_digest_for_preimage(&preimage);
    Ok((preimage, Run { advice, expected }))
}

/// Parse a Cairo `run_transfer` `--arguments-file` array into a `leanVM` `Run` and `output_preimage`.
pub fn parse_cairo_transfer_args(args: &[String]) -> Result<(Vec<Felt>, Run), String> {
    let felts: Vec<Felt> = args
        .iter()
        .map(|s| parse_hex_felt(s))
        .collect::<Result<_, _>>()?;
    if felts.len() < 5 {
        return Err("transfer args too short".into());
    }
    let n_inputs = felt_to_u64(&felts[1])? as usize;
    if !(1..=tzel_guest::MAX_INPUTS).contains(&n_inputs) {
        return Err(format!("invalid transfer n_inputs: {n_inputs}"));
    }
    let expected_fields = 4
        + 9 * n_inputs
        + n_inputs * EXACT_TREE_DEPTH
        + n_inputs * EXACT_AUTH_DEPTH
        + n_inputs * WOTS_CHAINS
        + n_inputs
        + 9 * 4
        + 1;
    if felts.len() != expected_fields + 1 {
        return Err(format!(
            "transfer args length mismatch: got {}, expected {}",
            felts.len(),
            expected_fields + 1
        ));
    }
    if felt_to_u64(&felts[0])? as usize != expected_fields {
        return Err(format!(
            "transfer declared length mismatch: got {}, expected {}",
            felts[0][0], expected_fields
        ));
    }

    let mut pos = 2;
    let auth_domain = felts[pos];
    pos += 1;
    let root = felts[pos];
    pos += 1;
    let fee = felt_to_u64(&felts[pos])?;
    pos += 1;

    let mut base_inputs = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let nf = felts[pos];
        let nk_spend = felts[pos + 1];
        let auth_root = felts[pos + 2];
        let auth_pub_seed = felts[pos + 3];
        let auth_idx = felt_to_u64(&felts[pos + 4])?;
        let d_j = felts[pos + 5];
        let v = felt_to_u64(&felts[pos + 6])?;
        let rseed = felts[pos + 7];
        let cm_path_idx = felt_to_u64(&felts[pos + 8])?;
        pos += 9;
        base_inputs.push((
            nf,
            nk_spend,
            auth_root,
            auth_pub_seed,
            auth_idx,
            d_j,
            v,
            rseed,
            cm_path_idx,
        ));
    }

    let mut cm_paths = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let path: [Felt; EXACT_TREE_DEPTH] = felts[pos..pos + EXACT_TREE_DEPTH]
            .try_into()
            .map_err(|_| "cm_siblings slice".to_string())?;
        pos += EXACT_TREE_DEPTH;
        cm_paths.push(path);
    }

    let mut auth_paths = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let path: [Felt; EXACT_AUTH_DEPTH] = felts[pos..pos + EXACT_AUTH_DEPTH]
            .try_into()
            .map_err(|_| "auth_siblings slice".to_string())?;
        pos += EXACT_AUTH_DEPTH;
        auth_paths.push(path);
    }

    let mut wots_sigs = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let sig: [Felt; WOTS_CHAINS] = felts[pos..pos + WOTS_CHAINS]
            .try_into()
            .map_err(|_| "wots_sig slice".to_string())?;
        pos += WOTS_CHAINS;
        wots_sigs.push(sig);
    }

    let mut input_assets = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        input_assets.push(felts[pos]);
        pos += 1;
    }

    let mut inputs = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let (nf, nk_spend, auth_root, auth_pub_seed, auth_idx, d_j, v, rseed, cm_path_idx) =
            base_inputs[i];
        inputs.push(InputNoteWitness {
            nf,
            nk_spend,
            auth_root,
            auth_pub_seed,
            auth_idx,
            d_j,
            v,
            rseed,
            cm_path_idx,
            asset: input_assets[i],
            cm_siblings: cm_paths[i],
            auth_siblings: auth_paths[i],
            wots_sig: wots_sigs[i],
        });
    }

    let mut outputs_vec = Vec::with_capacity(4);
    for _ in 0..4 {
        let cm = felts[pos];
        let d_j = felts[pos + 1];
        let v = felt_to_u64(&felts[pos + 2])?;
        let rseed = felts[pos + 3];
        let auth_root = felts[pos + 4];
        let auth_pub_seed = felts[pos + 5];
        let nk_tag = felts[pos + 6];
        let memo_ct_hash = felts[pos + 7];
        let asset = felts[pos + 8];
        pos += 9;
        outputs_vec.push(OutputNoteWitness {
            cm,
            d_j,
            v,
            rseed,
            auth_root,
            auth_pub_seed,
            nk_tag,
            memo_ct_hash,
            asset,
        });
    }
    let outputs: [OutputNoteWitness; 4] = outputs_vec
        .try_into()
        .map_err(|_| "outputs slice".to_string())?;
    let primary_non_tez_asset = felts[pos];

    let hdr = TransferHeader {
        n_inputs: n_inputs as u64,
        auth_domain,
        root,
        fee,
        primary_non_tez_asset,
        outputs,
    };

    hdr.verify(&inputs)
        .map_err(|e| format!("transfer witness verification failed: {e}"))?;

    let mut advice = vec![OpTag::ExactTransfer as u64];
    advice.extend(unsafe { as_words_unchecked(&hdr) });
    for inp in &inputs {
        advice.extend(unsafe { as_words_unchecked(inp) });
    }

    let mut pub_outputs = Vec::with_capacity(11 + n_inputs);
    pub_outputs.push(hdr.auth_domain);
    pub_outputs.push(hdr.root);
    for inp in &inputs {
        pub_outputs.push(inp.nf);
    }
    pub_outputs.push(u64_to_felt(hdr.fee));
    for out in &hdr.outputs {
        pub_outputs.push(out.cm);
    }
    for out in &hdr.outputs {
        pub_outputs.push(out.memo_ct_hash);
    }
    let preimage = wrap_bootloader_output_preimage(PROGRAM_HASH_TRANSFER, &pub_outputs);
    let expected = public_digest_for_preimage(&preimage);
    Ok((preimage, Run { advice, expected }))
}

/// Parse a Cairo `run_unshield` `--arguments-file` array into a `leanVM` `Run` and `output_preimage`.
pub fn parse_cairo_unshield_args(args: &[String]) -> Result<(Vec<Felt>, Run), String> {
    let felts: Vec<Felt> = args
        .iter()
        .map(|s| parse_hex_felt(s))
        .collect::<Result<_, _>>()?;
    if felts.len() < 7 {
        return Err("unshield args too short".into());
    }
    let n_inputs = felt_to_u64(&felts[1])? as usize;
    if !(1..=tzel_guest::MAX_INPUTS).contains(&n_inputs) {
        return Err(format!("invalid unshield n_inputs: {n_inputs}"));
    }
    let expected_fields = 6
        + 9 * n_inputs
        + n_inputs * EXACT_TREE_DEPTH
        + n_inputs * EXACT_AUTH_DEPTH
        + n_inputs * WOTS_CHAINS
        + n_inputs
        + 9
        + 9
        + 8
        + 2;
    if felts.len() != expected_fields + 1 {
        return Err(format!(
            "unshield args length mismatch: got {}, expected {}",
            felts.len(),
            expected_fields + 1
        ));
    }
    if felt_to_u64(&felts[0])? as usize != expected_fields {
        return Err(format!(
            "unshield declared length mismatch: got {}, expected {}",
            felts[0][0], expected_fields
        ));
    }

    let mut pos = 2;
    let auth_domain = felts[pos];
    pos += 1;
    let root = felts[pos];
    pos += 1;
    let v_pub = felt_to_u64(&felts[pos])?;
    pos += 1;
    let fee = felt_to_u64(&felts[pos])?;
    pos += 1;
    let recipient = felts[pos];
    pos += 1;

    let mut base_inputs = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let nf = felts[pos];
        let nk_spend = felts[pos + 1];
        let auth_root = felts[pos + 2];
        let auth_pub_seed = felts[pos + 3];
        let auth_idx = felt_to_u64(&felts[pos + 4])?;
        let d_j = felts[pos + 5];
        let v = felt_to_u64(&felts[pos + 6])?;
        let rseed = felts[pos + 7];
        let cm_path_idx = felt_to_u64(&felts[pos + 8])?;
        pos += 9;
        base_inputs.push((
            nf,
            nk_spend,
            auth_root,
            auth_pub_seed,
            auth_idx,
            d_j,
            v,
            rseed,
            cm_path_idx,
        ));
    }

    let mut cm_paths = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let path: [Felt; EXACT_TREE_DEPTH] = felts[pos..pos + EXACT_TREE_DEPTH]
            .try_into()
            .map_err(|_| "cm_siblings slice".to_string())?;
        pos += EXACT_TREE_DEPTH;
        cm_paths.push(path);
    }

    let mut auth_paths = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let path: [Felt; EXACT_AUTH_DEPTH] = felts[pos..pos + EXACT_AUTH_DEPTH]
            .try_into()
            .map_err(|_| "auth_siblings slice".to_string())?;
        pos += EXACT_AUTH_DEPTH;
        auth_paths.push(path);
    }

    let mut wots_sigs = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let sig: [Felt; WOTS_CHAINS] = felts[pos..pos + WOTS_CHAINS]
            .try_into()
            .map_err(|_| "wots_sig slice".to_string())?;
        pos += WOTS_CHAINS;
        wots_sigs.push(sig);
    }

    let mut input_assets = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        input_assets.push(felts[pos]);
        pos += 1;
    }

    let mut inputs = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let (nf, nk_spend, auth_root, auth_pub_seed, auth_idx, d_j, v, rseed, cm_path_idx) =
            base_inputs[i];
        inputs.push(InputNoteWitness {
            nf,
            nk_spend,
            auth_root,
            auth_pub_seed,
            auth_idx,
            d_j,
            v,
            rseed,
            cm_path_idx,
            asset: input_assets[i],
            cm_siblings: cm_paths[i],
            auth_siblings: auth_paths[i],
            wots_sig: wots_sigs[i],
        });
    }

    let parse_change_slot = |slice: &[Felt]| -> Result<UnshieldChangeSlot, String> {
        Ok(UnshieldChangeSlot {
            has_change: felt_to_u64(&slice[0])?,
            d_j: slice[1],
            v: felt_to_u64(&slice[2])?,
            rseed: slice[3],
            auth_root: slice[4],
            auth_pub_seed: slice[5],
            nk_tag: slice[6],
            memo_ct_hash: slice[7],
            asset: slice[8],
        })
    };

    let change_1 = parse_change_slot(&felts[pos..pos + 9])?;
    pos += 9;
    let change_2 = parse_change_slot(&felts[pos..pos + 9])?;
    pos += 9;

    let fee_d_j = felts[pos];
    let fee_v = felt_to_u64(&felts[pos + 1])?;
    let fee_rseed = felts[pos + 2];
    let fee_auth_root = felts[pos + 3];
    let fee_auth_pub_seed = felts[pos + 4];
    let fee_nk_tag = felts[pos + 5];
    let fee_memo_ct_hash = felts[pos + 6];
    let fee_asset = felts[pos + 7];
    pos += 8;
    let fee_cm = exact::commit(
        &fee_d_j,
        fee_v,
        &fee_asset,
        &exact::derive_rcm(&fee_rseed),
        &exact::owner_tag(&fee_auth_root, &fee_auth_pub_seed, &fee_nk_tag),
    );
    let fee_note = OutputNoteWitness {
        cm: fee_cm,
        d_j: fee_d_j,
        v: fee_v,
        rseed: fee_rseed,
        auth_root: fee_auth_root,
        auth_pub_seed: fee_auth_pub_seed,
        nk_tag: fee_nk_tag,
        memo_ct_hash: fee_memo_ct_hash,
        asset: fee_asset,
    };

    let asset_pub = felts[pos];
    let primary_non_tez_asset = felts[pos + 1];

    let hdr = UnshieldHeader {
        n_inputs: n_inputs as u64,
        auth_domain,
        root,
        v_pub,
        asset_pub,
        fee,
        recipient,
        primary_non_tez_asset,
        change_1,
        change_2,
        fee_note,
    };

    let (c1, c2, cf) = hdr
        .verify(&inputs)
        .map_err(|e| format!("unshield witness verification failed: {e}"))?;

    let mut advice = vec![OpTag::ExactUnshield as u64];
    advice.extend(unsafe { as_words_unchecked(&hdr) });
    for inp in &inputs {
        advice.extend(unsafe { as_words_unchecked(inp) });
    }

    let mut pub_outputs = Vec::with_capacity(12 + n_inputs);
    pub_outputs.push(hdr.auth_domain);
    pub_outputs.push(hdr.root);
    for inp in &inputs {
        pub_outputs.push(inp.nf);
    }
    pub_outputs.push(u64_to_felt(hdr.v_pub));
    pub_outputs.push(hdr.asset_pub);
    pub_outputs.push(u64_to_felt(hdr.fee));
    pub_outputs.push(hdr.recipient);
    pub_outputs.push(c1);
    pub_outputs.push(hdr.change_1.memo_ct_hash);
    pub_outputs.push(c2);
    pub_outputs.push(hdr.change_2.memo_ct_hash);
    pub_outputs.push(cf);
    pub_outputs.push(hdr.fee_note.memo_ct_hash);
    let preimage = wrap_bootloader_output_preimage(PROGRAM_HASH_UNSHIELD, &pub_outputs);
    let expected = public_digest_for_preimage(&preimage);
    Ok((preimage, Run { advice, expected }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanvm::{Machine, Program, Proof, Prover, Randomness, Rate, Trap};
    use tzel_guest::TzelError;

    fn run_on_vm(run: &Run) -> Result<[u64; 4], Trap> {
        let program = Program::from_elf(ELF).expect("valid tzel.elf");
        Machine::new(program.rv(), &run.advice).run()
    }

    #[test]
    fn exact_circuits_execute_on_vm_and_match_expected_digest() {
        let cases = [
            ("exact_shield_tez", build_exact_shield(ASSET_TEZ).1),
            ("exact_shield_fa2", build_exact_shield(FA2_ASSET_FELT).1),
            ("exact_transfer_1in_tez", build_exact_transfer(1, false).2),
            ("exact_transfer_2in_mixed", build_exact_transfer(2, true).2),
            ("exact_transfer_5in_mixed", build_exact_transfer(5, true).2),
            ("exact_unshield_1in_tez", build_exact_unshield(1, false).2),
            ("exact_unshield_2in_mixed", build_exact_unshield(2, true).2),
            ("exact_unshield_5in_mixed", build_exact_unshield(5, true).2),
        ];

        for (name, run) in cases {
            assert_eq!(run_on_vm(&run), Ok(run.expected), "{name} failed on VM");
        }
    }

    #[test]
    fn multiasset_security_invariants_reject_invalid_witnesses() {
        // 1. Producer fee asset must be ASSET_TEZ.
        let (mut shield, _) = build_exact_shield(FA2_ASSET_FELT);
        shield.asset_producer = FA2_ASSET_FELT;
        assert_eq!(shield.verify(), Err(TzelError::ProducerAssetNotTez));

        // 2. Tez accumulator conservation and primary non-tez accumulator conservation.
        let (mut xfer_hdr, xfer_inputs, _) = build_exact_transfer(2, true);
        xfer_hdr.fee += 1;
        assert!(xfer_hdr.verify(&xfer_inputs).is_err());

        // 3. Unauthorized 3rd asset rejected by 2-accumulator gate.
        let (mut xfer_hdr2, xfer_inputs2, _) = build_exact_transfer(2, true);
        xfer_hdr2.outputs[0].asset = [0xDEAD_BEEF, 0, 0, 0];
        assert_eq!(xfer_hdr2.verify(&xfer_inputs2), Err(TzelError::BadAsset));

        // 4. Duplicate nullifier rejected (either via sighash/XMSS or DuplicateNullifier check).
        let (xfer_hdr3, mut xfer_inputs3, _) = build_exact_transfer(2, false);
        xfer_inputs3[1] = xfer_inputs3[0];
        assert!(xfer_hdr3.verify(&xfer_inputs3).is_err());

        // 5. Disabled unshield change slot with non-zero field rejected.
        let (mut unshield_hdr, unshield_inputs, _) = build_exact_unshield(1, false);
        unshield_hdr.change_2.v = 1;
        assert_eq!(
            unshield_hdr.verify(&unshield_inputs),
            Err(TzelError::BadDisabledChangeSlot)
        );

        // 6. Unshield with v_pub == 0 rejected.
        let (mut unshield_hdr2, unshield_inputs2, _) = build_exact_unshield(1, false);
        unshield_hdr2.v_pub = 0;
        assert_eq!(
            unshield_hdr2.verify(&unshield_inputs2),
            Err(TzelError::PublicAmountZero)
        );
    }

    #[test]
    fn bootloader_header_program_hash_is_cryptographically_bound_to_digest() {
        let (hdr, inputs, run) = build_exact_transfer(2, true);
        let mut pub_outputs = Vec::with_capacity(11 + inputs.len());
        pub_outputs.push(hdr.auth_domain);
        pub_outputs.push(hdr.root);
        for inp in &inputs {
            pub_outputs.push(inp.nf);
        }
        pub_outputs.push(u64_to_felt(hdr.fee));
        for out in &hdr.outputs {
            pub_outputs.push(out.cm);
        }
        for out in &hdr.outputs {
            pub_outputs.push(out.memo_ct_hash);
        }
        let valid_preimage = wrap_bootloader_output_preimage(PROGRAM_HASH_TRANSFER, &pub_outputs);
        assert_eq!(
            validate_and_digest_preimage(&valid_preimage).unwrap(),
            run.expected
        );

        // Even if pub_outputs[k - 8] (cm_1) were crafted to look like a u64 felt,
        // swapping PROGRAM_HASH_TRANSFER to PROGRAM_HASH_UNSHIELD changes the digest!
        let mut forged = valid_preimage.clone();
        forged[2] = PROGRAM_HASH_UNSHIELD;
        forged[4 + 13 - 10] = u64_to_felt(100);
        forged[4 + 13 - 8] = u64_to_felt(50);
        if let Ok(forged_digest) = validate_and_digest_preimage(&forged) {
            assert_ne!(forged_digest, run.expected);
        }
    }

    #[test]
    fn parse_cairo_args_reject_mismatched_declared_length() {
        let xfer_fields = 4
            + 9
            + EXACT_TREE_DEPTH
            + EXACT_AUTH_DEPTH
            + WOTS_CHAINS
            + 1
            + 9 * 4
            + 1;
        let mut xfer_args = vec!["0x0".to_string(); xfer_fields + 1];
        xfer_args[0] = format!("0x{:x}", xfer_fields - 1);
        xfer_args[1] = "0x1".to_string();
        let err = parse_cairo_transfer_args(&xfer_args).unwrap_err();
        assert!(err.contains("transfer declared length mismatch"), "{err}");

        let unshield_fields = 6
            + 9
            + EXACT_TREE_DEPTH
            + EXACT_AUTH_DEPTH
            + WOTS_CHAINS
            + 1
            + 9
            + 9
            + 8
            + 2;
        let mut unshield_args = vec!["0x0".to_string(); unshield_fields + 1];
        unshield_args[0] = format!("0x{:x}", unshield_fields + 1);
        unshield_args[1] = "0x1".to_string();
        let err = parse_cairo_unshield_args(&unshield_args).unwrap_err();
        assert!(err.contains("unshield declared length mismatch"), "{err}");
    }

    #[test]
    fn prove_and_verify_plain_and_zk_multiasset_transfer() {
        let program = Program::from_elf(ELF).expect("valid tzel.elf");
        let (_, _, run) = build_exact_transfer(1, false);

        // Plain STARK proof
        let proven_plain = Prover::new(Rate::MIN)
            .prove(&program, &run.advice)
            .expect("plain proof succeeds");
        assert_eq!(proven_plain.output, run.expected);
        let plain_bytes = proven_plain.proof.to_bytes();
        program
            .verify(proven_plain.output, &Proof::from_bytes(&plain_bytes).unwrap())
            .expect("plain proof verifies");

        // Zero-Knowledge STARK proof
        let proven_zk = Prover::new(Rate::MIN)
            .zero_knowledge(Randomness::Os)
            .prove(&program, &run.advice)
            .expect("zk proof succeeds");
        assert_eq!(proven_zk.output, run.expected);
        let zk_bytes = proven_zk.proof.to_bytes();
        program
            .verify(proven_zk.output, &Proof::from_bytes(&zk_bytes).unwrap())
            .expect("zk proof verifies");
    }
}
