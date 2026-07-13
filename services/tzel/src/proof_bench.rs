use tzel_core::{
    commit, deposit_pubkey_hash, derive_account, derive_address, derive_ask,
    derive_auth_pub_seed, derive_nk_tag, derive_rcm, felt_tag, hash, hash_two, nullifier,
    owner_tag, shield_sighash, transfer_sighash, u64_to_felt, unshield_sighash, wots_pk,
    wots_pk_to_leaf, wots_sign, xmss_tree_node_hash, Account, CircuitKind, MerkleTree,
    ASSET_TEZ, AUTH_DEPTH, AUTH_TREE_SIZE, DEPTH, F, MIN_TX_FEE, WOTS_CHAINS, ZERO,
};

pub const MAX_BENCH_INPUTS: usize = 7;

#[derive(Clone, Debug)]
pub struct BenchWitness {
    pub args: Vec<String>,
    pub expected_public_outputs: Vec<F>,
}

fn felt_to_hex(f: &F) -> String {
    let mut be = [0u8; 32];
    for (dst, src) in be.iter_mut().zip(f.iter().rev()) {
        *dst = *src;
    }
    let hex_str = hex::encode(be);
    let trimmed = hex_str.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_string()
    } else {
        format!("0x{}", trimmed)
    }
}

fn felt_u64_to_hex(v: u64) -> String {
    format!("0x{:x}", v)
}

fn bench_master_sk() -> F {
    u64_to_felt(0xB001)
}

fn bench_account() -> Account {
    derive_account(&bench_master_sk())
}

fn bench_rseed(tag: &[u8], idx: usize) -> F {
    hash_two(&felt_tag(tag), &u64_to_felt(idx as u64 + 1))
}

fn build_auth_root_and_paths(ask_j: &F, prefix_len: usize) -> (F, F, Vec<Vec<F>>) {
    assert!(prefix_len > 0);
    assert!(prefix_len <= MAX_BENCH_INPUTS);

    let pub_seed = derive_auth_pub_seed(ask_j);
    let mut level: Vec<F> = (0..AUTH_TREE_SIZE)
        .map(|key_idx| wots_pk_to_leaf(&pub_seed, key_idx as u32, &wots_pk(ask_j, key_idx as u32)))
        .collect();

    let mut paths = vec![Vec::with_capacity(AUTH_DEPTH); prefix_len];
    for depth in 0..AUTH_DEPTH {
        for (leaf_idx, path) in paths.iter_mut().enumerate() {
            let node_idx = leaf_idx >> depth;
            path.push(level[node_idx ^ 1]);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for (node_idx, pair) in level.chunks_exact(2).enumerate() {
            next.push(xmss_tree_node_hash(
                &pub_seed,
                depth as u32,
                node_idx as u32,
                &pair[0],
                &pair[1],
            ));
        }
        level = next;
    }

    (level[0], pub_seed, paths)
}

fn synthetic_output_fields(base: u64) -> (F, F, F, F, F, F) {
    (
        u64_to_felt(base + 1),
        u64_to_felt(base + 2),
        u64_to_felt(base + 3),
        u64_to_felt(base + 4),
        u64_to_felt(base + 5),
        u64_to_felt(base + 6),
    )
}

/// Build a witness for the XMSS-signed shield circuit. The recipient
/// note is owned by `addr_index = 0`'s auth tree (which the shield
/// circuit also signs under), and the WOTS+ key at `auth_idx = 0` is
/// consumed.
pub fn build_shield_bench_witness() -> BenchWitness {
    let account = bench_account();
    let addr_index = 0u32;
    let ask_j = derive_ask(&account.ask_base, addr_index);
    let d_j = derive_address(&account.incoming_seed, addr_index);
    let nk_spend = account.nk;
    let nk_tag = derive_nk_tag(&nk_spend);
    let (auth_root, auth_pub_seed, auth_paths) = build_auth_root_and_paths(&ask_j, 1);
    let auth_path = auth_paths.into_iter().next().expect("path 0");

    let auth_domain = u64_to_felt(0xF101);
    let blind = hash_two(&felt_tag(b"bench-blind"), &u64_to_felt(0xCAFE));
    let pubkey_hash = deposit_pubkey_hash(&auth_domain, &auth_root, &auth_pub_seed, &blind);

    let v_note = 400_000u64;
    let fee = MIN_TX_FEE;
    let producer_fee = 1u64;

    let rseed = bench_rseed(b"bench-shield-recipient", 0);
    let cm_new = commit(
        &d_j,
        v_note,
        &ASSET_TEZ,
        &derive_rcm(&rseed),
        &owner_tag(&auth_root, &auth_pub_seed, &nk_tag));

    // Producer note has its own independent owner witness; the circuit
    // only checks the commitment opens correctly.
    let (producer_d_j, producer_auth_root, producer_auth_pub_seed, producer_nk_tag, mh_producer, producer_rseed) =
        synthetic_output_fields(0xE100);
    let cm_producer = commit(
        &producer_d_j,
        producer_fee,
        &ASSET_TEZ,
        &derive_rcm(&producer_rseed),
        &owner_tag(&producer_auth_root, &producer_auth_pub_seed, &producer_nk_tag));
    let mh_recipient = hash_two(&felt_tag(b"bench-mh-recipient"), &u64_to_felt(0));

    let sighash = shield_sighash(
        &auth_domain,
        &pubkey_hash,
        v_note,
        fee,
        producer_fee,
        &cm_new,
        &cm_producer,
        &mh_recipient,
        &mh_producer,
        &ASSET_TEZ,
        &ASSET_TEZ,
    );
    let (sig, _, _) = wots_sign(&ask_j, 0, &sighash);

    // +2 for asset_new and asset_producer.
    let total_fields = 16 + WOTS_CHAINS + AUTH_DEPTH + 5 + 2;
    let mut args = Vec::with_capacity(total_fields + 1);
    args.push(felt_u64_to_hex(total_fields as u64));
    args.push(felt_to_hex(&auth_domain));
    args.push(felt_to_hex(&pubkey_hash));
    args.push(felt_u64_to_hex(v_note));
    args.push(felt_u64_to_hex(fee));
    args.push(felt_u64_to_hex(producer_fee));
    args.push(felt_to_hex(&cm_new));
    args.push(felt_to_hex(&cm_producer));
    args.push(felt_to_hex(&mh_recipient));
    args.push(felt_to_hex(&mh_producer));
    args.push(felt_to_hex(&auth_root));
    args.push(felt_to_hex(&auth_pub_seed));
    args.push(felt_to_hex(&nk_tag));
    args.push(felt_to_hex(&d_j));
    args.push(felt_to_hex(&rseed));
    args.push(felt_to_hex(&blind));
    args.push(felt_u64_to_hex(0));
    for s in &sig {
        args.push(felt_to_hex(s));
    }
    for sibling in &auth_path {
        args.push(felt_to_hex(sibling));
    }
    args.push(felt_to_hex(&producer_auth_root));
    args.push(felt_to_hex(&producer_auth_pub_seed));
    args.push(felt_to_hex(&producer_nk_tag));
    args.push(felt_to_hex(&producer_d_j));
    args.push(felt_to_hex(&producer_rseed));
    // Multiasset Phase B: shield outputs pinned to tez (v1 single bridge,
    // and producer fee always tez).
    args.push(felt_to_hex(&ASSET_TEZ)); // asset_new
    args.push(felt_to_hex(&ASSET_TEZ)); // asset_producer

    let expected_public_outputs = vec![
        auth_domain,
        pubkey_hash,
        u64_to_felt(v_note),
        u64_to_felt(fee),
        u64_to_felt(producer_fee),
        cm_new,
        cm_producer,
        mh_recipient,
        mh_producer,
    ];

    BenchWitness {
        args,
        expected_public_outputs,
    }
}

pub fn build_transfer_bench_witness(n_inputs: usize) -> BenchWitness {
    assert!((1..=MAX_BENCH_INPUTS).contains(&n_inputs));

    let account = bench_account();
    let addr_index = 0u32;
    let ask_j = derive_ask(&account.ask_base, addr_index);
    let d_j = derive_address(&account.incoming_seed, addr_index);
    let nk_spend = account.nk;
    let nk_tag = derive_nk_tag(&nk_spend);
    let (auth_root, auth_pub_seed, auth_paths) = build_auth_root_and_paths(&ask_j, n_inputs);
    let otag = owner_tag(&auth_root, &auth_pub_seed, &nk_tag);

    let mut tree = MerkleTree::new();
    let mut cms = Vec::with_capacity(n_inputs);
    let mut values = Vec::with_capacity(n_inputs);
    let mut rseeds = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let value = 200_000 + 10_000 * i as u64;
        let rseed = bench_rseed(b"bench-tr-in", i);
        let cm = commit(&d_j, value, &ASSET_TEZ, &derive_rcm(&rseed), &otag);
        tree.append(cm);
        cms.push(cm);
        values.push(value);
        rseeds.push(rseed);
    }

    let root = tree.root();
    let nullifiers: Vec<F> = cms
        .iter()
        .enumerate()
        .map(|(i, cm)| nullifier(&nk_spend, cm, i as u64))
        .collect();
    let total_in: u64 = values.iter().sum();

    // Phase C: 4 output slots — recipient (cm_1), change_1 (cm_2),
    // change_2 placeholder (cm_3, zero-value), producer fee (cm_4).
    let (d_j_1, auth_root_1, auth_pub_seed_1, nk_tag_1, mh_1, rseed_1) =
        synthetic_output_fields(0xD000);
    let (d_j_2, auth_root_2, auth_pub_seed_2, nk_tag_2, mh_2, rseed_2) =
        synthetic_output_fields(0xE000);
    let (d_j_3, auth_root_3, auth_pub_seed_3, nk_tag_3, mh_3, rseed_3) =
        synthetic_output_fields(0xF000);
    let (d_j_4, auth_root_4, auth_pub_seed_4, nk_tag_4, mh_4, rseed_4) =
        synthetic_output_fields(0xC000);
    let producer_fee = 1u64;
    let spendable = total_in - MIN_TX_FEE - producer_fee;
    let v_1 = spendable / 2;
    let v_2 = spendable - v_1;
    let v_3: u64 = 0;
    let cm_1 = commit(
        &d_j_1,
        v_1,
        &ASSET_TEZ,
        &derive_rcm(&rseed_1),
        &owner_tag(&auth_root_1, &auth_pub_seed_1, &nk_tag_1));
    let cm_2 = commit(
        &d_j_2,
        v_2,
        &ASSET_TEZ,
        &derive_rcm(&rseed_2),
        &owner_tag(&auth_root_2, &auth_pub_seed_2, &nk_tag_2));
    let cm_3 = commit(
        &d_j_3,
        v_3,
        &ASSET_TEZ,
        &derive_rcm(&rseed_3),
        &owner_tag(&auth_root_3, &auth_pub_seed_3, &nk_tag_3));
    let cm_4 = commit(
        &d_j_4,
        producer_fee,
        &ASSET_TEZ,
        &derive_rcm(&rseed_4),
        &owner_tag(&auth_root_4, &auth_pub_seed_4, &nk_tag_4));

    let auth_domain = u64_to_felt(0xF001);
    let fee = MIN_TX_FEE;
    let sighash = transfer_sighash(
        &auth_domain,
        &root,
        &nullifiers,
        fee,
        &cm_1,
        &cm_2,
        &cm_3,
        &cm_4,
        &mh_1,
        &mh_2,
        &mh_3,
        &mh_4,
    );

    let mut cm_paths = Vec::with_capacity(n_inputs);
    let mut wots_sigs = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let (cm_path, path_root) = tree.auth_path(i);
        assert_eq!(path_root, root);
        cm_paths.push(cm_path);
        let (sig, _, _) = wots_sign(&ask_j, i as u32, &sighash);
        wots_sigs.push(sig);
    }

    // Phase C: 4 output blocks of 9 fields each + n input asset tags + 1
    // primary_non_tez_asset.
    let total_fields = 4
        + 9 * n_inputs
        + n_inputs * DEPTH
        + n_inputs * AUTH_DEPTH
        + n_inputs * WOTS_CHAINS
        + n_inputs
        + 9 * 4
        + 1;
    let mut args = Vec::with_capacity(total_fields + 1);
    args.push(felt_u64_to_hex(total_fields as u64));
    args.push(felt_u64_to_hex(n_inputs as u64));
    args.push(felt_to_hex(&auth_domain));
    args.push(felt_to_hex(&root));
    args.push(felt_u64_to_hex(fee));

    for i in 0..n_inputs {
        args.push(felt_to_hex(&nullifiers[i]));
        args.push(felt_to_hex(&nk_spend));
        args.push(felt_to_hex(&auth_root));
        args.push(felt_to_hex(&auth_pub_seed));
        args.push(felt_u64_to_hex(i as u64));
        args.push(felt_to_hex(&d_j));
        args.push(felt_u64_to_hex(values[i]));
        args.push(felt_to_hex(&rseeds[i]));
        args.push(felt_u64_to_hex(i as u64));
    }
    for path in &cm_paths {
        for sibling in path {
            args.push(felt_to_hex(sibling));
        }
    }
    for path in &auth_paths {
        for sibling in path {
            args.push(felt_to_hex(sibling));
        }
    }
    for sig in &wots_sigs {
        for s in sig {
            args.push(felt_to_hex(s));
        }
    }
    // Multiasset Phase B: per-input asset tags (pure-tez bench).
    for _ in 0..n_inputs {
        args.push(felt_to_hex(&ASSET_TEZ));
    }

    args.push(felt_to_hex(&cm_1));
    args.push(felt_to_hex(&d_j_1));
    args.push(felt_u64_to_hex(v_1));
    args.push(felt_to_hex(&rseed_1));
    args.push(felt_to_hex(&auth_root_1));
    args.push(felt_to_hex(&auth_pub_seed_1));
    args.push(felt_to_hex(&nk_tag_1));
    args.push(felt_to_hex(&mh_1));
    args.push(felt_to_hex(&ASSET_TEZ)); // asset_1 (recipient)

    args.push(felt_to_hex(&cm_2));
    args.push(felt_to_hex(&d_j_2));
    args.push(felt_u64_to_hex(v_2));
    args.push(felt_to_hex(&rseed_2));
    args.push(felt_to_hex(&auth_root_2));
    args.push(felt_to_hex(&auth_pub_seed_2));
    args.push(felt_to_hex(&nk_tag_2));
    args.push(felt_to_hex(&mh_2));
    args.push(felt_to_hex(&ASSET_TEZ)); // asset_2 (change_1)

    args.push(felt_to_hex(&cm_3));
    args.push(felt_to_hex(&d_j_3));
    args.push(felt_u64_to_hex(v_3));
    args.push(felt_to_hex(&rseed_3));
    args.push(felt_to_hex(&auth_root_3));
    args.push(felt_to_hex(&auth_pub_seed_3));
    args.push(felt_to_hex(&nk_tag_3));
    args.push(felt_to_hex(&mh_3));
    args.push(felt_to_hex(&ASSET_TEZ)); // asset_3 (change_2 placeholder)

    args.push(felt_to_hex(&cm_4));
    args.push(felt_to_hex(&d_j_4));
    args.push(felt_u64_to_hex(producer_fee));
    args.push(felt_to_hex(&rseed_4));
    args.push(felt_to_hex(&auth_root_4));
    args.push(felt_to_hex(&auth_pub_seed_4));
    args.push(felt_to_hex(&nk_tag_4));
    args.push(felt_to_hex(&mh_4));
    args.push(felt_to_hex(&ASSET_TEZ)); // asset_4 (producer, pinned tez)

    // primary_non_tez_asset — any value works for pure-tez txs;
    // we use ASSET_TEZ for the bench.
    args.push(felt_to_hex(&ASSET_TEZ));

    let mut expected_public_outputs = vec![auth_domain, root];
    expected_public_outputs.extend(nullifiers.iter().copied());
    expected_public_outputs.push(u64_to_felt(fee));
    expected_public_outputs.extend([cm_1, cm_2, cm_3, cm_4, mh_1, mh_2, mh_3, mh_4]);

    BenchWitness {
        args,
        expected_public_outputs,
    }
}

/// Mixed-asset transfer witness for the slow real-proof FA2 guard.
///
/// Builds a 2-input transfer where input 0 carries tez (covering fee
/// + producer + tez change) and input 1 carries a primary non-tez
/// asset (becomes the recipient amount). Stress-tests the
/// 2-accumulator per-asset balance constraint with BOTH lanes
/// strictly positive — the configuration the pure-tez bench cannot
/// exercise (its primary lane is always 0 == 0).
///
/// Balance:
///   tez_in     = 40
///   tez_out    = 32 (change_1 tez) + 0 (change_2 placeholder) + 3 (producer) = 35
///   fee        = 5; 40 == 35 + 5                                              ✓
///   primary_in = 30
///   primary_out = 30 (recipient primary)                                       ✓
pub fn build_transfer_mixed_assets_bench_witness(primary_asset: F) -> BenchWitness {
    let account = bench_account();
    let nk_spend = account.nk;
    let nk_tag = derive_nk_tag(&nk_spend);

    // Two inputs at auth_idx 0 and 1 sharing the same XMSS tree.
    let ask_j = derive_ask(&account.ask_base, 0);
    let d_j = derive_address(&account.incoming_seed, 0);
    let (auth_root, auth_pub_seed, auth_paths) = build_auth_root_and_paths(&ask_j, 2);
    let otag = owner_tag(&auth_root, &auth_pub_seed, &nk_tag);

    let v_in_0: u64 = 40; // tez
    let v_in_1: u64 = 30; // primary
    let rseed_in_0 = bench_rseed(b"bench-tr-mix-tez", 0);
    let rseed_in_1 = bench_rseed(b"bench-tr-mix-pri", 1);

    let mut tree = MerkleTree::new();
    let cm_0 = commit(&d_j, v_in_0, &ASSET_TEZ, &derive_rcm(&rseed_in_0), &otag);
    tree.append(cm_0);
    let cm_1 = commit(&d_j, v_in_1, &primary_asset, &derive_rcm(&rseed_in_1), &otag);
    tree.append(cm_1);
    let root = tree.root();

    let nf_0 = nullifier(&nk_spend, &cm_0, 0);
    let nf_1 = nullifier(&nk_spend, &cm_1, 1);

    // Output slots:
    //   1: recipient primary, v_1 = 30
    //   2: change_1 tez, v_2 = 32
    //   3: change_2 placeholder, v_3 = 0
    //   4: producer tez, v_4 = 3
    let (d_j_1, auth_root_1, auth_pub_seed_1, nk_tag_1, mh_1, rseed_1) =
        synthetic_output_fields(0xD300);
    let (d_j_2, auth_root_2, auth_pub_seed_2, nk_tag_2, mh_2, rseed_2) =
        synthetic_output_fields(0xE300);
    let (d_j_3, auth_root_3, auth_pub_seed_3, nk_tag_3, mh_3, rseed_3) =
        synthetic_output_fields(0xF300);
    let (d_j_4, auth_root_4, auth_pub_seed_4, nk_tag_4, mh_4, rseed_4) =
        synthetic_output_fields(0xC300);
    let fee: u64 = 5;
    let v_1: u64 = 30;
    let v_2: u64 = 32;
    let v_3: u64 = 0;
    let v_4: u64 = 3;

    let cm_out_1 = commit(
        &d_j_1,
        v_1,
        &primary_asset,
        &derive_rcm(&rseed_1),
        &owner_tag(&auth_root_1, &auth_pub_seed_1, &nk_tag_1),
    );
    let cm_out_2 = commit(
        &d_j_2,
        v_2,
        &ASSET_TEZ,
        &derive_rcm(&rseed_2),
        &owner_tag(&auth_root_2, &auth_pub_seed_2, &nk_tag_2),
    );
    let cm_out_3 = commit(
        &d_j_3,
        v_3,
        &ASSET_TEZ,
        &derive_rcm(&rseed_3),
        &owner_tag(&auth_root_3, &auth_pub_seed_3, &nk_tag_3),
    );
    let cm_out_4 = commit(
        &d_j_4,
        v_4,
        &ASSET_TEZ,
        &derive_rcm(&rseed_4),
        &owner_tag(&auth_root_4, &auth_pub_seed_4, &nk_tag_4),
    );

    let auth_domain = u64_to_felt(0xF300_5001);
    let nullifiers = vec![nf_0, nf_1];
    let sighash = transfer_sighash(
        &auth_domain,
        &root,
        &nullifiers,
        fee,
        &cm_out_1,
        &cm_out_2,
        &cm_out_3,
        &cm_out_4,
        &mh_1,
        &mh_2,
        &mh_3,
        &mh_4,
    );

    let mut cm_paths = Vec::with_capacity(2);
    let mut wots_sigs = Vec::with_capacity(2);
    for i in 0..2 {
        let (cm_path, path_root) = tree.auth_path(i);
        assert_eq!(path_root, root);
        cm_paths.push(cm_path);
        let (sig, _, _) = wots_sign(&ask_j, i as u32, &sighash);
        wots_sigs.push(sig);
    }

    let n_inputs = 2usize;
    let total_fields = 4
        + 9 * n_inputs
        + n_inputs * DEPTH
        + n_inputs * AUTH_DEPTH
        + n_inputs * WOTS_CHAINS
        + n_inputs
        + 9 * 4
        + 1;

    let mut args: Vec<String> = Vec::with_capacity(total_fields + 1);
    args.push(felt_u64_to_hex(total_fields as u64));
    args.push(felt_u64_to_hex(n_inputs as u64));
    args.push(felt_to_hex(&auth_domain));
    args.push(felt_to_hex(&root));
    args.push(felt_u64_to_hex(fee));

    // Per-input fields, in (i, auth_idx) pairs.
    let in_v = [v_in_0, v_in_1];
    let in_rseed = [rseed_in_0, rseed_in_1];
    let in_nf = [nf_0, nf_1];
    for (i, ((nf, v), rseed)) in in_nf.iter().zip(in_v.iter()).zip(in_rseed.iter()).enumerate() {
        args.push(felt_to_hex(nf));
        args.push(felt_to_hex(&nk_spend));
        args.push(felt_to_hex(&auth_root));
        args.push(felt_to_hex(&auth_pub_seed));
        args.push(felt_u64_to_hex(i as u64));
        args.push(felt_to_hex(&d_j));
        args.push(felt_u64_to_hex(*v));
        args.push(felt_to_hex(rseed));
        args.push(felt_u64_to_hex(i as u64));
    }
    for path in &cm_paths {
        for sib in path {
            args.push(felt_to_hex(sib));
        }
    }
    for path in &auth_paths {
        for sib in path {
            args.push(felt_to_hex(sib));
        }
    }
    for sig in &wots_sigs {
        for s in sig {
            args.push(felt_to_hex(s));
        }
    }

    // Per-input asset tags: input 0 = tez, input 1 = primary.
    args.push(felt_to_hex(&ASSET_TEZ));
    args.push(felt_to_hex(&primary_asset));

    // Output 1: recipient primary
    args.push(felt_to_hex(&cm_out_1));
    args.push(felt_to_hex(&d_j_1));
    args.push(felt_u64_to_hex(v_1));
    args.push(felt_to_hex(&rseed_1));
    args.push(felt_to_hex(&auth_root_1));
    args.push(felt_to_hex(&auth_pub_seed_1));
    args.push(felt_to_hex(&nk_tag_1));
    args.push(felt_to_hex(&mh_1));
    args.push(felt_to_hex(&primary_asset));

    // Output 2: change_1 tez
    args.push(felt_to_hex(&cm_out_2));
    args.push(felt_to_hex(&d_j_2));
    args.push(felt_u64_to_hex(v_2));
    args.push(felt_to_hex(&rseed_2));
    args.push(felt_to_hex(&auth_root_2));
    args.push(felt_to_hex(&auth_pub_seed_2));
    args.push(felt_to_hex(&nk_tag_2));
    args.push(felt_to_hex(&mh_2));
    args.push(felt_to_hex(&ASSET_TEZ));

    // Output 3: change_2 placeholder (tez, v=0)
    args.push(felt_to_hex(&cm_out_3));
    args.push(felt_to_hex(&d_j_3));
    args.push(felt_u64_to_hex(v_3));
    args.push(felt_to_hex(&rseed_3));
    args.push(felt_to_hex(&auth_root_3));
    args.push(felt_to_hex(&auth_pub_seed_3));
    args.push(felt_to_hex(&nk_tag_3));
    args.push(felt_to_hex(&mh_3));
    args.push(felt_to_hex(&ASSET_TEZ));

    // Output 4: producer (tez, permanent pin)
    args.push(felt_to_hex(&cm_out_4));
    args.push(felt_to_hex(&d_j_4));
    args.push(felt_u64_to_hex(v_4));
    args.push(felt_to_hex(&rseed_4));
    args.push(felt_to_hex(&auth_root_4));
    args.push(felt_to_hex(&auth_pub_seed_4));
    args.push(felt_to_hex(&nk_tag_4));
    args.push(felt_to_hex(&mh_4));
    args.push(felt_to_hex(&ASSET_TEZ));

    // primary_non_tez_asset: the FA2 asset the 2-accumulator
    // constraint accepts alongside tez.
    args.push(felt_to_hex(&primary_asset));

    let mut expected_public_outputs = vec![auth_domain, root];
    expected_public_outputs.extend(nullifiers.iter().copied());
    expected_public_outputs.push(u64_to_felt(fee));
    expected_public_outputs.extend([
        cm_out_1, cm_out_2, cm_out_3, cm_out_4, mh_1, mh_2, mh_3, mh_4,
    ]);

    BenchWitness {
        args,
        expected_public_outputs,
    }
}

pub fn build_unshield_bench_witness(n_inputs: usize) -> BenchWitness {
    assert!((1..=MAX_BENCH_INPUTS).contains(&n_inputs));

    let account = bench_account();
    let addr_index = 0u32;
    let ask_j = derive_ask(&account.ask_base, addr_index);
    let d_j = derive_address(&account.incoming_seed, addr_index);
    let nk_spend = account.nk;
    let nk_tag = derive_nk_tag(&nk_spend);
    let (auth_root, auth_pub_seed, auth_paths) = build_auth_root_and_paths(&ask_j, n_inputs);
    let otag = owner_tag(&auth_root, &auth_pub_seed, &nk_tag);

    let mut tree = MerkleTree::new();
    let mut cms = Vec::with_capacity(n_inputs);
    let mut values = Vec::with_capacity(n_inputs);
    let mut rseeds = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let value = 210_000 + 10_000 * i as u64;
        let rseed = bench_rseed(b"bench-un-in", i);
        let cm = commit(&d_j, value, &ASSET_TEZ, &derive_rcm(&rseed), &otag);
        tree.append(cm);
        cms.push(cm);
        values.push(value);
        rseeds.push(rseed);
    }

    let root = tree.root();
    let nullifiers: Vec<F> = cms
        .iter()
        .enumerate()
        .map(|(i, cm)| nullifier(&nk_spend, cm, i as u64))
        .collect();
    let total_in: u64 = values.iter().sum();

    let auth_domain = u64_to_felt(0xF101);
    let fee = MIN_TX_FEE;
    let producer_fee = 1u64;
    let spendable = total_in - fee - producer_fee;
    let v_pub = spendable / 2;
    let v_change = spendable - v_pub;
    let recipient = hash(b"bench-recipient");
    let (
        d_j_change,
        auth_root_change,
        auth_pub_seed_change,
        nk_tag_change,
        mh_change,
        rseed_change,
    ) = synthetic_output_fields(0xF200);
    let cm_change = commit(
        &d_j_change,
        v_change,
        &ASSET_TEZ,
        &derive_rcm(&rseed_change),
        &owner_tag(&auth_root_change, &auth_pub_seed_change, &nk_tag_change));
    let (d_j_fee, auth_root_fee, auth_pub_seed_fee, nk_tag_fee, mh_fee, rseed_fee) =
        synthetic_output_fields(0xF300);
    let cm_fee = commit(
        &d_j_fee,
        producer_fee,
        &ASSET_TEZ,
        &derive_rcm(&rseed_fee),
        &owner_tag(&auth_root_fee, &auth_pub_seed_fee, &nk_tag_fee));
    let sighash = unshield_sighash(
        &auth_domain,
        &root,
        &nullifiers,
        v_pub,
        &ASSET_TEZ,
        fee,
        &recipient,
        &cm_change,
        &mh_change,
        &ZERO,
        &ZERO,
        &cm_fee,
        &mh_fee
    
    );

    let mut cm_paths = Vec::with_capacity(n_inputs);
    let mut wots_sigs = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let (cm_path, path_root) = tree.auth_path(i);
        assert_eq!(path_root, root);
        cm_paths.push(cm_path);
        let (sig, _, _) = wots_sign(&ask_j, i as u32, &sighash);
        wots_sigs.push(sig);
    }

    // Phase B+C wire layout:
    //   prefix(6): N, auth_domain, root, v_pub, fee, recipient
    //   inputs: 9N + N*DEPTH + N*AUTH_DEPTH + N*WOTS_CHAINS + N (asset tags)
    //   change_1 slot: 9 fields (has_change + 7 fields + asset)
    //   change_2 slot: 9 fields (has_change_2 + 7 fields + asset)
    //   fee slot: 8 fields (7 + asset, no has_change)
    //   trailer: asset_pub + primary_non_tez_asset = 2
    let total_fields = 6
        + 9 * n_inputs
        + n_inputs * DEPTH
        + n_inputs * AUTH_DEPTH
        + n_inputs * WOTS_CHAINS
        + n_inputs
        + 9
        + 9
        + 8
        + 2;
    let mut args = Vec::with_capacity(total_fields + 1);
    args.push(felt_u64_to_hex(total_fields as u64));
    args.push(felt_u64_to_hex(n_inputs as u64));
    args.push(felt_to_hex(&auth_domain));
    args.push(felt_to_hex(&root));
    args.push(felt_u64_to_hex(v_pub));
    args.push(felt_u64_to_hex(fee));
    args.push(felt_to_hex(&recipient));

    for i in 0..n_inputs {
        args.push(felt_to_hex(&nullifiers[i]));
        args.push(felt_to_hex(&nk_spend));
        args.push(felt_to_hex(&auth_root));
        args.push(felt_to_hex(&auth_pub_seed));
        args.push(felt_u64_to_hex(i as u64));
        args.push(felt_to_hex(&d_j));
        args.push(felt_u64_to_hex(values[i]));
        args.push(felt_to_hex(&rseeds[i]));
        args.push(felt_u64_to_hex(i as u64));
    }
    for path in &cm_paths {
        for sibling in path {
            args.push(felt_to_hex(sibling));
        }
    }
    for path in &auth_paths {
        for sibling in path {
            args.push(felt_to_hex(sibling));
        }
    }
    for sig in &wots_sigs {
        for s in sig {
            args.push(felt_to_hex(s));
        }
    }
    // Multiasset Phase B: per-input asset tags.
    for _ in 0..n_inputs {
        args.push(felt_to_hex(&ASSET_TEZ));
    }

    // Change_1 slot — present (carries the actual change in this bench).
    args.push(felt_u64_to_hex(1));
    args.push(felt_to_hex(&d_j_change));
    args.push(felt_u64_to_hex(v_change));
    args.push(felt_to_hex(&rseed_change));
    args.push(felt_to_hex(&auth_root_change));
    args.push(felt_to_hex(&auth_pub_seed_change));
    args.push(felt_to_hex(&nk_tag_change));
    args.push(felt_to_hex(&mh_change));
    args.push(felt_to_hex(&ASSET_TEZ)); // asset_change

    // Phase C: change_2 slot — empty placeholder (has_change_2 = 0
    // so change_commitment_or_zero returns ZERO and the matching
    // sighash bound used ZERO/ZERO).
    args.push(felt_u64_to_hex(0));
    args.push(felt_to_hex(&ZERO));
    args.push(felt_u64_to_hex(0));
    args.push(felt_to_hex(&ZERO));
    args.push(felt_to_hex(&ZERO));
    args.push(felt_to_hex(&ZERO));
    args.push(felt_to_hex(&ZERO));
    args.push(felt_to_hex(&ZERO));
    args.push(felt_to_hex(&ASSET_TEZ)); // asset_change_2 (placeholder == tez)

    args.push(felt_to_hex(&d_j_fee));
    args.push(felt_u64_to_hex(producer_fee));
    args.push(felt_to_hex(&rseed_fee));
    args.push(felt_to_hex(&auth_root_fee));
    args.push(felt_to_hex(&auth_pub_seed_fee));
    args.push(felt_to_hex(&nk_tag_fee));
    args.push(felt_to_hex(&mh_fee));
    args.push(felt_to_hex(&ASSET_TEZ)); // asset_fee

    args.push(felt_to_hex(&ASSET_TEZ)); // asset_pub (v1: tez only)
    args.push(felt_to_hex(&ASSET_TEZ)); // primary_non_tez_asset

    let mut expected_public_outputs = vec![auth_domain, root];
    expected_public_outputs.extend(nullifiers.iter().copied());
    expected_public_outputs.extend([
        u64_to_felt(v_pub),
        ASSET_TEZ, // asset_pub (multiasset Phase B)
        u64_to_felt(fee),
        recipient,
        cm_change,
        mh_change,
        ZERO, // cm_change_2 (placeholder slot has has_change_2 = 0)
        ZERO, // mh_change_2
        cm_fee,
        mh_fee,
    ]);

    BenchWitness {
        args,
        expected_public_outputs,
    }
}

pub fn build_named_bench_witness(
    kind: &str,
    n_inputs: Option<usize>,
) -> Result<(CircuitKind, BenchWitness), String> {
    match (kind, n_inputs) {
        ("shield", None) | ("shield", Some(0)) => {
            Ok((CircuitKind::Shield, build_shield_bench_witness()))
        }
        ("transfer", Some(n)) => Ok((CircuitKind::Transfer, build_transfer_bench_witness(n))),
        ("unshield", Some(n)) => Ok((CircuitKind::Unshield, build_unshield_bench_witness(n))),
        ("shield", Some(_)) => Err("shield does not take an input count".into()),
        ("transfer", None) | ("unshield", None) => Err("missing input count".into()),
        _ => Err(format!("unknown bench witness kind: {}", kind)),
    }
}
