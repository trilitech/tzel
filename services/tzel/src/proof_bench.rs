use tzel_core::{
    commit, deposit_id_from_secret, deposit_secret_from_label, derive_account, derive_address,
    derive_ask, derive_auth_pub_seed, derive_nk_tag, derive_rcm, felt_tag, hash, hash_two,
    nullifier, owner_tag, transfer_sighash, u64_to_felt, unshield_sighash, wots_pk,
    wots_pk_to_leaf, wots_sign, xmss_tree_node_hash, Account, CircuitKind, MerkleTree, AUTH_DEPTH,
    AUTH_TREE_SIZE, DEPTH, F, MIN_TX_FEE, WOTS_CHAINS,
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

pub fn build_shield_bench_witness() -> BenchWitness {
    let deposit_secret = deposit_secret_from_label("bench-sender");
    let deposit_id = deposit_id_from_secret(&deposit_secret);
    let (d_j, auth_root, auth_pub_seed, nk_tag, memo_ct_hash_f, rseed) =
        synthetic_output_fields(0xC000);
    let (
        producer_d_j,
        producer_auth_root,
        producer_auth_pub_seed,
        producer_nk_tag,
        producer_memo_ct_hash_f,
        producer_rseed,
    ) = synthetic_output_fields(0xC100);
    let v_pub = 200_000u64;
    let fee = MIN_TX_FEE;
    let producer_fee = 1u64;
    let cm = commit(
        &d_j,
        v_pub,
        &derive_rcm(&rseed),
        &owner_tag(&auth_root, &auth_pub_seed, &nk_tag),
    );
    let producer_cm = commit(
        &producer_d_j,
        producer_fee,
        &derive_rcm(&producer_rseed),
        &owner_tag(
            &producer_auth_root,
            &producer_auth_pub_seed,
            &producer_nk_tag,
        ),
    );

    let args = vec![
        felt_u64_to_hex(19),
        felt_u64_to_hex(v_pub),
        felt_u64_to_hex(fee),
        felt_u64_to_hex(producer_fee),
        felt_to_hex(&cm),
        felt_to_hex(&producer_cm),
        felt_to_hex(&deposit_id),
        felt_to_hex(&memo_ct_hash_f),
        felt_to_hex(&producer_memo_ct_hash_f),
        felt_to_hex(&deposit_secret),
        felt_to_hex(&auth_root),
        felt_to_hex(&auth_pub_seed),
        felt_to_hex(&nk_tag),
        felt_to_hex(&d_j),
        felt_to_hex(&rseed),
        felt_to_hex(&producer_auth_root),
        felt_to_hex(&producer_auth_pub_seed),
        felt_to_hex(&producer_nk_tag),
        felt_to_hex(&producer_d_j),
        felt_to_hex(&producer_rseed),
    ];

    BenchWitness {
        args,
        expected_public_outputs: vec![
            u64_to_felt(v_pub),
            u64_to_felt(fee),
            u64_to_felt(producer_fee),
            cm,
            producer_cm,
            deposit_id,
            memo_ct_hash_f,
            producer_memo_ct_hash_f,
        ],
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
        let cm = commit(&d_j, value, &derive_rcm(&rseed), &otag);
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

    let (d_j_1, auth_root_1, auth_pub_seed_1, nk_tag_1, mh_1, rseed_1) =
        synthetic_output_fields(0xD000);
    let (d_j_2, auth_root_2, auth_pub_seed_2, nk_tag_2, mh_2, rseed_2) =
        synthetic_output_fields(0xE000);
    let (d_j_3, auth_root_3, auth_pub_seed_3, nk_tag_3, mh_3, rseed_3) =
        synthetic_output_fields(0xF000);
    let producer_fee = 1u64;
    let spendable = total_in - MIN_TX_FEE - producer_fee;
    let v_1 = spendable / 2;
    let v_2 = spendable - v_1;
    let cm_1 = commit(
        &d_j_1,
        v_1,
        &derive_rcm(&rseed_1),
        &owner_tag(&auth_root_1, &auth_pub_seed_1, &nk_tag_1),
    );
    let cm_2 = commit(
        &d_j_2,
        v_2,
        &derive_rcm(&rseed_2),
        &owner_tag(&auth_root_2, &auth_pub_seed_2, &nk_tag_2),
    );
    let cm_3 = commit(
        &d_j_3,
        producer_fee,
        &derive_rcm(&rseed_3),
        &owner_tag(&auth_root_3, &auth_pub_seed_3, &nk_tag_3),
    );

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
        &mh_1,
        &mh_2,
        &mh_3,
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

    let total_fields =
        4 + 9 * n_inputs + n_inputs * DEPTH + n_inputs * AUTH_DEPTH + n_inputs * WOTS_CHAINS + 24;
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

    args.push(felt_to_hex(&cm_1));
    args.push(felt_to_hex(&d_j_1));
    args.push(felt_u64_to_hex(v_1));
    args.push(felt_to_hex(&rseed_1));
    args.push(felt_to_hex(&auth_root_1));
    args.push(felt_to_hex(&auth_pub_seed_1));
    args.push(felt_to_hex(&nk_tag_1));
    args.push(felt_to_hex(&mh_1));

    args.push(felt_to_hex(&cm_2));
    args.push(felt_to_hex(&d_j_2));
    args.push(felt_u64_to_hex(v_2));
    args.push(felt_to_hex(&rseed_2));
    args.push(felt_to_hex(&auth_root_2));
    args.push(felt_to_hex(&auth_pub_seed_2));
    args.push(felt_to_hex(&nk_tag_2));
    args.push(felt_to_hex(&mh_2));

    args.push(felt_to_hex(&cm_3));
    args.push(felt_to_hex(&d_j_3));
    args.push(felt_u64_to_hex(producer_fee));
    args.push(felt_to_hex(&rseed_3));
    args.push(felt_to_hex(&auth_root_3));
    args.push(felt_to_hex(&auth_pub_seed_3));
    args.push(felt_to_hex(&nk_tag_3));
    args.push(felt_to_hex(&mh_3));

    let mut expected_public_outputs = vec![auth_domain, root];
    expected_public_outputs.extend(nullifiers.iter().copied());
    expected_public_outputs.push(u64_to_felt(fee));
    expected_public_outputs.extend([cm_1, cm_2, cm_3, mh_1, mh_2, mh_3]);

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
        let cm = commit(&d_j, value, &derive_rcm(&rseed), &otag);
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
        &derive_rcm(&rseed_change),
        &owner_tag(&auth_root_change, &auth_pub_seed_change, &nk_tag_change),
    );
    let (d_j_fee, auth_root_fee, auth_pub_seed_fee, nk_tag_fee, mh_fee, rseed_fee) =
        synthetic_output_fields(0xF300);
    let cm_fee = commit(
        &d_j_fee,
        producer_fee,
        &derive_rcm(&rseed_fee),
        &owner_tag(&auth_root_fee, &auth_pub_seed_fee, &nk_tag_fee),
    );
    let sighash = unshield_sighash(
        &auth_domain,
        &root,
        &nullifiers,
        v_pub,
        fee,
        &recipient,
        &cm_change,
        &mh_change,
        &cm_fee,
        &mh_fee,
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

    let total_fields =
        6 + 9 * n_inputs + n_inputs * DEPTH + n_inputs * AUTH_DEPTH + n_inputs * WOTS_CHAINS + 15;
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

    args.push(felt_u64_to_hex(1));
    args.push(felt_to_hex(&d_j_change));
    args.push(felt_u64_to_hex(v_change));
    args.push(felt_to_hex(&rseed_change));
    args.push(felt_to_hex(&auth_root_change));
    args.push(felt_to_hex(&auth_pub_seed_change));
    args.push(felt_to_hex(&nk_tag_change));
    args.push(felt_to_hex(&mh_change));

    args.push(felt_to_hex(&d_j_fee));
    args.push(felt_u64_to_hex(producer_fee));
    args.push(felt_to_hex(&rseed_fee));
    args.push(felt_to_hex(&auth_root_fee));
    args.push(felt_to_hex(&auth_pub_seed_fee));
    args.push(felt_to_hex(&nk_tag_fee));
    args.push(felt_to_hex(&mh_fee));

    let mut expected_public_outputs = vec![auth_domain, root];
    expected_public_outputs.extend(nullifiers.iter().copied());
    expected_public_outputs.extend([
        u64_to_felt(v_pub),
        u64_to_felt(fee),
        recipient,
        cm_change,
        mh_change,
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
