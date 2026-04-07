/// Generate witness data for all four transfer circuit variants.
/// Uses the CLI's verified hash functions for consistency.

use starkprivacy_cli::*;

fn hash_chain(x: &F, n: usize) -> F {
    let mut v = *x;
    for _ in 0..n { v = hash(&v); }
    v
}

fn felt_hex(f: &F) -> String {
    let be: Vec<u8> = f.iter().rev().cloned().collect();
    let s = hex::encode(be).trim_start_matches('0').to_string();
    if s.is_empty() { "0x0".into() } else { format!("0x{}", s) }
}

fn main() {
    eprintln!("Generating transfer witness data for all variants...");

    // ── Build a consistent transfer N=1 witness ─────────────────────
    // Input note: value 1000, split into 700 + 300
    let nk_spend = random_felt();
    let d_j = random_felt();
    let rseed = random_felt();
    let nk_tag = derive_nk_tag(&nk_spend);

    // Auth tree: minimal (leaf 0, rest zeros)
    let ask_j = random_felt();
    let (auth_root, auth_leaves) = build_auth_tree(&ask_j);
    let auth_leaf = auth_leaves[0];
    let auth_path = auth_tree_path(&auth_leaves, 0);

    let otag = owner_tag(&auth_root, &nk_tag);
    let rcm = derive_rcm(&rseed);
    let cm = commit(&d_j, 1000, &rcm, &otag);

    // Commitment tree: leaf at position 0, depth 48
    let mut cm_tree_zh = ZERO;
    let mut cm_sibs: Vec<F> = Vec::new();
    let mut current = cm;
    for _ in 0..DEPTH {
        cm_sibs.push(cm_tree_zh);
        current = hash_merkle(&current, &cm_tree_zh);
        cm_tree_zh = hash_merkle(&cm_tree_zh, &cm_tree_zh);
    }
    let root = current;
    let nf = nullifier(&nk_spend, &cm, 0);

    // Outputs
    let d_j_1 = random_felt(); let rseed_1 = random_felt();
    let auth_root_1 = random_felt(); let nk_tag_1 = random_felt();
    let otag_1 = owner_tag(&auth_root_1, &nk_tag_1);
    let rcm_1 = derive_rcm(&rseed_1);
    let cm_1 = commit(&d_j_1, 700, &rcm_1, &otag_1);

    let d_j_2 = random_felt(); let rseed_2 = random_felt();
    let auth_root_2 = random_felt(); let nk_tag_2 = random_felt();
    let otag_2 = owner_tag(&auth_root_2, &nk_tag_2);
    let rcm_2 = derive_rcm(&rseed_2);
    let cm_2 = commit(&d_j_2, 300, &rcm_2, &otag_2);

    // ── Baseline args ───────────────────────────────────────────────
    let mut baseline: Vec<String> = Vec::new();
    // root, nf, nk_spend, auth_root, auth_leaf, auth_idx, d_j, v, rseed, cm_path_idx
    let base_scalars = vec![
        felt_hex(&root), felt_hex(&nf), felt_hex(&nk_spend), felt_hex(&auth_root),
        felt_hex(&auth_leaf), "0x0".into(), felt_hex(&d_j), "0x3e8".into(), // v=1000
        felt_hex(&rseed), "0x0".into(), // cm_path_idx=0
    ];
    for s in &base_scalars { baseline.push(s.clone()); }
    for s in &cm_sibs { baseline.push(felt_hex(s)); }
    for s in &auth_path { baseline.push(felt_hex(s)); }

    // Outputs
    let out_args: Vec<String> = vec![
        felt_hex(&cm_1), felt_hex(&d_j_1), "0x2bc".into(), felt_hex(&rseed_1), // v_1=700
        felt_hex(&auth_root_1), felt_hex(&nk_tag_1),
        felt_hex(&cm_2), felt_hex(&d_j_2), "0x12c".into(), felt_hex(&rseed_2), // v_2=300
        felt_hex(&auth_root_2), felt_hex(&nk_tag_2),
    ];

    let mut baseline_full: Vec<String> = Vec::new();
    let bl = baseline.len() + out_args.len();
    baseline_full.push(format!("0x{:x}", bl));
    baseline_full.extend(baseline.clone());
    baseline_full.extend(out_args.clone());

    write_args("/tmp/bench_baseline.json", &baseline_full);
    eprintln!("  baseline: {} args", baseline_full.len());

    // ── WOTS+ w=4 ───────────────────────────────────────────────────
    let (wots4_sig, wots4_pk, wots4_digits) = gen_wots(4, 133, &ask_j);
    verify_wots(&wots4_sig, &wots4_pk, &wots4_digits, 4);
    let wots4_leaf = pk_to_leaf(&wots4_pk);

    // Build w4-specific auth tree + commitment
    let (w4_auth_root, w4_auth_path) = minimal_auth(wots4_leaf);
    let w4_otag = owner_tag(&w4_auth_root, &nk_tag);
    let w4_rcm = derive_rcm(&rseed);
    let w4_cm = commit(&d_j, 1000, &w4_rcm, &w4_otag);
    let (w4_root, w4_cm_sibs) = minimal_cm_tree(w4_cm);
    let w4_nf = nullifier(&nk_spend, &w4_cm, 0);

    let mut wots4: Vec<String> = Vec::new();
    let base4 = vec![
        felt_hex(&w4_root), felt_hex(&w4_nf), felt_hex(&nk_spend), felt_hex(&w4_auth_root),
        "0x0".into(), felt_hex(&d_j), "0x3e8".into(), felt_hex(&rseed), "0x0".into(),
    ];
    let w4len = base4.len() + DEPTH + AUTH_DEPTH + 133 * 3 + out_args.len();
    wots4.push(format!("0x{:x}", w4len));
    for s in &base4 { wots4.push(s.clone()); }
    for s in &w4_cm_sibs { wots4.push(felt_hex(s)); }
    for s in &w4_auth_path { wots4.push(felt_hex(s)); }
    for s in &wots4_sig { wots4.push(felt_hex(s)); }
    for s in &wots4_pk { wots4.push(felt_hex(s)); }
    for &d in &wots4_digits { wots4.push(format!("0x{:x}", d)); }
    wots4.extend(out_args.clone());

    write_args("/tmp/bench_wots4.json", &wots4);
    eprintln!("  wots4: {} args", wots4.len());

    // ── WOTS+ w=16 ──────────────────────────────────────────────────
    let (wots16_sig, wots16_pk, wots16_digits) = gen_wots(16, 67, &ask_j);
    verify_wots(&wots16_sig, &wots16_pk, &wots16_digits, 16);
    // For w=16 the pk→leaf will differ from auth_leaf (different scheme)
    // So we need a SEPARATE auth tree for w=16 tests
    let wots16_leaf = pk_to_leaf(&wots16_pk);
    let (wots16_auth_root, wots16_auth_path) = minimal_auth(wots16_leaf);
    // Recompute commitment with this auth_root
    let otag16 = owner_tag(&wots16_auth_root, &nk_tag);
    let rcm16 = derive_rcm(&rseed);
    let cm16 = commit(&d_j, 1000, &rcm16, &otag16);
    let mut cm16_sibs: Vec<F> = Vec::new();
    let mut zh16 = ZERO;
    let mut cur16 = cm16;
    for _ in 0..DEPTH {
        cm16_sibs.push(zh16);
        cur16 = hash_merkle(&cur16, &zh16);
        zh16 = hash_merkle(&zh16, &zh16);
    }
    let root16 = cur16;
    let nf16 = nullifier(&nk_spend, &cm16, 0);

    let mut wots16: Vec<String> = Vec::new();
    let base16 = vec![
        felt_hex(&root16), felt_hex(&nf16), felt_hex(&nk_spend), felt_hex(&wots16_auth_root),
        "0x0".into(), felt_hex(&d_j), "0x3e8".into(), felt_hex(&rseed), "0x0".into(),
    ];
    let w16len = base16.len() + DEPTH + AUTH_DEPTH + 67 * 3 + out_args.len();
    wots16.push(format!("0x{:x}", w16len));
    for s in &base16 { wots16.push(s.clone()); }
    for s in &cm16_sibs { wots16.push(felt_hex(s)); }
    for s in &wots16_auth_path { wots16.push(felt_hex(s)); }
    for s in &wots16_sig { wots16.push(felt_hex(s)); }
    for s in &wots16_pk { wots16.push(felt_hex(s)); }
    for &d in &wots16_digits { wots16.push(format!("0x{:x}", d)); }
    wots16.extend(out_args.clone());

    write_args("/tmp/bench_wots16.json", &wots16);
    eprintln!("  wots16: {} args", wots16.len());

    // ── Lamport ─────────────────────────────────────────────────────
    let (lam_revealed, lam_pk0, lam_pk1, lam_msg_hash) = gen_lamport(&ask_j);
    let lam_leaf = lamport_pk_to_leaf(&lam_pk0, &lam_pk1);
    let (lam_auth_root, lam_auth_path) = minimal_auth(lam_leaf);
    let otagL = owner_tag(&lam_auth_root, &nk_tag);
    let rcmL = derive_rcm(&rseed);
    let cmL = commit(&d_j, 1000, &rcmL, &otagL);
    let mut cmL_sibs: Vec<F> = Vec::new();
    let mut zhL = ZERO;
    let mut curL = cmL;
    for _ in 0..DEPTH {
        cmL_sibs.push(zhL);
        curL = hash_merkle(&curL, &zhL);
        zhL = hash_merkle(&zhL, &zhL);
    }
    let rootL = curL;
    let nfL = nullifier(&nk_spend, &cmL, 0);

    let mut lamport: Vec<String> = Vec::new();
    let baseL = vec![
        felt_hex(&rootL), felt_hex(&nfL), felt_hex(&nk_spend), felt_hex(&lam_auth_root),
        "0x0".into(), felt_hex(&d_j), "0x3e8".into(), felt_hex(&rseed), "0x0".into(),
    ];
    let llen = baseL.len() + DEPTH + AUTH_DEPTH + 256 * 3 + 1 + out_args.len();
    lamport.push(format!("0x{:x}", llen));
    for s in &baseL { lamport.push(s.clone()); }
    for s in &cmL_sibs { lamport.push(felt_hex(s)); }
    for s in &lam_auth_path { lamport.push(felt_hex(s)); }
    for s in &lam_revealed { lamport.push(felt_hex(s)); }
    for s in &lam_pk0 { lamport.push(felt_hex(s)); }
    for s in &lam_pk1 { lamport.push(felt_hex(s)); }
    lamport.push(felt_hex(&lam_msg_hash));
    lamport.extend(out_args);

    write_args("/tmp/bench_lamport.json", &lamport);
    eprintln!("  lamport: {} args", lamport.len());
    eprintln!("Done.");
}

fn write_args(path: &str, args: &[String]) {
    let json = serde_json::to_string(args).unwrap();
    std::fs::write(path, json).unwrap();
}

fn pk_to_leaf(pk: &[F]) -> F {
    let mut leaf = pk[0];
    for i in 1..pk.len() {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&leaf);
        buf[32..].copy_from_slice(&pk[i]);
        leaf = hash(&buf);
    }
    leaf
}

fn lamport_pk_to_leaf(pk0: &[F], pk1: &[F]) -> F {
    let mut leaf = pk0[0];
    for i in 0..pk0.len() {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&leaf);
        buf[32..].copy_from_slice(&pk0[i]);
        leaf = hash(&buf);
        buf[..32].copy_from_slice(&leaf);
        buf[32..].copy_from_slice(&pk1[i]);
        leaf = hash(&buf);
    }
    leaf
}

fn minimal_cm_tree(cm: F) -> (F, Vec<F>) {
    let mut zh = ZERO;
    let mut sibs: Vec<F> = Vec::new();
    let mut current = cm;
    for _ in 0..DEPTH {
        sibs.push(zh);
        current = hash_merkle(&current, &zh);
        zh = hash_merkle(&zh, &zh);
    }
    (current, sibs)
}

fn minimal_auth(leaf: F) -> (F, Vec<F>) {
    let mut zh = ZERO;
    let mut path: Vec<F> = Vec::new();
    let mut current = leaf;
    for _ in 0..AUTH_DEPTH {
        path.push(zh);
        current = hash_merkle(&current, &zh);
        zh = hash_merkle(&zh, &zh);
    }
    (current, path)
}

fn gen_wots(w: usize, chains: usize, ask_j: &F) -> (Vec<F>, Vec<F>, Vec<usize>) {
    // Generate WOTS+ keys from ask_j (so auth_leaf matches)
    let mut sk: Vec<F> = Vec::new();
    let mut pk: Vec<F> = Vec::new();
    for i in 0..chains {
        let seed = auth_key_seed(ask_j, i as u32);
        // Use seed as sk directly (simplified — real WOTS+ would derive differently)
        sk.push(seed);
        pk.push(hash_chain(&seed, w - 1));
    }

    // Message hash
    let msg = hash(b"bench sighash");
    let log_w = (w as f64).log2() as usize;

    let mut digits: Vec<usize> = Vec::new();
    for byte in msg.iter() {
        let mut b = *byte;
        for _ in 0..(8 / log_w) {
            digits.push((b & ((1 << log_w) - 1)) as usize);
            b >>= log_w;
        }
    }
    // Checksum
    let cs_count = if w == 4 { 5 } else { 3 }; // simplified
    let checksum: usize = digits.iter().map(|d| w - 1 - d).sum();
    let mut cs = checksum;
    for _ in 0..cs_count {
        digits.push(cs & ((1 << log_w) - 1));
        cs >>= log_w;
    }
    digits.truncate(chains);

    let sig: Vec<F> = digits.iter().enumerate()
        .map(|(i, &d)| hash_chain(&sk[i], d))
        .collect();

    (sig, pk, digits)
}

fn verify_wots(sig: &[F], pk: &[F], digits: &[usize], w: usize) {
    for (i, &d) in digits.iter().enumerate() {
        let remaining = w - 1 - d;
        let computed = hash_chain(&sig[i], remaining);
        assert_eq!(computed, pk[i], "wots verify failed at chain {}", i);
    }
    eprintln!("  wots w={} local verify OK ({} chains)", w, sig.len());
}

fn gen_lamport(ask_j: &F) -> (Vec<F>, Vec<F>, Vec<F>, F) {
    let mut sk0: Vec<F> = Vec::new();
    let mut sk1: Vec<F> = Vec::new();
    let mut pk0: Vec<F> = Vec::new();
    let mut pk1: Vec<F> = Vec::new();

    for i in 0..256u32 {
        let seed = auth_key_seed(ask_j, i);
        let s0 = hash(&seed);
        let mut seed2 = seed;
        seed2[0] ^= 0xFF;
        let s1 = hash(&seed2);
        pk0.push(hash(&s0));
        pk1.push(hash(&s1));
        sk0.push(s0);
        sk1.push(s1);
    }

    let msg_hash = hash(b"bench sighash");
    let mut revealed: Vec<F> = Vec::new();
    for i in 0..256 {
        let byte = msg_hash[i / 8];
        let bit = (byte >> (i % 8)) & 1;
        revealed.push(if bit == 0 { sk0[i] } else { sk1[i] });
    }

    // Verify locally
    for i in 0..256 {
        let h = hash(&revealed[i]);
        let byte = msg_hash[i / 8];
        let bit = (byte >> (i % 8)) & 1;
        let expected = if bit == 0 { pk0[i] } else { pk1[i] };
        assert_eq!(h, expected, "lamport verify failed at bit {}", i);
    }
    eprintln!("  lamport local verify OK (256 bits)");

    (revealed, pk0, pk1, msg_hash)
}
