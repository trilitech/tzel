//! Benchmark hash-based OTS schemes for STARK-internal verification.
//! We care about: number of hash operations for verification (= STARK circuit cost).

use blake2s_simd::Params;
use rand::Rng;

type H = [u8; 32];

fn hash(data: &[u8]) -> H {
    let d = Params::new().hash_length(32).hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

fn hash_chain(x: &H, n: usize) -> H {
    let mut v = *x;
    for _ in 0..n { v = hash(&v); }
    v
}

// ═══════════════════════════════════════════════════════════════════════
// Lamport OTS (256-bit)
// ═══════════════════════════════════════════════════════════════════════

fn lamport_bench(msg: &H) {
    let mut rng = rand::rng();
    let bits = 256;

    // Keygen
    let mut sk: Vec<(H, H)> = Vec::new();
    let mut pk: Vec<(H, H)> = Vec::new();
    for _ in 0..bits {
        let s0: H = rng.random();
        let s1: H = rng.random();
        pk.push((hash(&s0), hash(&s1)));
        sk.push((s0, s1));
    }

    // Sign
    let mut sig: Vec<H> = Vec::new();
    for i in 0..bits {
        let bit = (msg[i / 8] >> (i % 8)) & 1;
        sig.push(if bit == 0 { sk[i].0 } else { sk[i].1 });
    }

    // Verify — count hashes
    let mut hashes = 0usize;
    for i in 0..bits {
        let h = hash(&sig[i]); hashes += 1;
        let bit = (msg[i / 8] >> (i % 8)) & 1;
        let expected = if bit == 0 { pk[i].0 } else { pk[i].1 };
        assert_eq!(h, expected);
    }
    // PK to leaf hash
    let mut pk_buf = Vec::with_capacity(bits * 64);
    for (p0, p1) in &pk { pk_buf.extend_from_slice(p0); pk_buf.extend_from_slice(p1); }
    let _leaf = hash(&pk_buf); hashes += 1;

    let auth_tree = 10; // AUTH_DEPTH
    let total = hashes + auth_tree;

    println!("Lamport-256:");
    println!("  Verify:         {} hashes", hashes - 1);
    println!("  PK→leaf:        1 hash");
    println!("  Auth tree:      {} hashes", auth_tree);
    println!("  TOTAL in STARK: {} hashes", total);
    println!("  Sig size:       {} bytes ({:.1} KB)", bits * 32, bits as f64 * 32.0 / 1024.0);
    println!("  PK size:        {} bytes ({:.1} KB)", bits * 64, bits as f64 * 64.0 / 1024.0);
}

// ═══════════════════════════════════════════════════════════════════════
// WOTS+ (parameterized by w)
// ═══════════════════════════════════════════════════════════════════════

fn wots_bench(msg: &H, w: usize) {
    let mut rng = rand::rng();
    let log_w = (w as f64).log2() as usize;
    let msg_chains = 256 / log_w;

    // Checksum
    let max_checksum = msg_chains * (w - 1);
    let checksum_bits = (max_checksum as f64).log2().ceil() as usize + 1;
    let cs_chains = (checksum_bits + log_w - 1) / log_w;
    let total_chains = msg_chains + cs_chains;

    // Keygen
    let mut sk: Vec<H> = Vec::new();
    let mut pk: Vec<H> = Vec::new();
    for _ in 0..total_chains {
        let s: H = rng.random();
        pk.push(hash_chain(&s, w - 1));
        sk.push(s);
    }

    // Extract digits from message
    let mut digits: Vec<usize> = Vec::new();
    for byte in msg.iter() {
        let mut b = *byte;
        for _ in 0..(8 / log_w) {
            digits.push((b & ((1 << log_w) - 1)) as usize);
            b >>= log_w;
        }
    }
    // Checksum digits
    let checksum: usize = digits.iter().map(|d| w - 1 - d).sum();
    let mut cs = checksum;
    for _ in 0..cs_chains {
        digits.push(cs & ((1 << log_w) - 1));
        cs >>= log_w;
    }
    assert_eq!(digits.len(), total_chains);

    // Sign
    let sig: Vec<H> = digits.iter().enumerate()
        .map(|(i, &d)| hash_chain(&sk[i], d))
        .collect();

    // Verify — count hashes
    let mut verify_hashes = 0usize;
    for (i, &d) in digits.iter().enumerate() {
        let remaining = w - 1 - d;
        let computed = hash_chain(&sig[i], remaining);
        verify_hashes += remaining;
        assert_eq!(computed, pk[i]);
    }

    // Worst case: all digits = 0 → need w-1 hashes per chain
    let worst_verify = total_chains * (w - 1);
    // Best case: all digits = w-1 → need 0 hashes per chain
    // Average: total_chains * (w-1)/2
    let avg_verify = total_chains * (w - 1) / 2;

    // PK to leaf
    let pk_leaf_hashes = 1;

    let auth_tree = 10;
    let total_this = verify_hashes + pk_leaf_hashes + auth_tree;
    let total_worst = worst_verify + pk_leaf_hashes + auth_tree;
    let total_avg = avg_verify + pk_leaf_hashes + auth_tree;

    println!("WOTS+ w={} ({} chains: {} msg + {} checksum):", w, total_chains, msg_chains, cs_chains);
    println!("  Verify:         {} hashes (this msg), {} worst, {} avg",
        verify_hashes, worst_verify, avg_verify);
    println!("  PK→leaf:        1 hash");
    println!("  Auth tree:      {} hashes", auth_tree);
    println!("  TOTAL in STARK: {} (this), {} worst, {} avg", total_this, total_worst, total_avg);
    println!("  Sig size:       {} bytes ({:.1} KB)", total_chains * 32, total_chains as f64 * 32.0 / 1024.0);
    println!("  PK size:        {} bytes ({:.1} KB)", total_chains * 32, total_chains as f64 * 32.0 / 1024.0);
}

fn main() {
    let msg = hash(b"transaction sighash");

    println!("=== Hash-Based OTS: STARK Circuit Cost ===\n");

    lamport_bench(&msg);
    println!();
    wots_bench(&msg, 4);
    println!();
    wots_bench(&msg, 16);
    println!();
    wots_bench(&msg, 256);

    println!("\n=== Context: current circuit hashes ===");
    println!("  Shield:   ~50 hashes (rcm + owner_tag + commit + a few derivations)");
    println!("  Transfer: ~70 hashes per input (above + Merkle(48) + auth(10) + nullifier)");
    println!("  A 2x increase in hashes ≈ 2x increase in Cairo trace ≈ 2x prove time");
    println!();
    println!("=== Recommendation ===");
    println!("  Lamport:   267 extra hashes — ~4x current transfer input cost");
    println!("  WOTS+ w=4: ~211 avg extra   — ~3x current transfer input cost");
    println!("  WOTS+ w=16: ~522 avg extra  — ~7x current transfer input cost");
}
