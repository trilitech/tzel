//! Benchmark of TzEL Multiasset circuits (`Shield`, `Transfer`, `Unshield`) on `leanVM`
//! across both **Plain STARK** (`Prover::new(Rate::MIN)`) and **Zero-Knowledge STARK** (`Prover::new(Rate::MIN).zero_knowledge(Randomness::Os)`).

#[global_allocator]
static ALLOC: bench::Jemalloc = bench::Jemalloc;

use leanvm::{Program, Proof, Prover, Randomness, Rate};
use std::time::Instant;
use tzel_guest::ASSET_TEZ;
use tzel_host::{
    ELF, FA2_ASSET_FELT, build_exact_shield, build_exact_transfer, build_exact_unshield,
};

struct BenchCase {
    name: &'static str,
    run: leanvm_guest::Run,
}

fn main() {
    let program = Program::from_elf(ELF).expect("valid tzel.elf");
    let passes: usize = std::env::var("BENCH_PASSES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let cases = vec![
        BenchCase {
            name: "Shield (FA2)",
            run: build_exact_shield(FA2_ASSET_FELT).1,
        },
        BenchCase {
            name: "Shield (tez)",
            run: build_exact_shield(ASSET_TEZ).1,
        },
        BenchCase {
            name: "Transfer (1-in tez)",
            run: build_exact_transfer(1, false).2,
        },
        BenchCase {
            name: "Transfer (2-in FA2+tez)",
            run: build_exact_transfer(2, true).2,
        },
        BenchCase {
            name: "Transfer (5-in 4FA2+tez)",
            run: build_exact_transfer(5, true).2,
        },
        BenchCase {
            name: "Unshield (1-in tez)",
            run: build_exact_unshield(1, false).2,
        },
        BenchCase {
            name: "Unshield (2-in FA2+tez)",
            run: build_exact_unshield(2, true).2,
        },
        BenchCase {
            name: "Unshield (5-in 4FA2+tez)",
            run: build_exact_unshield(5, true).2,
        },
    ];

    let filter = std::env::var("BENCH_FILTER").ok();
    let prover_plain = Prover::new(Rate::MIN);
    let prover_zk = Prover::new(Rate::MIN).zero_knowledge(Randomness::Os);

    println!(
        "{:<32} | {:<5} | {:>9} | {:>11} | {:>10} | {:>10} | {:>9} | {:>9}",
        "Circuit / Spec",
        "Mode",
        "Cycles",
        "Proven Rows",
        "Prove (ms)",
        "Verify(ms)",
        "Proof KiB",
        "Table Breakdown"
    );
    println!("{}", "-".repeat(135));

    for case in &cases {
        if let Some(ref f) = filter {
            if !case.name.contains(f) {
                continue;
            }
        }
        for (mode_label, prover) in [("Plain", &prover_plain), ("ZK", &prover_zk)] {
            // Warmup pass
            let warm = prover
                .prove(&program, &case.run.advice)
                .expect("warmup proof succeeds");
            assert_eq!(warm.output, case.run.expected);
            let proof_bytes = warm.proof.to_bytes();
            let decoded = Proof::from_bytes(&proof_bytes).expect("valid proof bytes");
            program
                .verify(warm.output, &decoded)
                .expect("warmup verify succeeds");

            // Timed passes
            let mut prove_ms = Vec::with_capacity(passes);
            let mut verify_ms = Vec::with_capacity(passes);
            for _ in 0..passes {
                let t0 = Instant::now();
                let proven = prover
                    .prove(&program, &case.run.advice)
                    .expect("prove succeeds");
                prove_ms.push(t0.elapsed().as_secs_f64() * 1000.0);

                let bytes = proven.proof.to_bytes();
                let proof = Proof::from_bytes(&bytes).unwrap();
                let t1 = Instant::now();
                program.verify(proven.output, &proof).expect("verify succeeds");
                verify_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
            }

            prove_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
            verify_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let median_prove = prove_ms[passes / 2];
            let median_verify = verify_ms[passes / 2];
            let proof_kib = proof_bytes.len() as f64 / 1024.0;

            println!(
                "{:<32} | {:<5} | {:>9} | {:>11} | {:>10.2} | {:>10.2} | {:>9.1} | {}",
                case.name,
                mode_label,
                warm.stats.cycles(),
                warm.stats.proven_rows,
                median_prove,
                median_verify,
                proof_kib,
                warm.stats.details()
            );
        }
    }
}
