//! TzEL proof generator (`leanVM` ZK STARK prover by default).
//!
//! Modes:
//!   reprove <executable.json>                       — generate ZK STARK proof via leanVM, write bundle to --output
//!   reprove <executable.json> --debug-single-level  — non-ZK plain STARK proof (debug only)

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, Result};
use clap::Parser;
use leanvm::{Program, Proof as LeanProof, Prover, Randomness, Rate};
use tracing_subscriber::fmt;
use tzel_core::{CircuitKind, F};
use tzel_verifier::{compute_executable_program_hash, ProofBundle};

#[derive(Parser)]
#[command(
    name = "reprove",
    about = "Generate privacy proofs for TzEL circuits using leanVM ZK STARKs"
)]
struct Cli {
    /// Path to a circuit executable (.executable.json or circuit name)
    executable: PathBuf,

    /// Write proof bundle (JSON) to this file
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// JSON file with witness arguments (array of hex felt strings, length-prefixed)
    #[arg(long)]
    arguments_file: Option<PathBuf>,

    /// Prove a built-in synthetic sample transaction when --arguments-file is omitted
    #[arg(long)]
    sample: bool,

    /// DEBUG ONLY: non-ZK plain STARK proof
    #[arg(long)]
    debug_single_level: bool,

    /// Verify a proof bundle JSON file instead of generating a proof.
    /// Exit code 0 = valid, 1 = invalid.
    #[arg(long)]
    verify: Option<PathBuf>,

    /// Print the bootloader-authenticated program hash for the executable and exit.
    #[arg(long)]
    program_hash: bool,
}

fn get_peak_memory_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
}

fn infer_circuit_kind(executable: &Path) -> Result<CircuitKind> {
    let candidate = executable
        .file_name()
        .and_then(|s| s.to_str())
        .or_else(|| executable.to_str());
    match candidate {
        Some("shield" | "tzel_run_shield.executable.json" | "run_shield.executable.json") => {
            Ok(CircuitKind::Shield)
        }
        Some(
            "transfer" | "tzel_run_transfer.executable.json" | "run_transfer.executable.json",
        ) => Ok(CircuitKind::Transfer),
        Some(
            "unshield" | "tzel_run_unshield.executable.json" | "run_unshield.executable.json",
        ) => Ok(CircuitKind::Unshield),
        _ => Err(anyhow!(
            "cannot infer TzEL circuit kind from executable path '{}'",
            executable.display()
        )),
    }
}

fn build_leanvm_run(
    executable: &Path,
    args_file: Option<&Path>,
    allow_sample: bool,
) -> Result<(Vec<F>, tzel_host::Run)> {
    let circuit = infer_circuit_kind(executable)?;
    let (preimage_felts, run) = if let Some(path) = args_file {
        let content = fs::read_to_string(path)?;
        let args: Vec<String> = serde_json::from_str(&content)?;
        match circuit {
            CircuitKind::Shield => tzel_host::parse_cairo_shield_args(&args)
                .map_err(|e| anyhow!("{e}"))?,
            CircuitKind::Transfer => tzel_host::parse_cairo_transfer_args(&args)
                .map_err(|e| anyhow!("{e}"))?,
            CircuitKind::Unshield => tzel_host::parse_cairo_unshield_args(&args)
                .map_err(|e| anyhow!("{e}"))?,
        }
    } else if allow_sample {
        match circuit {
            CircuitKind::Shield => {
                let (tx, run) = tzel_host::build_exact_shield(tzel_host::ASSET_TEZ);
                let out = tx.verify().map_err(|e| anyhow!("{e}"))?;
                let pre = tzel_host::wrap_bootloader_output_preimage(
                    tzel_host::PROGRAM_HASH_SHIELD,
                    &out,
                );
                (pre, run)
            }
            CircuitKind::Transfer => {
                let (hdr, inputs, run) = tzel_host::build_exact_transfer(1, false);
                let mut pub_outputs = Vec::with_capacity(11 + inputs.len());
                pub_outputs.push(hdr.auth_domain);
                pub_outputs.push(hdr.root);
                for inp in &inputs {
                    pub_outputs.push(inp.nf);
                }
                pub_outputs.push(tzel_host::u64_to_felt(hdr.fee));
                for out in &hdr.outputs {
                    pub_outputs.push(out.cm);
                }
                for out in &hdr.outputs {
                    pub_outputs.push(out.memo_ct_hash);
                }
                let pre = tzel_host::wrap_bootloader_output_preimage(
                    tzel_host::PROGRAM_HASH_TRANSFER,
                    &pub_outputs,
                );
                (pre, run)
            }
            CircuitKind::Unshield => {
                let (hdr, inputs, run) = tzel_host::build_exact_unshield(1, false);
                let (c1, c2, cf) = hdr.verify(&inputs).map_err(|e| anyhow!("{e}"))?;
                let mut pub_outputs = Vec::with_capacity(12 + inputs.len());
                pub_outputs.push(hdr.auth_domain);
                pub_outputs.push(hdr.root);
                for inp in &inputs {
                    pub_outputs.push(inp.nf);
                }
                pub_outputs.push(tzel_host::u64_to_felt(hdr.v_pub));
                pub_outputs.push(hdr.asset_pub);
                pub_outputs.push(tzel_host::u64_to_felt(hdr.fee));
                pub_outputs.push(hdr.recipient);
                pub_outputs.push(c1);
                pub_outputs.push(hdr.change_1.memo_ct_hash);
                pub_outputs.push(c2);
                pub_outputs.push(hdr.change_2.memo_ct_hash);
                pub_outputs.push(cf);
                pub_outputs.push(hdr.fee_note.memo_ct_hash);
                let pre = tzel_host::wrap_bootloader_output_preimage(
                    tzel_host::PROGRAM_HASH_UNSHIELD,
                    &pub_outputs,
                );
                (pre, run)
            }
        }
    } else {
        return Err(anyhow!(
            "--arguments-file is required (or pass --sample to prove a built-in sample transaction)"
        ));
    };
    let output_preimage = preimage_felts
        .iter()
        .map(tzel_host::felt_to_bytes_le)
        .collect();
    Ok((output_preimage, run))
}

fn verify_bundle_for_program_hash(bundle: &ProofBundle, expected_program_hash: &F) -> Result<()> {
    tzel_core::validate_single_task_program_hash(&bundle.output_preimage, expected_program_hash)
        .map_err(|e| anyhow!("proof bundle executable mismatch: {e}"))?;
    bundle.verify()
}

fn main() -> Result<()> {
    fmt().with_max_level(tracing::Level::INFO).init();
    let cli = Cli::parse();

    // ── Verify mode ──────────────────────────────────────────────────
    if let Some(bundle_path) = &cli.verify {
        eprintln!("Verifying proof bundle: {:?}", bundle_path);
        let bundle_json = std::fs::read_to_string(bundle_path)?;
        let bundle: ProofBundle = serde_json::from_str(&bundle_json)?;
        let expected_program_hash =
            compute_executable_program_hash(&cli.executable).map_err(|e| anyhow!("{e}"))?;
        match verify_bundle_for_program_hash(&bundle, &expected_program_hash) {
            Ok(()) => {
                eprintln!("Proof VALID ✓");
                println!("verify=ok");
                return Ok(());
            }
            Err(e) => {
                eprintln!("Proof INVALID: {}", e);
                std::process::exit(1);
            }
        }
    }

    if cli.program_hash {
        let program_hash =
            compute_executable_program_hash(&cli.executable).map_err(|e| anyhow!("{e}"))?;
        println!("{}", hex::encode(program_hash));
        return Ok(());
    }

    eprintln!("Loading circuit from {:?}", cli.executable);
    let t_total = Instant::now();

    let (output_preimage, run) = build_leanvm_run(
        &cli.executable,
        cli.arguments_file.as_deref(),
        cli.sample,
    )?;

    // INSECURE SANDBOX/CI ONLY (gated by --cfg tzel_insecure_sandbox; no
    // prod build sets it).
    #[cfg(tzel_insecure_sandbox)]
    if std::env::var("TZEL_PROVE_MODE").as_deref() == Ok("stub") {
        eprintln!("INSECURE SANDBOX stub: witness check only, no proving");
        let bundle = ProofBundle::from_proof_parts(
            b"kernel-test-skip-verify".to_vec(),
            output_preimage,
        );
        if let Some(path) = &cli.output {
            fs::write(path, serde_json::to_string(&bundle)?)?;
        }
        eprintln!("stub bundle written (no proof generated)");
        return Ok(());
    }

    let program = Program::from_elf(tzel_host::ELF).expect("compiled-in tzel.elf must be valid");
    let (bundle, prove_ms, verify_ms, cycles) = prove_and_package(
        &program,
        &run,
        output_preimage,
        cli.debug_single_level,
    )?;

    let proof_size = bundle.proof_bytes.len();
    let peak_mem_kb = get_peak_memory_kb();

    eprintln!(
        "leanVM {} Prove: {}ms, Verify: {}ms, Cycles: {}",
        if cli.debug_single_level { "Plain" } else { "ZK" },
        prove_ms,
        verify_ms,
        cycles
    );
    eprintln!(
        "Proof: {} bytes ({:.1} KB)",
        proof_size,
        proof_size as f64 / 1024.0
    );
    if let Some(mem) = peak_mem_kb {
        eprintln!("Peak RSS: {:.1} MB", mem as f64 / 1024.0);
    }

    if let Some(path) = cli.output {
        let json = serde_json::to_string(&bundle)?;
        fs::write(&path, &json)?;
        eprintln!("Proof bundle written to {:?} ({} bytes)", path, json.len());
    }

    eprintln!("Total wall: {}ms", t_total.elapsed().as_millis());
    println!("cairo_prove_ms=0");
    println!("circuit_prove_ms={}", prove_ms);
    println!("prove_ms={}", prove_ms);
    println!("verify_ms={}", verify_ms);
    println!("proof_bytes={}", proof_size);
    println!("proof_zstd_bytes={}", proof_size);
    println!("output_preimage_len={}", bundle.output_preimage.len());
    if let Some(mem) = peak_mem_kb {
        println!("peak_rss_kb={}", mem);
    }

    Ok(())
}

fn prove_and_package(
    program: &Program,
    run: &tzel_host::Run,
    output_preimage: Vec<F>,
    debug_single_level: bool,
) -> Result<(ProofBundle, u128, u128, usize)> {
    let t_prove = Instant::now();
    let proven = if debug_single_level {
        eprintln!("WARNING: single-level mode is NOT zero-knowledge");
        Prover::new(Rate::MIN)
            .prove(program, &run.advice)
            .map_err(|e| anyhow!("leanVM prove failed: {e}"))?
    } else {
        eprintln!("Running leanVM ZK STARK prove...");
        Prover::new(Rate::MIN)
            .zero_knowledge(Randomness::Os)
            .prove(program, &run.advice)
            .map_err(|e| anyhow!("leanVM ZK prove failed: {e}"))?
    };
    if proven.output != run.expected {
        return Err(anyhow!(
            "leanVM guest output digest did not match host expected digest"
        ));
    }
    let prove_ms = t_prove.elapsed().as_millis();

    let raw_proof_bytes = proven.proof.to_bytes();
    let compressed = ProofBundle::encode_leanvm_proof_bytes(&raw_proof_bytes)?;
    let bundle = ProofBundle::from_proof_parts(compressed, output_preimage);

    let t_verify = Instant::now();
    if debug_single_level {
        let decoded = LeanProof::from_bytes(&raw_proof_bytes)
            .map_err(|e| anyhow!("decode leanVM proof: {e}"))?;
        program
            .verify(proven.output, &decoded)
            .map_err(|e| anyhow!("leanVM verify failed: {e}"))?;
    } else {
        bundle.verify()?;
    }
    let verify_ms = t_verify.elapsed().as_millis();

    Ok((bundle, prove_ms, verify_ms, proven.stats.cycles()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tzel_core::u64_to_felt;

    fn f(value: u64) -> F {
        u64_to_felt(value)
    }

    #[test]
    fn verify_bundle_rejects_wrong_executable_before_proof_verification() {
        let actual_program_hash = f(22);
        let expected_program_hash = f(99);
        let bundle = ProofBundle::from_proof_parts(
            vec![0xDE, 0xAD],
            vec![f(1), f(4), actual_program_hash, f(1), f(123)],
        );

        let err = verify_bundle_for_program_hash(&bundle, &expected_program_hash)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("unexpected circuit program hash"),
            "wrong executable should fail before proof verification, got: {err}"
        );
    }

    #[test]
    fn missing_arguments_file_without_sample_flag_is_rejected() {
        let executable = Path::new("tzel_run_shield.executable.json");
        let err = build_leanvm_run(executable, None, false)
            .err()
            .expect("missing --arguments-file without --sample should fail")
            .to_string();
        assert!(
            err.contains("--arguments-file is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn debug_single_level_bundle_is_rejected_by_zk_verifier() {
        let executable = Path::new("tzel_run_shield.executable.json");
        let (output_preimage, run) = build_leanvm_run(executable, None, true).unwrap();
        let program = Program::from_elf(tzel_host::ELF).unwrap();
        let (bundle, _, _, _) =
            prove_and_package(&program, &run, output_preimage, true).unwrap();
        let expected_hash = compute_executable_program_hash(executable).unwrap();
        let err = verify_bundle_for_program_hash(&bundle, &expected_hash)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("non-ZK STARK proof rejected"),
            "non-ZK debug bundle must be rejected by ProofBundle::verify, got: {err}"
        );
    }
}
