//! TzEL proof generator.
//!
//! Modes:
//!   reprove <executable.json>                       — generate ZK proof, write bundle to --output
//!   reprove <executable.json> --debug-single-level  — single-level proof (NOT ZK, debug only)

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Result};
use clap::Parser;
use tracing_subscriber::fmt;
use tzel_core::F;
use tzel_reprover::{
    compute_executable_program_hash, prove_single_level, prove_single_level_with_args_file,
    prove_with_args_file,
};
use tzel_verifier::ProofBundle;

#[derive(Parser)]
#[command(
    name = "reprove",
    about = "Generate privacy proofs for TzEL executables"
)]
struct Cli {
    /// Path to a .executable.json file
    executable: PathBuf,

    /// Write proof bundle (JSON) to this file
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// JSON file with witness arguments (array of hex felt strings, length-prefixed)
    #[arg(long)]
    arguments_file: Option<PathBuf>,

    /// DEBUG ONLY: single-level proof (NOT zero-knowledge)
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
        let program_hash = compute_executable_program_hash(&cli.executable)?;
        let expected_program_hash = program_hash.to_bytes_le();
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
        let program_hash = compute_executable_program_hash(&cli.executable)?;
        println!("{}", hex::encode(program_hash.to_bytes_le()));
        return Ok(());
    }

    eprintln!("Loading executable from {:?}", cli.executable);
    let t_total = Instant::now();

    let args_file = cli.arguments_file.clone();

    if cli.debug_single_level {
        eprintln!("WARNING: single-level mode is NOT zero-knowledge");
        let t_prove = Instant::now();
        let (compressed, _output_preimage) = if args_file.is_some() {
            prove_single_level_with_args_file(&cli.executable, args_file)?
        } else {
            prove_single_level(&cli.executable)?
        };
        let prove_ms = t_prove.elapsed().as_millis();
        let peak_mem_kb = get_peak_memory_kb();
        eprintln!("Prove: {}ms, Proof: {} bytes", prove_ms, compressed.len());
        if let Some(mem) = peak_mem_kb {
            eprintln!("Peak RSS: {:.1} MB", mem as f64 / 1024.0);
        }
        println!("prove_ms={}", prove_ms);
        println!("proof_zstd_bytes={}", compressed.len());
        if let Some(mem) = peak_mem_kb {
            println!("peak_rss_kb={}", mem);
        }
    } else {
        eprintln!("Running recursive prove...");
        let t_prove = Instant::now();
        let proof_output = prove_with_args_file(&cli.executable, args_file)?;
        let prove_ms = t_prove.elapsed().as_millis();
        let proof_size = proof_output.proof.len();
        let peak_mem_kb = get_peak_memory_kb();

        eprintln!(
            "Cairo: {}ms, Circuit: {}ms, Total: {}ms, Verify: {}ms",
            proof_output.cairo_prove_ms,
            proof_output.circuit_prove_ms,
            prove_ms,
            proof_output.verify_ms
        );
        eprintln!(
            "Proof: {} bytes ({:.1} KB)",
            proof_size,
            proof_size as f64 / 1024.0
        );
        if let Some(mem) = peak_mem_kb {
            eprintln!("Peak RSS: {:.1} MB", mem as f64 / 1024.0);
        }

        // Write proof bundle (JSON with proof + output_preimage)
        if let Some(path) = cli.output {
            let bundle = ProofBundle::from_proof_parts(
                proof_output.proof.clone(),
                proof_output
                    .output_preimage
                    .iter()
                    .map(|felt| felt.to_bytes_le())
                    .collect(),
            );
            let json = serde_json::to_string(&bundle)?;
            fs::write(&path, &json)?;
            eprintln!("Proof bundle written to {:?} ({} bytes)", path, json.len());
        }

        eprintln!("Total wall: {}ms", t_total.elapsed().as_millis());
        println!("cairo_prove_ms={}", proof_output.cairo_prove_ms);
        println!("circuit_prove_ms={}", proof_output.circuit_prove_ms);
        println!("prove_ms={}", prove_ms);
        println!("verify_ms={}", proof_output.verify_ms);
        println!("proof_bytes={}", proof_size);
        println!("output_preimage_len={}", proof_output.output_preimage.len());
        if let Some(mem) = peak_mem_kb {
            println!("peak_rss_kb={}", mem);
        }
    }

    Ok(())
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
}
