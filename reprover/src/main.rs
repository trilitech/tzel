//! StarkPrivacy proof generator.
//!
//! Modes:
//!   reprove <executable.json>                       — generate ZK proof, write bundle to --output
//!   reprove <executable.json> --debug-single-level  — single-level proof (NOT ZK, debug only)

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use starkprivacy_reprover::custom_circuit::ProofBundle;
use starkprivacy_reprover::{
    compute_executable_program_hash, prove_single_level, prove_with_args_file,
};
use tracing_subscriber::fmt;

#[derive(Parser)]
#[command(
    name = "reprove",
    about = "Generate privacy proofs for StarkPrivacy executables"
)]
struct Cli {
    /// Path to a .executable.json file
    executable: PathBuf,

    /// Write proof bundle (JSON) to this file
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// JSON file with witness arguments (array of decimal felt strings, length-prefixed)
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

fn main() -> Result<()> {
    fmt().with_max_level(tracing::Level::INFO).init();
    let cli = Cli::parse();

    // ── Verify mode ──────────────────────────────────────────────────
    if let Some(bundle_path) = &cli.verify {
        eprintln!("Verifying proof bundle: {:?}", bundle_path);
        let bundle_json = std::fs::read_to_string(bundle_path)?;
        let bundle: ProofBundle = serde_json::from_str(&bundle_json)?;
        match bundle.verify() {
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
        println!("{}", program_hash);
        return Ok(());
    }

    eprintln!("Loading executable from {:?}", cli.executable);
    let t_total = Instant::now();

    let args_file = cli.arguments_file.clone();

    if cli.debug_single_level {
        eprintln!("WARNING: single-level mode is NOT zero-knowledge");
        let t_prove = Instant::now();
        let (compressed, _output_preimage) = prove_single_level(&cli.executable)?;
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
            let bundle = ProofBundle::from_output(&proof_output);
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
