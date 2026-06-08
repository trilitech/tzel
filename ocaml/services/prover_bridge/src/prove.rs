//! tzel-prove: CLI bridge for the StarkWare proving stack.
//!
//! Takes a Cairo PIE file (produced by running a shield/transfer/unshield
//! circuit on the Cairo VM) and produces a privacy proof bundle.
//!
//! Usage:
//!   tzel-prove --pie <path> --output <path> [--recursive]
//!
//! The output is a JSON file:
//! {
//!   "proof_bytes": "<hex-encoded zstd-compressed proof>",
//!   "output_preimage": ["0x...", ...]
//! }

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use cairo_vm::vm::runners::cairo_pie::CairoPie;
use clap::Parser;
use privacy_prove::{privacy_prove, privacy_recursive_prove, prepare_recursive_prover_precomputes};
use starknet_types_core::felt::Felt;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "tzel-prove", about = "Generate a privacy STARK proof from a Cairo PIE")]
struct Args {
    /// Path to the Cairo PIE file
    #[arg(long)]
    pie: PathBuf,

    /// Output path for the proof bundle JSON
    #[arg(long)]
    output: PathBuf,

    /// Use two-level recursive proving (required for ZK)
    #[arg(long, default_value_t = false)]
    recursive: bool,
}

#[derive(serde::Serialize)]
struct ProofBundle {
    /// Hex-encoded zstd-compressed proof bytes
    proof_bytes: String,
    /// Output preimage felts (hex strings)
    output_preimage: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Load the Cairo PIE
    let pie = CairoPie::read_zip_file(&args.pie)?;

    // Run the prover
    let proof_output = if args.recursive {
        let precomputes = prepare_recursive_prover_precomputes()?;
        privacy_recursive_prove(pie, precomputes)?
    } else {
        privacy_prove(pie)?
    };

    // Serialize the output
    let bundle = ProofBundle {
        proof_bytes: hex::encode(&proof_output.proof),
        output_preimage: proof_output
            .output_preimage
            .iter()
            .map(|f| format!("0x{}", hex::encode(f.to_bytes_le())))
            .collect(),
    };

    let json = serde_json::to_string_pretty(&bundle)?;
    fs::write(&args.output, json)?;

    eprintln!("Proof written to {}", args.output.display());
    Ok(())
}
