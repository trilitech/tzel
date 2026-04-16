//! TzEL proof generator.
//!
//! Modes:
//!   reprove <executable.json>                       — generate ZK proof, write bundle to --output
//!   reprove <executable.json> --debug-single-level  — single-level proof (NOT ZK, debug only)

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::fmt;
use tzel_reprover::{
    compute_executable_program_hash, custom_circuit::VerifyMeta as ReproveVerifyMeta,
    prove_single_level, prove_single_level_with_args_file, prove_with_args_file,
};
use tzel_verifier::{ProofBundle, VerifyMeta};

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

fn verify_meta_from_reprove(meta: ReproveVerifyMeta) -> VerifyMeta {
    VerifyMeta {
        n_pow_bits: meta.n_pow_bits,
        n_preprocessed_columns: meta.n_preprocessed_columns,
        n_trace_columns: meta.n_trace_columns,
        n_interaction_columns: meta.n_interaction_columns,
        trace_columns_per_component: meta.trace_columns_per_component,
        interaction_columns_per_component: meta.interaction_columns_per_component,
        cumulative_sum_columns: meta.cumulative_sum_columns,
        n_components: meta.n_components,
        fri_log_trace_size: meta.fri_log_trace_size,
        fri_log_blowup: meta.fri_log_blowup,
        fri_log_last_layer: meta.fri_log_last_layer,
        fri_n_queries: meta.fri_n_queries,
        fri_fold_step: meta.fri_fold_step,
        interaction_pow_bits: meta.interaction_pow_bits,
        circuit_pow_bits: meta.circuit_pow_bits,
        circuit_fri_log_blowup: meta.circuit_fri_log_blowup,
        circuit_fri_log_last_layer: meta.circuit_fri_log_last_layer,
        circuit_fri_n_queries: meta.circuit_fri_n_queries,
        circuit_fri_fold_step: meta.circuit_fri_fold_step,
        circuit_lifting: meta.circuit_lifting,
        output_addresses: meta.output_addresses,
        n_blake_gates: meta.n_blake_gates,
        preprocessed_column_ids: meta.preprocessed_column_ids,
        preprocessed_root: meta.preprocessed_root,
        public_output_values: meta.public_output_values,
    }
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
            let bundle = ProofBundle::from_output_parts(
                proof_output.proof.clone(),
                proof_output
                    .output_preimage
                    .iter()
                    .map(|felt| felt.to_bytes_le())
                    .collect(),
                verify_meta_from_reprove(proof_output.verify_meta.clone()),
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

    fn sample_reprove_verify_meta() -> ReproveVerifyMeta {
        ReproveVerifyMeta {
            n_pow_bits: 7,
            n_preprocessed_columns: 8,
            n_trace_columns: 9,
            n_interaction_columns: 10,
            trace_columns_per_component: vec![11, 12],
            interaction_columns_per_component: vec![13, 14],
            cumulative_sum_columns: vec![true, false, true],
            n_components: 15,
            fri_log_trace_size: 16,
            fri_log_blowup: 17,
            fri_log_last_layer: 18,
            fri_n_queries: 19,
            fri_fold_step: 20,
            interaction_pow_bits: 21,
            circuit_pow_bits: 22,
            circuit_fri_log_blowup: 23,
            circuit_fri_log_last_layer: 24,
            circuit_fri_n_queries: 25,
            circuit_fri_fold_step: 26,
            circuit_lifting: Some(27),
            output_addresses: vec![28, 29],
            n_blake_gates: 30,
            preprocessed_column_ids: vec!["alpha".into(), "beta".into()],
            preprocessed_root: vec![31, 32, 33, 34, 35, 36, 37, 38],
            public_output_values: vec![39, 40, 41, 42],
        }
    }

    fn assert_verify_meta_matches_reprove(actual: &VerifyMeta, expected: &ReproveVerifyMeta) {
        assert_eq!(actual.n_pow_bits, expected.n_pow_bits);
        assert_eq!(
            actual.n_preprocessed_columns,
            expected.n_preprocessed_columns
        );
        assert_eq!(actual.n_trace_columns, expected.n_trace_columns);
        assert_eq!(actual.n_interaction_columns, expected.n_interaction_columns);
        assert_eq!(
            actual.trace_columns_per_component,
            expected.trace_columns_per_component
        );
        assert_eq!(
            actual.interaction_columns_per_component,
            expected.interaction_columns_per_component
        );
        assert_eq!(
            actual.cumulative_sum_columns,
            expected.cumulative_sum_columns
        );
        assert_eq!(actual.n_components, expected.n_components);
        assert_eq!(actual.fri_log_trace_size, expected.fri_log_trace_size);
        assert_eq!(actual.fri_log_blowup, expected.fri_log_blowup);
        assert_eq!(actual.fri_log_last_layer, expected.fri_log_last_layer);
        assert_eq!(actual.fri_n_queries, expected.fri_n_queries);
        assert_eq!(actual.fri_fold_step, expected.fri_fold_step);
        assert_eq!(actual.interaction_pow_bits, expected.interaction_pow_bits);
        assert_eq!(actual.circuit_pow_bits, expected.circuit_pow_bits);
        assert_eq!(
            actual.circuit_fri_log_blowup,
            expected.circuit_fri_log_blowup
        );
        assert_eq!(
            actual.circuit_fri_log_last_layer,
            expected.circuit_fri_log_last_layer
        );
        assert_eq!(actual.circuit_fri_n_queries, expected.circuit_fri_n_queries);
        assert_eq!(actual.circuit_fri_fold_step, expected.circuit_fri_fold_step);
        assert_eq!(actual.circuit_lifting, expected.circuit_lifting);
        assert_eq!(actual.output_addresses, expected.output_addresses);
        assert_eq!(actual.n_blake_gates, expected.n_blake_gates);
        assert_eq!(
            actual.preprocessed_column_ids,
            expected.preprocessed_column_ids
        );
        assert_eq!(actual.preprocessed_root, expected.preprocessed_root);
        assert_eq!(actual.public_output_values, expected.public_output_values);
    }

    fn assert_verify_meta_eq(left: &VerifyMeta, right: &VerifyMeta) {
        assert_eq!(left.n_pow_bits, right.n_pow_bits);
        assert_eq!(left.n_preprocessed_columns, right.n_preprocessed_columns);
        assert_eq!(left.n_trace_columns, right.n_trace_columns);
        assert_eq!(left.n_interaction_columns, right.n_interaction_columns);
        assert_eq!(
            left.trace_columns_per_component,
            right.trace_columns_per_component
        );
        assert_eq!(
            left.interaction_columns_per_component,
            right.interaction_columns_per_component
        );
        assert_eq!(left.cumulative_sum_columns, right.cumulative_sum_columns);
        assert_eq!(left.n_components, right.n_components);
        assert_eq!(left.fri_log_trace_size, right.fri_log_trace_size);
        assert_eq!(left.fri_log_blowup, right.fri_log_blowup);
        assert_eq!(left.fri_log_last_layer, right.fri_log_last_layer);
        assert_eq!(left.fri_n_queries, right.fri_n_queries);
        assert_eq!(left.fri_fold_step, right.fri_fold_step);
        assert_eq!(left.interaction_pow_bits, right.interaction_pow_bits);
        assert_eq!(left.circuit_pow_bits, right.circuit_pow_bits);
        assert_eq!(left.circuit_fri_log_blowup, right.circuit_fri_log_blowup);
        assert_eq!(
            left.circuit_fri_log_last_layer,
            right.circuit_fri_log_last_layer
        );
        assert_eq!(left.circuit_fri_n_queries, right.circuit_fri_n_queries);
        assert_eq!(left.circuit_fri_fold_step, right.circuit_fri_fold_step);
        assert_eq!(left.circuit_lifting, right.circuit_lifting);
        assert_eq!(left.output_addresses, right.output_addresses);
        assert_eq!(left.n_blake_gates, right.n_blake_gates);
        assert_eq!(left.preprocessed_column_ids, right.preprocessed_column_ids);
        assert_eq!(left.preprocessed_root, right.preprocessed_root);
        assert_eq!(left.public_output_values, right.public_output_values);
    }

    #[test]
    fn verify_meta_from_reprove_preserves_all_fields() {
        let meta = sample_reprove_verify_meta();
        let converted = verify_meta_from_reprove(meta.clone());

        assert_verify_meta_matches_reprove(&converted, &meta);
    }

    #[test]
    fn verify_meta_from_reprove_roundtrips_through_verifier_codec() {
        let converted = verify_meta_from_reprove(sample_reprove_verify_meta());
        let encoded = tzel_verifier::encode_verify_meta(&converted).unwrap();
        let decoded = tzel_verifier::decode_verify_meta(&encoded).unwrap();

        assert_verify_meta_eq(&decoded, &converted);
    }
}
