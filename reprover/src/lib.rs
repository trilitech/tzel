//! StarkPrivacy reprover library — proving and verification APIs.
//!
//! Exposes:
//! - `prove(executable_path)` → proof bytes + public outputs
//! - `verify(proof_bytes, output_preimage)` → ok/err
//! - `CustomProofOutput` struct with proof data and timing

pub mod custom_circuit;

use std::fs::read_to_string;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::{Result, anyhow};
use cairo_program_runner_lib::hints::compute_program_hash_chain;
use cairo_program_runner_lib::tasks::create_cairo1_program_task;
use cairo_program_runner_lib::types::{
    HashFunc, PrivacySimpleBootloaderInput, SimpleBootloaderInput, TaskSpec,
};
use cairo_program_runner_lib::{ProgramInput, cairo_run_program};
use privacy_circuit_verify::get_privacy_bootloader_program;
use privacy_prove::consts::{CAIRO_PROVER_PARAMS, CAIRO_RUN_CONFIG};
use starknet_types_core::felt::Felt;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo_cairo_adapter::adapter::adapt;
use stwo_cairo_prover::prover::prove_cairo;
use tempfile::NamedTempFile;

pub use custom_circuit::CustomProofOutput;
pub use custom_circuit::ProofBundle;

/// Run a Cairo executable through the privacy bootloader,
/// generate a two-level recursive ZK proof.
///
/// `args` is an optional list of felt252 values passed to the executable's main().
/// Returns the proof bytes (zstd-compressed circuit proof) and public outputs.
pub fn prove(executable_path: &PathBuf, args: Option<Vec<Felt>>) -> Result<CustomProofOutput> {
    let (prover_input, output_preimage) = run_privacy_bootloader(executable_path, args, None)?;
    custom_circuit::custom_recursive_prove(prover_input, output_preimage)
}

/// Compute the privacy bootloader program hash for a Cairo 1 executable.
pub fn compute_executable_program_hash(executable_path: &PathBuf) -> Result<Felt> {
    let task =
        create_cairo1_program_task(executable_path, None, None).map_err(|e| anyhow!("{e}"))?;
    let program = task.get_program().map_err(|e| anyhow!("{e}"))?;
    compute_program_hash_chain(&program, 0, HashFunc::Blake).map_err(|e| anyhow!("{e}"))
}

/// Same as `prove` but takes a BigUintAsHex args file path directly.
pub fn prove_with_args_file(
    executable_path: &PathBuf,
    args_file: Option<PathBuf>,
) -> Result<CustomProofOutput> {
    let (prover_input, output_preimage) = run_privacy_bootloader(executable_path, None, args_file)?;
    custom_circuit::custom_recursive_prove(prover_input, output_preimage)
}

/// Run a Cairo executable through the bootloader and generate a
/// single-level (NON-ZK) proof. For debugging/testing only.
pub fn prove_single_level(executable_path: &PathBuf) -> Result<(Vec<u8>, Vec<Felt>)> {
    let (prover_input, output_preimage) = run_privacy_bootloader(executable_path, None, None)?;
    let cairo_proof = prove_cairo::<Blake2sM31MerkleChannel>(prover_input, CAIRO_PROVER_PARAMS)
        .map_err(|e| anyhow!("{e}"))?;
    let json_bytes = serde_json::to_vec(&cairo_proof)?;
    let compressed = zstd::encode_all(&json_bytes[..], 3)?;
    Ok((compressed, output_preimage))
}

/// Run a Cairo executable through the privacy bootloader.
/// `args` is an optional list of felt252 values passed as user_args.
/// Returns the prover input (execution trace) and public outputs.
pub fn run_privacy_bootloader(
    executable_path: &PathBuf,
    args: Option<Vec<Felt>>,
    args_file_path: Option<PathBuf>,
) -> Result<(stwo_cairo_adapter::ProverInput, Vec<Felt>)> {
    // Convert Vec<Felt> to a BigUintAsHex temp file, or use provided file directly.
    let args_temp = if let Some(felts) = args {
        let file = NamedTempFile::new()?;
        let hex_args: Vec<String> = felts.iter().map(|f| format!("{:#x}", f)).collect();
        serde_json::to_writer(&file, &hex_args)?;
        Some(file)
    } else {
        None
    };
    let args_path = args_file_path.or_else(|| args_temp.as_ref().map(|f| f.path().to_path_buf()));
    let task =
        create_cairo1_program_task(executable_path, None, args_path).map_err(|e| anyhow!("{e}"))?;

    let task_spec = TaskSpec {
        task: Rc::new(task),
        program_hash_function: HashFunc::Blake,
    };

    let output_preimage_file = NamedTempFile::new()?;
    let output_preimage_path = output_preimage_file.path().to_path_buf();

    let bootloader_input = PrivacySimpleBootloaderInput {
        simple_bootloader_input: SimpleBootloaderInput {
            fact_topologies_path: None,
            single_page: true,
            tasks: vec![task_spec],
        },
        output_preimage_dump_path: output_preimage_path.clone(),
    };

    let bootloader_program = get_privacy_bootloader_program().map_err(|e| anyhow!("{e}"))?;

    let runner = cairo_run_program(
        &bootloader_program,
        Some(ProgramInput::Value(Box::new(bootloader_input))),
        CAIRO_RUN_CONFIG,
        None,
    )
    .map_err(|e| anyhow!("{e}"))?;

    let output_preimage_content = read_to_string(&output_preimage_path)?;
    let output_preimage: Vec<Felt> = serde_json::from_str(&output_preimage_content)?;
    let prover_input = adapt(&runner).map_err(|e| anyhow!("{e}"))?;

    Ok((prover_input, output_preimage))
}
