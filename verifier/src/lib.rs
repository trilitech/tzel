pub mod groth16;
mod out_hash;
pub mod snark;

pub use snark::{
    compute_expected_out_hash, verify_snark, verify_snark_tree, verify_snark_with_vk,
};

#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;

use tzel_core::{CircuitKind, ProgramHashes};

#[cfg(not(target_arch = "wasm32"))]
use cairo_program_runner_lib::hints::compute_program_hash_chain;
#[cfg(not(target_arch = "wasm32"))]
use cairo_program_runner_lib::tasks::create_cairo1_program_task;
#[cfg(not(target_arch = "wasm32"))]
use cairo_program_runner_lib::types::HashFunc;

#[cfg(not(target_arch = "wasm32"))]
fn compute_executable_program_hash(executable_path: &PathBuf) -> Result<tzel_core::F, String> {
    let task =
        create_cairo1_program_task(executable_path, None, None).map_err(|e| e.to_string())?;
    let program = task.get_program().map_err(|e| e.to_string())?;
    compute_program_hash_chain(&program, 0, HashFunc::Blake)
        .map(|felt| felt.to_bytes_le())
        .map_err(|e| e.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn load_program_hashes(executables_dir: &str) -> Result<ProgramHashes, String> {
    let base = PathBuf::from(executables_dir);
    let shield = base.join(CircuitKind::Shield.executable_filename());
    let transfer = base.join(CircuitKind::Transfer.executable_filename());
    let unshield = base.join(CircuitKind::Unshield.executable_filename());

    for path in [&shield, &transfer, &unshield] {
        if !path.exists() {
            return Err(format!(
                "missing Cairo executable required for verified mode: {}",
                path.display()
            ));
        }
    }

    Ok(ProgramHashes {
        shield: compute_executable_program_hash(&shield)?,
        transfer: compute_executable_program_hash(&transfer)?,
        unshield: compute_executable_program_hash(&unshield)?,
    })
}

#[cfg(target_arch = "wasm32")]
pub fn load_program_hashes(_executables_dir: &str) -> Result<ProgramHashes, String> {
    Err("load_program_hashes is not available on wasm targets".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_program_hashes_reports_missing_executables() {
        let err = load_program_hashes("/definitely/missing/tzel-executables").unwrap_err();
        assert!(err.contains("missing Cairo executable required for verified mode"));
        assert!(err.contains("run_shield.executable.json"));
    }
}
