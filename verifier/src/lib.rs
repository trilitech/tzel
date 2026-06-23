mod bundle;
pub mod groth16;
mod out_hash;
mod poseidon2_bn254;
pub mod snark;
mod verify_meta_codec;

pub use snark::{
    compute_expected_out_hash, verify_snark, verify_snark_tree, verify_snark_with_vk,
};

// ── STARK verification primitive (exposed, dormant) ──────────────────
//
// The kernel's OWN op-application path is Groth16-only (verify_snark /
// verify_snark_tree). This standalone STARK verifier is kept EXPOSED as a
// callable primitive — a future Tezos X smart contract may want to verify
// a raw stwo STARK proof directly (analogous to the Groth16 precompile).
//
// In practice it cannot be exercised until the DAL is activated: a raw
// STARK proof is multi-MB and exceeds the 4096-byte inbox cap, so its
// transport requires DAL. Exposing it now keeps the capability ready; it
// is NOT wired into any kernel submission/apply path (that was retired in
// the Groth16-only migration, W5).
pub use bundle::ProofBundle;

#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;

use tzel_core::{
    kernel_wire::{kernel_proof_to_host, KernelStarkProof, KernelVerifierConfig},
    validate_single_task_program_hash, CircuitKind, ProgramHashes, Proof,
};

/// STARK verification primitive. Verifies a stwo STARK proof bundle against
/// the canonical proof-system metadata and (in verified mode) the expected
/// per-circuit program hash. Exposed for smart-contract use once a DAL
/// transport for large proofs exists; not on the kernel's Groth16-only
/// submission path.
#[derive(Debug, Clone)]
pub struct DirectProofVerifier {
    allow_trust_me_bro: bool,
    verified_mode: Option<VerifiedProofConfig>,
}

#[derive(Debug, Clone)]
struct VerifiedProofConfig {
    program_hashes: ProgramHashes,
}

impl DirectProofVerifier {
    pub fn trust_me_bro_only() -> Self {
        Self {
            allow_trust_me_bro: true,
            verified_mode: None,
        }
    }

    pub fn verified(allow_trust_me_bro: bool, program_hashes: ProgramHashes) -> Self {
        Self {
            allow_trust_me_bro,
            verified_mode: Some(VerifiedProofConfig { program_hashes }),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_executables_dir(
        allow_trust_me_bro: bool,
        executables_dir: &str,
    ) -> Result<Self, String> {
        let program_hashes = load_program_hashes(executables_dir)?;
        Ok(Self::verified(allow_trust_me_bro, program_hashes))
    }

    pub fn from_kernel_config(config: &KernelVerifierConfig) -> Result<Self, String> {
        Ok(Self::verified(false, config.verified_program_hashes.clone()))
    }

    pub fn validate(&self, proof: &Proof, circuit: CircuitKind) -> Result<(), String> {
        check_proof_shape(proof, self.allow_trust_me_bro, self.verified_mode.is_some())?;
        match (&self.verified_mode, proof) {
            (Some(cfg), Proof::Stark { .. }) => {
                validate_stark_circuit(proof, circuit, &cfg.program_hashes)?;
                verify_stark_bundle(proof)
            }
            _ => Ok(()),
        }
    }

    pub fn validate_kernel(
        &self,
        proof: &KernelStarkProof,
        circuit: CircuitKind,
    ) -> Result<(), String> {
        let host_proof = kernel_proof_to_host(proof);
        self.validate(&host_proof, circuit)
    }
}

pub fn check_proof_shape(
    proof: &Proof,
    allow_trust_me_bro: bool,
    verified_mode: bool,
) -> Result<(), String> {
    match proof {
        Proof::TrustMeBro => {
            if allow_trust_me_bro {
                Ok(())
            } else {
                Err("TrustMeBro proofs rejected. Verified mode requires real STARK proofs.".into())
            }
        }
        Proof::Stark {
            proof_bytes,
            output_preimage,
        } => {
            if !verified_mode {
                return Err(
                    "Stark proofs rejected: verifier is not configured for verified mode.".into(),
                );
            }
            if proof_bytes.is_empty() {
                return Err("empty proof".into());
            }
            if output_preimage.is_empty() {
                return Err("empty output_preimage".into());
            }
            Ok(())
        }
    }
}

pub fn validate_stark_circuit(
    proof: &Proof,
    circuit: CircuitKind,
    hashes: &ProgramHashes,
) -> Result<(), String> {
    let Proof::Stark {
        output_preimage, ..
    } = proof
    else {
        return Ok(());
    };
    validate_single_task_program_hash(output_preimage, circuit.expected_program_hash(hashes))
        .map(|_| ())
        .map_err(|e| {
            format!(
                "invalid output_preimage for {} circuit: {}",
                circuit.name(),
                e
            )
        })
}

fn verify_stark_bundle(proof: &Proof) -> Result<(), String> {
    let Proof::Stark {
        proof_bytes,
        output_preimage,
    } = proof
    else {
        return Ok(());
    };

    let bundle = ProofBundle {
        proof_bytes: proof_bytes.clone(),
        output_preimage: output_preimage.clone(),
    };
    bundle.verify().map_err(stringify_bundle_verify_error)
}

#[cfg(target_arch = "wasm32")]
fn stringify_bundle_verify_error(_: anyhow::Error) -> String {
    "stark proof verification failed".into()
}

#[cfg(not(target_arch = "wasm32"))]
fn stringify_bundle_verify_error(e: anyhow::Error) -> String {
    e.to_string()
}

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
