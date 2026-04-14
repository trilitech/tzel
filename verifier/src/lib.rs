mod bundle;

#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;

use tzel_core::{
    kernel_wire::{kernel_proof_to_host, KernelStarkProof, KernelVerifierConfig},
    validate_single_task_program_hash, CircuitKind, ProgramHashes, Proof,
};

pub use bundle::{ProofBundle, VerifyMeta};

#[cfg(not(target_arch = "wasm32"))]
use cairo_program_runner_lib::hints::compute_program_hash_chain;
#[cfg(not(target_arch = "wasm32"))]
use cairo_program_runner_lib::tasks::create_cairo1_program_task;
#[cfg(not(target_arch = "wasm32"))]
use cairo_program_runner_lib::types::HashFunc;

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

    pub fn from_executables_dir(
        allow_trust_me_bro: bool,
        executables_dir: &str,
    ) -> Result<Self, String> {
        let program_hashes = load_program_hashes(executables_dir)?;
        Ok(Self::verified(allow_trust_me_bro, program_hashes))
    }

    pub fn from_kernel_config(config: &KernelVerifierConfig) -> Result<Self, String> {
        Ok(Self::verified(
            false,
            config.verified_program_hashes.clone(),
        ))
    }

    pub fn validate(&self, proof: &Proof, circuit: CircuitKind) -> Result<(), String> {
        check_proof_shape(proof, self.allow_trust_me_bro, self.verified_mode.is_some())?;
        match (&self.verified_mode, proof) {
            (Some(cfg), Proof::Stark { .. }) => {
                verify_stark_bundle(proof)?;
                validate_stark_circuit(proof, circuit, &cfg.program_hashes)
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
            verify_meta,
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
            if verify_meta.is_none() {
                return Err("Stark proof missing verify_meta — cannot verify".into());
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

pub fn verify_stark_bundle(proof: &Proof) -> Result<(), String> {
    let Proof::Stark {
        proof_bytes,
        output_preimage,
        verify_meta,
    } = proof
    else {
        return Ok(());
    };

    let verify_meta = verify_meta
        .clone()
        .ok_or_else(|| "Stark proof missing verify_meta — cannot verify".to_string())
        .and_then(|bytes| decode_verify_meta(&bytes))?;

    let bundle = ProofBundle {
        proof_bytes: proof_bytes.clone(),
        output_preimage: output_preimage.clone(),
        verify_meta: Some(verify_meta),
    };
    bundle.verify().map_err(|e| e.to_string())
}

pub fn encode_verify_meta(meta: &VerifyMeta) -> Result<Vec<u8>, String> {
    bincode::serialize(meta).map_err(|e| format!("encode verify_meta failed: {}", e))
}

pub fn decode_verify_meta(bytes: &[u8]) -> Result<VerifyMeta, String> {
    bincode::deserialize(bytes).map_err(|e| format!("invalid verify_meta: {}", e))
}

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
    use tzel_core::{u64_to_felt, F};

    use super::*;

    fn f(v: u64) -> F {
        u64_to_felt(v)
    }

    fn sample_hashes() -> ProgramHashes {
        ProgramHashes {
            shield: f(11),
            transfer: f(22),
            unshield: f(33),
        }
    }

    fn sample_stark_proof(output_preimage: Vec<F>) -> Proof {
        Proof::Stark {
            proof_bytes: vec![1, 2, 3],
            output_preimage,
            verify_meta: Some(vec![1, 2, 3]),
        }
    }

    #[test]
    fn test_check_proof_shape_rejects_disallowed_trust_me_bro() {
        let err = check_proof_shape(&Proof::TrustMeBro, false, false).unwrap_err();
        assert!(err.contains("TrustMeBro proofs rejected"));
        check_proof_shape(&Proof::TrustMeBro, true, false).unwrap();
    }

    #[test]
    fn test_check_proof_shape_rejects_malformed_stark_proofs() {
        let err = check_proof_shape(
            &Proof::Stark {
                proof_bytes: vec![1],
                output_preimage: vec![f(1), f(2), f(3)],
                verify_meta: Some(vec![0]),
            },
            false,
            false,
        )
        .unwrap_err();
        assert!(err.contains("verifier is not configured for verified mode"));

        let err = check_proof_shape(
            &Proof::Stark {
                proof_bytes: vec![],
                output_preimage: vec![f(1), f(2), f(3)],
                verify_meta: Some(vec![0]),
            },
            false,
            true,
        )
        .unwrap_err();
        assert!(err.contains("empty proof"));

        let err = check_proof_shape(
            &Proof::Stark {
                proof_bytes: vec![1],
                output_preimage: vec![],
                verify_meta: Some(vec![0]),
            },
            false,
            true,
        )
        .unwrap_err();
        assert!(err.contains("empty output_preimage"));

        let err = check_proof_shape(
            &Proof::Stark {
                proof_bytes: vec![1],
                output_preimage: vec![f(1), f(2), f(3)],
                verify_meta: None,
            },
            false,
            true,
        )
        .unwrap_err();
        assert!(err.contains("missing verify_meta"));
    }

    #[test]
    fn test_validate_stark_circuit_binds_expected_program_hash() {
        let hashes = sample_hashes();
        let proof = sample_stark_proof(vec![f(1), f(4), hashes.transfer, f(99), f(100)]);
        validate_stark_circuit(&proof, CircuitKind::Transfer, &hashes).unwrap();

        let err = validate_stark_circuit(&proof, CircuitKind::Shield, &hashes).unwrap_err();
        assert!(err.contains("invalid output_preimage for shield circuit"));
        assert!(err.contains("unexpected circuit program hash"));
    }

    #[test]
    fn test_verify_stark_bundle_rejects_invalid_verify_meta() {
        let err = verify_stark_bundle(&sample_stark_proof(vec![f(1), f(5), f(22), f(99), f(100)]))
            .unwrap_err();
        assert!(err.contains("invalid verify_meta"));
    }

    #[test]
    fn test_direct_verifier_validate_respects_mode_and_shape() {
        let trust_only = DirectProofVerifier::trust_me_bro_only();
        trust_only
            .validate(&Proof::TrustMeBro, CircuitKind::Shield)
            .unwrap();

        let err = trust_only
            .validate(
                &Proof::Stark {
                    proof_bytes: vec![1],
                    output_preimage: vec![f(1), f(4), f(11), f(99), f(100)],
                    verify_meta: Some(vec![0]),
                },
                CircuitKind::Shield,
            )
            .unwrap_err();
        assert!(err.contains("not configured for verified mode"));

        let verified = DirectProofVerifier::verified(false, sample_hashes());
        let err = verified
            .validate(&Proof::TrustMeBro, CircuitKind::Shield)
            .unwrap_err();
        assert!(err.contains("TrustMeBro proofs rejected"));
    }

    #[test]
    fn test_direct_verifier_validate_kernel_uses_host_conversion() {
        let verifier = DirectProofVerifier::from_kernel_config(&KernelVerifierConfig {
            auth_domain: f(77),
            verified_program_hashes: sample_hashes(),
        })
        .unwrap();

        let err = verifier
            .validate_kernel(
                &KernelStarkProof {
                    proof_bytes: vec![1, 2, 3],
                    output_preimage: vec![f(1), f(4), f(22), f(99), f(100)],
                    verify_meta: vec![1, 2, 3],
                },
                CircuitKind::Transfer,
            )
            .unwrap_err();
        assert!(err.contains("invalid verify_meta"));
    }

    #[test]
    fn test_from_kernel_config_disables_trust_me_bro() {
        let verifier = DirectProofVerifier::from_kernel_config(&KernelVerifierConfig {
            auth_domain: f(77),
            verified_program_hashes: sample_hashes(),
        })
        .unwrap();

        let err = verifier
            .validate(&Proof::TrustMeBro, CircuitKind::Shield)
            .unwrap_err();
        assert!(err.contains("TrustMeBro proofs rejected"));
    }

    #[test]
    fn test_load_program_hashes_reports_missing_executables() {
        let err = load_program_hashes("/definitely/missing/tzel-executables").unwrap_err();
        assert!(err.contains("missing Cairo executable required for verified mode"));
        assert!(err.contains("run_shield.executable.json"));
    }
}
