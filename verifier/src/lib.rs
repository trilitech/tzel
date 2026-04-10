use std::path::PathBuf;

use tzel_core::{
    kernel_wire::{kernel_proof_to_host, KernelStarkProof, KernelVerifierConfig},
    validate_single_task_program_hash, CircuitKind, ProgramHashes, Proof,
};
use tzel_reprover::{compute_executable_program_hash, custom_circuit::VerifyMeta, ProofBundle};

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
        Ok(Self::verified(false, config.verified_program_hashes.clone()))
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
    let Proof::Stark { output_preimage, .. } = proof else {
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
        .and_then(|value| {
            serde_json::from_value::<VerifyMeta>(value)
                .map_err(|e| format!("invalid verify_meta: {}", e))
        })?;

    let bundle = ProofBundle {
        proof_bytes: proof_bytes.clone(),
        output_preimage: output_preimage.clone(),
        verify_meta: Some(verify_meta),
    };
    bundle.verify().map_err(|e| e.to_string())
}

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
        shield: compute_executable_program_hash(&shield)
            .map_err(|e| e.to_string())?
            .to_bytes_le(),
        transfer: compute_executable_program_hash(&transfer)
            .map_err(|e| e.to_string())?
            .to_bytes_le(),
        unshield: compute_executable_program_hash(&unshield)
            .map_err(|e| e.to_string())?
            .to_bytes_le(),
    })
}
