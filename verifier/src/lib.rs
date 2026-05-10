mod bundle;
mod verify_meta_codec;

#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;

use tzel_core::{
    kernel_wire::{kernel_proof_to_host, KernelStarkProof, KernelVerifierConfig},
    validate_single_task_program_hash, CircuitKind, ProgramHashes, Proof,
};

pub use bundle::ProofBundle;

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
    use std::sync::OnceLock;

    use serde::Deserialize;
    use tzel_core::{u64_to_felt, F};

    use crate::bundle::{canonical_verify_meta, validate_canonical_verify_meta};

    use super::*;

    #[derive(Clone, Deserialize)]
    struct VerifiedBridgeFixture {
        program_hashes: ProgramHashes,
        shield: tzel_core::ShieldReq,
        transfer: tzel_core::TransferReq,
        unshield: tzel_core::UnshieldReq,
    }

    fn f(v: u64) -> F {
        u64_to_felt(v)
    }

    fn verified_bridge_fixture() -> &'static VerifiedBridgeFixture {
        static FIXTURE: OnceLock<VerifiedBridgeFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            serde_json::from_str(include_str!(
                "../../tezos/rollup-kernel/testdata/verified_bridge_flow.json"
            ))
            .expect("checked-in verified bridge fixture should parse")
        })
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
            },
            false,
            true,
        )
        .unwrap_err();
        assert!(err.contains("empty output_preimage"));
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
    fn test_verify_stark_bundle_rejects_invalid_proof_bytes_without_metadata() {
        let err = verify_stark_bundle(&sample_stark_proof(vec![f(1), f(5), f(22), f(99), f(100)]))
            .unwrap_err();
        assert!(err.contains("zstd decompress"));
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
                },
                CircuitKind::Transfer,
            )
            .unwrap_err();
        assert!(err.contains("zstd decompress"));
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

    #[test]
    fn test_verified_real_bridge_fixture_proofs_validate() {
        let fixture = verified_bridge_fixture();
        let verifier = DirectProofVerifier::verified(false, fixture.program_hashes.clone());

        verifier
            .validate(&fixture.shield.proof, CircuitKind::Shield)
            .unwrap();
        verifier
            .validate(&fixture.transfer.proof, CircuitKind::Transfer)
            .unwrap();
        verifier
            .validate(&fixture.unshield.proof, CircuitKind::Unshield)
            .unwrap();
    }

    #[test]
    fn test_embedded_verify_meta_matches_canonical_template() {
        let meta = canonical_verify_meta().unwrap();
        validate_canonical_verify_meta(&meta).unwrap();
        assert!(!meta.public_output_values.is_empty());
    }

    #[test]
    fn test_verified_bridge_fixture_proofs_do_not_carry_verify_meta() {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../tezos/rollup-kernel/testdata/verified_bridge_flow.json"
        ))
        .expect("checked-in verified bridge fixture should parse as JSON");

        for name in ["shield", "transfer", "unshield"] {
            assert!(
                value[name]["proof"].get("verify_meta").is_none(),
                "{name} fixture proof should not carry verifier metadata"
            );
        }
    }

    #[test]
    fn test_proof_bundle_rejects_verifier_metadata_json() {
        let fixture = verified_bridge_fixture();
        let Proof::Stark {
            proof_bytes,
            output_preimage,
        } = &fixture.transfer.proof
        else {
            panic!("fixture transfer proof should be Stark");
        };
        let json = serde_json::json!({
            "proof_bytes": hex::encode(proof_bytes),
            "output_preimage": output_preimage.iter().map(hex::encode).collect::<Vec<_>>(),
            "verify_meta": {"unexpected": "metadata"},
        });
        let err = serde_json::from_value::<ProofBundle>(json)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field `verify_meta`"), "{err}");
    }

    #[test]
    fn test_verified_real_bridge_fixture_rejects_tampered_output_preimage() {
        let fixture = verified_bridge_fixture();
        let mut proof = fixture.transfer.proof.clone();

        let Proof::Stark {
            output_preimage, ..
        } = &mut proof
        else {
            panic!("checked-in verified bridge fixture should contain a Stark proof");
        };
        output_preimage[0] = f(999);

        let err = verify_stark_bundle(&proof).unwrap_err();
        assert!(err.contains("circuit verification FAILED"));
    }
}
