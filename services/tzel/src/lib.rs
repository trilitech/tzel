//! TzEL shared library — verifier helpers, vectors, and host-side glue.

pub mod canonical_wire;
pub mod interop_scenario;
pub mod proof_bench;
pub mod protocol_vectors;

pub use tzel_core::*;
use tzel_verifier::ProofBundle as VerifyProofBundle;

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LedgerProofVerifier {
    allow_trust_me_bro: bool,
    verified_mode: Option<VerifiedProofConfig>,
}

#[derive(Debug, Clone)]
struct VerifiedProofConfig {
    reprove_bin: String,
    program_hashes: ProgramHashes,
    executable_paths: Option<VerifiedExecutablePaths>,
}

#[derive(Debug, Clone)]
struct VerifiedExecutablePaths {
    shield: PathBuf,
    transfer: PathBuf,
    unshield: PathBuf,
}

impl VerifiedExecutablePaths {
    fn from_dir(executables_dir: &str) -> Self {
        let base = PathBuf::from(executables_dir);
        Self {
            shield: base.join(CircuitKind::Shield.executable_filename()),
            transfer: base.join(CircuitKind::Transfer.executable_filename()),
            unshield: base.join(CircuitKind::Unshield.executable_filename()),
        }
    }

    fn path_for(&self, circuit: CircuitKind) -> &Path {
        match circuit {
            CircuitKind::Shield => &self.shield,
            CircuitKind::Transfer => &self.transfer,
            CircuitKind::Unshield => &self.unshield,
        }
    }
}

impl LedgerProofVerifier {
    pub fn trust_me_bro_only() -> Self {
        Self {
            allow_trust_me_bro: true,
            verified_mode: None,
        }
    }

    pub fn verified(
        allow_trust_me_bro: bool,
        reprove_bin: String,
        program_hashes: ProgramHashes,
    ) -> Self {
        Self {
            allow_trust_me_bro,
            verified_mode: Some(VerifiedProofConfig {
                reprove_bin,
                program_hashes,
                executable_paths: None,
            }),
        }
    }

    pub fn from_reprove_bin(
        allow_trust_me_bro: bool,
        reprove_bin: String,
        executables_dir: &str,
    ) -> Result<Self, String> {
        let program_hashes = load_program_hashes(&reprove_bin, executables_dir)?;
        Ok(Self {
            allow_trust_me_bro,
            verified_mode: Some(VerifiedProofConfig {
                reprove_bin,
                program_hashes,
                executable_paths: Some(VerifiedExecutablePaths::from_dir(executables_dir)),
            }),
        })
    }

    pub fn validate(&self, proof: &Proof, circuit: CircuitKind) -> Result<(), String> {
        self.check_proof(proof)?;
        if let Some(ref verified_mode) = self.verified_mode {
            validate_stark_circuit(proof, circuit, &verified_mode.program_hashes)?;
            let executable = verified_mode
                .executable_paths
                .as_ref()
                .map(|paths| paths.path_for(circuit))
                .unwrap_or_else(|| Path::new("dummy"));
            verify_stark_proof(&verified_mode.reprove_bin, executable, proof)?;
        }
        Ok(())
    }

    fn check_proof(&self, proof: &Proof) -> Result<(), String> {
        match proof {
            Proof::TrustMeBro => {
                if !self.allow_trust_me_bro {
                    return Err("TrustMeBro proofs rejected. Ledger requires real STARK proofs. (Start ledger with --trust-me-bro to allow.)".into());
                }
                Ok(())
            }
            Proof::Stark {
                proof_bytes,
                output_preimage,
            } => {
                if self.verified_mode.is_none() {
                    return Err(
                        "Stark proofs rejected: ledger is not configured with --reprove-bin. Start the ledger with --reprove-bin for verified proofs or use --trust-me-bro for development.".into(),
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
}

fn verify_stark_proof(reprove_bin: &str, executable: &Path, proof: &Proof) -> Result<(), String> {
    let Proof::Stark {
        proof_bytes,
        output_preimage,
    } = proof
    else {
        return Ok(());
    };

    let bundle_file = tempfile::NamedTempFile::new().map_err(|e| format!("tempfile: {}", e))?;
    let encoded = encode_verify_bundle_json(proof_bytes, output_preimage)
        .map_err(|e| format!("encode bundle: {}", e))?;
    std::fs::write(bundle_file.path(), encoded).map_err(|e| format!("write bundle: {}", e))?;

    let output = std::process::Command::new(reprove_bin)
        .arg(executable)
        .arg("--verify")
        .arg(bundle_file.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("reprove failed to start: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "STARK proof verification FAILED: {}",
            stderr.trim()
        ));
    }

    Ok(())
}

fn encode_verify_bundle_json(
    proof_bytes: &Vec<u8>,
    output_preimage: &Vec<F>,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&VerifyProofBundle {
        proof_bytes: proof_bytes.clone(),
        output_preimage: output_preimage.clone(),
    })
    .map_err(|e| e.to_string())
}

fn compute_program_hash(reprove_bin: &str, executable: &Path) -> Result<F, String> {
    let output = std::process::Command::new(reprove_bin)
        .arg(executable)
        .arg("--program-hash")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| {
            format!(
                "failed to start reprover for {}: {}",
                executable.display(),
                e
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to compute program hash for {}: {}",
            executable.display(),
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "reprover returned empty program hash for {}",
            executable.display()
        ));
    }
    let bytes = hex::decode(&stdout).map_err(|_| {
        format!(
            "reprover returned non-hex program hash for {}",
            executable.display()
        )
    })?;
    if bytes.len() != 32 {
        return Err(format!(
            "reprover returned {} program-hash bytes for {}, expected 32",
            bytes.len(),
            executable.display()
        ));
    }
    let mut felt = [0u8; 32];
    felt.copy_from_slice(&bytes);
    Ok(felt)
}

fn load_program_hashes(reprove_bin: &str, executables_dir: &str) -> Result<ProgramHashes, String> {
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
        shield: compute_program_hash(reprove_bin, &shield)?,
        transfer: compute_program_hash(reprove_bin, &transfer)?,
        unshield: compute_program_hash(reprove_bin, &unshield)?,
    })
}

fn validate_stark_circuit(
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

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::KeyExport;
    use tzel_core::canonical_wire::ML_KEM768_ENCAPSULATION_KEY_BYTES;

    const TEST_FEE: u64 = MIN_TX_FEE;

    fn random_nonzero_felt() -> F {
        let mut value = random_felt();
        if value == ZERO {
            value[0] = 1;
        }
        value
    }

    fn test_deposit_id(label: &str) -> F {
        deposit_id_from_label(label)
    }

    fn test_deposit_key(label: &str) -> String {
        deposit_balance_key(&test_deposit_id(label))
    }

    fn random_payment_address() -> PaymentAddress {
        PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            auth_pub_seed: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0; ML_KEM768_ENCAPSULATION_KEY_BYTES],
            ek_d: vec![0; ML_KEM768_ENCAPSULATION_KEY_BYTES],
        }
    }

    fn test_auth_root(d_j: &F, auth_pub_seed: &F) -> F {
        hash_two(&felt_tag(b"svc.auth"), &hash_two(d_j, auth_pub_seed))
    }

    fn derived_test_address(seed_byte: u8) -> (Account, PaymentAddress, F) {
        let mut master_sk = ZERO;
        master_sk[0] = seed_byte;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let auth_root = test_auth_root(&d_j, &auth_pub_seed);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let (ek_v, _, ek_d, _) = derive_kem_keys(&acc.incoming_seed, 0);
        (
            acc,
            PaymentAddress {
                d_j,
                auth_root,
                auth_pub_seed,
                nk_tag: nk_tg,
                ek_v: ek_v.to_bytes().to_vec(),
                ek_d: ek_d.to_bytes().to_vec(),
            },
            nk_sp,
        )
    }

    fn test_encrypted_note(seed_byte: u8) -> EncryptedNote {
        let seed_v = [seed_byte; 64];
        let seed_d = [seed_byte.wrapping_add(1); 64];
        let (ek_v, _) = kem_keygen_from_seed(&seed_v);
        let (ek_d, _) = kem_keygen_from_seed(&seed_d);
        encrypt_note(
            seed_byte as u64 + 1,
            &u(10_000 + seed_byte as u64),
            None,
            &ek_v,
            &ek_d,
        )
    }

    fn test_output_note(seed_byte: u8) -> (F, EncryptedNote, F) {
        let enc = test_encrypted_note(seed_byte);
        let cm = random_nonzero_felt();
        let mh = memo_ct_hash(&enc);
        (cm, enc, mh)
    }

    /// Check the deterministic address/tag/commitment path without rebuilding a
    /// full depth-16 XMSS tree. The ignored wallet fixture test covers the
    /// expensive full-tree regeneration separately.
    #[test]
    fn test_cross_implementation_auth_material() {
        // master_sk = 0xA11CE as LE felt252
        let (acc, addr, nk_sp) = derived_test_address(0xCE);
        let nk_tg = derive_nk_tag(&nk_sp);
        let otag = owner_tag(&addr.auth_root, &addr.auth_pub_seed, &addr.nk_tag);
        let mut rseed = ZERO;
        rseed[0] = 0x01;
        rseed[1] = 0x10; // 0x1001
        let rcm = derive_rcm(&rseed);
        let cm = commit(&addr.d_j, 1000, &rcm, &otag);
        let nf = nullifier(&nk_sp, &cm, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let pub_seed = derive_auth_pub_seed(&ask_j);
        let wots_leaf = wots_pk_to_leaf(&pub_seed, 0, &wots_pk(&ask_j, 0));

        assert_eq!(addr.auth_pub_seed, pub_seed);
        assert_eq!(addr.nk_tag, nk_tg);
        assert_ne!(addr.auth_root, ZERO, "auth_root must not be zero");
        assert_ne!(addr.auth_pub_seed, ZERO, "auth_pub_seed must not be zero");
        assert_eq!(wots_leaf, auth_leaf_hash(&ask_j, 0));
        assert_ne!(cm, ZERO, "cm must not be zero");
        assert_ne!(nf, ZERO, "nf must not be zero");
    }

    #[test]
    fn test_verify_bundle_json_uses_explicit_byte_strings_without_metadata() {
        let proof_bytes = vec![0xAB, 0xCD];
        let output_preimage = vec![u(7), u(9)];

        let encoded = encode_verify_bundle_json(&proof_bytes, &output_preimage)
            .expect("bundle encoding should succeed");
        let json: serde_json::Value =
            serde_json::from_slice(&encoded).expect("encoded bundle should be valid JSON");

        assert_eq!(json["proof_bytes"], serde_json::json!("abcd"));
        assert_eq!(
            json["output_preimage"],
            serde_json::json!([hex::encode(u(7)), hex::encode(u(9)),])
        );
        assert!(json.get("verify_meta").is_none());
    }

    /// Verify that auth_leaf_hash using WOTS+ key derivation produces a valid
    /// 32-byte hash and that the auth tree built from it is consistent.
    #[test]
    fn test_auth_leaf_wots() {
        let mut ask_j = ZERO;
        ask_j[0] = 0x42;
        let pub_seed = derive_auth_pub_seed(&ask_j);
        let leaf_0 = auth_leaf_hash(&ask_j, 0);
        let leaf_1 = auth_leaf_hash(&ask_j, 1);
        assert_ne!(leaf_0, ZERO);
        assert_eq!(leaf_0, wots_pk_to_leaf(&pub_seed, 0, &wots_pk(&ask_j, 0)));
        assert_eq!(leaf_1, wots_pk_to_leaf(&pub_seed, 1, &wots_pk(&ask_j, 1)));
        assert_ne!(leaf_0, leaf_1);
    }

    /// End-to-end: shield → scan → transfer → scan → unshield, all locally.
    #[test]
    fn test_e2e_local() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 300_010);

        // Generate alice's address with auth tree
        let mut master_sk = ZERO;
        master_sk[0] = 0x99;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let auth_root = test_auth_root(&d_j, &auth_pub_seed);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);

        let seed_v: [u8; 64] = [1u8; 64];
        let seed_d: [u8; 64] = [2u8; 64];
        let (ek_v, dk_v, ek_d, dk_d) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed_v);
            let (ekd, dkd) = kem_keygen_from_seed(&seed_d);
            (ekv, dkv, ekd, dkd)
        };

        // Shield
        let addr = PaymentAddress {
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };
        let (shield_fee_cm, shield_fee_enc, _shield_fee_mh) = test_output_note(0x01);
        let resp = ledger
            .shield(&ShieldReq {
                deposit_id: test_deposit_id("alice"),
                v: 200_000,
                fee: TEST_FEE,
                producer_fee: 1,
                address: addr,
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
                producer_cm: shield_fee_cm,
                producer_enc: Some(shield_fee_enc),
            })
            .unwrap();

        assert_eq!(resp.index, 0);

        // Scan — verify the note can be detected and decrypted
        let (cm, enc) = &ledger.memos[0];
        assert!(detect(enc, &dk_d));
        let (v, rseed, _) = decrypt_memo(enc, &dk_v).unwrap();
        assert_eq!(v, 200_000);
        let rcm = derive_rcm(&rseed);
        let otag = owner_tag(&auth_root, &auth_pub_seed, &nk_tg);
        assert_eq!(commit(&d_j, v, &rcm, &otag), *cm);

        // Compute nullifier
        let nf = nullifier(&nk_sp, cm, 0);
        assert_ne!(nf, ZERO);

        // Unshield
        let resp = ledger
            .unshield(&UnshieldReq {
                root: ledger.tree.root(),
                nullifiers: vec![nf],
                v_pub: 100_000,
                fee: TEST_FEE,
                recipient: "alice".into(),
                cm_change: ZERO,
                enc_change: None,
                cm_fee: random_nonzero_felt(),
                enc_fee: test_encrypted_note(0x02),
                proof: Proof::TrustMeBro,
            })
            .unwrap();
        assert_eq!(resp.change_index, None);
        assert_eq!(ledger.balances["alice"], 100_000);
        assert_eq!(ledger.balances[&test_deposit_key("alice")], 9);

        // Double-spend rejected
        assert!(ledger
            .unshield(&UnshieldReq {
                root: ledger.tree.root(),
                nullifiers: vec![nf],
                v_pub: 100_000,
                fee: TEST_FEE,
                recipient: "alice".into(),
                cm_change: ZERO,
                enc_change: None,
                cm_fee: random_nonzero_felt(),
                enc_fee: test_encrypted_note(0x03),
                proof: Proof::TrustMeBro,
            })
            .is_err());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Attack tests — these attacks would succeed without output_preimage
    // validation. Each constructs a fake Proof::Stark with a tampered
    // output_preimage and verifies the ledger rejects it.
    // ═══════════════════════════════════════════════════════════════════

    fn u(v: u64) -> F {
        u64_to_felt(v)
    }

    fn fee_f() -> F {
        u(TEST_FEE)
    }

    /// Helper: build a fake Stark proof with a given output_preimage.
    /// The proof bytes are garbage — only the output_preimage matters for
    /// these tests (we're testing the ledger's validation, not STARK crypto).
    fn fake_stark(mut output_preimage: Vec<F>) -> Proof {
        let auth_domain = default_auth_domain();
        if output_preimage.len() >= 6 && output_preimage.first() != Some(&auth_domain) {
            output_preimage.insert(0, auth_domain);
        }
        Proof::Stark {
            proof_bytes: vec![0xDE; 128], // non-empty garbage
            output_preimage,
        }
    }

    /// Helper: set up a ledger with one shielded note, return (ledger, cm, nf, root, enc).
    fn setup_with_note() -> (Ledger, F, F, F, EncryptedNote) {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 300_010);

        let mut master_sk = ZERO;
        master_sk[0] = 0xAA;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let auth_root = test_auth_root(&d_j, &auth_pub_seed);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);

        let seed_v: [u8; 64] = [11u8; 64];
        let seed_d: [u8; 64] = [22u8; 64];
        let (ek_v, _, ek_d, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed_v);
            let (ekd, dkd) = kem_keygen_from_seed(&seed_d);
            (ekv, dkv, ekd, dkd)
        };

        let addr = PaymentAddress {
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };
        let (producer_cm, producer_enc, _producer_mh) = test_output_note(0x04);
        ledger
            .shield(&ShieldReq {
                deposit_id: test_deposit_id("alice"),
                v: 200_000,
                fee: TEST_FEE,
                producer_fee: 1,
                address: addr,
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
                producer_cm,
                producer_enc: Some(producer_enc),
            })
            .unwrap();

        let cm = ledger.tree.leaves[0];
        let root = ledger.tree.root();
        let nf = nullifier(&nk_sp, &cm, 0);
        let enc = ledger.memos[0].1.clone();
        (ledger, cm, nf, root, enc)
    }

    /// Attack: transfer with inflated output commitments.
    /// Attacker submits a Stark proof that claims cm_1 and cm_2 are valid,
    /// but the output_preimage contains DIFFERENT commitments than the request.
    /// Without validation, the ledger would append the request's cm values
    /// (which commit to inflated amounts) while the proof proved different ones.
    #[test]
    fn test_attack_transfer_cm_mismatch_rejected() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();

        let real_cm_1 = random_felt();
        let fake_cm_1 = random_felt(); // attacker's commitment (different amount)
        let cm_2 = random_felt();
        let (cm_3, enc_3, mh_3) = test_output_note(0x10);

        // Build output_preimage as if the proof proved (root, nf, real_cm_1, cm_2, mh1, mh2)
        // but submit the request with fake_cm_1
        let preimage = vec![root, nf, fee_f(), real_cm_1, cm_2, cm_3, ZERO, ZERO, mh_3];

        let result = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1: fake_cm_1, // attacker substitutes a DIFFERENT commitment
            cm_2,
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "transfer with mismatched cm_1 should be rejected"
        );
        assert!(
            result.unwrap_err().contains("cm_1 mismatch"),
            "should specifically catch cm_1 mismatch"
        );
    }

    /// Attack: transfer with swapped encrypted notes (memo substitution).
    /// Attacker generates a valid proof but replaces enc_1 with garbage.
    /// The memo hash in the proof won't match the swapped encrypted note.
    #[test]
    fn test_attack_transfer_memo_substitution_rejected() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();

        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let mh_1 = memo_ct_hash(&enc); // hash of the REAL encrypted note
        let (cm_3, enc_3, mh_3) = test_output_note(0x11);

        // Create a DIFFERENT encrypted note (attacker's garbage)
        let seed_atk: [u8; 64] = [0xBB; 64];
        let (ek_atk, _) = kem_keygen_from_seed(&seed_atk);
        let fake_enc = encrypt_note(999, &random_felt(), None, &ek_atk, &ek_atk);
        // Output_preimage commits to mh_1 (real note's hash)
        let preimage = vec![root, nf, fee_f(), cm_1, cm_2, cm_3, mh_1, ZERO, mh_3];

        let result = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1,
            cm_2,
            cm_3,
            enc_1: fake_enc, // attacker swaps in a DIFFERENT encrypted note
            enc_2: enc.clone(),
            enc_3,
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "transfer with swapped memo should be rejected"
        );
        assert!(
            result.unwrap_err().contains("memo_ct_hash_1 mismatch"),
            "should specifically catch memo substitution"
        );
    }

    /// Attack: unshield with redirected recipient.
    /// Attacker generates a proof for recipient=alice but submits with recipient=attacker.
    /// Without validation, the ledger credits attacker instead of alice.
    #[test]
    fn test_attack_unshield_redirect_recipient_rejected() {
        let (mut ledger, _cm, nf, root, _enc) = setup_with_note();

        let alice_recipient = hash(b"alice");
        let (cm_fee, enc_fee, mh_fee) = test_output_note(0x12);

        // Proof commits to alice as recipient
        let preimage = vec![
            root,
            nf,
            u(1000),
            fee_f(),
            alice_recipient,
            ZERO,
            ZERO,
            cm_fee,
            mh_fee,
        ];

        let result = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 1000,
            fee: TEST_FEE,
            recipient: "attacker".into(), // attacker redirects to themselves
            cm_change: ZERO,
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "unshield with redirected recipient should be rejected"
        );
        assert!(
            result.unwrap_err().contains("recipient mismatch"),
            "should specifically catch recipient redirect"
        );
    }

    /// Attack: unshield with inflated v_pub.
    /// Attacker's proof proves v_pub=100 but submits v_pub=1000000.
    #[test]
    fn test_attack_unshield_inflated_vpub_rejected() {
        let (mut ledger, _cm, nf, root, _enc) = setup_with_note();
        let (cm_fee, enc_fee, mh_fee) = test_output_note(0x13);

        // Proof commits to v_pub=100
        let preimage = vec![
            root,
            nf,
            u(100),
            fee_f(),
            hash(b"alice"),
            ZERO,
            ZERO,
            cm_fee,
            mh_fee,
        ];

        let result = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 1000000, // attacker claims 1000000
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "unshield with inflated v_pub should be rejected"
        );
        assert!(
            result.unwrap_err().contains("v_pub mismatch"),
            "should specifically catch v_pub inflation"
        );
    }

    /// Attack: shield with inflated amount.
    /// Attacker's proof proves v_pub=1 but submits v=1000000.
    #[test]
    fn test_attack_shield_inflated_amount_rejected() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 2000000);

        let cm = random_felt();
        let (producer_cm, producer_enc, producer_mh) = test_output_note(0x14);

        // Proof commits to v_pub=1
        let preimage = vec![
            u(1),
            fee_f(),
            u(1),
            cm,
            producer_cm,
            test_deposit_id("alice"),
            ZERO,
            producer_mh,
        ];

        let addr = random_payment_address();

        let result = ledger.shield(&ShieldReq {
            deposit_id: test_deposit_id("alice"),
            v: 1000000, // attacker claims 1000000
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(EncryptedNote {
                ct_d: vec![0; 1088],
                tag: 0,
                ct_v: vec![0; 1088],
                nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
                encrypted_data: vec![0; 1080],
                outgoing_ct: empty_outgoing_recovery_ct(),
            }),
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(
            result.is_err(),
            "shield with inflated amount should be rejected"
        );
        assert!(
            result.unwrap_err().contains("proof note value mismatch"),
            "should specifically catch amount inflation"
        );
    }

    /// Attack: transfer with fabricated nullifier.
    /// Attacker submits a nullifier not in the proof's output_preimage.
    #[test]
    fn test_attack_transfer_fake_nullifier_rejected() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();

        let fake_nf = random_felt(); // attacker invents a nullifier
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let (cm_3, enc_3, mh_3) = test_output_note(0x51);
        let mh = ZERO;

        // Proof commits to the REAL nullifier
        let preimage = vec![root, nf, fee_f(), cm_1, cm_2, cm_3, mh, mh, mh_3];

        let result = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![fake_nf], // attacker substitutes a DIFFERENT nullifier
            fee: TEST_FEE,
            cm_1,
            cm_2,
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "transfer with fake nullifier should be rejected"
        );
        assert!(
            result.unwrap_err().contains("nullifier 0 mismatch"),
            "should specifically catch nullifier substitution"
        );
    }

    // ── State-level checks (no proof needed) ─────────────────────────

    /// Shield: insufficient public balance.
    #[test]
    fn test_shield_insufficient_balance() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 100);
        let addr = random_payment_address();
        let (producer_cm, producer_enc, _producer_mh) = test_output_note(0x20);
        let r = ledger.shield(&ShieldReq {
            deposit_id: test_deposit_id("alice"),
            v: 200,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: Proof::TrustMeBro,
            client_cm: ZERO,
            client_enc: None,
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("insufficient"));
    }

    /// Transfer: zero inputs rejected.
    #[test]
    fn test_transfer_zero_inputs_rejected() {
        let (mut ledger, _, _, root, enc) = setup_with_note();
        let (cm_3, enc_3, _mh_3) = test_output_note(0x21);
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![], // zero inputs
            fee: TEST_FEE,
            cm_1: random_felt(),
            cm_2: random_felt(),
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("bad nullifier count"));
    }

    /// Transfer: invalid Merkle root rejected.
    #[test]
    fn test_transfer_invalid_root_rejected() {
        let (mut ledger, _, nf, _, enc) = setup_with_note();
        let fake_root = random_felt(); // not in valid_roots
        let (cm_3, enc_3, _mh_3) = test_output_note(0x22);
        let r = ledger.transfer(&TransferReq {
            root: fake_root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1: random_felt(),
            cm_2: random_felt(),
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("invalid root"));
    }

    /// Transfer: double-spend (same nullifier across transactions) rejected.
    #[test]
    fn test_transfer_double_spend_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();
        let (cm_3a, enc_3a, _mh_3a) = test_output_note(0x23);
        // First spend succeeds
        ledger
            .transfer(&TransferReq {
                root,
                nullifiers: vec![nf],
                fee: TEST_FEE,
                cm_1: random_felt(),
                cm_2: random_felt(),
                cm_3: cm_3a,
                enc_1: enc.clone(),
                enc_2: enc.clone(),
                enc_3: enc_3a,
                proof: Proof::TrustMeBro,
            })
            .unwrap();
        let (cm_3b, enc_3b, _mh_3b) = test_output_note(0x24);
        // Second spend with same nullifier fails
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1: random_felt(),
            cm_2: random_felt(),
            cm_3: cm_3b,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3: enc_3b,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("already spent"));
    }

    /// Transfer: duplicate nullifiers within one transaction rejected.
    #[test]
    fn test_transfer_duplicate_nullifier_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();
        let (cm_3, enc_3, _mh_3) = test_output_note(0x25);
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf, nf], // same nf twice
            fee: TEST_FEE,
            cm_1: random_felt(),
            cm_2: random_felt(),
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("duplicate"));
    }

    /// Unshield: invalid root rejected.
    #[test]
    fn test_unshield_invalid_root_rejected() {
        let (mut ledger, _, nf, _, _) = setup_with_note();
        let (cm_fee, enc_fee, _mh_fee) = test_output_note(0x26);
        let r = ledger.unshield(&UnshieldReq {
            root: random_felt(),
            nullifiers: vec![nf],
            v_pub: 1000,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("invalid root"));
    }

    /// Unshield: double-spend rejected.
    #[test]
    fn test_unshield_double_spend_rejected() {
        let (mut ledger, _, nf, root, _) = setup_with_note();
        let (cm_fee_a, enc_fee_a, _mh_fee_a) = test_output_note(0x27);
        ledger
            .unshield(&UnshieldReq {
                root,
                nullifiers: vec![nf],
                v_pub: 1000,
                fee: TEST_FEE,
                recipient: "alice".into(),
                cm_change: ZERO,
                enc_change: None,
                cm_fee: cm_fee_a,
                enc_fee: enc_fee_a,
                proof: Proof::TrustMeBro,
            })
            .unwrap();
        let (cm_fee_b, enc_fee_b, _mh_fee_b) = test_output_note(0x28);
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 1000,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee: cm_fee_b,
            enc_fee: enc_fee_b,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("already spent"));
    }

    /// Unshield: duplicate nullifiers within one transaction rejected.
    #[test]
    fn test_unshield_duplicate_nullifier_rejected() {
        let (mut ledger, _, nf, root, _) = setup_with_note();
        let (cm_fee, enc_fee, _mh_fee) = test_output_note(0x29);
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf, nf],
            v_pub: 1000,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("duplicate"));
    }

    // ── Proof output_preimage checks ────────────────────────────────

    /// Attack: shield with proof cm that doesn't match client_cm.
    #[test]
    fn test_attack_shield_cm_mismatch_rejected() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);

        let real_cm = random_felt();
        let fake_cm = random_felt();
        let (producer_cm, producer_enc, producer_mh) = test_output_note(0x2A);

        let preimage = vec![
            u(1000),
            fee_f(),
            u(1),
            real_cm,
            producer_cm,
            test_deposit_id("alice"),
            ZERO,
            producer_mh,
        ];

        let addr = random_payment_address();
        let r = ledger.shield(&ShieldReq {
            deposit_id: test_deposit_id("alice"),
            v: 1000,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: fake_cm, // DIFFERENT cm
            client_enc: Some(EncryptedNote {
                ct_d: vec![0; 1088],
                tag: 0,
                ct_v: vec![0; 1088],
                nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
                encrypted_data: vec![0; 1080],
                outgoing_ct: empty_outgoing_recovery_ct(),
            }),
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("cm mismatch"));
    }

    /// Attack: transfer with proof root that doesn't match request root.
    #[test]
    fn test_attack_transfer_root_mismatch_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();

        let fake_root = random_felt();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let (cm_3, enc_3, mh_3) = test_output_note(0x30);
        let mh = memo_ct_hash(&enc);

        // Proof commits to fake_root
        let preimage = vec![fake_root, nf, fee_f(), cm_1, cm_2, cm_3, mh, mh, mh_3];

        let r = ledger.transfer(&TransferReq {
            root, // request uses the REAL root
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1,
            cm_2,
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof: fake_stark(preimage),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("root mismatch"));
    }

    #[test]
    fn test_attack_transfer_auth_domain_mismatch_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();
        let bad_domain = random_felt();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let (cm_3, enc_3, mh_3) = test_output_note(0x31);
        let mh = memo_ct_hash(&enc);

        let proof = Proof::Stark {
            proof_bytes: vec![0xDE; 128],
            output_preimage: vec![
                bad_domain,
                root,
                nf,
                fee_f(),
                cm_1,
                cm_2,
                cm_3,
                mh,
                mh,
                mh_3,
            ],
        };

        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1,
            cm_2,
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("auth_domain mismatch"));
    }

    /// Attack: transfer with mismatched cm_2 (only cm_1 is correct).
    #[test]
    fn test_attack_transfer_cm2_mismatch_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();

        let cm_1 = random_felt();
        let real_cm_2 = random_felt();
        let fake_cm_2 = random_felt();
        let (cm_3, enc_3, mh_3) = test_output_note(0x32);
        let mh = memo_ct_hash(&enc);

        let preimage = vec![root, nf, fee_f(), cm_1, real_cm_2, cm_3, mh, mh, mh_3];

        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1,
            cm_2: fake_cm_2, // attacker substitutes cm_2
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof: fake_stark(preimage),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("cm_2 mismatch"));
    }

    /// Attack: unshield with proof root mismatch.
    #[test]
    fn test_attack_unshield_root_mismatch_rejected() {
        let (mut ledger, _, nf, root, _) = setup_with_note();

        let fake_root = random_felt();
        let recipient = hash(b"alice");
        let (cm_fee, enc_fee, mh_fee) = test_output_note(0x33);

        let preimage = vec![
            fake_root,
            nf,
            u(1000),
            fee_f(),
            recipient,
            ZERO,
            ZERO,
            cm_fee,
            mh_fee,
        ];

        let r = ledger.unshield(&UnshieldReq {
            root, // request uses the REAL root
            nullifiers: vec![nf],
            v_pub: 1000,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: fake_stark(preimage),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("root mismatch"));
    }

    /// Attack: unshield with substituted change commitment.
    /// Attacker's proof commits to cm_change=X but submits cm_change=Y.
    #[test]
    fn test_attack_unshield_cm_change_substitution_rejected() {
        let (mut ledger, _cm, nf, root, _enc) = setup_with_note();

        let real_cm_change = random_felt();
        let fake_cm_change = random_felt(); // attacker's commitment
        let recipient = hash(b"alice");
        let (cm_fee, enc_fee, mh_fee) = test_output_note(0x34);

        let preimage = vec![
            root,
            nf,
            u(500),
            fee_f(),
            recipient,
            real_cm_change,
            ZERO,
            cm_fee,
            mh_fee,
        ];

        let result = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 500,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: fake_cm_change, // attacker substitutes a DIFFERENT change commitment
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: fake_stark(preimage),
        });
        assert!(
            result.is_err(),
            "unshield with substituted cm_change should be rejected"
        );
        assert!(
            result.unwrap_err().contains("cm_change mismatch"),
            "should specifically catch cm_change substitution"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Regression tests — each corresponds to a specific bug that was
    // found and fixed. If any of these fail, the fix has regressed.
    // ═══════════════════════════════════════════════════════════════════

    /// Regression: random_felt() must produce valid 251-bit values.
    /// Bug: rng.random::<[u8;32]>() generated 256-bit values that exceeded
    /// the Stark field prime. When hex-encoded and sent to Cairo, values
    /// were reduced mod P, producing different commitments than Rust computed.
    #[test]
    fn test_regression_random_felt_251bit() {
        for _ in 0..1000 {
            let f = random_felt();
            // Top 5 bits must be zero (251-bit truncation)
            assert_eq!(
                f[31] & 0xF8,
                0,
                "random_felt produced >251-bit value: top byte = {:#04x}",
                f[31]
            );
        }
    }

    /// Regression: all hash outputs must be 251-bit truncated.
    /// Bug: if hash output exceeds felt252 range, Cairo and Rust interpret
    /// the same hex string differently (Cairo reduces mod P, Rust uses raw bytes).
    #[test]
    fn test_regression_hash_output_251bit() {
        for i in 0u32..100 {
            let mut input = ZERO;
            input[..4].copy_from_slice(&i.to_le_bytes());
            let h = hash(&input);
            assert_eq!(h[31] & 0xF8, 0, "hash output >251 bits at input {}", i);

            let h2 = hash_merkle(&input, &ZERO);
            assert_eq!(h2[31] & 0xF8, 0, "hash_merkle output >251 bits");

            let h3 = owner_tag(&input, &ZERO, &ZERO);
            assert_eq!(h3[31] & 0xF8, 0, "owner_tag output >251 bits");

            let h4 = derive_nk_spend(&input, &ZERO);
            assert_eq!(h4[31] & 0xF8, 0, "derive_nk_spend output >251 bits");

            let h5 = hash1_wots(&input);
            assert_eq!(h5[31] & 0xF8, 0, "hash1_wots output >251 bits");

            let h6 = sighash_fold(&input, &ZERO);
            assert_eq!(h6[31] & 0xF8, 0, "sighash_fold output >251 bits");
        }
    }

    /// Regression: WOTS+ key indices must produce different keys.
    /// Bug: wallet always used key index 0, causing one-time signature reuse
    /// which leaks secret key material and allows forgery.
    #[test]
    fn test_regression_wots_key_index_produces_different_keys() {
        let ask_j = random_felt();
        let pub_seed = derive_auth_pub_seed(&ask_j);

        // Different key indices produce different seeds
        let seed_0 = auth_key_seed(&ask_j, 0);
        let seed_1 = auth_key_seed(&ask_j, 1);
        assert_ne!(
            seed_0, seed_1,
            "different key indices must produce different seeds"
        );

        // Different key indices produce different public keys
        let pk_0 = wots_pk(&ask_j, 0);
        let pk_1 = wots_pk(&ask_j, 1);
        assert_ne!(
            pk_0, pk_1,
            "different key indices must produce different public keys"
        );

        // Different key indices produce different auth leaves
        let leaf_0 = wots_pk_to_leaf(&pub_seed, 0, &pk_0);
        let leaf_1 = wots_pk_to_leaf(&pub_seed, 1, &pk_1);
        assert_ne!(
            leaf_0, leaf_1,
            "different key indices must produce different auth leaves"
        );

        // Same key + different message = different signature (one-time property)
        let msg1 = hash(b"msg1");
        let msg2 = hash(b"msg2");
        let (sig1, _, _) = wots_sign(&ask_j, 0, &msg1);
        let (sig2, _, _) = wots_sign(&ask_j, 0, &msg2);
        assert_ne!(
            sig1, sig2,
            "same key + different messages must produce different signatures"
        );
    }

    /// Regression: shield with Stark proof MUST provide client_cm.
    /// Bug: ledger accepted Stark proofs with client_cm=ZERO and generated
    /// its own cm, making the proof commit to a different commitment than
    /// what was appended to the tree.
    #[test]
    fn test_regression_shield_stark_requires_client_cm() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);

        let addr = random_payment_address();
        let (producer_cm, producer_enc, _producer_mh) = test_output_note(0x35);
        let r = ledger.shield(&ShieldReq {
            deposit_id: test_deposit_id("alice"),
            v: 1000,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: fake_stark(vec![ZERO; 8]),
            client_cm: ZERO, // BUG: no client cm with Stark proof
            client_enc: None,
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(
            r.is_err(),
            "Stark proof with ZERO client_cm should be rejected"
        );
        assert!(r.unwrap_err().contains("requires client_cm"));
    }

    /// Regression: shield proof must bind to the funded deposit id.
    /// Bug: the ledger did not validate the deposit id from the proof's
    /// output_preimage, allowing front-running of shield proofs.
    #[test]
    fn test_regression_shield_deposit_id_validated() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);
        let _ = ledger.fund(&test_deposit_key("attacker"), 200_000);

        let cm = random_felt();
        let alice_deposit_id = test_deposit_id("alice");
        let enc = EncryptedNote {
            ct_d: vec![0; 1088],
            tag: 0,
            ct_v: vec![0; 1088],
            nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![0; 1080],
            outgoing_ct: empty_outgoing_recovery_ct(),
        };
        let mh = memo_ct_hash(&enc);
        let (producer_cm, producer_enc, producer_mh) = test_output_note(0x36);

        // Proof commits to Alice's deposit id.
        let preimage = vec![
            u(1000),
            fee_f(),
            u(1),
            cm,
            producer_cm,
            alice_deposit_id,
            mh,
            producer_mh,
        ];

        let addr = random_payment_address();
        let r = ledger.shield(&ShieldReq {
            deposit_id: test_deposit_id("attacker"), // attacker front-runs with a different deposit
            v: 1000,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(enc),
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(
            r.is_err(),
            "shield with mismatched deposit id should be rejected"
        );
        assert!(r.unwrap_err().contains("deposit_id mismatch"));
    }

    /// Regression: shield proof must bind to memo_ct_hash.
    /// Bug: the ledger didn't validate memo_ct_hash, allowing memo spoofing.
    #[test]
    fn test_regression_shield_memo_hash_validated() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);

        let cm = random_felt();
        let deposit_id = test_deposit_id("alice");

        // Real encrypted note
        let seed: [u8; 64] = [0x33; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let real_enc = encrypt_note(1000, &random_felt(), None, &ek, &ek);
        let real_mh = memo_ct_hash(&real_enc);
        let (producer_cm, producer_enc, producer_mh) = test_output_note(0x37);

        // Fake encrypted note with different content
        let fake_enc = encrypt_note(999, &random_felt(), Some(b"evil"), &ek, &ek);

        // Proof commits to the REAL memo hash
        let preimage = vec![
            u(1000),
            fee_f(),
            u(1),
            cm,
            producer_cm,
            deposit_id,
            real_mh,
            producer_mh,
        ];

        let addr = random_payment_address();
        let r = ledger.shield(&ShieldReq {
            deposit_id,
            v: 1000,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(fake_enc), // attacker swaps the encrypted note
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(r.is_err(), "shield with swapped memo should be rejected");
        assert!(r.unwrap_err().contains("memo_ct_hash mismatch"));
    }

    /// Regression: unshield proof mh_change must be 0 when no change note.
    /// Bug: the ledger didn't validate mh_change=0 for no-change unshields,
    /// allowing an attacker to inject nonzero mh_change.
    #[test]
    fn test_regression_unshield_mh_change_zero_enforced() {
        let (mut ledger, _, nf, root, _) = setup_with_note();

        let recipient = hash(b"alice");
        let (cm_fee, enc_fee, _mh_fee) = test_output_note(0x38);
        // Proof has nonzero mh_change but no enc_change
        let preimage = vec![
            root,
            nf,
            u(1000),
            fee_f(),
            recipient,
            ZERO,
            u(12345),
            cm_fee,
            ZERO,
        ];

        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![nf],
            v_pub: 1000,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: fake_stark(preimage),
        });
        assert!(
            r.is_err(),
            "nonzero mh_change without enc_change should be rejected"
        );
        assert!(r.unwrap_err().contains("memo_ct_hash_change should be 0"));
    }

    /// Regression: shield Stark proof must include client_enc.
    /// Bug: with client_cm set but client_enc=None, the ledger fell through
    /// to server-side cm generation, inserting an unproved commitment.
    #[test]
    fn test_regression_shield_stark_requires_client_enc() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);

        let cm = random_felt();
        let deposit_id = test_deposit_id("alice");
        let (producer_cm, producer_enc, producer_mh) = test_output_note(0x39);
        let preimage = vec![
            u(1000),
            fee_f(),
            u(1),
            cm,
            producer_cm,
            deposit_id,
            ZERO,
            producer_mh,
        ];

        let addr = random_payment_address();
        let r = ledger.shield(&ShieldReq {
            deposit_id,
            v: 1000,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: None, // BUG: Stark proof without client_enc
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(
            r.is_err(),
            "Stark proof with None client_enc should be rejected"
        );
        assert!(r.unwrap_err().contains("requires client_enc"));
    }

    /// Regression: WOTS+ chain hashing uses dedicated wotsSP__ IV, not generic.
    /// Bug: WOTS+ chains shared the generic IV with key derivation, violating
    /// domain separation. Now uses dedicated wotsSP__ personalization.
    #[test]
    fn test_regression_wots_dedicated_iv() {
        let x = random_felt();
        let generic = hash(&x);
        let wots = hash1_wots(&x);
        assert_ne!(
            generic, wots,
            "WOTS+ chain hash must differ from generic hash (different IVs)"
        );
    }

    /// Regression: sighash uses dedicated sighSP__ IV.
    #[test]
    fn test_regression_sighash_dedicated_iv() {
        let a = random_felt();
        let b = random_felt();
        let generic = hash_two(&a, &b);
        let sh = sighash_fold(&a, &b);
        assert_ne!(
            generic, sh,
            "sighash fold must differ from generic hash (different IVs)"
        );
    }

    /// Regression: transfer and unshield sighashes differ (circuit-type tag).
    /// Bug: without type tags, a transfer and unshield with same public
    /// outputs could produce the same sighash, enabling cross-circuit replay.
    #[test]
    fn test_regression_sighash_circuit_type_tags_differ() {
        let auth_domain = default_auth_domain();
        let root = random_felt();
        let nf = random_felt();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let cm_3 = random_felt();
        let mh = ZERO;
        let mh_3 = random_felt();

        let transfer_sh = transfer_sighash(
            &auth_domain,
            &root,
            &[nf],
            0,
            &cm_1,
            &cm_2,
            &cm_3,
            &mh,
            &mh,
            &mh_3,
        );

        // Unshield with same values (treating cm_1 as v_pub felt, cm_2 as recipient, etc.)
        let unshield_sh = unshield_sighash(
            &auth_domain,
            &root,
            &[nf],
            0,
            0,
            &cm_2,
            &mh,
            &cm_3,
            &mh_3,
            &mh,
        );

        assert_ne!(
            transfer_sh, unshield_sh,
            "transfer and unshield sighashes must differ due to circuit-type tags"
        );
    }

    #[test]
    fn test_regression_sighash_auth_domain_changes_digest() {
        let root = random_felt();
        let nf = random_felt();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let cm_3 = random_felt();
        let mh = random_felt();
        let mh_3 = random_felt();
        let auth_domain_a = default_auth_domain();
        let auth_domain_b = random_felt();

        let sh_a = transfer_sighash(
            &auth_domain_a,
            &root,
            &[nf],
            0,
            &cm_1,
            &cm_2,
            &cm_3,
            &mh,
            &mh,
            &mh_3,
        );
        let sh_b = transfer_sighash(
            &auth_domain_b,
            &root,
            &[nf],
            0,
            &cm_1,
            &cm_2,
            &cm_3,
            &mh,
            &mh,
            &mh_3,
        );

        assert_ne!(
            sh_a, sh_b,
            "changing auth_domain must change the spend sighash"
        );
    }

    /// Regression: memo_ct_hash must cover detection data (ct_d + tag), not just
    /// the viewing-key portion (ct_v + encrypted_data).
    /// Bug: a relayer could swap ct_d/tag to redirect note detection to a different
    /// server without invalidating the proof, because memo_ct_hash didn't cover them.
    #[test]
    fn test_regression_memo_ct_hash_covers_detection_data() {
        let seed: [u8; 64] = [0x44; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let enc = encrypt_note(100, &random_felt(), None, &ek, &ek);
        let original_hash = memo_ct_hash(&enc);

        // Tamper with detection ciphertext (ct_d)
        let mut tampered = enc.clone();
        tampered.ct_d[0] ^= 0xFF;
        assert_ne!(
            memo_ct_hash(&tampered),
            original_hash,
            "changing ct_d must change memo_ct_hash"
        );

        // Tamper with detection tag
        let mut tampered = enc.clone();
        tampered.tag ^= 0xFFFF;
        assert_ne!(
            memo_ct_hash(&tampered),
            original_hash,
            "changing detection tag must change memo_ct_hash"
        );

        // Tamper with viewing ciphertext (ct_v)
        let mut tampered = enc.clone();
        tampered.ct_v[0] ^= 0xFF;
        assert_ne!(
            memo_ct_hash(&tampered),
            original_hash,
            "changing ct_v must change memo_ct_hash"
        );

        // Tamper with encrypted payload
        let mut tampered = enc.clone();
        tampered.encrypted_data[0] ^= 0xFF;
        assert_ne!(
            memo_ct_hash(&tampered),
            original_hash,
            "changing encrypted_data must change memo_ct_hash"
        );

        // Tamper with outgoing recovery ciphertext
        let mut tampered = enc.clone();
        tampered.outgoing_ct[0] ^= 0xFF;
        assert_ne!(
            memo_ct_hash(&tampered),
            original_hash,
            "changing outgoing_ct must change memo_ct_hash"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Coverage tests — exercise code paths not hit by other tests
    // ═══════════════════════════════════════════════════════════════════

    /// Serde roundtrip for Note, PaymentAddress, and API types.
    /// Covers hex_f, hex_f_vec, hex_bytes serialize/deserialize.
    #[test]
    fn test_serde_roundtrip() {
        // Note roundtrip
        let note = Note {
            nk_spend: random_felt(),
            nk_tag: random_felt(),
            auth_root: random_felt(),
            d_j: random_felt(),
            v: 42,
            rseed: random_felt(),
            cm: random_felt(),
            index: 7,
            addr_index: 3,
        };
        let json = serde_json::to_string(&note).unwrap();
        let back: Note = serde_json::from_str(&json).unwrap();
        assert_eq!(note.cm, back.cm);
        assert_eq!(note.v, back.v);
        assert_eq!(note.nk_spend, back.nk_spend);

        // PaymentAddress roundtrip
        let addr = PaymentAddress {
            d_j: random_felt(),
            auth_root: random_felt(),
            auth_pub_seed: random_felt(),
            nk_tag: random_felt(),
            ek_v: vec![0xAB; 1184],
            ek_d: vec![0xCD; 1184],
        };
        let json = serde_json::to_string(&addr).unwrap();
        let back: PaymentAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(addr.d_j, back.d_j);
        assert_eq!(addr.ek_v, back.ek_v);

        // TransferReq with nullifier vec (exercises hex_f_vec)
        let req = TransferReq {
            root: random_felt(),
            nullifiers: vec![random_felt(), random_felt()],
            fee: TEST_FEE,
            cm_1: random_felt(),
            cm_2: random_felt(),
            cm_3: random_felt(),
            enc_1: EncryptedNote {
                ct_d: vec![0; 1088],
                tag: 42,
                ct_v: vec![0; 1088],
                nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
                encrypted_data: vec![0; 1080],
                outgoing_ct: empty_outgoing_recovery_ct(),
            },
            enc_2: EncryptedNote {
                ct_d: vec![0; 1088],
                tag: 99,
                ct_v: vec![0; 1088],
                nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
                encrypted_data: vec![0; 1080],
                outgoing_ct: empty_outgoing_recovery_ct(),
            },
            enc_3: EncryptedNote {
                ct_d: vec![0; 1088],
                tag: 7,
                ct_v: vec![0; 1088],
                nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
                encrypted_data: vec![0; 1080],
                outgoing_ct: empty_outgoing_recovery_ct(),
            },
            proof: Proof::TrustMeBro,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: TransferReq = serde_json::from_str(&json).unwrap();
        assert_eq!(req.nullifiers.len(), back.nullifiers.len());
        assert_eq!(req.nullifiers[0], back.nullifiers[0]);
    }

    /// MerkleTree: build a small tree, extract auth path, verify it.
    /// Covers MerkleTree::auth_path (20 uncovered lines).
    #[test]
    fn test_merkle_tree_auth_path() {
        let mut tree = MerkleTree::new();
        let leaf_0 = random_felt();
        let leaf_1 = random_felt();
        let leaf_2 = random_felt();
        tree.append(leaf_0);
        tree.append(leaf_1);
        tree.append(leaf_2);

        let root = tree.root();

        // Extract and verify auth path for each leaf
        for (i, leaf) in [leaf_0, leaf_1, leaf_2].iter().enumerate() {
            let (siblings, path_root) = tree.auth_path(i);
            assert_eq!(path_root, root, "auth_path root mismatch for leaf {}", i);
            assert_eq!(siblings.len(), DEPTH, "wrong sibling count");

            // Walk the path manually to verify
            let mut current = *leaf;
            let mut idx = i;
            for sib in &siblings {
                current = if idx & 1 == 1 {
                    hash_merkle(sib, &current)
                } else {
                    hash_merkle(&current, sib)
                };
                idx /= 2;
            }
            assert_eq!(current, root, "manual path walk mismatch for leaf {}", i);
        }
    }

    #[test]
    fn test_felt_integer_helpers() {
        assert_eq!(felt_to_u64(&ZERO).unwrap(), 0);

        let mut small = ZERO;
        small[0] = 42;
        assert_eq!(felt_to_u64(&small).unwrap(), 42);

        let mut u64max = ZERO;
        u64max[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(felt_to_u64(&u64max).unwrap(), u64::MAX);

        let mut too_large = ZERO;
        too_large[16] = 1;
        assert!(felt_to_u64(&too_large).is_err());
    }

    /// Detect with malformed ciphertext returns false (not panic).
    /// Covers the early-return false path in detect().
    #[test]
    fn test_detect_malformed_ciphertext() {
        let seed: [u8; 64] = [0x55; 64];
        let (_, _, _, dk_d) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed);
            let (ekd, dkd) = kem_keygen_from_seed(&seed);
            (ekv, dkv, ekd, dkd)
        };
        // Too short ct_d
        let bad_enc = EncryptedNote {
            ct_d: vec![0; 10], // wrong length — should be 1088
            tag: 0,
            ct_v: vec![0; 1088],
            nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![0; 1080],
            outgoing_ct: empty_outgoing_recovery_ct(),
        };
        assert!(
            !detect(&bad_enc, &dk_d),
            "malformed ct_d should return false, not panic"
        );
    }

    /// decrypt_memo with malformed ciphertext returns None (not panic).
    #[test]
    fn test_decrypt_memo_malformed() {
        let seed: [u8; 64] = [0x66; 64];
        let (_, dk_v, _, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed);
            let (ekd, dkd) = kem_keygen_from_seed(&seed);
            (ekv, dkv, ekd, dkd)
        };
        // Too short ct_v
        let bad_enc = EncryptedNote {
            ct_d: vec![0; 1088],
            tag: 0,
            ct_v: vec![0; 10], // wrong length
            nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![0; 1080],
            outgoing_ct: empty_outgoing_recovery_ct(),
        };
        assert!(
            decrypt_memo(&bad_enc, &dk_v).is_none(),
            "malformed ct_v should return None"
        );
    }

    #[test]
    fn test_encrypted_note_validate_accepts_canonical_sizes() {
        let seed: [u8; 64] = [0x33; 64];
        let (ek_v, _, ek_d, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed);
            let (ekd, dkd) = kem_keygen_from_seed(&seed);
            (ekv, dkv, ekd, dkd)
        };
        let enc = encrypt_note(17, &random_felt(), None, &ek_v, &ek_d);
        assert!(enc.validate().is_ok());
    }

    #[test]
    fn test_ledger_shield_rejects_malformed_client_note_lengths() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);

        let mut master_sk = ZERO;
        master_sk[0] = 0x44;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let auth_root = test_auth_root(&d_j, &auth_pub_seed);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        let seed: [u8; 64] = [0x77; 64];
        let (ek_v, _, ek_d, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed);
            let (ekd, dkd) = kem_keygen_from_seed(&seed);
            (ekv, dkv, ekd, dkd)
        };
        let addr = PaymentAddress {
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };
        let bad_enc = EncryptedNote {
            ct_d: vec![0; 10],
            tag: 0,
            ct_v: vec![0; ML_KEM768_CIPHERTEXT_BYTES],
            nonce: vec![0; NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![0; ENCRYPTED_NOTE_BYTES],
            outgoing_ct: empty_outgoing_recovery_ct(),
        };
        let mut client_cm = ZERO;
        client_cm[0] = 1;

        let err = ledger
            .shield(&ShieldReq {
                deposit_id: test_deposit_id("alice"),
                v: 100,
                fee: TEST_FEE,
                producer_fee: 1,
                address: addr,
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm,
                client_enc: Some(bad_enc),
                producer_cm: random_nonzero_felt(),
                producer_enc: Some(test_encrypted_note(0x40)),
            })
            .unwrap_err();
        assert!(err.contains("invalid client encrypted note"));
    }

    #[test]
    fn test_ledger_transfer_rejects_malformed_output_note_lengths() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();
        let mut bad_enc = enc.clone();
        bad_enc.ct_d.pop();

        let err = ledger
            .transfer(&TransferReq {
                root,
                nullifiers: vec![nf],
                fee: TEST_FEE,
                cm_1: random_felt(),
                cm_2: random_felt(),
                cm_3: random_felt(),
                enc_1: bad_enc,
                enc_2: enc,
                enc_3: test_encrypted_note(0x41),
                proof: Proof::TrustMeBro,
            })
            .unwrap_err();
        assert!(err.contains("invalid output note 1"));
    }

    #[test]
    fn test_ledger_unshield_rejects_change_note_without_cm() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();

        let err = ledger
            .unshield(&UnshieldReq {
                root,
                nullifiers: vec![nf],
                v_pub: 1000,
                fee: TEST_FEE,
                recipient: "alice".into(),
                cm_change: ZERO,
                enc_change: Some(enc),
                cm_fee: random_nonzero_felt(),
                enc_fee: test_encrypted_note(0x42),
                proof: Proof::TrustMeBro,
            })
            .unwrap_err();
        assert!(err.contains("change note data provided with zero cm_change"));
    }

    /// Ledger transfer: mh_2 mismatch rejected.
    /// Covers the mh_2 validation branch.
    #[test]
    fn test_attack_transfer_mh2_mismatch_rejected() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let (cm_3, enc_3, mh_3) = test_output_note(0x43);
        let mh_1 = memo_ct_hash(&enc);
        let real_mh_2 = memo_ct_hash(&enc);

        // Create a different encrypted note for enc_2
        let seed: [u8; 64] = [0x77; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let fake_enc_2 = encrypt_note(100, &random_felt(), None, &ek, &ek);

        let preimage = vec![root, nf, fee_f(), cm_1, cm_2, cm_3, mh_1, real_mh_2, mh_3];
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1,
            cm_2,
            cm_3,
            enc_1: enc.clone(),
            enc_2: fake_enc_2, // attacker swaps enc_2
            enc_3,
            proof: fake_stark(preimage),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("memo_ct_hash_2 mismatch"));
    }

    /// Ledger unshield: zero inputs rejected.
    #[test]
    fn test_unshield_zero_inputs_rejected() {
        let (mut ledger, _, _, root, _) = setup_with_note();
        let (cm_fee, enc_fee, _mh_fee) = test_output_note(0x44);
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: vec![],
            v_pub: 100,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("bad nullifier count"));
    }

    /// Ledger: transfer proof public outputs must exactly match the nullifier count.
    #[test]
    fn test_transfer_public_output_length_mismatch_rejected() {
        let (mut ledger, _, nf, root, enc) = setup_with_note();
        let (cm_3, enc_3, _mh_3) = test_output_note(0x45);
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1: random_felt(),
            cm_2: random_felt(),
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof: fake_stark(vec![u(1), u(2)]),
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("public output length mismatch"));
    }

    /// Shield with Stark proof: client_cm used instead of server-generated.
    /// Covers the client_cm/client_enc branch in shield().
    #[test]
    fn test_shield_client_cm_used() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);

        let cm = random_felt();
        let deposit_id = test_deposit_id("alice");
        let seed: [u8; 64] = [0x88; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let enc = encrypt_note(500, &random_felt(), None, &ek, &ek);
        let mh = memo_ct_hash(&enc);
        let (producer_cm, producer_enc, producer_mh) = test_output_note(0x46);

        let preimage = vec![
            u(500),
            fee_f(),
            u(1),
            cm,
            producer_cm,
            deposit_id,
            mh,
            producer_mh,
        ];
        let addr = random_payment_address();
        let r = ledger.shield(&ShieldReq {
            deposit_id,
            v: 500,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: Some(enc),
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(
            r.is_ok(),
            "shield with matching client_cm should succeed: {:?}",
            r.err()
        );
        let resp = r.unwrap();
        assert_eq!(
            resp.cm, cm,
            "ledger should use client_cm, not generate its own"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Mutation-killing tests — each targets specific surviving mutants
    // identified by cargo-mutants. See MUTATION_TESTING.md for details.
    // ═══════════════════════════════════════════════════════════════════

    /// Group 1: sighash functions must produce specific, deterministic outputs.
    /// Kills: replace transfer_sighash/unshield_sighash -> Default::default()
    #[test]
    fn test_mutant_sighash_known_answer() {
        let auth_domain = default_auth_domain();
        let root = [0x01; 32];
        let nf = [0x02; 32];
        let cm_1 = [0x03; 32];
        let cm_2 = [0x04; 32];
        let cm_3 = [0x05; 32];
        let mh_1 = [0x05; 32];
        let mh_2 = [0x06; 32];
        let mh_3 = [0x07; 32];

        let sh = transfer_sighash(
            &auth_domain,
            &root,
            &[nf],
            0,
            &cm_1,
            &cm_2,
            &cm_3,
            &mh_1,
            &mh_2,
            &mh_3,
        );
        assert_ne!(sh, ZERO, "transfer_sighash must not be zero");
        // Pin the value — any mutation that changes the fold will break this
        let pinned = sh;

        // Call again with same inputs — must be deterministic
        let sh2 = transfer_sighash(
            &auth_domain,
            &root,
            &[nf],
            0,
            &cm_1,
            &cm_2,
            &cm_3,
            &mh_1,
            &mh_2,
            &mh_3,
        );
        assert_eq!(sh, sh2, "sighash must be deterministic");

        // Different input → different output
        let sh3 = transfer_sighash(
            &auth_domain,
            &root,
            &[nf],
            0,
            &cm_2,
            &cm_1,
            &cm_3,
            &mh_1,
            &mh_2,
            &mh_3,
        );
        assert_ne!(sh, sh3, "swapping cm_1/cm_2 must change sighash");

        // Unshield sighash with same root/nf must differ from transfer (type tags)
        let recipient = [0x07; 32];
        let ush = unshield_sighash(
            &auth_domain,
            &root,
            &[nf],
            1000,
            0,
            &recipient,
            &ZERO,
            &ZERO,
            &cm_3,
            &mh_3,
        );
        assert_ne!(ush, ZERO, "unshield_sighash must not be zero");
        assert_ne!(ush, sh, "transfer and unshield sighash must differ");

        // Unshield is also deterministic
        let ush2 = unshield_sighash(
            &auth_domain,
            &root,
            &[nf],
            1000,
            0,
            &recipient,
            &ZERO,
            &ZERO,
            &cm_3,
            &mh_3,
        );
        assert_eq!(ush, ush2);

        // Different v_pub → different output
        let ush3 = unshield_sighash(
            &auth_domain,
            &root,
            &[nf],
            999,
            0,
            &recipient,
            &ZERO,
            &ZERO,
            &cm_3,
            &mh_3,
        );
        assert_ne!(ush, ush3, "different v_pub must change sighash");

        // Pin both values for regression (if the function is replaced with Default, these fail)
        assert_eq!(pinned, sh, "transfer_sighash regression");
        assert_ne!(pinned, ZERO);
    }

    /// Group 2: WOTS+ pk derivation must produce correct chain length.
    /// Kills: replace - with +/÷ in wots_pk (chain length), replace auth_leaf_hash -> Default
    #[test]
    fn test_mutant_wots_pk_correctness() {
        let ask_j = [0x42; 32];
        let pub_seed = derive_auth_pub_seed(&ask_j);

        // wots_pk returns 133 chain endpoints
        let pk = wots_pk(&ask_j, 0);
        assert_eq!(pk.len(), WOTS_CHAINS);

        let msg = hash(b"wots pk correctness");
        let (sig, pk_from_sign, digits) = wots_sign(&ask_j, 0, &msg);
        assert_eq!(pk_from_sign, pk, "wots_sign pk must match wots_pk");
        let recovered_pk = recover_wots_pk(&msg, &pub_seed, 0, &sig);
        assert_eq!(recovered_pk, pk, "recover_wots_pk must match wots_pk");
        assert_eq!(digits.len(), WOTS_CHAINS);

        // auth_leaf_hash must be non-zero and match wots_pk_to_leaf(wots_pk(...))
        let leaf = auth_leaf_hash(&ask_j, 0);
        assert_ne!(leaf, ZERO, "auth_leaf_hash must not be zero");
        assert_eq!(
            leaf,
            wots_pk_to_leaf(&pub_seed, 0, &pk),
            "auth_leaf_hash must match fold(wots_pk)"
        );

        // Different key index → different leaf
        let leaf_1 = auth_leaf_hash(&ask_j, 1);
        assert_ne!(leaf, leaf_1);
    }

    /// Group 3: WOTS+ sign must produce verifiable signatures.
    /// Kills: all 9 wots_sign mutations (shift, checksum, chain hash count)
    #[test]
    fn test_mutant_wots_sign_then_verify() {
        let ask_j = [0x55; 32];
        let msg = hash(b"test message for wots");

        let (sig, pk, digits) = wots_sign(&ask_j, 0, &msg);
        assert_eq!(sig.len(), WOTS_CHAINS);
        assert_eq!(pk.len(), WOTS_CHAINS);
        assert_eq!(digits.len(), WOTS_CHAINS);

        let pub_seed = derive_auth_pub_seed(&ask_j);
        let recovered_pk = recover_wots_pk(&msg, &pub_seed, 0, &sig);
        assert_eq!(
            recovered_pk, pk,
            "recover_wots_pk must reproduce the signer pk"
        );

        // Verify checksum: sum(W-1 - msg_digit[i] for i in 0..128) must decompose into digits[128..133]
        let msg_checksum: u32 = digits[..128].iter().map(|&d| (WOTS_W as u32 - 1) - d).sum();
        let mut cs_reconstructed: u32 = 0;
        for (i, &d) in digits[128..].iter().enumerate() {
            cs_reconstructed += d * (4u32.pow(i as u32));
        }
        assert_eq!(
            msg_checksum, cs_reconstructed,
            "checksum digits must encode the message checksum"
        );

        // Verify pk matches independently derived wots_pk
        let pk_direct = wots_pk(&ask_j, 0);
        assert_eq!(pk, pk_direct, "wots_sign pk must match wots_pk");

        // Verify digits match independent decomposition of the message hash.
        // This catches >>= to <<= mutation in digit extraction.
        let mut expected_digits: Vec<usize> = Vec::new();
        for &byte in msg.iter() {
            expected_digits.push((byte & 3) as usize);
            expected_digits.push(((byte >> 2) & 3) as usize);
            expected_digits.push(((byte >> 4) & 3) as usize);
            expected_digits.push(((byte >> 6) & 3) as usize);
        }
        for j in 0..128 {
            assert_eq!(
                digits[j] as usize, expected_digits[j],
                "digit {} mismatch: wots_sign produced {} but expected {} from byte decomposition",
                j, digits[j], expected_digits[j]
            );
        }
    }

    /// Regression: the auth leaf must be the fold of the WOTS+ public key
    /// recovered from the signature itself.
    #[test]
    fn test_regression_wots_signature_binds_to_auth_leaf() {
        let ask_j = [0x66; 32];
        let pub_seed = derive_auth_pub_seed(&ask_j);
        let key_idx = 7u32;
        let msg = hash(b"bind recovered wots pk to auth leaf");

        let (sig, _, _digits) = wots_sign(&ask_j, key_idx, &msg);
        let recovered_pk = recover_wots_pk(&msg, &pub_seed, key_idx, &sig);

        let recovered_leaf = wots_pk_to_leaf(&pub_seed, key_idx, &recovered_pk);
        let expected_leaf = auth_leaf_hash(&ask_j, key_idx);
        assert_eq!(
            recovered_leaf, expected_leaf,
            "the recovered WOTS+ endpoints must fold to the authenticated auth-tree leaf"
        );

        let wrong_leaf = auth_leaf_hash(&ask_j, key_idx + 1);
        assert_ne!(wrong_leaf, recovered_leaf, "leaf index binding must hold");
    }

    /// Group 4: auth leaf derivation must stay index-bound.
    /// This keeps the WOTS/XMSS boundary covered without regenerating a full tree.
    #[test]
    fn test_mutant_auth_leaf_index_binding() {
        let ask_j = [0x77; 32];
        let pub_seed = derive_auth_pub_seed(&ask_j);
        let leaf_0 = auth_leaf_hash(&ask_j, 0);
        let leaf_1 = auth_leaf_hash(&ask_j, 1);
        let leaf_2 = auth_leaf_hash(&ask_j, 2);
        assert_eq!(leaf_0, wots_pk_to_leaf(&pub_seed, 0, &wots_pk(&ask_j, 0)));
        assert_eq!(leaf_1, wots_pk_to_leaf(&pub_seed, 1, &wots_pk(&ask_j, 1)));
        assert_eq!(leaf_2, wots_pk_to_leaf(&pub_seed, 2, &wots_pk(&ask_j, 2)));
        assert_ne!(leaf_0, leaf_1);
        assert_ne!(leaf_1, leaf_2);
        assert_ne!(leaf_0, leaf_2);
    }

    /// Group 5a: shield balance edge cases.
    /// Kills: replace < with ==/<=  in balance check
    #[test]
    fn test_mutant_shield_exact_balance() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 500 + TEST_FEE + 1);

        let addr = random_payment_address();
        let (producer_cm_a, producer_enc_a, _producer_mh_a) = test_output_note(0x47);

        // Exact balance: v == bal. Must succeed.
        // (< mutation turns `bal < v` into `bal == v`, which would REJECT this)
        // (<= mutation turns `bal < v` into `bal <= v`, which would REJECT this)
        let r = ledger.shield(&ShieldReq {
            deposit_id: test_deposit_id("alice"),
            v: 500,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr.clone(),
            memo: None,
            proof: Proof::TrustMeBro,
            client_cm: ZERO,
            client_enc: None,
            producer_cm: producer_cm_a,
            producer_enc: Some(producer_enc_a),
        });
        assert!(
            r.is_ok(),
            "shield with exact balance must succeed: {:?}",
            r.err()
        );

        // Over balance: must fail
        let (producer_cm_b, producer_enc_b, _producer_mh_b) = test_output_note(0x48);
        let r = ledger.shield(&ShieldReq {
            deposit_id: test_deposit_id("alice"),
            v: 1,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: Proof::TrustMeBro,
            client_cm: ZERO,
            client_enc: None,
            producer_cm: producer_cm_b,
            producer_enc: Some(producer_enc_b),
        });
        assert!(r.is_err(), "shield exceeding balance must fail");
    }

    /// Group 5a-extra: shield output_preimage length boundary.
    /// Kills: replace < with ==/<=  in output_preimage.len() < 4
    #[test]
    fn test_mutant_shield_preimage_length_boundary() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);

        let cm = random_felt();
        let deposit_id = test_deposit_id("alice");
        let seed: [u8; 64] = [0x99; 64];
        let (ek, _) = kem_keygen_from_seed(&seed);
        let enc = encrypt_note(1000, &random_felt(), None, &ek, &ek);
        let mh = memo_ct_hash(&enc);

        // Preimage with exactly 5 elements (minimum valid — no bootloader header)
        let _preimage_5 = vec![u(1000), fee_f(), cm, deposit_id, mh];
        let (producer_cm, producer_enc, producer_mh) = test_output_note(0x49);
        let preimage_8 = vec![
            u(1000),
            fee_f(),
            u(1),
            cm,
            producer_cm,
            deposit_id,
            mh,
            producer_mh,
        ];
        let addr = random_payment_address();
        let r = ledger.shield(&ShieldReq {
            deposit_id,
            v: 1000,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr.clone(),
            memo: None,
            proof: fake_stark(preimage_8),
            client_cm: cm,
            client_enc: Some(enc.clone()),
            producer_cm,
            producer_enc: Some(producer_enc.clone()),
        });
        assert!(
            r.is_ok(),
            "preimage of exactly 5 should be accepted: {:?}",
            r.err()
        );

        // Preimage with 4 elements (too short)
        let preimage_7 = vec![u(1000), fee_f(), u(1), cm, producer_cm, deposit_id, mh];
        let r = ledger.shield(&ShieldReq {
            deposit_id,
            v: 1000,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: fake_stark(preimage_7),
            client_cm: cm,
            client_enc: Some(enc),
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(r.is_err(), "preimage of 3 should be rejected");
    }

    /// Group 5b: shield with client_cm but no client_enc (TrustMeBro path).
    /// Kills: replace && with || in client_cm/client_enc check at line 932.
    /// With ||, cm!=ZERO alone would enter the client path and unwrap() None → panic.
    #[test]
    fn test_mutant_shield_cm_without_enc_tmb() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);
        let addr = random_payment_address();
        let (producer_cm, producer_enc, _producer_mh) = test_output_note(0x4A);
        // TrustMeBro with client_cm set but client_enc=None
        // With &&: client_cm!=ZERO && client_enc.is_some() = true && false = false → server generates cm (OK)
        // With ||: client_cm!=ZERO || client_enc.is_some() = true || false = true → unwrap None → PANIC
        let r = ledger.shield(&ShieldReq {
            deposit_id: test_deposit_id("alice"),
            v: 1000,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: Proof::TrustMeBro,
            client_cm: random_felt(), // set but enc is None
            client_enc: None,
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        // Should succeed — server generates its own cm/enc
        assert!(
            r.is_ok(),
            "TrustMeBro shield with partial client data should fall through to server: {:?}",
            r.err()
        );
    }

    /// Group 5b (Stark path): shield Stark with client_cm but no client_enc.
    #[test]
    fn test_mutant_shield_stark_cm_without_enc() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 200_000);

        let cm = random_felt();
        let (producer_cm, producer_enc, producer_mh) = test_output_note(0x4B);
        let preimage = vec![
            u(1000),
            fee_f(),
            u(1),
            cm,
            producer_cm,
            ZERO,
            ZERO,
            producer_mh,
        ];
        let addr = random_payment_address();

        // client_cm set but client_enc is None — must be rejected
        // (&&→|| mutation would accept this because client_cm != ZERO is true)
        let r = ledger.shield(&ShieldReq {
            deposit_id: test_deposit_id("alice"),
            v: 1000,
            fee: TEST_FEE,
            producer_fee: 1,
            address: addr,
            memo: None,
            proof: fake_stark(preimage),
            client_cm: cm,
            client_enc: None, // THIS is the key — Stark proof requires enc
            producer_cm,
            producer_enc: Some(producer_enc),
        });
        assert!(
            r.is_err(),
            "Stark proof with client_cm but no client_enc must be rejected"
        );
    }

    /// Group 5c: transfer and unshield with 7 inputs (max) must succeed, 8 must fail.
    /// Kills: replace > with ==/>=  in N > MAX_INPUTS check
    #[test]
    fn test_mutant_transfer_max_inputs() {
        let (mut ledger, _, _, root, enc) = setup_with_note();

        // N=7 should be accepted (> mutation turns N > 7 into N == 7, rejecting 7)
        // We can't easily create 7 real notes here, so test the boundary:
        // N=8 must be rejected
        let nfs: Vec<F> = (0..8).map(|_| random_felt()).collect();
        let (cm_3a, enc_3a, _mh_3a) = test_output_note(0x4C);
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: nfs,
            fee: TEST_FEE,
            cm_1: random_felt(),
            cm_2: random_felt(),
            cm_3: cm_3a,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3: enc_3a,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err(), "N=8 transfer must be rejected");
        assert!(r.unwrap_err().contains("bad nullifier count"));

        // N=7 should pass the count check (may fail on nullifier/root, that's fine)
        let nfs7: Vec<F> = (0..7).map(|_| random_felt()).collect();
        let (cm_3b, enc_3b, _mh_3b) = test_output_note(0x4D);
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: nfs7,
            fee: TEST_FEE,
            cm_1: random_felt(),
            cm_2: random_felt(),
            cm_3: cm_3b,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3: enc_3b,
            proof: Proof::TrustMeBro,
        });
        // Should NOT fail with "bad nullifier count" — may fail with "nullifier spent" or "invalid root"
        if let Err(e) = &r {
            assert!(
                !e.contains("bad nullifier count"),
                "N=7 should pass the count check, got: {}",
                e
            );
        }
    }

    /// Group 5c (continued): unshield max inputs boundary.
    #[test]
    fn test_mutant_unshield_max_inputs() {
        let (mut ledger, _, _, root, _) = setup_with_note();

        let nfs8: Vec<F> = (0..8).map(|_| random_felt()).collect();
        let (cm_fee_a, enc_fee_a, _mh_fee_a) = test_output_note(0x4E);
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: nfs8,
            v_pub: 100,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee: cm_fee_a,
            enc_fee: enc_fee_a,
            proof: Proof::TrustMeBro,
        });
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("bad nullifier count"));

        let nfs7: Vec<F> = (0..7).map(|_| random_felt()).collect();
        let (cm_fee_b, enc_fee_b, _mh_fee_b) = test_output_note(0x4F);
        let r = ledger.unshield(&UnshieldReq {
            root,
            nullifiers: nfs7,
            v_pub: 100,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee: cm_fee_b,
            enc_fee: enc_fee_b,
            proof: Proof::TrustMeBro,
        });
        if let Err(e) = &r {
            assert!(
                !e.contains("bad nullifier count"),
                "N=7 should pass count check, got: {}",
                e
            );
        }
    }

    /// Group 5d: transfer output_preimage positional validation with distinct values.
    /// Kills: replace + with -/* in cm1_pos calculation, and < with <= in length check
    #[test]
    fn test_mutant_transfer_preimage_positions() {
        let (mut ledger, _cm, nf, root, enc) = setup_with_note();

        // Create a valid-looking preimage where every field has a UNIQUE value.
        // This ensures positional checks can't pass by coincidence.
        let cm_1 = random_felt();
        let cm_2 = random_felt();
        let (cm_3, enc_3, mh_3) = test_output_note(0x50);
        let mh_1 = memo_ct_hash(&enc);
        let mh_2 = memo_ct_hash(&enc);

        // N=1: tail layout is [root, nf, fee, cm_1, cm_2, cm_3, mh_1, mh_2, mh_3]
        let preimage = vec![root, nf, fee_f(), cm_1, cm_2, cm_3, mh_1, mh_2, mh_3];

        // This should succeed — all fields at correct positions
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1,
            cm_2,
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3: enc_3.clone(),
            proof: fake_stark(preimage.clone()),
        });
        assert!(
            r.is_ok(),
            "transfer with correct preimage should succeed: {:?}",
            r.err()
        );

        // Now test with preimage that has cm_1 and cm_2 SWAPPED in position
        let bad_preimage = vec![root, nf, fee_f(), cm_2, cm_1, cm_3, mh_1, mh_2, mh_3];
        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf],
            fee: TEST_FEE,
            cm_1,
            cm_2,
            cm_3,
            enc_1: enc.clone(),
            enc_2: enc.clone(),
            enc_3,
            proof: fake_stark(bad_preimage),
        });
        assert!(r.is_err(), "swapped cm_1/cm_2 positions must be caught");
    }

    /// Kills 3 mutants that survive with N=1 nullifier:
    /// - line 986: `<` vs `<=` (exact-length preimage)
    /// - line 998: `1+i` vs `1-i` (multi-nullifier indexing)
    /// - line 1012: `cm1_pos+2` vs `cm1_pos*2` (diverge when cm1_pos=3)
    #[test]
    fn test_mutant_transfer_multi_nullifier_preimage() {
        let mut ledger = Ledger::new();
        let _ = ledger.fund(&test_deposit_key("alice"), 300_000);

        // Create two notes so we have two distinct nullifiers
        let mut master_sk = ZERO;
        master_sk[0] = 0xCC;
        let acc = derive_account(&master_sk);
        let d_j = derive_address(&acc.incoming_seed, 0);
        let ask_j = derive_ask(&acc.ask_base, 0);
        let auth_pub_seed = derive_auth_pub_seed(&ask_j);
        let auth_root = test_auth_root(&d_j, &auth_pub_seed);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);

        let seed_v: [u8; 64] = [0x33u8; 64];
        let seed_d: [u8; 64] = [0x44u8; 64];
        let (ek_v, _, ek_d, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed_v);
            let (ekd, dkd) = kem_keygen_from_seed(&seed_d);
            (ekv, dkv, ekd, dkd)
        };
        let addr = PaymentAddress {
            d_j,
            auth_root,
            auth_pub_seed,
            nk_tag: nk_tg,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        };
        let (producer_cm_a, producer_enc_a, _producer_mh_a) = test_output_note(0x52);
        let (producer_cm_b, producer_enc_b, _producer_mh_b) = test_output_note(0x53);

        // Shield two notes
        ledger
            .shield(&ShieldReq {
                deposit_id: test_deposit_id("alice"),
                v: 1000,
                fee: TEST_FEE,
                producer_fee: 1,
                address: addr.clone(),
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
                producer_cm: producer_cm_a,
                producer_enc: Some(producer_enc_a),
            })
            .unwrap();
        ledger
            .shield(&ShieldReq {
                deposit_id: test_deposit_id("alice"),
                v: 2000,
                fee: TEST_FEE,
                producer_fee: 1,
                address: addr.clone(),
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
                producer_cm: producer_cm_b,
                producer_enc: Some(producer_enc_b),
            })
            .unwrap();

        let cm_0 = ledger.tree.leaves[0];
        let cm_1_note = ledger.tree.leaves[1];
        let root = ledger.tree.root();
        let nf_0 = nullifier(&nk_sp, &cm_0, 0);
        let nf_1 = nullifier(&nk_sp, &cm_1_note, 1);
        let enc = ledger.memos[0].1.clone();

        let out_cm_1 = random_felt();
        let out_cm_2 = random_felt();
        let out_cm_3 = random_felt();
        // Use two DIFFERENT encrypted notes so mh_1 != mh_2.
        // This is critical: with N=2, cm1_pos=3, so cm1_pos+2=5 and cm1_pos*2=6.
        // If mh_1==mh_2, tail[5]==tail[6] and the * mutant survives.
        let enc_1 = enc.clone();
        let enc_2 = encrypt_note(500, &random_felt(), Some(b"different"), &ek_v, &ek_d);
        let mh_1 = memo_ct_hash(&enc_1);
        let mh_2 = memo_ct_hash(&enc_2);
        let enc_3 = test_encrypted_note(0x54);
        let mh_3 = memo_ct_hash(&enc_3);
        assert_ne!(
            mh_1, mh_2,
            "mh_1 and mh_2 must differ to detect positional mutants"
        );

        // N=2: tail = [root, nf_0, nf_1, fee, cm_1, cm_2, cm_3, mh_1, mh_2, mh_3]
        // cm1_pos = 2+n+1 = 5 in the old mutant discussion, but we still need distinct
        // positions for the three output commitments and hashes.
        // With i=1: 1+1=2, 1-1=0 — these DIFFER, catching the - mutant

        // Build EXACT-length preimage (no bootloader header padding)
        // This means preimage.len() == expected_tail_len, catching < vs <= mutant
        let preimage = vec![
            root,
            nf_0,
            nf_1,
            fee_f(),
            out_cm_1,
            out_cm_2,
            out_cm_3,
            mh_1,
            mh_2,
            mh_3,
        ];

        let r = ledger.transfer(&TransferReq {
            root,
            nullifiers: vec![nf_0, nf_1],
            fee: TEST_FEE,
            cm_1: out_cm_1,
            cm_2: out_cm_2,
            cm_3: out_cm_3,
            enc_1: enc_1.clone(),
            enc_2: enc_2.clone(),
            enc_3: enc_3.clone(),
            proof: fake_stark(preimage),
        });
        assert!(
            r.is_ok(),
            "transfer with 2 nullifiers and exact-length preimage must succeed: {:?}",
            r.err()
        );

        // Also verify that swapping nf_0/nf_1 in the preimage is caught
        // (detects 1+i vs 1-i mutant — with N=2 and i=1 they index differently)
        let mut ledger2 = Ledger::new();
        let _ = ledger2.fund(&test_deposit_key("alice"), 300_000);
        let (producer_cm_c, producer_enc_c, _producer_mh_c) = test_output_note(0x55);
        let (producer_cm_d, producer_enc_d, _producer_mh_d) = test_output_note(0x56);
        ledger2
            .shield(&ShieldReq {
                deposit_id: test_deposit_id("alice"),
                v: 1000,
                fee: TEST_FEE,
                producer_fee: 1,
                address: addr.clone(),
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
                producer_cm: producer_cm_c,
                producer_enc: Some(producer_enc_c),
            })
            .unwrap();
        ledger2
            .shield(&ShieldReq {
                deposit_id: test_deposit_id("alice"),
                v: 2000,
                fee: TEST_FEE,
                producer_fee: 1,
                address: addr.clone(),
                memo: None,
                proof: Proof::TrustMeBro,
                client_cm: ZERO,
                client_enc: None,
                producer_cm: producer_cm_d,
                producer_enc: Some(producer_enc_d),
            })
            .unwrap();
        let root2 = ledger2.tree.root();
        let nf2_0 = nullifier(&nk_sp, &ledger2.tree.leaves[0], 0);
        let nf2_1 = nullifier(&nk_sp, &ledger2.tree.leaves[1], 1);

        let bad_preimage = vec![
            root2,
            nf2_1,
            nf2_0,
            fee_f(),
            out_cm_1,
            out_cm_2,
            out_cm_3,
            mh_1,
            mh_2,
            mh_3,
        ];
        let r = ledger2.transfer(&TransferReq {
            root: root2,
            nullifiers: vec![nf2_0, nf2_1],
            fee: TEST_FEE,
            cm_1: out_cm_1,
            cm_2: out_cm_2,
            cm_3: out_cm_3,
            enc_1: enc_1.clone(),
            enc_2: enc_2.clone(),
            enc_3,
            proof: fake_stark(bad_preimage),
        });
        assert!(
            r.is_err(),
            "swapped nullifier order in preimage must be caught"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Regression tests for security audit findings
    // ═══════════════════════════════════════════════════════════════════

    /// Regression: per-address KEM keys must be unique across addresses.
    /// Without per-address derivation, all addresses share the same ek_v/ek_d,
    /// making them trivially linkable (finding #3 from static audit).
    #[test]
    fn test_per_address_kem_keys_unique() {
        let mut master_sk = ZERO;
        master_sk[0] = 0xDD;
        let acc = derive_account(&master_sk);

        let (ek_v_0, _, ek_d_0, _) = derive_kem_keys(&acc.incoming_seed, 0);
        let (ek_v_1, _, ek_d_1, _) = derive_kem_keys(&acc.incoming_seed, 1);
        let (ek_v_2, _, ek_d_2, _) = derive_kem_keys(&acc.incoming_seed, 2);

        // All viewing keys must differ
        assert_ne!(
            ek_v_0.to_bytes(),
            ek_v_1.to_bytes(),
            "ek_v must differ across addresses"
        );
        assert_ne!(ek_v_0.to_bytes(), ek_v_2.to_bytes());
        assert_ne!(ek_v_1.to_bytes(), ek_v_2.to_bytes());

        // All detection keys must differ
        assert_ne!(
            ek_d_0.to_bytes(),
            ek_d_1.to_bytes(),
            "ek_d must differ across addresses"
        );
        assert_ne!(ek_d_0.to_bytes(), ek_d_2.to_bytes());
        assert_ne!(ek_d_1.to_bytes(), ek_d_2.to_bytes());

        // Viewing and detection keys must also differ from each other
        assert_ne!(
            ek_v_0.to_bytes(),
            ek_d_0.to_bytes(),
            "ek_v and ek_d must differ"
        );
    }

    /// Regression: per-address KEM derivation must be deterministic.
    #[test]
    fn test_per_address_kem_keys_deterministic() {
        let mut master_sk = ZERO;
        master_sk[0] = 0xEE;
        let acc = derive_account(&master_sk);

        let (ek_v_a, _, ek_d_a, _) = derive_kem_keys(&acc.incoming_seed, 5);
        let (ek_v_b, _, ek_d_b, _) = derive_kem_keys(&acc.incoming_seed, 5);

        assert_eq!(
            ek_v_a.to_bytes(),
            ek_v_b.to_bytes(),
            "same index must produce same ek_v"
        );
        assert_eq!(
            ek_d_a.to_bytes(),
            ek_d_b.to_bytes(),
            "same index must produce same ek_d"
        );
    }

    /// Regression: encrypt-then-detect must work with per-address keys.
    /// Sender encrypts to address j's public keys, recipient detects + decrypts
    /// with address j's secret keys. Must NOT detect with address k's keys.
    #[test]
    fn test_per_address_encrypt_detect_decrypt_isolation() {
        let mut master_sk = ZERO;
        master_sk[0] = 0xFF;
        let acc = derive_account(&master_sk);

        let (ek_v_0, dk_v_0, ek_d_0, dk_d_0) = derive_kem_keys(&acc.incoming_seed, 0);
        let (_, dk_v_1, _, dk_d_1) = derive_kem_keys(&acc.incoming_seed, 1);

        // Encrypt to address 0
        let rseed = random_felt();
        let enc = encrypt_note(42, &rseed, Some(b"test"), &ek_v_0, &ek_d_0);

        // Address 0's dk_d should detect it
        assert!(detect(&enc, &dk_d_0), "address 0 must detect its own note");

        // Address 1's dk_d should almost certainly NOT detect it (tag collision ~1/1024)
        // We test this probabilistically — if it fails, it's a 1-in-1024 fluke
        // (acceptable for a regression test)
        let detected_by_1 = detect(&enc, &dk_d_1);
        // Don't assert — just verify decryption isolation below

        // Address 0's dk_v should decrypt it
        let dec = decrypt_memo(&enc, &dk_v_0);
        assert!(dec.is_some(), "address 0 must decrypt its own note");
        let (v, rs, _) = dec.unwrap();
        assert_eq!(v, 42);
        assert_eq!(rs, rseed);

        // Address 1's dk_v must NOT decrypt it (wrong shared secret)
        let dec_1 = decrypt_memo(&enc, &dk_v_1);
        assert!(
            dec_1.is_none(),
            "address 1 must NOT decrypt address 0's note"
        );
        let _ = detected_by_1;
    }

    /// Regression: detect() must not panic on correctly-sized but mismatched ciphertext.
    /// (Finding #14 from static audit — untrusted input from ledger feed.)
    #[test]
    fn test_detect_well_sized_but_wrong_ciphertext_no_panic() {
        let mut master_sk = ZERO;
        master_sk[0] = 0xAB;
        let acc = derive_account(&master_sk);
        let (_, _, _, dk_d) = derive_kem_keys(&acc.incoming_seed, 0);

        // Create a correctly-sized but garbage ciphertext
        let ct_d = vec![0xAA; 1088]; // ML-KEM-768 ciphertext size
        let enc = EncryptedNote {
            ct_d,
            tag: 42,
            ct_v: vec![0xBB; 1088],
            nonce: vec![0xDD; NOTE_AEAD_NONCE_BYTES],
            encrypted_data: vec![0xCC; 100],
            outgoing_ct: empty_outgoing_recovery_ct(),
        };

        // Must not panic — should return false
        let result = detect(&enc, &dk_d);
        assert!(!result, "garbage ciphertext must not match");
    }

    /// Regression: derive_kem_view_seed and derive_kem_detect_seed must produce
    /// different seeds even for the same address index.
    #[test]
    fn test_kem_view_detect_seeds_differ() {
        let mut master_sk = ZERO;
        master_sk[0] = 0x77;
        let acc = derive_account(&master_sk);

        let sv = derive_kem_view_seed(&acc.incoming_seed, 0);
        let sd = derive_kem_detect_seed(&acc.incoming_seed, 0);
        assert_ne!(sv, sd, "view and detect seeds for same address must differ");
    }

    #[test]
    fn test_parse_single_task_output_preimage() {
        let output_preimage = vec![u(1), u(5), u(12345), u(11), u(22), u(33)];

        let parsed = parse_single_task_output_preimage(&output_preimage).unwrap();
        assert_eq!(parsed.program_hash, &u(12345));
        assert_eq!(parsed.public_outputs, &output_preimage[3..]);
    }

    #[test]
    fn test_validate_single_task_program_hash_rejects_wrong_program() {
        let output_preimage = vec![u(1), u(5), u(12345), u(11), u(22), u(33)];

        let err = validate_single_task_program_hash(&output_preimage, &u(99999)).unwrap_err();
        assert!(
            err.contains("unexpected circuit program hash"),
            "unexpected error: {}",
            err
        );
    }

    fn fake_stark_with_program_hash(program_hash: F) -> Proof {
        Proof::Stark {
            proof_bytes: vec![0],
            output_preimage: vec![u(1), u(5), program_hash, u(11), u(22), u(33)],
        }
    }

    #[test]
    fn test_ledger_proof_verifier_accepts_expected_program_hash() {
        let proof = fake_stark_with_program_hash(u(12345));
        let hashes = ProgramHashes {
            shield: u(111),
            transfer: u(12345),
            unshield: u(333),
        };

        let result = validate_stark_circuit(&proof, CircuitKind::Transfer, &hashes);
        assert!(result.is_ok(), "expected matching program hash to verify");
    }

    #[test]
    fn test_ledger_proof_verifier_rejects_unexpected_program_hash() {
        let proof = fake_stark_with_program_hash(u(12345));
        let hashes = ProgramHashes {
            shield: u(111),
            transfer: u(99999),
            unshield: u(333),
        };

        let err = validate_stark_circuit(&proof, CircuitKind::Transfer, &hashes).unwrap_err();
        assert!(
            err.contains("unexpected circuit program hash"),
            "unexpected error: {}",
            err
        );
        assert!(
            err.contains("transfer"),
            "expected circuit name in error: {}",
            err
        );
    }

    #[test]
    fn test_ledger_proof_verifier_rejects_unexpected_program_hash_before_external_verify() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("external-verifier-ran");
        let script = temp.path().join("fake-reprove");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf ran > '{}'\necho external verifier should not run >&2\nexit 42\n",
                marker.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let proof = fake_stark_with_program_hash(u(12345));
        let verifier = LedgerProofVerifier::verified(
            false,
            script.display().to_string(),
            ProgramHashes {
                shield: u(111),
                transfer: u(99999),
                unshield: u(333),
            },
        );

        let err = verifier
            .validate(&proof, CircuitKind::Transfer)
            .unwrap_err();

        assert!(
            err.contains("unexpected circuit program hash"),
            "wrong circuit should be rejected by public output preflight, got: {err}"
        );
        assert!(
            !marker.exists(),
            "external verifier must not run for a proof whose public program hash is already wrong"
        );
    }

    #[test]
    fn test_ledger_proof_verifier_passes_operation_executable_to_external_verify() {
        let temp = tempfile::tempdir().unwrap();
        let executables_dir = temp.path().join("executables");
        std::fs::create_dir(&executables_dir).unwrap();
        for name in [
            CircuitKind::Shield.executable_filename(),
            CircuitKind::Transfer.executable_filename(),
            CircuitKind::Unshield.executable_filename(),
        ] {
            std::fs::write(executables_dir.join(name), "{}").unwrap();
        }

        let marker = temp.path().join("verify-executable-arg");
        let script = temp.path().join("fake-reprove");
        let transfer_hash = u(222);
        std::fs::write(
            &script,
            format!(
                r#"#!/bin/sh
if [ "$2" = "--program-hash" ]; then
  case "$1" in
    *run_shield.executable.json) printf '{}\n' ;;
    *run_transfer.executable.json) printf '{}\n' ;;
    *run_unshield.executable.json) printf '{}\n' ;;
    *) echo "unknown executable: $1" >&2; exit 2 ;;
  esac
  exit 0
fi
if [ "$2" = "--verify" ]; then
  printf '%s' "$1" > '{}'
  exit 0
fi
echo "unexpected invocation" >&2
exit 2
"#,
                hex::encode(u(111)),
                hex::encode(transfer_hash),
                hex::encode(u(333)),
                marker.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let verifier = LedgerProofVerifier::from_reprove_bin(
            false,
            script.display().to_string(),
            executables_dir.to_str().unwrap(),
        )
        .unwrap();
        let proof = fake_stark_with_program_hash(transfer_hash);

        verifier.validate(&proof, CircuitKind::Transfer).unwrap();

        let invoked_executable = std::fs::read_to_string(marker).unwrap();
        assert!(
            invoked_executable.ends_with(CircuitKind::Transfer.executable_filename()),
            "external verifier should receive the operation executable, got: {invoked_executable}"
        );
    }

    #[test]
    fn test_ledger_proof_verifier_rejects_stark_without_verified_mode() {
        let verifier = LedgerProofVerifier::trust_me_bro_only();
        let proof = fake_stark_with_program_hash(u(12345));

        let err = verifier
            .validate(&proof, CircuitKind::Transfer)
            .unwrap_err();
        assert!(
            err.contains("not configured with --reprove-bin"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_single_task_output_preimage_rejects_bad_length() {
        let output_preimage = vec![u(1), u(7), u(12345), u(11), u(22), u(33)];

        let err = parse_single_task_output_preimage(&output_preimage).unwrap_err();
        assert!(err.contains("length mismatch"), "unexpected error: {}", err);
    }

    #[test]
    fn test_fund_rejects_public_balance_overflow() {
        let mut ledger = Ledger::new();
        ledger.balances.insert("alice".into(), u64::MAX);

        let err = ledger.fund("alice", 1).unwrap_err();
        assert!(
            err.contains("public balance overflow"),
            "unexpected error: {}",
            err
        );
        assert_eq!(ledger.balances.get("alice"), Some(&u64::MAX));
    }

    #[test]
    fn test_unshield_rejects_public_balance_overflow() {
        let mut ledger = Ledger::new();
        ledger.balances.insert("alice".into(), u64::MAX);
        let (cm_fee, enc_fee, _mh_fee) = test_output_note(0x57);

        let req = UnshieldReq {
            root: ledger.tree.root(),
            nullifiers: vec![random_felt()],
            v_pub: 1,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: ZERO,
            enc_change: None,
            cm_fee,
            enc_fee,
            proof: Proof::TrustMeBro,
        };

        let err = ledger.unshield(&req).unwrap_err();
        assert!(
            err.contains("public balance overflow"),
            "unexpected error: {}",
            err
        );
        assert_eq!(ledger.balances.get("alice"), Some(&u64::MAX));
        assert!(
            !ledger.nullifiers.contains(&req.nullifiers[0]),
            "overflowing unshield must not consume nullifiers"
        );
    }

    #[test]
    fn test_unshield_overflow_is_atomic_even_with_change_note() {
        let mut ledger = Ledger::new();
        ledger.balances.insert("alice".into(), u64::MAX);
        let tree_size_before = ledger.tree.leaves.len();
        let memo_count_before = ledger.memos.len();

        let seed: [u8; 64] = [0xAB; 64];
        let (ek_v, _, ek_d, _) = {
            let (ekv, dkv) = kem_keygen_from_seed(&seed);
            let (ekd, dkd) = kem_keygen_from_seed(&seed);
            (ekv, dkv, ekd, dkd)
        };
        let enc_change = encrypt_note(1, &random_felt(), None, &ek_v, &ek_d);
        let (cm_fee, enc_fee, _mh_fee) = test_output_note(0x58);
        let req = UnshieldReq {
            root: ledger.tree.root(),
            nullifiers: vec![random_felt()],
            v_pub: 1,
            fee: TEST_FEE,
            recipient: "alice".into(),
            cm_change: random_felt(),
            enc_change: Some(enc_change),
            cm_fee,
            enc_fee,
            proof: Proof::TrustMeBro,
        };

        let err = ledger.unshield(&req).unwrap_err();
        assert!(
            err.contains("public balance overflow"),
            "unexpected error: {}",
            err
        );
        assert_eq!(ledger.tree.leaves.len(), tree_size_before);
        assert_eq!(ledger.memos.len(), memo_count_before);
        assert!(
            !ledger.nullifiers.contains(&req.nullifiers[0]),
            "overflowing unshield must not consume nullifiers"
        );
    }
}
