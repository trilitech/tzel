#[cfg(not(feature = "proof-verifier"))]
fn main() {
    eprintln!("verified_bridge_fixture_message requires the proof-verifier feature");
    std::process::exit(1);
}

#[cfg(feature = "proof-verifier")]
mod with_verifier {
    use std::{env, fs};

    use serde::{Deserialize, Serialize};
    use tzel_core::{
        kernel_wire::{
            encode_kernel_inbox_message, KernelInboxMessage, KernelShieldReq, KernelStarkProof,
            KernelTransferReq, KernelUnshieldReq,
        },
        ProgramHashes, Proof, ShieldReq, TransferReq, UnshieldReq, F,
    };

    #[derive(Debug, Deserialize)]
    struct VerifiedBridgeFixture {
        #[serde(with = "tzel_core::hex_f")]
        auth_domain: F,
        program_hashes: ProgramHashes,
        bridge_ticketer: String,
        withdrawal_recipient: String,
        shield: ShieldReq,
        transfer: TransferReq,
        unshield: UnshieldReq,
    }

    #[derive(Debug, Serialize)]
    struct FixtureMetadata<'a> {
        auth_domain: String,
        shield_program_hash: String,
        transfer_program_hash: String,
        unshield_program_hash: String,
        bridge_ticketer: &'a str,
        withdrawal_recipient: &'a str,
        shield_deposit_id: String,
        shield_amount: u64,
        shield_total_debit: u64,
        shield_tree_size_after: u64,
    }

    fn usage() -> ! {
        eprintln!(
            "usage:\n  verified_bridge_fixture_message metadata [fixture.json]\n  verified_bridge_fixture_message shield-raw [fixture.json]\n  verified_bridge_fixture_message transfer-raw [fixture.json]\n  verified_bridge_fixture_message unshield-raw [fixture.json]"
        );
        std::process::exit(2);
    }

    fn felt_hex(value: &F) -> String {
        hex::encode(value)
    }

    fn load_fixture(path: Option<&str>) -> VerifiedBridgeFixture {
        match path {
            Some(path) => {
                let body = fs::read_to_string(path).expect("fixture file should be readable");
                serde_json::from_str(&body).expect("fixture json should parse")
            }
            None => serde_json::from_str(include_str!("../../testdata/verified_bridge_flow.json"))
                .expect("checked-in fixture should parse"),
        }
    }

    fn kernel_proof_from_fixture(proof: &Proof) -> KernelStarkProof {
        match proof {
            Proof::Stark {
                proof_bytes,
                output_preimage,
            } => KernelStarkProof {
                proof_bytes: proof_bytes.clone(),
                output_preimage: output_preimage.clone(),
            },
            Proof::TrustMeBro => panic!("fixture should contain real Stark proofs"),
        }
    }

    fn kernel_shield_req_from_fixture(req: &ShieldReq) -> KernelShieldReq {
        KernelShieldReq {
            deposit_id: req.deposit_id,
            v: req.v,
            fee: req.fee,
            producer_fee: req.producer_fee,
            address: req.address.clone(),
            memo: req.memo.clone(),
            proof: kernel_proof_from_fixture(&req.proof),
            client_cm: req.client_cm,
            client_enc: req.client_enc.clone(),
            producer_cm: req.producer_cm,
            producer_enc: req.producer_enc.clone(),
        }
    }

    fn kernel_transfer_req_from_fixture(req: &TransferReq) -> KernelTransferReq {
        KernelTransferReq {
            root: req.root,
            nullifiers: req.nullifiers.clone(),
            fee: req.fee,
            cm_1: req.cm_1,
            cm_2: req.cm_2,
            cm_3: req.cm_3,
            enc_1: req.enc_1.clone(),
            enc_2: req.enc_2.clone(),
            enc_3: req.enc_3.clone(),
            proof: kernel_proof_from_fixture(&req.proof),
        }
    }

    fn kernel_unshield_req_from_fixture(req: &UnshieldReq) -> KernelUnshieldReq {
        KernelUnshieldReq {
            root: req.root,
            nullifiers: req.nullifiers.clone(),
            v_pub: req.v_pub,
            fee: req.fee,
            recipient: req.recipient.clone(),
            cm_change: req.cm_change,
            enc_change: req.enc_change.clone(),
            cm_fee: req.cm_fee,
            enc_fee: req.enc_fee.clone(),
            proof: kernel_proof_from_fixture(&req.proof),
        }
    }

    fn emit_raw_hex(message: KernelInboxMessage) {
        let payload = encode_kernel_inbox_message(&message).expect("kernel message should encode");
        println!("{}", hex::encode(payload));
    }

    fn fixture_metadata(fixture: &VerifiedBridgeFixture) -> FixtureMetadata<'_> {
        FixtureMetadata {
            auth_domain: felt_hex(&fixture.auth_domain),
            shield_program_hash: felt_hex(&fixture.program_hashes.shield),
            transfer_program_hash: felt_hex(&fixture.program_hashes.transfer),
            unshield_program_hash: felt_hex(&fixture.program_hashes.unshield),
            bridge_ticketer: &fixture.bridge_ticketer,
            withdrawal_recipient: &fixture.withdrawal_recipient,
            shield_deposit_id: tzel_core::deposit_balance_key(&fixture.shield.deposit_id),
            shield_amount: fixture.shield.v,
            shield_total_debit: fixture.shield.v + fixture.shield.fee + fixture.shield.producer_fee,
            shield_tree_size_after: 2,
        }
    }

    pub fn main() {
        let mut args = env::args().skip(1);
        let Some(cmd) = args.next() else {
            usage();
        };
        let fixture = load_fixture(args.next().as_deref());
        if args.next().is_some() {
            usage();
        }

        match cmd.as_str() {
            "metadata" => {
                let metadata = fixture_metadata(&fixture);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&metadata)
                        .expect("fixture metadata should serialize")
                );
            }
            "shield-raw" => {
                emit_raw_hex(KernelInboxMessage::Shield(kernel_shield_req_from_fixture(
                    &fixture.shield,
                )));
            }
            "transfer-raw" => {
                emit_raw_hex(KernelInboxMessage::Transfer(
                    kernel_transfer_req_from_fixture(&fixture.transfer),
                ));
            }
            "unshield-raw" => {
                emit_raw_hex(KernelInboxMessage::Unshield(
                    kernel_unshield_req_from_fixture(&fixture.unshield),
                ));
            }
            _ => usage(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn metadata_reports_full_shield_requirements() {
            let fixture = load_fixture(None);
            let metadata = fixture_metadata(&fixture);

            assert_eq!(metadata.shield_amount, fixture.shield.v);
            assert_eq!(
                metadata.shield_total_debit,
                fixture.shield.v + fixture.shield.fee + fixture.shield.producer_fee
            );
            assert_eq!(metadata.shield_tree_size_after, 2);
        }
    }
}

#[cfg(feature = "proof-verifier")]
fn main() {
    with_verifier::main();
}
