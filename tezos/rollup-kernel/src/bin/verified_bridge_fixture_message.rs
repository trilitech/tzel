#[cfg(not(feature = "proof-verifier"))]
fn main() {
    eprintln!("verified_bridge_fixture_message requires the proof-verifier feature");
    std::process::exit(1);
}

#[cfg(feature = "proof-verifier")]
mod with_verifier {
    use std::{env, fs};

    use serde::{Deserialize, Serialize};
    use tzel_core::{ProgramHashes, ShieldReq, TransferReq, UnshieldReq, F};

    #[derive(Debug, Deserialize)]
    struct VerifiedBridgeFixture {
        #[serde(with = "tzel_core::hex_f")]
        auth_domain: F,
        program_hashes: ProgramHashes,
        bridge_ticketer: String,
        shield: ShieldReq,
        // Retained so the checked-in fixture JSON keeps deserializing; the
        // inline `transfer-raw` / `unshield-raw` emitters were retired (W5),
        // so these are no longer read.
        #[allow(dead_code)]
        transfer: TransferReq,
        #[allow(dead_code)]
        unshield: UnshieldReq,
    }

    #[derive(Debug, Serialize)]
    struct FixtureMetadata<'a> {
        auth_domain: String,
        shield_program_hash: String,
        transfer_program_hash: String,
        unshield_program_hash: String,
        bridge_ticketer: &'a str,
        shield_pool_recipient: String,
        shield_amount: u64,
        shield_total_debit: u64,
        shield_tree_size_after: u64,
    }

    fn usage() -> ! {
        eprintln!("usage:\n  verified_bridge_fixture_message metadata [fixture.json]");
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

    fn fixture_metadata(fixture: &VerifiedBridgeFixture) -> FixtureMetadata<'_> {
        FixtureMetadata {
            auth_domain: felt_hex(&fixture.auth_domain),
            shield_program_hash: felt_hex(&fixture.program_hashes.shield),
            transfer_program_hash: felt_hex(&fixture.program_hashes.transfer),
            unshield_program_hash: felt_hex(&fixture.program_hashes.unshield),
            bridge_ticketer: &fixture.bridge_ticketer,
            shield_pool_recipient: tzel_core::deposit_recipient_string(&fixture.shield.pubkey_hash),
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
            "shield-raw" | "transfer-raw" | "unshield-raw" => {
                // The v17 inline proof-bearing messages (Shield/Transfer/
                // Unshield) were retired with the W5 Groth16-only kernel.
                // STARK fixtures can no longer be replayed as inbox messages;
                // the live path is v18 SubmitOps (Groth16 wrap + staged
                // notes), produced by services/tzel/src/submit_v18.rs.
                eprintln!(
                    "{cmd}: retired — the inline STARK message path was removed (W5). \
                     Use the v18 SubmitOps producer instead."
                );
                std::process::exit(1);
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
