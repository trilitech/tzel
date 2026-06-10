use std::env;

use hex::encode as hex_encode;
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{inbox::ExternalMessageFrame, smart_rollup::SmartRollupAddress};
use tzel_core::{
    auth_leaf_hash, derive_auth_pub_seed, hash,
    kernel_wire::{
        encode_kernel_inbox_message, sign_kernel_bridge_config, sign_kernel_verifier_config,
        KernelBridgeConfig, KernelInboxMessage, KernelLeafSlot, KernelOpDecl, KernelOpDeclBody,
        KernelStagedNoteRef, KernelSubmitOps, KernelTreeBinding, KernelVerifierConfig,
    },
    ProgramHashes, F,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  octez_kernel_message admin-material\n  octez_kernel_message configure-bridge <sr1...> <KT1...>\n  octez_kernel_message configure-verifier <sr1...> <auth_domain_hex> <shield_hash_hex> <transfer_hash_hex> <unshield_hash_hex>\n  octez_kernel_message raw-configure-bridge <KT1...>\n  octez_kernel_message raw-configure-verifier <auth_domain_hex> <shield_hash_hex> <transfer_hash_hex> <unshield_hash_hex>\n  octez_kernel_message raw-stub-shield\n  octez_kernel_message raw-stub-unshield"
    );
    std::process::exit(2);
}

fn parse_felt(hex: &str) -> F {
    let bytes = hex::decode(hex).expect("felt hex should decode");
    assert_eq!(bytes.len(), 32, "felt hex must be 32 bytes");
    let mut felt = [0u8; 32];
    felt.copy_from_slice(&bytes);
    felt
}

fn emit_targeted_message(rollup_address: &str, message: &KernelInboxMessage) {
    let address =
        SmartRollupAddress::from_b58check(rollup_address).expect("rollup address should be valid");
    let payload = encode_kernel_inbox_message(message).expect("kernel message should encode");
    let frame = ExternalMessageFrame::Targetted {
        address,
        contents: payload.as_slice(),
    };
    let mut framed = Vec::new();
    frame
        .bin_write(&mut framed)
        .expect("targeted frame should encode");
    println!("{}", hex_encode(framed));
}

fn config_admin_ask() -> F {
    if let Ok(hex) = env::var("TZEL_ROLLUP_CONFIG_ADMIN_ASK_HEX") {
        return parse_felt(&hex);
    }
    if cfg!(debug_assertions) {
        return hash(b"tzel-dev-rollup-config-admin");
    }
    panic!("set TZEL_ROLLUP_CONFIG_ADMIN_ASK_HEX to sign config messages");
}

fn signed_bridge_message(ticketer: String) -> KernelInboxMessage {
    let ask = config_admin_ask();
    KernelInboxMessage::ConfigureBridge(
        sign_kernel_bridge_config(&ask, KernelBridgeConfig { ticketer })
            .expect("bridge config should sign"),
    )
}

fn signed_verifier_message(
    auth_domain: String,
    shield: String,
    transfer: String,
    unshield: String,
) -> KernelInboxMessage {
    let ask = config_admin_ask();
    KernelInboxMessage::ConfigureVerifier(
        sign_kernel_verifier_config(
            &ask,
            KernelVerifierConfig {
                auth_domain: parse_felt(&auth_domain),
                verified_program_hashes: ProgramHashes {
                    shield: parse_felt(&shield),
                    transfer: parse_felt(&transfer),
                    unshield: parse_felt(&unshield),
                },
            },
        )
        .expect("verifier config should sign"),
    )
}

/// A wire-valid v18 `KernelInboxMessage::SubmitOps` (single shield op,
/// depth-1 binding tree) whose cryptographic content is all zeros. It decodes
/// successfully through `decode_kernel_inbox_message` and passes the
/// structural `validate_kernel_submit_ops`, but is deterministically rejected
/// by `apply_kernel_message` — its declared staged-note refs name no SEALED
/// staging entry, so `apply_submit_ops` fails before any proof check.
///
/// Used by the orchestrator sandbox smoke to assert the kernel *dispatch*
/// path (internal `Transfer<MichelsonBytes>` → `decode_kernel_inbox_message`
/// → `apply_kernel_message`) without shipping a real Groth16 proof + staged
/// notes through L1.
fn stub_submit_ops(op: KernelOpDecl) -> KernelInboxMessage {
    // Depth-1 binding: slot 0 = the declared op, slot 1 = a zeroed Opaque
    // padding leaf (all-zero lanes are valid M31 values).
    let binding = KernelTreeBinding {
        depth: 1,
        leaf_slots: vec![
            KernelLeafSlot::DeclaredOp(0),
            KernelLeafSlot::Opaque {
                root: [0u32; 8],
                outputs: [0u32; 8],
            },
        ],
    };
    KernelInboxMessage::SubmitOps(KernelSubmitOps {
        ops: vec![op],
        groth16_proof: b"kernel-test-skip-verify".to_vec(),
        tree_roots: [[0u8; 32]; 4],
        out_hash: [0u32; 8],
        binding,
    })
}

fn stub_shield_message() -> KernelInboxMessage {
    stub_submit_ops(KernelOpDecl {
        output_preimage: Vec::new(),
        // Shield expects two staged notes (client + producer); both reference
        // a never-sealed staging entry so the apply is rejected at note
        // resolution.
        staged_notes: vec![
            KernelStagedNoteRef {
                staging_id: 0,
                payload_hash: [0u8; 32],
            },
            KernelStagedNoteRef {
                staging_id: 0,
                payload_hash: [0u8; 32],
            },
        ],
        body: KernelOpDeclBody::Shield {
            pubkey_hash: [0u8; 32],
            fee: 0,
            v: 0,
            producer_fee: 0,
            client_cm: [0u8; 32],
            producer_cm: [0u8; 32],
        },
    })
}

/// A wire-valid v18 `SubmitOps` carrying a single unshield op (no change
/// note, one fee note). The smallest user-facing TzEL submission. Like the
/// stub shield it decodes cleanly, passes structural validation, and is
/// deterministically rejected by `apply_kernel_message` because its
/// staged-note ref names no sealed entry.
fn stub_unshield_message() -> KernelInboxMessage {
    stub_submit_ops(KernelOpDecl {
        output_preimage: Vec::new(),
        // Unshield with cm_change == 0 expects exactly one staged note (fee).
        staged_notes: vec![KernelStagedNoteRef {
            staging_id: 0,
            payload_hash: [0u8; 32],
        }],
        body: KernelOpDeclBody::Unshield {
            root: [0u8; 32],
            nullifiers: vec![[0u8; 32]],
            v_pub: 0,
            fee: 0,
            recipient: "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb".to_string(),
            cm_change: [0u8; 32],
            cm_fee: [0u8; 32],
        },
    })
}

fn emit_raw_message(message: &KernelInboxMessage) {
    let payload = encode_kernel_inbox_message(message).expect("kernel message should encode");
    println!("{}", hex_encode(payload));
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        usage();
    };

    match cmd.as_str() {
        "admin-material" => {
            if args.next().is_some() {
                usage();
            }
            let ask = config_admin_ask();
            let pub_seed = derive_auth_pub_seed(&ask);
            let verifier_leaf = auth_leaf_hash(
                &ask,
                tzel_core::kernel_wire::KERNEL_VERIFIER_CONFIG_KEY_INDEX,
            );
            let bridge_leaf =
                auth_leaf_hash(&ask, tzel_core::kernel_wire::KERNEL_BRIDGE_CONFIG_KEY_INDEX);
            println!(
                "TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX={}",
                hex_encode(pub_seed)
            );
            println!(
                "TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX={}",
                hex_encode(verifier_leaf)
            );
            println!(
                "TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX={}",
                hex_encode(bridge_leaf)
            );
        }
        "configure-bridge" => {
            let Some(rollup_address) = args.next() else {
                usage();
            };
            let Some(ticketer) = args.next() else {
                usage();
            };
            if args.next().is_some() {
                usage();
            }
            emit_targeted_message(&rollup_address, &signed_bridge_message(ticketer));
        }
        "configure-verifier" => {
            let Some(rollup_address) = args.next() else {
                usage();
            };
            let Some(auth_domain) = args.next() else {
                usage();
            };
            let Some(shield) = args.next() else {
                usage();
            };
            let Some(transfer) = args.next() else {
                usage();
            };
            let Some(unshield) = args.next() else {
                usage();
            };
            if args.next().is_some() {
                usage();
            }
            emit_targeted_message(
                &rollup_address,
                &signed_verifier_message(auth_domain, shield, transfer, unshield),
            );
        }
        "raw-configure-bridge" => {
            let Some(ticketer) = args.next() else {
                usage();
            };
            if args.next().is_some() {
                usage();
            }
            emit_raw_message(&signed_bridge_message(ticketer));
        }
        "raw-configure-verifier" => {
            let Some(auth_domain) = args.next() else {
                usage();
            };
            let Some(shield) = args.next() else {
                usage();
            };
            let Some(transfer) = args.next() else {
                usage();
            };
            let Some(unshield) = args.next() else {
                usage();
            };
            if args.next().is_some() {
                usage();
            }
            emit_raw_message(&signed_verifier_message(
                auth_domain, shield, transfer, unshield,
            ));
        }
        "raw-stub-shield" => {
            if args.next().is_some() {
                usage();
            }
            emit_raw_message(&stub_shield_message());
        }
        "raw-stub-unshield" => {
            if args.next().is_some() {
                usage();
            }
            emit_raw_message(&stub_unshield_message());
        }
        _ => usage(),
    }
}
