use std::env;

use hex::encode as hex_encode;
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{inbox::ExternalMessageFrame, smart_rollup::SmartRollupAddress};
use tzel_core::{
    auth_leaf_hash, derive_auth_pub_seed, hash,
    kernel_wire::{
        encode_kernel_inbox_message, sign_kernel_bridge_config, sign_kernel_verifier_config,
        KernelBridgeConfig, KernelDalChunkPointer, KernelDalPayloadKind, KernelDalPayloadPointer,
        KernelInboxMessage, KernelShieldReq, KernelStarkProof, KernelUnshieldReq,
        KernelVerifierConfig,
    },
    EncryptedNote, ProgramHashes, ENCRYPTED_NOTE_BYTES, F, ML_KEM768_CIPHERTEXT_BYTES,
    NOTE_AEAD_NONCE_BYTES, OUTGOING_RECOVERY_CT_BYTES,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  octez_kernel_message admin-material\n  octez_kernel_message configure-bridge <sr1...> <KT1...>\n  octez_kernel_message configure-verifier <sr1...> <auth_domain_hex> <shield_hash_hex> <transfer_hash_hex> <unshield_hash_hex>\n  octez_kernel_message raw-configure-bridge <KT1...>\n  octez_kernel_message raw-configure-verifier <auth_domain_hex> <shield_hash_hex> <transfer_hash_hex> <unshield_hash_hex>\n  octez_kernel_message raw-stub-shield\n  octez_kernel_message raw-stub-unshield\n  octez_kernel_message dal-pointer <sr1...> <configure-verifier|configure-bridge|shield|transfer|unshield> <payload_hash_hex> <payload_len> (<published_level> <slot_index> <chunk_len>)+"
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

fn parse_dal_kind(kind: &str) -> KernelDalPayloadKind {
    match kind {
        "configure-verifier" => KernelDalPayloadKind::ConfigureVerifier,
        "configure-bridge" => KernelDalPayloadKind::ConfigureBridge,
        "shield" => KernelDalPayloadKind::Shield,
        "transfer" => KernelDalPayloadKind::Transfer,
        "unshield" => KernelDalPayloadKind::Unshield,
        _ => usage(),
    }
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

/// A wire-valid `KernelInboxMessage::Shield` whose cryptographic content is
/// all zeros. It decodes successfully through `decode_kernel_inbox_message`
/// (the encrypted notes have the exact required lengths) but is
/// deterministically rejected by `apply_kernel_message` — on an unconfigured
/// rollup the first failure is "proof verifier is not configured".
///
/// Used by the orchestrator sandbox smoke to assert the kernel *dispatch*
/// path (internal `Transfer<MichelsonBytes>` → `decode_kernel_inbox_message`
/// → `apply_kernel_message`) without shipping a multi-megabyte real proof
/// through an L1 operation.
fn stub_encrypted_note() -> EncryptedNote {
    EncryptedNote {
        ct_d: vec![0u8; ML_KEM768_CIPHERTEXT_BYTES],
        tag: 0,
        ct_v: vec![0u8; ML_KEM768_CIPHERTEXT_BYTES],
        nonce: vec![0u8; NOTE_AEAD_NONCE_BYTES],
        encrypted_data: vec![0u8; ENCRYPTED_NOTE_BYTES],
        outgoing_ct: vec![0u8; OUTGOING_RECOVERY_CT_BYTES],
    }
}

fn stub_shield_message() -> KernelInboxMessage {
    let stub_note = stub_encrypted_note();
    KernelInboxMessage::Shield(KernelShieldReq {
        pubkey_hash: [0u8; 32],
        fee: 0,
        v: 0,
        producer_fee: 0,
        proof: KernelStarkProof {
            proof_bytes: vec![0u8; 32],
            output_preimage: Vec::new(),
        },
        client_cm: [0u8; 32],
        client_enc: stub_note.clone(),
        producer_cm: [0u8; 32],
        producer_enc: stub_note,
    })
}

/// A wire-valid `KernelInboxMessage::Unshield` with zeroed cryptographic
/// content and no change note. With a single mandatory encrypted note it is
/// the only user-facing TzEL request that fits under the L1 smart-rollup
/// inbox message size cap (4096 bytes) — Shield and Transfer carry two or
/// more notes and cannot fit. Like the stub shield, it decodes cleanly and
/// is deterministically rejected by `apply_kernel_message` with
/// "proof verifier is not configured" on an unconfigured rollup.
fn stub_unshield_message() -> KernelInboxMessage {
    KernelInboxMessage::Unshield(KernelUnshieldReq {
        root: [0u8; 32],
        nullifiers: vec![[0u8; 32]],
        v_pub: 0,
        fee: 0,
        recipient: "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb".to_string(),
        cm_change: [0u8; 32],
        enc_change: None,
        cm_fee: [0u8; 32],
        enc_fee: stub_encrypted_note(),
        proof: KernelStarkProof {
            proof_bytes: vec![0u8; 32],
            output_preimage: Vec::new(),
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
        "dal-pointer" => {
            let Some(rollup_address) = args.next() else {
                usage();
            };
            let Some(kind) = args.next() else {
                usage();
            };
            let Some(payload_hash_hex) = args.next() else {
                usage();
            };
            let Some(payload_len) = args.next() else {
                usage();
            };
            let kind = parse_dal_kind(&kind);
            let payload_hash = parse_felt(&payload_hash_hex);
            let payload_len = payload_len
                .parse::<u64>()
                .expect("payload_len should parse as u64");
            let mut chunks = Vec::new();
            loop {
                let Some(published_level) = args.next() else {
                    break;
                };
                let Some(slot_index) = args.next() else {
                    usage();
                };
                let Some(chunk_len) = args.next() else {
                    usage();
                };
                chunks.push(KernelDalChunkPointer {
                    published_level: published_level
                        .parse::<u64>()
                        .expect("published_level should parse as u64"),
                    slot_index: slot_index
                        .parse::<u8>()
                        .expect("slot_index should parse as u8"),
                    payload_len: chunk_len
                        .parse::<u64>()
                        .expect("chunk_len should parse as u64"),
                });
            }
            if chunks.is_empty() {
                usage();
            }
            emit_targeted_message(
                &rollup_address,
                &KernelInboxMessage::DalPointer(KernelDalPayloadPointer {
                    kind,
                    chunks,
                    payload_len,
                    payload_hash,
                }),
            );
        }
        _ => usage(),
    }
}
