use std::env;

use hex::encode as hex_encode;
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{inbox::ExternalMessageFrame, smart_rollup::SmartRollupAddress};
use tzel_core::{
    kernel_wire::{
        encode_kernel_inbox_message, KernelBridgeConfig, KernelDalChunkPointer,
        KernelDalPayloadKind, KernelDalPayloadPointer, KernelInboxMessage, KernelVerifierConfig,
    },
    ProgramHashes, F,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  octez_kernel_message configure-bridge <sr1...> <KT1...>\n  octez_kernel_message configure-verifier <sr1...> <auth_domain_hex> <shield_hash_hex> <transfer_hash_hex> <unshield_hash_hex>\n  octez_kernel_message dal-pointer <sr1...> <shield|transfer|unshield> <payload_hash_hex> <payload_len> (<published_level> <slot_index> <chunk_len>)+"
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

fn parse_dal_kind(kind: &str) -> KernelDalPayloadKind {
    match kind {
        "shield" => KernelDalPayloadKind::Shield,
        "transfer" => KernelDalPayloadKind::Transfer,
        "unshield" => KernelDalPayloadKind::Unshield,
        _ => usage(),
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        usage();
    };

    match cmd.as_str() {
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
            emit_targeted_message(
                &rollup_address,
                &KernelInboxMessage::ConfigureBridge(KernelBridgeConfig { ticketer }),
            );
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
                &KernelInboxMessage::ConfigureVerifier(KernelVerifierConfig {
                    auth_domain: parse_felt(&auth_domain),
                    verified_program_hashes: ProgramHashes {
                        shield: parse_felt(&shield),
                        transfer: parse_felt(&transfer),
                        unshield: parse_felt(&unshield),
                    },
                }),
            );
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
