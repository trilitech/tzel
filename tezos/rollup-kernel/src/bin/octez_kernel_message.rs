use std::env;
use std::fs;

use hex::encode as hex_encode;
use serde::Deserialize;
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{inbox::ExternalMessageFrame, smart_rollup::SmartRollupAddress};
use tzel_core::{
    auth_leaf_hash, derive_auth_pub_seed, hash,
    kernel_wire::{
        encode_kernel_inbox_message, encode_staged_note_payload, sign_kernel_bridge_config,
        sign_kernel_verifier_config, KernelBridgeConfig, KernelInboxMessage, KernelLeafSlot,
        KernelOpDecl, KernelOpDeclBody, KernelStageChunk, KernelStagedConfigRef,
        KernelStagedNoteRef, KernelSubmitOps, KernelTreeBinding, KernelVerifierConfig,
        MAX_STAGE_CHUNK_BYTES,
    },
    EncryptedNote, Proof, ProgramHashes, ShieldReq, TransferReq, UnshieldReq, F,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  octez_kernel_message admin-material\n  octez_kernel_message configure-bridge <sr1...> <KT1...>\n  octez_kernel_message configure-verifier <sr1...> <auth_domain_hex> <shield_hash_hex> <transfer_hash_hex> <unshield_hash_hex>\n  octez_kernel_message raw-configure-bridge <KT1...>\n  octez_kernel_message raw-configure-verifier <auth_domain_hex> <shield_hash_hex> <transfer_hash_hex> <unshield_hash_hex>\n  octez_kernel_message raw-stub-shield\n  octez_kernel_message raw-stub-unshield\n  octez_kernel_message v18-stage-note <sr1...> <fixture.json> <shield|transfer|unshield> <slot> <staging_id> <chunk_count>\n  octez_kernel_message v18-submit-shield <sr1...> <fixture.json> <client_staging_id> <producer_staging_id>\n  octez_kernel_message v18-stage-config-verifier <sr1...> <fixture.json> <staging_id> <chunk_count>\n  octez_kernel_message v18-stage-config-bridge <sr1...> <fixture.json> <staging_id> <chunk_count>\n  octez_kernel_message v18-stage-raw <sr1...> <staging_id> <envelope_hex>\n  octez_kernel_message v18-payload-hash <hex>\n  octez_kernel_message v18-submit-staged-config <sr1...> <staging_id> <payload_hash_hex>"
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

// ── v18 sandbox E2E emitters (docs/SNARK-SUBMISSION-DESIGN.md) ───────
//
// These read the checked-in `verified_bridge_flow.json` fixture and emit the
// v18 DAL-free submission messages (`StageChunk`, `SubmitOps`,
// `SubmitStagedConfig`) as *external Targetted* frames for injection via
// `octez-client send smart rollup message`. They use the
// `kernel-test-skip-verify` Groth16 token, so the kernel WASM MUST be built
// with `TZEL_INSECURE_SANDBOX=1` (the token only fires under that cfg). The
// token bypasses ONLY the Groth16 tree walk + program-hash binding; the core
// output-binding (the op's `output_preimage` vs its declared public fields)
// STILL runs and is satisfied by the fixture's real `output_preimage`, so a
// successful apply is a genuine state transition, not a TrustMeBro free pass.

/// Subset of `verified_bridge_flow.json` needed by the v18 emitters. The
/// per-op `proof` carries the real `output_preimage` the core output-binding
/// checks against (the `proof_bytes` are discarded — the wrap is replaced by
/// the sandbox skip token).
#[derive(Debug, Deserialize)]
struct Fixture {
    #[serde(with = "tzel_core::hex_f")]
    auth_domain: F,
    program_hashes: ProgramHashes,
    bridge_ticketer: String,
    shield: ShieldReq,
    transfer: TransferReq,
    unshield: UnshieldReq,
}

fn load_fixture(path: &str) -> Fixture {
    let body = fs::read_to_string(path).expect("fixture file should be readable");
    serde_json::from_str(&body).expect("fixture json should parse")
}

fn op_output_preimage(proof: &Proof) -> Vec<F> {
    match proof {
        Proof::Stark {
            output_preimage, ..
        } => output_preimage.clone(),
        Proof::TrustMeBro => Vec::new(),
    }
}

/// Emit the StageChunk frame(s) carrying one fixture note across
/// `chunk_count` chunks, and print the staged-entry's `payload_hash` (hex) on
/// the LAST stdout line so the caller can build the matching staged-note ref.
/// One frame per stdout line (the leading lines are the chunks; the trailing
/// line is `payload_hash=<hex>`).
fn emit_stage_note_chunks(
    rollup_address: &str,
    staging_id: u64,
    chunk_count: u16,
    note: &EncryptedNote,
) {
    let payload = encode_staged_note_payload(note).expect("note payload should encode");
    let payload_hash = hash(&payload);
    emit_stage_chunks(rollup_address, staging_id, chunk_count, &payload, &payload_hash);
    println!("payload_hash={}", hex_encode(payload_hash));
}

/// Split `payload` into `chunk_count` near-equal slices and emit one Targetted
/// StageChunk frame per slice (each on its own stdout line). Every chunk must
/// be ≤ MAX_STAGE_CHUNK_BYTES and non-empty.
fn emit_stage_chunks(
    rollup_address: &str,
    staging_id: u64,
    chunk_count: u16,
    payload: &[u8],
    payload_hash: &F,
) {
    assert!(chunk_count >= 1, "chunk_count must be >= 1");
    let total = payload.len();
    assert!(total > 0, "cannot stage an empty payload");
    let n = chunk_count as usize;
    // ceil division so the last chunk holds the remainder (never empty as
    // long as total >= n; the caller picks chunk_count <= note length).
    let base = total.div_ceil(n);
    assert!(
        base <= MAX_STAGE_CHUNK_BYTES,
        "per-chunk size {} exceeds MAX_STAGE_CHUNK_BYTES {} (raise chunk_count)",
        base,
        MAX_STAGE_CHUNK_BYTES
    );
    for index in 0..n {
        let start = index * base;
        if start >= total {
            panic!("chunk_count {} too large for payload of {} bytes", n, total);
        }
        let end = ((index + 1) * base).min(total);
        let chunk = KernelStageChunk {
            staging_id,
            chunk_index: index as u16,
            chunk_count,
            payload_hash: *payload_hash,
            bytes: payload[start..end].to_vec(),
        };
        emit_targeted_message(rollup_address, &KernelInboxMessage::StageChunk(chunk));
    }
}

/// Build the depth-1 single-op `SubmitOps` binding the bridge_flow recipe
/// uses (`[DeclaredOp(0), Opaque]`) with the sandbox skip token.
fn single_op_submit(op: KernelOpDecl) -> KernelSubmitOps {
    KernelSubmitOps {
        ops: vec![op],
        groth16_proof: b"kernel-test-skip-verify".to_vec(),
        tree_roots: [[0u8; 32]; 4],
        out_hash: [0u32; 8],
        binding: KernelTreeBinding {
            depth: 1,
            leaf_slots: vec![
                KernelLeafSlot::DeclaredOp(0),
                KernelLeafSlot::Opaque {
                    root: [0u32; 8],
                    outputs: [0u32; 8],
                },
            ],
        },
    }
}

/// Resolve the `slot`-th encrypted note of the named fixture op.
/// shield: [client_enc, producer_enc]; transfer: [enc_1, enc_2, enc_3];
/// unshield: [enc_change?, enc_fee].
fn fixture_note<'a>(fixture: &'a Fixture, op: &str, slot: usize) -> &'a EncryptedNote {
    match (op, slot) {
        ("shield", 0) => &fixture.shield.client_enc,
        ("shield", 1) => &fixture.shield.producer_enc,
        ("transfer", 0) => &fixture.transfer.enc_1,
        ("transfer", 1) => &fixture.transfer.enc_2,
        ("transfer", 2) => &fixture.transfer.enc_3,
        ("unshield", 0) => fixture
            .unshield
            .enc_change
            .as_ref()
            .unwrap_or(&fixture.unshield.enc_fee),
        ("unshield", 1) => &fixture.unshield.enc_fee,
        _ => {
            eprintln!("no fixture note for op={op:?} slot={slot}");
            std::process::exit(2);
        }
    }
}

fn staged_ref(staging_id: u64, note: &EncryptedNote) -> KernelStagedNoteRef {
    let payload = encode_staged_note_payload(note).expect("note payload should encode");
    KernelStagedNoteRef {
        staging_id,
        payload_hash: hash(&payload),
    }
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
        // ── v18 sandbox E2E emitters ────────────────────────────────
        // v18-stage-note <sr1...> <fixture.json> <op> <slot> <staging_id> <chunk_count>
        //   op ∈ {shield,transfer,unshield}; slot picks which note of that op.
        //   Prints N StageChunk frames (one per line) + a final
        //   `payload_hash=<hex>` line.
        "v18-stage-note" => {
            let rollup_address = args.next().unwrap_or_else(|| usage());
            let fixture_path = args.next().unwrap_or_else(|| usage());
            let op = args.next().unwrap_or_else(|| usage());
            let slot: usize = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            let staging_id: u64 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            let chunk_count: u16 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let fixture = load_fixture(&fixture_path);
            let note = fixture_note(&fixture, &op, slot);
            emit_stage_note_chunks(&rollup_address, staging_id, chunk_count, note);
        }
        // v18-submit-shield <sr1...> <fixture.json> <client_staging_id> <producer_staging_id>
        //   Emit a Targetted single-op SubmitOps shielding the fixture shield,
        //   referencing the two pre-staged notes.
        "v18-submit-shield" => {
            let rollup_address = args.next().unwrap_or_else(|| usage());
            let fixture_path = args.next().unwrap_or_else(|| usage());
            let client_id: u64 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            let producer_id: u64 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let fixture = load_fixture(&fixture_path);
            let s = &fixture.shield;
            let op = KernelOpDecl {
                output_preimage: op_output_preimage(&s.proof),
                staged_notes: vec![
                    staged_ref(client_id, &s.client_enc),
                    staged_ref(producer_id, &s.producer_enc),
                ],
                body: KernelOpDeclBody::Shield {
                    pubkey_hash: s.pubkey_hash,
                    fee: s.fee,
                    v: s.v,
                    producer_fee: s.producer_fee,
                    client_cm: s.client_cm,
                    producer_cm: s.producer_cm,
                },
            };
            emit_targeted_message(
                &rollup_address,
                &KernelInboxMessage::SubmitOps(single_op_submit(op)),
            );
        }
        // v18-stage-config-verifier <sr1...> <fixture.json> <staging_id> <chunk_count>
        //   Stage a signed ConfigureVerifier *envelope* (the v17 inline
        //   payload) across N chunks for the gap-#1 SubmitStagedConfig path.
        //   Prints N StageChunk frames + a final `payload_hash=<hex>` line.
        "v18-stage-config-verifier" => {
            let rollup_address = args.next().unwrap_or_else(|| usage());
            let fixture_path = args.next().unwrap_or_else(|| usage());
            let staging_id: u64 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            let chunk_count: u16 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let fixture = load_fixture(&fixture_path);
            let envelope = encode_kernel_inbox_message(&signed_verifier_message(
                hex_encode(fixture.auth_domain),
                hex_encode(fixture.program_hashes.shield),
                hex_encode(fixture.program_hashes.transfer),
                hex_encode(fixture.program_hashes.unshield),
            ))
            .expect("verifier config envelope should encode");
            let payload_hash = hash(&envelope);
            emit_stage_chunks(
                &rollup_address,
                staging_id,
                chunk_count,
                &envelope,
                &payload_hash,
            );
            println!("payload_hash={}", hex_encode(payload_hash));
        }
        // v18-stage-config-bridge <sr1...> <fixture.json> <staging_id> <chunk_count>
        "v18-stage-config-bridge" => {
            let rollup_address = args.next().unwrap_or_else(|| usage());
            let fixture_path = args.next().unwrap_or_else(|| usage());
            let staging_id: u64 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            let chunk_count: u16 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let fixture = load_fixture(&fixture_path);
            let envelope =
                encode_kernel_inbox_message(&signed_bridge_message(fixture.bridge_ticketer))
                    .expect("bridge config envelope should encode");
            let payload_hash = hash(&envelope);
            emit_stage_chunks(
                &rollup_address,
                staging_id,
                chunk_count,
                &envelope,
                &payload_hash,
            );
            println!("payload_hash={}", hex_encode(payload_hash));
        }
        // v18-stage-raw <sr1...> <staging_id> <envelope_hex>
        //   Stage an arbitrary already-encoded kernel envelope (hex) across as
        //   few chunks as fit under MAX_STAGE_CHUNK_BYTES. Prints the chunk
        //   frames + a final `payload_hash=<hex>` line. Used to stage a signed
        //   ConfigureBridge envelope naming the live sandbox ticketer.
        "v18-stage-raw" => {
            let rollup_address = args.next().unwrap_or_else(|| usage());
            let staging_id: u64 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            let envelope_hex = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let envelope = hex::decode(&envelope_hex).expect("envelope hex should decode");
            let payload_hash = hash(&envelope);
            let chunk_count =
                envelope.len().div_ceil(MAX_STAGE_CHUNK_BYTES).max(1) as u16;
            emit_stage_chunks(
                &rollup_address,
                staging_id,
                chunk_count,
                &envelope,
                &payload_hash,
            );
            println!("payload_hash={}", hex_encode(payload_hash));
        }
        // v18-fixture-meta <fixture.json> — print the deposit/shield metadata
        //   the sandbox harness needs, one value per line:
        //     shield_pool_recipient
        //     shield_total_debit (v + fee + producer_fee)
        //     bridge_ticketer
        //     shield_tree_size_after (= 2, the two shield commitments)
        //   (Replaces verified_bridge_fixture_message, which needs the heavy
        //   proof-verifier feature; this bin builds without it.)
        "v18-fixture-meta" => {
            let fixture_path = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let fixture = load_fixture(&fixture_path);
            let s = &fixture.shield;
            println!(
                "{}",
                tzel_core::deposit_recipient_string(&s.pubkey_hash)
            );
            println!("{}", s.v + s.fee + s.producer_fee);
            println!("{}", fixture.bridge_ticketer);
            println!("2");
        }
        // v18-payload-hash <hex> — blake2s of the given bytes (staging hash).
        "v18-payload-hash" => {
            let bytes_hex = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let bytes = hex::decode(&bytes_hex).expect("hex should decode");
            println!("{}", hex_encode(hash(&bytes)));
        }
        // v18-submit-staged-config <sr1...> <staging_id> <payload_hash_hex>
        "v18-submit-staged-config" => {
            let rollup_address = args.next().unwrap_or_else(|| usage());
            let staging_id: u64 = args
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage());
            let payload_hash_hex = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let reff = KernelStagedConfigRef {
                staging_id,
                payload_hash: parse_felt(&payload_hash_hex),
            };
            emit_targeted_message(
                &rollup_address,
                &KernelInboxMessage::SubmitStagedConfig(reff),
            );
        }
        _ => usage(),
    }
}
