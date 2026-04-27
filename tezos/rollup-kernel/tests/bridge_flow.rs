use std::collections::{HashMap, VecDeque};

#[cfg(feature = "proof-verifier")]
use std::sync::OnceLock;

#[cfg(feature = "proof-verifier")]
use serde::Deserialize;
use tezos_data_encoding_05::{enc::BinWriter as _, nom::NomReader as _};
use tezos_smart_rollup_encoding::{
    contract::Contract as TezosContract,
    inbox::{
        ExternalMessageFrame, InboxMessage as TezosInboxMessage,
        InternalInboxMessage as TezosInternalInboxMessage, Transfer as TezosTransfer,
    },
    michelson::{
        ticket::FA2_1Ticket, MichelsonBytes, MichelsonContract, MichelsonInt, MichelsonOption,
        MichelsonPair, MichelsonUnit,
    },
    outbox::OutboxMessage as TezosOutboxMessage,
    public_key_hash::PublicKeyHash,
    smart_rollup::SmartRollupAddress,
};
use tzel_core::kernel_wire::{
    encode_kernel_inbox_message, sign_kernel_bridge_config, sign_kernel_verifier_config,
    KernelBridgeConfig, KernelDalChunkPointer, KernelDalPayloadKind, KernelDalPayloadPointer,
    KernelInboxMessage, KernelResult, KernelVerifierConfig,
};
#[cfg(feature = "proof-verifier")]
use tzel_core::kernel_wire::{
    KernelShieldReq, KernelStarkProof, KernelTransferReq, KernelUnshieldReq,
};
use tzel_core::{default_auth_domain, deposit_recipient_string, hash, ProgramHashes, F, ZERO};

/// Test-only deterministic pubkey_hash derived from a label. The real
/// pubkey_hash is `H(0x04, auth_domain, auth_root, auth_pub_seed,
/// blind)`; these tests only exercise the bridge-receiver parsing and
/// pool-balance accounting, so an opaque label-derived F suffices.
fn pubkey_hash_from_label(label: &str) -> F {
    hash(label.as_bytes())
}
#[cfg(feature = "proof-verifier")]
use tzel_core::{Proof, ShieldReq, TransferReq, UnshieldReq};
use tzel_rollup_kernel::{
    read_last_input, read_last_result, read_ledger, read_stats, run_with_host, DalParameters, Host,
    InputMessage, MAX_INPUT_BYTES,
};

const PATH_BRIDGE_TICKETER: &[u8] = b"/tzel/v1/state/bridge/ticketer";
const PATH_WITHDRAWAL_PREFIX: &[u8] = b"/tzel/v1/state/withdrawals/index/";

#[derive(Clone, Default)]
struct TestHost {
    inputs: VecDeque<InputMessage>,
    store: HashMap<Vec<u8>, Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    debug: String,
    dal_parameters: Option<DalParameters>,
    dal_pages: HashMap<(i32, u8, u16), Vec<u8>>,
}

impl TestHost {
    fn from_store(store: HashMap<Vec<u8>, Vec<u8>>) -> Self {
        Self {
            store,
            ..Self::default()
        }
    }

    fn push_input(&mut self, level: i32, id: i32, payload: Vec<u8>) {
        self.inputs.push_back(InputMessage { level, id, payload });
    }
}

impl Host for TestHost {
    fn next_input(&mut self) -> Option<InputMessage> {
        self.inputs.pop_front()
    }

    fn read_store(&self, path: &[u8], max_bytes: usize) -> Option<Vec<u8>> {
        let value = self.store.get(path)?;
        Some(value[..value.len().min(max_bytes)].to_vec())
    }

    fn write_store(&mut self, path: &[u8], value: &[u8]) {
        self.store.insert(path.to_vec(), value.to_vec());
    }

    fn write_output(&mut self, value: &[u8]) -> Result<(), String> {
        self.outputs.push(value.to_vec());
        Ok(())
    }

    fn write_debug(&mut self, message: &str) {
        self.debug.push_str(message);
    }

    fn rollup_address(&self) -> Vec<u8> {
        sample_rollup_address().hash().as_ref().clone()
    }

    fn reveal_dal_parameters(&self) -> Result<DalParameters, String> {
        self.dal_parameters
            .clone()
            .ok_or_else(|| "DAL is not configured in bridge_flow test host".into())
    }

    fn reveal_dal_page(
        &self,
        published_level: i32,
        slot_index: u8,
        page_index: u16,
        max_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        Ok(self
            .dal_pages
            .get(&(published_level, slot_index, page_index))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(max_bytes)
            .collect())
    }
}

fn sample_config_admin_ask() -> F {
    hash(b"tzel-dev-rollup-config-admin")
}

fn signed_bridge_message(config: KernelBridgeConfig) -> KernelInboxMessage {
    KernelInboxMessage::ConfigureBridge(
        sign_kernel_bridge_config(&sample_config_admin_ask(), config).unwrap(),
    )
}

fn install_test_dal_payload(
    host: &mut TestHost,
    published_level: i32,
    slot_index: u8,
    page_size: usize,
    slot_size: usize,
    payload: &[u8],
) -> KernelDalChunkPointer {
    assert!(page_size > 0);
    assert!(slot_size > 0);
    host.dal_parameters = Some(DalParameters {
        number_of_slots: u64::from(slot_index) + 1,
        attestation_lag: 8,
        slot_size: slot_size as u64,
        page_size: page_size as u64,
    });
    let chunk_len = payload.len().min(slot_size);
    let chunk = &payload[..chunk_len];
    let page_count = chunk_len.div_ceil(page_size);
    for page_index in 0..page_count {
        let start = page_index * page_size;
        let end = (start + page_size).min(chunk_len);
        let mut page = vec![0u8; page_size];
        page[..end - start].copy_from_slice(&chunk[start..end]);
        host.dal_pages.insert(
            (
                published_level,
                slot_index,
                u16::try_from(page_index).expect("page index fits"),
            ),
            page,
        );
    }
    KernelDalChunkPointer {
        published_level: u64::try_from(published_level)
            .expect("published level must be non-negative"),
        slot_index,
        payload_len: chunk_len as u64,
    }
}

fn signed_verifier_message(config: KernelVerifierConfig) -> KernelInboxMessage {
    KernelInboxMessage::ConfigureVerifier(
        sign_kernel_verifier_config(&sample_config_admin_ask(), config).unwrap(),
    )
}

fn sample_program_hashes() -> ProgramHashes {
    ProgramHashes {
        shield: hash(b"tzel-test-shield"),
        transfer: hash(b"tzel-test-transfer"),
        unshield: hash(b"tzel-test-unshield"),
    }
}

fn default_verifier_config() -> KernelVerifierConfig {
    KernelVerifierConfig {
        auth_domain: default_auth_domain(),
        verified_program_hashes: sample_program_hashes(),
        operator_producer_owner_tag: ZERO,
    }
}

#[test]
fn bridge_configuration_can_be_delivered_via_dal_pointer() {
    let mut host = TestHost::default();
    let payload = encode_kernel_inbox_message(&signed_bridge_message(KernelBridgeConfig {
        ticketer: sample_ticketer().into(),
    }))
    .unwrap();
    let pointer = KernelDalPayloadPointer {
        kind: KernelDalPayloadKind::ConfigureBridge,
        chunks: vec![install_test_dal_payload(
            &mut host, 101, 0, 64, 8192, &payload,
        )],
        payload_len: payload.len() as u64,
        payload_hash: hash(&payload),
    };
    host.push_input(
        0,
        0,
        encode_external_kernel_message(KernelInboxMessage::DalPointer(pointer)),
    );

    run_with_host(&mut host);

    assert_eq!(
        host.read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .expect("ticketer stored"),
        sample_ticketer().as_bytes()
    );
    assert!(matches!(
        read_last_result(&host).unwrap(),
        KernelResult::Configured
    ));
}

#[test]
fn bridge_deposit_requires_configuration_and_recovers_after_external_configuration() {
    let mut host = TestHost::default();
    // Synthetic pubkey_hash stand-in. The real pubkey_hash is derived
    // from the wallet's auth tree + a deterministic blind; this test
    // only exercises the bridge balance-keying check, not shield.
    let deposit_key = deposit_recipient_string(&pubkey_hash_from_label("alice"));
    let deposit = encode_ticket_deposit_message(&deposit_key, 12);
    host.push_input(0, 0, deposit.clone());

    run_with_host(&mut host);

    match read_last_result(&host).unwrap() {
        KernelResult::Error { message } => {
            assert!(message.contains("bridge ticketer is not configured"))
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }

    // Verifier must be configured before bridge deposits are accepted —
    // the kernel's pubkey_hash check folds in the kernel's frozen
    // `auth_domain`.
    host.push_input(
        1,
        0,
        encode_external_kernel_message(signed_verifier_message(default_verifier_config())),
    );
    host.push_input(
        2,
        0,
        encode_external_kernel_message(signed_bridge_message(KernelBridgeConfig {
            ticketer: sample_ticketer().into(),
        })),
    );
    host.push_input(3, 0, deposit);

    run_with_host(&mut host);

    let stats = read_stats(&host);
    assert_eq!(stats.raw_input_count, 4);
    // Probe the durable balance entry directly: read_ledger does not
    // enumerate deposit balances (no index by design — bounded storage).
    let pubkey_hash = pubkey_hash_from_label("alice");
    let mut balance_path = b"/tzel/v1/state/deposits/balance/".to_vec();
    balance_path.extend_from_slice(hex::encode(pubkey_hash).as_bytes());
    let bytes = host.read_store(&balance_path, 8).expect("balance entry");
    assert_eq!(u64::from_le_bytes(bytes.try_into().unwrap()), 12);
    let _ = deposit_key;
    assert!(matches!(
        read_last_result(&host).unwrap(),
        KernelResult::Deposit
    ));
}

#[test]
fn bridge_deposit_rejects_non_pubkey_hash_receiver() {
    let mut host = TestHost::default();
    host.push_input(
        0,
        0,
        encode_external_kernel_message(signed_verifier_message(default_verifier_config())),
    );
    host.push_input(
        1,
        0,
        encode_external_kernel_message(signed_bridge_message(KernelBridgeConfig {
            ticketer: sample_ticketer().into(),
        })),
    );
    host.push_input(2, 0, encode_ticket_deposit_message("alice", 12));

    run_with_host(&mut host);

    match read_last_result(&host).unwrap() {
        KernelResult::Error { message } => {
            assert!(
                message.contains("deposit receiver must be"),
                "unexpected error: {message}"
            );
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }
}

#[test]
fn bridge_deposit_rejects_non_canonical_pubkey_hash_receiver() {
    let mut host = TestHost::default();
    let deposit_key = deposit_recipient_string(&pubkey_hash_from_label("alice"));
    let (_, hex_id) = deposit_key.split_once(':').unwrap();
    let non_canonical_key = format!("deposit:{}", hex_id.to_uppercase());
    assert_ne!(deposit_key, non_canonical_key);

    host.push_input(
        0,
        0,
        encode_external_kernel_message(signed_verifier_message(default_verifier_config())),
    );
    host.push_input(
        1,
        0,
        encode_external_kernel_message(signed_bridge_message(KernelBridgeConfig {
            ticketer: sample_ticketer().into(),
        })),
    );
    host.push_input(2, 0, encode_ticket_deposit_message(&non_canonical_key, 12));

    run_with_host(&mut host);

    match read_last_result(&host).unwrap() {
        KernelResult::Error { message } => {
            assert!(
                message.contains("deposit receiver must be"),
                "unexpected error: {message}"
            );
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_bridge_roundtrip_uses_checked_in_real_proofs() {
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);

    assert!(matches!(
        read_last_result(&host).unwrap(),
        KernelResult::Configured
    ));
    assert_eq!(read_ledger(&host).unwrap().auth_domain, fixture.auth_domain);
    assert_eq!(
        host.read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .expect("ticketer stored"),
        fixture.bridge_ticketer.as_bytes()
    );

    apply_fixture_deposit(&mut host, fixture, 2);

    assert!(matches!(
        read_last_result(&host).unwrap(),
        KernelResult::Deposit
    ));
    let balance_path = tzel_rollup_kernel::deposit_balance_path(&fixture.shield.pubkey_hash);
    assert_eq!(
        host.read_store(&balance_path, 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap())),
        Some(fixture.shield.v + fixture.shield.fee + fixture.shield.producer_fee)
    );

    apply_fixture_shield(&mut host, fixture, 3);

    match read_last_result(&host).unwrap() {
        KernelResult::Shield(resp) => {
            assert_eq!(resp.index, 0);
            assert_eq!(resp.cm, fixture.shield.client_cm);
            assert_eq!(resp.producer_index, 1);
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }
    // Pool drained: kernel writes empty bytes (best-effort delete) when
    // the residual balance is zero.
    assert!(host.read_store(&balance_path, 8).map_or(true, |b| b.is_empty()));
    let ledger = read_ledger(&host).unwrap();
    assert_eq!(
        ledger.tree.leaves,
        vec![fixture.shield.client_cm, fixture.shield.producer_cm]
    );

    apply_fixture_transfer(&mut host, fixture, 4);

    match read_last_result(&host).unwrap() {
        KernelResult::Transfer(resp) => {
            assert_eq!((resp.index_1, resp.index_2, resp.index_3), (2, 3, 4))
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }
    let ledger = read_ledger(&host).unwrap();
    assert_eq!(
        ledger.tree.leaves,
        vec![
            fixture.shield.client_cm,
            fixture.shield.producer_cm,
            fixture.transfer.cm_1,
            fixture.transfer.cm_2,
            fixture.transfer.cm_3,
        ]
    );
    assert_eq!(ledger.nullifiers.len(), 1);
    assert!(ledger.nullifiers.contains(&fixture.transfer.nullifiers[0]));

    let mut restarted = TestHost::from_store(host.store.clone());
    apply_fixture_unshield(&mut restarted, fixture, 5);

    match read_last_result(&restarted).unwrap() {
        KernelResult::Unshield(resp) => {
            assert_eq!(resp.change_index, None);
            assert_eq!(resp.producer_index, 5);
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }
    let ledger = read_ledger(&restarted).unwrap();
    assert_eq!(ledger.nullifiers.len(), 2);
    assert!(ledger.nullifiers.contains(&fixture.transfer.nullifiers[0]));
    assert!(ledger.nullifiers.contains(&fixture.unshield.nullifiers[0]));
    assert_eq!(ledger.withdrawals.len(), 1);
    assert_eq!(ledger.withdrawals[0].recipient, fixture.unshield.recipient);
    assert_eq!(ledger.withdrawals[0].amount, fixture.unshield.v_pub);
    assert_eq!(restarted.outputs.len(), 1);
    assert_outbox_withdrawal(
        &restarted.outputs[0],
        fixture.bridge_ticketer.as_str(),
        fixture.unshield.recipient.as_str(),
        fixture.unshield.v_pub,
    );
    let stats = read_stats(&restarted);
    assert_eq!(stats.raw_input_count, 6);
    assert_eq!(stats.last_input_level, Some(5));
    assert_eq!(
        read_last_input(&restarted)
            .expect("last input persisted")
            .level,
        5
    );
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_unshield_survives_restart_and_persists_withdrawal_record() {
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);
    apply_fixture_deposit(&mut host, fixture, 2);
    apply_fixture_shield(&mut host, fixture, 3);
    apply_fixture_transfer(&mut host, fixture, 4);

    let mut restarted = TestHost::from_store(host.store.clone());
    apply_fixture_unshield(&mut restarted, fixture, 5);

    let ledger = read_ledger(&restarted).unwrap();
    assert_eq!(ledger.withdrawals.len(), 1);
    assert_eq!(ledger.withdrawals[0].recipient, fixture.unshield.recipient);
    assert_eq!(ledger.withdrawals[0].amount, fixture.unshield.v_pub);
    assert!(restarted
        .store
        .contains_key(&indexed_path(PATH_WITHDRAWAL_PREFIX, 0)));
    assert_eq!(restarted.outputs.len(), 1);
    assert_outbox_withdrawal(
        &restarted.outputs[0],
        fixture.bridge_ticketer.as_str(),
        fixture.unshield.recipient.as_str(),
        fixture.unshield.v_pub,
    );
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_bridge_can_be_configured_via_dal_pointers() {
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge_via_dal(&mut host, fixture);

    assert!(matches!(
        read_last_result(&host).unwrap(),
        KernelResult::Configured
    ));
    assert_eq!(read_ledger(&host).unwrap().auth_domain, fixture.auth_domain);
    assert_eq!(
        host.read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .expect("ticketer stored"),
        fixture.bridge_ticketer.as_bytes()
    );

    apply_fixture_deposit(&mut host, fixture, 2);
    apply_fixture_shield(&mut host, fixture, 3);

    match read_last_result(&host).unwrap() {
        KernelResult::Shield(resp) => {
            assert_eq!(resp.index, 0);
            assert_eq!(resp.producer_index, 1);
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_bridge_rejects_transfer_when_program_hashes_do_not_match_fixture() {
    let fixture = verified_bridge_fixture();
    let mut bad_hashes = fixture.program_hashes.clone();
    bad_hashes.transfer[0] ^= 0x01;

    let mut host = TestHost::default();
    configure_verified_bridge_with_hashes(&mut host, fixture, bad_hashes);
    apply_fixture_deposit(&mut host, fixture, 2);
    apply_fixture_shield(&mut host, fixture, 3);

    let before_transfer = read_ledger(&host).unwrap();
    host.push_input(
        4,
        0,
        encode_external_kernel_message(KernelInboxMessage::Transfer(
            kernel_transfer_req_from_fixture(&fixture.transfer),
        )),
    );
    run_with_host(&mut host);

    match read_last_result(&host).unwrap() {
        KernelResult::Error { message } => {
            assert!(
                message.contains("invalid output_preimage for transfer circuit")
                    || message.contains("unexpected circuit program hash"),
                "unexpected verifier error: {}",
                message
            );
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }

    assert_ledger_state_unchanged(&before_transfer, &read_ledger(&host).unwrap());
    assert!(host.outputs.is_empty());
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_shield_rejects_tampered_client_note_without_mutating_pool() {
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);
    apply_fixture_deposit(&mut host, fixture, 2);

    let before_shield = read_ledger(&host).unwrap();
    let balance_path = tzel_rollup_kernel::deposit_balance_path(&fixture.shield.pubkey_hash);
    let pool_balance_before = host
        .read_store(&balance_path, 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    let mut req = fixture.shield.clone();
    req.client_enc.encrypted_data[0] ^= 0x01;
    host.push_input(
        3,
        0,
        encode_external_kernel_message(KernelInboxMessage::Shield(kernel_shield_req_from_fixture(
            &req,
        ))),
    );
    run_with_host(&mut host);

    match read_last_result(&host).unwrap() {
        KernelResult::Error { message } => {
            assert!(message.contains("proof memo_ct_hash mismatch"));
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }

    assert_ledger_state_unchanged(&before_shield, &read_ledger(&host).unwrap());
    let pool_balance_after = host
        .read_store(&balance_path, 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    assert_eq!(pool_balance_before, pool_balance_after);
    assert!(host.outputs.is_empty());
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_transfer_rejects_tampered_output_note_without_mutating_state() {
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);
    apply_fixture_deposit(&mut host, fixture, 2);
    apply_fixture_shield(&mut host, fixture, 3);

    let before_transfer = read_ledger(&host).unwrap();
    let mut req = fixture.transfer.clone();
    req.enc_2.encrypted_data[0] ^= 0x01;
    host.push_input(
        4,
        0,
        encode_external_kernel_message(KernelInboxMessage::Transfer(
            kernel_transfer_req_from_fixture(&req),
        )),
    );
    run_with_host(&mut host);

    match read_last_result(&host).unwrap() {
        KernelResult::Error { message } => {
            assert!(message.contains("proof memo_ct_hash_2 mismatch"));
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }

    assert_ledger_state_unchanged(&before_transfer, &read_ledger(&host).unwrap());
    assert!(host.outputs.is_empty());
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_transfer_consumes_one_note_and_creates_change_and_recipient_notes() {
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);
    apply_fixture_deposit(&mut host, fixture, 2);
    apply_fixture_shield(&mut host, fixture, 3);

    let before_transfer = read_ledger(&host).unwrap();
    apply_fixture_transfer(&mut host, fixture, 4);

    match read_last_result(&host).unwrap() {
        KernelResult::Transfer(resp) => {
            assert_eq!((resp.index_1, resp.index_2, resp.index_3), (2, 3, 4))
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }

    let after_transfer = read_ledger(&host).unwrap();
    assert_eq!(after_transfer.withdrawals, before_transfer.withdrawals);
    assert_eq!(
        after_transfer.tree.leaves.len(),
        before_transfer.tree.leaves.len() + 3
    );
    assert_eq!(
        after_transfer.nullifiers.len(),
        before_transfer.nullifiers.len() + 1
    );
    assert_eq!(
        after_transfer.tree.leaves,
        vec![
            fixture.shield.client_cm,
            fixture.shield.producer_cm,
            fixture.transfer.cm_1,
            fixture.transfer.cm_2,
            fixture.transfer.cm_3,
        ]
    );
    assert!(after_transfer
        .nullifiers
        .contains(&fixture.transfer.nullifiers[0]));
    assert!(host.outputs.is_empty());
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_unshield_rejects_tampered_recipient_without_mutating_state() {
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);
    apply_fixture_deposit(&mut host, fixture, 2);
    apply_fixture_shield(&mut host, fixture, 3);
    apply_fixture_transfer(&mut host, fixture, 4);

    let before_unshield = read_ledger(&host).unwrap();
    let mut req = fixture.unshield.clone();
    req.recipient = sample_other_l1_receiver().into();
    host.push_input(
        5,
        0,
        encode_external_kernel_message(KernelInboxMessage::Unshield(
            kernel_unshield_req_from_fixture(&req),
        )),
    );
    run_with_host(&mut host);

    match read_last_result(&host).unwrap() {
        KernelResult::Error { message } => {
            assert!(message.contains("proof recipient mismatch"));
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }

    assert_ledger_state_unchanged(&before_unshield, &read_ledger(&host).unwrap());
    assert!(host.outputs.is_empty());
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_shield_rejects_replay_after_pool_topup() {
    // Replay attack: an attacker observes a valid shield proof, waits
    // for the pool to be topped up by anyone (mirror deposits are
    // donations under the deposit-pool design), then resubmits the
    // same shield. The kernel MUST reject the replay so the recipient
    // doesn't receive a duplicate of their original shield note. (The
    // duplicate would otherwise be independently spendable since the
    // nullifier is per-tree-position, doubling the user's shielded
    // balance at the dust-attacker's expense.)
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);
    apply_fixture_deposit(&mut host, fixture, 2);
    apply_fixture_shield(&mut host, fixture, 3);

    // After the legitimate shield, the pool is fully drained; tree has
    // the recipient + producer notes from this shield.
    let after_shield = read_ledger(&host).unwrap();
    assert_eq!(after_shield.tree.leaves.len(), 2);

    // Top up the pool by exactly the same debit the original shield
    // consumed (mirror deposit — anyone can fund anyone's pool).
    apply_fixture_deposit(&mut host, fixture, 4);

    // Replay the shield. The kernel should reject it; the tree must
    // not grow to 4 leaves and the pool must not be drained again.
    apply_fixture_shield(&mut host, fixture, 5);

    match read_last_result(&host).unwrap() {
        KernelResult::Error { message } => {
            assert!(
                message.contains("shield replay")
                    || message.contains("already applied")
                    || message.contains("commitment already")
                    || message.contains("duplicate"),
                "expected replay rejection, got: {}",
                message
            );
        }
        other => panic!("replay must be rejected, got: {:?}", other),
    }

    let after_replay = read_ledger(&host).unwrap();
    assert_eq!(
        after_replay.tree.leaves.len(),
        after_shield.tree.leaves.len(),
        "replay must not append duplicate notes to the tree"
    );
    let balance_path = tzel_rollup_kernel::deposit_balance_path(&fixture.shield.pubkey_hash);
    let pool_balance = host
        .read_store(&balance_path, 8)
        .map(|b| {
            if b.is_empty() {
                0u64
            } else {
                u64::from_le_bytes(b.try_into().unwrap())
            }
        })
        .unwrap_or(0);
    let topup = fixture.shield.v + fixture.shield.fee + fixture.shield.producer_fee;
    assert_eq!(
        pool_balance, topup,
        "rejected replay must leave the topup intact in the pool"
    );
}

fn encode_external_kernel_message(message: KernelInboxMessage) -> Vec<u8> {
    let payload = encode_kernel_inbox_message(&message).unwrap();
    let mut framed = Vec::new();
    ExternalMessageFrame::Targetted {
        address: sample_rollup_address(),
        contents: payload.as_slice(),
    }
    .bin_write(&mut framed)
    .unwrap();
    let mut bytes = Vec::new();
    TezosInboxMessage::<MichelsonUnit>::External(framed.as_slice())
        .serialize(&mut bytes)
        .unwrap();
    bytes
}

fn encode_ticket_deposit_message(recipient: &str, amount: u64) -> Vec<u8> {
    encode_custom_ticket_deposit_message(
        recipient.as_bytes().to_vec(),
        amount,
        sample_ticketer(),
        sample_ticketer(),
        0,
        None,
    )
}

fn encode_custom_ticket_deposit_message(
    recipient: Vec<u8>,
    amount: u64,
    creator_ticketer: &str,
    sender_ticketer: &str,
    token_id: i32,
    metadata: Option<Vec<u8>>,
) -> Vec<u8> {
    let creator = TezosContract::from_b58check(creator_ticketer).unwrap();
    let sender_contract = TezosContract::from_b58check(sender_ticketer).unwrap();
    let sender = match sender_contract {
        TezosContract::Originated(kt1) => kt1,
        TezosContract::Implicit(_) => panic!("ticketer must be KT1"),
    };
    let payload = MichelsonPair(
        MichelsonBytes(recipient),
        FA2_1Ticket::new(
            creator,
            MichelsonPair(
                MichelsonInt::from(token_id),
                MichelsonOption(metadata.map(MichelsonBytes)),
            ),
            amount,
        )
        .unwrap(),
    );
    let transfer = TezosTransfer {
        payload,
        sender,
        source: sample_l1_source(),
        destination: sample_rollup_address(),
    };
    let mut bytes = Vec::new();
    TezosInboxMessage::Internal(TezosInternalInboxMessage::Transfer(transfer))
        .serialize(&mut bytes)
        .unwrap();
    bytes
}

fn assert_outbox_withdrawal(bytes: &[u8], ticketer: &str, recipient: &str, amount: u64) {
    let (rest, decoded) =
        TezosOutboxMessage::<MichelsonPair<MichelsonContract, FA2_1Ticket>>::nom_read(bytes)
            .expect("valid outbox encoding");
    assert!(rest.is_empty(), "outbox encoding should consume all bytes");
    let batch = match decoded {
        TezosOutboxMessage::AtomicTransactionBatch(batch) => batch,
    };
    assert_eq!(batch.len(), 1);
    let tx = &batch[0];
    assert_eq!(tx.destination.to_b58check(), ticketer);
    assert_eq!(tx.entrypoint.name(), "burn");
    assert_eq!(tx.parameters.0 .0.to_b58check(), recipient);
    assert_eq!(tx.parameters.1.creator().0.to_b58check(), ticketer);
    assert_eq!(tx.parameters.1.amount_as::<u64, _>().unwrap(), amount);
}

fn indexed_path(prefix: &[u8], index: u64) -> Vec<u8> {
    let mut path = Vec::with_capacity(prefix.len() + 16);
    path.extend_from_slice(prefix);
    path.extend_from_slice(format!("{:016x}", index).as_bytes());
    path
}

#[cfg(feature = "proof-verifier")]
fn assert_ledger_state_unchanged(before: &tzel_core::Ledger, after: &tzel_core::Ledger) {
    assert_eq!(after.auth_domain, before.auth_domain);
    assert_eq!(after.tree.leaves, before.tree.leaves);
    assert_eq!(after.tree.root(), before.tree.root());
    assert_eq!(after.nullifiers, before.nullifiers);
    assert_eq!(after.valid_roots, before.valid_roots);
    assert_eq!(after.root_history, before.root_history);
    assert_eq!(after.withdrawals, before.withdrawals);
    assert_eq!(after.deposit_balances, before.deposit_balances);
}

#[cfg(feature = "proof-verifier")]
#[derive(Clone, Deserialize)]
struct VerifiedBridgeFixture {
    #[serde(with = "tzel_core::hex_f")]
    auth_domain: F,
    program_hashes: ProgramHashes,
    bridge_ticketer: String,
    shield: ShieldReq,
    transfer: TransferReq,
    unshield: UnshieldReq,
}

#[cfg(feature = "proof-verifier")]
fn verified_bridge_fixture() -> &'static VerifiedBridgeFixture {
    static FIXTURE: OnceLock<VerifiedBridgeFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!("../testdata/verified_bridge_flow.json"))
            .expect("valid verified bridge fixture")
    })
}

#[cfg(feature = "proof-verifier")]
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

#[cfg(feature = "proof-verifier")]
fn kernel_shield_req_from_fixture(req: &ShieldReq) -> KernelShieldReq {
    KernelShieldReq {
        pubkey_hash: req.pubkey_hash,
        v: req.v,
        fee: req.fee,
        producer_fee: req.producer_fee,
        proof: kernel_proof_from_fixture(&req.proof),
        client_cm: req.client_cm,
        client_enc: req.client_enc.clone(),
        producer_cm: req.producer_cm,
        producer_enc: req.producer_enc.clone(),
    }
}

#[cfg(feature = "proof-verifier")]
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

#[cfg(feature = "proof-verifier")]
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

#[cfg(feature = "proof-verifier")]
fn configure_verified_bridge(host: &mut TestHost, fixture: &VerifiedBridgeFixture) {
    configure_verified_bridge_with_hashes(host, fixture, fixture.program_hashes.clone());
}

#[cfg(feature = "proof-verifier")]
fn configure_verified_bridge_via_dal(host: &mut TestHost, fixture: &VerifiedBridgeFixture) {
    let verifier_payload =
        encode_kernel_inbox_message(&signed_verifier_message(KernelVerifierConfig {
            auth_domain: fixture.auth_domain,
            verified_program_hashes: fixture.program_hashes.clone(),
            operator_producer_owner_tag: ZERO,
        }))
        .unwrap();
    let verifier_pointer = KernelDalPayloadPointer {
        kind: KernelDalPayloadKind::ConfigureVerifier,
        chunks: vec![install_test_dal_payload(
            host,
            101,
            0,
            64,
            8192,
            &verifier_payload,
        )],
        payload_len: verifier_payload.len() as u64,
        payload_hash: hash(&verifier_payload),
    };
    host.push_input(
        0,
        0,
        encode_external_kernel_message(KernelInboxMessage::DalPointer(verifier_pointer)),
    );

    let bridge_payload = encode_kernel_inbox_message(&signed_bridge_message(KernelBridgeConfig {
        ticketer: fixture.bridge_ticketer.clone(),
    }))
    .unwrap();
    let bridge_pointer = KernelDalPayloadPointer {
        kind: KernelDalPayloadKind::ConfigureBridge,
        chunks: vec![install_test_dal_payload(
            host,
            102,
            1,
            64,
            8192,
            &bridge_payload,
        )],
        payload_len: bridge_payload.len() as u64,
        payload_hash: hash(&bridge_payload),
    };
    host.push_input(
        1,
        0,
        encode_external_kernel_message(KernelInboxMessage::DalPointer(bridge_pointer)),
    );
    run_with_host(host);
}

#[cfg(feature = "proof-verifier")]
fn configure_verified_bridge_with_hashes(
    host: &mut TestHost,
    fixture: &VerifiedBridgeFixture,
    hashes: ProgramHashes,
) {
    host.push_input(
        0,
        0,
        encode_external_kernel_message(signed_verifier_message(KernelVerifierConfig {
            auth_domain: fixture.auth_domain,
            verified_program_hashes: hashes,
            operator_producer_owner_tag: ZERO,
        })),
    );
    host.push_input(
        1,
        0,
        encode_external_kernel_message(signed_bridge_message(KernelBridgeConfig {
            ticketer: fixture.bridge_ticketer.clone(),
        })),
    );
    run_with_host(host);
}

#[cfg(feature = "proof-verifier")]
fn apply_fixture_deposit(host: &mut TestHost, fixture: &VerifiedBridgeFixture, level: i32) {
    host.push_input(
        level,
        0,
        encode_custom_ticket_deposit_message(
            deposit_recipient_string(&fixture.shield.pubkey_hash).into_bytes(),
            fixture.shield.v + fixture.shield.fee + fixture.shield.producer_fee,
            &fixture.bridge_ticketer,
            &fixture.bridge_ticketer,
            0,
            None,
        ),
    );
    run_with_host(host);
}

#[cfg(feature = "proof-verifier")]
fn apply_fixture_shield(host: &mut TestHost, fixture: &VerifiedBridgeFixture, level: i32) {
    host.push_input(
        level,
        0,
        encode_external_kernel_message(KernelInboxMessage::Shield(kernel_shield_req_from_fixture(
            &fixture.shield,
        ))),
    );
    run_with_host(host);
}

#[cfg(feature = "proof-verifier")]
fn apply_fixture_transfer(host: &mut TestHost, fixture: &VerifiedBridgeFixture, level: i32) {
    host.push_input(
        level,
        0,
        encode_external_kernel_message(KernelInboxMessage::Transfer(
            kernel_transfer_req_from_fixture(&fixture.transfer),
        )),
    );
    run_with_host(host);
}

#[cfg(feature = "proof-verifier")]
fn apply_fixture_unshield(host: &mut TestHost, fixture: &VerifiedBridgeFixture, level: i32) {
    host.push_input(
        level,
        0,
        encode_external_kernel_message(KernelInboxMessage::Unshield(
            kernel_unshield_req_from_fixture(&fixture.unshield),
        )),
    );
    run_with_host(host);
}

fn sample_ticketer() -> &'static str {
    "KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc"
}

fn sample_other_l1_receiver() -> &'static str {
    "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN"
}

fn sample_l1_source() -> PublicKeyHash {
    PublicKeyHash::from_b58check("tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN").unwrap()
}

fn sample_rollup_address() -> SmartRollupAddress {
    SmartRollupAddress::from_b58check("sr1UNDWPUYVeomgG15wn5jSw689EJ4RNnVQa").unwrap()
}
