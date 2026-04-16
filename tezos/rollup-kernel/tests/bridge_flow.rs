use std::collections::{HashMap, VecDeque};

#[cfg(feature = "proof-verifier")]
use std::sync::OnceLock;

#[cfg(feature = "proof-verifier")]
use serde::Deserialize;
use tezos_data_encoding_05::nom::NomReader as _;
use tezos_smart_rollup_encoding::{
    contract::Contract as TezosContract,
    inbox::{
        InboxMessage as TezosInboxMessage, InternalInboxMessage as TezosInternalInboxMessage,
        Transfer as TezosTransfer,
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
    encode_kernel_inbox_message, KernelBridgeConfig, KernelInboxMessage, KernelResult,
    KernelWithdrawReq,
};
#[cfg(feature = "proof-verifier")]
use tzel_core::kernel_wire::{
    KernelShieldReq, KernelStarkProof, KernelTransferReq, KernelUnshieldReq, KernelVerifierConfig,
};
#[cfg(feature = "proof-verifier")]
use tzel_core::{ProgramHashes, Proof, ShieldReq, TransferReq, UnshieldReq, F};
use tzel_rollup_kernel::{
    read_last_input, read_last_result, read_ledger, read_stats, run_with_host, Host, InputMessage,
    MAX_INPUT_BYTES,
};

const PATH_BRIDGE_TICKETER: &[u8] = b"/tzel/v1/state/bridge/ticketer";
const PATH_WITHDRAWAL_PREFIX: &[u8] = b"/tzel/v1/state/withdrawals/index/";

#[derive(Clone, Default)]
struct TestHost {
    inputs: VecDeque<InputMessage>,
    store: HashMap<Vec<u8>, Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    debug: String,
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
}

#[test]
fn bridge_roundtrip_survives_restarts_and_preserves_append_only_withdrawals() {
    let mut host = TestHost::default();
    host.push_input(
        0,
        0,
        encode_external_kernel_message(KernelInboxMessage::ConfigureBridge(KernelBridgeConfig {
            ticketer: sample_ticketer().into(),
        })),
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

    host.push_input(1, 0, encode_ticket_deposit_message("alice", 75));
    run_with_host(&mut host);

    assert!(matches!(
        read_last_result(&host).unwrap(),
        KernelResult::Deposit
    ));
    assert_eq!(read_ledger(&host).unwrap().balances.get("alice"), Some(&75));

    let first_withdraw =
        encode_external_kernel_message(KernelInboxMessage::Withdraw(KernelWithdrawReq {
            sender: "alice".into(),
            recipient: sample_l1_receiver().into(),
            amount: 40,
        }));
    host.push_input(2, 0, first_withdraw);
    run_with_host(&mut host);

    match read_last_result(&host).unwrap() {
        KernelResult::Withdraw(resp) => {
            let withdrawal_index = resp.withdrawal_index;
            assert_eq!(withdrawal_index, 0)
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }
    assert_eq!(host.outputs.len(), 1);
    assert_outbox_withdrawal(
        &host.outputs[0],
        sample_ticketer(),
        sample_l1_receiver(),
        40,
    );

    let mut restarted = TestHost::from_store(host.store.clone());
    restarted.outputs = host.outputs.clone();
    restarted.push_input(3, 0, encode_ticket_deposit_message("alice", 10));
    restarted.push_input(
        4,
        0,
        encode_external_kernel_message(KernelInboxMessage::Withdraw(KernelWithdrawReq {
            sender: "alice".into(),
            recipient: sample_l1_receiver().into(),
            amount: 5,
        })),
    );

    run_with_host(&mut restarted);

    let stats = read_stats(&restarted);
    assert_eq!(stats.raw_input_count, 5);
    assert_eq!(stats.last_input_level, Some(4));
    assert_eq!(stats.last_input_id, Some(0));
    assert_eq!(
        read_last_input(&restarted)
            .expect("last input persisted")
            .level,
        4
    );

    match read_last_result(&restarted).unwrap() {
        KernelResult::Withdraw(resp) => {
            let withdrawal_index = resp.withdrawal_index;
            assert_eq!(withdrawal_index, 1)
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }

    let ledger = read_ledger(&restarted).unwrap();
    assert_eq!(ledger.balances.get("alice"), Some(&40));
    assert_eq!(ledger.withdrawals.len(), 2);
    assert_eq!(ledger.withdrawals[0].recipient, sample_l1_receiver());
    assert_eq!(ledger.withdrawals[0].amount, 40);
    assert_eq!(ledger.withdrawals[1].recipient, sample_l1_receiver());
    assert_eq!(ledger.withdrawals[1].amount, 5);
    assert!(restarted
        .store
        .contains_key(&indexed_path(PATH_WITHDRAWAL_PREFIX, 0)));
    assert!(restarted
        .store
        .contains_key(&indexed_path(PATH_WITHDRAWAL_PREFIX, 1)));
    assert_eq!(restarted.outputs.len(), 2);
    assert_outbox_withdrawal(
        &restarted.outputs[1],
        sample_ticketer(),
        sample_l1_receiver(),
        5,
    );
}

#[test]
fn bridge_deposit_requires_configuration_and_recovers_after_external_configuration() {
    let mut host = TestHost::default();
    let deposit = encode_ticket_deposit_message("alice", 12);
    host.push_input(0, 0, deposit.clone());

    run_with_host(&mut host);

    assert!(read_ledger(&host).unwrap().balances.is_empty());
    match read_last_result(&host).unwrap() {
        KernelResult::Error { message } => {
            assert!(message.contains("bridge ticketer is not configured"))
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }

    host.push_input(
        1,
        0,
        encode_external_kernel_message(KernelInboxMessage::ConfigureBridge(KernelBridgeConfig {
            ticketer: sample_ticketer().into(),
        })),
    );
    host.push_input(2, 0, deposit);

    run_with_host(&mut host);

    let stats = read_stats(&host);
    assert_eq!(stats.raw_input_count, 3);
    assert_eq!(read_ledger(&host).unwrap().balances.get("alice"), Some(&12));
    assert!(matches!(
        read_last_result(&host).unwrap(),
        KernelResult::Deposit
    ));
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
    assert_eq!(
        read_ledger(&host)
            .unwrap()
            .balances
            .get(fixture.shield.sender.as_str()),
        Some(&fixture.shield.v)
    );

    apply_fixture_shield(&mut host, fixture, 3);

    match read_last_result(&host).unwrap() {
        KernelResult::Shield(resp) => {
            assert_eq!(resp.index, 0);
            assert_eq!(resp.cm, fixture.shield.client_cm);
        }
        other => panic!("unexpected rollup result: {:?}", other),
    }
    let ledger = read_ledger(&host).unwrap();
    assert_eq!(
        ledger.balances.get(fixture.shield.sender.as_str()),
        Some(&0)
    );
    assert_eq!(ledger.tree.leaves, vec![fixture.shield.client_cm]);

    apply_fixture_transfer(&mut host, fixture, 4);

    match read_last_result(&host).unwrap() {
        KernelResult::Transfer(resp) => assert_eq!((resp.index_1, resp.index_2), (1, 2)),
        other => panic!("unexpected rollup result: {:?}", other),
    }
    let ledger = read_ledger(&host).unwrap();
    assert_eq!(
        ledger.tree.leaves,
        vec![
            fixture.shield.client_cm,
            fixture.transfer.cm_1,
            fixture.transfer.cm_2,
        ]
    );
    assert_eq!(ledger.nullifiers.len(), 1);
    assert!(ledger.nullifiers.contains(&fixture.transfer.nullifiers[0]));

    let mut restarted = TestHost::from_store(host.store.clone());
    apply_fixture_unshield(&mut restarted, fixture, 5);

    match read_last_result(&restarted).unwrap() {
        KernelResult::Unshield(resp) => assert_eq!(resp.change_index, None),
        other => panic!("unexpected rollup result: {:?}", other),
    }
    let ledger = read_ledger(&restarted).unwrap();
    assert_eq!(
        ledger.balances.get(fixture.unshield.recipient.as_str()),
        Some(&fixture.unshield.v_pub)
    );
    assert_eq!(ledger.nullifiers.len(), 2);
    assert!(ledger.nullifiers.contains(&fixture.transfer.nullifiers[0]));
    assert!(ledger.nullifiers.contains(&fixture.unshield.nullifiers[0]));

    restarted.push_input(
        6,
        0,
        encode_external_kernel_message(KernelInboxMessage::Withdraw(KernelWithdrawReq {
            sender: fixture.unshield.recipient.clone(),
            recipient: fixture.withdrawal_recipient.clone(),
            amount: fixture.unshield.v_pub,
        })),
    );
    run_with_host(&mut restarted);

    match read_last_result(&restarted).unwrap() {
        KernelResult::Withdraw(resp) => assert_eq!(resp.withdrawal_index, 0),
        other => panic!("unexpected rollup result: {:?}", other),
    }
    let stats = read_stats(&restarted);
    assert_eq!(stats.raw_input_count, 7);
    assert_eq!(stats.last_input_level, Some(6));
    assert_eq!(
        read_last_input(&restarted)
            .expect("last input persisted")
            .level,
        6
    );

    let ledger = read_ledger(&restarted).unwrap();
    assert_eq!(
        ledger.balances.get(fixture.unshield.recipient.as_str()),
        Some(&0)
    );
    assert_eq!(ledger.withdrawals.len(), 1);
    assert_eq!(
        ledger.withdrawals[0].recipient,
        fixture.withdrawal_recipient.as_str()
    );
    assert_eq!(ledger.withdrawals[0].amount, fixture.unshield.v_pub);
    assert_eq!(restarted.outputs.len(), 1);
    assert_outbox_withdrawal(
        &restarted.outputs[0],
        &fixture.bridge_ticketer,
        &fixture.withdrawal_recipient,
        fixture.unshield.v_pub,
    );
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

    let after_transfer = read_ledger(&host).unwrap();
    assert_eq!(after_transfer.balances, before_transfer.balances);
    assert_eq!(after_transfer.tree.leaves, before_transfer.tree.leaves);
    assert_eq!(after_transfer.nullifiers, before_transfer.nullifiers);
    assert_eq!(after_transfer.withdrawals, before_transfer.withdrawals);
    assert!(host.outputs.is_empty());
}

#[cfg(feature = "proof-verifier")]
#[test]
fn verified_shield_rejects_tampered_client_note_without_mutating_public_balance() {
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);
    apply_fixture_deposit(&mut host, fixture, 2);

    let before_shield = read_ledger(&host).unwrap();
    let mut req = fixture.shield.clone();
    req.client_enc
        .as_mut()
        .expect("fixture shield note")
        .encrypted_data[0] ^= 0x01;
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
fn verified_unshield_rejects_tampered_recipient_without_mutating_state() {
    let fixture = verified_bridge_fixture();
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);
    apply_fixture_deposit(&mut host, fixture, 2);
    apply_fixture_shield(&mut host, fixture, 3);
    apply_fixture_transfer(&mut host, fixture, 4);

    let before_unshield = read_ledger(&host).unwrap();
    let mut req = fixture.unshield.clone();
    req.recipient = "mallory".into();
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

fn encode_external_kernel_message(message: KernelInboxMessage) -> Vec<u8> {
    let payload = encode_kernel_inbox_message(&message).unwrap();
    let mut bytes = Vec::new();
    TezosInboxMessage::<MichelsonUnit>::External(payload.as_slice())
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
    assert_eq!(after.balances, before.balances);
    assert_eq!(after.valid_roots, before.valid_roots);
    assert_eq!(after.root_history, before.root_history);
    assert_eq!(after.withdrawals, before.withdrawals);
}

#[cfg(feature = "proof-verifier")]
#[derive(Clone, Deserialize)]
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
            verify_meta,
        } => KernelStarkProof {
            proof_bytes: proof_bytes.clone(),
            output_preimage: output_preimage.clone(),
            verify_meta: verify_meta
                .clone()
                .expect("fixture Stark proof verify_meta"),
        },
        Proof::TrustMeBro => panic!("fixture should contain real Stark proofs"),
    }
}

#[cfg(feature = "proof-verifier")]
fn kernel_shield_req_from_fixture(req: &ShieldReq) -> KernelShieldReq {
    KernelShieldReq {
        sender: req.sender.clone(),
        v: req.v,
        address: req.address.clone(),
        memo: req.memo.clone(),
        proof: kernel_proof_from_fixture(&req.proof),
        client_cm: req.client_cm,
        client_enc: req.client_enc.clone(),
    }
}

#[cfg(feature = "proof-verifier")]
fn kernel_transfer_req_from_fixture(req: &TransferReq) -> KernelTransferReq {
    KernelTransferReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        cm_1: req.cm_1,
        cm_2: req.cm_2,
        enc_1: req.enc_1.clone(),
        enc_2: req.enc_2.clone(),
        proof: kernel_proof_from_fixture(&req.proof),
    }
}

#[cfg(feature = "proof-verifier")]
fn kernel_unshield_req_from_fixture(req: &UnshieldReq) -> KernelUnshieldReq {
    KernelUnshieldReq {
        root: req.root,
        nullifiers: req.nullifiers.clone(),
        v_pub: req.v_pub,
        recipient: req.recipient.clone(),
        cm_change: req.cm_change,
        enc_change: req.enc_change.clone(),
        proof: kernel_proof_from_fixture(&req.proof),
    }
}

#[cfg(feature = "proof-verifier")]
fn configure_verified_bridge(host: &mut TestHost, fixture: &VerifiedBridgeFixture) {
    configure_verified_bridge_with_hashes(host, fixture, fixture.program_hashes.clone());
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
        encode_external_kernel_message(KernelInboxMessage::ConfigureVerifier(
            KernelVerifierConfig {
                auth_domain: fixture.auth_domain,
                verified_program_hashes: hashes,
            },
        )),
    );
    host.push_input(
        1,
        0,
        encode_external_kernel_message(KernelInboxMessage::ConfigureBridge(KernelBridgeConfig {
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
            fixture.shield.sender.as_bytes().to_vec(),
            fixture.shield.v,
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

fn sample_l1_receiver() -> &'static str {
    "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx"
}

fn sample_l1_source() -> PublicKeyHash {
    PublicKeyHash::from_b58check("tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN").unwrap()
}

fn sample_rollup_address() -> SmartRollupAddress {
    SmartRollupAddress::from_b58check("sr1UNDWPUYVeomgG15wn5jSw689EJ4RNnVQa").unwrap()
}
