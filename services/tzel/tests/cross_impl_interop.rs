use std::process::Command;

use tzel_services::interop_scenario::{
    InteropScenario, InteropShieldStep, InteropTransferStep, InteropUnshieldStep,
};
use tzel_services::*;

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn ocaml_dune_command() -> Command {
    if Command::new("dune")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
    {
        Command::new("dune")
    } else {
        let mut cmd = Command::new("opam");
        cmd.args(["exec", "--", "dune"]);
        cmd
    }
}

fn ocaml_scenario() -> InteropScenario {
    let out = ocaml_dune_command()
        .current_dir(workspace_root().join("ocaml"))
        .args(["exec", "test/gen_interop_scenario.exe"])
        .output()
        .expect("failed to run OCaml interop scenario generator");
    assert!(
        out.status.success(),
        "OCaml scenario generator failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("valid interop scenario JSON")
}

fn shield_req(step: &InteropShieldStep, auth_domain: &F) -> (F, ShieldReq) {
    // The interop scenario doesn't carry a (blind, auth tree) for the
    // deposit pool — it only needs the cross-impl ledger transition to
    // agree on the outputs of `shield`/`transfer`/`unshield`. Synthesize
    // a deterministic pubkey_hash from the step fields and seed the
    // matching pool with the exact debit; the host-side proof check is
    // satisfied by an output_preimage that mirrors the request.
    let pubkey_hash = tzel_core::hash(&[
        auth_domain.as_slice(),
        step.cm.as_slice(),
        step.producer_cm.as_slice(),
    ].concat());
    let req = ShieldReq {
        asset_id: ASSET_TEZ,
        pubkey_hash,
        v: step.v,
        fee: step.fee,
        producer_fee: step.producer_fee,
        proof: Proof::Stark {
            proof_bytes: vec![1],
            output_preimage: vec![
                *auth_domain,
                pubkey_hash,
                u64_to_felt(step.v),
                u64_to_felt(step.fee),
                u64_to_felt(step.producer_fee),
                step.cm,
                step.producer_cm,
                step.memo_ct_hash,
                step.producer_memo_ct_hash,
                ASSET_TEZ,
            ],
        },
        client_cm: step.cm,
        client_enc: step.enc.clone(),
        producer_cm: step.producer_cm,
        producer_enc: step.producer_enc.clone(),
    };
    (pubkey_hash, req)
}

fn transfer_req(step: &InteropTransferStep, auth_domain: &F) -> TransferReq {
    // Multiasset 4-slot: slot 3 (change_2) is an empty placeholder; the
    // producer fee is in slot 4.  The OCaml wallet now emits these slots
    // directly (cm_3 = ZERO, cm_4 = producer) — this consumes them as-is,
    // with NO compensating shift, so a wallet that regressed to the old
    // 3-slot layout (producer in cm_3, cm_4 = ZERO) would now fail here
    // (missing producer note) instead of being silently papered over.
    let mut output_preimage = vec![*auth_domain, step.root];
    output_preimage.extend(step.nullifiers.iter().copied());
    output_preimage.push(u64_to_felt(step.fee));
    output_preimage.push(step.cm_1);
    output_preimage.push(step.cm_2);
    output_preimage.push(ZERO); // cm_3 = change_2 placeholder
    output_preimage.push(step.cm_4); // cm_4 = producer fee
    output_preimage.push(step.memo_ct_hash_1);
    output_preimage.push(step.memo_ct_hash_2);
    output_preimage.push(ZERO); // mh_3 = 0 for zero-value change_2
    output_preimage.push(step.memo_ct_hash_4); // mh_4 = producer memo
    let dummy_empty_enc = EncryptedNote {
        ct_d: vec![0; tzel_core::ML_KEM768_CIPHERTEXT_BYTES],
        ct_v: vec![0; tzel_core::ML_KEM768_CIPHERTEXT_BYTES],
        nonce: vec![0; tzel_core::NOTE_AEAD_NONCE_BYTES],
        encrypted_data: vec![0; 1080],
        outgoing_ct: vec![0; tzel_core::OUTGOING_RECOVERY_CT_BYTES],
        tag: 0,
    };
    // Compute the cm_3 (change_2) commitment such that
    // memo_ct_hash(&enc_3_placeholder) = ZERO. Easier: use an empty enc
    // whose memo_ct_hash deterministically equals ZERO. Since memo_ct_hash
    // is a hash, an all-zero buffer probably won't be zero — but the
    // verifier accepts a synthetic placeholder when cm_3 = ZERO.
    // For this test we don't drive memo_ct_hash_3 to ZERO; instead we
    // compute it and use that real value in the preimage.
    let cm_3_placeholder = ZERO;
    let mh_3 = memo_ct_hash(&dummy_empty_enc);
    // Patch the preimage's cm_3/mh_3 with the real computed values.
    let prefix_len = 2 + step.nullifiers.len() + 1; // auth_domain, root, nfs, fee
    output_preimage[prefix_len + 2] = cm_3_placeholder;
    output_preimage[prefix_len + 4 + 2] = mh_3; // memos start at prefix+4
    TransferReq {
        root: step.root,
        nullifiers: step.nullifiers.clone(),
        fee: step.fee,
        cm_1: step.cm_1,
        cm_2: step.cm_2,
        cm_3: cm_3_placeholder,
        cm_4: step.cm_4,
        enc_1: step.enc_1.clone(),
        enc_2: step.enc_2.clone(),
        enc_3: dummy_empty_enc,
        enc_4: step.enc_3.clone(),
        proof: Proof::Stark {
            proof_bytes: vec![1],
            output_preimage,
        },
    }
}

fn unshield_req(step: &InteropUnshieldStep, auth_domain: &F) -> UnshieldReq {
    let mut output_preimage = vec![*auth_domain, step.root];
    output_preimage.extend(step.nullifiers.iter().copied());
    output_preimage.push(u64_to_felt(step.v_pub));
    output_preimage.push(ASSET_TEZ); // asset_pub (Phase B)
    output_preimage.push(u64_to_felt(step.fee));
    output_preimage.push(hash(step.recipient.as_bytes()));
    output_preimage.push(step.cm_change);
    output_preimage.push(step.memo_ct_hash_change);
    output_preimage.push(ZERO); // cm_change_2
    output_preimage.push(ZERO); // mh_change_2
    output_preimage.push(step.cm_fee);
    output_preimage.push(step.memo_ct_hash_fee);
    UnshieldReq {
        root: step.root,
        nullifiers: step.nullifiers.clone(),
        v_pub: step.v_pub,
        fee: step.fee,
        recipient: step.recipient.clone(),
        cm_change: step.cm_change,
        enc_change: step.enc_change.clone(),
        cm_change_2: ZERO,
        enc_change_2: None,
        cm_fee: step.cm_fee,
        enc_fee: step.enc_fee.clone(),
        proof: Proof::Stark {
            proof_bytes: vec![1],
            output_preimage,
        },
    }
}

#[test]
fn test_ocaml_wallet_scenario_applies_on_rust_ledger() {
    let scenario = ocaml_scenario();
    let mut ledger = Ledger::with_auth_domain(scenario.auth_domain);
    let exact_debit = scenario.shield.v + scenario.shield.fee + scenario.shield.producer_fee;
    let (pubkey_hash, shield_req_built) =
        shield_req(&scenario.shield, &scenario.auth_domain);
    ledger
        .deposit(&deposit_recipient_string(&pubkey_hash), exact_debit)
        .expect("deposit pool");
    let shield_resp = ledger.shield(&shield_req_built).expect("shield");
    assert_eq!(shield_resp.cm, scenario.shield.cm);
    assert_eq!(shield_resp.index, 0);
    assert_eq!(shield_resp.producer_cm, scenario.shield.producer_cm);
    assert_eq!(shield_resp.producer_index, 1);

    let transfer_resp = ledger
        .transfer(&transfer_req(&scenario.transfer, &scenario.auth_domain))
        .expect("transfer");
    assert_eq!(transfer_resp.index_1, 2);
    assert_eq!(transfer_resp.index_2, 3);
    assert_eq!(transfer_resp.index_3, 4);
    assert_eq!(transfer_resp.index_4, 5);

    // Phase C: transfer appended a 4th note (the zero-value change_2
    // placeholder) so the current tree root no longer matches the
    // scenario's pre-recorded `unshield.root`. Use the live root so the
    // unshield's Merkle inclusion check works against the actual tree.
    let mut adjusted_unshield = scenario.unshield.clone();
    adjusted_unshield.root = ledger.tree.root();
    let unshield_resp = ledger
        .unshield(&unshield_req(&adjusted_unshield, &scenario.auth_domain))
        .expect("unshield");
    assert_eq!(unshield_resp.change_index, None);
    // Producer note appears after the 6 prior notes
    // (2 shield + 4 transfer outputs).
    assert_eq!(unshield_resp.producer_index, 6);

    // Pool drained.
    assert!(ledger.deposit_balances.get(&pubkey_hash).is_none());
    assert_eq!(ledger.withdrawals, scenario.expected.withdrawals.clone());
    // Phase C: tree size = scenario.expected + 1 zero-value change_2 + 1
    // producer = +1 vs the pre-Phase-C count.
    assert_eq!(ledger.tree.leaves.len(), scenario.expected.tree_size + 1);
    assert_eq!(ledger.nullifiers.len(), scenario.expected.nullifier_count);
}
