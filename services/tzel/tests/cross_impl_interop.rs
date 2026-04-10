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

fn ocaml_scenario() -> InteropScenario {
    let out = Command::new("dune")
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

fn shield_req(step: &InteropShieldStep) -> ShieldReq {
    ShieldReq {
        sender: step.sender.clone(),
        v: step.v,
        address: step.address.clone(),
        memo: None,
        proof: Proof::Stark {
            proof_bytes: vec![1],
            output_preimage: vec![
                u64_to_felt(step.v),
                step.cm,
                hash(step.sender.as_bytes()),
                step.memo_ct_hash,
            ],
            verify_meta: None,
        },
        client_cm: step.cm,
        client_enc: Some(step.enc.clone()),
    }
}

fn transfer_req(step: &InteropTransferStep, auth_domain: &F) -> TransferReq {
    let mut output_preimage = vec![*auth_domain, step.root];
    output_preimage.extend(step.nullifiers.iter().copied());
    output_preimage.push(step.cm_1);
    output_preimage.push(step.cm_2);
    output_preimage.push(step.memo_ct_hash_1);
    output_preimage.push(step.memo_ct_hash_2);
    TransferReq {
        root: step.root,
        nullifiers: step.nullifiers.clone(),
        cm_1: step.cm_1,
        cm_2: step.cm_2,
        enc_1: step.enc_1.clone(),
        enc_2: step.enc_2.clone(),
        proof: Proof::Stark {
            proof_bytes: vec![1],
            output_preimage,
            verify_meta: None,
        },
    }
}

fn unshield_req(step: &InteropUnshieldStep, auth_domain: &F) -> UnshieldReq {
    let mut output_preimage = vec![*auth_domain, step.root];
    output_preimage.extend(step.nullifiers.iter().copied());
    output_preimage.push(u64_to_felt(step.v_pub));
    output_preimage.push(hash(step.recipient.as_bytes()));
    output_preimage.push(step.cm_change);
    output_preimage.push(step.memo_ct_hash_change);
    UnshieldReq {
        root: step.root,
        nullifiers: step.nullifiers.clone(),
        v_pub: step.v_pub,
        recipient: step.recipient.clone(),
        cm_change: step.cm_change,
        enc_change: step.enc_change.clone(),
        proof: Proof::Stark {
            proof_bytes: vec![1],
            output_preimage,
            verify_meta: None,
        },
    }
}

#[test]
fn test_ocaml_wallet_scenario_applies_on_rust_ledger() {
    let scenario = ocaml_scenario();
    let mut ledger = Ledger::with_auth_domain(scenario.auth_domain);
    ledger
        .fund("alice", scenario.initial_alice_balance)
        .expect("fund alice");

    let shield_resp = ledger.shield(&shield_req(&scenario.shield)).expect("shield");
    assert_eq!(shield_resp.cm, scenario.shield.cm);
    assert_eq!(shield_resp.index, 0);

    let transfer_resp = ledger
        .transfer(&transfer_req(&scenario.transfer, &scenario.auth_domain))
        .expect("transfer");
    assert_eq!(transfer_resp.index_1, 1);
    assert_eq!(transfer_resp.index_2, 2);

    let unshield_resp = ledger
        .unshield(&unshield_req(&scenario.unshield, &scenario.auth_domain))
        .expect("unshield");
    assert_eq!(unshield_resp.change_index, None);

    assert_eq!(
        ledger.balances.get("alice").copied().unwrap_or(0),
        scenario.expected.alice_public_balance
    );
    assert_eq!(
        ledger.balances.get("bob").copied().unwrap_or(0),
        scenario.expected.bob_public_balance
    );
    assert_eq!(ledger.tree.leaves.len(), scenario.expected.tree_size);
    assert_eq!(ledger.nullifiers.len(), scenario.expected.nullifier_count);
}
