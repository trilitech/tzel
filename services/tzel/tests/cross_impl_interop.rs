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
    let mut output_preimage = vec![*auth_domain, step.root];
    output_preimage.extend(step.nullifiers.iter().copied());
    output_preimage.push(u64_to_felt(step.fee));
    output_preimage.push(step.cm_1);
    output_preimage.push(step.cm_2);
    output_preimage.push(step.cm_3);
    output_preimage.push(step.memo_ct_hash_1);
    output_preimage.push(step.memo_ct_hash_2);
    output_preimage.push(step.memo_ct_hash_3);
    TransferReq {
        root: step.root,
        nullifiers: step.nullifiers.clone(),
        fee: step.fee,
        cm_1: step.cm_1,
        cm_2: step.cm_2,
        cm_3: step.cm_3,
        enc_1: step.enc_1.clone(),
        enc_2: step.enc_2.clone(),
        enc_3: step.enc_3.clone(),
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
    output_preimage.push(u64_to_felt(step.fee));
    output_preimage.push(hash(step.recipient.as_bytes()));
    output_preimage.push(step.cm_change);
    output_preimage.push(step.memo_ct_hash_change);
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

    let unshield_resp = ledger
        .unshield(&unshield_req(&scenario.unshield, &scenario.auth_domain))
        .expect("unshield");
    assert_eq!(unshield_resp.change_index, None);
    assert_eq!(unshield_resp.producer_index, 5);

    // Pool drained.
    assert!(ledger.deposit_balances.get(&pubkey_hash).is_none());
    assert_eq!(ledger.withdrawals, scenario.expected.withdrawals.clone());
    assert_eq!(ledger.tree.leaves.len(), scenario.expected.tree_size);
    assert_eq!(ledger.nullifiers.len(), scenario.expected.nullifier_count);
}
