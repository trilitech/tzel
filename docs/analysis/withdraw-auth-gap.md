# Kernel auth gap on `Withdraw` (and by extension `Shield`)

## Summary

The rollup kernel applies `KernelInboxMessage::Withdraw` without any
authentication of the `sender` field against the actual owner of the
targeted public account. Anyone who can submit an external inbox message
to the rollup — i.e., anyone with a Tezos L1 account and enough gas to
pay for `send smart rollup message` — can drain any known
`public_account` to a recipient they control. The same structural
absence of sender authentication applies to `Shield` (the STARK proof
binds the sender string but does not prove ownership of it).

This is a **protocol-level** gap, not an operator-level one: the
operator's bearer token is not the defense, and bypassing it by
submitting directly to L1 is trivial.

## Reproducible proof

Two independent reproductions are included:

1. `tezos/rollup-kernel/tests/bridge_flow.rs::withdraw_poc_drains_unauthorized_sender`
   — a Rust integration test against the kernel PVM that exercises:
   configure bridge → deposit 500_001 mutez to `alice` → unauthorized
   third party injects a Withdraw with `sender = "alice"` → asserts
   `alice`'s balance is drained to 0 and the outbox message credits the
   attacker's recipient. Runs under plain `cargo test --test bridge_flow
   withdraw_poc_drains_unauthorized_sender` (no sandbox required).

2. `scripts/sandbox_withdraw_auth_bypass_poc.sh` — an end-to-end sandbox
   smoke that spins up an octez sandbox, does the legitimate deposit
   flow, then submits the attack Withdraw as `bootstrap2` (which is
   **not** the operator's source_alias). The smoke terminates with
   `VULNERABILITY CONFIRMED: alice's 500001 mutez was drained` once the
   kernel processes the attack message. Requires
   `TZEL_OCTEZ_SANDBOX_PRESERVE=1` to keep artefacts for inspection.

Both reproductions use a temporary `octez_kernel_message withdraw <sr1>
<sender> <recipient> <amount>` subcommand introduced in this branch
(PoC helper only — no signature, no proof, emits a framed
`KernelInboxMessage::Withdraw` ready for `octez-client send smart
rollup message`).

## Evidence in the code

### 1. `KernelWithdrawReq` has three fields and no signature

`core/src/kernel_wire.rs:110-115`:

```rust
#[derive(Debug, Clone)]
pub struct KernelWithdrawReq {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
}
```

Contrast with `KernelSignedVerifierConfig` or `KernelSignedBridgeConfig`,
which wrap a `signature: Vec<F>` produced by `wots_sign` and verified by
the kernel. The admin path is authenticated; the user withdraw path is
not.

### 2. `apply_kernel_message` on `Withdraw` runs no auth check

`tezos/rollup-kernel/src/lib.rs` (around line 1009):

```rust
KernelInboxMessage::Withdraw(req) => {
    let host_req = kernel_withdraw_req_to_host(&req);
    let ticketer = ledger
        .read_string(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)?
        .ok_or_else(|| "bridge ticketer is not configured".to_string())?;
    let balance = ledger.balance(&host_req.sender)?;
    if balance < host_req.amount {
        return Err("insufficient balance".into());
    }
    let outbox = encode_withdrawal_outbox_message(
        &ticketer,
        &WithdrawalRecord {
            recipient: host_req.recipient.clone(),
            amount: host_req.amount,
        },
    )?;
    ledger.host.write_output(&outbox)?;
    let resp = apply_withdraw(ledger, &host_req)?;
    Ok(KernelResult::Withdraw(resp))
}
```

The only validation is balance sufficiency and recipient format (via
`TezosContract::from_b58check` inside `encode_withdrawal_outbox_message`
at `tezos/rollup-kernel/src/lib.rs:509`). Neither checks ownership.

### 3. `apply_shield` is in the same shape

`core/src/lib.rs:1659-1740`:

- Reads `state.balance(&req.sender)` as a string lookup.
- The STARK proof binds `tail[5] == hash(req.sender.as_bytes())` — this
  only proves the prover chose to reference that sender string, not that
  they own the underlying balance.
- All proof inputs are either public (amount, fee, dal_fee, recipient
  `PaymentAddress`) or generated locally by the prover (rseed, producer
  rseed). No private input is tied to the sender.

A third party can therefore construct a valid shield proof for any
`sender` they choose, directing the output note to a `PaymentAddress`
they control. Cost: one STARK proof generation (~seconds on commodity
hardware) plus one L1 transaction.

### 4. The operator adds no sender-level check either

`services/tzel/src/bin/tzel_operator.rs:474` (`submit_rollup_message`
handler):

- `require_bearer_auth(&headers, &state.config)` — compares the
  `Authorization` header against a single `config.bearer_token` stored
  per operator instance. There is no per-user token, no mapping of
  tokens to authorized public accounts, and no rotation.
- `process_submission` then encodes and forwards the payload to L1 or
  DAL. It calls `kernel_message_matches_submission_kind` (which only
  checks that `kind == Shield` matches a `Shield` variant etc.) and
  `validate_fee_note_against_policy` (DAL fee policy, separate concern).
  **Nothing compares `req.sender` with the authenticated caller.**

### 5. The bearer token is not even required for the attack

`send smart rollup message` is a standard Tezos protocol operation
callable by any L1 account holder. Nothing on the protocol side filters
messages by source. An attacker skips the operator entirely and submits
the Withdraw directly:

```bash
octez-client send smart rollup message "hex:[ \"...withdraw hex...\" ]" \
    from <any_tz1>
```

This is exactly how the sandbox PoC succeeds (it submits from
`bootstrap2`, not from the operator's `source_alias`).

## Threat model and blast radius

- **`public_account` names are enumerable.** The rollup's durable
  storage RPC (`/global/block/head/durable/wasm_2_0_0/value?key=/tzel/v1/state/balances/by-key/<hex>`)
  lets anyone scan public balances. Bridge deposits also record the
  receiver bytes in clear on L1 (they are an argument of the bridge
  `mint` entrypoint in every deposit operation).

- **Attack cost:** one L1 tx (a few cents of fees) plus a STARK proof
  for Shield (seconds of compute on a laptop) or nothing for Withdraw
  (three strings).

- **Defense in depth currently present:**
  - Recipient format is validated (kernel rejects malformed
    tz1/KT1 strings — discovered empirically during PoC when a garbage
    recipient string failed with "invalid withdrawal recipient
    contract").
  - Nothing else.

## Where this is and is not a problem

- **Single-tenant self-custodial deployments** (one user runs the whole
  stack locally, user = operator = admin = wallet owner) are **not
  affected in practice**: the only entity that could exploit the gap is
  the user themselves against themselves.

- **Shared operators** (multiple users share one operator bearer token
  and rely on the bearer model for isolation) are **fully affected**.
  Any holder of the bearer token can drain any other user's public
  balance. More importantly, an attacker without the bearer token can
  drain anyone's public balance by submitting directly to L1.

- **Public deployments** where public account identities are discoverable
  (which, per the enumeration argument above, is the default) are
  **fully affected**.

## Possible mitigations (not an endorsement — design space only)

1. **Bind `public_account` identity to an L1 `tz1`.** Use
   `hex(SENDER)` inside the bridge `mint` entrypoint instead of an
   arbitrary receiver bytes argument, so the public_account is
   cryptographically tied to a Tezos address. Then require a Tezos
   signature in `KernelWithdrawReq` / `KernelShieldReq` and have the
   kernel verify it against the tz1 encoded in `sender`. Requires
   bridge contract changes, kernel changes, and wallet tooling changes.

2. **Add a WOTS/XMSS signature field to `KernelWithdrawReq` and
   `KernelShieldReq`,** symmetric with the existing admin Configure*
   messages. A public account registers a WOTS public leaf during
   deposit (kernel stores it indexed by account name), and subsequent
   Withdraw/Shield messages carry a signature the kernel verifies
   against the stored leaf. Fully post-quantum; no L1 sig overhead;
   requires a registration step at first deposit.

3. **Make the operator the trust anchor per-user.** Replace the single
   bearer token with per-user tokens, each mapped server-side to the
   set of `public_account` names that token is allowed to act on. Does
   not fix the direct-L1-submit bypass — attackers can still skip the
   operator. Only buys safety if the rollup's inbox is somehow made
   unreachable except via the operator, which is not possible under
   standard Tezos protocol rules.

4. **Accept single-tenant as the intended model** and document the
   constraint explicitly in deployment guides, operator runbooks, and
   the wallet UX. This is coherent with the present design but
   forecloses any public dapp.

Options (1) and (2) are kernel-protocol changes that require design
alignment before implementation. Option (3) is insufficient on its own.
Option (4) is a scoping decision.

## What this branch does and does not do

- Adds a reproducible Rust integration test that exercises the gap.
- Adds a sandbox-level smoke PoC that demonstrates the gap
  end-to-end with real octez binaries.
- Adds a temporary `withdraw` subcommand to `octez_kernel_message` used
  by the PoC script. (The binary was already an admin/ops helper; this
  extension is local and can be removed once mitigations land.)
- **Does not** propose a fix. The design space is not this branch's
  scope; see the mitigations section for sketches that would require
  alignment with the kernel maintainer.
