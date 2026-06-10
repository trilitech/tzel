# TzEL orchestrator (Shape A)

`tzel_orchestrator.mligo` — a Michelson contract on the Tezos X **Michelson
interface** that exposes the three user-facing TzEL operations (`shield`,
`transfer`, `unshield`) and forwards the wire-encoded body to the TzEL
smart rollup.

It is the on-chain analogue of `apps/wallet/src/lib.rs:submit_kernel_message`
(`apps/wallet/src/lib.rs:2394-2422`), but lives in Michelson so it can be
called from any wallet, dApp or composability scenario on Tezos X without
the wallet binary acting as a relayer.

---

## 1. Wire format mirrored

Source of truth: `core/src/kernel_wire.rs`.

| Layer | Value | Source |
|------|-------|--------|
| `KERNEL_WIRE_VERSION` | `17u16` (LE) | `kernel_wire.rs:14`, `kernel_wire.rs:339-342` |
| Tag `Shield`          | `0x02`       | `kernel_wire.rs:322-336` |
| Tag `Transfer`        | `0x03`       | `kernel_wire.rs:322-336` |
| Tag `Unshield`        | `0x04`       | `kernel_wire.rs:322-336` |
| `WireKernelShieldReq`   | felt + 3×u64-LE + dyn proof + 2×(felt+dyn note) | `kernel_wire.rs:222-233` |
| `WireKernelTransferReq` | dyn bytes of the nested encoding             | `kernel_wire.rs:243-247`, `kernel_wire.rs:950-963` |
| `WireKernelUnshieldReq` | dyn bytes of the nested encoding             | `kernel_wire.rs:256-260`, `kernel_wire.rs:1030-1051` |

The contract concatenates `version_le ++ tag ++ body`. The caller computes
the body off-chain (the wallet already exposes a `body-only` codec via the
exact same `kernel_wire` module — see `encode_kernel_inbox_message` at
`kernel_wire.rs:367-391` and the wire-tagging done by
`#[derive(BinWriter)]`).

The rollup payload **must** be the result of feeding the orchestrator's
output through `decode_kernel_inbox_message`
(`tezos/rollup-kernel/src/lib.rs:684-696`) and must produce the matching
`KernelInboxMessage` variant. The orchestrator does no further validation
beyond non-empty calldata — the rollup remains the source of truth for
proof verification, nullifier checks etc.

---

## 2. Two dispatch modes

The contract supports two forwarding modes, configurable by admin
(`forward_mode` in storage):

### Mode A — `Forward_to_rollup` (atomic, **needs kernel delta**)

The orchestrator emits a `TRANSFER_TOKENS bytes 0mutez rollup` operation.
This becomes an internal inbox entry of shape
`TezosInternalInboxMessage::Transfer<MichelsonBytes>` once it reaches the
rollup.

The current kernel parser only handles two internal-message shapes:
- a `Transfer<BridgeDepositPayload>` (`rollup-kernel/src/lib.rs:678-682`)
  — the bridge ticket deposit;
- any other internal — `ParsedRollupMessage::Ignore`
  (`rollup-kernel/src/lib.rs:683`).

So in Mode A the orchestrator's payload **is silently dropped** by today's
kernel. To activate Mode A, ship the small kernel delta described in §5.

### Mode B — `Emit_only` (works today, off-chain relay)

The orchestrator emits a Michelson event `%tzel_inbox (nonce, payload)`
that an off-chain relayer subscribes to and re-broadcasts as an external
rollup message — i.e. the same `ExternalMessageFrame::Targetted` envelope
the wallet emits today (`apps/wallet/src/lib.rs:2524-2536`).

Mode B works against an unmodified kernel and is what we recommend for the
first dailynet deployment; Mode A becomes available as soon as the kernel
delta lands.

---

## 3. Storage

```cameligo
type forward_mode =
  | Forward_to_rollup of address  (* the TzEL sr1... rollup address *)
  | Emit_only

type storage = {
  admin        : address ;
  rollup       : address ;        (* informational copy — Mode A uses the
                                     address inside `forward_mode`. *)
  forward_mode : forward_mode ;
  paused       : bool ;
  nonce        : nat ;            (* per-call monotonically increasing *)
}
```

The admin can:
- pause/unpause (`%set_paused`);
- rotate itself (`%set_admin`);
- switch dispatch mode (`%set_forward_mode`);
- update the rollup address (`%set_rollup`).

Per audit feedback the admin key is **test-only**; on mainnet the contract
should be redeployed under governance control (no admin key, or a multisig
behind it).

---

## 4. Build, originate, call

### 4.1 Compile

```bash
cd tezos
ligo compile contract tzel_orchestrator.mligo --syntax cameligo \
    > tzel_orchestrator.tz
```

The bytecode currently fits in well under the Tezos hard size cap (the raw
Michelson printout is ~190 lines).

### 4.2 Originate

For the sandbox / a daily-master Michelson interface endpoint:

```bash
# Pick a real admin key, the TzEL rollup sr1... address, and a forward mode.
ADMIN=$(octez-client show address alice | head -1 | awk '{print $2}')
ROLLUP=sr1RYurGZtN8KNSpkMcCt9CgWeUaNkzsAfXf  # replace with the live rollup

INIT_STORAGE=$(ligo compile storage tezos/tzel_orchestrator.mligo \
  "{ admin = (\"$ADMIN\" : address); \
     rollup = (\"$ROLLUP\" : address); \
     forward_mode = Emit_only; \
     paused = false; \
     nonce = 0n }" \
  --syntax cameligo)

octez-client originate contract tzel_orchestrator \
  transferring 0 from "$ADMIN" \
  running tezos/tzel_orchestrator.tz \
  --init "$INIT_STORAGE" \
  --burn-cap 5
```

Switch to atomic Mode A by re-running with
`forward_mode = Forward_to_rollup (\"$ROLLUP\" : address)` once the
kernel delta (§5) is live.

### 4.3 Call — shield / transfer / unshield

The body is the wire-encoded request *without* the version+tag wrapper —
those are added by the contract.

```bash
# 1. Build a `KernelInboxMessage::Shield(...)` body off-chain via the
#    wallet helper (`kernel_wire::encode_kernel_inbox_message`) — strip the
#    first 3 bytes (version_le ++ tag) before passing it on-chain.
SHIELD_BODY=0x...   # bytes from the wallet, version+tag stripped

octez-client transfer 0 from alice to tzel_orchestrator \
  --entrypoint shield \
  --arg "$SHIELD_BODY" \
  --burn-cap 1
```

`transfer` and `unshield` follow the same pattern with the matching
entrypoint name and body.

### 4.4 Sandbox test recipe

```bash
# 1. Build the kernel with Mode A support (see §5) and start a daily-master
#    sandbox configured with the Michelson interface enabled.
make -C tezos/rollup-kernel build

# 2. Originate the bridge ticketer and the orchestrator.
octez-client originate contract tez_bridge_ticketer \
  transferring 0 from bootstrap1 \
  running tezos/tez_bridge_ticketer.tz \
  --init Unit --burn-cap 5
octez-client originate contract tzel_orchestrator \
  transferring 0 from bootstrap1 \
  running tezos/tzel_orchestrator.tz \
  --init "$INIT_STORAGE_EMIT_ONLY" \
  --burn-cap 5

# 3. Funding the deposit pool still goes through tez_bridge_ticketer.mint.
#    Use the wallet binary as today (the orchestrator does NOT handle XTZ
#    deposits — it only orchestrates shield/transfer/unshield kernel msgs).

# 4. Drive a shield via the orchestrator; the relayer should observe the
#    %tzel_inbox event and forward it as an external message in Mode B,
#    or the kernel should consume it directly in Mode A.
```

---

## 5. Kernel-side delta required (Mode A only)

Mode B (`Emit_only`) works against an unmodified kernel.

Mode A (`Forward_to_rollup`) requires the kernel to learn one new internal
inbox shape. In `tezos/rollup-kernel/src/lib.rs:684-696` the parser is:

```rust
match ExternalMessageFrame::parse(payload) {
    Ok(ExternalMessageFrame::Targetted { address, contents }) => {
        if address.hash().as_ref().as_slice() != current_rollup {
            Ok(ParsedRollupMessage::Ignore)
        } else {
            decode_kernel_inbox_message(contents)
                .map(ParsedRollupMessage::Kernel)
        }
    }
    Err(_) => Ok(ParsedRollupMessage::Ignore),
}
```

Add — in `parse_rollup_message_against` (`rollup-kernel/src/lib.rs:673`) —
an arm for `TezosInternalInboxMessage::Transfer<MichelsonBytes>` whose
`destination` is the current rollup:

```rust
TezosInboxMessage::Internal(TezosInternalInboxMessage::Transfer(transfer))
    if /* payload type is MichelsonBytes */ =>
{
    if transfer.destination.hash().as_ref().as_slice() != current_rollup {
        Ok(ParsedRollupMessage::Ignore)
    } else {
        decode_kernel_inbox_message(transfer.payload.as_slice())
            .map(ParsedRollupMessage::Kernel)
    }
}
```

Concretely:

- introduce a parametric `parse_rollup_message_against` over the union
  `BridgeDepositPayload | MichelsonBytes`, or alternatively a two-pass
  `try_parse_as::<MichelsonBytes>(...)` before the catch-all
  `Internal(_) => Ignore` arm at line 683;
- treat the sender (transfer.sender) as advisory only — the orchestrator
  contract address is **not** a security boundary by itself, just like the
  external path does not authenticate the submitter. Authentication of the
  message contents lives in the STARK proofs already.

No other kernel modules need to change. The wire envelope itself is
identical to the external path (same `decode_kernel_inbox_message`
output), so existing tests at
`tezos/rollup-kernel/src/lib.rs:4276-4297` already cover the decoder.

---

## 6. Known limitations / open questions

- **Mode A requires a `bytes`-typed rollup (sandbox-verified).** The
  orchestrator resolves the rollup with
  `Tezos.get_contract_opt (bytes contract)`. A rollup originated with the
  ticket-bearing parameter type
  `(pair bytes (ticket (pair nat (option bytes))))` (the type needed for
  live bridge deposits, see `rollup-kernel/README.md`) fails that
  typecheck, so `%shield` aborts with `TZEL_ORCH_ROLLUP_NOT_FOUND`. Mode A
  and the L1 ticket bridge are therefore mutually exclusive on a single
  rollup today. Unifying them needs an `or`-typed rollup parameter (e.g.
  `(or (bytes %kernel) (pair %deposit bytes (ticket ...)))`), the
  orchestrator targeting the `%kernel` entrypoint, and a kernel parser
  that unwraps the Micheline `Left/Right` constructor.
- **The 4096-byte inbox cap blocks full Shield/Transfer bodies
  (sandbox-verified).** An L1 smart-rollup inbox message (internal
  transfers included) is capped at 4096 bytes; the protocol rejects the
  operation at injection with `Failed to encode a rollup management
  protocol inbox message value`. A wire-valid Shield body carries two
  mandatory encrypted notes (~3.4 KiB each, ML-KEM768 ciphertexts) and is
  ~7.1 KiB *before* any real proof — it can never fit. A minimal Unshield
  (no change note) is ~3.7 KiB and fits only with a stub proof. Since real
  STARK proofs are megabytes, Mode A can only ever carry *pointer-sized*
  payloads: practical use requires either exposing a rate-limited
  DAL-pointer entrypoint or Mode B (event + relayer, which has the same
  cap on external messages but can shard via DAL).
- **Atomicity scope.** In Mode A the Michelson op group, the orchestrator
  call, the internal TRANSFER_TOKENS, and the inbox enqueueing all happen
  atomically at L1 op level. But the **rollup execution** of the resulting
  `KernelInboxMessage` happens at the next inbox tick — so a successful
  `%shield` operation only guarantees enqueueing, not application. The
  rollup may still reject the message later (proof invalid, nullifier
  re-use, etc.). Callers should wait for a rollup-level receipt before
  considering the operation final.
- **No Mode-A receipt to the caller.** The orchestrator does not return
  data to the caller — it just enqueues. Rollup-level acknowledgements
  must be observed off-chain (operator HTTP, indexer, etc.). The wallet's
  `RollupSubmissionReceipt` pipeline (`apps/wallet/src/lib.rs:2394`) is
  the reference.
- **`KERNEL_WIRE_VERSION` hard-coded.** The version constant
  (`0x1200` = 18 LE) is inlined in the contract. Any bump of
  `KERNEL_WIRE_VERSION` requires redeploying the orchestrator (or making
  the version a storage field — left as a follow-up to keep the first
  deployment minimal).
- **Staged submission variants not exposed.** Only `Shield`, `Transfer`,
  `Unshield` are user-facing. Verifier/bridge configuration (tags
  `0x00`/`0x01`) and the v18 staged submission messages (`StageChunk`
  `0x07` / `SubmitOps` `0x08`) stay on the off-chain operator path.
  Tag `0x06` (the deleted v17 `DalPointer`) is retired.
- **No fee handling on chain.** The orchestrator rejects any incoming
  `AMOUNT`. XTZ deposits to the shielded pool still go through
  `tez_bridge_ticketer.tz` (the existing path); the orchestrator only
  carries the cryptographic payloads.
- **Admin key is test-only** (per project convention — see
  `CLAUDE.md` *Admin key is test-only*). Mainnet originations should use
  governance, not a single admin key, or omit the admin entrypoints
  entirely.
- **Replay protection.** The kernel already verifies the STARK proof and
  consumes nullifiers (`rollup-kernel/src/lib.rs:1074-1117`) — the
  orchestrator does not add anti-replay on top, but the per-call `nonce`
  is exposed in the `%tzel_inbox` event to give relayers a deterministic
  ordering signal.

---

## 7. File map

| File | Role |
|------|------|
| `tezos/tzel_orchestrator.mligo` | This contract (CameLIGO source). |
| `tezos/tzel_orchestrator.tz`    | Generated Michelson (run `ligo compile contract …`). |
| `tezos/tez_bridge_ticketer.tz`  | Existing XTZ-deposit bridge — unchanged. |
| `tezos/rollup-kernel/src/lib.rs`| Rollup kernel — Mode A requires the §5 delta. |
| `apps/wallet/src/lib.rs`        | Off-chain submitter — still required for direct external submission and for fielding rollup receipts. |
