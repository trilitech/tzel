# TzEL rollup kernel MVP

This crate is a Tezos smart-rollup kernel scaffold for TzEL.

Scope:
- raw WASM host-function bindings
- shared-ledger integration through `tzel-core`
- verifier-only proof checks through `tzel-verifier`
- durable storage for inbox accounting plus path-addressed rollup state
- host-mock unit tests for the kernel loop

The kernel consumes Tezos Data Encoding inbox messages and records:
- total inbox message count
- total inbox bytes seen
- last inbox message level/id
- last inbox payload

Supported message kinds:
- `deposit` (bridge-balance credit after an L1 deposit is observed)
- `shield` (convert credited bridge balance into a user note plus a DAL-producer fee note, and burn the protocol fee)
- `transfer` (shielded transfer inside the rollup, creating recipient, change, and DAL-producer fee notes while burning the protocol fee)
- `unshield` (consume a shielded note, burn the protocol fee, credit transparent rollup balance, and append the DAL-producer fee note plus optional change)
- `withdraw` (debit transparent rollup balance and emit an L1 outbox withdrawal payload)

These messages are applied through the shared Rust transition logic in `core/`.

## Admin configuration messages and DAL routing

Two admin-signed messages configure the rollup post-origination:

- `ConfigureVerifier` — sets the expected Cairo program hashes (shield /
  transfer / unshield) and the STARK auth domain.
- `ConfigureBridge` — sets the KT1 ticketer contract whose tickets the
  kernel will accept as legitimate deposit receipts.

Both are signed with a WOTS one-time signature authenticated by a leaf
baked into the kernel WASM at build time (`admin-material`,
`TZEL_ROLLUP_{VERIFIER,BRIDGE}_CONFIG_ADMIN_LEAF_HEX`).  The WOTS
signature accounts for most of the message size (`WOTS_CHAINS × F` =
133 × 32 = 4256 bytes).

### Delivery invariant

The Tezos protocol constant `sc_rollup_message_size_limit` caps L1 inbox
external messages at **4096 bytes**.  Both admin config messages exceed
this limit once signed:

| Message              | Serialized size | L1 inbox viable? |
|----------------------|----------------:|:-----------------|
| `ConfigureVerifier`  | 4923 bytes      | ❌ must use DAL  |
| `ConfigureBridge`    | 4835 bytes      | ❌ must use DAL  |

They are therefore routed through the DAL delivery path, same as
`Shield`, `Transfer`, `Unshield`.  The flow:

1. Operator computes the unframed `KernelInboxMessage` bytes via the
   `configure-{verifier,bridge}-payload` subcommands of
   `octez_kernel_message`.
2. Operator chunks the bytes, publishes them as DAL slots, waits for
   attestation.
3. Operator injects into the L1 inbox a small `DalPointer` message
   (framed via `ExternalMessageFrame::Targetted`) whose `kind` field
   (`configure_verifier` / `configure_bridge`) tells the kernel how to
   interpret the DAL payload.
4. Kernel's `fetch_kernel_message_from_dal` reassembles the chunks,
   verifies the hash, decodes as `KernelInboxMessage`, and dispatches
   based on `pointer.kind ↔ message` consistency.

### Adding a new oversized message type

If a future message exceeds 4096 bytes and must reach the kernel:

1. Add a variant to `KernelDalPayloadKind` in `core/src/kernel_wire.rs`
   (next free wire tag).
2. Add the reciprocal arm in `fetch_kernel_message_from_dal` in this
   crate's `lib.rs` and in `dal_payload_kind_name`.  The outer match
   is exhaustive on `KernelDalPayloadKind`, so the compiler will
   refuse to build until both arms are present.
3. Decide which submission path applies:
   - **User-facing payloads** (Shield / Transfer / Unshield and
     similar): mirror the variant in `RollupSubmissionKind` and the
     operator's `kernel_message_matches_submission_kind` /
     `dal_pointer_from_submission`, so the wallet can submit via the
     operator.
   - **Admin-signed payloads** (`Configure*` and anything else
     authenticated by the config-admin WOTS key): do **not** route
     through the operator.  Admin messages are injected directly with
     `octez_kernel_message` + `octez-client send smart rollup
     message`, using the admin's own L1 key and WOTS ask.  This keeps
     the operator surface narrow and prevents a bearer-token leak
     from granting admin injection.
4. Update the `octez_kernel_message` CLI: add a `<cmd>-payload`
   subcommand that outputs the raw unframed bytes, and extend
   `parse_dal_kind` with the new token.
5. Add a size-sentinel test under `core/src/kernel_wire.rs::tests`
   (see `configure_verifier_serialized_size_sentinel`).  The
   variant-exhaustive test `inbox_size_invariant_covers_all_variants`
   will also refuse to build until the new variant is classified as
   `FitsL1` or `RequiresDal` in its `required_routing`.

If a change *reduces* an existing message below 4096 bytes, the direct
L1 path becomes usable again but the DAL path can remain for uniformity
— review on a case-by-case basis.

The kernel does not keep the full ledger as one serialized blob. It stores:
- note records under append-only per-index paths
- the commitment-tree append frontier and current root
- valid-root membership markers
- nullifier membership markers
- per-account bridge balances used for deposit/withdrawal accounting
- queued withdrawals under append-only per-index paths

Durable storage paths:
- `/tzel/v1/stats/raw_input_count`
- `/tzel/v1/stats/raw_input_bytes`
- `/tzel/v1/state/last_input_level`
- `/tzel/v1/state/last_input_id`
- `/tzel/v1/state/last_input_len`
- `/tzel/v1/state/last_input_payload`
- `/tzel/v1/state/auth_domain`
- `/tzel/v1/state/tree/*`
- `/tzel/v1/state/notes/*`
- `/tzel/v1/state/roots/*`
- `/tzel/v1/state/nullifiers/*`
- `/tzel/v1/state/balances/*`
- `/tzel/v1/state/withdrawals/*`
- `/tzel/v1/state/verifier_config.bin`
- `/tzel/v1/state/last_result.bin`

This crate reuses the shared state-transition logic and verifies proofs
in-kernel without linking prover code.

Build the kernel WASM:

```bash
./scripts/build_rollup_kernel_release.sh
```

The resulting kernel is at:

```text
target/wasm32-unknown-unknown/release/tzel_rollup_kernel.wasm
```

That helper also generates or reuses rollup configuration-admin material under
`target/rollup-config-admin/` and bakes the derived public values into the
release kernel build.

For live bridge deposits, originate the rollup with a ticket-bearing parameter
type:

```text
(pair bytes (ticket (pair nat (option bytes))))
```

Originating it as plain `bytes` is sufficient for external messages, but it does
not allow the L1 ticketer contract to deliver ticket transfers into the inbox.
The minimal tez bridge contract validated for this flow lives at
`tezos/tez_bridge_ticketer.tz`.

Local Octez sandbox smokes:

```bash
TZEL_RUN_OCTEZ_ROLLUP_SANDBOX=1 \
  cargo test -p tzel-rollup-kernel --test octez_sandbox -- --ignored --nocapture
```

```bash
TZEL_RUN_OCTEZ_ROLLUP_SANDBOX_DAL=1 \
  cargo test -p tzel-rollup-kernel --test octez_sandbox_dal -- --ignored --nocapture
```

The DAL smoke requires `octez-dal-node` in addition to the normal sandbox
dependencies. It spins up a local node, baker, DAL node, rollup node, and
`tzel-operator`, then submits the checked-in verified shield fixture through the
operator and waits for the rollup durable state to reflect the shield.

You can then strip it and run it with the Octez smart-rollup debugger as
described in the Tezos smart-rollup tutorial.
