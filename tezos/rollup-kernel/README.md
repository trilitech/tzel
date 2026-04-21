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

The kernel does not keep the full ledger as one serialized blob. It stores:
- note records under append-only per-index paths
- the commitment-tree append frontier and current root
- valid-root membership markers
- nullifier membership markers
- per-account bridge balances used for deposit/withdrawal accounting
- queued withdrawals under append-only per-index paths

The current POC kernel uses a simple congestion fee policy for private
transactions:

- floor: `100000` mutez
- first two accepted private transactions per inbox level pay that floor
- each additional accepted private transaction at that same level doubles the
  required burn fee
- the doubling schedule is capped after 6 steps
- when the inbox level advances, the required fee resets to the floor

Durable storage paths:
- `/tzel/v1/stats/raw_input_count`
- `/tzel/v1/stats/raw_input_bytes`
- `/tzel/v1/state/last_input_level`
- `/tzel/v1/state/last_input_id`
- `/tzel/v1/state/last_input_len`
- `/tzel/v1/state/last_input_payload`
- `/tzel/v1/state/fees/*`
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
publishes both the signed config messages and the checked-in verified shield
fixture through DAL pointers, then waits for the rollup durable state to reflect
the configuration and shield.

You can then strip it and run it with the Octez smart-rollup debugger as
described in the Tezos smart-rollup tutorial.
