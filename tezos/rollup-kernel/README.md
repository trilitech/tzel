# TzEL rollup kernel MVP

This crate is the first Tezos smart-rollup kernel scaffold for TzEL.

Current scope:
- raw WASM host-function bindings
- shared-ledger integration through `tzel-core`
- verifier-only proof checks through `tzel-verifier`
- durable storage for inbox accounting plus path-addressed rollup state
- host-mock unit tests for the kernel loop

The kernel currently consumes Tezos Data Encoding inbox messages, records:
- total inbox message count
- total inbox bytes seen
- last inbox message level/id
- last inbox payload

Supported message kinds:
- `fund` (bridge-balance credit after an L1 deposit is observed)
- `shield` (convert credited bridge balance into a shielded note)
- `transfer` (shielded transfer inside the rollup)
- `unshield` (consume a shielded note and credit an L1 withdrawal recipient)

These messages are applied through the shared Rust transition logic in `core/`.

The kernel does not keep the full ledger as one serialized blob. It stores:
- note records under append-only per-index paths
- the commitment-tree append frontier and current root
- valid-root membership markers
- nullifier membership markers
- per-account bridge balances used for deposit/withdrawal accounting

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
- `/tzel/v1/state/verifier_config.bin`
- `/tzel/v1/state/last_result.bin`

This is still intentionally narrower than the eventual TzEL rollup
integration. The kernel now reuses the shared state-transition logic and
verifies proofs in-kernel without linking prover code.

Build the kernel WASM:

```bash
rustup target add wasm32-unknown-unknown
cargo build -p tzel-rollup-kernel --target wasm32-unknown-unknown --release
```

The resulting kernel is at:

```text
target/wasm32-unknown-unknown/release/tzel_rollup_kernel.wasm
```

You can then strip it and run it with the Octez smart-rollup debugger as
described in the Tezos smart-rollup tutorial.
