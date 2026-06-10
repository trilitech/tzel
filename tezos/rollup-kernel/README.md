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
- L1 internal `Transfer` carrying a bridge ticket (credits the
  per-pool aggregated balance keyed by `pubkey_hash =
  H_pubkey(auth_domain, auth_root, auth_pub_seed, blind)` parsed from
  the ticket's `deposit:<hex(pubkey_hash)>` recipient string;
  multiple tickets to the same pool aggregate)
- `shield` (debit the named pool by `v + fee + producer_fee` and
  append the recipient note plus a DAL-producer fee note; the proof
  verifies an in-circuit WOTS+ signature under the recipient's auth
  tree, binding the entire shield request)
- `transfer` (shielded transfer inside the rollup, creating recipient,
  change, and DAL-producer fee notes while burning the protocol fee)
- `unshield` (consume one or more shielded notes, append optional change
  and a DAL-producer fee note, queue a withdrawal record, and emit an
  L1 outbox withdrawal payload directly — there is no separate
  transparent-balance step)
- `configure_verifier` / `configure_bridge` (signed administrative
  messages installing the verifier config and bridge ticketer)

These messages are applied through the shared Rust transition logic in `core/`.

The kernel does not keep the full ledger as one serialized blob. It stores:
- note records under append-only per-index paths
- the commitment-tree append frontier and current root
- valid-root membership markers
- nullifier membership markers
- per-pool aggregated deposit balances keyed by `pubkey_hash`. A pool
  whose balance reaches zero is removed (best-effort delete via empty
  value).
- queued withdrawals under append-only per-index paths
- the configured bridge ticketer (one-shot; reconfiguration is
  rejected once set)
- the verifier config (`auth_domain`, program hashes); also one-shot.

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
- `/tzel/v1/state/deposits/balance/<hex(pubkey_hash)>` — u64 balance
  for the named pool. Empty value or absent key means "no funds".
- `/tzel/v1/state/shields/applied_cm/<hex(client_cm)>` — single-byte
  marker recording that a shield with this `client_cm` has been
  applied. Replay protection.
- `/tzel/v1/state/withdrawals/*`
- `/tzel/v1/state/bridge/ticketer`
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

```bash
TZEL_RUN_ORCHESTRATOR_SANDBOX=1 \
  cargo test -p tzel-rollup-kernel --test octez_orchestrator_sandbox -- --ignored --nocapture
```

The orchestrator smoke (no DAL node needed) originates a `bytes`-typed
rollup plus the `tzel_orchestrator.tz` contract (Mode A,
`Forward_to_rollup`), calls `%shield`/`%unshield` through it, and asserts —
via `/tzel/v1/state/last_result.bin` — that the kernel parses the resulting
internal `Transfer<MichelsonBytes>` inbox entries and dispatches them
through `apply_kernel_message` (deterministic rejections on an unconfigured
verifier). See `scripts/octez_orchestrator_sandbox_smoke.sh` and
`tezos/TZEL_ORCHESTRATOR_README.md` §6 for the Mode A size/typing limits it
documents.

```bash
TZEL_RUN_V18_SANDBOX=1 \
  cargo test -p tzel-rollup-kernel --test octez_v18_sandbox -- --ignored --nocapture
# or run the harness directly:
scripts/octez_v18_sandbox_smoke.sh
```

The v18 smoke (no DAL node, no `ligo`, no orchestrator) drives the DAL-free
submission protocol (`docs/SNARK-SUBMISSION-DESIGN.md`) — `StageChunk`,
`SubmitOps`, `SubmitStagedConfig` — by injecting *external Targetted* inbox
messages with `octez-client send smart rollup message`. The kernel WASM is
built `--no-default-features` (no `tzel-verifier`) with `TZEL_INSECURE_SANDBOX=1`
so the `kernel-test-skip-verify` Groth16 token fires in-rollup; the harness
greps the artifact for the `TZEL_INSECURE_SANDBOX_PROOF_SKIP` canary as a
build-time gate. The skip token bypasses only the Groth16 tree walk +
program-hash binding — the kernel's core output-binding still runs and is
satisfied by the fixture's real `output_preimage`, so a green run is a genuine
durable APPLY, not a TrustMeBro pass. Message wire bytes are produced by the
`octez_kernel_message v18-*` subcommands (`v18-stage-note`, `v18-submit-shield`,
`v18-stage-config-verifier`, `v18-stage-raw`, `v18-submit-staged-config`,
`v18-fixture-meta`, `v18-payload-hash`).

> KNOWN BLOCKER (kernel storage layer, NOT the v18 harness): on the real Octez
> rollup runtime the kernel's `WasmHost::read_store`/`write_store`
> (src/lib.rs ~2760) issue a SINGLE raw `store_read`/`store_write`, which the
> PVM caps at `MAX_FILE_CHUNK_SIZE = 2048` bytes per call. `apply_stage_chunk`
> writes each chunk's `bytes` (≈3.4 KiB per encrypted note, ≈4.9 KiB per signed
> config envelope) in one `write_store`, so the write silently fails and the
> seal-time reassembly reports `staging entry N chunk K is missing`. The
> in-process `bridge_flow.rs` tests miss this because `TestHost` is a HashMap
> with no per-call size cap. The fix lives in kernel src (loop both helpers
> over `MAX_FILE_CHUNK_SIZE`, or use the SDK `store_read_all`/`store_write_all`)
> — out of scope here. Until then every v18 staging scenario reaches the kernel
> and dispatches correctly but cannot SEAL a multi-KiB chunk on real Octez.

The DAL smoke requires `octez-dal-node` in addition to the normal sandbox
dependencies. It spins up a local node, baker, DAL node, rollup node, and
publishes both the signed config messages and the checked-in verified shield
fixture through DAL pointers, then waits for the rollup durable state to reflect
the configuration and shield.

You can then strip it and run it with the Octez smart-rollup debugger as
described in the Tezos smart-rollup tutorial.
