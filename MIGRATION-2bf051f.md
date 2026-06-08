# Migration to stwo-circuits @ 2bf051f

Status: TZEL + proving-utils fork build clean (release). Tests/runtime not yet exercised.

## Why 2bf051f

This is the first stwo-circuits revision containing `circuit_multiverifier` (a
single STARK circuit that verifies N STARK proofs at once). It is the
foundation for TZEL recursive aggregation (G2+).

Previous TZEL pin: `618db0a` (proving-utils main HEAD c0b937bb19's transitive
pin). `618db0a` predates `circuit_multiverifier`.

## What changed

### 1. proving-utils fork

- Cloned `starkware-libs/proving-utils` to `~/git/proving-utils`
- Branch `feat/bump-stwo-circuits-2bf051f` based on `c0b937bb19`
- `crates/privacy_circuit_verify/Cargo.toml` + `crates/privacy_prove/Cargo.toml`:
  `rev "618db0a"` → `"2bf051f"` (all 7 stwo-circuits sub-crates)
- `crates/privacy_circuit_verify/src/lib.rs:181`:
  `output_addresses: CIRCUIT_OUTPUT_ADDRESSES.to_vec()` → `n_outputs: CIRCUIT_OUTPUT_ADDRESSES.len()`
  (`CircuitConfig` lost `output_addresses` at 2bf051f — replaced by `n_outputs: usize`)

### 2. TZEL (this repo)

Cargo manifests:
- `verifier/Cargo.toml`
- `services/reprover/Cargo.toml`
- `ocaml/services/prover_bridge/Cargo.toml`

Changes per manifest:
- proving-utils crates (cairo-program-runner-lib, privacy-prove, privacy-circuit-verify):
  `git = ".../proving-utils"` → `path = "/home/saroupille/git/proving-utils/crates/..."`
- stwo-circuits crates: `rev = "618db0a"` → `rev = "2bf051f"`
- Added `circuit-multiverifier` dep (new at 2bf051f)

Source migrations (mechanical, same pattern as proving-utils):
- `verifier/src/bundle.rs:288`: `output_addresses` → `n_outputs`
- `services/reprover/src/custom_circuit.rs:385`: `output_addresses` → `n_outputs`

Workspace plumbing (new files):
- `services/reprover/rust-toolchain.toml`: pin nightly-2025-07-14
- `services/reprover/Cargo.toml`: appended empty `[workspace]` table (this crate is
  standalone, not in root workspace `members`)
- `ocaml/services/prover_bridge/rust-toolchain.toml`: pin nightly-2025-07-14
- `ocaml/services/prover_bridge/Cargo.toml`: appended empty `[workspace]` table

Drift fix (NOT related to 2bf051f, surfaced by fresh Cargo.lock resolve):
- `ocaml/services/prover_bridge/src/prove.rs:57`: `CairoPie::read_zip_file(&p, None)`
  → `CairoPie::read_zip_file(&p)`. cairo-vm 3.2.0 dropped the second arg —
  pre-existing breakage that was masked by stale lockfile.

Lockfile pinning (`Cargo.lock` for reprover and prover_bridge):
- `ruint` 1.18.0 → 1.12.3 (`cargo update -p ruint --precise 1.12.3`)
- 1.18.0 calls `slice::reverse()` in a `const fn`, which is not stable on
  nightly-2025-07-14. proving-utils' own build doesn't hit this because it
  doesn't pull `stwo-cairo-common` (the only path to ruint). reprover and
  prover_bridge do.

## Build status

| Crate | Build (release) | Notes |
|-------|-----------------|-------|
| proving-utils workspace | ✅ | path-dep target for TZEL |
| tzel-verifier | ✅ | 1 source migration |
| tzel-reprover | ✅ | 1 source migration + toolchain + workspace marker + ruint pin |
| tzel-prover (prover_bridge) | ✅ | + cairo-vm drift fix + ruint pin |

Tests (`cargo test`) and runtime behavior NOT exercised yet.

## Known TODOs before any PR

1. **proving-utils tests** — `privacy_circuit_verify/src/tests.rs:102` asserts
   `preprocessed_circuit.params.output_addresses == CIRCUIT_OUTPUT_ADDRESSES`.
   `params.output_addresses` no longer exists at 2bf051f. Must port the assert
   (likely to `n_outputs` + a separate addresses check) before upstream PR.

2. **Path deps** — all 3 TZEL Cargo.toml use absolute path
   `/home/saroupille/git/proving-utils/crates/...`. NOT portable. Before any
   commit pushed to remote, switch to either:
   - relative path (`../../../proving-utils/...`), or
   - git URL pointing to a pushed branch of the fork.

3. **Workspace markers + `rust-toolchain.toml`** — these are new files.
   Decide where they live long-term (in the crate dirs as today, or hoist
   `rust-toolchain.toml` to root).

## Reproduction commands

```bash
# proving-utils fork
cd ~/git/proving-utils
cargo build --release

# TZEL crates (each in its own workspace)
cd ~/git/tzel
cargo build --release -p tzel-verifier

cd ~/git/tzel/services/reprover
cargo build --release

cd ~/git/tzel/ocaml/services/prover_bridge
cargo build --release
```

## Next: G2 — multiverifier aggregation harness

Build a binary tree of `circuit_multiverifier` nodes in `services/reprover/`
that takes N TZEL STARK proofs and produces a single root STARK proof
(to be wrapped by Groth16 downstream).

The `circuit-multiverifier` crate is now available in all 3 TZEL manifests.

## G2 — DONE (build clean)

`services/reprover/src/aggregate.rs` exposes:
- `AggregationShape { Leaf, Internal }`
- `AggregationNode { proof, shape }`
- `AggregationContext::new(leaf_preprocessed, leaf_pcs_config)` — computes
  per-shape SharedConfig + PreprocessedCircuit
- `aggregate_pair(ctx, left, right)` — verifies 2 STARK proofs inside one
  multiverifier circuit, returns the new STARK proof
- `aggregate_tree(ctx, leaves)` — binary tree (N must be power of two)

`services/reprover/src/custom_circuit.rs` refactored: extracted
`run_leaf_pipeline_internal` so that both `custom_recursive_prove` (existing
serialize+verify path) and `produce_leaf_artifacts` (new aggregation entry
point) share the leaf-proof body. New struct `LeafArtifacts` exposes the
raw `CircuitProof` + `Arc<PreprocessedCircuit>` + `pcs_config` to the
aggregator.

## G3 — DONE (E2E aggregation validated, 4 → 1 in ~4 min)

`services/reprover/tests/aggregation_e2e.rs::aggregate_four_leaves_to_root` —
generates 4 leaves from `run_shield` + bench args, runs `aggregate_tree`,
asserts the root has multiverifier shape. Passes in 224s.

The fix that unblocked it was distinguishing the two multiverifier topologies
in `AggregationContext`: `leaf_to_mv_preprocessed` for level 0 → 1 (verifies
leaf-shape proofs) and `mv_to_mv_preprocessed` for level ≥ 1 (verifies
multiverifier-shape proofs). Earlier revisions reused a single preprocessed
for both, causing silent witness corruption at level ≥ 1 (xor_8 / eq panics
during `prove_circuit_assignment`).

## G3.5 — Cross-program aggregation validated

`services/reprover/tests/aggregation_cross_program.rs::aggregate_two_shields_two_transfers`
— 2× shield + 2× transfer → 1 root, passes in ~263s. Confirms that the
privacy bootloader's normalization is sufficient for cross-program
aggregation in the current TZEL family.

Also added `services/reprover/tests/g4_cross_program_check.rs` as a fast
(~80s) diagnostic that dumps shield + transfer `enable_bits` and
`component_log_sizes`. Findings:
- `enable_bits` ARE identical between shield and transfer (46/83 same mask).
- `component_log_sizes` differ per-component (shield max 20, transfer max 20,
  distributions differ). These are public inputs to the inner verifier, not
  topology metadata in `CairoVerifierConfig`, so the multiverifier handles
  them transparently.

## G4 — Deferred (not required for current TZEL programs)

The "force enable_bits canonical via Cairo prologue" task is unnecessary at
this stage: the bootloader already produces identical `enable_bits` for
shield/transfer (and almost certainly unshield, same crypto profile).
Cross-program aggregation works without a prologue.

A canonical prologue WOULD become required when adding a TZEL program that
activates a different opcode subset (e.g. `ec_op_builtin`, currently
disabled). Track as a future-work item, do not block G5 / G6.

## Old "G3 — PARTIAL" diagnosis (kept for context)

`services/reprover/tests/aggregation_e2e.rs`:
- Fixture: `cairo/target/dev/run_shield.executable.json` + pre-generated
  bench-witness args at `services/reprover/tests/fixtures/run_shield_args.json`
  (regenerate with `cargo run -p tzel-services --bin gen_proof_bench_args -- shield > services/reprover/tests/fixtures/run_shield_args.json`).
- Marked `#[ignore]` (heavy: ~3–6 min). Compiles clean.

What WORKS at 2bf051f:
- 4 TZEL leaf proofs generated (~40-55s each, log_blowup=2, 46 components enabled)
- AggregationContext sets up leaf + internal SharedConfig with correct
  `lifting_log_size` for both shapes
- `build_multiverifier_circuit(leaf0, leaf1, &leaf_shared_config)` passes
  `is_circuit_valid` (the circuit constraints are locally satisfied — both
  leaf proofs verify INSIDE the multiverifier circuit symbolically)

What FAILS:
- `prove_circuit_assignment(node_ctx.values(), &internal_preprocessed, ...)`
  panics at `circuit_prover::witness::components::verify_bitwise_xor_8::add_input`:
  `input_to_row.get(input).unwrap()` returns `None`. The 8-bit XOR lookup
  table built from the multiverifier's preprocessed_trace is missing the
  input value that the prover is trying to look up.

Diagnostic:
- The same setup pattern (`build_multiverifier_circuit::<NoValue>` →
  `PreprocessedCircuit::preprocess_circuit`) works in stwo-circuits' own
  `test_multiverifier_tree_depth_2` (privacy fixture).
- The privacy fixture leaf does NOT apply ZK blinding. TZEL leaves do
  (via `add_zk_blinding`).
- ZK blinding injects extra `qm31_ops` / `eq` components that change the
  inner verifier topology. The multiverifier's preprocessed trace —
  built once with `<NoValue>` `empty_proof` — likely doesn't see those
  blinding-driven lookups, so its xor_8 table lacks the rows the prover
  needs at runtime.

To unblock G3:
- Option A: generate aggregation-input leaves WITHOUT ZK blinding. Re-add
  blinding only at the multiverifier root (one ZK proof for the whole tree).
- Option B: ensure the multiverifier's NoValue topology fully exercises the
  ZK-blinded shape so its preprocessed trace covers those lookups.

Option A is simpler and aligns with how recursion stacks usually work
(blinding at the outermost layer). Option B is more general but requires
threading the blinding parameters through `build_multiverifier_circuit`.
