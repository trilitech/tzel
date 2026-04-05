# StarkPrivacy — Status & Direction

## What we have

A privacy protocol (shield, unshield, join/split) implemented in Cairo 2.16.1 with a 48-level Merkle commitment tree. The circuit uses Poseidon for note commitments/nullifiers and supports a configurable Merkle tree hash via feature flags:

- `--features blake` → Blake2s-256 Merkle tree (uses Cairo's native `blake2s_finalize`)
- default → Poseidon Merkle tree (uses Cairo's native Poseidon builtin)
- `--features depth16` / `depth32` / `depth48` → tree depth selection

The `bench.sh` script benchmarks all four operations (shield, unshield, join, split) with both Stwo and Stone provers:

```
./bench.sh                # depth=48
./bench.sh --depth 16     # faster for testing
```

### Current benchmark results (depth=48)

#### Via `reprover` (privacy bootloader + optimized Stwo prover params)

| Operation | Prove  | JSON size | zstd size | Verify |
|-----------|--------|-----------|-----------|--------|
| Shield    | 20.5s  | 2.1 MB    | 850 KB    | 11ms   |
| Unshield  | 19.0s  | 2.1 MB    | 876 KB    | ~11ms  |
| Join      | 18.8s  | 2.1 MB    | 864 KB    | ~11ms  |
| Split     | 19.1s  | 2.2 MB    | 884 KB    | ~11ms  |

Uses proving-utils v1.2.2 privacy bootloader with `CAIRO_PROVER_PARAMS` (96-bit security, Blake2s Merkle channel, log_blowup_factor=3, 23 FRI queries, pow_bits=27).

Note: the old `scarb prove` JSON (~13MB) included substantial metadata beyond the proof itself. The reprover serializes only the `CairoProof` struct.

#### Via `scarb prove` (direct Stwo, for comparison)

| Operation | Stwo prove | Stwo raw JSON | Stone prove | Stone size |
|-----------|-----------|---------------|-------------|------------|
| Shield    | 23s       | 12.5 MB       | 13s         | 941 KB     |
| Unshield  | 25s       | 13.1 MB       | 51s         | 2.2 MB     |
| Join      | 26s       | 13.0 MB       | 50s         | 2.4 MB     |
| Split     | 25s       | 13.0 MB       | 50s         | 2.2 MB     |

Note: `scarb prove` JSON sizes include metadata unrelated to the proof. Not directly comparable.

### Stone proving pipeline

Stone support required significant tooling work:

- `cairo1-run` (lambdaclass/cairo-vm) is incompatible with Cairo 2.16.1 (stuck on 2.12.0-dev, also broken by `size-of` crate on Rust 1.93)
- Replaced with `cairo-execute` v2.16.1 (official starkware binary) which natively supports `.executable.json` and has `--trace-file`, `--memory-file`, `--air-public-input`, `--air-private-input` flags
- Stone prover binaries (`cpu_air_prover`, `cpu_air_verifier`) installed from `dipdup-io/stone-packaging` v3.0.3
- Uses `recursive_with_poseidon` layout (Stone v3.0.3 doesn't support `add_mod`/`mul_mod` builtins in `all_cairo`)
- FRI parameters auto-generated per trace size

## What we explored (and abandoned)

### Stwo → Stone wrapping (Cairo verifier)

The idea: prove with Stwo, then verify the Stwo proof inside a Cairo program, then prove *that* with Stone. This would give smaller Stone proofs.

**Repo:** `starkware-libs/stwo-cairo` has `stwo_cairo_verifier`, a Cairo program that verifies Stwo proofs.

**What worked:**
- Built the stwo-cairo prover (`run_and_prove`) and verifier
- Successfully proved our program with `run_and_prove --program_type executable`
- Successfully verified a test proof inside the Cairo verifier (~13M Cairo steps)

**What didn't:**
- Executable format mismatch: `run_and_prove` (cairo-lang 2.15.0 VM) doesn't properly initialize builtin segments for Cairo 1 executables. The VM creates segments for all builtins in the layout, but the executable only declares `["output", "poseidon"]`, leading to invalid segment ranges in the proof. Cairo 0 `compiled.json` programs work because they declare all builtins.
- Poseidon252 channel overhead: using Poseidon for Stwo's internal Merkle commitments (needed so the Cairo verifier is efficient) makes proving ~37x slower (17s → 638s) because Poseidon is ~100x slower than Blake2s in native computation, and the prover computes millions of hashes for the PCS commitment trees.

**Verdict:** StarkWare says Stone is deprecated. Don't invest more time here.

## Where we're going

Per StarkWare guidance:

1. **Stwo only** — Stone is deprecated, Stwo replaced it on Starknet mainnet in late 2025
2. **Stwo circuit reprover** — shrinks proofs from ~13MB to ~300KB
3. **Long term: Plonkish Stwo circuits** — move away from Cairo/AIR entirely

### Stwo circuit reprover (`proving-utils`)

The `starkware-libs/proving-utils` repo provides library crates (no standalone CLI) for recursive proving:

**`privacy_prove(pie) → ~620KB`** (single-level)
- Takes a CairoPie (from `scarb execute --target bootloader --output cairo-pie`)
- Runs it through a "privacy simple bootloader"
- Generates a Stwo proof

**`privacy_recursive_prove(pie) → ~344KB`** (two-level, the reprover)
- Same input
- Step 1: generates Stwo Cairo proof
- Step 2: verifies that proof inside an Stwo *circuit* (not Cairo), producing a smaller circuit proof
- Output: ~300KB after zstd compression

Both achieve 96 bits of security.

**Key constraints:**
- Input is CairoPie (not `scarb prove` JSON) — the reprover re-proves from the execution trace, not from an existing proof
- Requires Rust nightly (`nightly-2025-07-14`)
- Depends on `cairo-lang 2.17.0-rc.4` and `cairo-vm 3.2.0`
- The privacy bootloader and circuit topology are currently hardcoded — the set of allowed opcodes/builtins is fixed to 57 components
- No CLI binary exists; need to write a thin Rust wrapper

**Proof size comparison:**

| Format | Size |
|--------|------|
| `scarb prove` (raw JSON) | ~13 MB |
| `privacy_prove` (single-level) | ~620 KB |
| `privacy_recursive_prove` (two-level) | ~300 KB |
| On-chain (Groth16 wrap via gnark) | constant (~200 bytes) |

### Reprover binary (`reprover/`)

The `reprover/` directory contains a thin Rust binary that:
1. Takes a `.executable.json` file (from `scarb build`)
2. Runs it through the privacy bootloader from proving-utils v1.2.2
3. Generates a Stwo proof with optimized parameters (96-bit security)
4. Verifies the proof
5. Serializes as JSON + zstd compression

```bash
./reprover/target/release/reprove target/dev/step_shield.executable.json
./reprover/target/release/reprove target/dev/step_shield.executable.json --no-verify -o proof.zst
```

Requires Rust nightly-2025-07-14 (pinned in `reprover/rust-toolchain.toml`).

### Circuit reprover status

The two-level circuit reprover (`privacy_recursive_prove`) failed with an index-out-of-bounds error in `proof_from_stark_proof.rs`. The issue: `prepare_cairo_proof_for_circuit_verifier` expects a proof structure matching exactly the 57 hardcoded `PRIVACY_TRANSACTION_COMPONENTS` and `CAIRO_TRACE_LOG_SIZE=20`. Our programs produce a proof with estimated size 481KB vs expected 621KB — the column layout doesn't match. The privacy circuit was calibrated for a specific Starknet privacy transaction program.

To fix this, we'd need to either:
- Ensure our program produces the exact same column layout (unlikely without matching the original program structure)
- Build a custom circuit verifier configuration for our programs
- Wait for proving-utils to support configurable component sets

## Next steps

1. **Fix circuit reprover** — investigate building a custom `CircuitConfig` / `ProofConfig` for our program's component set, which would bring proofs from ~850KB to ~300KB

2. **Investigate Plonkish Stwo circuits** — the direction StarkWare is pushing for new development, using a circuit DSL instead of Cairo/AIR

3. **Remove Stone from bench.sh** — Stone is deprecated, the reprover pipeline replaces it
