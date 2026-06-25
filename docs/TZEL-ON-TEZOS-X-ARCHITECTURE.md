# TzEL on Tezos X — target architecture

Status: DESIGN (2026-06-10). Supersedes the rollup-kernel approach
(branch `feat/reprove-bin-output`). Decision: build TzEL as a **privacy
application on top of Tezos X** — a Michelson smart contract that calls
**verification primitives offered by the Tezos X runtime** — rather than
as a bespoke smart-rollup kernel. Modelled on Tezos Sapling
(`SAPLING_VERIFY_UPDATE` + `sapling_state`), generalised to STARK/SNARK.

This memo specifies the three layers and the user flow.

```
┌──────────────────────────────────────────────────────────────┐
│  tzel-wallet (off-chain)                                       │
│  builds notes, runs the prover, assembles the operation        │
└───────────────────────────┬──────────────────────────────────┘
                            │ Michelson call (shield/transfer/unshield)
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  TzEL Michelson contract  (the application — services)         │
│  holds: commitment tree, nullifier set, roots, deposits        │
│  enforces: the off-proof obligations; updates the ledger       │
└───────────────────────────┬──────────────────────────────────┘
                            │ VERIFY_SNARK / VERIFY_STARK / BLAKE2S
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  Tezos X runtime  (MIR Michelson interpreter — primitives)     │
│  enshrined verification instructions, generic to any ZK app    │
└──────────────────────────────────────────────────────────────┘
```

The proof system itself is unchanged: a TzEL operation is a Cairo (stwo)
STARK, aggregated through the `circuit_multiverifier`, wrapped in a
388-byte Groth16 BN254 proof. Verification of that proof is what the
runtime primitive performs.

---

## Layer 1 — the privacy runtime's verify (a cross-runtime call, NOT a Michelson primitive)

> **Decision (validated 2026-06-23). The verify is a FUNCTION exported by a
> privacy RUNTIME, invoked from Michelson via Tezos X's cross-runtime
> composition (CRAC) — the same mechanism as EVM↔Michelson calls.** It is
> NOT a new Michelson instruction, NOT an EVM-style precompile, and NOT an
> enshrined MIR primitive. The "privacy runtime" = the existing wasm-clean
> `tzel-verifier::verify_snark` packaged as a callable runtime. Reuses what
> we already have + Tezos X's native multi-runtime composability — no
> Michelson-language amendment, no protocol-level primitive work.
>
> **One call does everything.** `verify_snark(vk, proof, output_preimage)`
> bundles, inside the runtime: (a) the Groth16-BN254 pairing check, (b) the
> proof↔op binding — re-derive the OutHash from `output_preimage`
> (`BLAKE2S` for `output_values`, then `POSEIDON2_BN254` for the wrap
> re-commit) and assert it equals the proof's pinned OutHash, (c) parse and
> **return `(program_hash, public_outputs)`** (or an error). So the
> **Michelson contract needs NO `VERIFY_SNARK`/`BLAKE2S`/`POSEIDON2_BN254`
> primitives of its own** — the binding lives inside the runtime call; the
> contract just cross-runtime-calls verify, then compares the returned
> `program_hash` and runs its ledger checks.

The signatures in §1.1–§1.2b below describe what the runtime verify does
**internally** (the service ABI), not separate Michelson opcodes.

### 1.1 `VERIFY_SNARK` (required)

```
VERIFY_SNARK
  :: bytes        -- verifying key (Groth16 BN254 vk, gnark-serialised)
  -> bytes        -- proof        (388-byte Groth16, gnark-serialised)
  -> list bytes   -- public inputs (field elements, 32-byte big-endian each)
  -> bool
```

Pure cryptographic check: the Groth16 pairing equation over the supplied
public inputs, including gnark's Pedersen-commitment splice (the wrap
circuit uses `frontend.Commit`). Returns `true` iff the proof verifies.
**Generic** — knows nothing about TzEL; any ZK app can call it. The
reference implementation is the existing `tzel-verifier::groth16`
(`verify_groth16_wrap` / arkworks BN254), already wasm-clean and tested
against real artifacts (11/11). Gas: ~constant (a few pairings),
benchmark-pinned.

Design note: the vk is passed as `bytes` so the contract pins its own
trusted vk in storage (rotation = a contract admin/governance action, not
a protocol amendment). Alternatively the vk can be a protocol constant if
Tezos X wants a single blessed wrap circuit.

### 1.2 `BLAKE2S` (required for the binding)

```
BLAKE2S :: bytes      -- personalization (8 bytes; empty = none)
        -> bytes      -- data
        -> bytes      -- 32-byte digest
```

TzEL's proof-to-operation binding (below) is a BLAKE2s chain (the chip's
`OutHash` and the multiverifier fold use BLAKE2s over M31 lanes, not
BLAKE2b). The contract also maintains the note commitment Merkle tree,
whose `hash_merkle` is BLAKE2s **personalized** with `"mrklSP__"`
(domain separation; `core/src/lib.rs:208`). So the instruction must take
an 8-byte **personalization** parameter (the blake2s parameter-block
field — *not* a prefix of the data; plain BLAKE2b/Keccak can't express
it). Empty personalization = standard BLAKE2s (used by the OutHash
`blake_qm31`).

Scope note: TzEL uses several personalizations (`mrklSP__`, `nulfSP__`,
`cmmtSP__`, …), but the **contract** only needs `mrklSP__` (the tree) and
the empty one (the multiverifier-level `output_values`). The others —
nullifier/commitment derivation — live *inside the proof*; the contract
receives those values and only checks set-membership/uniqueness, never
recomputes them. Trivial addition next to the existing BLAKE2b/Keccak
instructions.

### 1.2b `POSEIDON2_BN254` (required for the OutHash binding)

```
POSEIDON2_BN254 :: list bytes   -- field elements to absorb (BN254 Fr, 32B BE each)
                -> bytes        -- sponge digest (a BN254 Fr, 32B)
```

The **item-D** wrap re-commits its OutHash in BN254 (not blake2s): the
chip's `out_hash` public output is
`POSEIDON2_BN254(preprocessed_root ‖ output_values M31 limbs)` mapped to 8
M31 lanes (chip `outputHash`, crosscheck-validated against the off-circuit
reference). So the contract's binding (§2.3 check 2) recomputes through this
sponge. Reference impl = the same Poseidon2-BN254 the wrap verify already
uses (wasm-clean). A new hashing primitive **alongside** `BLAKE2S` — both
are needed: `BLAKE2S` for the commitment tree + the `output_values` level,
`POSEIDON2_BN254` for the final re-commit. (This is a v1-required primitive,
not future/optional.)

### 1.3 `VERIFY_STARK` (future / optional)

```
VERIFY_STARK
  :: bytes        -- proof-system config / vk identity
  -> bytes        -- raw stwo STARK proof
  -> list bytes   -- public inputs
  -> bool
```

Verifies a raw stwo (Circle-STARK) proof directly, without the Groth16
wrap. Reference impl: `tzel-verifier::DirectProofVerifier` /
`verify_stark_bundle` (kept exposed, dormant). **Not usable until the DAL
is activated**: a raw STARK proof is multi-MB and exceeds the Michelson
calldata budget, so its transport needs DAL. Enshrined for the future;
TzEL v1 uses only `VERIFY_SNARK` (388 bytes fits inline).

### What stays out of the runtime

No note logic, no nullifier set, no Merkle tree, no TzEL types. The
runtime offers verification + hashing; **all application state and policy
live in the Michelson contract**. This is the Sapling split (the protocol
verifies a state-update proof; the contract owns the `sapling_state`),
generalised.

---

## Layer 2 — TzEL Michelson contract (the services)

A single Michelson contract (LIGO) holds the shielded ledger and exposes
the privacy operations. It is the only stateful, trusted-policy component.

### 2.1 Storage

```
type storage = {
  // ── identity / config (write-once, admin) ──
  verifier_vk        : bytes;                 // Groth16 wrap vk (Layer 1 input)
  auth_domain        : bytes;                 // 32B — domain-separates this ledger
  program_hashes     : { shield : bytes; transfer : bytes; unshield : bytes };
  bridge_ticketer    : address;               // KT1 minting/burning XTZ tickets

  // ── shielded ledger ──
  commitment_root    : bytes;                 // current Merkle root
  commitment_size    : nat;                   // # leaves
  frontier           : list bytes;            // DEPTH=48 frontier nodes
  notes              : big_map nat bytes;     // index → encrypted note payload
  nullifiers         : big_map bytes unit;    // spent-note markers
  roots              : big_map bytes unit;    // valid-root membership
  roots_fifo         : list bytes;            // bounded history (≤ 4096)
  applied_shields    : big_map bytes unit;    // client_cm → replay marker

  // ── bridge ──
  deposits           : big_map bytes nat;     // pubkey_hash → escrowed XTZ
}
```

Every structure maps to a Michelson `big_map` (sparse, lazy durable
storage) or a small record. No structure requires a runtime primitive
beyond hashing.

### 2.2 Entrypoints (services)

| Entrypoint | Caller | Effect |
|---|---|---|
| `%configure(vk, auth_domain, program_hashes, ticketer)` | admin (once) | pins the verification identity |
| `%deposit` | bridge ticketer (L1 XTZ → ticket) | credits `deposits[pubkey_hash] += amount` |
| `%shield(proof, op_publics, enc_notes)` | user | escrowed XTZ → shielded notes |
| `%transfer(proof, op_publics, enc_notes)` | user | shielded → shielded (consume + create) |
| `%unshield(proof, op_publics, enc_notes)` | user | shielded → XTZ withdrawal + change |

`op_publics` carries the operation's public data (the bootloader
`output_preimage`: program_hash + the op's public outputs — value, fee,
nullifiers, commitments, recipient hash, memo hashes). `enc_notes` are the
encrypted payloads (opaque blobs the contract stores, wallets decrypt).

### 2.3 The verification + binding the contract performs

For each op the contract runs **five checks** before mutating state. The
proof attests *local* correctness; the contract enforces *global*
consistency. This is the crux of the port — what must live outside the
proof:

1. **SNARK verify** — `VERIFY_SNARK(verifier_vk, proof, [tree_roots ‖ out_hash])`.
   The wrap's public inputs are the 4 STARK tree roots (128 bytes) + the
   8-lane `OutHash`.
2. **Proof↔operation binding** — recompute `expected_out_hash` from
   `op_publics` and assert it equals the proof's `out_hash`. The **item-D
   ABI** is `out_hash = POSEIDON2_BN254(preprocessed_root ‖ output_values)`
   with `output_values = BLAKE2S(output_preimage)` — so the recompute needs
   **both** primitives: `BLAKE2S` for the multiverifier-level `output_values`,
   then `POSEIDON2_BN254` for the wrap's BN254 re-commit. (The wrap's OutHash
   was blake2s pre-item-D; the Poseidon2-BN254 sponge replaced it so the
   BN254 wrap re-commits in its own field — see chip `outputHash`.) Prevents
   pairing a valid proof with a different op's data (second-preimage,
   ~2⁻¹²⁸).
3. **Circuit binding** — parse `program_hash` from `op_publics`, assert it
   equals `program_hashes.{shield|transfer|unshield}` for this entrypoint,
   and assert `auth_domain` matches. Binds the proof to *this* circuit and
   *this* ledger.
4. **Ledger preconditions** (per op):
   - shield: `deposits[pubkey_hash] ≥ v+fees`; `applied_shields[client_cm]` absent (replay).
   - transfer/unshield: `roots[root]` present (valid, possibly stale root);
     each nullifier absent from `nullifiers` and unique within the batch.
   - memo binding: `BLAKE2S(enc_note)` equals the proof's memo hash.
5. **Commit** (infallible ordering): debit deposits / append commitments
   (`frontier` + `root` + `size`) / insert nullifiers / snapshot root /
   for unshield, **emit the L2→L1 withdrawal first**, then mutate the tree
   (atomicity: an observed withdrawal must never roll back).

Everything here is plain Michelson arithmetic, `big_map` membership, and
`BLAKE2S` — no further primitive needed. For a single-op submission the
"aggregation tree" is depth-1 (one real leaf + padding), so the
multiverifier tree-walk reduces to one blake fold; batched submission
(many ops, one proof) is a v2 optimisation.

### 2.4 What dissolves vs the rollup kernel

The v18 inbox wire, StageChunk staging, DAL pointers, the
prepare/commit-durable split, and the sender-attribution machinery were
all **rollup-inbox artefacts**. As a Michelson contract these vanish:
calldata replaces the inbox, `big_map` replaces hand-rolled durable
chunking, Michelson's atomic call replaces prepare/commit. The 388-byte
Groth16 fits in calldata, so no chunking/DAL is needed for v1.

---

## Layer 3 — User flow via tzel-wallet

A `shield` from a user's perspective (transfer/unshield analogous):

```
1. Deposit (one-time funding)
   wallet → bridge: send XTZ, mint a ticket, deliver to the TzEL contract
   contract.%deposit credits deposits[pubkey_hash]

2. Build the operation (off-chain, in the wallet)
   - pick deposit + amounts, derive the new note commitments client_cm /
     producer_cm, encrypt the note payloads (ML-KEM768)
   - assemble the Cairo witness, run the prover pipeline:
       Cairo STARK  →  L2 reprove  →  multiverifier aggregate  →  Groth16 wrap
     yielding (proof 388B, tree_roots, out_hash, output_preimage)
   - prove time today: ~minutes on CPU; the wallet calls a prover service
     (the operator), not the user's laptop, for the heavy step

3. Submit (one Michelson call)
   wallet → contract.%shield(proof, op_publics, [client_enc, producer_enc])
   the contract runs the 5 checks (§2.3) and, on success, escrows→notes

4. Observe
   the wallet scans the contract's notes big_map, trial-decrypts payloads
   with its viewing keys, learns its new spendable notes + the new root
```

`transfer`: the wallet selects input notes (it knows their tree paths from
scanning), computes nullifiers, proves the spend, and calls `%transfer`.
`unshield`: same, plus a public `recipient` + `v_pub`; the contract emits
the L2→L1 withdrawal and the bridge releases XTZ.

Key UX consequences of the Michelson design:
- **No rollup inbox / DAL latency** for v1 — submission is a normal
  Michelson operation; finality is L1 finality.
- **Composability** — other Tezos X contracts can call TzEL entrypoints or
  read its public roots; the bridge is a normal L1 contract interaction,
  not an inbox/outbox workaround.
- The wallet's prover orchestration is unchanged from today (the proof
  system is identical); only the *submission target* changes from a rollup
  inbox message to a Michelson contract call.

---

## What must be true for this to ship

| Dependency | Owner | Status |
|---|---|---|
| `VERIFY_SNARK` instruction in MIR | Tezos X protocol | to enshrine (~4-5 files + amendment; pattern = `PAIRING_CHECK`) |
| `BLAKE2S` instruction in MIR | Tezos X protocol | to enshrine (trivial, next to BLAKE2b) |
| Reference verify impl (arkworks BN254) | TzEL | ✅ exists (`tzel-verifier`, wasm-clean, 11/11 vs real proof) |
| Groth16 wrap vk (mv-target) | TzEL | ✅ produced (cloud Setup, on GCS) |
| TzEL Michelson contract (LIGO) | TzEL | to build (~700-900 LOC; state + the 5 checks) |
| `VERIFY_STARK` instruction | Tezos X protocol | future (needs DAL for large-proof transport) |

The only hard external dependency is the `VERIFY_SNARK` (+ `BLAKE2S`)
runtime instruction. Until it lands, the contract can be prototyped
against a stubbed verify to validate that the state machine holds in
Michelson (the least-certain part of the feasibility study).

---

## Resolved design decisions (2026-06-10)

1. **vk placement → contract-pinned.** The wrap vk lives in the TzEL
   contract storage, set by an admin/governance entrypoint. Circuit
   upgrades (soundness bump, stwo-circuits revision) rotate the vk via a
   contract operation, with no protocol amendment. Keeps `VERIFY_SNARK`
   generic (it verifies any Groth16 against a caller-supplied vk).

2. **Primitive abstraction → thin `VERIFY_SNARK` + `BLAKE2S`.** The runtime
   stays generic; the OutHash binding lives in the contract. `BLAKE2S` is a
   plain `bytes -> bytes` instruction.
   **Caveat to derisk in the prototype:** the binding is not just a
   blake2s-of-bytes. The chip's OutHash packs field elements into M31/QM31
   lanes (felt252 → 28 × 9-bit limbs → `pack_into_qm31s`) around the blake
   calls. The contract must reimplement that lane packing in Michelson
   (bit manipulation on `nat`/`bytes`). If that proves too gnarly in LIGO,
   the fallback is a slightly higher-level primitive (e.g. an OutHash
   helper) — to be decided empirically once the contract exists.

3. **Submission → single-op v1, architected for batch.** v1 is one op per
   proof (depth-1 aggregation tree: one real leaf + padding, one blake
   fold). The contract's binding walk and the wire are designed so depth-d
   batching (one proof, many ops) drops in later without a redesign —
   `verify_snark_tree` already handles arbitrary depth. Support both
   eventually; ship single-op first.

4. **Withdrawal & value custody → native Michelson tickets, atomic.**
   The TzEL contract custodies escrowed XTZ as a Michelson **ticket**
   (minted by `tez_bridge_ticketer.tz`'s `%mint`, 1 mutez = 1 unit),
   split/joined per operation:
   - **deposit / shield-in**: user calls `ticketer.%mint(pubkey_hash,
     tzel_contract)` with XTZ → the contract's `%deposit` receives
     `(pair bytes (ticket …))`, credits `deposits[pubkey_hash]`, joins the
     ticket into its held balance.
   - **withdrawal / unshield-out**: the contract `SPLIT_TICKET`s a `v_pub`
     ticket and `TRANSFER_TOKENS` it to `ticketer.%burn(recipient, ticket)`,
     which releases XTZ to the L1 recipient.
   The rollup's emit-before-mutate hazard (the H1 atomicity bug) **vanishes**:
   in Michelson the storage update and the emitted internal operations are
   one atomic operation — any failure reverts everything. No runtime
   affordance beyond the standard ticket instructions (`TICKET`,
   `SPLIT_TICKET`, `JOIN_TICKETS`, `READ_TICKET`), which MIR supports.

These four are settled; the prototype (LIGO contract + stubbed verify)
can proceed. The one empirical unknown is decision 2's M31-lane packing in
Michelson — the first thing the prototype validates.

---

## Proving performance (measured 2026-06-22)

The proof system shape is unchanged, but the recursion → wrap pipeline has
been measured end-to-end and optimised since the 2026-06-10 design freeze.
All numbers below are **measured** (not estimated) at production security
(96-bit, `TZEL_SEC=96`), and every change is **byte-identical** — the OUTER
proof SHA is invariant (`ad426dbb…`), so none of the perf work alters the
proof.

### Pipeline stages

A TzEL operation proves as: **4 leaf STARKs → 2 mv-inner aggregations →
1 OUTER aggregation** (Poseidon2-BN254 channel, so the BN254 wrap can verify
it cheaply) **→ Groth16-BN254 wrap** (388 bytes, 10,594,113 R1CS). The leaf
and aggregation STARKs are GPU-resident (bespoke A100 CUDA: Poseidon2-BN254
commit + Circle-FFT + Blake2s, behind `gpu_commit/gpu_fft/gpu_blake` +
`TZEL_RESIDENT=1`). The wrap is CPU-bound (gnark Groth16).

### Levers landed this cycle

- **fold2** (FRI `fold_step=2`): collapsed the OUTER FRI layers 21→11 →
  **OUTER 104.5 s → 49 s**. fold3 is *not* viable — an 8-wide coset spans 2
  packed Merkle leaves (`LOG_PACKED_LEAF_SIZE = 2` ⇒ 4 QM31/leaf), a
  decommit-topology change, not a knob.
- **L2/L3 reprover perf** (committed `5274d93`, byte-identical): skip the
  redundant `is_circuit_valid()` re-eval (L2) + fat-LTO/codegen-units=1/
  mimalloc/`target-cpu=native` AVX-512 (L3) → **mv-inner 26.5 s → 17.4 s,
  leaves 68.8 s → 44.4 s** (the leaf gain is pure L3 AVX-512).

### Measured E2E

The full chain was run **continuously, stitched** (leaf→mv→OUTER→BN254
emit→Go witness-extract→Groth16 prove→verify) — the OUTER→wrap seam
**verifies end-to-end**, and the inter-stage glue is negligible (every
serialize handoff sub-ms; Go witness-extract **25 ms** — there is no hidden
integration cost). Per-stage, on the best validated hardware (A100-80GB
GPU + 96-core c4 for the wrap), fanned (4 leaf boxes ∥, 2 mv ∥):

| stage | A100 | **H100** |
|---|---|---|
| leaf (1 unit, 4 fanned) | ~11.7 s | ~7.1 s |
| mv-inner (1 unit, 2 fanned) | ~9.0 s | ~5.1 s |
| **OUTER** | 43.2 s | **28.4 s** |
| wrap (Groth16, 96-core CPU) | 9.3 s | 9.3 s |
| glue (agg-ctx + verify + handoffs) | ~2.4 s | ~1.4 s |
| **fanned E2E** | ≈ 76 s | **≈ 51 s** |

(Single-box sequential Rust chain is ~107 s on A100 / ~65 s on H100, + the
wrap.) **OUTER dominates** the fanned E2E. The **H100 `sm_90` port is done
and byte-exact** — the bespoke CUDA kernels are arch-clean (no Hopper
intrinsics), so it was a pure recompile, and the OUTER proof SHA is
unchanged (`ad426dbb…`). H100 measured **OUTER 28.4 s** (from 43.2 s on
A100, ~1.52× via higher memory bandwidth), taking the fanned E2E to
**≈ 51 s**. Hopper capacity is scarce (on-demand stockout; DWS flex-start is
preemptible and a full ~45-min build does not survive it) — the number was
obtained by pre-building the binary off-Hopper into a disk image, then
running a build-free ~5-min job via DWS flex-start. The wrap is CPU-bound:
cost scales with core count (witness-solve ~6.2 s is a serial floor); the
icicle GPU wrap is faster (~12 s) but emits an invalid proof today.

### Open soundness caveat

The current BN254 wrap runs with **2 documented skips active**
(`SkipOutputHash`, `SkipOodsCompositionAssert`) — the proof verifies *with
them skipped*, so the wrap is **not yet fully sound**. Closing them (adds a
modest R1CS bump) is a prerequisite before production, tracked separately
from the external audit.
