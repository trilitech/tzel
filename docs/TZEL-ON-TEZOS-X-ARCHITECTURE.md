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

## Layer 1 — Runtime primitives (what Tezos X must enshrine)

The Tezos X MIR runtime today has hashes (BLAKE2b, Keccak, SHA-256/3/512),
`CHECK_SIGNATURE`, and `PAIRING_CHECK` (BLS12-381 via `blst`). It has **no**
generic SNARK/STARK verification and **no** BLAKE2s. The new instructions
follow the established `PAIRING_CHECK` pattern (AST enum + lexer +
typechecker + interpreter + gas; no new Michelson *type* needed — proofs
and keys are `bytes`).

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
BLAKE2S :: bytes -> bytes   -- 32-byte digest
```

TzEL's proof-to-operation binding (below) is a BLAKE2s chain (the chip's
`OutHash` and the multiverifier fold use BLAKE2s over M31 lanes, not
BLAKE2b). The contract needs it to re-derive `OutHash` and walk the
aggregation tree. Trivial addition next to the existing BLAKE2b/Keccak
instructions. (If absent, the alternative is folding the whole binding
into a fatter, TzEL-specific `VERIFY_SNARK` — rejected here to keep the
primitive generic.)

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
   `op_publics` with `BLAKE2S` (the chip's `OutHash` = blake over
   `preprocessed_root ‖ output_values`, `output_values = blake(output_preimage)`)
   and assert it equals the proof's `out_hash`. Prevents pairing a valid
   proof with a different op's data (a blake2s second-preimage attack,
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
