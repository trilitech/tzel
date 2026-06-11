# TzEL — commitment tree, valid roots & wallet sync (design)

Status: DECIDED 2026-06-11 (with François), CORRECTED 2026-06-11 after reading
the actual circuits. This supersedes the earlier (wrong) "circuit outputs
new_root" draft.

## The actual circuit model (read first)

The TzEL spend circuits (`cairo/src/merkle.cairo`, `transfer.cairo`,
`shield.cairo`) do **membership-only** Merkle verification:

> *"The tree is append-only: new commitments are added at the next available
> leaf position, and old roots remain valid forever. The on-chain contract
> accepts any historical root, so a proof against a stale root is fine —
> double-spend is prevented by the global nullifier set, not by root
> freshness."* (merkle.cairo:5-15)

So a spend proves *"my note is a leaf of a tree with root R"* where **R is any
historical root**. The circuit does **not** append and does **not** output a
new root. Transfer's public output is
`[auth_domain, R(membership root), nf_1..nf_N, fee, cm_1..3, memo_hashes]`;
shield's output has **no root at all**.

## Consequences for the on-chain side

Someone must maintain (1) the **append-only commitment tree** and (2) the
**set of valid historical roots** the contract accepts. Computing one append =
48 personalized-blake2s (depth-48 tree); doing that on-chain via the gateway
`blake2s` view = ~48 calls/commitment = prohibitive. The circuit doesn't help
(membership-only).

**Decision: a generic append-only Merkle accumulator, exposed by the zk runtime
(same runtime for now), holds the tree in the runtime's durable storage and
does the append in Rust.** The contract sends only 32-byte leaves and reads
roots — nothing shuttles. See `A′` below.

The tree being "off-chain" only means the contract does not store the derived
tree. The leaves (commitments) and encrypted notes are PUBLISHED on-chain (op
calldata + an `EMIT` event), so any wallet rebuilds the tree by replay (the DA
argument is unchanged from the earlier draft).

## A′ — the accumulator (zk runtime, stateful)

Generic, asset-agnostic, leaves opaque. Trees are namespaced
`tree_id = (caller_contract, tag)` — `caller` from `X-Tezos-Sender` (gateway
provides identity → contract A cannot touch B's tree); `tag` contract-chosen
(multiple trees per contract → **one tree per asset** for multi-asset, `tag =
asset_id`).

State: `trees[(caller, tag)] = { frontier:[32]*48, count:u64, roots:Set<[32]> }`.

| Endpoint | Kind | I/O |
|---|---|---|
| `tree_append` | `%call` (mutating) | `tag ‖ n ‖ leaf*n` → `new_root ‖ new_count`; appends (kernel `append_note` walk, blake2s perso `mrklSP__`), records `new_root` in `roots` |
| `tree_known_root` | `VIEW` (read-only) | `tag ‖ root` → `Some 0x01` iff `root ∈ roots[(caller,tag)]` |

**Atomicity**: the `tree_append` durable write and the contract op are atomic by
**NAC** when both are in one transaction — the write is staged in the journaled
layered-state and reverts with the frame (same mechanism proved for
NAC-ALIAS-G8 / NAC-CREDIT; end-to-end MIR lift still in FV). No state shuttling.

**Cost**: compute = 48·n hashes/append (bounded); frontier storage ~1.5 KB/tree
(fixed); `roots` set grows with history — **same profile as a Zcash/Sapling
anchor history**, acceptable; a sliding window of recent anchors is an available
optimisation (Zcash has it too) to revisit at pricing time.

## Contract responsibilities (application semantics — stay here)

Per op, after binding the proof (OutHash binding, already wired):

1. **Pin the circuit identity** — `tree_roots[0]` (STARK preprocessed root) ==
   the pinned circuit root in storage. *Without this, the wrap vk only pins the
   universal wrap circuit and ANY inner circuit forges effects → pool theft.*
2. **Pin** `program_hash` (output_preimage[2]) and `auth_domain`
   (output_preimage[3]) against stored constants (circuit + ledger identity;
   kills cross-circuit and cross-ledger replay).
3. **Validate the membership root** — read `R` from the bound output and require
   `tree_known_root(tag, R)` (A′). *The proof proves membership in a tree with
   root R; the contract must check R is a real historical root of THIS pool,
   else a fabricated tree passes.*
4. **Spend ALL nullifiers** the circuit output (transfer is N→2, up to 7
   inputs) — reject any already in the nullifier big_map; reject in-batch dups.
5. **Append** the new commitments via `tree_append` (A′) → tree advances, new
   root becomes valid.
6. **`EMIT` (commitments, encrypted notes)** for wallet sync.

Contract storage: `{ gateway, vk, circuit_root, program_hash, auth_domain,
nullifiers:big_map }` — **no on-chain tree, no single "current root" register**
(the valid-roots set lives in A′).

## Wallet bootstrap / sync (unchanged)

Fresh wallet: scan ops from genesis/checkpoint → replay commitments → rebuild
the tree + frontier locally → trial-decrypt published note ciphertexts → find
its notes → compute auth-paths for the prover. Sync = process new ops only.
Costs (initial scan O(commitments), trial-decrypt O(notes)) are the standard
shielded-pool costs (Zcash/Aztec), mitigated by checkpoints / detection tags.

## Per-layer split

| Layer | Responsibility |
|---|---|
| **Circuit** (Cairo) | Prove spend = membership against a historical root + well-formed new commitments. Outputs membership root + nullifiers + commitments. **No new_root output, no in-circuit append.** (Multi-asset extension forthcoming.) |
| **Runtime (zk)** | `verify_snark` + `blake2s` (binding) + **A′ accumulator** (`tree_append` / `tree_known_root`). |
| **Contract** | Bind proof; **pin identities**; validate membership root via A′; spend all nullifiers; append commitments via A′; EMIT. Stores only identities + nullifier set. |
| **Wallet / operator** | Tree off-chain; bootstrap/sync by scanning the on-chain commitment + note stream; build auth-paths and proofs. |

## Status / dependencies

- A′ accumulator: to build (zk runtime endpoints).
- Contract identity pins + nullifier-list + membership-root check: do now
  (security-critical, asset-independent).
- Exact output felt offsets per entrypoint, wire-length constants, value
  custody (per-asset tickets): pinned to the upcoming multi-asset circuit pass.
