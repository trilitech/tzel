# TzEL — commitment tree & wallet sync (design)

Status: DECIDED 2026-06-11 (with François). Supersedes the on-chain
Merkle-frontier / `merkle_append` primitive idea.

## Decision in one line

**The commitment tree lives off-chain; only its root is on-chain. The circuit
proves the insertion and outputs the new root. The leaves (commitments) and the
encrypted notes are published on-chain so any wallet can rebuild the tree.**

## Why (not on-chain tree, not a `merkle_append` primitive)

The transfer/shield circuits output the *new commitments* (`cm_1/2/3`), not the
new tree root. Computing the new root means inserting them into a depth-48
incremental Merkle tree = 48 `blake2s` per commitment.

- Doing it **in the contract** via the gateway `blake2s` view = 48 view calls
  per commitment (144 per transfer). Prohibitive.
- Exposing a **`merkle_append` runtime primitive** removes that, but the tree
  *state* (the ~1.5 KB frontier) would then shuttle in/out of contract storage
  every op: storage gas + burn on changing data, plus serialise/deserialise on
  both sides. That cost is the symptom of putting the tree in the wrong place.

The right place for the tree is **the circuit** (as in Zcash/Sapling, Aztec):
the prover already touches the tree to prove spends, so proving the append and
outputting `new_root` is marginal. Then:

- the contract stores only the **32-byte root** (+ the nullifier set);
- **no frontier on-chain, no shuttling, no `merkle_append` primitive**;
- the OutHash binding (already wired) ties `new_root` to the proof, so the
  contract reads it from the bound `output_preimage` and trusts it.

## Data availability — leaves are on-chain

"Off-chain tree" means the contract does not store the *derived* tree. The
underlying data is fully on-chain:

- every op publishes its **commitments** (`cm_1/2/3`) and the **encrypted
  notes** (note ciphertext for recipients), both in the operation calldata and
  via a contract **`EMIT` event** (so indexers/light wallets can subscribe);
- the tree is a deterministic replay of the commitment stream — anyone can
  rebuild it and gets the same root.

So there is no data-availability problem: the contract is just a
root-register + nullifier-set; the leaves live in the chain history/events.

## Wallet bootstrap (fresh wallet)

1. **Scan** the contract's shield/transfer ops from genesis (or a signed
   checkpoint).
2. **Replay** the commitments in order → rebuild the full tree + frontier
   locally.
3. **Trial-decrypt** the published encrypted notes → find the notes addressed
   to this wallet (its funds).
4. For each owned note, compute the **Merkle authentication path** from the
   reconstructed tree — this is the witness handed to the prover to spend.
5. **Check** the reconstructed root equals the on-chain root (consistency).

## Wallet sync (incremental)

Process only new ops: append new commitments to the local tree, trial-decrypt
new note ciphertexts. O(Δ), no full re-scan.

## The prover's frontier

Whoever builds a proof (wallet or operator) already reconstructed the tree by
the sync above, so it has the frontier and the auth-paths on hand. No special
data is shuttled — everything derives from the on-chain commitment stream.

## Costs (inherent to the privacy model)

- **Initial scan** = O(all commitments) — like Zcash. Mitigated by signed
  **checkpoints/snapshots**: an operator serves a tree state at a height, the
  wallet verifies the root and continues from there.
- **Trial-decryption** = O(all notes) — the classic shielded-pool cost
  (Zcash/Aztec the same). Mitigated by detection tags / light-wallet protocols;
  the trust-minimised fallback is always "scan + decrypt".

## What this means for each layer

| Layer | Responsibility |
|---|---|
| **Circuit** (Cairo) | Prove the spend AND the insertion; **output `new_root`** in `output_preimage`. *(extension — folds into the upcoming multi-asset circuit work)* |
| **Runtime (zk)** | Unchanged: `verify_snark` + `blake2s` (for the OutHash binding) suffice. **No `merkle_append` primitive.** |
| **Contract (Michelson)** | Trivial: verify the bound proof → read `new_root` from the bound `output_preimage` → `current := new_root` → spend nullifiers → **`EMIT` (commitments, encrypted notes)** for wallet sync. Stores only `(root, nullifiers)`. |
| **Wallet / operator** | Holds the tree off-chain; bootstraps/syncs by scanning the on-chain commitment + note stream; builds auth-paths and proofs. |

## Dependency

The contract reading `new_root` from `output_preimage` requires the circuit to
**output it** — which the current single-value circuit does NOT (it outputs the
old root + the new commitments). This extension is pinned to the upcoming
multi-asset circuit pass. Until then the contract path that reads `new_root` is
staged but cannot be exercised against real proofs.
