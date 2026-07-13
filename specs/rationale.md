# TzEL v2: Design Rationale

This document is informative, not normative. The canonical protocol rules and encodings are in `specs/spec.md`.

## Owner Tags and Nullifier Binding

The note commitment includes:

```text
owner_tag = H_owner(auth_root, pub_seed, nk_tag)
cm        = H_commit(d_j, v, asset_id, rcm, owner_tag)
```

This is the mechanism that binds the commitment to the nullifier key material.

Without owner tags, the commitment could look like:

```text
cm = H_commit(d_j, v, rcm)
```

In that weaker design, an attacker observing `cm` could choose an arbitrary nullifier key and try to spend the same commitment under a fresh nullifier. The owner-tag chain:

```text
nk_spend -> nk_tag -> owner_tag(auth_root, pub_seed, nk_tag) -> cm
```

forces the commitment to be tied to the spender's nullifier derivation path. The spending proof then has to be consistent with the same bound commitment.

## Position-Dependent Nullifiers

The nullifier includes the Merkle position:

```text
nf = H_nf(nk_spend, H_nf(cm, pos))
```

The purpose is to ensure that two equal commitments inserted at different tree positions do not collapse to the same nullifier. This avoids aliasing between duplicated commitments and makes nullifier uniqueness a function of both note ownership and concrete tree placement.

## Multiasset Design

The multiasset upgrade (Phase B-E in the codebase) adds support for non-tez assets (FA2 tokens) without sacrificing privacy guarantees. The key design choices:

### Asset hidden inside the commitment

`asset_id` is in the commitment preimage, not a separate on-chain field. Two notes that differ only in asset produce different commitments, but an on-chain observer cannot tell which asset a given `cm` holds. The alternative — a separate asset-ID column on each note — would expose every transaction's asset to chain analysis. Rare-asset transactions would then be trivially identifiable. With the hidden tag, rare-asset transactions hide in the common-asset crowd.

### Producer fee permanently tez

The DAL slot publisher receives an in-tree producer-fee note for every shielded transaction. If that note could be denominated in an arbitrary asset, a hostile publisher submitting blocks containing only transfers with their fee paid in a rarely-traded NFT or illiquid FA2 token would starve the inclusion market. The circuit therefore pins the producer-fee output to `ASSET_TEZ` regardless of the transfer's primary asset.

This pin has a consequence: any non-tez shield/transfer/unshield must also spend some tez (to pay the producer fee plus the burned public fee). The kernel enforces this for shields by debiting `producer_fee` from a separate `(ASSET_TEZ, pubkey_hash)` deposit pool when the user shields an FA2 asset (bug #2 fix in commit `aff523a`). Without this split-debit, an FA2 shield would mint `producer_fee` tez in the commitment tree out of nothing — drainable later via the tez ticketer's L1 backing.

### Two-accumulator value conservation

Cairo cannot iterate over felts inside a constraint system, so the circuit cannot directly express "for every asset α, `sum_in(α) = sum_out(α) + (fee if α == tez)`". Instead, the witness declares one primary non-tez asset `A` per transaction, and the circuit enforces that every input and output asset lies in `{ASSET_TEZ, A}`. Two accumulators then close the per-asset balance.

This is a stronger constraint than the abstract per-asset conservation (which would allow any number of distinct assets per transaction), but it's sufficient for client-side composition: any user-level multi-asset transfer can be serialized as a sequence of 2-asset transactions. The simplification dramatically cuts circuit cost.

### Structural ticketer-to-asset binding

`derive_asset_id(ticketer_kt1) = H("tzel:asset:" || ticketer_kt1_string)` makes the L2 asset_id a pure function of the L1 ticketer's KT1 address. No on-chain registration step is needed; the kernel just maintains a compile-time list of recognized ticketer strings. Asset removal is asymmetric: removing a ticketer from the list refuses new deposits but leaves existing pools and notes intact (unshieldable only after re-adding). This gives the rollup a "soft fork" path for de-registering broken FA2 contracts without stranding user funds permanently.

### Canonical L2 ticket content

The FA2 bridge ticketer's L2 ticket is always emitted with content `(0, None)` regardless of the underlying FA2's `token_id`. The asset_id binding lives in the ticketer's immutable storage; the L2 layer doesn't repeat it inside the ticket. An earlier draft used `(storage.token_id, None)` content; this broke bridging for any FA2 with `token_id != 0` because the kernel uniformly enforces `content.token_id == 0` (bug #3, fixed in commit `73ad6fb`). The canonical-content design isolates "what asset is this" (ticketer KT1) from "what's inside the L2 ticket" (a payload-free amount marker).

## Phase C: Two Change Notes per Transfer/Unshield

Pre-multiasset transfer had three output slots: recipient, change, producer fee. With multiasset, a transfer that mixes tez and FA2 inputs can legitimately need TWO change notes (one per asset) plus the recipient. Phase C therefore adds a fourth slot:

```
slot 1: recipient   (asset chosen by sender)
slot 2: change_1    (same asset as recipient)
slot 3: change_2    (the OTHER asset; zero-value placeholder for pure single-asset transfers)
slot 4: producer fee (permanently ASSET_TEZ)
```

Unshield gains an analogous `cm_change_2`. Pure single-asset transfers don't pay for the extra slot at proof-cost time (zero-value placeholder commitments still hash, but the auxiliary witness data collapses to zero); multi-asset transfers can now express their full balance closure in one transaction.
