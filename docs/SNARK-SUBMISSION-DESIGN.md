# SNARK submission design — DAL-free, operator-chosen aggregation

Status: DESIGN LOCKED 2026-06-10 (user decision). Supersedes the
DAL-pointer submission path for proof-bearing operations.

## Decision

1. **The Groth16 wrapper removes the DAL dependency.** Operations are
   submitted purely through inbox messages (≤ 4096 bytes each). The
   388-byte Groth16 proof + binding data fit inline; encrypted notes
   (the only oversized component) are chunked across inbox messages
   and reassembled by the kernel.
2. **The kernel supports BOTH single-op and batched submission.** The
   application operator chooses how to interact with the rollup:
   aggregate N ops under one mv root (amortised SNARK) or submit one
   op at a time (padded mv root). Same wire format, same verification
   path — a batch of size 1 IS the single-op mode.

## Why this works now

- The mv-target chip wraps an aggregated multiverifier root; the
  Groth16 proof is 388 bytes, Verify ≈ 1.6 ms. After the fold2 wrap
  rewrite the circuit is 10,594,113 R1CS; the Groth16 **Prove** is
  CPU-bound and hardware-sensitive — measured **9.3 s** on a 96-core
  c4-highcpu (the knee; witness-solve is a ~6.2 s serial floor, MSM
  ~3.1 s scales with cores), **21 s** on a 24-vCPU box. (The earlier
  "3m21s" was a pre-fold2 single-thread number, superseded.) The GPU
  (icicle) wrap is ~12 s but currently emits an INVALID proof — not
  usable until the icicle BSB22 commitment bug is fixed. See
  TZEL-ON-TEZOS-X-ARCHITECTURE.md § Proving performance for the full
  pipeline E2E.
- `verify_snark_mv` (verifier/src/snark.rs) already binds a Groth16
  proof to the mv root's children data (15/15 acceptance incl. the
  positive happy path on real artifacts).
- The mv tree derivation is golden-vectored at every level:
  `parent.output_values = blake_m31(rootL ‖ ovL ‖ rootR ‖ ovR)`.
- Sandbox finding (2026-06-10): the 4096-byte inbox cap blocks full
  Shield bodies (≥ 7.1 KiB of ML-KEM768 notes) — hence note chunking;
  everything else fits.

## Wire format (v18)

Two new message kinds (replacing the DAL-pointer variants):

### `StageChunk`

```
StageChunk {
    staging_id:  u64,      // operator-chosen, scoped per sender
    chunk_index: u16,
    chunk_count: u16,
    payload_hash: Felt,    // hash of the FULL reassembled payload
    bytes: Vec<u8>,        // ≤ ~3.9 KiB after framing
}
```

Kernel stages chunks in transient durable storage keyed by
`(sender, staging_id)`. On the final chunk, the kernel verifies
`hash(reassembled) == payload_hash` and seals the staging entry.
Stale entries are garbage-collected after a TTL (in levels).

### `SubmitOps`

```
SubmitOps {
    ops: Vec<OpDecl>,            // 1..=MAX_BATCH_OPS, operator's choice
    groth16_proof: [u8; 388],    // wrap of the mv ROOT
    tree_roots: [[u8; 32]; 4],   // wrap public inputs
    out_hash: [u32; 8],          //   "
    binding: TreeBinding,        // see below
}

OpDecl {
    kind: Shield | Transfer | Unshield,
    output_preimage: Vec<Felt>,  // the op's bootloader preimage
    staged_notes: Vec<(staging_id, payload_hash)>,  // sealed refs
    // ... op-specific public fields (recipient, amount commitments)
}
```

### `TreeBinding`

The proof attests the mv ROOT. The kernel must check each declared op
is a leaf of that root. Binding data per tree level:

```
TreeBinding {
    depth: u8,                       // tree depth (#leaves = 2^depth)
    leaf_slots: Vec<LeafSlot>,       // 2^depth entries
}

LeafSlot =
  | DeclaredOp(op_index)             // backed by ops[op_index]
  | Opaque { root: [QM31; 2], outputs: [QM31; 2] }   // padding/sibling
```

Verification walk (all in kernel WASM, pure blake2s):
1. For each `DeclaredOp` leaf: derive the leaf's
   `(preprocessed_root, output_values)` from `ops[i].output_preimage`
   via the leaf-statement derivation (the leaf↔mv junction —
   privacy_circuit_verify chain). The leaf preprocessed_root is a
   protocol constant (the leaf circuit's identity).
2. For `Opaque` slots: take the supplied lanes as-is (range-checked).
3. Fold pairwise: `parent.outputs = blake_m31(rootL ‖ ovL ‖ rootR ‖ ovR)`;
   internal-node preprocessed_root is the mv-circuit constant
   (leaf_to_mv root at level 1, mv_to_mv root at levels ≥ 2).
4. Assert the final root's `(preprocessed_root, output_values)`
   matches `(tree_roots[0], out_hash)` via the wrap OutHash equation.
5. `verify_groth16_wrap(groth16_proof, tree_roots, out_hash)`.

Soundness: an attacker cannot bind a declared op the proof doesn't
cover — any change to a leaf's preimage changes the blake chain and
breaks either step 4 or the Groth16 publics. Opaque slots cannot
smuggle ops (they are never applied). Duplicate leaves (padding the
same op 4×) are harmless: the kernel applies `ops[]` exactly once
each; nullifiers enforce no double-spend across messages.

### Single-op mode = batch of 1

The operator pads the aggregation tree (e.g. duplicates the op's leaf
4×), declares `ops = [the_op]`, marks one slot `DeclaredOp(0)` and the
rest `Opaque` (with the duplicate lanes). Cost: ~6-7 min prove per op.
Batch mode amortises: N ops → one SNARK.

## Size budget (4096-byte inbox messages)

| Component | Bytes |
|---|---|
| Groth16 proof | 388 |
| tree_roots + out_hash | 160 |
| TreeBinding (depth 2, 4 slots) | ~300 |
| OpDecl w/o notes (preimage ~12 felts) | ~500 |
| **SubmitOps total (1 op, depth 2)** | **~1.4 KiB ✓** |
| Shield notes (2 × ML-KEM768) | ~7.1 KiB → **2 StageChunk msgs** |
| Unshield (no notes) | fully inline ✓ |

Batch of 4 ops: ~3.5 KiB + staged notes — fits; larger batches split
OpDecls across a staged payload too (same StageChunk mechanism).

## What gets deleted

- DAL pointer variants in kernel_wire (`WireKernelDalPayloadPointer`,
  chunk lists, `reveal_dal_*` host usage for op payloads).
- The STARK-direct verification path (`DirectProofVerifier`,
  `verifier/src/bundle.rs`, `canonical_verify_meta.hex`,
  `verify_meta_codec.rs`) — the kernel verifies Groth16 only.
- The 8 `verified_*` bridge_flow fixtures regenerate as Groth16
  envelopes (they are already broken on this branch).

## Implementation tracks

| | Scope | Est. |
|---|---|---|
| W1 | kernel_wire v18: StageChunk + SubmitOps + TreeBinding (+ encode/decode tests) | 3-4 d |
| W2 | kernel: staging storage + batch apply + verify_snark_mv callsite (replaces validate_transition_proof) + delete legacy | 4-6 d |
| W3 | verifier: leaf↔mv junction golden vectors + recursive tree-walk API | 2-3 d |
| W4 | wallet/operator: produce both modes (single padded / batched), prove pipeline orchestration | 4-6 d |
| W5 | sandbox E2E both modes + fixture regen | 3-4 d |

W3 is the only remaining cryptographic link; W1/W2 are wire+state
machinery; W4/W5 integration. W1+W3 are independent and can start
immediately; W2 depends on W1+W3; W4/W5 close the loop.

## Open points

- StageChunk TTL + anti-spam (staging storage is attacker-fillable:
  bound per-sender staging bytes; sender pays L1 gas per message).
- MAX_BATCH_OPS (proposal: 16 — one mv tree of depth 4).
- The leaf preprocessed_root protocol constant must be pinned per
  TzEL release (it changes when the leaf circuit changes).
- Outbox/withdrawal path (unshield) unchanged — already inbox-sized.
