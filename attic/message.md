# StarkPrivacy: circuit topology question

## What we have

A UTXO-based private transaction system proven with two-level recursive STARKs (Cairo AIR → Stwo circuit reprover, ~295 KB ZK proofs, 96-bit security). All hashing is BLAKE2s with personalized IVs for domain separation. Post-quantum: ML-KEM-768 for memo encryption/detection, no elliptic curves anywhere.

**Note structure:**
```
cm  = H_commit(d_j, v, rcm, ak)     — commitment
nf  = H_null(nk, cm)                — nullifier
rcm = H("rcm", rseed)               — from per-note randomness
```

`nk` is account-level (one per account). `ak` is per-address (authorization key, bound into commitment to prevent delegated prover substitution). `d_j` is a diversified address. The commitment does not contain `nk` — spending and address material live in separate branches (Penumbra-style).

**Current circuits:**
- **Shield**: proves `cm = H(d_j, v, rcm, ak)` — one new commitment
- **Unshield**: proves Merkle membership + `nf = H(nk, cm)` — destroys one note, releases value publicly
- **Transfer (2→2)**: consumes exactly 2 input notes, creates exactly 2 output notes, proves balance conservation `v_a + v_b = v_1 + v_2`

The 2→2 constraint means you need pre-shielded zero-value dummy notes to fill unused input slots (e.g., to do a 1→2 split, you need a dummy as the second input). Each dummy must exist in the Merkle tree and has its nullifier consumed when used.

**Proof size is ~295 KB regardless of circuit complexity** because the Stwo preprocessed trace (2^20 rows) dominates. Our actual computation is ~4K-30K steps — well under the padded trace. Even significantly larger circuits would not change the proof size.

## What we're considering

Replace the fixed 2→2 transfer with a single **N→2 circuit** where N is a runtime parameter:

```
fn verify(
    root, nf_list[0..n], cm_1, cm_2, ak_list[0..n],
    // private: n input notes with Merkle paths, 2 output notes
) {
    for i in 0..n: verify input i (recompute cm, Merkle check, nullifier)
    verify both outputs
    assert sum(v_inputs) == v_1 + v_2
}
```

N is private (the number of inputs is not revealed by the proof structure — only the resulting nullifiers and commitments appear as public outputs). The circuit is one Cairo program; N doesn't change the program hash, just the execution trace length.

**What this gives us:**
- 1→2 (split), 2→2 (standard), 5→2 (consolidation) — all one circuit
- **Eliminates dummy notes entirely**: with N=1 supported, no second input slot to fill
- Shield becomes a pure contract call (no STARK needed — the depositor is public, the contract just appends cm and deducts from their balance)
- Unshield could be a special case of N→2 where one output is a public withdrawal, or kept as a separate simpler circuit

**Our analysis of proof size impact:**
Current 2→2 uses ~30K Cairo steps. Each additional input adds ~48 Merkle levels × some Blake compress calls. Even a 12→2 would be ~150K steps — still under the 2^20 padded trace. We believe proof size stays at ~295 KB regardless of N. The circuit reprover adapts dynamically (it builds ProofConfig from the proof's claim enable bits).

**Questions we'd like your perspective on:**

1. Is our analysis correct that proof size remains constant up to reasonable N (say 16)?

2. Should we cap N at a fixed maximum (e.g., 16) or leave it truly variable? A cap simplifies worst-case analysis. An uncapped N means a user could theoretically consolidate hundreds of UTXOs in one proof, but the trace might exceed 2^20 at some point.

3. The public output length varies with N (each input contributes a nullifier + an ak). Does this create any issues for the on-chain verifier or the circuit reprover? The verifier needs to parse a variable-length output.

4. With N→2, shield no longer needs a STARK proof — the contract just appends a commitment. Are there any security concerns with unproven shields? The depositor is public, `v` is public, and `cm` is opaque — if it's malformed, only the depositor loses (they can't spend the note). The contract doesn't need to verify the commitment's internal structure.

5. Should unshield remain a separate circuit, or should it be a special case of N→2 with one output designated as a public withdrawal? A separate unshield circuit is simpler (no second output commitment to create). But having fewer circuit types is cleaner.

6. Any other concerns with the N→2 approach we haven't considered?
