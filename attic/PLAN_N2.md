# StarkPrivacy: N→2 Circuit Topology

## Summary

Replace the fixed 2→2 transfer with variable-input circuits. Three circuit types, each serving a distinct role.

## Circuits

### Shield (0→1)

**Unchanged from current design.** The shield circuit remains necessary: it proves the commitment `cm` binds to the public deposit amount `v_pub`. Without this proof, an attacker could deposit 1 token but commit to a note with v=100, creating value from thin air. The contract checks `v_pub` in the proof output against the actual deposited amount.

```
Public outputs: [v_pub, cm_new, ak, sender]
Private inputs: d_j, rseed
Constraint:     cm_new = H_commit(d_j, v_pub, rcm, ak)
```

One output note. Encrypted memo + detection data posted on-chain (~3.2 KB).

### Transfer (N→2, where 1 ≤ N ≤ 16)

**Replaces the current fixed 2→2.** One Cairo program; N is a runtime input, not a program parameter. The program hash is the same regardless of N.

```
Public outputs: [root, nf_0, ..., nf_{N-1}, cm_1, cm_2, ak_0, ..., ak_{N-1}]
Private inputs: N input notes (each with d_j, v, rseed, ak, Merkle path, nk),
                2 output notes (each with d_j, v, rseed, ak)
Constraints:
  For each input i (0..N):
    rcm_i = H("rcm", rseed_i)
    cm_i  = H_commit(d_j_i, v_i, rcm_i, ak_i)
    Merkle membership of cm_i under root
    nf_i  = H_null(nk_i, cm_i)
  All nf_i are pairwise distinct
  For both outputs:
    rcm   = H("rcm", rseed)
    cm    = H_commit(d_j, v, rcm, ak)
  Balance: sum(v_inputs) = v_1 + v_2
  All values are u64 (implicit range check)
```

Two output notes. Two encrypted memos + detection data posted on-chain (~6.4 KB).

**N is not private.** The number of published nullifiers reveals the input count. This is inherent to per-input nullifier publication. Acceptable metadata leak — the user controls how many inputs they consolidate.

**Cap at 16.** Worst-case ~16 × 48 Merkle levels of Blake compress operations. Must benchmark to verify this stays within the 2^20 padded trace domain. If it exceeds, reduce the cap. The cap is for prover time and calldata cost, not soundness.

### Unshield (N→change+withdrawal, where 1 ≤ N ≤ 16)

**Kept as a separate circuit** (not unified with Transfer). Cleaner, easier to audit, avoids awkward zero-output edge cases.

```
Public outputs: [root, nf_0, ..., nf_{N-1}, v_pub, ak_0, ..., ak_{N-1}, recipient,
                 cm_change (or 0 if no change)]
Private inputs: N input notes, optional change output note
Constraints:
  Same per-input verification as Transfer
  sum(v_inputs) = v_pub + v_change
  If change: cm_change = H_commit(d_j_change, v_change, rcm_change, ak_change)
  If no change: cm_change = 0, v_change = 0
```

Optional change output (0 or 1 private notes). The public withdrawal amount `v_pub` and `recipient` are in the public outputs. The contract credits `v_pub` to `recipient` and appends `cm_change` to the tree (if nonzero).

## What this eliminates

- **Dummy notes.** With N=1 as a valid input count, no need to pre-shield zero-value notes to fill a second input slot. The only remaining "dummy" is a zero-value output (when change is exactly zero), which is a fresh commitment created on the fly — no pre-shielding required.

- **Multiple circuit variants.** One transfer circuit handles 1→2 through 16→2. One unshield circuit handles 1→withdrawal through 16→withdrawal.

## What doesn't change

- Commitment format: `cm = H_commit(d_j, v, rcm, ak)`
- Nullifier: `nf = H_null(nk, cm)`
- Key hierarchy (spend branch + incoming branch)
- BLAKE2s with personalized IVs
- ML-KEM-768 for memos/detection
- Two-level recursive STARKs (~295 KB proofs)
- 1 KB user memo per output note
- Delegated proving (prover gets nk + per-note data, signs with ask afterward)

## Proof size analysis

Current 2→2 transfer: ~30K Cairo steps, padded to 2^20. Proof: ~295 KB.

16→2 transfer estimate: ~16 × (48 Merkle levels × ~10 Blake compress ops + commitment recomputation) ≈ ~150K steps. Still under 2^20. Proof should remain in the ~295 KB band.

**Must benchmark before shipping.** The proof size is not mathematically constant — it depends on column log sizes and FRI structure. "Same band" is the correct expectation, not "identical." Run `reprover` on a 16-input transfer and compare.

## On-chain data per transaction type

### Shield (~298 KB)
```
proof             ~295 KB    circuit proof
public_outputs     128 B     [v_pub, cm_new, ak, sender]
note_data          3.2 KB    1 output note (cm + detection + 1KB memo)
signature           64 B     spend auth
```

### Transfer N→2 (~302 KB + 64N bytes)
```
proof             ~295 KB    circuit proof
public_outputs     64+64N B  [root, cm_1, cm_2] + N×[nf_i] + N×[ak_i]
note_data          6.4 KB    2 output notes
signatures         64N B     N spend auths (one per input ak)
```
For N=5: ~302 KB + 640 B ≈ ~303 KB.

### Unshield N→change+withdrawal (~298 KB + 64N bytes)
```
proof             ~295 KB    circuit proof
public_outputs     96+64N B  [root, v_pub, recipient, cm_change] + N×[nf_i] + N×[ak_i]
note_data          0-3.2 KB  0 or 1 change note
signatures         64N B     N spend auths
```

## Open questions

1. **Pairwise nullifier distinctness check.** For N=16, checking all pairs is O(N²) = 256 assertions. Alternatively, sort nullifiers and check adjacent pairs — O(N log N) but sorting in Cairo is more complex. For N≤16, the quadratic check is fine (~256 comparisons is negligible in a 2^20 trace).

2. **Canonical ordering of public outputs.** Define lexicographic ordering for nullifiers and ak values, or accept permutation malleability (the contract processes them as a set anyway).

3. **Per-input nk.** The current transfer takes per-input nk (supporting cross-account inputs). With N inputs, this means N separate nk values in the witness. Verify this doesn't create issues — an observer who sees N nullifiers from different accounts might learn something about account relationships.

4. **Fee model.** Price by N (more inputs = more calldata + more contract processing). Not a cryptographic concern but affects economics.

## Implementation order

1. Implement the N→2 transfer circuit in Cairo (replacing current 2→2)
2. Implement the N→change+withdrawal unshield circuit
3. Update step executables to test various N values (1, 2, 5)
4. Update common.cairo test data
5. Benchmark with reprover at N=1, 2, 5, 10, 16
6. Update spec.md with new circuit descriptions and transaction format
7. Update demo
8. Security audit
