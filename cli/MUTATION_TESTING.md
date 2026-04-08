# Mutation Testing Results

Tool: `cargo-mutants` v27.0.0  
Target: `cli/src/lib.rs` (unit tests only, `--lib`)  
Date: 2026-04-08  
Status: **Complete**

## Final Totals

| Status | Count |
|--------|-------|
| **Caught** | ~297 |
| **Missed** | 0 |
| **Timeout** | 5 |
| **Total** | ~302 |

**Mutation kill rate: 100%** (all non-timeout mutants caught)

## Tests Added to Kill Surviving Mutants

12 targeted unit tests were added to catch the 31 originally-missed mutants across 5 groups:

### Group 1: Sighash functions (2 mutants) — CAUGHT
Tests: `test_sighash_known_answer`

### Group 2: WOTS+ key derivation (3 mutants) — CAUGHT
Tests: `test_wots_pk_known_answer`

### Group 3: WOTS+ signing internals (9 mutants) — CAUGHT
Tests: `test_wots_sign_then_verify`, `test_mutant_wots_digit_decomposition`

### Group 4: Auth tree path internals (7 mutants) — CAUGHT
Tests: `test_auth_tree_path_manual_walk`

### Group 5: Ledger validation edge cases (10 mutants) — CAUGHT
Tests:
- `test_mutant_shield_preimage_length_boundary` — shield balance `<` vs `<=` vs `==`
- `test_mutant_shield_cm_without_enc_tmb` — shield `&&` vs `||`
- `test_mutant_transfer_max_inputs` — transfer N>16
- `test_mutant_unshield_max_inputs` — unshield N>16
- `test_mutant_transfer_preimage_positions` — cm position swaps (N=1)
- `test_mutant_transfer_multi_nullifier_preimage` — multi-nullifier positional indexing (N=2), exact-length preimage boundary, memo hash position validation

## Timeout Mutants (5)

```
src/lib.rs:263:31: replace * with + in felt_to_dec
src/lib.rs:264:33: replace / with % in felt_to_dec
src/lib.rs:266:29: replace != with == in felt_to_dec
src/lib.rs:405:15: replace >>= with <<= in wots_sign
src/lib.rs:413:12: replace >>= with <<= in wots_sign
```

These cause infinite loops. The mutation is detected (test hangs) but not via assertion failure. This is expected behavior.
