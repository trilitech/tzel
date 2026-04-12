# Audit Follow-Up

Disposition of findings from [audit_report.md](/home/arthurb/src/starkprivacy/audit_report.md).

## Specification

| Finding | Status | Disposition |
| --- | --- | --- |
| `S1` | Fixed | Spec key hierarchy updated to the XMSS derivation actually implemented. |
| `S2` | Fixed | Spec domain-separation table aligned with the XMSS section and implementation. |
| `S3` | Fixed | Missing XMSS tag strings documented. |
| `S4` | Fixed | Spec zero-list for no-change unshield now includes `pub_seed_change`. |
| `S5` | Fixed | `fold()` specified as the sequential left-fold used by the code. |
| `S6` | Documented | Security docs now describe the delegated prover as learning per-address nullifier capability, not just loose linking. No protocol change yet. |
| `S7` | Documented | No-expiry risk is explicitly documented; no protocol-level expiry added yet. |
| `S8` | Mitigated | Backup/restore risk remains fundamental, but the wallet now keeps a durable XMSS floor sidecar and rejects stale wallet-file restores that roll indices backwards while the sidecar remains current. |
| `S9` | Documented | Shield still omits `auth_domain`; deployment note kept explicit. |
| `S10` | Fixed | Parsing rule and other minor spec clarifications were added. |

## Code

| Finding | Status | Disposition |
| --- | --- | --- |
| `C1` | Fixed | OCaml commitment encoding now matches Rust’s canonical 8-byte `u64` layout and zeroed gap. The OCaml nondeterminism bug from uninitialized gap bytes was also fixed. |
| `C2` | Partially mitigated | Wallet file permissions are forced to `0600` on Unix, but the wallet is still plaintext and secrets are still not zeroized in memory. |
| `H1` | Partially mitigated | Wallet persistence was already atomic; the new XMSS floor sidecar now catches stale wallet-file restores in the common local case. Full rollback protection still requires stronger external monotonicity. |
| `M1` | Deferred | Fixed-nonce memo AEAD remains unchanged for now. Any meaningful fix should be thought through with the deterministic test path and spec, not patched casually. |
| `M2` | Fixed | Detection tag comparison was changed to a constant-time style comparison. |
| `M3` | Deferred | Historical root pruning remains a policy/protocol decision. |
| `M4` | Deferred | `ml-kem` RC dependency not changed in-tree. |
| `L1` | Fixed | Added a first-principles Rust unit test deriving the Cairo precomputed BLAKE2s IVs from the RFC parameter block and checking the hardcoded constants. |
| `L2` | Fixed | Rust commitment code now documents the intentional 24-byte zero gap. |
| `L3` | Accepted | Same-personalization nullifier layering is intentional and unchanged. |
| `L4` | Deferred | Reference ledger still has no rate limiting. Operational concern, not a local protocol bug. |
| `L5` | Deferred | Wallet cleanup/submission atomicity remains a UX issue; no change made. |
| `L6` | Informational | No action needed. |

## Tests

| Finding | Status | Disposition |
| --- | --- | --- |
| `T1` | Deferred | Cairo still lacks direct unit tests. |
| `T2` | Partially fixed | Core crypto property coverage is better than the report counted, and more small-depth XMSS/BDS tests were added. More invariant/property work is still worthwhile. |
| `T3` | Deferred | No fuzzing targets added yet. |
| `T4` | Resolved | Existing Rust sighash sensitivity coverage already included more fields than the report credited. |
| `T5` | Resolved | High-index WOTS+ sign/verify tests at `256` and `65535` already exist in Rust. |
| `T6` | Partially fixed | Wallet unit coverage was expanded substantially around state transitions, BDS behavior, and persistence. Full multi-input/change witness construction coverage is still not complete. |
| `T7` | Partially fixed | Added a wallet unit test for stale-backup rejection against the durable XMSS floor sidecar. |
| `T8` | Partially fixed | Commitment layout agreement is now checked explicitly on the OCaml side, and Rust/OCaml protocol vectors remain aligned. A dedicated cross-impl `u64::MAX` test would still be a good follow-up. |
| `T9` | Fixed / stale | Dead code was removed and several helper paths now have direct tests. |
| `T10` | Deferred | TrustMeBro paths still rely mostly on service/integration coverage rather than dedicated unit tests. |
| `T11` | Partially fixed | Some more state-transition coverage was added, but the full rejection/atomicity matrix is still incomplete. |
| `T12` | Deferred | Ignored proof-generation tests are still not wired into CI from inside this repo. |

## Next sensible work

1. Add direct Cairo unit tests.
2. Add wallet multi-input/change witness unit coverage.
3. Add a dedicated Rust/OCaml cross-implementation commitment check at `v = u64::MAX`.
4. Decide whether to implement historical root pruning and memo nonce changes as protocol changes rather than local code tweaks.
