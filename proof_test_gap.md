# Transfer Input Cap Analysis

## Current operational decision

The live cap for both transfer and unshield is **N=7**.

This is a prover-capacity cap, not a protocol-soundness or XMSS-capacity cap. The current Cairo proving configuration supports `N=7` safely across both circuits and fails loudly beyond that common ceiling.

## Empirical results

These results came from real proving with current post-XMSS witnesses, not from `TrustMeBro` placeholders.

### Single-level Cairo proving

| N | Transfer | Unshield |
|---|----------|-----------|
| 1 | Pass | Pass |
| 2 | Pass | Pass |
| 4 | Pass | Pass |
| 7 | Pass | Pass |
| 8 | Pass | Fail (`Not enough twiddles!`) |
| 9 | Fail (`Not enough twiddles!`) | Not re-run after `N=8` failure |
| 10 | Fail (`Not enough twiddles!`) | Not re-run |
| 12 | Fail (`Not enough twiddles!`) | Not re-run |
| 16 | Fail (`Not enough twiddles!`) | Not re-run |

### Relevant measured traces

| Case | Cairo steps | Outcome |
|------|-------------|---------|
| transfer `N=7` | `2,575,428` | Pass |
| transfer `N=8` | `2,904,781` | Pass |
| unshield `N=7` | `2,669,139` | Pass |
| unshield `N=8` | `3,104,207` | Fail |
| transfer `N=16` | `5,595,817` | Fail |

The important operational fact is that `unshield N=8` fails while `transfer N=8` still passes, so the common safe deployment cap is `7`.

## What this does and does not mean

- This is **not** a silent truncation issue. The observed failure mode is loud prover failure (`Not enough twiddles!`), not acceptance of an invalid proof.
- This is **not** an XMSS tree-size limit. The failure comes from Cairo/Stwo proving capacity for the full spend statement, which includes XMSS/WOTS verification, commitment-tree paths, and note logic.
- This is **not** evidence that `N=8` is fundamentally out of reach. The gap between `transfer N=8` and `unshield N=8` is modest enough that a deliberate prover-capacity extension may recover `8`.

## Current test coverage around the boundary

- Live code enforces `N <= 7` in:
  - `cairo/src/transfer.cairo`
  - `cairo/src/unshield.cairo`
  - `core/src/lib.rs`
- Fast boundary tests assert:
  - `N=7` succeeds
  - `N=8` is rejected
- The slow ignored real-proof integration guard is now:
  - `test_transfer_7_inputs_proof_roundtrip`
- Bench cases now include real witness generation for:
  - `Unshield (N=7)`
  - `Consolidate (N=7)`

## Why the cap is 7 today

The Cairo reprover uses a fixed Cairo-level capacity configuration. Under that configuration:

- `transfer N=8` still fits
- `unshield N=8` does not

Because deployments need one shared supported limit across both circuits, the honest current cap is `7`.

## Likely next step if we want 8 back

`N=8` looks plausibly recoverable with a modest proving-capacity increase. The measured step counts suggest the gap is not huge; the problem is that the current proving configuration sits on a hard boundary.

The right future path is:

1. keep the live cap at `7`
2. extend the Cairo proving capacity carefully
3. re-measure `unshield N=8`
4. only raise the cap once both transfer and unshield pass under the same supported configuration

The wrong path is to pretend `16` works today or to raise the cap without a real proof run.
