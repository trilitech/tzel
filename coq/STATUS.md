# Rocq model — current status

Snapshot of where the formalization stands as of branch `coq-model`,
commit pending. Pause here; main-branch PR review takes priority.

## Architecture (recommended by team expert)

Three layers, with the spec layer derived from documents (whitepaper
+ spec.md), not the Cairo code:

```
docs/whitepaper.tex + specs/spec.md
            │
            ▼ (transcribe)
        coq/Spec/                ← whitepaper-derived abstract spec
            │
            ▼ (refine + prove refinement)
        coq/Impl/                ← extractable, Cairo-shaped refinement
            │
            ▼ (Coq → OCaml extraction)
        certified OCaml model
            │
            ▼ (PBT / QCheck2 conformance)
        cairo/src/*.cairo        ← actual on-chain implementation
```

Strict requirement: **no `admit` anywhere**. Every theorem closes.

## Done

- **Branch + scaffolding:** `coq-model` branch exists with the
  three-layer directory structure: `coq/Common`, `coq/Spec`,
  `coq/Impl`. `_CoqProject` lists all three with `-Q` mappings.
- **Drift detection:** `coq/MANIFEST.toml` pins SHA-256 of every
  modeled Cairo file; `coq/Drift/check.sh` re-hashes and fails CI
  on divergence. Verified working in CI on the previous scaffolding
  commit.
- **CI:** `.github/workflows/coq.yml` runs the drift check and (now,
  pending the build job's first run on this restructure) builds the
  Rocq theory via opam-installed `rocq-prover`. Same opam-via-
  setup-ocaml pattern as the OCaml unit tests workflow — actions
  pinned to commit SHAs.
- **`Common/Felt.v`:** opaque [Felt] type, shared between Spec and
  Impl so refinement statements can mention the same type on both
  sides.
- **`Spec/Wots.v`:** abstract WOTS+ chain step. Defines `step` (one
  application of `F pub_seed (ADRS k c s) x`) and `iter` (n-step
  iteration, with the step counter incrementing). Parameterized
  over the hash and the address encoding. Whitepaper-derived; does
  *not* look at the Cairo. Definitions only — proofs land next.
- **`Spec/Hashes.v`:** protocol constants (`wots_w = 4`,
  `wots_chain_len = 3`, `wots_chains = 133`, `auth_depth = 16`,
  `tree_depth = 48`) and hash-family documentation.
- **`Spec/Merkle.v`:** abstract Merkle path verification (two
  variants). `merkle_root` for the commitment tree (uniform hash);
  `auth_root` for the XMSS auth tree (level/position-indexed hash).
  Proved: `merkle_root_nil`, `merkle_root_cons`, `merkle_root_app`
  (path composition — the Merkle analogue of `iter_compose`),
  `merkle_root_snoc`, `auth_root_nil`, `auth_root_cons`.
- **`Spec/Xmss.v`:** L-tree compression and XMSS verifier skeleton.
  `pair_nodes` (structurally recursive pairwise compression),
  `pair_nodes_length_le` (monotonicity proof), `ltree_aux` /
  `ltree` (fuel-bounded iteration), `ltree_singleton` and
  `ltree_pair` proved.  `recover_endpoint` / `recover_all` (WOTS+
  pubkey recovery using `Wots.iter`), `recover_endpoint_correct`
  (recovery is correct — corollary of `Wots.recover_correct`).
  `xmss_verify` predicate combining recovery → L-tree → auth path.
- **`Spec/Transfer.v` / `Spec/Shield.v` / `Spec/Unshield.v`:** stubs
  with intent docs explaining what each will model.
- **`Impl/Common.v`:** placeholder for impl-side shared declarations.
- **`Impl/Hashes.v`:** declares `Hash3` and `Hash4` parameters
  (concrete, will be realized at extraction).
- **`Impl/Wots.v`:** mirrors Cairo `xmss_chain_step` as a one-line
  Coq function. Contains an `pack_adrs_chain` parameter for the
  ADRS encoding. Refinement theorem `refines_spec` closes by
  `reflexivity`.
- **`Impl/Merkle.v`:** instantiates `Spec.Merkle` with concrete
  hash parameters.  `merkle_compute_root` for the commitment tree
  (via `Hash2_merkle`), `auth_compute_root` for the auth tree (via
  `Hash4` + `pack_adrs_tree`).  Refinement theorems close by
  `reflexivity`.
- **`Impl/Xmss.v`:** instantiates `Spec.Xmss` L-tree and recovery
  with concrete hash parameters (`Hash4` + `pack_adrs_ltree`,
  `Hash3` + `pack_adrs_chain`).  Soundness proofs pending.
- **`Impl/{Transfer,Shield,Unshield}.v`:** stubs with intent docs.
- **`Spec/Wots.v` chain-step lemmas:** `iter_succ`,
  `iter_compose`, and `recover_correct` proved.  `recover_correct`
  states that chaining a signature element forward by the remaining
  steps recovers the public key endpoint — follows directly from
  `iter_compose` and arithmetic.  Foundation for XMSS verifier
  soundness.
- **`Impl/Wots.v` refinement:** `Theorem refines_spec` closes by
  `reflexivity` — `xmss_chain_step` equals `Spec.Wots.step` under
  the realized `Hash3` / `pack_adrs_chain`. Future Spec-level
  lemmas about `step` now transfer to the extractable function.
- **Extraction + OCaml driver (re-port):** `Impl/Extraction.v`
  realizes `Felt → bytes`, `nat → int`, and writes
  `tzel_wots.{ml,mli}` to `coq/Impl/`. The driver moved from
  `coq/Extracted/` into the OCaml dune workspace at
  `ocaml/coq_driver/` so it can link against `tzel`.
  `coq/Extracted/build.sh` orchestrates: copy the extracted
  files into `ocaml/coq_driver/`, `dune build`, symlink the
  binary back to `coq/Extracted/chain_step` for stable invocation.
- **Real `Hash3` / `pack_adrs_chain` realizations:** the
  extraction directives now wire to `Tzel.Hash.hash3` (BLAKE2s
  of `pub_seed || ADRS || x`, truncated to 251 bits) and to
  `Tzel.Wots.pack_adrs Tzel.Wots.tag_xmss_chain key chain step
  0`, both bit-equivalent to the Cairo under the existing
  cross-impl interop check. The CI smoke runs the driver on
  the zero-input vector and asserts the result equals the
  reference value computed via the OCaml port directly
  (`5ca134c7…155466807`).

- **Soundness infrastructure (CR + binding):**
  - `Spec/Hashes.v`: `injective_2`, `injective_4`, `node_injective`
    — collision resistance modeled as injectivity. Taken as Section
    hypotheses, never globally axiomatized.
  - `Spec/Merkle.v`: `merkle_binding` — same root + position bits
    implies same leaf AND siblings (under CR). `auth_binding` — same
    for the XMSS auth tree with per-slot node hash injectivity.
  - `Spec/Xmss.v`: `pair_nodes_injective` — pairwise L-tree
    compression is injective under CR.
  - `Spec/Xmss.v`: `xmss_verify_unique_leaf` — two signatures
    verifying against the same root and position recover the same
    leaf. Follows from `auth_binding`.
- **XMSS completeness:** `xmss_completeness` — if a signer has
  valid secret keys, signs with valid digits, and provides a correct
  auth path, then `xmss_verify` holds. Assembles `recover_all_correct`
  + `ltree_succeeds` + auth-path hypothesis.
- **Sighash + nullifier definitions:** `sighash_fold` with
  composition proof, `commitment`, `nullifier` (position-dependent).

## Not done

### Cairo runner for differential check (next concrete piece)

Add `cairo/src/run_chain_step.cairo` as an executable target in
`Scarb.toml`. Takes 5 felts as input, calls
`xmss_common::xmss_chain_step`, returns the result. Lets the
differential driver call Cairo as a subprocess.

### QCheck2 conformance harness

OCaml driver:
- Generate random `(x, pub_seed, key_idx, chain_idx, step)`
- Run the extracted Coq's `xmss_chain_step` (with OCaml
  protocol-port realizations)
- Run the Cairo `run_chain_step` executable on the same inputs
- Assert outputs byte-equal

Initial budget: ~30 seconds per CI run, scheduled longer runs
nightly. After basic conformance lands, ask for edge-case search;
divergences trigger triage:
- Spec model bug → fix Spec, re-derive Impl refinement
- Cairo bug → fix Cairo
- Generator bug → fix generator

### Beyond chain step

Once the Wots chain-step pattern is end-to-end (Spec proofs +
refinement + extraction + conformance), the same shape repeats for:
- Merkle path verification (`Spec.Merkle` ↔ `Impl.Merkle`)
- L-tree compression (extension of `Spec.Wots`)
- Full XMSS verifier (`Spec.Xmss` ↔ `Impl.Xmss`) — the headline
  module; soundness theorem here is the most subtle and the
  highest-value to mechanically check
- The three top-level circuits: `Spec.Transfer` ↔ `Impl.Transfer`,
  same for shield + unshield. Soundness predicates `Phi_*` enumerate
  the protocol-level safety properties; the Spec proofs force the
  `*Relation pub wit -> Phi pub` chain to close on actual Coq
  assertions, which is the missing-assertion check.

## Open questions / decisions deferred

1. **Whether to formalize XMSS unforgeability or axiomatize it.**
   Light path: state the standard XMSS unforgeability theorem as a
   parameter, leaning on the published Hülsing et al. proofs. Heavy
   path: re-derive in Rocq from PRF/PRE/SM-DSPR axioms. Light is
   the obvious starting point; heavy is a separate research-grade
   undertaking we may never need.

2. **mathcomp dependency.** Not yet pulled in. Will likely want
   `mathcomp-ssreflect` for tactic ergonomics when proofs grow;
   `mathcomp-algebra` if we end up reasoning about the Stark prime
   field algebraically. Adding both is one opam install line; not
   urgent until the proofs feel painful in vanilla Rocq.

3. **LaTeX-aligned spec step.** The expert recommended writing the
   spec in LaTeX first and aligning before going to Rocq for
   non-trivial pieces. Currently we're going straight to Rocq for
   the WOTS+ chain step (small enough to skip LaTeX). For the full
   XMSS verifier and the per-circuit safety predicates, the LaTeX
   step is probably worth it — roughly the same size as the
   whitepaper's existing math sections.

## Resumption checklist

When picking this back up:

1. `git checkout coq-model`
2. Read `coq/STATUS.md` (this file)
3. Re-read `coq/README.md` for the architecture refresher
4. Pick the next concrete piece — currently: add the Cairo-side
   `cairo/src/run_chain_step.cairo` executable target to
   `Scarb.toml` so the same chain-step witness can be evaluated
   from Cairo, then build a QCheck2 differential harness that
   feeds randomized witnesses to the extracted driver and the
   Cairo runner and asserts byte-equality.
5. Run CI on each commit; the build job will catch syntax issues
   that can't be caught locally without an opam Rocq install
