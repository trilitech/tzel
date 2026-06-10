# Rocq model — current status

Snapshot of where the formalization stands as of branch `coq-proofs`
(continuation of `coq-model`, which is fully contained in `multiasset`;
this branch sits on top of `multiasset`).

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
- **Two-accumulator conservation (transfer + unshield):**
  `Impl/Transfer.v` `two_accumulator_conservation` — the Cairo
  balance strategy (witness-declared `primary_non_tez_asset`, per-
  entry `{tez, primary}` gate, separate tez / primary accumulator
  equations) implies the abstract per-asset
  `Spec.Transfer.phi_value_conservation` for EVERY asset, including
  ones absent from the transaction. `acc_tez` / `acc_primary`
  mirror the Cairo routing literally (primary lane = "not tez",
  with the gate doing the work — the proof fails without it,
  which is the missing-assert check working as intended).
  `Impl/Unshield.v` `unshield_two_accumulator_conservation` reuses
  it with the public exit modeled as a prepended `(asset_pub,
  v_pub)` output entry; its `Hgate_exit` hypothesis is precisely
  the Phase E.5 bug-#1 fix (`assert(asset_pub ∈ {tez, primary})`)
  — the corollary is not derivable without it. This closes the
  value-conservation leg of the `Relation -> Phi` refinement for
  both spending circuits (PR #36 review-attention item 1).

- **Batch double-spend prevention (this iteration):**
  `Spec/Hashes.v` `batch_nullifier_set_faithful`: a list of spend
  descriptors `(nk_spend, cm, pos)` has no duplicates IFF its
  nullifier list has no duplicates. Forward (non-trivial, CR
  direction, via `desc_nf_injective` <- `nullifier_binding`): a
  deduplicated nullifier set guarantees no note-at-position is spent
  twice in the batch. Backward (unconditional): re-spending a
  descriptor reproduces its nullifier so the dedup always catches
  it. Conclusion: the kernel rejecting duplicate nullifiers prevents
  EVERY double-spend and ONLY double-spends (no false rejection of
  distinct spends). This lifts the per-note `nullifier_binding` to
  the batch-level protocol guarantee.

- **Malleability resistance / signature binding (this iteration):**
  - `Spec/Hashes.v` `sighash_fold_injective`: under H_sighash
    collision resistance, the fold is injective on EQUAL-LENGTH
    field lists (same sighash + same length => same accumulators and
    same fields). The equal-length hypothesis is shown necessary,
    not incidental (a hash output can alias a raw shorter-run
    accumulator); every circuit's sighash folds a fixed-length
    field list so it always holds. Plus `sighash_binds_fields`
    (same-tag specialization) and `app_eq_len_l` (prefix-split
    utility).
  - `Spec/Transfer.v` `transfer_sighash_binds`: assembles those over
    the transfer sighash layout — two accepted transfers sharing a
    sighash AND input count publish byte-identical public outputs
    (auth_domain, root, every nullifier, fee, all four cms, all four
    memo hashes). Since the WOTS+ signature is over the sighash,
    this is the formal "sign what you see" guarantee: a relayer
    cannot alter any public field without invalidating the
    signature.
  - `Spec/Unshield.v` `unshield_sighash_binds` and `Spec/Shield.v`
    `shield_sighash_binds`: the SAME guarantee proved (not just
    asserted) for the other two circuits. Unshield binds the L1
    exit triple (v_pub, asset_pub, recipient) that releases real
    funds, both change commitments, the producer commitment, and
    all memo hashes (same input-count hypothesis as transfer).
    Shield has no inputs, so its field list is structurally
    fixed-length and equal sighashes ALONE force every public field
    equal — no count hypothesis needed.
  - `Spec/Hashes.v` `replay_resistant`: the cross-circuit capstone.
    Under CR, two transactions starting from DIFFERENT type tags
    (transfer 0x01 / unshield 0x02 / shield 0x03 / pubkey 0x04) that
    fold the same NUMBER of public fields can never share a sighash,
    so a WOTS+ signature valid for one circuit is never valid for
    another — blocking sign-a-transfer-replay-as-shield confusion at
    the signature layer. Equal-arity is the in-scope case; cross-
    arity confusion is blocked outside the model by the kernel's
    per-circuit program-hash pinning (documented in the theorem).

- **GLOBAL no-inflation law (NEW — `Spec/Ledger.v`):** the headline
  system-wide theorem, from circuit soundness, NOT a pool/turnstile
  argument. Models the shielded ledger as a state machine (deposit
  log, exit log, live-note multiset) with two transitions:
  `step_deposit` (value enters) and `step_settle` (the common
  shield/transfer/unshield shape: consume a sub-multiset of live
  notes, produce new ones, send `exits` out, under per-asset
  conservation). `reachable_invariant`: every state reachable from
  `genesis` satisfies `deposited(a) = exited(a) + live(a)` for every
  asset. `no_inflation`: hence `exited(a) <= deposited(a)` always —
  no interleaving of operations can move more of any asset out than
  came in (public withdrawals are exits, so withdrawn <= deposited).
  The settle step has NO pool-balance check; its only structural
  condition is `live = consumed ++ rest` (consumed notes are really
  present), which is what Merkle membership + nullifier uniqueness
  (`batch_nullifier_set_faithful`) deliver. Bridges
  `settle_conservation_of_transfer` / `_unshield` show the settle
  step's per-asset conservation hypothesis IS exactly
  `phi_value_conservation` / `phi_unshield_value_conservation` with
  the right exit list, so a proven transfer/unshield induces a valid
  step. REMAINING SEAM: the multiset-containment consumption rule is
  modeled (justified by the separately-proven membership/nullifier
  lemmas) rather than mechanically threaded from a circuit trace —
  closing that (carry a nullifier set in the Step state, prove
  consumed notes fresh) is the next tightening.

- **SEAM CLOSED — `Spec/LedgerNf.v`:** the faithful no-inflation
  model. Append-only `committed`; spending MARKS a nullifier in a
  growing `spent` set (nothing deleted); live value DERIVED (a
  committed note counts iff its nullifier is unspent). Settle
  consumes only under membership (`Permutation committed (consumed
  ++ rest)`) + freshness (consumed nfs unspent); `wf` carries NoDup
  committed-nfs (= nullifier_binding) + spent ⊆ committed_nfs + NoDup
  spent. Re-proves `reachable_conserved` and `no_inflation`, adds
  `no_double_spend`. `Print Assumptions no_inflation` = Felt +
  Felt_eq_dec only (no CR axiom; CR enters only via the wf
  invariant). `note_sum_is_sum_at` bridges to the circuits'
  phi_value_conservation. Consumption is now DERIVED from membership
  + freshness + uniqueness, not modeled. Documents the nat/overflow
  idealization (faithful given Cairo u64 range checks + u128
  accumulator headroom).

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
  STATUS: TRANSFER IS DONE — `Impl/Transfer.v` defines the
  Cairo-shaped `TransferRelation` (CairoInput/CairoOutput records
  mirroring the witness spans; recomputed-not-trusted cm/otag/rcm;
  Merkle + XMSS legs via `Spec.Xmss.merkle_verify` /
  `xmss_verify_cairo_sep`; the sighash fold in Cairo order; the
  two accumulator equations) and proves `transfer_relation_sound :
  TransferRelation -> Phi_transfer` with every conjunct closing.
  `Spec/Xmss.v` gained `xmss_verify_cairo_sep`, a domain-separated
  variant of `xmss_verify_cairo` (the original conflates the
  L-tree and auth-tree node hashes, which the Cairo separates by
  ADRS tag and key_idx slot — the relation uses the faithful one).
  UNSHIELD IS DONE — `Impl/Unshield.v` `UnshieldRelation` +
  `unshield_relation_sound`, reusing transfer's `input_checks`
  verbatim (the Cairo input loops are identical), modeling the
  optional change slots faithfully (`change_slot_checks` mirrors
  `change_commitment_or_zero`'s publish-0-and-zero-assert-all
  semantics) and the exit-folded accumulator equations.  Two spec
  fixes fell out of writing it: `Spec/Unshield.v`'s per-output
  well-formedness was TOO STRONG (it demanded commitment
  well-formedness of absent slots, which publish literal 0 — now
  `phi_unshield_change_slot` is present-or-absent, with
  `phi_unshield_change_absent` capturing the zero-pinning), and
  `phi_unshield_sighash`'s field order grouped cms-then-memos
  while the Cairo INTERLEAVES (cm, memo) pairs — binding-
  equivalent, but a byte-level model<->circuit differential would
  have flagged it (now matches the circuit exactly).
  SHIELD IS DONE — `Impl/Shield.v` `ShieldRelation` +
  `shield_relation_sound`.  No inputs / Merkle / nullifiers; the
  relation binds pubkey_hash, the recipient note's owner_tag, and
  the WOTS+ verification to the SAME (auth_root, auth_pub_seed).
  The dual-pool conservation conjunct is kernel-side (the circuit
  never sees pool balances), so the soundness theorem takes the
  debit equations as an explicit hypothesis in
  `phi_shield_value_conservation`'s exact shape — the seam where
  a future kernel model plugs in.
  HIGH-LEVEL PROPERTIES (this iteration):
  - `Spec/Hashes.v` `nullifier_binding`: under H_nf injectivity
    (CR), equal nullifiers imply the same (nk_spend, cm, pos) —
    the double-spend soundness direction, complementing
    `nullifier_deterministic` (completeness).
  - `Spec/Transfer.v` `batch_value_conservation`: per-tx
    `phi_value_conservation` COMPOSES over a list of accepted txs —
    for every asset, total in = total out + (tez fees burned).
    No sequence of transfers inflates any asset's supply; non-tez
    assets conserved exactly. Proved via `sum_at_app`
    (parallel-list concatenation distributes).
  CONFORMANCE / FUZZING:
  - `coq/Extracted/build.sh` now guards the differential-test
    snapshot: it fails loudly (or refreshes under
    REFRESH_TEST_SNAPSHOT=1) if `ocaml/coq_driver/test`'s tracked
    `tzel_wots.{ml,mli}` drift from the fresh Rocq extraction, so
    the QCheck2 harness can never silently validate stale code.
  - `.github/workflows/coq.yml` now RUNS the differential test
    (`dune test coq_driver/test`, 15k random witnesses/run:
    10k single chain-step + 5k iterated) after the smoke vector —
    previously the harness existed but no workflow executed it.
  COMMITMENT CONFORMANCE (this iteration):
  - `Impl/Hashes.v`: added `Hash5` (the 5-input multiasset
    commitment hash) + top-level `commit` + `commit_refines_spec`
    (commit = Spec.Hashes.commitment under H_commit := Hash5,
    mirroring Impl.Wots.refines_spec).
  - `Impl/Extraction.v`: realizes `Hash5` => `Tzel.Hash.hash_commit`
    and extracts `commit` alongside `xmss_chain_step`.
  - Differential harness now covers the commitment: 10k random
    5-felt fuzz cases (asset drawn from the FULL felt range, so the
    multiasset binding is exercised) PLUS a non-tautological
    golden-vector case pinning the extracted Coq `commit` to
    `commitment_u64_max_v1.json` — the same fixture Rust core checks
    and the cross-impl interop derives from Cairo. So the
    commitment now has Rocq <-> OCaml <-> Cairo transitive
    assurance, byte-for-byte against a golden value (not just
    structural).
  NULLIFIER CONFORMANCE (this iteration): same pattern extended to
  the nullifier — `Impl/Hashes.v` `Hash_nf` + `nullifier nk cm pos
  := H_nf nk (H_nf cm pos)` + `nullifier_refines_spec` (so the
  proven `Spec.Hashes.nullifier_binding` transfers to the
  extractable fn). Realized `Hash_nf => Tzel.Hash.hash_nf`,
  extracted `nullifier`. Differential: 10k random fuzz (structural,
  pins the nk-outside/cm-pos-inside nesting) + a non-tautological
  golden vector against protocol_v1.json notes[0]'s nf (Rust-gen,
  Cairo-pinned). The two security-critical multiasset primitives
  (commitment, nullifier) now both have Rocq <-> OCaml <-> Cairo
  conformance, golden-anchored.
  SIGHASH-FOLD CONFORMANCE (this iteration): the binding primitive
  the malleability theorems are stated about is now differentially
  tested. `Impl/Hashes.v` `Hash_sighash` + `sighash_fold acc fields
  := Spec.Hashes.sighash_fold Hash_sighash ...` +
  `sighash_fold_refines_spec`. Realized `Hash_sighash =>
  Tzel.Hash.hash_sighash`, extracted (with Coq `list` now mapped to
  native OCaml list). Differential: 10k random fuzz (random acc +
  random-length field list) + non-tautological golden vector
  against protocol_v1.json sighash[0] (Rust-gen, Cairo-pinned). So
  the malleability proofs (transfer/unshield/shield_sighash_binds)
  now constrain a computation shown byte-equal to the Cairo's.
  Differential suite is now 8 cases: chain step x2, commit
  fuzz+golden, nullifier fuzz+golden, sighash fuzz+golden.
  MERKLE-ROOT CONFORMANCE (this iteration): the last security-
  critical primitive (membership = spend authorization) is now
  differentially tested. Realized `Hash2_merkle =>
  Tzel.Hash.hash_merkle`, mapped Coq `bool` => native OCaml bool,
  extracted `merkle_compute_root : bool list -> felt list -> felt
  -> felt`. Differential: 10k random fuzz (random depth 0..16,
  parallel bit/sibling lists) vs the port's
  `Tzel.Merkle.root_from_path` (cross-impl pinned to Cairo
  merkle::verify) + a golden anchor reaching protocol_v1.json
  merkle[0]'s Rust-generated root via the port's auth_path.
  ALL FIVE security-critical primitives now have Rocq <-> OCaml
  <-> Cairo conformance (golden-anchored where a direct fixture
  exists): WOTS chain step, commitment, nullifier, sighash fold,
  merkle root. Differential suite = 10 cases.
  Remaining: realize the FULL transfer/unshield/shield relations +
  Cairo-side `run_*` runners for whole-circuit (assembled-relation)
  conformance — the primitives are all covered; the assembly is not
  yet run end-to-end against Cairo.

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
