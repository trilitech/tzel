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

## Integrity audit (full-theory health check)

Verified on a clean rebuild from scratch:
- **25 Spec modules + Impl + Common** build under Rocq 9.0.0 (~16s).
- **Zero admits** anywhere (`grep Admitted|admit\b` = 0); strict
  no-`admit` requirement met.
- **Minimal, honest axiom base (comprehensive)** — `Print Assumptions`
  across 23 HEADLINE theorems spanning every component (no-inflation
  for all flows + multiasset, per-note value/asset/auth binding,
  nullifier binding, faerie-gold, double-spend, shield-replay, WOTS/
  XMSS one-time unforgeability, bridge collateralization, burn
  authentication, deposit anti-spoofing, registry routing, per-asset
  L1<->L2 solvency, storage-path & deposit-key collision-freedom,
  withdrawal serialization, the full O(depth) Merkle frontier, merkle
  binding) shows the ENTIRE body of work depends on EXACTLY TWO
  axioms: `Felt : Type` and `Felt_eq_dec`. The hash functions are
  uninterpreted `Parameter`s with NO global properties; every
  collision-resistance / injectivity assumption is a LOCAL Section
  hypothesis, never a global axiom. (The clean rebuild also guards
  against stale .vo — it caught a local stale MerkleFrontierCorrect.vo
  that a clean build resolves; CI always builds clean.)
- **Drift check 6/6**: the Cairo↔Coq mirrors match (SHA-pinned).
- **Differential faithfulness 13/13**: extracted Coq functions
  (chain-step, commit, nullifier, sighash, merkle path, and the
  Merkle tree model root_of/mroot/tdfront) match the cross-impl-tested
  OCaml port byte-for-byte under fuzzing.

## Verification map (how the layers compose)

```
circuit no-inflation (any shield/transfer/unshield mix, any asset)   [GrandConservation]
        │  grounded in the real per-flow circuit relations
        ▼     (unshield_is_op / shield_is_op ↔ phi_*_value_conservation)
kernel value conservation (withdrawn ≤ deposited, per asset)          [KernelLedger, KernelPool]
        │  + deposit anti-spoofing, registry routing, double-spend,
        │    shield-replay, storage-path & deposit-key collision-freedom
        ▼
per-asset L1↔L2 collateralization (custody = pool + notes, ∀ asset)   [EndToEndMulti, EndToEnd]
        │  bridge holds exactly the FA2 backing each asset's L2 claims
        ▼
L1 bridge contract: exact collateralization + mint anti-spoof +       [BridgeTicketer, BridgeBurn,
   burn authentication (no foreign-ticket drain)                       KernelDeposit]
```
Underneath: WOTS+ one-time unforgeability, append-only Merkle
correctness (general index), withdrawal-record serialization safety,
nullifier/commitment binding.

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
- **`Spec/Transfer.v` / `Spec/Shield.v` / `Spec/Unshield.v`:** (this
  early "stub" description is SUPERSEDED) — now full circuit relations
  with proven theorems: per-asset value conservation, batch
  no-inflation (`batch_value_conservation`,
  `batch_unshield_value_conservation`), and sighash non-malleability
  (`transfer_sighash_binds` / `shield_sighash_binds` /
  `unshield_sighash_binds`). See also the unified
  `GrandConservation.grand_conservation`.
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
  `Hash3` + `pack_adrs_chain`).  (Earlier "soundness proofs pending"
  is SUPERSEDED — `Spec.Xmss` now has `ltree_injective`,
  `xmss_verify_unique_leaf`, `xmss_soundness_reduces_to_wots`,
  `wots_one_time_unforgeable`, and the assembled
  `xmss_one_time_unforgeable`.)
- **`Impl/{Transfer,Shield,Unshield}.v`:** extractable refinements of
  the corresponding `Spec` relations (the earlier "stubs with intent
  docs" is superseded).
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

- **OVERFLOW SAFETY PROVED — `Spec/LedgerBounded.v`:** the nat
  idealization's faithfulness, mechanized rather than asserted.
  - `tx_conservation_mod_iff`: for ANY modulus `ab` with headroom
    `mx * vb < ab`, a conservation check in arithmetic mod `ab`
    (`note_sum consumed mod ab = note_sum outputs mod ab`) is
    EQUIVALENT to true-integer conservation. Covers the Cairo u128
    accumulators (ab = 2^128) AND a field check (ab = the ~2^251
    prime) — neither can wrap to fake or hide conservation, given
    value/count bounds. Built on `note_sum_lt` (bounded note totals
    stay < ab) and `mod_eq_iff` (mod = id below the modulus).
  - `headroom_u128`: the side condition holds for real widths —
    `(11 * 2^64 < 2^128)%N`, proved by `vm_compute` in binary N
    (nat can't represent 2^128). 11 covers a transfer's worst case.
  - `totals_bounded_by_deposit` / `totals_under_supply_cap`:
    globally exited, live <= deposited in every reachable state, so
    under a supply cap deposited <= B all running totals stay <= B
    (no kernel-total overflow at any width holding B). The cap is a
    world-fact hypothesis; the implication is proved.
  The earlier nat/overflow caveat in LedgerNf is now discharged: the
  model's `nat` arithmetic provably coincides with the real bounded
  (u128 / field) arithmetic under the circuit's range + count bounds.

- **KERNEL POOL SOLVENCY (`Spec/KernelPool.v`) — NEW SCOPE:** the
  first proof about the rollup KERNEL (not the circuits). Models the
  per-pool deposit accounting in tezos/rollup-kernel/src/lib.rs
  (`credit_deposit` = checked_add rejecting u64 overflow;
  `debit_deposit` = rejects when balance < amount) as a state machine
  over (balance, credited, debited). Proves:
  - `pool_invariant_reachable`: every reachable pool satisfies
    balance = credited - debited AND debited <= credited;
  - `kernel_solvency`: hence debited <= credited always — no
    sequence of deposits + shields can shield out more of a pool than
    was deposited (the kernel-side complement of circuit no-inflation;
    `Print Assumptions` = just the abstract u64 ceiling);
  - `balance_never_negative`: balance = credited - debited (the
    `current < amount -> Err` underflow guard IS the debit
    precondition);
  - `credit_overflow_rejected`: a positive credit breaching the u64
    ceiling takes no step (mirrors checked_add -> None; the false
    amt=0 case was caught and excluded by a positivity hypothesis).
  Pools are path-keyed so distinct (asset, pubkey_hash) pools are
  independent — single-pool captures the accounting; per-asset
  aggregate is the independent sum. Faithfulness is by transcription
  of credit/debit_deposit (validated by reading the kernel).

- **END-TO-END KERNEL CONSERVATION (`Spec/KernelLedger.v`):** joins
  the pool accounting (`Spec.KernelPool`) and the note system
  (`Spec.LedgerNf`) into ONE aggregate per-asset model over the whole
  kernel value lifecycle. State tracks, per asset: deposited, in
  pools, in live notes, burned (fees), withdrawn. Invariant
  (preserved by every transition): `dep a = pool a + notes a +
  burned a + wd a`. Transitions mirror kernel moves: deposit (L1->
  pool), shield_tez (single pool -> recipient+producer notes + fee
  burn), shield_fa2 (the DUAL-POOL FA2 shield — FA2 pool funds
  v+fee AND the tez pool funds producer_fee, so the tez producer note
  is backed not minted; the only two-asset transition, where "no
  unbacked tez" lives), withdraw (note -> L1), burn_fee (note ->
  burned). Theorems (zero admits):
  - `no_inflation`: ks_wd a <= ks_dep a — withdrawn never exceeds
    deposited, across deposits/shields/withdrawals/fees including the
    FA2 dual-pool path.
  - `outflows_backed`: wd + live-notes + burned <= deposited — the
    sharper "every outflow and live note is backed by a deposit",
    confirming FA2-shield producer tez is fully backed.
  Faithfulness boundary: the per-asset note-internal conservation a
  transfer relies on is the LedgerNf result; this adds the
  pool<->note<->L1 boundary at the aggregate level.

- **DEPOSIT ANTI-SPOOFING (`Spec/KernelDeposit.v`):** models the
  kernel's bridge-deposit acceptance (parse_bridge_deposit +
  validate_bridge_deposit) and proves you cannot forge a pool credit.
  `accept` = creator=sender (authentic, non-forwarded ticket) AND
  token_id=0 AND metadata=None AND recipient canonical AND verifier
  configured AND sender registered. Proved (zero admits):
  - each spoof vector is rejected: forwarded ticket (creator<>sender),
    unregistered sender, nonzero token_id, present metadata,
    unconfigured verifier — each implies ~accept;
  - accept_authentic_and_registered: every accepted deposit is
    authentic and credits a registered asset;
  - credit_requires_owning_ticketer: to credit asset A you must be
    the registered ticketer for A (the authentic creator maps to A);
  - credit_ticketer_unique: under registry injectivity (one ticketer
    per asset — derive_asset_id is a CR hash) the crediting ticketer
    is unique, so only its holder can credit A.
  Ticket authenticity (creator IS the minter) is the L1 guarantee
  taken as the meaning of creator=sender (out of scope); everything
  downstream the kernel enforces is proved.

- **L1 BRIDGE COLLATERALIZATION (`Spec/BridgeTicketer.v`):** models
  the Michelson FA2 bridge ticketer (tezos/fa2_bridge_ticketer.tz)
  and proves it is ALWAYS EXACTLY collateralized. State: bt_custody
  (FA2 held by SELF), bt_outstanding (SELF-minted tickets in
  circulation), bt_in/bt_out (running FA2 totals). Steps mirror the
  entrypoints: %mint (0<n; custody+=n, outstanding+=n, atomic FA2
  pull + ticket mint) and %burn (n<=outstanding, i.e. authentic
  ticketer==SELF + linearity; custody-=n, outstanding-=n). Invariant
  `bt_custody = bt_outstanding`. Proved (zero admits):
  - `fully_collateralized`: custody = outstanding always — two-sided
    (>= every ticket redeemable; <= no FA2 stranded beyond tickets);
  - `ticket_redeemable`: any n <= outstanding has the custody to be
    released (burns never fail for want of funds);
  - `bridge_solvency`: bt_out <= bt_in (FA2 released <= FA2
    deposited);
  - `custody_backed`, `no_overburn` (over-burning takes no step).
  Out of scope (L1 given): ticket linearity + creator authenticity —
  the Michelson/protocol semantics justifying that a burn can only
  consume an authentic outstanding ticket.

- **L1<->L2 CROSS-SYSTEM SOLVENCY (`Spec/EndToEnd.v`):** COMPOSES
  the bridge and kernel into one state machine, LINKED by the value
  crossing the boundary, and proves the cross-system invariant the
  separate facts only imply piecewise:
    L1 FA2 custody = L2 pool value + L2 live-note value.
  The link is the crux: a deposit credits L1 custody (bridge mint)
  AND the L2 pool by the same amount (atomic); a withdrawal debits L2
  notes (unshield) AND L1 custody (the outbox ticket the bridge
  burns) by the same amount — bridge and kernel cannot move
  independently across the boundary. Theorems (zero admits):
  - `l1_collateral_equals_l2_claims`: custody = pool + notes always;
  - `notes_backed_by_l1`: every live L2 note is backed by real L1 FA2
    (notes <= custody);
  - `no_stranded_l1`: no L1 FA2 stranded beyond L2 claims;
  - `withdrawal_honored`: any live note value has the L1 custody to
    release;
  - `roundtrip_solvency`: total withdrawn to L1 <= total deposited.
  Scope: one FA2 asset (per-asset independent); FA2-denominated fees
  taken as zero (rollup/producer fees are tez, on the tez lane in
  KernelLedger).

- **ASSET REGISTRY ROUND-TRIP CONSISTENCY (`Spec/AssetRegistry.v`):**
  models the kernel's registry (compose_asset_registry_with,
  asset_for_ticketer, ticketer_for_asset) and proves the cross-layer
  routing-correctness property the security review flagged (item 3).
  Both lookups are first-match `find`, so the round-trip is FALSE
  without: derive_asset_id injective on ticketers (CR) AND
  derive t <> ASSET_TEZ (domain separation), plus the registry's
  dedup of an FA2 ticketer equal to the tez one. Proved (zero admits,
  real list reasoning not accounting):
  - roundtrip_ta / roundtrip_at: under NoDup keys the two first-match
    lookups invert each other;
  - compose_ticketers_nodup / compose_assets_nodup: the composed
    registry has distinct ticketers AND distinct asset_ids (derive
    injective + nonzero gives the asset distinctness);
  - deposit_withdraw_roundtrip / withdraw_deposit_roundtrip: deposit
    routing (ticketer->asset) and withdrawal routing (asset->ticketer)
    are proper mutual inverses — no deposit of asset A can unlock a
    withdrawal routed to the WRONG bridge;
  - fa2_routes_correctly: a registered FA2 ticketer u routes deposits
    to derive u and withdrawals of derive u back to u.
  The CR/nonzero hypotheses are the same kind Spec.Hashes takes for
  nullifiers/commitments; here they make the cross-layer asset
  routing provably unambiguous.

- **KERNEL DOUBLE-SPEND PREVENTION (`Spec/KernelNullifier.v`):**
  models the kernel's durable nullifier set
  (has_nullifier/insert_nullifier + the within-batch "duplicate
  nullifier" reject) and proves the consensus-critical no-double-spend
  at the KERNEL boundary, complementing circuit nullifier_binding. A
  tx with nullifiers nfs is acceptable iff NoDup nfs (no within-tx
  dup) AND none already in the spent set; on accept all are inserted.
  Proved (zero admits):
  - reachable_nodup: the spent set is duplicate-free in every
    reachable state — no nullifier ever recorded by two transactions;
  - respend_rejected: a tx presenting an already-spent nullifier
    cannot step (rejected);
  - spent_is_permanent / once_spent_forever_blocked: the set only
    grows; once spent, no future state accepts a re-spend;
  - note_spent_at_most_once (composition): with the circuit
    nullifier-of-note map, each note can be consumed at most once
    across the whole history — circuit binding (nullifier identifies
    the note) + kernel dedup (each nullifier accepted once) =
    end-to-end no-double-spend;
  - distinct_notes_distinct_nullifiers: under binding-injectivity,
    distinct notes never collide, so spending one never falsely
    blocks another.

- **APPEND-ONLY MERKLE TREE (`Spec/MerkleTree.v`):** verifies the
  ALGORITHMS the kernel uses to compute commitment-tree roots
  (zero_hashes precompute + simulate_frontier_append), not an
  accounting invariant — a genuine algorithm-correctness proof.
  Against an explicit batch Merkle-root definition (build_level
  pair-and-hash, folded depth times), proved (zero admits):
  - empty_subtree: the root of an all-empty depth-h subtree equals
    zero_hash h — i.e. the kernel's precomputed zero_hashes[h] is the
    correct empty-subtree root (an off-by-one there would let a
    prover forge membership in empty slots). Via build_level_repeat
    (a uniform layer halves) + a custom hpow mirroring zero_hash's
    recursion to avoid a Nat.iter direction mismatch.
  - frontier_first_leaf: the incremental simulate_frontier_append
    (O(depth) state, never the full leaf array) computes, for the
    first appended leaf, the SAME root as the batch definition over
    [cm, z0, z0, ...]. The append-only-Merkle algorithm (Zcash /
    Ethereum deposit contract); proving it equals the structural
    batch root (via the left-spine = fold_levels of a leaf + empty
    padding) is the non-trivial correctness letting the kernel commit
    notes without storing the whole tree.
  (UPDATE: the arbitrary-append-index general case, originally listed
  here as future work, has since been PROVED — see the General Merkle
  Frontier Correctness entry below: `tdfront_correct`.)

- **SHIELD REPLAY PROTECTION (`Spec/ShieldReplay.v`):** the kernel
  records each applied shield's client_cm (applied_shield_path /
  has_marker) and rejects a shield whose cm is already present —
  without which an attacker could top up a drained pool, resubmit a
  victim's shield proof, and mint a DUPLICATE of the recipient's note
  at a fresh position (independently spendable, doubling their
  balance). The mechanism is an append-only dedup set, structurally
  identical to the nullifier set — so rather than duplicate the
  proof, this INSTANTIATES Spec.KernelNullifier's polymorphic
  machinery at the commitment type. Proved (zero admits):
  - applied_set_nodup: no commitment is recorded by two shields;
  - shield_replay_rejected: a shield re-presenting an applied cm
    cannot step;
  - no_duplicate_shielded_note: once cm c is shielded, no reachable
    future shield carrying c is accepted — the recipient note is
    minted at most once; the balance cannot be doubled by replay.
  Demonstrates one verified mechanism (the append-only dedup set)
  covering TWO distinct attacks: double-spend (nullifiers) and
  shield-replay note-duplication (commitments).

- **GENERAL MERKLE FRONTIER CORRECTNESS (closed — `Spec/MerkleTree.v`):**
  the previously-deferred hard item, now proved for ARBITRARY append
  index. Key move: a top-down recursive model `tdfront d pre cm`
  (insert cm at position length pre) that carries the prefix
  explicitly, so the stored left-subtree roots become
  `mroot d' (firstn (2^d') pre)` — exactly what the kernel stores as
  branches[]. `tdfront_correct`: length pre < 2^d -> tdfront d pre cm
  = mroot d (pre ++ [cm]). Every insertion, not just the first,
  computes the true batch Merkle root with O(depth) state — clean
  induction on depth with the left/right half case split (firstn/
  skipn + mroot_nil). `mroot_nil` (recursive batch root of [] =
  zero_hash d) ties it to the empty-subtree result. Faithfulness:
  tdfront is the top-down form of the kernel's bottom-up frontier
  loop (same stored data = completed-left-subtree roots, same root);
  the loop direction is an implementation detail.

- **MERKLE MODEL DIFFERENTIAL (faithfulness, `coq_driver/test`):**
  closes the by-inspection gap for the append-only-tree proofs. The
  kernel state-machine models so far were faithful by transcription;
  this validates the Merkle MODEL the way the circuit primitives were
  validated. Extracted the Coq `root_of` / `mroot` / `tdfront`
  (polymorphic over the node hash + empty-leaf) and differential-fuzz
  them, instantiated with `Tzel.Hash.hash_merkle` / `Tzel.Felt.zero`,
  against `Tzel.Merkle.root_of_leaves` (cross-impl tested vs Cairo and
  the Rust kernel's hash_merkle):
  - root_of / mroot vs port over full 2^depth trees (2k cases each);
  - tdfront (incremental frontier) vs the batch root of (prefix ++
    [cm]) for random prefixes (5k cases).
  All green. So the model whose correctness was PROVED
  (tdfront_correct) is also VALIDATED to compute what the production
  tree computes — proof + differential, both directions. This is the
  Coq <-> OCaml <-> Cairo/kernel faithfulness pattern (used for the
  circuit primitives) now extended to the kernel Merkle tree.

- **WOTS+ ONE-TIME UNFORGEABILITY (`Spec/Wots.v` + `Spec/Xmss.v`):**
  assembles the two halves of the WOTS+ security argument into the
  structural unforgeability statement (the existing wots_no_dominance
  was only the checksum half).
  - `Wots.forward_forge_element` (NEW): walking a chain element
    FORWARD by (d'-d) and recovering for the larger digit d' reaches
    the SAME endpoint (via iter_compose). So the only signature
    elements an attacker can produce without a chain preimage are
    those for a LARGER digit — a forgery never decreases a digit.
  - `Xmss.wots_one_time_unforgeable` (NEW): combining that (every
    forgeable digit only increased: Forall2 >=) with wots_no_dominance
    (a dominating digit-vector with valid checksum must equal the
    original) gives: a signature an attacker can forge using only
    forward chain walks verifies for the ORIGINAL message and no
    other. This is the one-time unforgeability that makes XMSS index
    reuse catastrophic and single-use safe. The only crypto
    assumption is preimage resistance (what makes "forward-only" the
    attacker's whole move set), stated explicitly.

- **WITHDRAWAL-RECORD SERIALIZATION SAFETY (`Spec/WithdrawalRecord.v`):**
  models the kernel's durable withdrawal-record codec
  (encode/decode_withdrawal_record) and proves it lossless and
  unambiguous — a fund-safety surface (a round-trip bug would
  misdirect a withdrawal or corrupt its amount). Wire layout exactly
  the Rust: asset_id(32) || amount(u64 LE,8) || recipient_len(u32
  LE,4) || recipient. Proved (zero admits, genuine byte arithmetic):
  - from_le_le: the little-endian base-256 codec round-trips for any
    value < 256^k (the arithmetic core, via div_mod +
    div_lt_upper_bound);
  - decode_encode: decode (encode r) = Some r for well-formed records
    (32-byte asset, amount < 2^64, recipient len < 2^32) — lossless;
  - encode_injective: distinct records have distinct encodings (no
    durable-storage aliasing of two withdrawals);
  - the length-prefix framing is unambiguous (decode reads exactly
    44 + recipient_len bytes, rejects any other length).
  Note: bounds stated as 256^8 / 256^4 (= u64 / u32) to keep them
  symbolic — writing 2^64 in unary nat would force a cbn blowup.

- **STORAGE-PATH NAMESPACE COLLISION-FREEDOM (`Spec/StoragePaths.v`):**
  the kernel keys all durable storage by a typed string path
  (per-key-type prefix + attacker-influenceable key: hex nullifier /
  commitment / deposit key). A CROSS-TYPE collision would be
  catastrophic — a deposit key producing a nullifier path lets an
  attacker mark a victim's nullifier spent (locking their note), or
  commingle pools. Proved (zero admits) using the ACTUAL prefix
  constants:
  - append_eq_prefix: equal appends p++a = q++b force one base to be a
    prefix of the other (the key fact);
  - cross_no_collision: incomparable type prefixes (neither a prefix
    of the other) => paths never collide for ANY keys;
  - kernel_prefixes_pairwise_incomparable: the 7 key-bearing prefixes
    (nullifier by-key/index, deposit, applied-shield, valid-root,
    note, tree-branch) are pairwise incomparable, by vm_compute on the
    real strings — including the subtle nullifiers/by-key vs
    nullifiers/index pair that shares the long nullifiers/ stem;
  - within_no_collision: distinct keys under one prefix => distinct
    paths (append left-injective);
  - concrete corollaries: deposit/applied-shield/valid-root keys can
    never alias a nullifier path, etc.

- **DEPOSIT POOL KEY INJECTIVITY (`Spec/DepositKey.v`):** complements
  StoragePaths (cross-TYPE) with WITHIN-deposit injectivity. A pool is
  keyed by hex(asset) ++ "/" ++ hex(pubkey) (deposit_balance_path);
  if two distinct (asset, pubkey) pools shared a key their balances
  would COMMINGLE in one slot (theft). Proved (zero admits):
  - append_eq_fixed: equal-length string prefixes split an append
    equality uniquely — the fixed-width framing lemma;
  - deposit_key_injective: distinct (asset, pubkey) -> distinct keys,
    given hex injective + fixed-width;
  - GROUNDED, not assumed: a concrete byte-level hex (each byte -> two
    nibble chars) is proved fixed-width (hexs_len) and injective
    (hexs_inj), the latter from nibble-map injectivity (nib_inj, via a
    left inverse over the 16 hex chars) + the fixed-width framing;
  - deposit_key_bytes_injective: the concrete corollary for 32-byte
    felts — distinct pools never share a durable slot, using the real
    hex encoding, no assumed injectivity.

- **BATCH EXIT-PATH NO-INFLATION (`Spec/Unshield.v`):** the unshield
  analogue of Transfer.batch_value_conservation — and unshield is
  where value actually LEAVES the shielded pool to L1, so it is the
  most consensus-critical conservation. Previously Unshield had only
  the per-tx phi_unshield_value_conservation predicate; this adds the
  global theorem. Summing the per-tx circuit relation over a whole
  batch, for every asset a (zero admits):
    total consumed note value (a)
      = total produced note value (a)   (change + producer notes)
      + total withdrawn to L1 (a)       (sum of v_pub where asset_pub=a)
      + (a = tez ? total burned tez fees : 0).
  So no batch of unshields can withdraw — as notes-plus-L1-exits —
  more value of any asset than the notes it consumed, derived from
  the soundness of the per-tx conservation (not a turnstile
  argument). Models a UTx batch (in/out asset+value lists, v_pub,
  asset_pub, fee); proof mirrors the transfer batch induction with
  the extra per-asset v_pub term summed via list_sum.

- **BRIDGE BURN-SIDE AUTHENTICATION (`Spec/BridgeBurn.v`):** discharges
  the assumption behind BridgeTicketer's abstract burn guard (amount
  <= outstanding) by modeling the Michelson %burn entrypoint's real
  authentication (fa2_bridge_ticketer.tz): after READ_TICKET it checks
  ticketer == SELF_ADDRESS, metadata == None, token_id == 0 before
  releasing FA2. Security content: a foreign ticket (minted by a
  DIFFERENT contract) can NEVER drain this bridge's custody — without
  the ticketer==SELF check anyone could mint their own ticket and burn
  it here. Proved (zero admits):
  - foreign_ticket_rejected / nonzero_token_rejected /
    metadata_rejected: each malformed/foreign ticket fails accept_burn;
  - accept_burn_authentic: an accepted burn is of a SELF-minted ticket;
  - custody_decrease_authentic: in the refined bridge state machine,
    any single step that REDUCES custody was a burn of an authentic
    (ticketer=SELF) ticket — a foreign ticket cannot reduce custody;
  - reachable_collateralized: collateralization (custody=outstanding)
    holds in every reachable state, now with the burn guard GROUNDED
    in the real %burn authentication rather than assumed.

- **GRAND UNIFIED NO-INFLATION (`Spec/GrandConservation.v`):** the
  capstone — UNIFIES shield/transfer/unshield into one operation type
  and one conservation law, then proves value is conserved per asset
  across ANY MIXED batch. Each Op has input/output note lists + three
  scalar lanes: a deposit lane (shield credits from L1), an exit lane
  (unshield withdraws to L1), a tez fee. op_conserves(o):
    sum_at a in + deposit@a = sum_at a out + exit@a + fee@tez.
  Theorems (zero admits):
  - grand_conservation: across any list of mixed ops, for every asset
    a, total notes-consumed + total deposited = total notes-produced +
    total withdrawn + total tez fees. No sequence of shields,
    transfers, and unshields in any order creates or destroys value of
    any asset — derived from each op's circuit-relation soundness.
  - unshield_is_op / shield_is_op: the unified op_conserves
    specializes exactly to the unshield circuit relation
    (phi_unshield_value_conservation) and the shield relation, so the
    unification is grounded in the real per-flow relations, not a
    fresh abstraction. (Transfer is the deposit=exit=0 case.)

- **MULTIASSET L1<->L2 SOLVENCY (`Spec/EndToEndMulti.v`):** generalizes
  the EndToEnd cross-system solvency from one FA2 asset to PER-ASSET
  (Felt -> nat state); the invariant holds for EVERY asset
  simultaneously. So the bridge holds, for each asset independently,
  exactly the FA2 backing that asset's L2 claims. Same value flow
  (deposit credits custody[a]+pool[a]; shield moves pool[a]->notes[a];
  unshield debits notes[a]+custody[a]), now keyed by asset via upd /
  upd_other. Proved (zero admits), for all reachable states and ALL a:
  - l1_collateral_equals_l2_claims: custody a = pool a + notes a;
  - notes_backed_by_l1: notes a <= custody a (every live note of every
    asset redeemable); no_stranded_l1; withdrawal_honored;
  - roundtrip_solvency: out a <= in a (withdrawn <= deposited) per
    asset.
  The L2 pool/note movements are exactly the circuit ops whose value
  conservation GrandConservation.grand_conservation proves — so the
  full stack composes: circuit no-inflation (any op mix) -> kernel
  conservation -> per-asset L1<->L2 collateralization.

- **MULTIASSET COMMITMENT BINDING (`Spec/Hashes.v`):** closes a real
  gap — injective_5 was defined but unused, and the asset-substitution
  soundness was only described in comments, not proven. Added:
  - commitment_binding: under injective_5 H_commit, a commitment binds
    ALL five fields (d_j, v, asset, rcm, owner_tag) — equal cms arise
    only from identical notes (the note-integrity root of trust);
  - commitment_binds_asset: equal cms have the same asset — a note
    committed under one asset can NEVER be presented as a different
    asset, ruling out the asset-substitution attack (spending a cheap
    note as an expensive asset) that Spec.Shield flags as a hazard;
  - commitment_binds_value: equal cms have the same value (no per-note
    amount inflation by re-presenting a different value).
  This is the multiasset analogue of nullifier_binding, and the
  per-note counterpart to the aggregate value conservation: each note
  is welded to its asset and amount by its commitment.

- **SPENDING-AUTHORITY BINDING (`Spec/Hashes.v`):** continues the
  commitment-binding work to the spending authority. owner_tag =
  H_owner(auth_root, pub_seed, nk_tag) (Spec.Shield); auth_root is the
  root of the spender's authorization Merkle tree. Added (zero admits;
  injective_3 was missing, now defined):
  - owner_tag_binding: under injective_3 H_owner, the owner tag binds
    auth_root, pub_seed, nk_tag;
  - commitment_binds_auth_root: composing commitment_binding (cm binds
    its owner_tag field) with owner_tag_binding (owner_tag binds
    auth_root) — two notes with the same cm have the SAME
    authorization root. A note's spending authority is welded to its
    commitment; a note committed to one auth tree can never be spent
    under a different one (no authority substitution).
  This completes the per-note integrity chain: cm binds
  value/asset/owner_tag (commitment_binding), and owner_tag binds the
  auth_root (owner_tag_binding) — so the commitment pins amount,
  asset, AND who may spend.

- **FAERIE-GOLD RESISTANCE (`Spec/Hashes.v`):** the nullifier's
  position-dependence (nf = H_nf(nk, H_nf(cm, pos))) is documented as
  preventing faerie-gold attacks but was only in comments. Added
  nullifier_position_distinct (corollary of nullifier_binding): the
  same note value (same nk, same cm) at two DISTINCT positions yields
  DISTINCT nullifiers. So an attacker re-committing a victim's cm at a
  different position creates an INDEPENDENT note — spending it neither
  nullifies nor locks the victim's original. Documented defense, now a
  theorem.
  (Note: injective_4 / Hash4 audited — Hash4 is the level/position-
  indexed Merkle/XMSS node hash whose binding is already captured by
  Merkle.merkle_binding/auth_binding via node_injective, so injective_4
  is a superseded generic helper, not a gap.)

- **FULL XMSS ONE-TIME UNFORGEABILITY (`Spec/Xmss.v`):** assembled the
  top-level signature-scheme security. xmss_soundness_reduces_to_wots
  proved the REDUCTION (two XMSS sigs verifying against the same
  leaf/root recover the same WOTS endpoints) but stopped there; its
  header claimed WOTS+ unforgeability was "axiomatized, we don't prove
  it". That was OUT OF DATE — wots_one_time_unforgeable proves it
  structurally (forward-only attacker + checksum no-dominance). Added
  (zero admits):
  - xmss_one_time_unforgeable: two signatures verifying against the
    SAME deployed XMSS key, where the second is a forward-only forgery
    (digits componentwise >=), (a) recover the same WOTS+ public key
    AND (b) sign the same message. So a forward-only forger cannot,
    against a fixed XMSS leaf, produce a signature for any message
    other than the one signed. Composes xmss_soundness_reduces_to_wots
    (same key) with wots_one_time_unforgeable (same message), bridged
    by recover_all_length.
  Also corrected the two stale comments claiming the WOTS+
  unforgeability is axiomatized — it is proven (the only crypto
  assumption is chain-hash preimage resistance, made explicit).

- **WHOLE-TREE CORRECTNESS (`Spec/MerkleTree.v`):** lifts the
  single-append tdfront_correct to the FULL append sequence.
  tree_root d leaves = the root after appending every leaf via the
  frontier; tree_root_correct: tree_root d leaves = mroot d leaves
  (length leaves <= 2^d) — the root the kernel commits after appending
  all notes equals the batch Merkle root of all the notes. This is
  what a membership proof trusts: the committed root faithfully
  reflects exactly the set of committed notes. (Sequence-level
  corollary of tdfront_correct via app_removelast_last; honest framing
  — the hard content is tdfront_correct, this packages it for the
  whole tree.)

- **O(depth) INCREMENTAL FRONTIER (`Spec/MerkleFrontier.v`):** models
  the kernel's actual O(depth) frontier state (simulate_frontier_append
  / branches[]) as a binary-counter frontier and proves its core
  structural correctness — the genuinely-hard incremental-Merkle item
  deferred earlier, now substantially closed. A frontier is a
  list (option Felt); appending a leaf is binary increment with carry.
  Proved (zero admits):
  - mroot_combine: the carry is value-correct
    (mroot (S lv)(a++b) = H (mroot lv a)(mroot lv b) for |a|=2^lv);
  - fval_fappend: fappend is a correct binary counter (appending a
    height-lv block adds 2^lv to the represented leaf count, with
    carry);
  - fappend_preserves_frep + fbuild_frep: the frontier built by
    appending all leaves FAITHFULLY REPRESENTS them — every slot is
    exactly the complete-subtree root of its leaf block (decreasing
    size). This is the correctness of the kernel's O(depth)
    branches[] state: it tracks the true subtree roots using O(depth)
    storage, not the full leaf array.
  - froot_empty: the root read off an empty frontier = zero_hash d.
  REMAINING (documented, NOT admitted): the read-off bridge
  froot (fbuild leaves) = mroot d leaves (level-offset + padding
  bookkeeping). The security-relevant committed-root=batch-root is
  already in MerkleTree (tree_root_correct) + differentially
  validated; this adds the O(depth)-state structural correctness
  beneath it.

- **BOTTOM-UP = TOP-DOWN MERKLE ROOT (`Spec/MerkleTree.v`):** proves
  the two batch-root definitions agree — a fundamental consistency the
  file relied on implicitly (empty_subtree is about root_of, the
  bottom-up build_level fold; tdfront_correct about mroot, the
  top-down recursive split) but never connected. Genuinely hard
  (bottom-up pairwise vs top-down halving). Proved (zero admits):
  - build_level_firstn / build_level_skipn: pairing commutes with
    taking the first/last n pairs;
  - build_level_length: build_level halves an even-length list;
  - build_level_mroot: pairing the bottom level + depth-k root =
    depth-(S k) root;
  - root_of_mroot: length l = 2^d -> root_of d l = mroot d l. So the
    two Merkle-root definitions in the file are interchangeable, and
    results proved about one (empty_subtree on root_of, tdfront/
    tree_root on mroot) transfer to the other.

- **MERKLE ZERO-PADDING INVARIANCE (`Spec/MerkleTree.v`):** the
  committed root depends ONLY on the actual leaves, not on the
  zero-padding count. Proved (zero admits):
  - mroot_app_z0: length l < 2^d -> mroot d (l ++ [z0]) = mroot d l
    (appending the padding value in the padding region is a no-op),
    by induction with the left/right-half case split;
  - mroot_app_zeros: length l + k <= 2^d ->
    mroot d (l ++ repeat z0 k) = mroot d l (any number of padding
    zeros). So the kernel's fixed-depth tree — which treats empty
    positions as z0 — commits exactly the notes regardless of how many
    empty slots remain. (Also the remaining ingredient for the
    MerkleFrontier froot read-off: explicit-z0 = implicit padding.)

- **MERKLE ROOT SYNTHESIS (`Spec/MerkleTree.v`):** ties the recent
  Merkle results together. mroot_eq_root_of_padded:
  length leaves <= 2^d -> mroot d leaves = root_of d (leaves ++
  repeat z0 (2^d - length leaves)). The top-down recursive root of the
  ACTUAL notes (a partial leaf list) equals the bottom-up build_level
  fold of those notes padded with z0 to a full tree — exactly how an
  implementation computes the committed root (fill empty slots with
  z0, fold up). Composes root_of_mroot (full-tree bottom-up=top-down
  equivalence) with mroot_app_zeros (padding invariance). Zero admits.

- **MERKLE FULL-TREE BASE INDEPENDENCE (`Spec/MerkleTree.v`):**
  mroot_base_irrelevant: length l = 2^d -> mroot z0 d l = mroot z1 d l.
  A full depth-d tree (exactly 2^d leaves) never reaches the
  empty-leaf padding base case, so its root is independent of the
  padding value. Clean induction (full list keeps both halves full).
  Standalone structural fact + an ingredient toward the MerkleFrontier
  read-off (where the frontier processes nodes at shifting levels with
  level-dependent padding zh lv, and full sublists make the base drop
  out). Zero admits.

- **FRONTIER->MROOT BRIDGE (`Spec/MerkleBridge.v`):** the
  mathematical heart of why the O(depth) frontier read-off is correct.
  The bridge lemma relates ONE level-step of the bottom-up combination
  to the top-down mroot: mroot (zh lv)(S d') X =
  mroot (zh (S lv)) d' (ppair lv X) (length X <= 2^(S d')), where
  ppair pairs adjacent nodes padding an odd tail with zh lv. So each
  branches[] level corresponds to exactly one mroot level. Proved
  (zero admits) on top of build_level_mroot + mroot_app_zeros +
  mroot_base_irrelevant:
  - build_level_app_even: build_level distributes over an even prefix;
  - build_level_pad (the crux): build_level of X + zh-padding splits
    into ppair lv X then a run of zh(S lv), via 2-step (parity)
    strong induction;
  - bridge: assembles them — pad to a full level, drop one level
    (build_level_mroot), swap base (base-irrelevant on the now-full
    list), then peel the padding.
  REMAINING: fold bridge over the whole frontier (froot_correct) to
  get froot (fbuild leaves) = mroot d leaves — mechanical given the
  bridge, the frep structure (MerkleFrontier), and mroot_app_z0.

- **O(depth) FRONTIER READ-OFF CORRECT — CAPSTONE
  (`Spec/MerkleFrontierCorrect.v`):** the previously-deferred hard
  item, now CLOSED. Reading the root off the kernel's O(depth)
  frontier state equals the true batch Merkle root of all notes.
  froot_fbuild_eq: length leaves < 2^d -> length (fbuild leaves) <= d
  -> froot d (fbuild leaves) 0 z0 = mroot d leaves. So the kernel
  commits the correct commitment-tree root using only O(depth)
  storage, never the full leaf array. Proved (zero admits):
  - froot_correct: the heart — folds the per-level MerkleBridge.bridge
    over the whole frontier, using fbuild_frep (the frontier
    faithfully represents the notes) and the ppair snoc computations,
    by induction on the frontier with per-level length bounds;
  - froot_nil_eq, ppair_even_snoc, ppair_even2, pairup_bl: connecting
    lemmas. The depth bound length (fbuild leaves) <= d is an explicit
    structural precondition (the binary-counter frontier of < 2^d
    notes has at most d slots), everything else proved.
  Completes the multi-iteration incremental-Merkle arc: fbuild_frep ->
  root_of_mroot -> padding invariance -> base independence -> bridge ->
  froot_correct, all zero-admit.

- **FRONTIER READ-OFF DIFFERENTIAL (faithfulness):** validates the
  just-proved O(depth) frontier MODEL against the production tree.
  Extracted MerkleFrontier.froot / fbuild and differential-fuzz
  froot d (fbuild leaves) 0 z0 against Tzel.Merkle.root_of_leaves
  (cross-impl tested vs Cairo / the Rust kernel hash_merkle) over 5000
  random (depth, leaves) with length leaves < 2^depth. All pass. So
  froot_fbuild_eq's claim (frontier read-off = batch root) is both
  PROVED and empirically VALIDATED, and the froot/fbuild model is
  confirmed faithful. Differential suite now 14 cases.

- **FRONTIER DEPTH BOUND — capstone now hypothesis-free
  (`Spec/MerkleFrontier.v`):** removed the last side condition from
  froot_fbuild_eq. Proved fbuild_length_bound: length leaves < 2^d ->
  length (fbuild leaves) <= d (a binary-counter frontier of < 2^d
  notes has at most d slots). Via (zero admits): fappend_wf /
  fbuild_wf (the frontier is well-formed — last slot Some, no trailing
  None), fval_fbuild (fval 0 (fbuild leaves) = length leaves),
  wf_fval_lower (wf nonempty -> 2^(length-1) <= fval, the top Some
  contributes its level weight via fval_snoc_some), combined with pow
  monotonicity. So froot_fbuild_eq now assumes ONLY length leaves <
  2^d — the entire O(depth) frontier correctness is self-contained,
  zero admits, no leftover hypotheses.

- **CONFIG-UPDATE AUTHORIZATION UNFORGEABLE (`Spec/ConfigAuth.v`):** the
  kernel authenticates verifier-/bridge-config updates with a WOTS+
  signature from the admin key against a COMPILED-IN expected leaf
  (authenticate_verifier_config / authenticate_bridge_config:
  verify_wots_signature_against_leaf). So config substitution (swapping
  in a malicious verifier/bridge) is prevented by WOTS+ unforgeability.
  config_update_unforgeable (zero admits): two config updates that both
  authenticate against the SAME admin leaf, where the second is a
  forward-only forgery, (a) recover the same admin WOTS public key
  (ltree_injective) AND (b) sign the SAME config
  (wots_one_time_unforgeable). So an attacker cannot authenticate any
  config other than the one the admin actually signed. The
  kernel-GOVERNANCE analogue of the transaction-level
  xmss_one_time_unforgeable (authenticates against a fixed leaf
  directly, no Merkle auth path), composing the proven WOTS/L-tree
  machinery. A real kernel security check that wasn't yet stated as a
  theorem.

- **CONFIG IMMUTABILITY / SET-ONCE (`Spec/ConfigOnce.v`):** the kernel
  installs the verifier and bridge configs ONE-SHOT (configure_verifier
  / configure_bridge reject if already present: "rollup verifier/bridge
  is already configured"). Modeled as a write-once register (config
  slot = option C; a set step fires only when None; every other kernel
  op leaves it unchanged). Proved (zero admits):
  - config_immutable: once the slot holds Some c, every reachable later
    state still holds Some c — the config is frozen for the kernel's
    life;
  - reconfigure_unchanged: any step from Some c leaves it at Some c (no
    overwrite to a different config).
  Complements ConfigAuth.config_update_unforgeable: together the
  verifier/bridge is set ONCE by the admin and then IMMUTABLE — an
  attacker can neither forge an install (ConfigAuth) nor overwrite the
  installed config (here). Plus operations_require_config: in any
  reachable state where >=1 operation (deposit/shield/transfer/unshield)
  has occurred, the config is installed — the kernel processes no
  transactions before the config is in place. So the FULL config
  lifecycle: installed only by the admin (ConfigAuth), only once /
  immutable, and required before any operation. All found by reading
  the actual kernel config-management code.

- **TREE CAPACITY -> committed root is correct (`Spec/TreeCapacity.v`):**
  grounds froot_fbuild_eq in the kernel's actual capacity check. The
  kernel rejects appends past 2^DEPTH leaves (append_note /
  ensure_note_capacity: "Merkle tree full"). Modeled as a note list
  under capacity-checked append (a step fires only when count < cap).
  Proved (zero admits):
  - capacity_invariant: the note count never exceeds 2^DEPTH;
  - committed_root_correct: when the tree is not full, the root the
    kernel reads off its O(depth) frontier (froot over fbuild) equals
    the batch Merkle root of the committed notes (mroot).
  So the capacity check is exactly what discharges the
  length leaves < 2^DEPTH precondition of froot_fbuild_eq — the kernel
  always commits the true Merkle root of the notes it appended. Closes
  the loop between the Merkle frontier proof and the kernel's usage.

- **VALID-ROOT SET INTEGRITY (`Spec/ValidRoots.v`):** the kernel
  accepts a membership proof against ANY root in its valid-root set
  (has_valid_root), not just the latest. The set is seeded with the
  genesis root and grown ONLY by snapshot_root (marks the CURRENT tree
  root). Modeled as a (current_root, valid_set) state machine with an
  abstract `genuine` predicate (the roots the tree legitimately
  produces, proved correct in MerkleFrontierCorrect). Proved (zero
  admits): valid_roots_genuine — every root in the valid set is
  genuine. So "accept any historical root" is SAFE: no forged root is
  ever accepted; a membership proof can only be checked against a root
  the tree actually produced. Combined with Merkle.merkle_binding (no
  forged path to a genuine root) and KernelNullifier (double-spend
  prevented regardless of which root), membership is sound and
  historical-root acceptance adds no attack. Found by reading the
  kernel's valid-root management.

- **MASTER KERNEL SAFETY — invariants hold JOINTLY
  (`Spec/KernelSoundness.v`):** unifies the per-structure invariants
  into one. A single kernel state (nullifier set, valid-root set,
  current root, note list, config) and one step relation (spend a
  fresh nullifier / append a note within capacity with a genuine
  snapshotted root / install the config once), with the conjunction
  invariant. Proved (zero admits):
  - kernel_state_sound: in EVERY reachable state (from a genuine-seeded
    genesis), all four hold at once — NoDup nullifiers (no
    double-spend), every valid root genuine, current root genuine, tree
    within capacity. So across any interleaving of spends, appends, and
    the config install, the kernel never double-spends, only holds
    genuine roots, and never overfills the tree — the per-structure
    proofs (KernelNullifier, ValidRoots, TreeCapacity) compose with NO
    interference (a spend can't overflow the tree, an append can't
    double-spend, configure touches none of them).
  - kernel_config_frozen: across the SAME unified steps an installed
    config stays installed (ConfigOnce immutability holds in the joint
    machine too).
  The whole-system safety statement the separate invariants compose
  into.

- **Impl REFINEMENT LAYER COMPLETE — XMSS stub closed
  (`Impl/Xmss.v`):** the three-layer architecture's core artifact (the
  extractable Cairo-shaped Impl provably discharges the Spec safety
  properties) is now complete for EVERY module. Impl/Xmss was the last
  genuine stub ("the most subtle module... the primary value of the
  formalization", per its own docstring) — executable definitions but
  no soundness theorem. Now proved (zero admits):
  - xmss_verify_impl: the extractable verifier = Spec.Xmss.xmss_verify
    at the concrete chain hash (Hash3 / pack_adrs_chain);
  - xmss_ltree_injective_impl: L-tree compression injective (Spec
    ltree_injective transferred to the concrete ltree_node_hash);
  - xmss_verify_impl_one_time_unforgeable: the headline one-time
    unforgeability for the actual extraction source (Spec
    xmss_one_time_unforgeable instantiated at the concrete hashes),
    under the local node-hash injectivity hypothesis.
  Also corrected stale "refinement pending" docstrings in Impl/Xmss
  and Impl/Shield (shield_relation_sound / transfer_relation_sound were
  already proven). So all six Impl modules (Merkle, Wots, Xmss,
  Transfer, Shield, Unshield) carry proven refinement/soundness
  theorems — the extraction source is sound end to end.

- **AXIOM AUDIT extended to all recent + Impl-layer theorems
  (cross-layer, complete):** Print Assumptions on the recent kernel
  modules (config-governance, tree-capacity, valid-roots, master
  soundness) shows they rest on ONLY `Felt : Type` — no unexpected
  axioms. The Impl-layer theorems (xmss_verify_impl_one_time_
  unforgeable, xmss_ltree_injective_impl) additionally depend on the
  hash/ADRS PARAMETERS (Hash3, Hash4, pack_adrs_ltree, pack_adrs_chain)
  — the uninterpreted hash interface that is realized concretely at
  extraction. Crucially, NO global properties are asserted on those
  Parameters (only their function signatures appear; every collision-
  resistance / injectivity premise remains a LOCAL hypothesis). So the
  complete cross-layer picture: Spec theorems assume only Felt (+
  Felt_eq_dec where used); Impl theorems assume Felt + the abstract
  hash functions with no asserted properties. No surprises at any
  layer.

- **NON-VACUITY of the circuit-relation soundness (`Spec/XmssInhabited.v`):**
  guards against the "False in the hypotheses" failure mode — a
  Relation -> Phi theorem proves nothing if Relation is unsatisfiable.
  The circuit relations (Transfer/Shield/Unshield Relation) have one
  non-trivially-satisfiable conjunct: the in-circuit XMSS check
  xmss_verify_cairo_sep (gates / value equations / commitment equations
  are satisfiable by construction). Proved (zero admits):
  xmss_cairo_sep_inhabited — an honest signature verifies, so
  xmss_verify_cairo_sep is INHABITED (for any well-formed message and
  matching non-empty key, there exist a sig and auth path making it
  hold). Built from recover_all_correct (honest sig recovers the public
  key), ltree_succeeds (the key compresses to a leaf), and the auth path
  to the computed root. Generalized to the separate L-tree / auth-tree
  hashes the Cairo uses. So the relation-soundness theorems are not
  vacuously true on their cryptographic core — the differential tests
  validate the extracted FUNCTIONS, but this is the only check that the
  relation PROPS are satisfiable, which fuzzing cannot establish.

- **FULL ShieldRelation INHABITATION — airtight non-vacuity
  (`Impl/Shield.v`):** completes the non-vacuity work. Last iteration's
  XmssInhabited proved the XMSS conjunct satisfiable; this proves the
  WHOLE ShieldRelation is satisfiable by a single concrete witness, so
  shield_relation_sound : ShieldRelation -> Phi_shield is provably NOT
  vacuously true. shield_relation_inhabited (zero admits): an honest
  shield (outputs whose commitments are the hash of their fields, the
  producer pinned to tez with v=1>0, the canonical pubkey-hash fold,
  and an honest WOTS+ signature under the recipient's auth tree)
  satisfies every conjunct at once. The construction fixes the key
  first so the committed auth_root is the signature's own computed root
  (no circularity). A helper lemma xmss_honest_verifies isolates the
  XMSS-verify reasoning from the output-record construction (so the
  conjunction proof applies it without unfolding the record poses).
  Under the wots_digits well-formedness facts the real base-w
  decomposition satisfies. So a modeling error making ShieldRelation
  self-contradictory is ruled out — a check fuzzing cannot perform.

- **FULL UnshieldRelation INHABITATION (`Impl/Unshield.v`):** extends
  the non-vacuity work to the unshield relation (the most complex — it
  has inputs, the 2-accumulator conservation, change slots, and the
  public exit). unshield_relation_inhabited (zero admits): a single
  concrete honest unshield satisfies all 12 conjuncts at once — one tez
  input spending a note that is genuinely in the tree (merkle path to
  the computed root + honest WOTS+ spend signature + correct nullifier
  + asset gate), both change slots absent (all-zero), a tez producer
  note (v=1>0), the public exit pinned to tez, and a BALANCED
  2-accumulator (input value 2 = exit 0 + changes 0 + producer 1 + fee
  1; the primary lane is 0 since all assets are tez). The signature
  circularity (the input's sig signs a sighash that includes its own
  nullifier and the root) is broken by computing cm/nf/root from the
  non-signature fields first, then signing. Helper u_xmss_honest + s
  u_sign_len_eq. So unshield_relation_sound is provably not vacuously
  true. Two of the three circuit relations (shield, unshield) now have
  full inhabitation; transfer remains.

- **FULL TransferRelation INHABITATION — non-vacuity arc COMPLETE
  (`Impl/Transfer.v`):** the last of the three circuit relations.
  transfer_relation_inhabited (zero admits): a single concrete honest
  transfer (one tez input spending a tree note, three zero-value tez
  outputs, a tez producer note v=1, balanced 2-accumulator) satisfies
  all 13 conjuncts of TransferRelation. So ALL THREE circuit-relation
  soundness theorems (transfer/shield/unshield_relation_sound) are now
  provably NOT vacuously true — the entire circuit-relation soundness
  layer is non-vacuous. The pattern (key fixed first to break the
  signature circularity, t_xmss_honest helper isolating the XMSS
  reasoning, `change` to reduce pose projections, one Felt_eq_dec case
  split for the accumulators) transferred cleanly from unshield and
  compiled first try. Combined with Spec/XmssInhabited
  (xmss_cairo_sep_inhabited), the relations are non-vacuous on both
  the shared crypto core and as whole relations.

- **FAITHFULNESS: per-input wots_sig length now modeled
  (`Impl/Transfer.v input_checks`):** a systematic cross-check of every
  Cairo circuit assertion against the relations found one real Cairo
  assert not captured: the per-input WOTS+ signature length check
  ("transfer/unshield: wots sig len", asserting each input's wots_sig
  has WOTS_CHAINS elements). Added length (ci_wots_sig c) = wots_chains
  as a conjunct of input_checks (shared by transfer + unshield), so the
  relation matches the Cairo accept condition. Not a soundness gap (a
  short sig recovers a wrong leaf -> verification fails; a long sig's
  extra elements are harmlessly ignored), but a faithfulness-
  completeness improvement. Updated the soundness destructuring
  (transfer/unshield_relation_sound) and re-discharged the new conjunct
  in the inhabitations (the honest witness's sign(...) has the right
  length via *_sign_len_eq). The cross-check also confirmed everything
  else is modeled: the change-slot-absent asset check (asset=0=ASSET_TEZ,
  and ASSET_TEZ=0 so co_asset=asset_tez is faithful), the producer-tez
  pin, conservation, gates, nullifier, merkle, xmss are all captured.

- **WOTS+ CHECKSUM HYPOTHESIS REALIZED (`Spec/WotsChecksum.v`):** the
  unforgeability theorems (wots_one_time_unforgeable / xmss / config)
  take the checksum well-formedness `base4_val cs = checksum msg` as a
  HYPOTHESIS — it is the load-bearing fact (raising any message digit
  lowers the checksum, so a forward-only attacker can't advance the
  checksum chains). Previously assumed; now PROVED to be realized by
  the actual decomposition the Cairo computes
  (blake_hash.cairo: the 5 checksum digits are the base-4 encoding of
  sum(3 - digit[i])). checksum_hypothesis_realized (zero admits): for
  any valid 128-digit message, base4_val (base4_encode5 (checksum msg))
  = checksum msg, where base4_encode5 mirrors the Cairo's `cs & 3; cs
  >>= 2` five times. Built from base4_val_encode5 (5-base-4-digit
  round-trip for values < 4^5; the top digit is n/256 in {0..3}, not 0)
  and checksum_bound (checksum <= 3*128 = 384 < 1024). So the
  unforgeability premise is non-vacuous and faithful to the circuit's
  checksum construction (which is also SHA-drift-pinned). Found by a
  faithfulness probe: the checksum is security-critical but its
  computation was not connected to the security proof.

- **L-TREE DIFFERENTIAL — XMSS verification's untested link closed
  (`Impl/Extraction.v`, `ocaml/coq_driver/test`):** the XMSS verify is
  recover(chains) -> ltree(endpoints->leaf) -> merkle(leaf->root). The
  chain step and merkle path were already differentially fuzzed; the
  L-TREE compression in the middle was NOT (only proven injective +
  drift-pinned). Now closed: extracted Impl.Xmss.xmss_ltree (with Hash4
  and pack_adrs_ltree realized at key_idx 0) and differential-fuzz it
  against the OCaml port's Tzel.Wots.pk_to_leaf over 2000 random
  133-endpoint WOTS pubkeys (cross-impl tested vs Cairo). All pass,
  exercising the odd-leaf carry (133 is odd). So the security-relevant
  leaf computation (the leaf the XMSS auth path verifies against) is now
  validated faithful, not just proven-injective. Differential suite now
  15 cases. (The port asserts exactly n_chains=133 endpoints — the real
  WOTS pubkey size — which the test respects.)

- **THEFT RESISTANCE — spend authorization made explicit
  (`Impl/Transfer.v` `spend_authorized_by_owner`):** the headline
  ownership property, previously enforced structurally but never named.
  The relation recomputes each spent note's commitment ci_cm from the
  SAME ci_auth_root the in-circuit XMSS signature is verified against
  (ci_otag = H_owner(ci_auth_root, ci_pub_seed, H_nktag(ci_nk_spend)),
  ci_cm = H_commit(..., ci_otag)). Theorem (zero admits): under
  commitment- and owner-tag injectivity (injective_5 H_commit /
  injective_3 H_owner), if an accepted spend consumes a note whose
  commitment has owner (R, ps, nkt), then ci_auth_root = R AND
  ci_pub_seed = ps AND H_nktag(ci_nk_spend) = nkt — the spender's
  signing identity is forced to be the note's owner. Composed with the
  relation's XMSS verification under ci_auth_root and WOTS+/XMSS
  one-time unforgeability: only the holder of R's signing key can spend
  a note owned by R. Covers BOTH transfer and unshield (they share
  CairoInput / input_checks verbatim). You cannot spend someone else's
  note.

- **NO DOUBLE-SPEND, witness-varying attacker
  (`Impl/Transfer.v` `no_double_spend`):** the kernel rejects duplicate
  nullifiers, so double-spend prevention reduces to "two spends of the
  same note yield the same nullifier". The subtle attack is to re-spend
  a note with a DIFFERENT nk_spend to dodge the dedup. Defeated: the
  note's commitment binds H_nktag(nk_spend) via owner_tag, so
  spend_authorized_by_owner forces both spends' nk_spend to share the
  same nk-tag, and with H_nktag injective they are the SAME nk_spend;
  the nullifier is a function of (nk_spend, cm, pos), so the spends
  collide and the second is rejected. Theorem (zero admits): under
  injective_5 H_commit / injective_3 H_owner / H_nktag injective, two
  spends of a note with the same commitment and position produce the
  same nullifier. No witness choice lets the owner spend a note twice.
  Companion to [[spend_authorized_by_owner]] (theft resistance).

- **SHIELD ENTRY-POINT BINDING — funds reach exactly the published
  owner (`Impl/Shield.v` `shield_note_bound_to_pubkey_hash`):** the
  output/creation-side analog of theft resistance. The deposit pool is
  keyed by the public pubkey_hash = fold(tag_pkh, [auth_domain;
  auth_root; auth_pub_seed; blind]). The relation feeds the SAME
  (co_auth_root r, co_pub_seed r) of the recipient note into BOTH that
  pubkey_hash fold AND the note commitment (s_output_cm_ok via co_otag),
  and verifies the in-circuit XMSS under co_auth_root r. Theorem (zero
  admits): under sighash-fold injectivity (injective_2 H_sighash), an
  accepted shield to a published pubkey_hash whose owner is (R, PS)
  forces co_auth_root r = R and co_pub_seed r = PS. So the shielded note
  is owned by exactly the published pool key, and (with the signature
  under co_auth_root r = R) only that key's holder can shield — nobody
  can shield a victim's pool into a note they control. Companion to the
  spend-side [[spend_authorized_by_owner]].

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
   RESOLVED — formalized, not axiomatized. `wots_one_time_unforgeable`
   proves WOTS+ one-time unforgeability structurally for the
   forward-only attacker model (`forward_forge_element` + checksum
   `wots_no_dominance`), and `xmss_one_time_unforgeable` assembles it
   with the XMSS reduction (`xmss_soundness_reduces_to_wots`) into the
   top-level statement. This is neither the "light" parameter path nor
   the full game-based PRF/PRE/SM-DSPR re-derivation: the single
   remaining cryptographic assumption is preimage resistance of the
   chain hash (which is what makes "forward-only" the attacker's whole
   move set), stated as an explicit local hypothesis — never a global
   axiom.

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
