# Security-property → Coq-theorem coverage

This maps each security property documented in `specs/security.md` to the
Coq theorem(s) that formally verify it, for the audit.  Every theorem
listed is zero-admit and depends only on the abstract field type
(`Felt`, `Felt_eq_dec`); all collision-resistance / injectivity premises
are explicit local hypotheses (see `STATUS.md`, "comprehensive axiom
audit").

## Balance conservation (no inflation)

> "values are u64, arithmetic in u128, circuits enforce exact
> input/output equality … balance is per-asset: `tez_in = tez_out + fee`
> AND `primary_in = primary_out` separately."

- **Per-tx, per-asset:** `Spec.Transfer.phi_value_conservation`,
  `Spec.Shield.phi_shield_value_conservation`,
  `Spec.Unshield.phi_unshield_value_conservation` — each is
  `sum_at a in = sum_at a out + (exit@a) + (fee@tez)` for *every* asset
  `a`.  This is the per-asset accumulator semantics.
- **The bug-#1 fix (CRITICAL):** the documented `v_pub` lane-routing bug
  (`unshield.cairo` `2003bf5`: unconditional `tez_out += v_pub`) is
  exactly excluded by the `(if Felt_eq_dec a asset_pub then v_pub else 0)`
  term in `phi_unshield_value_conservation` — `v_pub` contributes only to
  its own asset's accumulator, so a tez-only input set cannot mint FA2.
- **Across a batch / any operation mix:**
  `Spec.Transfer.batch_value_conservation`,
  `Spec.Unshield.batch_unshield_value_conservation`,
  `Spec.GrandConservation.grand_conservation` (shield+transfer+unshield,
  any order, per asset).
- **Kernel side & L1<->L2:** the proven kernel invariant is actually
  the EXACT per-asset accounting equality (stronger than mere
  no-inflation) — `Spec.KernelLedger.invariant`:
  `ks_dep a = ks_pool a + ks_notes a + ks_burned a + ks_wd a` holds in
  every reachable state (`reachable_invariant`), so no asset is created
  OR silently destroyed; every value movement is exact (deposited =
  in-pools + in-notes + burned + withdrawn). `Spec.KernelLedger.no_inflation`
  (withdrawn ≤ deposited, per asset) is the security-direction
  corollary. `Spec.EndToEndMulti.l1_collateral_equals_l2_claims`
  (L1 FA2 custody = L2 claimable, every asset).
- **Dual-pool FA2 shield — "no unbacked tez" (the second-most-flagged
  attack surface: break the dual-pool and you mint tez from nothing).**
  `Spec.KernelLedger.kstep_shield_fa2` models the FA2 shield's TWO pool
  debits explicitly: the FA2 pool funds `v_note + fee`
  (`v_note + fee <= ks_pool A`) AND the *same pubkey_hash's tez pool*
  funds the producer fee (`producer_fee <= ks_pool asset_tez`), moving
  exactly `producer_fee` from the tez pool to the tez producer note. So
  the tez producer note is BACKED by deposited tez — it cannot be
  conjured.  `no_inflation` is the multi-step reachable-state invariant
  (`reachable_invariant` → `step_preserves_invariant` over every step
  *including* `kstep_shield_fa2`), so across any operation sequence the
  tez total (pools + notes + burned + withdrawn) never exceeds tez
  deposited.  The `producer_fee <= ks_pool asset_tez` premise is the
  load-bearing "no unbacked tez" check, required and used.

## u64 / u128 overflow safety

> "values are u64, arithmetic is carried out in u128 … exact equality."

- `Spec.LedgerBounded.tx_conservation_mod_iff` (modular = true
  conservation under the bound, for any modulus with `mx*vb < ab`,
  covering u128 and the field), `headroom_u128` (`11 * 2^64 < 2^128`),
  `totals_under_supply_cap`.
- `Spec.KernelPool.credit_overflow_rejected` (the kernel's `checked_add`
  rejects overflow; pool balance stays bounded).

## Per-asset 2-accumulator constraints — the GATE is load-bearing

> "circuits take a witness-declared primary non-tez asset A and pin every
> input/output asset to {ASSET_TEZ, A}."  The 2-accumulator scheme is
> sound ONLY if that gate holds for every slot — the top adversarial
> concern: any slot whose asset is unconstrained (or gated against the
> wrong set) breaks per-asset closure, since the two lanes can't catch an
> imbalance in a third asset.

- `Impl.Transfer.two_accumulator_conservation` proves the crux: given the
  asset gate on inputs AND outputs (`asset_gate primary _` =
  `Forall (∈ {tez, primary})`) plus the two lane equations, the FULL
  per-asset conservation (`Spec.Transfer.phi_value_conservation`, a
  `forall a`) follows.  The gate is a *required, used* hypothesis — the
  "third asset `a ∉ {tez, primary}`" case closes only via
  `sum_at_absent_zero`, which needs the gate.  Without it the lemma is
  unprovable, exactly mirroring the design's soundness condition.
- The gate is part of the MODELED relation, so the Cairo is obligated to
  enforce it: `TransferRelation` / `UnshieldRelation` carry a gate
  conjunct for every slot — inputs (via `*_input_checks`), each change
  slot (`co_asset c1/c2 ∈ {tez, primary}`, **including `cm_change_2`**),
  the producer slot pinned to tez, and — for unshield — the public exit
  `asset_pub ∈ {tez, primary}` (the Phase-E.5 fix).
  `transfer_relation_sound` / `unshield_relation_sound` extract these and
  feed `two_accumulator_conservation`.  So no slot is left unconstrained.
- The bug-#1 `v_pub` lane-routing fix is modeled and proved: in
  `UnshieldRelation` the exit `(asset_pub, v_pub)` is folded into the
  accumulator lists, so `v_pub` lands in the `asset_pub` lane (tez OR
  primary), never unconditionally in tez — the precise inverse of the
  `2003bf5` bug.
- `GrandConservation.grand_conservation` is the per-asset law across any
  mixed batch.

## Asset registry: duplicate-ticketer dedup + routing

> "compose_asset_registry_with silently skips any FA2 entry equal to the
> configured tez_ticketer … without the guard, first-match ordering
> becomes a security property."

- `Spec.AssetRegistry`: `compose` models the dedup (`dedup_fa2` skips
  `fa2 = tez`); `deposit_withdraw_roundtrip` / `withdraw_deposit_roundtrip`
  prove deposit routing (`asset_for_ticketer`) and withdrawal routing
  (`ticketer_for_asset`) are proper mutual inverses — which *requires* the
  dedup plus `derive_asset_id` injectivity and `≠ ASSET_TEZ`.  So
  first-match ordering is provably *not* load-bearing.

## Shield/transfer/unshield are signature-bound (non-malleability)

> "every prover-rewritable field … is folded into the sighash and signed
> by an in-circuit WOTS+ signature."

- `Spec.Shield.shield_sighash_binds`,
  `Spec.Transfer.transfer_sighash_binds`,
  `Spec.Unshield.unshield_sighash_binds` — two accepted txs sharing a
  sighash publish byte-identical public fields (recipient, amounts, asset
  commitments, nullifiers, fee, memo hashes).  Since the WOTS+ signature
  is over the sighash, no field can be altered without invalidating it.
  In particular the unshield's L1 `recipient` / `asset` / `amount` are
  signed — the sequencer cannot redirect or re-denominate a withdrawal.
- `Impl.Shield.shield_note_bound_to_pubkey_hash` — ENTRY-POINT BINDING:
  the SAME `(auth_root, auth_pub_seed)` are folded into both the public
  deposit-pool key (`pubkey_hash`) and the created note's owner tag, and
  the in-circuit XMSS is verified under that `auth_root`.  So an accepted
  shield to a published `pubkey_hash` owned by `(R, PS)` is forced to
  create a note owned by exactly `(R, PS)`, and only that key-holder can
  perform it — nobody can shield a victim's pool into a note they
  control.  The deposit→note creation-side companion to
  `spend_authorized_by_owner`.
- `Spec.Hashes.replay_resistant` (cross-deployment replay via auth_domain):
  proves the MECHANISM — a proof for one `auth_domain` does not verify
  under another (the differing sighash invalidates the signature).
  OPERATIONAL PRECONDITION (must be surfaced honestly): this gives
  cross-deployment separation only if each deployment configures a
  DISTINCT `auth_domain`.  `core::default_auth_domain()` is a FIXED dev
  constant (`hash("tzel-auth-domain-local-dev-v1")`) whose own doc-comment
  says "Production deployments should override this with a unique
  per-deployment value" — set via `configure_verifier`'s
  `config.auth_domain` (then frozen, `ConfigOnce`).  Two deployments that
  both leave the default in place would share an `auth_domain` and the
  theorem's hypothesis (distinct domains) would not hold.  The proof is
  honest about its condition; the deployment must satisfy it.

## WOTS+ one-time / key-reuse safety

> "reusing a one-time key across two transactions can expose enough chain
> preimages for forgery."

- `Spec.Xmss.wots_one_time_unforgeable` +
  `Spec.Xmss.xmss_one_time_unforgeable`: a forward-only forgery against a
  fixed leaf verifies only for the *originally signed* message.  The
  single-use safety is the contrapositive of the documented reuse hazard;
  the only crypto assumption is chain-hash preimage resistance (explicit).

## Note integrity: commitment binds its fields

> (Underpins "watch wallets must iterate the candidate-asset registry
> because cm alone doesn't reveal the asset", and rules out asset/value
> substitution.)

- `Spec.Hashes.commitment_binds_asset` (a note's asset is welded to its
  cm — no asset substitution), `commitment_binds_value` (no per-note
  amount inflation), `commitment_binds_auth_root` (spending authority
  welded to cm — no authority substitution).
- RELATION-LEVEL ENFORCEMENT (the circuit's witness cannot deviate from
  the note's bound fields, because `ci_otag` is COMPUTED from
  `ci_auth_root` and fed into `ci_cm`):
  - `Impl.Transfer.spend_authorized_by_owner` — THEFT RESISTANCE: a
    spend of a note owned by `R` forces the witness `ci_auth_root = R`
    (and pub_seed / nk_tag); composed with the in-circuit XMSS check
    under `ci_auth_root` and XMSS unforgeability, only `R`'s key-holder
    can spend `R`'s note.
  - `Impl.Transfer.spend_binds_asset` — ASSET-CONFUSION RESISTANCE
    (multiasset): a spend whose commitment carries asset `a` forces the
    declared `ci_asset = a`; with per-asset `grand_conservation`, no
    cross-asset inflation.
  - Both cover transfer AND unshield (shared `CairoInput`/`input_checks`).

## Double-spend / replay / faerie-gold

- `Spec.KernelNullifier.reachable_nodup` / `respend_rejected`
  (no nullifier accepted twice), `note_spent_at_most_once`
  (composes with the circuit nullifier binding).
- `Impl.Transfer.no_double_spend` — WITNESS-VARYING double-spend
  resistance: two spends of the same note yield the SAME nullifier even
  if the attacker varies `nk_spend`, because `owner_tag` binds
  `H_nktag(nk_spend)` and `H_nktag` is injective — so the kernel's
  dedup cannot be evaded by re-deriving the nullifier.
- `Spec.Hashes.nullifier_binding` (distinct notes → distinct nullifiers:
  no aliasing a victim's nullifier to block their spend).
- `Spec.Merkle.merkle_binding` (FAERIE-GOLD: a verifying path uniquely
  determines the leaf at its position — you cannot spend a note that
  isn't a genuine tree leaf).
- `Spec.ShieldReplay.no_duplicate_shielded_note` (a replayed shield
  cannot mint a duplicate note).
- `Spec.Hashes.nullifier_position_distinct` (the same note
  value at distinct positions has distinct nullifiers).

## Bridge / Michelson contract (fa2_bridge_ticketer.tz)

- **Collateralization (dynamic):** `Spec.BridgeTicketer.fully_collateralized`
  (custody = outstanding tickets, *exactly*, as a state-machine
  invariant preserved by every mint/burn `BStep`),
  `ticket_redeemable` (any amount ≤ outstanding tickets is ≤ custody —
  every ticket is always redeemable).
- **Burn authentication:** `Spec.BridgeBurn.custody_decrease_authentic`
  (a foreign ticket cannot drain custody — the `ticketer == SELF`
  check), `foreign_ticket_rejected` / `forwarded_ticket_rejected`
  (only SELF-minted tickets burn).
- **Canonical ticket content** (the documented `ticket.content.token_id
  == 0` design — the asset is bound to the ticketer KT1 address, not
  the content): `Spec.BridgeBurn.nonzero_token_rejected` /
  `metadata_rejected` AND `Spec.KernelDeposit.nonzero_token_rejected` /
  `metadata_rejected` — a ticket with a non-zero `token_id` or any
  metadata is rejected on BOTH the L1 burn and the L2 deposit, so no
  content-based asset confusion across the round-trip.
- **Deposit anti-spoofing:**
  `Spec.KernelDeposit.credit_requires_owning_ticketer` (only the
  registered ticketer can credit a pool),
  `unregistered_sender_rejected`.
- **Routing bijection:** `Spec.AssetRegistry.fa2_routes_correctly` (a
  registered FA2 asset's deposit and withdrawal routes are mutual
  inverses), `deposit_withdraw_roundtrip` / `withdraw_deposit_roundtrip`.
- **Round-trip solvency:** `Spec.EndToEnd(Multi).withdrawal_honored`
  (any L2-note value is ≤ L1 custody — every withdrawal can be
  honored), `no_stranded_l1` (custody ≤ pool + notes — no L1 funds
  unclaimable), `roundtrip_solvency` (out ≤ in over the full deposit →
  shield → unshield → exit lifecycle), per asset.

## Storage / serialization foundations

- `Spec.StoragePaths.cross_no_collision` + per-type incomparability
  (no nullifier/deposit/shield-cm path ever collides),
  `Spec.DepositKey.deposit_key_bytes_injective` (distinct pools never
  share a durable slot), `Spec.WithdrawalRecord.decode_encode`
  (lossless withdrawal-record codec — no misdirected/corrupted exit).

## Commitment tree

- `Spec.Merkle.merkle_binding` / `auth_binding` (membership soundness:
  can't forge two leaves to one root),
  `Spec.MerkleTree.tree_root_correct` (committed root = batch root of all
  notes), `Spec.MerkleFrontierCorrect.froot_fbuild_eq` (the kernel's
  O(depth) frontier read-off equals the batch root — also
  differential-validated against the production tree).
- `Spec.TreeCapacity.capacity_invariant` (the tree never exceeds
  `2^DEPTH` — the `append_note` capacity check) + `committed_root_correct`
  (so the frontier proof's precondition is discharged by the kernel's own
  check: the kernel always commits the true batch root).
- `Spec.ValidRoots.valid_roots_genuine` (the kernel accepts membership
  against ANY root in its valid-root set, and every such root is a
  genuine tree root — so historical-root acceptance is safe: no forged
  root is ever accepted, composing with `merkle_binding` and the
  nullifier set).

## Kernel config governance (verifier / bridge config)

> Implicit in the threat model: the verifier and bridge configs must be
> installed only by the admin, never swapped, and required before any
> operation.

- `Spec.ConfigAuth.config_update_unforgeable` — config updates are
  WOTS+-signed against a compiled admin leaf; only the admin can install
  a config (reduces to WOTS+ unforgeability).
- `Spec.ConfigOnce.config_immutable` / `reconfigure_unchanged` — the
  config is one-shot; once installed it is frozen (no overwrite).
- `Spec.ConfigOnce.operations_require_config` — no deposit / shield /
  transfer / unshield is processed before the config is installed.
- Together: config substitution is impossible from every angle (forge
  install, overwrite, or operate unconfigured).
- **OPERATIONAL PRECONDITION (must be surfaced honestly):**
  `config_update_unforgeable` reduces config-install security to WOTS+
  unforgeability of the *compiled admin leaf* — which is only a real
  secret in a PRODUCTION build.  The kernel has a `USES_DEV_ADMIN_FALLBACK`
  path (`debug_assertions` build with no `TZEL_ROLLUP_*_HEX` env vars)
  whose admin key is the PUBLIC constant `dev_config_admin_ask()` =
  `hash("tzel-dev-rollup-config-admin")`; under it, anyone could forge a
  config install (e.g. a malicious verifier that accepts any proof —
  total compromise).  The kernel emits a loud "SECURITY WARNING … MUST
  NOT be used in production. Rebuild with `cargo build --release` AND set
  the `TZEL_ROLLUP_*_HEX` env vars" on every config message in that mode.
  So the unforgeability theorem is honest about its premise (a secret
  admin key); the deployment must provide one (release build + env
  vars), not the dev fallback.  CONTAINMENT (verified by tracing the
  derivation): the fallback is gated `cfg!(any(test, debug_assertions))`,
  so a RELEASE build can never silently use the dev key — a release
  build lacking the env vars fails SAFE (`compiled_config_admin_*`
  returns `Err`, the config is rejected, no operations proceed) rather
  than falling back.  The verifier-config and bridge-config admin leaves
  are SEPARATE WOTS keys (distinct `TZEL_ROLLUP_VERIFIER_…` /
  `…_BRIDGE_…_LEAF_HEX`, shared pub seed), each its own one-time key, so
  the two authorities are separable and a verifier-config signature
  cannot install a bridge config (different leaf AND config-specific
  sighash).

## Master kernel safety (joint invariants, non-interference)

- `Spec.KernelSoundness.kernel_state_sound` — over a unified kernel state
  and step relation (spend / append / configure), the safety invariants
  hold SIMULTANEOUSLY in every reachable state: no double-spend AND every
  valid root genuine AND current root genuine AND tree within capacity.
  The content is non-interference — each operation preserves the
  invariants it doesn't touch — so the per-structure proofs compose into
  whole-system safety with no gaps. `kernel_config_frozen` carries the
  config immutability into the joint machine.

## Extraction-source soundness (Spec → Impl refinement)

> The three-layer architecture: the extractable, Cairo-shaped `Impl`
> provably discharges the abstract `Spec` safety properties (so the
> extraction source is trustworthy and missing assertions are caught).

- `Impl.Merkle.merkle_refines_spec` / `auth_refines_spec`,
  `Impl.Wots.refines_spec` — the executable Merkle path / WOTS+ chain
  step are the Spec definitions at the concrete hashes.
- `Impl.Transfer.transfer_relation_sound`,
  `Impl.Shield.shield_relation_sound`,
  `Impl.Unshield.unshield_relation_sound` — the Cairo-shaped
  transfer / shield / unshield relations discharge the corresponding
  `Spec.*` value conservation and sighash / pubkey-hash bindings (the
  `asset registered` conjunct is deliberately lifted to the kernel and
  discharged there by `AssetRegistry`).
- `Impl.Xmss.xmss_verify_impl_one_time_unforgeable` /
  `xmss_ltree_injective_impl` — the extractable XMSS verifier inherits
  the Spec one-time unforgeability and L-tree injectivity at the concrete
  `Hash3` / `pack_adrs_chain`. All six Impl modules carry proven
  refinement/soundness theorems.

### The relation-soundness theorems are provably NON-VACUOUS

A theorem `Relation -> Phi` proves nothing if `Relation` is
unsatisfiable (a modeling contradiction would make it vacuously true —
and the differential tests, which exercise extracted *functions*, cannot
detect an unsatisfiable *relation*).  The relations are proven inhabited:

- `Impl.Shield.shield_relation_inhabited`,
  `Impl.Transfer.transfer_relation_inhabited`,
  `Impl.Unshield.unshield_relation_inhabited` — a single concrete honest
  transaction satisfies every conjunct of each relation at once (honest
  WOTS+ signature with the key fixed first, hash-correct commitments,
  pinned producer fee, balanced 2-accumulator).
- `Spec.XmssInhabited.xmss_cairo_sep_inhabited` — the only
  non-trivially-satisfiable conjunct (the in-circuit XMSS verify) is
  inhabited in isolation.
- `Spec.XmssInhabited.inhab_hyps_satisfiable` — the `wots_digits`/`sks`
  well-formedness premises of those inhabitations are themselves
  satisfiable, so the inhabitations are not vacuously conditional.

All five rest on only `Felt` + `Felt_eq_dec` (Print Assumptions).  So
the circuit-relation soundness theorems are load-bearing, not hollow.

The implementation-grounding theorems are likewise clean (Print
Assumptions, verified): the pure checksum arithmetic
(`checksum_encoding_wellformed`, `base4_val_encode5`) is AXIOM-FREE; the
WOTS+/XMSS/config unforgeability-for-the-real-format theorems
(`wots_`/`xmss_`/`config_update_concrete_checksum`) rest on `Felt`
alone — every collision-resistance / injectivity assumption they use
(`node_injective`, the hash injectivities) appears as a universally
quantified PREMISE, never a global axiom; `grand_conservation` and its
three flow instances rest on `Felt` + `Felt_eq_dec`.  The four headline
spend/entry guarantees — `spend_authorized_by_owner` (theft),
`no_double_spend`, `spend_binds_asset` (asset confusion), and
`shield_note_bound_to_pubkey_hash` (entry binding) — each rest on `Felt`
ALONE (Print Assumptions, verified), with their commitment / owner-tag /
nk-tag / sighash injectivity hypotheses as explicit premises.  So
nothing in the recent grounding work introduced a hidden axiom or
`Admitted`: the whole theory's trusted base remains the two `Felt`
parameters plus the explicitly-discharged local CR hypotheses.

A CLEAN STRUCTURAL SEPARATION falls out of a system-level Print
Assumptions (verified): the ACCOUNTING / SOLVENCY layer depends on no
cryptographic assumption at all.  `Spec.KernelSoundness.kernel_state_sound`
(master kernel safety) and `Spec.BridgeTicketer.bridge_solvency` are
AXIOM-FREE (pure nat accounting); `Spec.KernelLedger.no_inflation`,
`Spec.EndToEndMulti.l1_collateral_equals_l2_claims`, and
`grand_conservation` rest on `Felt` + `Felt_eq_dec` ALONE.  The
collision-resistance / injectivity hypotheses appear ONLY in the
circuit-binding theorems (theft, double-spend, asset-confusion,
commitment / nullifier / sighash binding), always as local premises.
So the ledger conservation, kernel state invariants, bridge
collateralization, and L1<->L2 backing are UNCONDITIONAL — they need no
hash assumption; cryptographic hardness is required only to BIND those
accounting quantities to the actual notes and signatures the circuits
manipulate.  An attacker who broke every hash could not violate the
accounting invariants; they could only mis-bind a note to a value or
owner — which is exactly what the CR-premised circuit theorems forbid.

GRANULAR CRYPTO-DEPENDENCY MAP (which hash's collision-resistance is
load-bearing for which guarantee — "if hash X is not CR, what breaks?"):

| CR / injectivity premise        | Guarantees it underpins |
|---------------------------------|-------------------------|
| `injective_5 H_commit`          | commitment binds value / asset / owner; theft (`spend_authorized_by_owner`); asset-confusion (`spend_binds_asset`); double-spend (`no_double_spend`) |
| `injective_3 H_owner`           | owner-tag binds auth_root; theft; double-spend |
| `H_nktag` injective             | double-spend under witness variation (`no_double_spend`) |
| `injective_2 H_nf`              | nullifier binding (no aliasing); position-distinct nullifiers; dedup soundness |
| `injective_2 H_sighash`         | sighash non-malleability (all three flows); pubkey_hash / shield entry-point binding; config-governance unforgeability; cross-deployment replay; exit non-redirection |
| `node_injective H_node`         | Merkle membership / faerie-gold (`merkle_binding`); XMSS auth-tree binding (`auth_binding`); L-tree injectivity |
| `derive_asset_id` inj + `≠ tez` | asset-registry routing bijection (deposit/withdraw inverse) |
| WOTS+ chain-hash preimage res.  | the forward-only attacker model under which `wots_`/`xmss_one_time_unforgeable` holds |

So an auditor reviewing a single hash can read off exactly which
guarantees rest on it; conversely every CR premise here is LOCAL (a
Section hypothesis), never a global axiom (`Print Assumptions`).

## How faithfulness (model ↔ implementation) is established

The Coq relations/state-machines are claimed to model the Cairo
circuits, the Rust kernel, and the Michelson contract.  That claim
rests on three independent mechanisms, not on trust:

1. **SHA-pinned drift gate** (`Drift/check.sh`, `MANIFEST.toml`): every
   modeled Cairo file's SHA-256 is pinned; CI fails on any divergence,
   forcing a model review when the source changes (6/6 mirrors).
2. **Differential fuzzing** (`ocaml/coq_driver/test`, 15 cases): the
   *extracted* Coq functions (chain step, commitment, nullifier,
   sighash, merkle path, L-tree compression, O(depth) frontier root) are
   checked byte-for-byte against the OCaml port on thousands of random
   inputs — so the executable parts of the model compute what an
   independent implementation computes.  NOTE on the reference: the
   differential's reference is the OCaml protocol port, which agrees
   with the Rust protocol (`tzel_core`) via pinned cross-impl vectors —
   it is NOT (yet) run directly against the Cairo.  The Cairo's tie to
   the model is established by mechanisms 1 and 3 (SHA-pinned drift +
   the assertion cross-check); a *direct* Cairo-vs-extracted-function
   conformance runner is forthcoming.
3. **Systematic assertion cross-check** (manual, documented): every
   assertion in the three Cairo circuits, every check in the Michelson
   bridge contract, the kernel's deposit/config/capacity/valid-root
   gates, AND the kernel apply-path commits (shield dual-pool balances +
   `client_cm` replay + asset-registered; unshield/transfer nullifier
   freshness + root snapshot) were enumerated and matched to a relation
   conjunct or a theorem.  This found exactly one omission — the
   per-input `wots_sig` length assert — now modeled (`input_checks`).
   Confirmed faithful:
   the asset gates, 2-accumulator balance, producer-tez pin, nullifier,
   merkle membership, in-circuit XMSS, change-slot-absent zeroing
   (`asset = 0 = ASSET_TEZ`), and the deposit accept gates
   (`d_creator = d_sender` anti-relay, token_id=0, no metadata,
   canonical recipient, registered sender, configured).

What the differential cannot establish (relation *satisfiability*) is
covered by the inhabitation theorems above; what drift+differential
cannot establish (the relation *Props* match the Cairo accept
condition) is covered by the assertion cross-check.

---

## Documented properties NOT formally verified (and why)

- **THE FUNDAMENTAL BOUNDARY — what these proofs do and do not cover.**
  The Coq proves the circuit RELATIONS are sound: *if* a witness
  satisfies a relation (the conjunction of the circuit's accept
  conditions), *then* the protocol safety property holds (no inflation,
  no theft, etc.).  Full safety of the DEPLOYED system additionally
  requires two things this model does NOT prove, both deliberately out
  of scope:
  (a) **The STARK proof system soundly enforces the relation** — that a
      verifying proof implies the existence of a witness satisfying the
      relation.  This is STARK soundness (the prover cannot prove a false
      statement), explicitly out of scope per the engagement.
  (b) **The deployed verifier key corresponds to THESE audited
      circuits** — the verification key the kernel is configured with
      (admin-set, then frozen) must be the one generated from the exact
      Cairo circuits this model is faithful to (drift-pinned).  If a
      different key were installed, the STARK would verify a DIFFERENT
      circuit and none of the relation-soundness results would apply.
      The deployment must generate the key from these circuits; the
      admin-config trust root (above) gates who installs it.
  So the chain is: [Coq: relation ⇒ safety] ∘ [drift+differential: Coq
  relation = Cairo circuit] ∘ [STARK+key: verifying proof ⇒ satisfying
  witness of that circuit].  This module owns the first link and the
  faithfulness of the second; the third is the proof-system boundary.
- **`validate_l1_ticketer_canonical` (b58check canonicalization):**
  string-level input validation (trim whitespace, require KT1, b58check
  parse + re-emit).  This is byte/parsing-level Tezos-address handling,
  out of scope (the Tezos b58check codec is a vendored dependency).  The
  proofs that *use* asset ids (`AssetRegistry`) take `derive_asset_id`
  injectivity as a hypothesis — which holds precisely *because* inputs are
  canonicalized first; the canonicalization itself is assumed, not proved.
- **Detection-tag false-positive rate / ML-KEM:** privacy/crypto
  primitive, explicitly out of scope.
- **Memo *semantic* correctness:** the spec itself states `memo_ct_hash`
  is transport integrity, not semantic correctness; the sighash binding
  (proved) covers the transport-integrity claim, and nothing more is
  claimed.
- **Kernel apply-path durable-state atomicity:** the Rust
  `apply_durable_*_commit` functions' stateful sequencing is modeled at
  the level of the accounting state machines (`KernelLedger`,
  `KernelNullifier`, …), not byte-for-byte against the durable-storage
  imperative code.  The faithfulness boundary (transcription, not
  extraction) is stated per-module.
- **Michelson contract interaction-robustness `FAILWITH`s:** a fresh
  cross-check of `fa2_bridge_ticketer.tz` confirms every
  SECURITY-relevant guard is modelled (zero-amount mint → `bstep_mint`
  `0<n`; burn `creator==SELF` / `token_id==0` / metadata-`None` →
  `BridgeBurn`).  The remaining `FAILWITH`s are interaction-robustness
  against OUT-OF-SCOPE contracts and are intentionally not modelled:
  "must not attach tez" (line 83 — the contract is non-payable, a
  no-stuck-tez guard orthogonal to the FA2 collateralization the bridge
  state machine tracks); "FA2 %transfer entrypoint not found" (the FA2
  contract); "invalid rollup contract" (the caller-chosen rollup
  destination — and the kernel independently credits only registered
  ticketers, `KernelDeposit.credit_requires_owning_ticketer`, so a
  mis-sent ticket is never credited).
