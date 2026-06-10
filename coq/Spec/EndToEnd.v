(** * Spec.EndToEnd — L1 <-> L2 cross-system solvency

    The previous kernel/bridge modules each proved a one-sided
    accounting fact:
    - [Spec.BridgeTicketer]: L1 FA2 custody = outstanding tickets;
    - [Spec.KernelPool]:      deposited >= shielded (per pool);
    - [Spec.KernelLedger]:    withdrawn <= deposited (per asset).

    This module COMPOSES the bridge and the kernel into one state
    machine, with the two systems LINKED by the value that crosses
    the boundary, and proves the cross-system invariant the separate
    facts only imply piecewise:

      L1 FA2 custody  =  L2 pool value  +  L2 live-note value

    i.e. the FA2 the bridge holds on L1 always equals exactly the
    value that is claimable on L2 (sitting in deposit pools or live
    notes).  Two readings, both safety-critical:
    - [>=]  every live L2 note is backed by real L1 FA2 — a holder
            can always withdraw;
    - [<=]  no L1 FA2 is stranded beyond outstanding L2 claims.

    Scope: one FA2 asset (the per-asset accounting is independent
    across assets; tez and the producer-fee coupling are handled in
    [Spec.KernelLedger]).  FA2-denominated fees are taken as zero
    here — the rollup and producer fees are tez, accounted on the tez
    lane — so an FA2 asset's value moves pool<->note without burning.

    The LINK is the crux and is what makes this a composition rather
    than two unrelated lemmas:
    - a DEPOSIT credits L1 custody (a bridge mint) AND the L2 pool
      (the rollup receiving the minted ticket) by the same amount;
    - a WITHDRAW debits the L2 notes (an unshield) AND, via the
      outbox ticket the bridge burns, L1 custody by the same amount.
    Bridge and kernel cannot move independently across the boundary;
    every L1 custody change is matched by an L2 change. *)

From Stdlib Require Import Arith Lia.

(** Combined per-asset state of the whole L1<->L2 system. *)
Record EState : Type := mkEState {
  e_custody : nat;   (* L1: FA2 held by the bridge *)
  e_pool    : nat;   (* L2: deposit-pool value (deposited, not shielded) *)
  e_notes   : nat;   (* L2: live note value *)
  e_in      : nat;   (* cumulative deposited from L1 *)
  e_out     : nat;   (* cumulative withdrawn to L1 *)
}.

Definition egenesis : EState := mkEState 0 0 0 0 0.

Inductive EStep : EState -> EState -> Prop :=
| estep_deposit :
    (* L1 bridge mint + L2 pool credit, same amount, atomic *)
    forall s n,
      EStep s (mkEState (e_custody s + n) (e_pool s + n) (e_notes s)
                        (e_in s + n) (e_out s))
| estep_shield :
    (* L2-internal: pool -> notes; no L1 effect *)
    forall s v,
      v <= e_pool s ->
      EStep s (mkEState (e_custody s) (e_pool s - v) (e_notes s + v)
                        (e_in s) (e_out s))
| estep_unshield :
    (* L2 note burn + L1 bridge burn (outbox ticket), same amount *)
    forall s v,
      v <= e_notes s ->
      EStep s (mkEState (e_custody s - v) (e_pool s) (e_notes s - v)
                        (e_in s) (e_out s + v)).

Inductive ESteps : EState -> EState -> Prop :=
| esteps_refl  : forall s, ESteps s s
| esteps_trans : forall s s' s'', EStep s s' -> ESteps s' s'' -> ESteps s s''.

(** The cross-system invariant: L1 custody = L2 claimable value, plus
    the round-trip accounting custody = in - out. *)
Definition einvariant (s : EState) : Prop :=
  e_custody s = e_pool s + e_notes s
  /\ e_custody s = e_in s - e_out s
  /\ e_out s <= e_in s.

Lemma egenesis_inv : einvariant egenesis.
Proof.
  unfold einvariant, egenesis; cbn [e_custody e_pool e_notes e_in e_out].
  repeat split; lia.
Qed.

Lemma estep_preserves : forall s s', einvariant s -> EStep s s' -> einvariant s'.
Proof.
  intros s s' [Hcoll [Hacc Hle]] Hstep.
  destruct Hstep as [s n | s v Hv | s v Hv];
    unfold einvariant; cbn [e_custody e_pool e_notes e_in e_out];
    repeat split; lia.
Qed.

Lemma esteps_preserve : forall s s', ESteps s s' -> einvariant s -> einvariant s'.
Proof.
  intros s s' H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Hinv.
  - exact Hinv.
  - apply IH. eapply estep_preserves; eauto.
Qed.

Theorem reachable_einvariant :
  forall s, ESteps egenesis s -> einvariant s.
Proof. intros s H. exact (esteps_preserve egenesis s H egenesis_inv). Qed.

(** ** The cross-system solvency law.

    In every reachable state, the FA2 the bridge holds on L1 equals
    exactly the value claimable on L2 (pools + live notes). *)
Theorem l1_collateral_equals_l2_claims :
  forall s, ESteps egenesis s ->
    e_custody s = e_pool s + e_notes s.
Proof. intros s H. destruct (reachable_einvariant s H) as [Hc _]. exact Hc. Qed.

(** Every live L2 note is backed by real L1 FA2: custody covers the
    live note value (and the pools too). *)
Theorem notes_backed_by_l1 :
  forall s, ESteps egenesis s -> e_notes s <= e_custody s.
Proof. intros s H. pose proof (l1_collateral_equals_l2_claims s H). lia. Qed.

(** No L1 FA2 is stranded beyond L2 claims: custody never exceeds
    pools + notes. *)
Theorem no_stranded_l1 :
  forall s, ESteps egenesis s -> e_custody s <= e_pool s + e_notes s.
Proof. intros s H. pose proof (l1_collateral_equals_l2_claims s H). lia. Qed.

(** Round-trip: total withdrawn to L1 never exceeds total deposited
    from L1 — across the whole bridge+kernel system. *)
Theorem roundtrip_solvency :
  forall s, ESteps egenesis s -> e_out s <= e_in s.
Proof. intros s H. destruct (reachable_einvariant s H) as [_ [_ Hle]]. exact Hle. Qed.

(** A withdrawal can always be honored on L1: if [v] units are live
    as notes, the bridge holds at least [v] FA2 to release. *)
Theorem withdrawal_honored :
  forall s v, ESteps egenesis s -> v <= e_notes s -> v <= e_custody s.
Proof. intros s v H Hv. pose proof (notes_backed_by_l1 s H). lia. Qed.
