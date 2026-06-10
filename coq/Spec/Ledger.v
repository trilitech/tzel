(** * Spec.Ledger — global value-conservation law

    The per-circuit soundness proofs ([Relation -> Phi] in
    [Impl.Transfer] / [Impl.Unshield] / [Impl.Shield]) each give a
    SINGLE-transaction value-conservation fact: for every asset, the
    value consumed equals the value produced plus what the
    transaction sends out of the shielded system (a public exit
    and/or the burned fee).

    This module lifts that to the WHOLE system.  It models the
    shielded ledger as a tiny state machine and proves an inductive
    invariant that holds in every reachable state:

      for every asset a,
        total_deposited(a) = total_exited(a) + value_of_live_notes(a)

    from which the headline NO-INFLATION law drops out:

        total_exited(a) <= total_deposited(a)

    i.e. no sequence of shields / transfers / unshields — however
    interleaved, however adversarial — can ever move more value of
    any asset out of the system than was deposited into it.  Public
    withdrawals (the unshield [v_pub] exits) are a subset of the
    exits, so in particular withdrawn(a) <= deposited(a).

    ** Why this is soundness-based and NOT a pool/turnstile argument.

    The state machine has NO pool-balance bookkeeping.  Its only
    "check" is structural: a settlement step consumes notes that are
    LITERALLY PRESENT in the live multiset ([led_live = consumed ++
    rest]).  That decomposition is exactly what the circuit soundness
    delivers — Merkle membership says each consumed note is a real
    leaf of the commitment tree, and nullifier uniqueness
    ([Spec.Hashes.batch_nullifier_set_faithful]) says each is removed
    at most once.  Given that, the global law follows purely from the
    per-transaction conservation equation; the kernel's operational
    pool accounting is never invoked.

    ** Bridge to the circuits.

    [settle_conservation_of_transfer] / [..._unshield] show that the
    per-asset conservation hypothesis the settlement step requires is
    EXACTLY [Spec.Transfer.phi_value_conservation] /
    [Spec.Unshield.phi_unshield_value_conservation] with the right
    exit list — so a valid (proven) transfer or unshield really does
    induce a valid ledger step. *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Common Require Import Felt.
From Spec Require Import Transfer Unshield.

(** [sum_at] distributes over parallel-list concatenation. *)
Lemma sum_at_app (target : Felt) (xs ys : list Felt) (vs ws : list nat) :
  length xs = length vs ->
  sum_at target (xs ++ ys) (vs ++ ws)
  = sum_at target xs vs + sum_at target ys ws.
Proof.
  revert vs.
  induction xs as [| x xr IH]; intros [| v vr] Hlen;
    try discriminate; cbn.
  - reflexivity.
  - rewrite IH by (injection Hlen; auto). lia.
Qed.

(** [sum_at] of a singleton (asset, value) pair. *)
Lemma sum_at_single (t a : Felt) (v : nat) :
  sum_at a [t] [v] = (if Felt_eq_dec t a then v else 0).
Proof. cbn. destruct (Felt_eq_dec t a); lia. Qed.

(** ** The ledger state

    Three append-only logs, each a parallel (asset, value) pair of
    lists so [sum_at] can total any asset:
    - [dep]  — every L1 deposit that entered the system;
    - [exit] — every value that left (unshield public exits + burned
               fees);
    - [live] — the multiset of currently-unspent notes (this lumps
               the deposit pool and the commitment tree's live notes;
               the distinction is irrelevant to value conservation). *)

Record Ledger : Type := mkLedger {
  led_dep_a  : list Felt; led_dep_v  : list nat;
  led_exit_a : list Felt; led_exit_v : list nat;
  led_live_a : list Felt; led_live_v : list nat;
}.

Definition genesis : Ledger := mkLedger [] [] [] [] [] [].

Definition wf (s : Ledger) : Prop :=
  length (led_dep_a s)  = length (led_dep_v s)
  /\ length (led_exit_a s) = length (led_exit_v s)
  /\ length (led_live_a s) = length (led_live_v s).

(** The conservation invariant. *)
Definition conserved (s : Ledger) : Prop :=
  forall a : Felt,
    sum_at a (led_dep_a s) (led_dep_v s)
    = sum_at a (led_exit_a s) (led_exit_v s)
      + sum_at a (led_live_a s) (led_live_v s).

(** ** The transition relation

    - [step_deposit a v]: an L1 deposit of [v] of asset [a] — credits
      [dep] and mints a live note (value enters the system).
    - [step_settle]: the common shape of shield / transfer / unshield.
      Consumes a sub-multiset of live notes (witnessed by [live =
      consumed ++ rest]), produces new live notes, and sends value
      out as [exits] (an unshield [v_pub] and/or the burned fee).
      [Hcons] — consumed = produced + exits per asset — is the
      circuit's Phi guarantee. *)

Inductive Step : Ledger -> Ledger -> Prop :=
| step_deposit :
    forall s a v,
      Step s (mkLedger
                (a :: led_dep_a s) (v :: led_dep_v s)
                (led_exit_a s) (led_exit_v s)
                (a :: led_live_a s) (v :: led_live_v s))
| step_settle :
    forall s
      (cons_a : list Felt) (cons_v : list nat)
      (rest_a : list Felt) (rest_v : list nat)
      (prod_a : list Felt) (prod_v : list nat)
      (ex_a : list Felt) (ex_v : list nat),
      led_live_a s = cons_a ++ rest_a ->
      led_live_v s = cons_v ++ rest_v ->
      length cons_a = length cons_v ->
      length prod_a = length prod_v ->
      length ex_a = length ex_v ->
      (forall a, sum_at a cons_a cons_v
                 = sum_at a prod_a prod_v + sum_at a ex_a ex_v) ->
      Step s (mkLedger
                (led_dep_a s) (led_dep_v s)
                (ex_a ++ led_exit_a s) (ex_v ++ led_exit_v s)
                (prod_a ++ rest_a) (prod_v ++ rest_v)).

(** ** Preservation *)

Lemma step_preserves_wf : forall s s', wf s -> Step s s' -> wf s'.
Proof.
  intros s s' [Hd [He Hl]] Hstep.
  destruct Hstep as [s a v | s ca cv ra rv pa pv ea ev HA HV HLc HLp HLe HC].
  - repeat split; cbn; auto.
  - repeat split; cbn.
    + exact Hd.
    + rewrite !length_app. lia.
    + (* live lengths: from old wf + the consumed/rest split *)
      rewrite HA in Hl. rewrite HV in Hl. rewrite !length_app in Hl.
      rewrite !length_app. lia.
Qed.

Lemma step_preserves_conserved :
  forall s s', wf s -> conserved s -> Step s s' -> conserved s'.
Proof.
  intros s s' [Hd [He Hl]] Hcons Hstep a.
  destruct Hstep as [s a0 v | s ca cv ra rv pa pv ea ev HA HV HLc HLp HLe HC].
  - (* deposit *)
    cbn. specialize (Hcons a). cbn in Hcons.
    destruct (Felt_eq_dec a0 a); lia.
  - (* settle *)
    cbn.
    specialize (Hcons a). cbn in Hcons.
    rewrite HA, HV in Hcons.
    rewrite (sum_at_app a ca ra cv rv HLc) in Hcons.
    rewrite (sum_at_app a ea (led_exit_a s) ev (led_exit_v s) HLe).
    rewrite (sum_at_app a pa ra pv rv HLp).
    specialize (HC a).
    lia.
Qed.

(** ** Reachability and the global laws *)

Inductive Steps : Ledger -> Ledger -> Prop :=
| steps_refl  : forall s, Steps s s
| steps_trans : forall s s' s'', Step s s' -> Steps s' s'' -> Steps s s''.

Lemma genesis_wf : wf genesis.
Proof. repeat split. Qed.

Lemma genesis_conserved : conserved genesis.
Proof. intro a. reflexivity. Qed.

Lemma steps_preserve :
  forall s s', Steps s s' -> wf s -> conserved s -> wf s' /\ conserved s'.
Proof.
  intros s s' Hsteps.
  induction Hsteps as [s | s s' s'' Hstep Hrest IH]; intros Hwf Hc.
  - split; assumption.
  - apply IH.
    + eapply step_preserves_wf; eauto.
    + eapply step_preserves_conserved; eauto.
Qed.

(** Every reachable ledger state satisfies the conservation
    invariant: deposited = exited + live, for every asset. *)
Theorem reachable_invariant :
  forall s, Steps genesis s -> wf s /\ conserved s.
Proof.
  intros s H.
  exact (steps_preserve genesis s H genesis_wf genesis_conserved).
Qed.

(** ** No inflation.

    The headline law: in any reachable state, the total value of any
    asset that has LEFT the system is at most the total that was
    deposited.  Public withdrawals are exits, so withdrawn <=
    deposited in particular.  Holds for every asset, over every
    reachable interleaving of operations. *)
Theorem no_inflation :
  forall s a,
    Steps genesis s ->
    sum_at a (led_exit_a s) (led_exit_v s)
    <= sum_at a (led_dep_a s) (led_dep_v s).
Proof.
  intros s a Hsteps.
  destruct (reachable_invariant s Hsteps) as [_ Hc].
  specialize (Hc a). lia.
Qed.

(** ** Bridge to the circuit soundness proofs

    The settlement step's [Hcons] hypothesis is precisely the
    per-asset value-conservation conjunct that the circuit [Phi]
    predicates carry (and that [Relation -> Phi] discharges).  These
    lemmas exhibit the exact exit list for each circuit, so a proven
    transfer / unshield really does induce a valid [step_settle]. *)

(** Transfer: the only exit is the burned tez fee. *)
Lemma settle_conservation_of_transfer
    (asset_tez : Felt)
    (in_a out_a : list Felt) (in_v out_v : list nat) (fee : nat) :
  phi_value_conservation asset_tez in_a in_v out_a out_v fee ->
  forall a,
    sum_at a in_a in_v
    = sum_at a out_a out_v + sum_at a [asset_tez] [fee].
Proof.
  intros Hphi a. specialize (Hphi a).
  rewrite sum_at_single.
  destruct (Felt_eq_dec asset_tez a) as [He | He];
    destruct (Felt_eq_dec a asset_tez) as [He2 | He2];
    try congruence; lia.
Qed.

(** Unshield: the exits are the public exit [(asset_pub, v_pub)] and
    the burned tez fee. *)
Lemma settle_conservation_of_unshield
    (asset_tez asset_pub : Felt)
    (in_a out_a : list Felt) (in_v out_v : list nat)
    (v_pub fee : nat) :
  phi_unshield_value_conservation asset_tez
    in_a in_v out_a out_v v_pub asset_pub fee ->
  forall a,
    sum_at a in_a in_v
    = sum_at a out_a out_v
      + sum_at a [asset_pub; asset_tez] [v_pub; fee].
Proof.
  intros Hphi a. specialize (Hphi a).
  cbn [sum_at].
  destruct (Felt_eq_dec asset_pub a) as [Hp | Hp];
    destruct (Felt_eq_dec asset_tez a) as [Ht | Ht];
    destruct (Felt_eq_dec a asset_pub) as [Hp2 | Hp2];
    destruct (Felt_eq_dec a asset_tez) as [Ht2 | Ht2];
    try congruence; lia.
Qed.
