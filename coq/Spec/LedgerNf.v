(** * Spec.LedgerNf — global no-inflation with an explicit nullifier set

    [Spec.Ledger] proved the global conservation law over a model
    where spending REMOVES notes from a live multiset.  That is a
    faithful abstraction only if "consume a note" really behaves like
    multiset removal — which is itself a consequence of the nullifier
    mechanism.  This module discharges that seam: it models the real
    discipline.

    - Notes are append-only: a [committed] log grows and never
      shrinks (mirroring the commitment tree).
    - Spending marks a NULLIFIER in a growing [spent] set (mirroring
      the kernel's nullifier set); nothing is ever deleted.
    - "Live value" is DERIVED: a committed note counts iff its
      nullifier is not yet spent.

    A settlement step consumes notes only if (a) they are committed
    [membership], (b) their nullifiers are not yet spent [freshness],
    and the global note-nullifier assignment is injective
    [distinctness — exactly [Spec.Hashes.nullifier_binding]].  Under
    that discipline we re-prove:

    - [reachable_conserved]: deposited(a) = exited(a) + live(a) in
      every reachable state;
    - [no_inflation]: hence exited(a) <= deposited(a);
    - [no_double_spend]: the spent set never contains a duplicate, so
      no note is ever consumed twice.

    Now the consumption rule is DERIVED from membership + nullifier
    freshness + uniqueness, not modeled as removal. *)

From Stdlib Require Import List Arith Lia Permutation.
Import ListNotations.
From Common Require Import Felt.
From Spec Require Import Transfer.

(** A note carries its asset, value, and nullifier identity. *)
Record Note : Type := mkNote {
  n_asset : Felt;
  n_value : nat;
  n_nf    : Felt;
}.

(** Is nullifier [x] in the spent set? *)
Definition is_spent (x : Felt) (spent : list Felt) : bool :=
  if in_dec Felt_eq_dec x spent then true else false.

(** A note's contribution to the live total of asset [a]: its value,
    unless its asset differs or its nullifier is already spent. *)
Definition note_contrib (a : Felt) (spent : list Felt) (n : Note) : nat :=
  if Felt_eq_dec (n_asset n) a
  then (if is_spent (n_nf n) spent then 0 else n_value n)
  else 0.

(** Plain nat sum (own fixpoint so [simpl] reduces it reliably). *)
Fixpoint nsum (l : list nat) : nat :=
  match l with
  | [] => 0
  | x :: xs => x + nsum xs
  end.

(** Live value of asset [a]: sum of contributions over committed. *)
Definition live_sum (a : Felt) (committed : list Note) (spent : list Felt)
  : nat :=
  nsum (map (note_contrib a spent) committed).

(** Plain per-asset value of a note list (no nullifier filtering):
    [live_sum] against an empty spent set. *)
Definition note_sum (a : Felt) (notes : list Note) : nat :=
  live_sum a notes [].

(* ================================================================ *)
(** ** Arithmetic of [live_sum]                                       *)
(* ================================================================ *)

Lemma nsum_app (xs ys : list nat) :
  nsum (xs ++ ys) = nsum xs + nsum ys.
Proof. induction xs as [| x xr IH]; simpl; lia. Qed.

Lemma nsum_perm (xs ys : list nat) :
  Permutation xs ys -> nsum xs = nsum ys.
Proof.
  intro H.
  induction H as [| x l l' Hp IH | x y l | l l' l'' H1 IH1 H2 IH2];
    simpl; lia.
Qed.

Lemma live_sum_app (a : Felt) (c1 c2 : list Note) (spent : list Felt) :
  live_sum a (c1 ++ c2) spent = live_sum a c1 spent + live_sum a c2 spent.
Proof. unfold live_sum. rewrite map_app, nsum_app. reflexivity. Qed.

Lemma live_sum_perm (a : Felt) (c1 c2 : list Note) (spent : list Felt) :
  Permutation c1 c2 -> live_sum a c1 spent = live_sum a c2 spent.
Proof.
  intro H. unfold live_sum. apply nsum_perm. apply Permutation_map. exact H.
Qed.

(** [is_spent] against an extended set. *)
Lemma is_spent_app_notin (x : Felt) (added spent : list Felt) :
  ~ In x added -> is_spent x (added ++ spent) = is_spent x spent.
Proof.
  intro Hnotin. unfold is_spent.
  destruct (in_dec Felt_eq_dec x (added ++ spent)) as [Hin | Hnin];
    destruct (in_dec Felt_eq_dec x spent) as [Hin2 | Hnin2];
    try reflexivity.
  - apply in_app_or in Hin. destruct Hin; [contradiction | contradiction].
  - exfalso. apply Hnin. apply in_or_app. right. exact Hin2.
Qed.

Lemma is_spent_app_in (x : Felt) (added spent : list Felt) :
  In x added -> is_spent x (added ++ spent) = true.
Proof.
  intro Hin. unfold is_spent.
  destruct (in_dec Felt_eq_dec x (added ++ spent)) as [_ | Hnin].
  - reflexivity.
  - exfalso. apply Hnin. apply in_or_app. left. exact Hin.
Qed.

(** Notes whose nullifiers all avoid [added] are unaffected by adding
    [added] to the spent set. *)
Lemma live_sum_unaffected (a : Felt) (notes : list Note)
    (added spent : list Felt) :
  (forall n, In n notes -> ~ In (n_nf n) added) ->
  live_sum a notes (added ++ spent) = live_sum a notes spent.
Proof.
  intro Havoid. unfold live_sum. f_equal.
  apply map_ext_in. intros n Hin. unfold note_contrib.
  rewrite (is_spent_app_notin (n_nf n) added spent (Havoid n Hin)).
  reflexivity.
Qed.

(** Notes all of whose nullifiers are in [added] contribute nothing. *)
Lemma live_sum_all_spent (a : Felt) (notes : list Note)
    (added spent : list Felt) :
  (forall n, In n notes -> In (n_nf n) added) ->
  live_sum a notes (added ++ spent) = 0.
Proof.
  intro Hall. unfold live_sum.
  assert (Hmap : map (note_contrib a (added ++ spent)) notes
                 = map (fun _ => 0) notes).
  { apply map_ext_in. intros n Hin. unfold note_contrib.
    rewrite (is_spent_app_in (n_nf n) added spent (Hall n Hin)).
    destruct (Felt_eq_dec (n_asset n) a); reflexivity. }
  rewrite Hmap.
  clear. induction notes; simpl; lia.
Qed.

(** Notes all of whose nullifiers are fresh (unspent) contribute their
    plain per-asset value. *)
Lemma live_sum_fresh (a : Felt) (notes : list Note) (spent : list Felt) :
  (forall n, In n notes -> is_spent (n_nf n) spent = false) ->
  live_sum a notes spent = note_sum a notes.
Proof.
  intro Hfresh. unfold live_sum, note_sum, live_sum. f_equal.
  apply map_ext_in. intros n Hin. unfold note_contrib.
  rewrite (Hfresh n Hin).
  destruct (Felt_eq_dec (n_asset n) a); reflexivity.
Qed.

(* ================================================================ *)
(** ** The consumption delta                                          *)
(* ================================================================ *)

(** The key lemma.  If [committed] decomposes (up to permutation) into
    the [consumed] notes and a [rest], the consumed notes are unspent,
    and the rest's nullifiers are disjoint from the consumed ones
    (distinctness), then marking the consumed nullifiers spent reduces
    the live total by exactly the consumed value:

      live_sum committed spent
        = note_sum consumed + live_sum committed (consumed_nfs ++ spent)

    Stated additively to avoid nat subtraction. *)
Lemma live_sum_consume (a : Felt)
    (committed consumed rest : list Note) (spent : list Felt) :
  Permutation committed (consumed ++ rest) ->
  (forall n, In n consumed -> is_spent (n_nf n) spent = false) ->
  (forall n, In n rest -> ~ In (n_nf n) (map n_nf consumed)) ->
  live_sum a committed spent
  = note_sum a consumed
    + live_sum a committed (map n_nf consumed ++ spent).
Proof.
  intros Hperm Hfresh Hdisj.
  (* rewrite committed by the permutation on both live_sums *)
  rewrite (live_sum_perm a committed (consumed ++ rest) spent Hperm).
  rewrite (live_sum_perm a committed (consumed ++ rest)
             (map n_nf consumed ++ spent) Hperm).
  rewrite !live_sum_app.
  (* consumed under old spent = note_sum (fresh) *)
  rewrite (live_sum_fresh a consumed spent Hfresh).
  (* consumed under new spent = 0 (all its nfs are in the added set) *)
  rewrite (live_sum_all_spent a consumed (map n_nf consumed) spent).
  2:{ intros n Hin. apply in_map_iff. exists n. split; [reflexivity | exact Hin]. }
  (* rest unaffected by the added nfs *)
  rewrite (live_sum_unaffected a rest (map n_nf consumed) spent Hdisj).
  lia.
Qed.

(* ================================================================ *)
(** ** The ledger state machine                                       *)
(* ================================================================ *)

Record Ledger : Type := mkLedger {
  led_dep    : list Note;                          (* deposit log *)
  led_exit   : list Note;                          (* exit log *)
  led_commit : list Note;                          (* append-only notes *)
  led_spent  : list Felt;                          (* nullifier set *)
}.

Definition genesis : Ledger := mkLedger [] [] [] [].

(** Total deposited of asset [a]. *)
Definition dep_sum (a : Felt) (s : Ledger) : nat :=
  note_sum a (led_dep s).

Definition exit_sum (a : Felt) (s : Ledger) : nat :=
  note_sum a (led_exit s).

Definition live (a : Felt) (s : Ledger) : nat :=
  live_sum a (led_commit s) (led_spent s).

(** The conservation invariant. *)
Definition conserved (s : Ledger) : Prop :=
  forall a : Felt, dep_sum a s = exit_sum a s + live a s.

(** Well-formedness.  Three invariants, all guaranteed by the
    nullifier mechanism's soundness:
    - [NoDup (map n_nf committed)]: distinct notes have distinct
      nullifiers (exactly [Spec.Hashes.nullifier_binding]).  Append-
      only: spent notes STAY committed, so the spent set is NOT
      disjoint from the committed nullifiers — that is why we cannot
      ask for [NoDup (committed_nfs ++ spent)].
    - [incl spent (map n_nf committed)]: every spent nullifier
      belongs to a real committed note.
    - [NoDup spent]: no nullifier is spent twice (no double-spend). *)
Definition wf (s : Ledger) : Prop :=
  NoDup (map n_nf (led_commit s))
  /\ incl (led_spent s) (map n_nf (led_commit s))
  /\ NoDup (led_spent s).

(** Transitions. *)
Inductive Step : Ledger -> Ledger -> Prop :=
| step_deposit :
    forall s a v nf,
      (* the new note's nullifier is globally fresh *)
      ~ In nf (map n_nf (led_commit s)) ->
      Step s (mkLedger
                (mkNote a v nf :: led_dep s)
                (led_exit s)
                (mkNote a v nf :: led_commit s)
                (led_spent s))
| step_settle :
    forall s (consumed rest produced exits : list Note),
      (* membership: committed is consumed ++ rest (up to order) *)
      Permutation (led_commit s) (consumed ++ rest) ->
      (* freshness: consumed nullifiers are not yet spent *)
      (forall n, In n consumed -> is_spent (n_nf n) (led_spent s) = false) ->
      (* produced notes get globally-fresh, distinct nullifiers *)
      NoDup (map n_nf produced ++ map n_nf (led_commit s)) ->
      (* per-asset value conservation: consumed = produced + exits *)
      (forall a, note_sum a consumed
                 = note_sum a produced + note_sum a exits) ->
      Step s (mkLedger
                (led_dep s)
                (exits ++ led_exit s)
                (produced ++ led_commit s)
                (map n_nf consumed ++ led_spent s)).

(* ================================================================ *)
(** ** Small helpers                                                  *)
(* ================================================================ *)

Lemma note_sum_cons (a : Felt) (n : Note) (ns : list Note) :
  note_sum a (n :: ns)
  = (if Felt_eq_dec (n_asset n) a then n_value n else 0) + note_sum a ns.
Proof.
  unfold note_sum, live_sum. cbn [map nsum]. unfold note_contrib, is_spent.
  cbn. destruct (Felt_eq_dec (n_asset n) a); reflexivity.
Qed.

Lemma note_sum_app (a : Felt) (l1 l2 : list Note) :
  note_sum a (l1 ++ l2) = note_sum a l1 + note_sum a l2.
Proof. unfold note_sum. apply live_sum_app. Qed.

Lemma live_sum_cons (a : Felt) (n : Note) (ns : list Note) (spent : list Felt) :
  live_sum a (n :: ns) spent
  = note_contrib a spent n + live_sum a ns spent.
Proof. unfold live_sum. cbn [map nsum]. reflexivity. Qed.

Lemma nodup_app_disj {A} (l1 l2 : list A) :
  NoDup (l1 ++ l2) -> forall x, In x l2 -> ~ In x l1.
Proof.
  induction l1 as [| y l1 IH]; cbn; intros Hnd x Hin2 Hin1.
  - exact Hin1.
  - inversion Hnd as [| ? ? Hnotin Hnd']; subst.
    destruct Hin1 as [Heq | Hin1].
    + subst y. apply Hnotin. apply in_or_app. right. exact Hin2.
    + exact (IH Hnd' x Hin2 Hin1).
Qed.

(** [is_spent] is false exactly when the nullifier is absent. *)
Lemma is_spent_false_notin (x : Felt) (spent : list Felt) :
  ~ In x spent -> is_spent x spent = false.
Proof.
  intro Hn. unfold is_spent.
  destruct (in_dec Felt_eq_dec x spent); [contradiction | reflexivity].
Qed.

(* ================================================================ *)
(** ** Preservation                                                   *)
(* ================================================================ *)

Lemma step_preserves_wf : forall s s', wf s -> Step s s' -> wf s'.
Proof.
  intros s s' [Hnd [Hincl Hnds]] Hstep.
  destruct Hstep as [s a v nf Hfresh
                    | s consumed rest produced exits Hperm Hfresh Hndp Hceq];
    cbn [led_dep led_exit led_commit led_spent].
  - (* deposit *)
    repeat split; cbn.
    + constructor; assumption.
    + intros x Hx. right. apply Hincl. exact Hx.
    + exact Hnds.
  - (* settle *)
    (* consumed nfs are a sub-multiset of committed nfs *)
    assert (Hpm : Permutation (map n_nf (led_commit s))
                    (map n_nf consumed ++ map n_nf rest)).
    { rewrite <- map_app. apply Permutation_map. exact Hperm. }
    assert (HcommitND : NoDup (map n_nf consumed ++ map n_nf rest)).
    { eapply Permutation_NoDup; [exact Hpm | exact Hnd]. }
    repeat split; cbn.
    + (* NoDup (produced_nfs ++ commit_nfs) — given *)
      rewrite map_app. exact Hndp.
    + (* spent' = consumed_nfs ++ spent included in commit' = produced++commit *)
      intros x Hx. rewrite map_app. apply in_app_or in Hx.
      apply in_or_app. right. destruct Hx as [Hxc | Hxs].
      * (* x in consumed_nfs ⊆ commit_nfs *)
        eapply Permutation_in; [apply Permutation_sym; exact Hpm |].
        apply in_or_app. left. exact Hxc.
      * (* x in spent ⊆ commit_nfs *)
        apply Hincl. exact Hxs.
    + (* NoDup (consumed_nfs ++ spent) *)
      apply NoDup_app.
      * (* NoDup consumed_nfs *)
        eapply NoDup_app_remove_r. exact HcommitND.
      * exact Hnds.
      * (* disjoint: consumed_nfs ∩ spent = ∅, from freshness *)
        intros x Hxc Hxs.
        (* x ∈ consumed_nfs means some consumed note has nf = x *)
        apply in_map_iff in Hxc. destruct Hxc as [n [Hnf Hin]].
        specialize (Hfresh n Hin). unfold is_spent in Hfresh.
        destruct (in_dec Felt_eq_dec (n_nf n) (led_spent s)) as [_ | Hni].
        -- discriminate.
        -- apply Hni. rewrite Hnf. exact Hxs.
Qed.

Lemma step_preserves_conserved :
  forall s s', wf s -> conserved s -> Step s s' -> conserved s'.
Proof.
  intros s s' [Hnd [Hincl Hnds]] Hcons Hstep.
  destruct Hstep as [s a0 v nf Hfresh
                    | s consumed rest produced exits Hperm Hfresh Hndp Hceq];
    intro a; specialize (Hcons a);
    unfold dep_sum, exit_sum, live in *;
    cbn [led_dep led_exit led_commit led_spent] in *.
  - (* deposit *)
    rewrite note_sum_cons, live_sum_cons.
    unfold note_contrib. cbn [n_asset n_value n_nf].
    assert (Hns : is_spent nf (led_spent s) = false).
    { apply is_spent_false_notin. intro Hin. apply Hfresh, Hincl, Hin. }
    rewrite Hns.
    destruct (Felt_eq_dec a0 a); lia.
  - (* settle *)
    (* consumed nfs sub-permute committed nfs *)
    assert (Hpm : Permutation (map n_nf (led_commit s))
                    (map n_nf consumed ++ map n_nf rest)).
    { rewrite <- map_app. apply Permutation_map. exact Hperm. }
    assert (HcND : NoDup (map n_nf consumed ++ map n_nf rest)).
    { eapply Permutation_NoDup; [exact Hpm | exact Hnd]. }
    (* rest nfs disjoint from consumed nfs *)
    assert (Hdisj : forall n, In n rest -> ~ In (n_nf n) (map n_nf consumed)).
    { intros n Hin Hc. eapply (nodup_app_disj _ _ HcND).
      - apply in_map_iff. exists n. split; [reflexivity | exact Hin].
      - exact Hc. }
    (* produced nfs are fresh against consumed_nfs ++ spent *)
    assert (Hpfresh : forall n, In n produced ->
              is_spent (n_nf n) (map n_nf consumed ++ led_spent s) = false).
    { intros n Hin. apply is_spent_false_notin. intro Hbad.
      apply in_app_or in Hbad.
      (* n_nf n is in produced_nfs, hence not in commit_nfs *)
      assert (Hnotcommit : ~ In (n_nf n) (map n_nf (led_commit s))).
      { intro Hcm. eapply (nodup_app_disj _ _ Hndp _ Hcm).
        apply in_map_iff. exists n. split; [reflexivity | exact Hin]. }
      destruct Hbad as [Hbc | Hbs].
      - (* in consumed_nfs ⊆ commit_nfs *)
        apply Hnotcommit. eapply Permutation_in;
          [apply Permutation_sym; exact Hpm |].
        apply in_or_app. left. exact Hbc.
      - (* in spent ⊆ commit_nfs *)
        apply Hnotcommit. apply Hincl. exact Hbs. }
    (* now compute *)
    rewrite note_sum_app.
    rewrite live_sum_app.
    rewrite (live_sum_fresh a produced _ Hpfresh).
    (* delta on the committed part *)
    pose proof (live_sum_consume a (led_commit s) consumed rest
                  (led_spent s) Hperm Hfresh Hdisj) as Hdelta.
    specialize (Hceq a).
    lia.
Qed.

(* ================================================================ *)
(** ** Reachability and the global laws                               *)
(* ================================================================ *)

Inductive Steps : Ledger -> Ledger -> Prop :=
| steps_refl  : forall s, Steps s s
| steps_trans : forall s s' s'', Step s s' -> Steps s' s'' -> Steps s s''.

Lemma genesis_wf : wf genesis.
Proof.
  unfold wf, genesis; cbn.
  repeat split; try constructor. intros x H. inversion H.
Qed.

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

Theorem reachable_invariant :
  forall s, Steps genesis s -> wf s /\ conserved s.
Proof.
  intros s H. exact (steps_preserve genesis s H genesis_wf genesis_conserved).
Qed.

(** Conservation law: in every reachable state, for every asset,
    deposited = exited + live. *)
Theorem reachable_conserved :
  forall s a, Steps genesis s -> dep_sum a s = exit_sum a s + live a s.
Proof.
  intros s a H. destruct (reachable_invariant s H) as [_ Hc]. exact (Hc a).
Qed.

(** NO INFLATION: in every reachable state, for every asset, the total
    that left the system is at most the total deposited.  Withdrawals
    are exits, so withdrawn <= deposited in particular. *)
Theorem no_inflation :
  forall s a, Steps genesis s -> exit_sum a s <= dep_sum a s.
Proof.
  intros s a H. pose proof (reachable_conserved s a H). lia.
Qed.

(** NO DOUBLE-SPEND: in every reachable state the nullifier set has no
    duplicate — no note is ever consumed twice. *)
Theorem no_double_spend :
  forall s, Steps genesis s -> NoDup (led_spent s).
Proof.
  intros s H. destruct (reachable_invariant s H) as [[_ [_ Hnd]] _]. exact Hnd.
Qed.

(* ================================================================ *)
(** ** Bridge to the circuit conservation predicate                   *)
(* ================================================================ *)

(** [note_sum] over a note list equals [Spec.Transfer.sum_at] over its
    parallel (asset, value) projection — so the [step_settle]
    conservation hypothesis is exactly the circuits'
    [phi_value_conservation] / [phi_unshield_value_conservation]
    instantiated on the consumed / produced / exit note lists.  A
    proven (Relation -> Phi) transaction therefore induces a valid
    [step_settle]. *)
Lemma note_sum_is_sum_at (a : Felt) (notes : list Note) :
  note_sum a notes
  = Transfer.sum_at a (map n_asset notes) (map n_value notes).
Proof.
  induction notes as [| n ns IH]; [reflexivity |].
  rewrite note_sum_cons. cbn [map].
  rewrite Transfer.sum_at_cons, IH. reflexivity.
Qed.

(** * On modeling values as [nat] (overflow).

    Values here are [nat] — unbounded — so the accounting is exact and
    cannot wrap.  This is the NO-OVERFLOW IDEALIZATION, and it is
    faithful to the real system precisely because the Cairo circuits
    enforce the discipline that makes wraparound impossible there:

    - every value is range-checked to [u64] (the [try_into().unwrap()]
      in the [run_*] entry points), and
    - per-transaction conservation is accumulated in [u128], whose
      headroom the bounded input/output count (<= 7 in, <= 4 out)
      never exhausts (11 * 2^64 < 2^128), so no per-tx sum wraps.

    Under those two facts a real [u128]/[u64] conservation check
    coincides with this [nat] equation, so the idealization loses
    nothing.  What this model does NOT itself prove is those two facts
    — they are discharged in the Cairo (range asserts + accumulator
    width) and checked by reading it / the differential runners, not
    here.  A fully self-contained treatment would carry value bounds
    (values < 2^64, and a bound on the number of live notes so the
    GLOBAL totals stay within the real asset supply < 2^63 mutez) and
    prove the sums stay in range.  That is a refinement, not a gap in
    the law as stated over [nat]. *)
