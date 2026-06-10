(** * Spec.KernelNullifier — kernel-level double-spend prevention

    Models the rollup kernel's nullifier set
    ([has_nullifier]/[insert_nullifier] in
    [tezos/rollup-kernel/src/lib.rs], plus the within-batch
    "duplicate nullifier" check) and proves the consensus-critical
    no-double-spend property at the KERNEL boundary, complementing the
    circuit-level [Spec.Hashes.nullifier_binding].

    The kernel accepts a transaction presenting nullifiers [nfs] iff:
    - the [nfs] are internally distinct (the "duplicate nullifier"
      rejection — a transaction cannot list the same nullifier
      twice), and
    - none of [nfs] is already in the durable spent set
      ([has_nullifier] returns false for each).
    On acceptance every nullifier in [nfs] is inserted into the set.

    Proved (zero admits):
    - [reachable_nodup]: the spent set has no duplicates in any
      reachable state — no nullifier is ever recorded by two
      transactions;
    - [respend_rejected]: a transaction presenting an already-spent
      nullifier cannot take a step (the kernel rejects it);
    - [spent_is_permanent]: the spent set only grows — once a
      nullifier is recorded it stays recorded forever;
    - [note_spent_at_most_once]: composing with the circuit binding
      (note -> nullifier injective + deterministic), each note can be
      consumed at most once across the whole history. *)

From Stdlib Require Import List.
Import ListNotations.

Section KernelNullifier.

  Variable NF : Type.
  Variable NF_eq_dec : forall x y : NF, {x = y} + {x <> y}.

  (** The durable spent-nullifier set, as a list. *)
  Definition NfState := list NF.

  Definition nf_genesis : NfState := [].

  (** A transaction with nullifiers [nfs] is acceptable against the
      current set iff its nullifiers are internally distinct and none
      is already spent. *)
  Definition acceptable (spent : NfState) (nfs : list NF) : Prop :=
    NoDup nfs /\ (forall n, In n nfs -> ~ In n spent).

  Inductive NfStep : NfState -> NfState -> Prop :=
  | nfstep_apply :
      forall spent nfs,
        acceptable spent nfs ->
        NfStep spent (nfs ++ spent).

  Inductive NfSteps : NfState -> NfState -> Prop :=
  | nfsteps_refl  : forall s, NfSteps s s
  | nfsteps_trans : forall s s' s'', NfStep s s' -> NfSteps s' s'' -> NfSteps s s''.

  (* ============================================================= *)
  (** ** The spent set stays duplicate-free                          *)
  (* ============================================================= *)

  (** [NoDup] of a concatenation, given each side is [NoDup] and they
      are disjoint. *)
  Lemma NoDup_app_disjoint (l1 l2 : list NF) :
    NoDup l1 -> NoDup l2 ->
    (forall x, In x l1 -> ~ In x l2) ->
    NoDup (l1 ++ l2).
  Proof.
    induction l1 as [| x xs IH]; intros H1 H2 Hdisj; cbn.
    - exact H2.
    - inversion H1 as [| ? ? Hx Hxs]; subst.
      constructor.
      + intro Hin. apply in_app_or in Hin. destruct Hin as [Hin | Hin].
        * exact (Hx Hin).
        * apply (Hdisj x); [left; reflexivity | exact Hin].
      + apply IH; [exact Hxs | exact H2 |].
        intros y Hy. apply Hdisj. right. exact Hy.
  Qed.

  Lemma step_preserves_nodup :
    forall s s', NoDup s -> NfStep s s' -> NoDup s'.
  Proof.
    intros s s' Hnd Hstep.
    destruct Hstep as [spent nfs [Hndnfs Hfresh]].
    apply NoDup_app_disjoint; [exact Hndnfs | exact Hnd | exact Hfresh].
  Qed.

  Lemma steps_preserve_nodup :
    forall s s', NfSteps s s' -> NoDup s -> NoDup s'.
  Proof.
    intros s s' H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Hnd.
    - exact Hnd.
    - apply IH. eapply step_preserves_nodup; eauto.
  Qed.

  Lemma genesis_nodup : NoDup nf_genesis.
  Proof. constructor. Qed.

  (** No nullifier is ever recorded by two transactions: the spent set
      is duplicate-free in every reachable state. *)
  Theorem reachable_nodup :
    forall s, NfSteps nf_genesis s -> NoDup s.
  Proof.
    intros s H. exact (steps_preserve_nodup nf_genesis s H genesis_nodup).
  Qed.

  (* ============================================================= *)
  (** ** Re-spend is rejected; the set only grows                    *)
  (* ============================================================= *)

  (** A transaction containing an already-spent nullifier is NOT
      acceptable — so the kernel cannot take a step on it. *)
  Theorem respend_rejected :
    forall spent nfs n,
      In n spent -> In n nfs -> ~ acceptable spent nfs.
  Proof.
    intros spent nfs n Hspent Hnfs [_ Hfresh].
    exact (Hfresh n Hnfs Hspent).
  Qed.

  (** The spent set only grows: a recorded nullifier stays recorded. *)
  Lemma step_monotone : forall s s' n, NfStep s s' -> In n s -> In n s'.
  Proof.
    intros s s' n Hstep Hin. destruct Hstep as [spent nfs _].
    apply in_or_app. right. exact Hin.
  Qed.

  Theorem spent_is_permanent :
    forall s s' n, NfSteps s s' -> In n s -> In n s'.
  Proof.
    intros s s' n H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Hin.
    - exact Hin.
    - apply IH. eapply step_monotone; eauto.
  Qed.

  (** Once a nullifier is spent, no reachable future state will accept
      a transaction that re-presents it. *)
  Theorem once_spent_forever_blocked :
    forall s s' n nfs,
      NfSteps s s' -> In n s -> In n nfs -> ~ acceptable s' nfs.
  Proof.
    intros s s' n nfs Hsteps Hin Hnfs.
    apply (respend_rejected s' nfs n).
    - exact (spent_is_permanent s s' n Hsteps Hin).
    - exact Hnfs.
  Qed.

End KernelNullifier.

(* ================================================================ *)
(** ** Composition with the circuit nullifier binding                *)
(* ================================================================ *)

Section NoteUniqueSpend.

  (** Notes and their nullifiers.  [nf_of] is the circuit's nullifier
      function; [Spec.Hashes.nullifier_binding] gives that it is
      INJECTIVE under collision resistance (distinct notes -> distinct
      nullifiers) and it is of course deterministic.  We take those
      two facts as the interface. *)
  Variable Note NF : Type.
  Variable NF_eq_dec : forall x y : NF, {x = y} + {x <> y}.
  Variable nf_of : Note -> NF.
  Hypothesis nf_injective : forall a b, nf_of a = nf_of b -> a = b.

  (** "Note [m] is spent in state [s]" means its nullifier is in the
      durable set. *)
  Definition note_spent (s : list NF) (m : Note) : Prop := In (nf_of m) s.

  (** A note can be consumed at most once across the whole history:
      if note [m] is already spent, no reachable future transaction
      whose nullifiers include [m]'s can be accepted.  This is the
      end-to-end double-spend guarantee — circuit binding (the
      nullifier identifies the note) plus the kernel dedup (each
      nullifier accepted once). *)
  Theorem note_spent_at_most_once :
    forall (s s' : list NF) (m : Note) (nfs : list NF),
      NfSteps NF s s' ->
      note_spent s m ->
      In (nf_of m) nfs ->
      ~ acceptable NF s' nfs.
  Proof.
    intros s s' m nfs Hsteps Hsp Hin.
    exact (once_spent_forever_blocked NF s s' (nf_of m) nfs Hsteps Hsp Hin).
  Qed.

  (** Two distinct notes never collide on a nullifier, so spending one
      never blocks the other (no false double-spend rejection): the
      kernel's dedup is exactly per-note. *)
  Theorem distinct_notes_distinct_nullifiers :
    forall a b : Note, a <> b -> nf_of a <> nf_of b.
  Proof.
    intros a b Hne Heq. apply Hne. exact (nf_injective a b Heq).
  Qed.

End NoteUniqueSpend.
