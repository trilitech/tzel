(** * Spec.TreeCapacity — the kernel's tree stays within capacity, so its
    committed root is provably the batch Merkle root

    The kernel's commitment tree has a fixed depth [DEPTH] (capacity
    [2^DEPTH] leaves).  [append_note] / [ensure_note_capacity]
    ([tezos/rollup-kernel/src/lib.rs]) reject appending once the tree
    is full ("Merkle tree full: 2^DEPTH leaves"; [append_note] checks
    [count >= 2^DEPTH] before writing at index [count]).

    This module models the note list under that capacity-checked
    append and proves:
    - [capacity_invariant]: the note count never exceeds [2^DEPTH];
    - [committed_root_correct]: when the tree is not full, the root
      the kernel reads off its O(depth) frontier
      ([MerkleFrontier.froot] over [fbuild]) equals the batch Merkle
      root of the committed notes ([mroot]).

    So the capacity check is exactly what discharges the
    [length leaves < 2^DEPTH] precondition of
    [Spec.MerkleFrontierCorrect.froot_fbuild_eq]: the kernel always
    commits the true Merkle root of the notes it has appended. *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Spec Require Import MerkleTree MerkleFrontier MerkleFrontierCorrect.

Section TreeCapacity.

  Variable Felt : Type.
  Variable Hh : Felt -> Felt -> Felt.
  Variable z0 : Felt.
  Variable DEPTH : nat.

  Notation cap := (2 ^ DEPTH).

  (** The committed-note list.  An append succeeds only when there is
      room (count < capacity), placing the note at index [count]. *)
  Inductive TStep : list Felt -> list Felt -> Prop :=
  | tstep_append :
      forall notes cm,
        length notes < cap ->
        TStep notes (notes ++ cm :: nil).

  Inductive TSteps : list Felt -> list Felt -> Prop :=
  | tsteps_refl  : forall s, TSteps s s
  | tsteps_trans : forall s s' s'', TStep s s' -> TSteps s' s'' -> TSteps s s''.

  (** The tree never exceeds capacity. *)
  Lemma tstep_keeps_cap : forall notes notes',
    length notes <= cap -> TStep notes notes' -> length notes' <= cap.
  Proof.
    intros notes notes' Hle Hstep. destruct Hstep as [notes0 cm Hlt].
    rewrite length_app. cbn [length]. lia.
  Qed.

  Theorem capacity_invariant : forall notes,
    TSteps nil notes -> length notes <= cap.
  Proof.
    intros notes H.
    assert (Hgen : length (@nil Felt) <= cap) by (cbn; lia).
    revert Hgen. induction H as [s | s s' s'' Hstep Hrest IH]; intro Hle.
    - exact Hle.
    - apply IH. exact (tstep_keeps_cap s s' Hle Hstep).
  Qed.

  (** When the tree is not full, the kernel's O(depth) frontier read-off
      equals the batch Merkle root of the committed notes — discharging
      the precondition of [froot_fbuild_eq] from the capacity bound. *)
  Theorem committed_root_correct : forall notes,
    TSteps nil notes ->
    length notes < cap ->
    froot Felt Hh z0 DEPTH (fbuild Felt Hh notes) 0 z0
    = mroot Felt Hh z0 DEPTH notes.
  Proof.
    intros notes _ Hlt.
    apply (froot_fbuild_eq Felt Hh z0 DEPTH notes Hlt).
  Qed.

End TreeCapacity.
