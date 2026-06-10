(** * Spec.ValidRoots — the valid-root set contains only genuine tree roots

    The kernel accepts a membership proof against ANY root in its
    valid-root set ([has_valid_root] in [tezos/rollup-kernel/src/lib.rs]),
    not just the latest.  The set is seeded with the genesis (empty
    tree) root and grown ONLY by [snapshot_root], which marks the
    CURRENT tree root after a state-changing operation.

    So the design decision "accept any historical root" is safe because
    the set never contains a forged root: every element was, at some
    point, the actual tree root the kernel computed.  Combined with
    [Spec.Merkle.merkle_binding] (you cannot forge an authentication
    path to a genuine root for a non-member note), a membership proof
    can only succeed for a note that was genuinely committed — and
    double-spend is independently prevented by the nullifier set
    ([Spec.KernelNullifier]), regardless of which historical root was
    used.

    Modeled as a state machine over [(current_root, valid_set)] with an
    abstract [genuine] predicate (the roots the tree legitimately
    produces, e.g. via the proven [simulate_frontier_append] /
    [froot_fbuild_eq]).  Proved (zero admits): every root in the valid
    set is genuine. *)

From Stdlib Require Import List.
Import ListNotations.

Section ValidRoots.

  Variable Felt : Type.

  (** The roots the tree legitimately produces.  Concretely these are
      the [froot]/[mroot] values of actual note lists (proved correct
      in [Spec.MerkleFrontierCorrect]); here it is abstract. *)
  Variable genuine : Felt -> Prop.

  Record VState : Type := mkV { v_cur : Felt; v_valid : list Felt }.

  Inductive VStep : VState -> VState -> Prop :=
  | vstep_update :
      (* a state-changing op recomputes the current root to a genuine
         new root [r'] (the tree only ever produces genuine roots) *)
      forall cur valid r', genuine r' -> VStep (mkV cur valid) (mkV r' valid)
  | vstep_snapshot :
      (* snapshot_root: mark the CURRENT root valid *)
      forall cur valid, VStep (mkV cur valid) (mkV cur (cur :: valid)).

  Inductive VSteps : VState -> VState -> Prop :=
  | vsteps_refl  : forall s, VSteps s s
  | vsteps_trans : forall s s' s'', VStep s s' -> VSteps s' s'' -> VSteps s s''.

  Definition v_inv (s : VState) : Prop :=
    genuine (v_cur s) /\ (forall r, In r (v_valid s) -> genuine r).

  Lemma v_step_preserves : forall s s', v_inv s -> VStep s s' -> v_inv s'.
  Proof.
    intros s s' [Hcur Hvalid] Hstep. destruct Hstep as [cur valid r' Hr' | cur valid].
    - (* update: cur := r' (genuine), valid unchanged *)
      split; [exact Hr' | exact Hvalid].
    - (* snapshot: valid := cur :: valid, cur genuine *)
      split; [exact Hcur | ].
      intros r [Heq | Hin]; cbn in *.
      + subst r. exact Hcur.
      + exact (Hvalid r Hin).
  Qed.

  Lemma v_steps_preserve : forall s s', VSteps s s' -> v_inv s -> v_inv s'.
  Proof.
    intros s s' H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Hinv.
    - exact Hinv.
    - apply IH. exact (v_step_preserves s s' Hinv Hstep).
  Qed.

  (** Genesis: the kernel seeds the set with the (genuine) empty-tree
      root.  Its invariant holds. *)
  Lemma v_inv_genesis : forall root0,
    genuine root0 -> v_inv (mkV root0 (root0 :: nil)).
  Proof.
    intros root0 H. split; cbn.
    - exact H.
    - intros r [Heq | []]. subst r. exact H.
  Qed.

  (** ** Every root in the valid set is a genuine tree root.

      So a membership proof — which the kernel accepts against any root
      in this set — can only be checked against a root the tree
      actually produced; no forged root is ever accepted. *)
  Theorem valid_roots_genuine : forall root0 s,
    genuine root0 ->
    VSteps (mkV root0 (root0 :: nil)) s ->
    forall r, In r (v_valid s) -> genuine r.
  Proof.
    intros root0 s Hg H r Hin.
    destruct (v_steps_preserve _ s H (v_inv_genesis root0 Hg)) as [_ Hvalid].
    exact (Hvalid r Hin).
  Qed.

End ValidRoots.
