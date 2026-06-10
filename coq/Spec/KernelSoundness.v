(** * Spec.KernelSoundness — the kernel's safety invariants hold jointly

    The kernel's durable state has several independent structures: the
    nullifier set, the valid-root set, the commitment tree, and the
    one-shot config.  Earlier modules each proved ONE invariant in
    isolation:
    - [Spec.KernelNullifier]: no nullifier is accepted twice;
    - [Spec.ValidRoots]: every valid root is a genuine tree root;
    - [Spec.TreeCapacity]: the tree never exceeds capacity;
    - [Spec.ConfigOnce]: the config, once installed, is frozen.

    This module unifies them: a single kernel state and a single
    transaction step relation (spend a note, append a note, install the
    config), and proves the conjunction of all the invariants is
    preserved by EVERY step — so they hold SIMULTANEOUSLY in every
    reachable state, and no operation breaks another operation's
    invariant (non-interference: a spend doesn't overflow the tree, an
    append doesn't double-spend, a configure touches none of them).

    This is the whole-system safety statement the separate per-structure
    proofs compose into.  Zero admits. *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.

Section KernelSoundness.

  Variable Felt : Type.
  Variable Cfg : Type.
  (** Roots the tree legitimately produces (proved correct in
      [Spec.MerkleFrontierCorrect]); abstract here. *)
  Variable genuine : Felt -> Prop.
  (** Tree capacity [2^DEPTH]. *)
  Variable cap : nat.

  Record KState : Type := mkK {
    k_nf    : list Felt;     (* spent nullifiers *)
    k_roots : list Felt;     (* valid-root set *)
    k_cur   : Felt;          (* current tree root *)
    k_notes : list Felt;     (* committed notes *)
    k_cfg   : option Cfg;    (* one-shot config *)
  }.

  Inductive KStep : KState -> KState -> Prop :=
  | kstep_spend :
      (* spend: the nullifier must be fresh (the kernel's
         has_nullifier check), then it is recorded *)
      forall nf roots cur notes cfg n,
        ~ In n nf ->
        KStep (mkK nf roots cur notes cfg)
              (mkK (n :: nf) roots cur notes cfg)
  | kstep_append :
      (* append a note: only with capacity; the new root is genuine
         (the computed froot/mroot) and is snapshotted into the
         valid-root set *)
      forall nf roots cur notes cfg cm r',
        length notes < cap -> genuine r' ->
        KStep (mkK nf roots cur notes cfg)
              (mkK nf (r' :: roots) r' (notes ++ cm :: nil) cfg)
  | kstep_configure :
      (* install the config (one-shot: only from unset) *)
      forall nf roots cur notes c,
        KStep (mkK nf roots cur notes None)
              (mkK nf roots cur notes (Some c)).

  Inductive KSteps : KState -> KState -> Prop :=
  | ksteps_refl  : forall s, KSteps s s
  | ksteps_trans : forall s s' s'', KStep s s' -> KSteps s' s'' -> KSteps s s''.

  (** The joint safety invariant: no double-spend, all valid roots
      genuine, current root genuine, tree within capacity. *)
  Definition k_inv (s : KState) : Prop :=
    NoDup (k_nf s)
    /\ Forall genuine (k_roots s)
    /\ genuine (k_cur s)
    /\ length (k_notes s) <= cap.

  Lemma k_step_preserves : forall s s', k_inv s -> KStep s s' -> k_inv s'.
  Proof.
    intros s s' [Hnf [Hroots [Hcur Hcap]]] Hstep.
    destruct Hstep as
      [nf roots cur notes cfg n Hfresh
      | nf roots cur notes cfg cm r' Hlt Hg
      | nf roots cur notes c]; cbn in *.
    - (* spend: NoDup extends; others unchanged *)
      repeat split; [| exact Hroots | exact Hcur | exact Hcap].
      constructor; [exact Hfresh | exact Hnf].
    - (* append: capacity grows by one, root genuine + snapshotted *)
      repeat split.
      + exact Hnf.
      + constructor; [exact Hg | exact Hroots].
      + exact Hg.
      + cbn [k_notes]. rewrite length_app. cbn [length]. lia.
    - (* configure: touches only the config slot *)
      repeat split; [exact Hnf | exact Hroots | exact Hcur | exact Hcap].
  Qed.

  Lemma k_steps_preserve : forall s s', KSteps s s' -> k_inv s -> k_inv s'.
  Proof.
    intros s s' H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Hinv.
    - exact Hinv.
    - apply IH. exact (k_step_preserves s s' Hinv Hstep).
  Qed.

  (** A well-formed genesis: empty nullifier set, the valid-root set
      seeded with the genuine empty-tree root, empty tree, unconfigured. *)
  Definition kgenesis (root0 : Felt) : KState :=
    mkK nil (root0 :: nil) root0 nil None.

  Lemma k_inv_genesis : forall root0,
    genuine root0 -> 0 <= cap -> k_inv (kgenesis root0).
  Proof.
    intros root0 Hg _. unfold kgenesis, k_inv; cbn.
    repeat split.
    - constructor.
    - constructor; [exact Hg | constructor].
    - exact Hg.
    - lia.
  Qed.

  (** ** MASTER SAFETY: in every reachable kernel state, all four
      invariants hold at once.

      So across any interleaving of spends, note-appends, and the
      config install, the kernel simultaneously: never double-spends,
      only ever holds genuine roots, keeps a genuine current root, and
      never overfills the tree.  The per-structure proofs compose with
      no interference. *)
  Theorem kernel_state_sound : forall root0 s,
    genuine root0 ->
    KSteps (kgenesis root0) s ->
    NoDup (k_nf s)
    /\ Forall genuine (k_roots s)
    /\ genuine (k_cur s)
    /\ length (k_notes s) <= cap.
  Proof.
    intros root0 s Hg Hsteps.
    apply (k_steps_preserve (kgenesis root0) s Hsteps).
    apply k_inv_genesis; [exact Hg | lia].
  Qed.

  (** Config non-interference: across the SAME unified steps, an
      installed config stays installed (no spend/append/configure
      overwrites it).  Composes the ConfigOnce immutability into the
      joint machine. *)
  Lemma kstep_cfg_frozen : forall s s' c,
    KStep s s' -> k_cfg s = Some c -> k_cfg s' = Some c.
  Proof.
    intros s s' c Hstep Heq.
    destruct Hstep; cbn in *; try exact Heq. discriminate Heq.
  Qed.

  Theorem kernel_config_frozen : forall s s' c,
    KSteps s s' -> k_cfg s = Some c -> k_cfg s' = Some c.
  Proof.
    intros s s' c H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Heq.
    - exact Heq.
    - apply IH. exact (kstep_cfg_frozen s s' c Hstep Heq).
  Qed.

End KernelSoundness.
