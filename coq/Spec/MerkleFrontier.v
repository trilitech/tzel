(** * Spec.MerkleFrontier — the kernel's O(depth) incremental frontier

    [Spec.MerkleTree] proved the append-only-Merkle root correct for an
    arbitrary append index ([tdfront_correct]) using a model that
    carries the WHOLE prefix.  The kernel ([simulate_frontier_append])
    instead keeps only O(depth) state — a [branches[]] array holding
    one "live left child" per level — and recomputes the root from it.
    This module models that O(depth) state directly as a binary-counter
    frontier and proves its core structural correctness.

    A frontier is a [list (option Felt)]: slot [lv] holds the root of a
    complete height-[lv] subtree ([Some]) or is empty ([None]).
    Appending a leaf is binary increment with carry — store at the
    first empty slot, or combine two subtrees and carry up.

    Proved (zero admits):
    - [mroot_combine]: the carry is value-correct — combining two
      equal-size subtree roots is the parent root
      ([mroot (S lv) (a ++ b) = H (mroot lv a) (mroot lv b)]);
    - [fval_fappend]: [fappend] is a correct binary counter — appending
      a height-[lv] block increments the represented leaf count by
      [2^lv] (with carry);
    - [fappend_preserves_frep]: appending a leaf preserves the
      structural invariant [frep] (the frontier slots are exactly the
      complete-subtree roots of the leaves so far, by decreasing size);
    - [froot_empty]: the root read off an empty frontier is the
      empty-subtree root [zero_hash d].

    REMAINING (honestly noted, not admitted): the final assembly
    [froot (fbuild leaves) = mroot d leaves] — that the root read off
    the O(depth) frontier equals the batch Merkle root — needs a
    [froot]-vs-[mroot] bridge over [frep] with the level-offset and
    zero-padding bookkeeping.  It is NOT stated here as an axiom.  The
    security-relevant "committed root = batch root of all notes" is
    already proved in [Spec.MerkleTree] ([tree_root_correct]) and
    differentially validated against the production tree; this module
    adds the O(depth)-state structural correctness underneath it. *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Spec Require Import MerkleTree.

Section MerkleFrontier.

  Variable Felt : Type.
  Variable H : Felt -> Felt -> Felt.
  Variable z0 : Felt.

  Notation zh := (zero_hash Felt H z0).
  Notation mr := (mroot Felt H z0).

  (* ============================================================= *)
  (** ** Carry value-correctness                                    *)
  (* ============================================================= *)

  (** Combining two complete equal-size subtree roots gives the parent
      root — the carry step is value-correct. *)
  Lemma mroot_combine : forall lv a b,
    length a = 2 ^ lv ->
    mr (S lv) (a ++ b) = H (mr lv a) (mr lv b).
  Proof.
    intros lv a b Ha. cbn [mroot].
    rewrite firstn_app, skipn_app, Ha, Nat.sub_diag.
    cbn [firstn skipn]. rewrite app_nil_r, firstn_all2 by lia.
    rewrite (skipn_all2 a) by lia. cbn [app]. reflexivity.
  Qed.

  (* ============================================================= *)
  (** ** The frontier and its binary-counter correctness            *)
  (* ============================================================= *)

  Fixpoint fappend (front : list (option Felt)) (cur : Felt)
                   : list (option Felt) :=
    match front with
    | [] => [Some cur]
    | None :: rest => Some cur :: rest
    | Some s :: rest => None :: fappend rest (H s cur)
    end.

  (** Leaf count a frontier represents (sum of [2^lv] over filled
      slots). *)
  Fixpoint fval (lv : nat) (front : list (option Felt)) : nat :=
    match front with
    | [] => 0
    | None :: rest => fval (S lv) rest
    | Some _ :: rest => 2 ^ lv + fval (S lv) rest
    end.

  (** [fappend] is a correct binary counter: appending a height-[lv]
      block increments the value by [2^lv] (with carry). *)
  Lemma fval_fappend : forall front lv cur,
    fval lv (fappend front cur) = fval lv front + 2 ^ lv.
  Proof.
    induction front as [| s rest IH]; intros lv cur; cbn [fappend].
    - cbn [fval]. lia.
    - destruct s as [s |]; cbn [fval].
      + rewrite (IH (S lv) (H s cur)).
        replace (2 ^ S lv) with (2 ^ lv + 2 ^ lv) by (cbn [Nat.pow]; lia). lia.
      + lia.
  Qed.

  (* ============================================================= *)
  (** ** Reading the root off the frontier                          *)
  (* ============================================================= *)

  (** Walk [d] levels from level [lv]: a stored slot is the left
      sibling, an empty slot pairs with the empty-subtree zero. *)
  Fixpoint froot (d : nat) (front : list (option Felt))
                 (lv : nat) (acc : Felt) : Felt :=
    match d with
    | 0 => acc
    | S d' =>
        match front with
        | [] => froot d' [] (S lv) (H acc (zh lv))
        | None :: rest => froot d' rest (S lv) (H acc (zh lv))
        | Some s :: rest => froot d' rest (S lv) (H s acc)
        end
    end.

  (** The empty frontier yields the empty-subtree root. *)
  Lemma froot_empty : forall d lv, froot d [] lv (zh lv) = zh (lv + d).
  Proof.
    induction d as [| d IH]; intros lv; cbn [froot].
    - rewrite Nat.add_0_r. reflexivity.
    - change (H (zh lv) (zh lv)) with (zh (S lv)).
      rewrite (IH (S lv)). f_equal. lia.
  Qed.

  (* ============================================================= *)
  (** ** Structural invariant: the frontier represents the leaves    *)
  (* ============================================================= *)

  (** Pair adjacent nodes (one level up). *)
  Fixpoint pairup (l : list Felt) : list Felt :=
    match l with a :: b :: r => H a b :: pairup r | _ => [] end.

  Lemma pairup_app_even : forall init s cur,
    Nat.Even (length init) ->
    pairup (init ++ s :: cur :: nil) = pairup init ++ H s cur :: nil.
  Proof.
    intros init s cur [k Hk]. revert init Hk.
    induction k as [| k IH]; intros init Hk.
    - destruct init; cbn [length] in Hk; [cbn [app pairup]; reflexivity | lia].
    - destruct init as [| a [| b init']]; cbn [length] in Hk; try lia.
      cbn [app pairup]. f_equal. apply IH. lia.
  Qed.

  (** [frep front nodes]: the frontier represents [nodes] (the current
      level's subtree roots) as a binary counter — filled slots hold
      the complete subtrees, the LSB slot is the last node when the
      count is odd, and pairing adjacent nodes recurses one level up. *)
  Fixpoint frep (front : list (option Felt)) (nodes : list Felt) : Prop :=
    match front with
    | nil => nodes = nil
    | None :: rest => Nat.Even (length nodes) /\ frep rest (pairup nodes)
    | Some s :: rest =>
        exists init, nodes = init ++ s :: nil
                     /\ Nat.Even (length init) /\ frep rest (pairup init)
    end.

  Lemma frep_nil : frep nil nil.
  Proof. cbn. reflexivity. Qed.

  (** Appending a leaf preserves the representation (carry via
      [pairup_app_even]).  So [fappend] correctly maintains, in
      O(depth) state, the complete-subtree roots of all leaves so
      far. *)
  Lemma fappend_preserves_frep : forall front nodes cur,
    frep front nodes -> frep (fappend front cur) (nodes ++ cur :: nil).
  Proof.
    induction front as [| s rest IH]; intros nodes cur Hrep; cbn [fappend].
    - cbn in Hrep. subst nodes. cbn [frep].
      exists nil. cbn [app length pairup].
      split; [reflexivity |]. split; [exists 0; reflexivity | reflexivity].
    - destruct s as [s |]; cbn [frep] in Hrep.
      + destruct Hrep as [init [Hnodes [Hev Hrest]]]. subst nodes. cbn [frep].
        split.
        * rewrite length_app. cbn [length].
          destruct Hev as [k Hk]. rewrite length_app in *. cbn [length] in *.
          exists (S k). lia.
        * rewrite <- app_assoc. cbn [app].
          rewrite (pairup_app_even init s cur Hev).
          apply (IH (pairup init) (H s cur) Hrest).
      + destruct Hrep as [Hev Hrest]. cbn [frep].
        exists nodes. repeat split; [exact Hev | exact Hrest].
  Qed.

  (** Building the frontier from a leaf list (append each leaf). *)
  Definition fbuild (leaves : list Felt) : list (option Felt) :=
    fold_left fappend leaves nil.

  (** The built frontier represents exactly the leaves: O(depth) state
      faithfully tracks the complete-subtree roots of all appended
      leaves. *)
  Theorem fbuild_frep : forall leaves, frep (fbuild leaves) leaves.
  Proof.
    intro leaves. unfold fbuild.
    (* generalize: fold over `rest` starting from a frontier repping `acc` *)
    assert (forall rest acc front,
              frep front acc -> frep (fold_left fappend rest front) (acc ++ rest)).
    { induction rest as [| x xs IH]; intros acc front Hf; cbn [fold_left].
      - rewrite app_nil_r. exact Hf.
      - replace (acc ++ x :: xs) with ((acc ++ x :: nil) ++ xs)
          by (rewrite <- app_assoc; reflexivity).
        apply IH. apply fappend_preserves_frep. exact Hf. }
    specialize (H0 leaves nil nil frep_nil). cbn [app] in H0. exact H0.
  Qed.

End MerkleFrontier.
