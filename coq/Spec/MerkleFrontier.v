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

    The final assembly [froot (fbuild leaves) = mroot d leaves] — that
    the root read off the O(depth) frontier equals the batch Merkle
    root — is now COMPLETE in [Spec.MerkleFrontierCorrect]
    ([froot_fbuild_eq]), built on the per-level bridge in
    [Spec.MerkleBridge].  This module also proves the depth bound
    [fbuild_length_bound] (a frontier of < 2^d notes has at most d
    slots), which discharges the last side condition, so the capstone
    needs only [length leaves < 2^d]. *)

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

(* ================================================================ *)
(** ** Frontier depth bound: a frontier of < 2^d notes fits in d slots *)
(* ================================================================ *)

Section FLen.
  Variable Felt : Type.
  Variable Hh : Felt -> Felt -> Felt.
  Notation fa := (fappend Felt Hh).
  Notation fv := (fval Felt).

  (** A Some slot at the end contributes its level's weight. *)
  Lemma fval_snoc_some : forall l lv s,
    fv lv (l ++ Some s :: nil) = fv lv l + 2 ^ (lv + length l).
  Proof.
    induction l as [| slot rest IH]; intros lv s; cbn [app fval length].
    - replace (lv + 0) with lv by lia. lia.
    - destruct slot as [s' |]; cbn [fval].
      + rewrite (IH (S lv) s).
        replace (S lv + length rest) with (lv + S (length rest)) by lia. lia.
      + rewrite (IH (S lv) s).
        replace (S lv + length rest) with (lv + S (length rest)) by lia. lia.
  Qed.

  (** Well-formed: empty, or the last slot is Some (no trailing None).
      This is exactly the shape [fappend] / [fbuild] produce. *)
  Definition wf (front : list (option Felt)) : Prop :=
    front = nil \/ exists init s, front = init ++ Some s :: nil.

  Lemma fappend_nonempty : forall front x, fa front x <> nil.
  Proof.
    intros [| s rest] x; cbn [fappend]; [discriminate |].
    destruct s; discriminate.
  Qed.

  Lemma wf_cons_some : forall s rest, wf (Some s :: rest) -> wf rest.
  Proof.
    intros s rest [Hnil | [init [s' Heq]]]; [discriminate |].
    destruct init as [| a init'].
    - cbn in Heq. injection Heq as _ ->. left. reflexivity.
    - cbn in Heq. injection Heq as _ Hrest. right. exists init', s'. exact Hrest.
  Qed.

  Lemma fappend_wf : forall front x, wf front -> wf (fa front x).
  Proof.
    induction front as [| slot rest IH]; intros x Hwf; cbn [fappend].
    - right. exists nil, x. reflexivity.
    - destruct slot as [s |].
      + (* Some s: None :: fa rest (H s x) *)
        assert (Hwfrest : wf rest) by (apply (wf_cons_some s); exact Hwf).
        specialize (IH (Hh s x) Hwfrest).
        destruct IH as [Hnil | [init [s' Heq]]].
        * exfalso. apply (fappend_nonempty rest (Hh s x)). exact Hnil.
        * right. exists (None :: init), s'. cbn [app]. rewrite Heq. reflexivity.
      + (* None: Some x :: rest *)
        destruct Hwf as [Hnil | [init [s' Heq]]]; [discriminate |].
        right.
        destruct init as [| a init'].
        * cbn in Heq. injection Heq as Habs _. discriminate Habs.
        * cbn in Heq. injection Heq as _ Hr.
          exists (Some x :: init'), s'. cbn [app]. rewrite Hr. reflexivity.
  Qed.

End FLen.

Section FLen2.
  Variable Felt : Type.
  Variable Hh : Felt -> Felt -> Felt.

  Lemma fbuild_wf : forall leaves, wf Felt (fbuild Felt Hh leaves).
  Proof.
    intro leaves. unfold fbuild.
    assert (forall l front, wf Felt front -> wf Felt (fold_left (fappend Felt Hh) l front)).
    { induction l as [| x xs IH]; intros front Hwf; cbn [fold_left].
      - exact Hwf.
      - apply IH. apply fappend_wf. exact Hwf. }
    apply H. left. reflexivity.
  Qed.

  Lemma fval_fbuild : forall leaves, fval Felt 0 (fbuild Felt Hh leaves) = length leaves.
  Proof.
    intro leaves. unfold fbuild.
    assert (forall l front,
              fval Felt 0 (fold_left (fappend Felt Hh) l front)
              = fval Felt 0 front + length l).
    { induction l as [| x xs IH]; intros front; cbn [fold_left length].
      - lia.
      - rewrite IH. rewrite (fval_fappend Felt Hh front 0 x). cbn [Nat.pow]. lia. }
    rewrite H. cbn [fval length]. reflexivity.
  Qed.

  (** A well-formed nonempty frontier has fval at least the weight of
      its top (last) Some slot. *)
  Lemma wf_fval_lower : forall front,
    wf Felt front -> front <> nil ->
    2 ^ (length front - 1) <= fval Felt 0 front.
  Proof.
    intros front Hwf Hne. destruct Hwf as [Hnil | [init [s Heq]]]; [contradiction |].
    subst front. rewrite (fval_snoc_some Felt init 0 s).
    rewrite length_app. cbn [length].
    replace (length init + 1 - 1) with (length init) by lia.
    cbn [Nat.add]. lia.
  Qed.

  (** THE BOUND: a binary-counter frontier of [< 2^d] notes has at
      most [d] slots. *)
  Lemma fbuild_length_bound : forall d leaves,
    length leaves < 2 ^ d -> length (fbuild Felt Hh leaves) <= d.
  Proof.
    intros d leaves Hlen.
    destruct (fbuild Felt Hh leaves) as [| slot rest] eqn:E.
    - cbn [length]. lia.
    - pose proof (wf_fval_lower (slot :: rest)) as Hlow.
      rewrite <- E in Hlow.
      specialize (Hlow (fbuild_wf leaves) ltac:(rewrite E; discriminate)).
      rewrite (fval_fbuild leaves) in Hlow.
      (* 2^(length(fbuild)-1) <= length leaves < 2^d *)
      assert (Hlt : 2 ^ (length (fbuild Felt Hh leaves) - 1) < 2 ^ d) by lia.
      rewrite E in Hlt. cbn [length] in Hlt |- *.
      (* 2^(S(length rest) - 1) < 2^d -> S(length rest) <= d *)
      assert (Hexp : length rest < d).
      { destruct (le_lt_dec d (length rest)) as [Hge | Hlt2]; [| exact Hlt2].
        exfalso. assert (2 ^ d <= 2 ^ (S (length rest) - 1)).
        { apply Nat.pow_le_mono_r; [lia | lia]. }
        lia. }
      lia.
  Qed.

End FLen2.

