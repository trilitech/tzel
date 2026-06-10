(** * Spec.MerkleBridge — the per-level frontier→mroot bridge

    The kernel's O(depth) incremental frontier ([Spec.MerkleFrontier])
    reads the root off the [branches[]] state level by level.  This
    module proves the mathematical heart of why that O(depth) read-off
    is correct: the [bridge] lemma, which relates ONE level-step of the
    bottom-up combination to the top-down [mroot].

    The remaining assembly — folding [bridge] over the whole frontier
    to get [froot (fbuild leaves) = mroot d leaves] — is the
    [froot_correct] induction (a separate step).  These lemmas are the
    genuinely-hard ingredients it routes through.

    Built on [Spec.MerkleTree]'s [build_level_mroot] (full-tree
    bottom-up = top-down), [mroot_app_zeros] (padding invariance), and
    [mroot_base_irrelevant] (full-tree base independence). *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Spec Require Import MerkleTree.

Section MerkleBridge.

  Variable Felt : Type.
  Variable Hh : Felt -> Felt -> Felt.
  Variable z0 : Felt.
  Notation zh := (zero_hash Felt Hh z0).
  Notation bl := (build_level Felt Hh).

  (** [build_level] distributes over an even-length prefix. *)
  Lemma build_level_app_even : forall X Y,
    Nat.Even (length X) -> bl (X ++ Y) = bl X ++ bl Y.
  Proof.
    intros X Y [k Hk]. revert X Hk.
    induction k as [| k IH]; intros X Hk.
    - destruct X; [reflexivity | cbn [length] in Hk; lia].
    - destruct X as [| a [| b X']]; cbn [length] in Hk; try lia.
      cbn [app build_level]. f_equal. apply IH. lia.
  Qed.

  (** [build_level] of a run of [zh lv] yields a run of [zh (S lv)]. *)
  Lemma bl_rep : forall lv j, bl (repeat (zh lv) (2 * j)) = repeat (zh (S lv)) j.
  Proof.
    intros lv j. rewrite (build_level_repeat Felt Hh j (zh lv)).
    change (Hh (zh lv) (zh lv)) with (zh (S lv)). reflexivity.
  Qed.

  Lemma bl_cons_rep : forall lv w j,
    bl (w :: repeat (zh lv) (2 * j + 1)) = Hh w (zh lv) :: repeat (zh (S lv)) j.
  Proof.
    intros lv w j. replace (2 * j + 1) with (S (2 * j)) by lia.
    cbn [repeat build_level]. f_equal. apply bl_rep.
  Qed.

  (** Pair-and-pad: pair adjacent, padding an odd tail with [zh lv]. *)
  Definition ppair (lv : nat) (X : list Felt) : list Felt :=
    bl (X ++ (if Nat.odd (length X) then zh lv :: nil else nil)).

  (** [build_level] of [X] followed by [zh lv] padding splits into the
      pair-and-padded [X] then a run of [zh (S lv)] — when the total
      length is even (which holds when padding [X] to a full level). *)
  Lemma build_level_pad : forall lv n X m,
    length X = n -> Nat.Even (n + m) ->
    exists k, bl (X ++ repeat (zh lv) m) = ppair lv X ++ repeat (zh (S lv)) k.
  Proof.
    intros lv n. induction n as [n IH] using lt_wf_ind.
    intros X m Hn Hev. unfold ppair.
    destruct X as [| a [| b X'']].
    - cbn [length] in Hn. subst n. cbn [Nat.odd app] in *.
      assert (Hm : Nat.Even m) by (cbn in Hev; exact Hev).
      destruct Hm as [j Hj]. subst m. rewrite bl_rep.
      exists j. cbn [build_level app]. reflexivity.
    - cbn [length] in Hn. subst n.
      assert (Hm : Nat.Odd m).
      { destruct Hev as [t Ht]. exists (t - 1). lia. }
      destruct Hm as [j Hj]. subst m.
      cbn [Nat.odd app]. rewrite bl_cons_rep.
      exists j. cbn [build_level app]. reflexivity.
    - cbn [length] in Hn.
      assert (Hlt : length X'' < n) by lia.
      assert (Hev'' : Nat.Even (length X'' + m))
        by (rewrite <- Hn in Hev; destruct Hev as [t Ht]; exists (t - 1); lia).
      destruct (IH (length X'') Hlt X'' m eq_refl Hev'') as [k Hk].
      unfold ppair in Hk.
      assert (Hparsame : Nat.odd (length (a :: b :: X'')) = Nat.odd (length X'')).
      { cbn [length]. rewrite Nat.odd_succ, Nat.even_succ. reflexivity. }
      exists k.
      rewrite Hparsame.
      cbn [app build_level].
      rewrite Hk. reflexivity.
  Qed.

  (** THE BRIDGE: combining a partial node list at level [lv] one step
      (mroot at base [zh lv], one level up) equals combining the
      pair-and-padded list at level [S lv].  This is why the O(depth)
      frontier read-off is correct: each [branches[]] level corresponds
      to exactly one [mroot] level. *)
  Lemma bridge : forall lv d' X,
    length X <= 2 ^ (S d') ->
    mroot Felt Hh (zh lv) (S d') X = mroot Felt Hh (zh (S lv)) d' (ppair lv X).
  Proof.
    intros lv d' X HleX.
    remember (2 ^ (S d') - length X) as m eqn:Hmdef.
    assert (Hpow : 2 ^ (S d') = 2 * 2 ^ d') by (rewrite Nat.pow_succ_r'; reflexivity).
    assert (HlenL : length (X ++ repeat (zh lv) m) = 2 ^ (S d')).
    { rewrite length_app, repeat_length. lia. }
    assert (Heven : Nat.Even (length X + m)).
    { exists (2 ^ d'). lia. }
    rewrite <- (mroot_app_zeros Felt Hh (zh lv) (S d') m X) by lia.
    rewrite <- (build_level_mroot Felt Hh (zh lv) d' (X ++ repeat (zh lv) m) HlenL).
    assert (HblL : length (bl (X ++ repeat (zh lv) m)) = 2 ^ d').
    { apply (build_level_length Felt Hh (2 ^ d')). rewrite HlenL.
      rewrite Nat.pow_succ_r'. reflexivity. }
    rewrite (mroot_base_irrelevant Felt Hh (zh lv) (zh (S lv)) d' _ HblL).
    destruct (build_level_pad lv (length X) X m eq_refl Heven) as [k Hk].
    rewrite Hk.
    rewrite (mroot_app_zeros Felt Hh (zh (S lv)) d' k (ppair lv X)).
    + reflexivity.
    + assert (length (ppair lv X ++ repeat (zh (S lv)) k) = 2 ^ d')
        by (rewrite <- Hk; exact HblL).
      rewrite length_app, repeat_length in *. lia.
  Qed.

End MerkleBridge.
