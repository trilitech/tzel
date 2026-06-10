(** * Spec.MerkleFrontierCorrect — the O(depth) frontier read-off is correct

    THE CAPSTONE of the incremental-Merkle work.  Proves that reading
    the root off the kernel's O(depth) frontier state
    ([Spec.MerkleFrontier.froot] over [fbuild]) equals the true batch
    Merkle root of all the appended notes — so the kernel commits the
    correct commitment-tree root using only O(depth) storage, never the
    full leaf array.

    [froot_correct] (zero admits) is the heart: folding the per-level
    [Spec.MerkleBridge.bridge] over the whole frontier, using the
    structural representation [Spec.MerkleFrontier.fbuild_frep] and the
    [ppair] computations.  [froot_fbuild_eq] is the headline:
    [froot d (fbuild leaves) 0 z0 = mroot d leaves].

    The depth bound [length (fbuild leaves) <= d] is taken as an
    explicit precondition (a true structural fact: the binary-counter
    frontier of [< 2^d] notes has at most [d] slots).  Everything else
    is proved. *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Spec Require Import MerkleTree MerkleFrontier MerkleBridge.

Section FC.
  Variable Felt : Type.
  Variable Hh : Felt -> Felt -> Felt.
  Variable z0 : Felt.
  Notation zh := (zero_hash Felt Hh z0).
  Notation bl := (build_level Felt Hh).
  Notation pp := (ppair Felt Hh z0).
  Notation pu := (pairup Felt Hh).
  Notation fr := (froot Felt Hh z0).
  Notation mrb := (mroot Felt Hh).

  (** MerkleFrontier's pairup is MerkleTree's build_level. *)
  Lemma pairup_bl : forall l, pu l = bl l.
  Proof. intro l; reflexivity. Qed.

  (** ppair of an even list + one element: pad the odd tail. *)
  Lemma ppair_even_snoc : forall lv nodes acc,
    Nat.Even (length nodes) ->
    pp lv (nodes ++ acc :: nil) = bl nodes ++ Hh acc (zh lv) :: nil.
  Proof.
    intros lv nodes acc Hev. unfold ppair.
    assert (Hodd : Nat.odd (length (nodes ++ acc :: nil)) = true).
    { rewrite length_app. cbn [length]. rewrite Nat.add_1_r, Nat.odd_succ.
      apply Nat.even_spec in Hev. exact Hev. }
    rewrite Hodd.
    replace (if true then zh lv :: nil else nil) with (zh lv :: nil) by reflexivity.
    rewrite <- app_assoc. cbn [app].
    rewrite (build_level_app_even Felt Hh nodes (acc :: zh lv :: nil) Hev).
    cbn [build_level]. reflexivity.
  Qed.

  (** ppair of an even list + two elements: no pad needed. *)
  Lemma ppair_even2 : forall lv init s acc,
    Nat.Even (length init) ->
    pp lv ((init ++ s :: nil) ++ acc :: nil) = bl init ++ Hh s acc :: nil.
  Proof.
    intros lv init s acc Hev. unfold ppair.
    assert (Hev2 : Nat.Even (length ((init ++ s :: nil) ++ acc :: nil))).
    { rewrite !length_app. cbn [length]. destruct Hev as [k Hk]. exists (S k). lia. }
    assert (Hodd : Nat.odd (length ((init ++ s :: nil) ++ acc :: nil)) = false).
    { apply Nat.even_spec in Hev2. rewrite <- Nat.negb_odd in Hev2.
      destruct (Nat.odd _); [discriminate Hev2 | reflexivity]. }
    rewrite Hodd.
    replace (if false then zh lv :: nil else nil) with (@nil Felt) by reflexivity.
    rewrite app_nil_r, <- app_assoc. cbn [app].
    rewrite (build_level_app_even Felt Hh init (s :: acc :: nil) Hev).
    cbn [build_level]. reflexivity.
  Qed.

  (** Reading the root off an empty frontier = mroot of [acc]. *)
  Lemma froot_nil_eq : forall d lv acc,
    fr d nil lv acc = mrb (zh lv) d (acc :: nil).
  Proof.
    induction d as [| d IH]; intros lv acc; cbn [froot].
    - reflexivity.
    - rewrite (IH (S lv) (Hh acc (zh lv))).
      rewrite (bridge Felt Hh z0 lv d (acc :: nil))
        by (assert (2 ^ S d <> 0) by (apply Nat.pow_nonzero; lia); cbn [length]; lia).
      f_equal.
  Qed.

  (** Reading the root off the frontier [front] (representing [nodes])
      equals [mroot] of the nodes with [acc] appended (the empty next
      position) at base [zh lv]. *)
  Lemma froot_correct : forall front d nodes lv acc,
    frep Felt Hh front nodes ->
    length front <= d ->
    length (nodes ++ acc :: nil) <= 2 ^ d ->
    fr d front lv acc = mrb (zh lv) d (nodes ++ acc :: nil).
  Proof.
    induction front as [| slot rest IH]; intros d nodes lv acc Hrep Hfront Hlen.
    - cbn [frep] in Hrep. subst nodes. cbn [app] in *.
      apply froot_nil_eq.
    - destruct d as [| d']; [cbn [length] in Hfront; lia |].
      cbn [length] in Hfront. assert (Hrest : length rest <= d') by lia.
      assert (Hpow : 2 ^ S d' = 2 * 2 ^ d') by (apply Nat.pow_succ_r').
      destruct slot as [s |]; cbn [frep] in Hrep.
      + (* Some s *)
        destruct Hrep as [init [Hnodes [Hevinit Hrestrep]]]. subst nodes.
        pose proof Hevinit as Hev2. destruct Hev2 as [k Hk].
        cbn [froot].
        assert (HblI : length (build_level Felt Hh init) = k)
          by (apply (build_level_length Felt Hh k); exact Hk).
        rewrite (IH d' (pairup Felt Hh init) (S lv) (Hh s acc) Hrestrep Hrest).
        * rewrite (bridge Felt Hh z0 lv d' ((init ++ s :: nil) ++ acc :: nil))
            by (rewrite !length_app in *; cbn [length] in *; lia).
          rewrite (ppair_even2 lv init s acc Hevinit).
          rewrite (pairup_bl init). reflexivity.
        * rewrite length_app, pairup_bl, HblI. cbn [length].
          rewrite !length_app in Hlen. cbn [length] in Hlen. lia.
      + (* None *)
        destruct Hrep as [Hevnodes Hrestrep]. cbn [froot].
        pose proof Hevnodes as Hev2. destruct Hev2 as [k Hk].
        assert (HblN : length (build_level Felt Hh nodes) = k)
          by (apply (build_level_length Felt Hh k); exact Hk).
        rewrite (IH d' (pairup Felt Hh nodes) (S lv) (Hh acc (zh lv)) Hrestrep Hrest).
        * rewrite (bridge Felt Hh z0 lv d' (nodes ++ acc :: nil))
            by (rewrite length_app in *; cbn [length] in *; lia).
          rewrite (ppair_even_snoc lv nodes acc Hevnodes).
          rewrite (pairup_bl nodes). reflexivity.
        * rewrite length_app, pairup_bl, HblN. cbn [length].
          rewrite length_app in Hlen. cbn [length] in Hlen. lia.
  Qed.

  (** THE CAPSTONE: the O(depth) frontier read-off equals the batch
      Merkle root.  [fbuild leaves] is the frontier after appending all
      the notes; reading its root (next position empty) yields exactly
      [mroot d leaves] — so the kernel commits the true Merkle root of
      all notes using only O(depth) state. *)
  Theorem froot_fbuild_eq : forall d leaves,
    length leaves < 2 ^ d ->
    length (fbuild Felt Hh leaves) <= d ->
    fr d (fbuild Felt Hh leaves) 0 z0 = mrb z0 d leaves.
  Proof.
    intros d leaves Hlen Hfront.
    rewrite (froot_correct (fbuild Felt Hh leaves) d leaves 0 z0
               (fbuild_frep Felt Hh leaves) Hfront
               ltac:(rewrite length_app; cbn [length]; lia)).
    change (zh 0) with z0. apply mroot_app_z0. exact Hlen.
  Qed.


End FC.
