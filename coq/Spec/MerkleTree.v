(** * Spec.MerkleTree — the append-only commitment tree

    Models the kernel's commitment Merkle tree
    ([tezos/rollup-kernel/src/lib.rs]: [zero_hashes],
    [simulate_frontier_append]) and proves two real correctness
    properties of the algorithms it uses to compute roots:

    1. [empty_subtree]: the root of an all-empty depth-[h] subtree is
       exactly [zero_hash h] (the kernel's precomputed
       [zero_hashes[h]]).  An off-by-one there would let a prover
       forge membership in empty slots, so this is the correctness of
       the kernel's [zero_hashes] precomputation.

    2. [frontier_first_leaf]: the incremental [simulate_frontier_-
       append] — which stores only O(depth) frontier nodes, never the
       full leaf array — computes, for the first appended leaf, the
       SAME root as the batch definition over the full padded leaf
       list.  This is the append-only-Merkle algorithm (Zcash / the
       Ethereum deposit contract); proving it equals the structural
       batch root is the non-trivial correctness the kernel relies on
       to commit notes without storing the whole tree.

    Parameterized over the node hash [H] (kernel [hash_merkle]) and
    the empty-leaf value [z0] (kernel [ZERO]). *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.

Section MerkleTree.

  Variable Felt : Type.
  Variable H : Felt -> Felt -> Felt.     (* hash_merkle *)
  Variable z0 : Felt.                     (* ZERO (empty leaf) *)

  (** Precomputed empty-subtree roots: kernel [zero_hashes] recurrence. *)
  Fixpoint zero_hash (h : nat) : Felt :=
    match h with
    | 0 => z0
    | S h' => H (zero_hash h') (zero_hash h')
    end.

  (** ** Batch Merkle root: pair-and-hash each level, [depth] times. *)
  Fixpoint build_level (l : list Felt) : list Felt :=
    match l with
    | a :: b :: r => H a b :: build_level r
    | _ => []
    end.

  Fixpoint fold_levels (h : nat) (l : list Felt) : list Felt :=
    match h with
    | 0 => l
    | S h' => fold_levels h' (build_level l)
    end.

  Definition root_of (h : nat) (l : list Felt) : Felt :=
    match fold_levels h l with x :: _ => x | [] => z0 end.

  (* ============================================================= *)
  (** ** Uniform-layer lemmas                                       *)
  (* ============================================================= *)

  Lemma pow2_pos : forall k, 2 ^ k <> 0.
  Proof. intro k. apply Nat.pow_nonzero. lia. Qed.

  (** Pairing a uniform layer halves it. *)
  Lemma build_level_repeat : forall n x,
    build_level (repeat x (2 * n)) = repeat (H x x) n.
  Proof.
    induction n as [| n IH]; intro x; cbn.
    - reflexivity.
    - replace (n + S (n + 0)) with (S (2 * n)) by lia. cbn.
      rewrite IH. reflexivity.
  Qed.

  (** A spine head over a uniform tail. *)
  Lemma build_level_spine : forall n x y,
    build_level (x :: repeat y (2 * n + 1)) = H x y :: repeat (H y y) n.
  Proof.
    intros n x y.
    replace (2 * n + 1) with (S (2 * n)) by lia. cbn [repeat].
    cbn [build_level]. rewrite build_level_repeat. reflexivity.
  Qed.

  (** Iterated self-hash, mirroring [zero_hash]'s recursion exactly so
      no [Nat.iter] direction mismatch arises. *)
  Fixpoint hpow (h : nat) (x : Felt) : Felt :=
    match h with
    | 0 => x
    | S k => H (hpow k x) (hpow k x)
    end.

  Lemma zero_hash_hpow : forall h, zero_hash h = hpow h z0.
  Proof.
    induction h as [| h IH]; cbn [zero_hash hpow]; [reflexivity | rewrite IH; reflexivity].
  Qed.

  (** [hpow] commutes with one [H _ _] level. *)
  Lemma hpow_shift : forall h x, hpow h (H x x) = hpow (S h) x.
  Proof.
    induction h as [| h IH]; intro x; cbn [hpow].
    - reflexivity.
    - rewrite IH. reflexivity.
  Qed.

  Lemma fold_levels_repeat : forall h x,
    fold_levels h (repeat x (2 ^ h)) = [hpow h x].
  Proof.
    induction h as [| h IH]; intro x; cbn [fold_levels hpow].
    - reflexivity.
    - rewrite Nat.pow_succ_r'.
      rewrite build_level_repeat. rewrite IH.
      rewrite hpow_shift. cbn [hpow]. reflexivity.
  Qed.

  (* ============================================================= *)
  (** ** Zero-subtree characterization                              *)
  (* ============================================================= *)

  (** The root of an all-empty depth-[h] subtree equals [zero_hash h]
      — the kernel's precomputed [zero_hashes[h]] is correct. *)
  Theorem empty_subtree : forall h,
    root_of h (repeat z0 (2 ^ h)) = zero_hash h.
  Proof.
    intro h. unfold root_of.
    rewrite fold_levels_repeat. cbn. rewrite zero_hash_hpow. reflexivity.
  Qed.

  (* ============================================================= *)
  (** ** The incremental frontier                                   *)
  (* ============================================================= *)

  (** The left spine: fold a leaf up the left edge, hashing the
      empty-subtree zero on the right at each level. *)
  Fixpoint left_spine (h lv : nat) (cur : Felt) : Felt :=
    match h with
    | 0 => cur
    | S k => left_spine k (S lv) (H cur (zero_hash lv))
    end.

  (** [simulate_frontier_append], modeled: walk the new leaf up [h]
      levels from level [lv]; at each level a left child (even index)
      pairs with the empty-subtree zero, a right child (odd) with the
      stored frontier node [front lv]. *)
  Fixpoint frontier_root (h lv idx : nat) (front : nat -> Felt)
                         (cur : Felt) : Felt :=
    match h with
    | 0 => cur
    | S k =>
        if Nat.even idx
        then frontier_root k (S lv) (idx / 2) front (H cur (zero_hash lv))
        else frontier_root k (S lv) (idx / 2) front (H (front lv) cur)
    end.

  (** At index 0 (the first leaf, even at every level) the frontier
      walk is exactly the left spine — it never reads [front]. *)
  Lemma frontier_root_zero : forall h lv front cur,
    frontier_root h lv 0 front cur = left_spine h lv cur.
  Proof.
    induction h as [| h IH]; intros lv front cur; cbn.
    - reflexivity.
    - apply IH.
  Qed.

  (** The batch root of one leaf followed by empty padding is the left
      spine. *)
  Lemma fold_levels_spine : forall m lv x,
    fold_levels m (x :: repeat (zero_hash lv) (2 ^ m - 1)) = [left_spine m lv x].
  Proof.
    induction m as [| m IH]; intros lv x; cbn [fold_levels left_spine].
    - cbn. reflexivity.
    - (* rewrite the layer as a spine head over a uniform tail *)
      assert (Hp : 2 ^ S m - 1 = 2 * (2 ^ m - 1) + 1).
      { rewrite Nat.pow_succ_r'. pose proof (pow2_pos m). lia. }
      rewrite Hp.
      rewrite build_level_spine.
      change (H (zero_hash lv) (zero_hash lv)) with (zero_hash (S lv)).
      rewrite IH. reflexivity.
  Qed.

  (** THE THEOREM: appending the FIRST leaf [cm] (into an empty tree,
      index 0) via the incremental frontier computes exactly the batch
      Merkle root of [[cm, z0, z0, ...]] — the kernel's
      [simulate_frontier_append] is correct for the first insertion,
      using only O(depth) state. *)
  Theorem frontier_first_leaf : forall depth front cm,
    frontier_root depth 0 0 front cm
    = root_of depth (cm :: repeat z0 (2 ^ depth - 1)).
  Proof.
    intros depth front cm.
    rewrite frontier_root_zero.
    unfold root_of.
    change z0 with (zero_hash 0) at 1.
    rewrite fold_levels_spine. reflexivity.
  Qed.

  (* ============================================================= *)
  (** ** General frontier correctness (arbitrary index)             *)
  (* ============================================================= *)

  (** A recursive (top-down) batch root, splitting each subtree into
      left and right halves.  Padding is implicit: [firstn]/[skipn]
      of a short list give short lists, and [mroot] of [[]] is the
      empty-subtree root (proved below). *)
  Fixpoint mroot (d : nat) (leaves : list Felt) : Felt :=
    match d with
    | 0 => match leaves with x :: _ => x | [] => z0 end
    | S d' => H (mroot d' (firstn (2 ^ d') leaves))
                (mroot d' (skipn (2 ^ d') leaves))
    end.

  (** Empty tree: [mroot d [] = zero_hash d] (the recursive batch root
      agrees with the precomputed empty-subtree root). *)
  Lemma mroot_nil : forall d, mroot d [] = zero_hash d.
  Proof.
    induction d as [| d IH]; cbn [mroot zero_hash].
    - reflexivity.
    - rewrite firstn_nil, skipn_nil. rewrite IH. reflexivity.
  Qed.

  (** The append-only insertion, top-down: [tdfront d pre cm] inserts
      [cm] at position [length pre] into a depth-[d] tree whose first
      [length pre] leaves are [pre].  When [cm] lands in the left half
      the right half is empty ([zero_hash d']); when it lands in the
      right half the left half is COMPLETE and its root
      [mroot d' (firstn (2^d') pre)] is exactly what the kernel stores
      as [branches[d']].  So this is a faithful model of the frontier
      append, with the stored left-subtree roots made explicit. *)
  Fixpoint tdfront (d : nat) (pre : list Felt) (cm : Felt) : Felt :=
    match d with
    | 0 => cm
    | S d' =>
        if length pre <? 2 ^ d'
        then H (tdfront d' pre cm) (zero_hash d')
        else H (mroot d' (firstn (2 ^ d') pre)) (tdfront d' (skipn (2 ^ d') pre) cm)
    end.

  (** THE GENERAL THEOREM: appending [cm] at ANY index ([length pre],
      with the tree not yet full) via the frontier computes exactly
      the batch Merkle root of the leaves so far ([pre ++ [cm]]).
      This is the full append-only-Merkle correctness — every
      insertion, not just the first — with O(depth) stored state. *)
  Theorem tdfront_correct : forall d pre cm,
    length pre < 2 ^ d ->
    tdfront d pre cm = mroot d (pre ++ [cm]).
  Proof.
    induction d as [| d IH]; intros pre cm Hlen; cbn [tdfront mroot].
    - (* d = 0: pre must be empty *)
      cbn in Hlen. assert (pre = []) by (destruct pre; [reflexivity | cbn in Hlen; lia]).
      subst pre. reflexivity.
    - destruct (Nat.ltb_spec (length pre) (2 ^ d)) as [Hlt | Hge].
      + (* cm lands in the left half; right half empty *)
        rewrite IH by exact Hlt.
        assert (Hle : length (pre ++ [cm]) <= 2 ^ d).
        { rewrite length_app. cbn. lia. }
        rewrite (firstn_all2 _ Hle).
        rewrite (skipn_all2 _ Hle).
        rewrite mroot_nil. reflexivity.
      + (* cm lands in the right half; left half complete *)
        assert (Hlenr : length (skipn (2 ^ d) pre) < 2 ^ d).
        { rewrite length_skipn. cbn [Nat.pow] in Hlen. lia. }
        rewrite IH by exact Hlenr.
        rewrite firstn_app, skipn_app.
        replace (2 ^ d - length pre) with 0 by lia. cbn [firstn skipn].
        rewrite app_nil_r. reflexivity.
  Qed.

  (** [frontier_first_leaf] is the [pre = []] instance of this. *)
  Corollary tdfront_first : forall d cm,
    0 < 2 ^ d -> tdfront d [] cm = mroot d [cm].
  Proof. intros d cm Hpos. exact (tdfront_correct d [] cm Hpos). Qed.

  (* ============================================================= *)
  (** ** Whole-tree correctness (the full append sequence)          *)
  (* ============================================================= *)

  (** The root of the commitment tree after appending ALL of [leaves],
      one at a time, via the frontier.  (Appending the last leaf onto
      the prefix of all the others; the empty tree is [zero_hash d].) *)
  Definition tree_root (d : nat) (leaves : list Felt) : Felt :=
    match leaves with
    | [] => zero_hash d
    | _ :: _ => tdfront d (removelast leaves) (last leaves z0)
    end.

  (** Lifts [tdfront_correct] (single append, any index) to the whole
      sequence: the root the kernel commits after appending every note
      equals the batch Merkle root of all the notes.  This is what a
      membership proof trusts — the committed root faithfully reflects
      exactly the set of committed notes. *)
  Theorem tree_root_correct : forall d leaves,
    length leaves <= 2 ^ d ->
    tree_root d leaves = mroot d leaves.
  Proof.
    intros d leaves Hlen. unfold tree_root.
    destruct leaves as [| x xs] eqn:E.
    - symmetry. apply mroot_nil.
    - set (l := x :: xs) in *.
      assert (Hne : l <> []) by (unfold l; discriminate).
      pose proof (app_removelast_last z0 Hne) as Hsplit.
      assert (Hl1 : length l = length (removelast l) + 1).
      { transitivity (length (removelast l ++ [last l z0])).
        - rewrite <- Hsplit. reflexivity.
        - rewrite length_app. cbn [length]. lia. }
      assert (Hlenrem : length (removelast l) < 2 ^ d) by lia.
      rewrite (tdfront_correct d (removelast l) (last l z0) Hlenrem).
      rewrite <- Hsplit. reflexivity.
  Qed.

  (* ============================================================= *)
  (** ** Bottom-up = top-down batch root                            *)
  (* ============================================================= *)

  (** [root_of] (bottom-up: pair adjacent, fold up) and [mroot]
      (top-down: recursive split) are TWO definitions of the batch
      Merkle root.  This proves they AGREE on full trees — a
      fundamental consistency the file relied on implicitly
      ([empty_subtree] is about [root_of]; [tdfront_correct] about
      [mroot]). *)

  Lemma build_level_length : forall n l,
    length l = 2 * n -> length (build_level l) = n.
  Proof.
    induction n as [| n IH]; intros l Hlen.
    - destruct l; [reflexivity | cbn [length] in Hlen; lia].
    - destruct l as [| a [| b r]]; cbn [length] in Hlen; try lia.
      cbn [build_level length]. f_equal. apply IH. lia.
  Qed.

  Lemma build_level_firstn : forall n l,
    build_level (firstn (2 * n) l) = firstn n (build_level l).
  Proof.
    induction n as [| n IH]; intros l.
    - cbn [firstn]. destruct l; reflexivity.
    - destruct l as [| a [| b r]].
      + cbn [firstn]. reflexivity.
      + cbn [firstn build_level]. replace (2 * S n) with (S (S (2*n))) by lia.
        cbn [firstn build_level]. reflexivity.
      + replace (2 * S n) with (S (S (2 * n))) by lia.
        cbn [firstn build_level]. rewrite IH. reflexivity.
  Qed.

  Lemma build_level_skipn : forall n l,
    build_level (skipn (2 * n) l) = skipn n (build_level l).
  Proof.
    induction n as [| n IH]; intros l.
    - reflexivity.
    - destruct l as [| a [| b r]].
      + reflexivity.
      + cbn [build_level]. replace (2 * S n) with (S (S (2*n))) by lia.
        cbn [skipn]. destruct (2*n); reflexivity.
      + replace (2 * S n) with (S (S (2 * n))) by lia.
        cbn [skipn build_level]. rewrite IH. reflexivity.
  Qed.

  (** Pairing the bottom level and taking the depth-[k] root equals the
      depth-[S k] root. *)
  Lemma build_level_mroot : forall k l,
    length l = 2 ^ (S k) -> mroot k (build_level l) = mroot (S k) l.
  Proof.
    induction k as [| k IH]; intros l Hlen.
    - destruct l as [| a [| b [| c r]]]; cbn in Hlen; try lia.
      cbn [build_level mroot firstn skipn]. reflexivity.
    - cbn [mroot].
      assert (Hlen2 : length l = 2 * 2 ^ S k)
        by (rewrite Hlen; apply Nat.pow_succ_r').
      assert (Hf : firstn (2 ^ k) (build_level l) = build_level (firstn (2 ^ S k) l)).
      { rewrite (Nat.pow_succ_r' 2 k). rewrite build_level_firstn. reflexivity. }
      assert (Hs : skipn (2 ^ k) (build_level l) = build_level (skipn (2 ^ S k) l)).
      { rewrite (Nat.pow_succ_r' 2 k). rewrite build_level_skipn. reflexivity. }
      rewrite Hf, Hs.
      rewrite (IH (firstn (2 ^ S k) l)) by (rewrite length_firstn; lia).
      rewrite (IH (skipn (2 ^ S k) l)) by (rewrite length_skipn; lia).
      reflexivity.
  Qed.

  Theorem root_of_mroot : forall d l,
    length l = 2 ^ d -> root_of d l = mroot d l.
  Proof.
    induction d as [| d IH]; intros l Hlen.
    - cbn in Hlen. destruct l as [| a [| b r]]; cbn [length] in Hlen; try lia.
      cbn [root_of fold_levels mroot]. reflexivity.
    - unfold root_of in *. cbn [fold_levels].
      assert (Hbl : length (build_level l) = 2 ^ d).
      { apply build_level_length. rewrite Hlen. apply Nat.pow_succ_r'. }
      rewrite (IH (build_level l) Hbl).
      apply build_level_mroot. exact Hlen.
  Qed.

  (* ============================================================= *)
  (** ** Zero-padding invariance                                    *)
  (* ============================================================= *)

  (** The committed root depends ONLY on the actual leaves, not on the
      zero-padding.  Appending the padding value [z0] in the padding
      region leaves the root unchanged — so the kernel's fixed-depth
      tree, which treats empty positions as [z0], commits exactly the
      notes regardless of how many empty slots remain. *)
  Lemma mroot_app_z0 : forall d l,
    length l < 2 ^ d -> mroot d (l ++ z0 :: nil) = mroot d l.
  Proof.
    induction d as [| d IH]; intros l Hlen.
    - cbn in Hlen. assert (l = nil) by (destruct l; [reflexivity | cbn in Hlen; lia]).
      subst l. cbn [mroot app]. reflexivity.
    - cbn [mroot].
      destruct (Nat.ltb_spec (length l) (2 ^ d)) as [Hlt | Hge].
      + assert (Hle : length (l ++ z0 :: nil) <= 2 ^ d)
          by (rewrite length_app; cbn [length]; lia).
        rewrite (firstn_all2 _ Hle), (skipn_all2 _ Hle).
        rewrite (firstn_all2 l) by lia. rewrite (skipn_all2 l) by lia.
        rewrite IH by exact Hlt. reflexivity.
      + rewrite firstn_app, skipn_app.
        replace (2 ^ d - length l) with 0 by lia. cbn [firstn skipn app].
        rewrite app_nil_r.
        assert (Hrlen : length (skipn (2 ^ d) l) < 2 ^ d).
        { rewrite length_skipn. cbn [Nat.pow] in Hlen. lia. }
        rewrite (IH (skipn (2 ^ d) l) Hrlen). reflexivity.
  Qed.

  Lemma mroot_app_zeros : forall d k l,
    length l + k <= 2 ^ d -> mroot d (l ++ repeat z0 k) = mroot d l.
  Proof.
    induction k as [| k IH]; intros l Hlen.
    - rewrite app_nil_r. reflexivity.
    - cbn [repeat].
      replace (l ++ z0 :: repeat z0 k) with ((l ++ z0 :: nil) ++ repeat z0 k)
        by (rewrite <- app_assoc; reflexivity).
      rewrite (IH (l ++ z0 :: nil))
        by (rewrite length_app; cbn [length]; lia).
      apply mroot_app_z0. lia.
  Qed.

End MerkleTree.
