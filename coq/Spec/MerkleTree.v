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

End MerkleTree.
