(** * Spec.Merkle — abstract Merkle path verification

    Source: whitepaper notes on the commitment tree (depth 48) and
    the auth tree (depth 16); standard binary hash-tree mechanics.

    Two variants:

    - [merkle_root]: uniform hash at every level.  Models the
      commitment tree where each internal node is [H(left, right)]
      with a fixed personalized IV.

    - [auth_root]: level- and position-indexed hash.  Models the
      XMSS auth tree where each internal node carries an ADRS
      encoding the level and node index.

    Key structural lemma: [merkle_root_app] — path composition.
    Walking two sub-paths in sequence equals walking their
    concatenation, the Merkle analogue of [Spec.Wots.iter_compose].
*)

From Stdlib Require Import List Bool Arith.
From Common Require Import Felt.
From Spec Require Import Hashes.

(* ================================================================ *)
(** ** Uniform-hash Merkle path (commitment tree)                    *)
(* ================================================================ *)

Section MerkleVerify.

  (** Abstract 2-input hash for internal nodes. *)
  Variable H : Felt -> Felt -> Felt.

  (** One level of path verification.  [bit = false] means the
      current node is the left child; [bit = true] means right. *)
  Definition merkle_step (bit : bool) (current sibling : Felt) : Felt :=
    if bit then H sibling current else H current sibling.

  (** Walk the full authentication path from leaf to root.
      [bits] is the leaf position in LSB-first bit order;
      [siblings] is the authentication path (one sibling per level).
      When [length bits = length siblings = depth], this computes the
      Merkle root of the tree containing [leaf] at the position
      encoded by [bits]. *)
  Fixpoint merkle_root (bits : list bool) (siblings : list Felt)
                        (leaf : Felt) : Felt :=
    match bits, siblings with
    | b :: bs, s :: ss => merkle_root bs ss (merkle_step b leaf s)
    | _, _ => leaf
    end.

  (** Base case: empty path returns the leaf unchanged. *)
  Lemma merkle_root_nil (leaf : Felt) :
    merkle_root nil nil leaf = leaf.
  Proof. reflexivity. Qed.

  (** One-step unfolding. *)
  Lemma merkle_root_cons (b : bool) (bs : list bool)
        (s : Felt) (ss : list Felt) (leaf : Felt) :
    merkle_root (b :: bs) (s :: ss) leaf =
    merkle_root bs ss (merkle_step b leaf s).
  Proof. reflexivity. Qed.

  (** Path composition: walking two sub-paths in sequence equals
      walking their concatenation.  Proof by induction on the first
      path, analogous to [Spec.Wots.iter_compose]. *)
  Lemma merkle_root_app
        (bits1 bits2 : list bool) (sibs1 sibs2 : list Felt)
        (leaf : Felt) :
    length bits1 = length sibs1 ->
    merkle_root (bits1 ++ bits2) (sibs1 ++ sibs2) leaf =
    merkle_root bits2 sibs2 (merkle_root bits1 sibs1 leaf).
  Proof.
    revert sibs1 leaf.
    induction bits1 as [| b bs IH]; intros sibs1 leaf Hlen.
    - destruct sibs1 as [| s ss]; [reflexivity | discriminate].
    - destruct sibs1 as [| s ss]; [discriminate |].
      simpl. apply IH. simpl in Hlen. congruence.
  Qed.

  (** Extending the path by one level at the root end.  Corollary of
      [merkle_root_app]. *)
  Lemma merkle_root_snoc
        (bits : list bool) (b : bool)
        (siblings : list Felt) (s : Felt) (leaf : Felt) :
    length bits = length siblings ->
    merkle_root (bits ++ b :: nil) (siblings ++ s :: nil) leaf =
    merkle_step b (merkle_root bits siblings leaf) s.
  Proof.
    intros Hlen.
    rewrite merkle_root_app; [| exact Hlen].
    reflexivity.
  Qed.

End MerkleVerify.

(* ================================================================ *)
(** ** Level-indexed Merkle path (XMSS auth tree)                    *)
(* ================================================================ *)

Section AuthTree.

  (** Node hash parameterized by level and node index.  In the
      protocol: [H_node level node_idx left right =
      H4(pub_seed, pack_adrs(TAG_XMSS_TREE, 0, level, node_idx, 0),
      left, right)]. *)
  Variable H_node : nat -> nat -> Felt -> Felt -> Felt.

  (** Walk the XMSS authentication path.  [idx] is the leaf index
      (halved at each level); [level] starts at 0 and increments.
      At each level, bit [idx mod 2] selects left/right placement,
      and [idx / 2] is the parent's node index. *)
  Fixpoint auth_root (bits : list bool) (siblings : list Felt)
                      (current : Felt) (idx level : nat) : Felt :=
    match bits, siblings with
    | b :: bs, s :: ss =>
        auth_root bs ss
          (if b then H_node level (idx / 2) s current
                else H_node level (idx / 2) current s)
          (idx / 2) (S level)
    | _, _ => current
    end.

  (** Base case. *)
  Lemma auth_root_nil (leaf : Felt) (idx level : nat) :
    auth_root nil nil leaf idx level = leaf.
  Proof. reflexivity. Qed.

  (** One-step unfolding. *)
  Lemma auth_root_cons (b : bool) (bs : list bool)
        (s : Felt) (ss : list Felt)
        (leaf : Felt) (idx level : nat) :
    auth_root (b :: bs) (s :: ss) leaf idx level =
    auth_root bs ss
      (if b then H_node level (idx / 2) s leaf
            else H_node level (idx / 2) leaf s)
      (idx / 2) (S level).
  Proof. reflexivity. Qed.

End AuthTree.

(* ================================================================ *)
(** ** Connection between uniform and indexed variants                *)
(* ================================================================ *)

(** When the node hash ignores its level and position arguments,
    [auth_root] degenerates to [merkle_root].  This connects the
    XMSS auth tree specification to the simpler commitment tree
    specification, and lets proofs about [merkle_root] (like path
    composition) transfer to [auth_root] in the uniform-hash
    special case. *)
Theorem auth_merkle_uniform
    (H : Felt -> Felt -> Felt)
    (bits : list bool) (siblings : list Felt)
    (leaf : Felt) (level : nat) :
  auth_root (fun _ _ => H) bits siblings leaf 0 level =
  merkle_root H bits siblings leaf.
Proof.
  revert siblings leaf level.
  induction bits as [| b bs IH]; intros siblings leaf level.
  - destruct siblings; reflexivity.
  - destruct siblings as [| s ss]; [reflexivity |].
    change (auth_root (fun _ _ => H) bs ss
      (if b then H s leaf else H leaf s) 0 (S level) =
      merkle_root H bs ss (if b then H s leaf else H leaf s)).
    apply IH.
Qed.

(* ================================================================ *)
(** ** Merkle binding (soundness under collision resistance)          *)
(* ================================================================ *)

(** If two Merkle path computations produce the same root using the
    same position bits, then the leaves and all siblings must be
    equal — under collision resistance of the hash.

    This is the key soundness lemma for Merkle inclusion proofs:
    it means a verified path uniquely determines the leaf at the
    claimed position.  A cheating prover who submits a different
    leaf would need to find a hash collision. *)

Section MerkleBinding.

  Variable H : Felt -> Felt -> Felt.
  Hypothesis H_inj : injective_2 H.

  Theorem merkle_binding
      (bits : list bool)
      (sibs1 sibs2 : list Felt)
      (leaf1 leaf2 : Felt) :
    length bits = length sibs1 ->
    length bits = length sibs2 ->
    merkle_root H bits sibs1 leaf1 = merkle_root H bits sibs2 leaf2 ->
    leaf1 = leaf2 /\ sibs1 = sibs2.
  Proof.
    revert sibs1 sibs2 leaf1 leaf2.
    induction bits as [| b bs IH];
      intros sibs1 sibs2 leaf1 leaf2 Hlen1 Hlen2 Heq.
    - (* Empty path: leaves are directly equal *)
      destruct sibs1; [| discriminate].
      destruct sibs2; [| discriminate].
      simpl in Heq. split; [exact Heq | reflexivity].
    - (* Inductive step *)
      destruct sibs1 as [| s1 ss1]; [discriminate |].
      destruct sibs2 as [| s2 ss2]; [discriminate |].
      simpl in Heq, Hlen1, Hlen2.
      assert (Hlen1' : length bs = length ss1) by congruence.
      assert (Hlen2' : length bs = length ss2) by congruence.
      (* IH gives us: merkle_step values match, tails match *)
      destruct (IH ss1 ss2 (merkle_step H b leaf1 s1)
                   (merkle_step H b leaf2 s2)
                   Hlen1' Hlen2' Heq) as [Hstep Hss].
      (* Crack open merkle_step with CR *)
      unfold merkle_step in Hstep; destruct b.
      + (* right child: H s1 leaf1 = H s2 leaf2 *)
        destruct (H_inj _ _ _ _ Hstep) as [Hs Hl].
        split; [exact Hl | congruence].
      + (* left child: H leaf1 s1 = H leaf2 s2 *)
        destruct (H_inj _ _ _ _ Hstep) as [Hl Hs].
        split; [exact Hl | congruence].
  Qed.

End MerkleBinding.

(** Auth-tree binding: same result under same starting index
    implies same leaf and siblings, under per-slot injectivity
    of the node hash. *)

Section AuthBinding.

  Variable H_node : nat -> nat -> Felt -> Felt -> Felt.
  Hypothesis H_node_inj : node_injective H_node.

  Theorem auth_binding
      (bits : list bool)
      (sibs1 sibs2 : list Felt)
      (leaf1 leaf2 : Felt)
      (idx level : nat) :
    length bits = length sibs1 ->
    length bits = length sibs2 ->
    auth_root H_node bits sibs1 leaf1 idx level =
    auth_root H_node bits sibs2 leaf2 idx level ->
    leaf1 = leaf2 /\ sibs1 = sibs2.
  Proof.
    revert sibs1 sibs2 leaf1 leaf2 idx level.
    induction bits as [| b bs IH];
      intros sibs1 sibs2 leaf1 leaf2 idx level Hlen1 Hlen2 Heq.
    - destruct sibs1; [| discriminate].
      destruct sibs2; [| discriminate].
      simpl in Heq. split; [exact Heq | reflexivity].
    - destruct sibs1 as [| s1 ss1]; [discriminate |].
      destruct sibs2 as [| s2 ss2]; [discriminate |].
      simpl in Heq, Hlen1, Hlen2.
      assert (Hlen1' : length bs = length ss1) by congruence.
      assert (Hlen2' : length bs = length ss2) by congruence.
      set (v1 := if b then H_node level (idx / 2) s1 leaf1
                       else H_node level (idx / 2) leaf1 s1) in *.
      set (v2 := if b then H_node level (idx / 2) s2 leaf2
                       else H_node level (idx / 2) leaf2 s2) in *.
      destruct (IH ss1 ss2 v1 v2 (idx / 2) (S level)
                   Hlen1' Hlen2' Heq) as [Hstep Hss].
      subst v1 v2; destruct b.
      + destruct (H_node_inj _ _ _ _ _ _ Hstep) as [Hs Hl].
        split; [exact Hl | congruence].
      + destruct (H_node_inj _ _ _ _ _ _ Hstep) as [Hl Hs].
        split; [exact Hl | congruence].
  Qed.

End AuthBinding.
