(** * Impl.Merkle — extractable Merkle path verification

    Mirror of [cairo/src/merkle.cairo] (commitment tree) and the
    auth-tree verification in [cairo/src/xmss_common.cairo].

    Two concrete instantiations of [Spec.Merkle]:

    - [merkle_compute_root]: commitment tree verification using
      [Hash2_merkle] (BLAKE2s with [mrklSP__] personalized IV).
    - [auth_compute_root]: XMSS auth tree verification using
      [Hash4] with level/position-dependent ADRS.

    Refinement theorems connect each to the corresponding
    [Spec.Merkle] definition by [reflexivity].
*)

From Stdlib Require Import List Bool.
From Common Require Import Felt.
From Impl Require Import Hashes.
From Spec Require Merkle.

(* ---------------------------------------------------------------- *)
(** ** Commitment tree (uniform hash)                                *)
(* ---------------------------------------------------------------- *)

(** Personalized 2-input hash for commitment Merkle tree.
    Extraction will realize as BLAKE2s with [mrklSP__] IV. *)
Parameter Hash2_merkle : Felt -> Felt -> Felt.

Definition merkle_compute_root (bits : list bool) (siblings : list Felt)
    (leaf : Felt) : Felt :=
  Merkle.merkle_root Hash2_merkle bits siblings leaf.

Theorem merkle_refines_spec : forall bits siblings leaf,
  merkle_compute_root bits siblings leaf =
  Merkle.merkle_root Hash2_merkle bits siblings leaf.
Proof. reflexivity. Qed.

(* ---------------------------------------------------------------- *)
(** ** Auth tree (level-indexed hash)                                *)
(* ---------------------------------------------------------------- *)

(** ADRS packing for auth-tree nodes:
    [pack_adrs(TAG_XMSS_TREE, 0, level, node_idx, 0)]. *)
Parameter pack_adrs_tree : nat -> nat -> Felt.

Section AuthTreeImpl.

  Variable pub_seed : Felt.

  (** XMSS auth-tree node hash.  Mirrors [xmss_node_hash] in
      [cairo/src/xmss_common.cairo]:
      [hash4_generic(pub_seed, pack_adrs(TAG, 0, level, node_idx, 0),
      left, right)]. *)
  Definition xmss_node_hash (level node_idx : nat)
      (left right : Felt) : Felt :=
    Hash4 pub_seed (pack_adrs_tree level node_idx) left right.

  Definition auth_compute_root (bits : list bool) (siblings : list Felt)
      (leaf : Felt) (key_idx : nat) : Felt :=
    Merkle.auth_root xmss_node_hash bits siblings leaf key_idx 0.

  Theorem auth_refines_spec : forall bits siblings leaf key_idx,
    auth_compute_root bits siblings leaf key_idx =
    Merkle.auth_root xmss_node_hash bits siblings leaf key_idx 0.
  Proof. reflexivity. Qed.

End AuthTreeImpl.
