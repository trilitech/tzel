(** * Impl.Xmss — extractable XMSS signature verification

    Mirror of the XMSS portion of [cairo/src/xmss_common.cairo].

    XMSS layers an auth tree on top of WOTS+ ([Impl.Wots]):

    - Each leaf at index j holds an L-tree-compressed WOTS+ public key.
    - The auth tree is a binary Merkle tree over the leaves rooted at
      [auth_root].
    - [xmss_verify] takes a signature [sig], a sighash [msg], the
      claimed leaf index [auth_idx], and the auth path. It (a) WOTS+
      verifies [sig] against [msg] to recover the candidate leaf
      pubkey, (b) L-tree compresses to a leaf hash, (c) walks the auth
      path up to [auth_root], (d) checks the recovered root matches.

    Soundness target (the headline):

      xmss_verify_sound:
        XmssVerify msg sig auth_idx auth_path auth_root = true ->
        exists pk, MembersOf auth_root auth_idx (LeafFromPk pk)
                /\ WotsRecover msg sig = pk

    Read in plain English: an accepting XMSS verification proves that
    the signature was produced by the holder of the secret key for
    *the specific leaf at the claimed index*, under the standard XMSS
    one-time-unforgeability assumption (which we either inherit as an
    axiom from the literature, or — much later — discharge via a
    reduction in [Spec.Hashes]'s axioms).

    This is the most subtle module to model. Plenty of room for a
    missing assertion to slip in (e.g., the chain step counts off by
    one, the L-tree compression skipping the odd-leaf padding, the
    auth-path bit decomposition). The proof obligation here is the
    primary value of the formalization — if the asserts in the Cairo
    aren't sufficient to discharge the soundness theorem, we've found
    a real gap.

    Status: stub — spec-layer definitions landed in [Spec.Xmss];
    impl-layer instantiation and refinement pending.
*)

From Stdlib Require Import List.
From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Wots.
From Impl Require Import Merkle.
From Spec Require Xmss.

(** ADRS packing for L-tree nodes:
    [pack_adrs(TAG_XMSS_LTREE, key_idx, level, node_idx, 0)]. *)
Parameter pack_adrs_ltree : nat -> nat -> Felt.

Section XmssImpl.

  Variable pub_seed : Felt.

  (** L-tree node hash for XMSS.  Mirrors the [xmss_node_hash] call
      with [TAG_XMSS_LTREE] in [xmss_ltree_level]. *)
  Definition ltree_node_hash (level node_idx : nat)
      (left right : Felt) : Felt :=
    Hash4 pub_seed (pack_adrs_ltree level node_idx) left right.

  (** L-tree compression of WOTS+ endpoints using the concrete
      hash. *)
  Definition xmss_ltree (endpoints : list Felt) : option Felt :=
    Xmss.ltree ltree_node_hash endpoints.

  (** Recover all WOTS+ chain endpoints from a signature. *)
  Definition xmss_recover_all (key_idx : nat) (digits : list nat)
      (sig : list Felt) : list Felt :=
    Xmss.recover_all Hash3 pack_adrs_chain pub_seed
                      key_idx 0 digits sig.

End XmssImpl.
