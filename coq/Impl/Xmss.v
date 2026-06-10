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

    Status: COMPLETE. The extractable verifier [xmss_verify_impl] is
    [Spec.Xmss.xmss_verify] at the concrete chain hash
    ([Hash3]/[pack_adrs_chain]); the Spec-level one-time
    unforgeability and L-tree injectivity transfer to it
    ([xmss_verify_impl_one_time_unforgeable],
    [xmss_ltree_injective_impl]) under the concrete node-hash
    injectivity hypothesis. So the extraction source for XMSS inherits
    the proven soundness.
*)

From Stdlib Require Import List.
From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Wots.
From Impl Require Import Merkle.
From Spec Require Import Xmss Hashes.

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

  (** The extractable XMSS verifier: [Spec.Xmss.xmss_verify] at the
      concrete WOTS+ chain hash ([Hash3] / [pack_adrs_chain]).  The
      auth/L-tree node hash [H_node] is left as a parameter (the Cairo
      uses [Hash4] under distinct ADRS tags). *)
  Definition xmss_verify_impl
      (H_node : nat -> nat -> Felt -> Felt -> Felt)
      (key_idx : nat) (digits : list nat) (sig : list Felt)
      (auth_bits : list bool) (auth_siblings : list Felt)
      (auth_root : Felt) : Prop :=
    Xmss.xmss_verify Hash3 pack_adrs_chain H_node pub_seed
      key_idx digits sig auth_bits auth_siblings auth_root.

  (** L-tree compression of the extractable verifier is injective when
      its node hash is — [Spec.Xmss.ltree_injective] transferred to the
      concrete [ltree_node_hash]. *)
  Theorem xmss_ltree_injective_impl :
    Hashes.node_injective (ltree_node_hash) ->
    forall e1 e2,
      length e1 = length e2 ->
      xmss_ltree e1 = xmss_ltree e2 ->
      xmss_ltree e1 <> None ->
      e1 = e2.
  Proof.
    intros Hinj e1 e2 Hlen Heq Hne.
    exact (Xmss.ltree_injective ltree_node_hash Hinj e1 e2 Hlen Heq Hne).
  Qed.

  (** THE HEADLINE, refined to the extractable verifier: an accepting
      [xmss_verify_impl] forces, against a forward-only forgery, the
      same WOTS+ public key and the same signed message — XMSS one-time
      unforgeability for the actual extraction source.  This is
      [Spec.Xmss.xmss_one_time_unforgeable] instantiated at the
      concrete chain hash; the only assumption is node-hash
      injectivity (preimage resistance), a local hypothesis. *)
  Theorem xmss_verify_impl_one_time_unforgeable :
    forall (H_node : nat -> nat -> Felt -> Felt -> Felt)
           (key_idx : nat)
           (msg1 cs1 msg2 cs2 : list nat) (sig1 sig2 : list Felt)
           (auth_bits : list bool) (auth_siblings : list Felt)
           (auth_root : Felt),
      Hashes.node_injective H_node ->
      length auth_bits = length auth_siblings ->
      length (msg1 ++ cs1) = length sig1 ->
      length (msg2 ++ cs2) = length sig2 ->
      length msg1 = length msg2 ->
      length cs1 = length cs2 ->
      Forall (fun d => d <= 3) msg1 -> Forall (fun d => d <= 3) msg2 ->
      Forall (fun d => d <= 3) cs1 -> Forall (fun d => d <= 3) cs2 ->
      Xmss.base4_val cs1 = Xmss.checksum msg1 ->
      Xmss.base4_val cs2 = Xmss.checksum msg2 ->
      xmss_verify_impl H_node key_idx (msg1 ++ cs1) sig1 auth_bits auth_siblings auth_root ->
      xmss_verify_impl H_node key_idx (msg2 ++ cs2) sig2 auth_bits auth_siblings auth_root ->
      Forall2 (fun d2 d1 => d2 >= d1) msg2 msg1 ->
      Forall2 (fun d2 d1 => d2 >= d1) cs2 cs1 ->
      Xmss.recover_all Hash3 pack_adrs_chain pub_seed key_idx 0 (msg1 ++ cs1) sig1
        = Xmss.recover_all Hash3 pack_adrs_chain pub_seed key_idx 0 (msg2 ++ cs2) sig2
      /\ msg1 = msg2.
  Proof.
    intros H_node key_idx msg1 cs1 msg2 cs2 sig1 sig2 auth_bits auth_siblings auth_root
      Hinj Hab Hs1 Hs2 Hmlen Hclen Hm1 Hm2 Hc1 Hc2 Hcs1 Hcs2 Hv1 Hv2 Hmge Hcge.
    exact (Xmss.xmss_one_time_unforgeable Hash3 pack_adrs_chain H_node pub_seed key_idx
             msg1 cs1 msg2 cs2 sig1 sig2 auth_bits auth_siblings auth_root
             Hinj Hab Hs1 Hs2 Hmlen Hclen Hm1 Hm2 Hc1 Hc2 Hcs1 Hcs2 Hv1 Hv2 Hmge Hcge).
  Qed.

End XmssImpl.
