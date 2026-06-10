(** * Spec.XmssInhabited — the Cairo XMSS verifier is not vacuous

    NON-VACUITY guard for the circuit-relation soundness theorems.
    [Impl.Transfer/Shield/Unshield]'s [*_relation_sound] all have the
    shape [Relation -> Phi].  Such a theorem proves nothing if
    [Relation] is unsatisfiable (a contradiction in the modeled
    constraints would make every soundness theorem vacuously true —
    exactly the "False slipped into the hypotheses" failure mode).

    The only non-trivially-satisfiable conjunct of those relations is
    the in-circuit XMSS check [Spec.Xmss.xmss_verify_cairo_sep] (the
    others — gates, value equations, commitment equations — are
    satisfiable by construction).  This module discharges that conjunct:
    an HONEST signature verifies, so [xmss_verify_cairo_sep] is
    inhabited and the relations are not vacuously false on their
    cryptographic core.

    Proof: the honest signature [sign ... digits sks] recovers exactly
    the public key [gen_pk ... sks] ([recover_all_correct]); that key
    L-tree-compresses to a leaf ([ltree_succeeds], non-empty key); and
    the auth path to the *computed* root verifies by construction. *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Common Require Import Felt.
From Spec Require Import Hashes Xmss Merkle.

Section XmssInhab.

  Variable F : Felt -> Felt -> Felt -> Felt.
  Variable ADRS_chain : nat -> nat -> nat -> Felt.
  Variable pub_seed : Felt.
  (* The Cairo separates the L-tree node hash from the auth-tree node
     hash (distinct ADRS tags) — keep them independent here. *)
  Variable H_ltree : nat -> nat -> Felt -> Felt -> Felt.
  Variable H_tree  : nat -> nat -> Felt -> Felt -> Felt.

  (** The Cairo XMSS verifier accepts an honest signature, so it is not
      vacuously false: for any well-formed message [digits] and a
      matching non-empty secret key [sks], there is a signature and auth
      path making [xmss_verify_cairo_sep] hold. *)
  Theorem xmss_cairo_sep_inhabited :
    forall (digits : list nat) (sks : list Felt),
      length digits = length sks ->
      sks <> nil ->
      Forall (fun d => d <= Hashes.wots_chain_len) digits ->
      exists (sig auth_siblings : list Felt) (auth_root : Felt),
        xmss_verify_cairo_sep H_tree H_ltree F ADRS_chain pub_seed 0
          digits sig auth_siblings auth_root.
  Proof.
    intros digits sks Hlen Hne Hd.
    exists (sign F ADRS_chain pub_seed 0 0 digits sks).
    assert (Hgpk : gen_pk F ADRS_chain pub_seed 0 0 sks <> nil).
    { destruct sks as [| sk rest]; [contradiction | cbn [gen_pk]; discriminate]. }
    destruct (ltree_succeeds H_ltree (gen_pk F ADRS_chain pub_seed 0 0 sks) Hgpk)
      as [leaf Hleaf].
    exists (repeat pub_seed Hashes.auth_depth).
    exists (Merkle.auth_root H_tree (nat_to_bits Hashes.auth_depth 0)
              (repeat pub_seed Hashes.auth_depth) leaf 0 0).
    unfold xmss_verify_cairo_sep.
    rewrite (recover_all_correct F ADRS_chain pub_seed 0 0 digits sks Hlen Hd).
    rewrite Hleaf.
    unfold auth_verify. split; [| split].
    - rewrite repeat_length. reflexivity.
    - assert (2 ^ Hashes.auth_depth <> 0) by (apply Nat.pow_nonzero; lia). lia.
    - reflexivity.
  Qed.

End XmssInhab.
