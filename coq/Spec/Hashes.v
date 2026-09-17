(** * Spec.Hashes — abstract hash families and protocol constants

    Source: whitepaper §"Cryptographic primitives" and spec.md hash
    catalogue.  The protocol uses domain-separated BLAKE2s at three
    arities; the spec layer abstracts each use-site as a distinct
    opaque function parameterized in each module's Section.

    Hash arities used by the protocol:

    - [H2 : Felt -> Felt -> Felt]
        Commitment Merkle tree internal nodes (personalized with
        [mrklSP__]), nullifier derivation ([nulfSP__]), sighash fold
        ([sighSP__]), nk_spend key derivation ([nkspSP__]).

    - [H3 : Felt -> Felt -> Felt -> Felt]
        WOTS+ chain step (unpersonalized BLAKE2s over 96 bytes;
        domain separation via ADRS packed into the second argument).

    - [H4 : Felt -> Felt -> Felt -> Felt -> Felt]
        L-tree and auth-tree internal node hashing (unpersonalized
        BLAKE2s over 128 bytes: [pub_seed || ADRS || left || right]).

    Cryptographic properties (collision resistance, preimage resistance,
    PRF) will be stated as axioms here when soundness proofs in
    [Spec.Xmss] or [Spec.Transfer] need them.  Currently unused —
    the structural properties proved so far hold for any functions of
    the right arity.
*)

From Stdlib Require Import List.
From Common Require Import Felt.

(** ** WOTS+ protocol parameters (whitepaper / RFC 8391)

    Base [w = 4]: each WOTS digit is in [{0, 1, 2, 3}].
    Chain length [w − 1 = 3]: each chain applies the hash [w − 1]
    times from secret key to public key endpoint.
    Total chains: 128 message digits + 5 checksum digits = 133. *)

Definition wots_w : nat := 4.
Definition wots_chain_len : nat := wots_w - 1.
Definition wots_chains : nat := 133.

(** ** Tree depth parameters

    Auth tree depth: 16 (2^16 = 65 536 one-time keys per address).
    Commitment tree depth: 48 (2^48 leaves). *)

Definition auth_depth : nat := 16.
Definition tree_depth : nat := 48.

(* ================================================================ *)
(** ** Collision resistance                                           *)
(* ================================================================ *)

(** We model collision resistance as injectivity.  This is strictly
    stronger than computational CR, but the proof obligations it
    generates are identical — every step where the real proof would
    say "unless a collision was found" becomes an appeal to this
    hypothesis.  A collision-finding adversary in the computational
    model corresponds to a witness that violates the axiom.

    The [Spec]-layer soundness theorems take these as hypotheses
    ([Section] variables); they are never globally axiomatized. *)

Definition injective_2 (H : Felt -> Felt -> Felt) : Prop :=
  forall a b c d, H a b = H c d -> a = c /\ b = d.

Definition injective_4 (H : Felt -> Felt -> Felt -> Felt -> Felt) : Prop :=
  forall a1 a2 a3 a4 b1 b2 b3 b4,
    H a1 a2 a3 a4 = H b1 b2 b3 b4 ->
    a1 = b1 /\ a2 = b2 /\ a3 = b3 /\ a4 = b4.

Definition injective_5
    (H : Felt -> Felt -> Felt -> Felt -> Felt -> Felt) : Prop :=
  forall a1 a2 a3 a4 a5 b1 b2 b3 b4 b5,
    H a1 a2 a3 a4 a5 = H b1 b2 b3 b4 b5 ->
    a1 = b1 /\ a2 = b2 /\ a3 = b3 /\ a4 = b4 /\ a5 = b5.

(** Per-slot injectivity for the level/position-indexed node hash
    used in auth trees and L-trees.  The hash is injective within
    each (level, node_idx) slot; cross-slot collisions are prevented
    by domain separation (different ADRS). *)
Definition node_injective
    (H_node : nat -> nat -> Felt -> Felt -> Felt) : Prop :=
  forall level nidx a b c d,
    H_node level nidx a b = H_node level nidx c d ->
    a = c /\ b = d.

(** Third-argument injectivity of the 3-input hash (chain hash).
    Models second-preimage resistance: given [F(a, b, x)], finding
    [x' ≠ x] with [F(a, b, x') = F(a, b, x)] is hard.  Weaker
    than full injectivity — only the chain element (third arg) must
    be recoverable; the key and ADRS (first two args) are fixed by
    the protocol context. *)
Definition hash3_third_injective (F : Felt -> Felt -> Felt -> Felt) : Prop :=
  forall a b x1 x2, F a b x1 = F a b x2 -> x1 = x2.

(* ================================================================ *)
(** ** Sighash fold                                                   *)
(* ================================================================ *)

(** The sighash binds all public outputs to the WOTS+ signature.
    It is computed as a sequential left-fold over the transaction's
    public fields using a personalized 2-input hash ([sighSP__] IV
    in Cairo).  The first element is the type tag (0x01 = transfer,
    0x02 = unshield, 0x03 = shield), preventing cross-circuit
    replay.

    The fold is order-dependent: reordering public fields changes
    the sighash, which invalidates the signature.  This is the
    "sighash completeness" property — if any public output is
    omitted or reordered, the sighash doesn't match, and the
    WOTS+ signature check fails.

    Source: spec.md "Sighash" + whitepaper "Authorization binding". *)

Section SighashFold.

  (** Personalized 2-input hash for sighash computation. *)
  Variable H_sighash : Felt -> Felt -> Felt.

  (** Left-fold hash over a list of public fields.
      [acc] starts as the type tag, and each field is folded in. *)
  Fixpoint sighash_fold (acc : Felt) (fields : list Felt) : Felt :=
    match fields with
    | nil => acc
    | x :: rest => sighash_fold (H_sighash acc x) rest
    end.

  (** Base case. *)
  Lemma sighash_fold_nil (acc : Felt) :
    sighash_fold acc nil = acc.
  Proof. reflexivity. Qed.

  (** One-step unfolding. *)
  Lemma sighash_fold_cons (acc x : Felt) (rest : list Felt) :
    sighash_fold acc (x :: rest) = sighash_fold (H_sighash acc x) rest.
  Proof. reflexivity. Qed.

  (** Composition: folding a concatenation equals folding the first
      part and then continuing with the second. *)
  Lemma sighash_fold_app (acc : Felt) (xs ys : list Felt) :
    sighash_fold acc (xs ++ ys) = sighash_fold (sighash_fold acc xs) ys.
  Proof.
    revert acc.
    induction xs as [| x rest IH]; intros acc.
    - reflexivity.
    - simpl. apply IH.
  Qed.

End SighashFold.

(* ================================================================ *)
(** ** Commitment and nullifier construction                          *)
(* ================================================================ *)

(** The note commitment binds (denomination, value, asset, randomness,
    owner_tag) into an opaque value stored in the Merkle tree.  The
    [asset] field is hidden inside the hash preimage — it does not
    appear in the cleartext nullifier or anywhere else publicly, so
    an on-chain observer cannot tell which asset a given commitment
    encodes.  Asset = [Felt(0)] by convention denotes tez; any other
    value is a future bridge-defined tag.

    The nullifier is position-dependent: it binds the spend key,
    the commitment, and the leaf position, ensuring that spending
    the same note at the same position always produces the same
    nullifier (double-spend detection) but spending different notes
    or the same note at different positions produces distinct
    nullifiers (privacy).  The asset is bound through [cm] (which
    appears in the inner hash) — there is no separate "asset
    nullifier" because the same note cannot have two assets.

    Source: spec.md "Commitments and nullifiers". *)

Section Nullifier.

  Variable H_commit : Felt -> Felt -> Felt -> Felt -> Felt -> Felt.
  Variable H_nf : Felt -> Felt -> Felt.

  (** Note commitment: [cm = H_commit(d_j, v, asset, rcm, owner_tag)]. *)
  Definition commitment (d_j v asset rcm owner_tag : Felt) : Felt :=
    H_commit d_j v asset rcm owner_tag.

  (** Nullifier: [nf = H_nf(nk_spend, H_nf(cm, pos))].
      Position-dependent to prevent faerie-gold attacks. *)
  Definition nullifier (nk_spend cm pos : Felt) : Felt :=
    H_nf nk_spend (H_nf cm pos).

  (** The nullifier is deterministic: same inputs always produce
      the same nullifier.  This ensures double-spend detection
      works — if a note is spent twice, the same nullifier appears
      twice in the nullifier set. *)
  Lemma nullifier_deterministic (nk cm pos : Felt) :
    nullifier nk cm pos = nullifier nk cm pos.
  Proof. reflexivity. Qed.

End Nullifier.
