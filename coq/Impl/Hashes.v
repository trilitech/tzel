(** * Impl.Hashes

    Implementation-side hash declarations, mirroring
    [cairo/src/blake_hash.cairo].

    [Hash3] is the generic 3-input hash ([blake_hash::hash3_generic]
    in Cairo) used by [xmss_chain_step] to mix [pub_seed], the
    ADRS-encoded chain index, and the running chain element.

    [Hash4] is the generic 4-input hash ([blake_hash::hash4_generic]
    in Cairo) used by the L-tree and auth-tree node computation to
    mix [pub_seed], the ADRS, and two child nodes.

    Domain separation comes from the ADRS encoding, not separate IVs.

    The [Spec] layer's hash parameters are abstract Section variables;
    the [Impl] layer here declares the concrete parameters that
    extraction realizes bit-equivalently to the Cairo.
*)

From Common Require Import Felt.
From Spec Require Import Hashes.

Parameter Hash3 : Felt -> Felt -> Felt -> Felt.
Parameter Hash4 : Felt -> Felt -> Felt -> Felt -> Felt.

(** [Hash5] is the 5-input commitment hash
    ([cairo/src/blake_hash.cairo::hash5], cmmt domain) introduced by
    multiasset: it mixes the diversified address, value, ASSET TAG,
    randomness, and owner tag.  Extraction realizes it as
    [Tzel.Hash.hash_commit], which the cross-impl interop check
    (and the regenerated [commitment_u64_max_v1.json] fixture) pins
    bit-equivalent to the Cairo. *)
Parameter Hash5 : Felt -> Felt -> Felt -> Felt -> Felt -> Felt.

(** The note commitment, concretely: [cm = H_commit(d_j, v, asset,
    rcm, owner_tag)].  Top-level (not a section variable) so it can
    be extracted and differentially fuzzed against the OCaml port. *)
Definition commit (d_j v asset rcm owner_tag : Felt) : Felt :=
  Hash5 d_j v asset rcm owner_tag.

(** Refinement: the executable [commit] equals the [Spec.Hashes]
    abstract commitment under the realization [H_commit := Hash5].
    Trivial by [Definition] expansion, mirroring
    [Impl.Wots.refines_spec] — it lets future Spec-level lemmas
    about [commitment] (e.g. binding under collision resistance)
    transfer to the extractable [commit]. *)
Theorem commit_refines_spec :
  forall d_j v asset rcm owner_tag,
    commit d_j v asset rcm owner_tag
    = Spec.Hashes.commitment Hash5 d_j v asset rcm owner_tag.
Proof. reflexivity. Qed.
