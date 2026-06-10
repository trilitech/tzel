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

Definition injective_3 (H : Felt -> Felt -> Felt -> Felt) : Prop :=
  forall a1 a2 a3 b1 b2 b3,
    H a1 a2 a3 = H b1 b2 b3 -> a1 = b1 /\ a2 = b2 /\ a3 = b3.

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

  (** ** Malleability resistance (transaction-binding)

      Under collision resistance of [H_sighash] (modeled as
      [injective_2], a Section hypothesis per this file's
      convention), the fold is INJECTIVE on equal-length field
      lists: if two runs from accumulators [acc], [acc'] over
      same-length field lists yield the same sighash, then the
      starting accumulators AND every field coincide.

      Protocol meaning: a WOTS+ signature is computed over the
      sighash, and the sighash folds (type tag :: all public
      outputs).  This lemma says no two DISTINCT public-output
      tuples of the same shape can share a sighash — so an attacker
      cannot alter any signed field (recipient, amount, asset
      commitment, nullifier, memo, …) without invalidating the
      signature.  This is the formal core of "sign what you see".

      The equal-length hypothesis is necessary, not incidental: a
      hash output [H_sighash acc x] could happen to equal a raw
      accumulator [acc'] of a shorter run, so different-length
      folds are NOT separated by injectivity alone.  Every circuit's
      sighash folds a FIXED-length field list (the public-output
      arity is structural), so the hypothesis always holds at the
      use site. *)
  Lemma sighash_fold_injective (Hinj : injective_2 H_sighash) :
    forall (xs ys : list Felt) (acc acc' : Felt),
      length xs = length ys ->
      sighash_fold acc xs = sighash_fold acc' ys ->
      acc = acc' /\ xs = ys.
  Proof.
    induction xs as [| x xr IH]; intros [| y yr] acc acc' Hlen Heq;
      try discriminate.
    - (* both empty: the fold is the accumulator *)
      split; [exact Heq | reflexivity].
    - (* both cons: peel one field via the IH, then invert the hash *)
      simpl in Heq.
      injection Hlen as Hlen'.
      destruct (IH yr (H_sighash acc x) (H_sighash acc' y) Hlen' Heq)
        as [Hhash Htail].
      destruct (Hinj _ _ _ _ Hhash) as [Hacc Hx].
      split; [exact Hacc | now subst].
  Qed.

  (** Specialization actually used by the per-circuit sighash
      predicates: the type tag is a fixed prefix, so two transactions
      that sign the same sighash and have the same number of public
      fields publish the SAME fields. *)
  Corollary sighash_binds_fields (Hinj : injective_2 H_sighash) :
    forall (tag : Felt) (xs ys : list Felt),
      length xs = length ys ->
      sighash_fold tag xs = sighash_fold tag ys ->
      xs = ys.
  Proof.
    intros tag xs ys Hlen Heq.
    now destruct (sighash_fold_injective Hinj xs ys tag tag Hlen Heq).
  Qed.

  (** ** Cross-circuit replay resistance

      The sighash starts from a circuit TYPE TAG (transfer = 0x01,
      unshield = 0x02, shield = 0x03, pubkey-hash = 0x04; see
      [Spec.Transfer]).  Under collision resistance, two transactions
      that start from DIFFERENT tags and fold the same NUMBER of
      public fields can never share a sighash — so a WOTS+ signature
      (computed over the sighash) valid for one circuit is never
      valid for another.  This blocks "sign a transfer, replay it as
      a shield" style cross-circuit confusion at the signature layer.

      Equal-arity is the in-scope case: the three spending/entry
      circuits publish different numbers of fields in general
      (transfer/unshield carry per-input nullifiers; shield none), so
      cross-arity confusion is instead blocked OUTSIDE this model by
      the kernel pinning each circuit's program hash before applying
      its message — a transfer proof is only ever verified against
      the transfer program.  Within a fixed arity, the tag alone
      suffices, and that is what this theorem certifies. *)
  Theorem replay_resistant (Hinj : injective_2 H_sighash) :
    forall (tag1 tag2 : Felt) (fields1 fields2 : list Felt),
      tag1 <> tag2 ->
      length fields1 = length fields2 ->
      sighash_fold tag1 fields1 <> sighash_fold tag2 fields2.
  Proof.
    intros tag1 tag2 fields1 fields2 Htag Hlen Heq.
    destruct (sighash_fold_injective Hinj fields1 fields2 tag1 tag2 Hlen Heq)
      as [Htageq _].
    exact (Htag Htageq).
  Qed.

  (** Utility: equal-length prefixes of equal concatenations match. *)
  Lemma app_eq_len_l (xs xs' ys ys' : list Felt) :
    length xs = length xs' ->
    xs ++ ys = xs' ++ ys' ->
    xs = xs' /\ ys = ys'.
  Proof.
    revert xs'.
    induction xs as [| x xr IH]; intros [| x' xr'] Hlen Heq;
      try discriminate.
    - split; [reflexivity | exact Heq].
    - simpl in Heq. injection Heq as Hx Hrest.
      injection Hlen as Hlen'.
      destruct (IH xr' Hlen' Hrest) as [Hxr Hys].
      split; [now subst | exact Hys].
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
  Variable H_owner : Felt -> Felt -> Felt -> Felt.

  (** Note commitment: [cm = H_commit(d_j, v, asset, rcm, owner_tag)]. *)
  Definition commitment (d_j v asset rcm owner_tag : Felt) : Felt :=
    H_commit d_j v asset rcm owner_tag.

  (** Under collision resistance of [H_commit] (modeled as 5-ary
      injectivity), a commitment BINDS all five fields: equal
      commitments only arise from the same
      [(d_j, v, asset, rcm, owner_tag)].  This is the note-integrity
      root of trust — a commitment in the tree determines, uniquely,
      the note it represents. *)
  Theorem commitment_binding (Hinj : injective_5 H_commit)
      (d v asset rcm owner d' v' asset' rcm' owner' : Felt) :
    commitment d v asset rcm owner = commitment d' v' asset' rcm' owner' ->
    d = d' /\ v = v' /\ asset = asset' /\ rcm = rcm' /\ owner = owner'.
  Proof. unfold commitment. apply Hinj. Qed.

  (** ** Multiasset soundness: the commitment binds its ASSET.

      Two notes with the same commitment have the same asset.  Since
      spending/unshielding a note proves membership of its commitment
      in the tree and re-derives that commitment from the presented
      fields, a note committed under one asset can NEVER be presented
      as a different asset.  This is exactly what rules out the
      "asset substitution" attack (the [Spec.Shield] hazard: spending
      a cheap-asset note as an expensive asset) — the asset is welded
      to the commitment, with no separate asset nullifier needed. *)
  Corollary commitment_binds_asset (Hinj : injective_5 H_commit)
      (d v asset rcm owner d' v' asset' rcm' owner' : Felt) :
    commitment d v asset rcm owner = commitment d' v' asset' rcm' owner' ->
    asset = asset'.
  Proof.
    intro Heq.
    destruct (commitment_binding Hinj d v asset rcm owner
                                 d' v' asset' rcm' owner' Heq)
      as [_ [_ [Ha _]]].
    exact Ha.
  Qed.

  (** Likewise the commitment binds its VALUE: a note's amount cannot
      be changed without changing its commitment (no per-note value
      inflation by re-presenting a different amount). *)
  Corollary commitment_binds_value (Hinj : injective_5 H_commit)
      (d v asset rcm owner d' v' asset' rcm' owner' : Felt) :
    commitment d v asset rcm owner = commitment d' v' asset' rcm' owner' ->
    v = v'.
  Proof.
    intro Heq.
    destruct (commitment_binding Hinj d v asset rcm owner
                                 d' v' asset' rcm' owner' Heq)
      as [_ [Hv _]].
    exact Hv.
  Qed.

  (** ** Spending-authority binding

      The owner tag welds a note to a spending authority:
      [owner_tag = H_owner(auth_root, pub_seed, nk_tag)] (see
      [Spec.Shield]).  [auth_root] is the root of the spender's
      authorization Merkle tree — only its holder can produce the
      witnesses a spend requires. *)
  Definition owner_tag (auth_root pub_seed nk_tag : Felt) : Felt :=
    H_owner auth_root pub_seed nk_tag.

  (** Under collision resistance of [H_owner], the owner tag binds the
      authorization root, the pub seed, and the nk tag. *)
  Theorem owner_tag_binding (Hinj : injective_3 H_owner)
      (ar ps nk ar' ps' nk' : Felt) :
    owner_tag ar ps nk = owner_tag ar' ps' nk' ->
    ar = ar' /\ ps = ps' /\ nk = nk'.
  Proof. unfold owner_tag. apply Hinj. Qed.

  (** ** The full chain: a commitment binds its spending authority.

      Composing [commitment_binding] (the commitment binds its
      owner_tag field) with [owner_tag_binding] (the owner_tag binds
      its auth_root): two notes with the same commitment, whose owner
      tags are well-formed, have the SAME authorization root.  So a
      note's spending authority is welded to its commitment — a note
      committed to one auth tree can never be spent under a different
      one (no authority substitution). *)
  Theorem commitment_binds_auth_root
      (Hc : injective_5 H_commit) (Ho : injective_3 H_owner)
      (d v asset rcm ar ps nk d' v' asset' rcm' ar' ps' nk' : Felt) :
    commitment d v asset rcm (owner_tag ar ps nk)
    = commitment d' v' asset' rcm' (owner_tag ar' ps' nk') ->
    ar = ar'.
  Proof.
    intro Heq.
    destruct (commitment_binding Hc d v asset rcm (owner_tag ar ps nk)
                                 d' v' asset' rcm' (owner_tag ar' ps' nk') Heq)
      as [_ [_ [_ [_ Hotag]]]].
    destruct (owner_tag_binding Ho ar ps nk ar' ps' nk' Hotag) as [Har _].
    exact Har.
  Qed.

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

  (** Under collision resistance of [H_nf] (modeled as injectivity,
      taken as a lemma hypothesis per this file's convention), a
      nullifier value BINDS the spending key, the note commitment,
      and the leaf position: equal nullifiers only arise from the
      same [(nk_spend, cm, pos)] triple.

      Together with [nullifier_deterministic] this gives the
      protocol's double-spend semantics in both directions:
      - completeness: re-spending the same note at the same
        position reproduces the same nullifier, so the kernel's
        nullifier-set membership check always fires;
      - soundness: a nullifier collision between different notes,
        positions, or keys would be an [H_nf] collision — the
        kernel's check never falsely locks an unspent note. *)
  Lemma nullifier_binding (Hinj : injective_2 H_nf)
      (nk cm pos nk' cm' pos' : Felt) :
    nullifier nk cm pos = nullifier nk' cm' pos' ->
    nk = nk' /\ cm = cm' /\ pos = pos'.
  Proof.
    intros Heq.
    destruct (Hinj _ _ _ _ Heq) as [Hnk Hinner].
    destruct (Hinj _ _ _ _ Hinner) as [Hcm Hpos].
    auto.
  Qed.

  (** ** Batch double-spend prevention

      A SPEND DESCRIPTOR is the [(nk_spend, cm, pos)] triple a single
      input reveals.  The kernel maintains a global nullifier set and
      rejects a batch with a repeated nullifier.  These two results
      show that dedup is EXACTLY spend dedup — faithful in both
      directions:

      - [desc_nf_injective]: distinct descriptors have distinct
        nullifiers (under CR).  So the kernel never rejects two
        genuinely-different spends as if they collided (no false
        positive).
      - [batch_nullifier_set_faithful]: a descriptor list has no
        duplicates IFF its nullifier list has no duplicates.  Forward
        (the non-trivial CR direction): a deduplicated nullifier set
        guarantees no note-at-position is spent twice in the batch.
        Backward (unconditional): re-spending the same descriptor
        reproduces its nullifier, so the dedup always catches it.

      Together: rejecting duplicate nullifiers prevents every
      double-spend and only double-spends. *)

  Definition desc_nf (d : Felt * Felt * Felt) : Felt :=
    let '(nk, cm, pos) := d in nullifier nk cm pos.

  Lemma desc_nf_injective (Hinj : injective_2 H_nf) :
    forall d d', desc_nf d = desc_nf d' -> d = d'.
  Proof.
    intros [[nk cm] pos] [[nk' cm'] pos'] H. cbn in H.
    destruct (nullifier_binding Hinj _ _ _ _ _ _ H) as [Hnk [Hcm Hpos]].
    subst. reflexivity.
  Qed.

  Theorem batch_nullifier_set_faithful (Hinj : injective_2 H_nf) :
    forall descs : list (Felt * Felt * Felt),
      NoDup descs <-> NoDup (map desc_nf descs).
  Proof.
    intros descs. split.
    - (* forward: injective image of a NoDup list is NoDup *)
      induction descs as [| d ds IH]; intros Hnd.
      + constructor.
      + inversion Hnd as [| ? ? Hnotin Hndtl]; subst.
        cbn. constructor.
        * (* ~ In (desc_nf d) (map desc_nf ds) *)
          intro Hin.
          apply in_map_iff in Hin.
          destruct Hin as [d' [Hfeq Hin']].
          apply (desc_nf_injective Hinj) in Hfeq. subst d'.
          exact (Hnotin Hin').
        * apply IH. exact Hndtl.
    - (* backward: holds for any map *)
      apply NoDup_map_inv.
  Qed.

End Nullifier.
