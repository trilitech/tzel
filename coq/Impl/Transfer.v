(** * Impl.Transfer

    Mirror of [cairo/src/transfer.cairo].

    The Cairo file implements the [N -> 4] multiasset transfer
    relation: spend
    [N] (1 ≤ N ≤ 7) input notes, produce four output commitments
    (recipient, change_1, change_2, producer-fee), every note
    carrying a hidden asset tag inside its commitment preimage.
    For each input [i], it checks:
    - the input note's commitment is Merkle-included in [root]
      (via [Tzel.Merkle]),
    - the published nullifier is correctly derived from the witness,
    - a one-time WOTS+ signature under the auth tree leaf at the
      claimed index verifies the sighash (via [Tzel.Xmss]).

    For each output [j ∈ {1,2,3}], it checks the commitment is
    well-formed: [cm_j = H_commit(d_j, v_j, asset_j, rcm(rseed_j),
    otag_j)] — 5-ary, asset included.

    It then checks per-asset value conservation via the
    two-accumulator scheme (witness-declared primary non-tez asset,
    per-entry {tez, primary} gate, separate lane equations
    [tez_in = tez_out + fee] and [primary_in = primary_out]) —
    see the [TwoAccumulator] section below, which proves this
    strategy implies [Spec.Transfer.phi_value_conservation].

    The sighash binds every public output, so a malicious prover
    cannot redirect outputs without re-signing.

    Soundness target (the headline):

      transfer_sound:
        TransferRelation pub wit ->
        Phi_transfer pub /\ exists witness_evidence ...

    where [Phi_transfer pub] is the protocol-level safety predicate:
    every nullifier was correctly derived from a real Merkle-included
    note, the value triple balances, every output commitment is
    well-formed, and a valid spend authorization existed.

    The proof here is mostly assembly — given [merkle_path_sound],
    [xmss_verify_sound], and [commit_injective] (all from earlier
    modules), the transfer-level soundness drops out from the Cairo
    asserts. The interesting case is when the proof DOESN'T drop out:
    that's where a missing assert lives.

    Status: safety predicate defined in [Spec.Transfer]; the
    value-conservation leg of the refinement is PROVED below
    ([two_accumulator_conservation]); the full Cairo-shaped
    [TransferRelation] record (Merkle + nullifier + XMSS legs)
    and the assembled [Relation -> Phi] theorem are pending.
*)

From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Merkle.
From Impl Require Import Wots.
From Impl Require Import Xmss.
From Spec Require Transfer.

From Stdlib Require Import List Arith.
Import ListNotations.

(** ** The two-accumulator balance scheme

    [cairo/src/transfer.cairo] cannot quantify over assets inside a
    constraint system, so it does NOT implement
    [Spec.Transfer.phi_value_conservation] directly.  Instead the
    witness declares one [primary_non_tez_asset], every input and
    output asset is gated into [{ASSET_TEZ, primary}], and two
    accumulators close the balance separately:

      tez lane:      [assert(tez_in == tez_out + fee)]
      primary lane:  [assert(primary_in == primary_out)]

    This section proves the headline soundness obligation for that
    strategy: the gate plus the two accumulator equations IMPLY the
    abstract per-asset conservation predicate, for EVERY felt [a] —
    including assets that appear nowhere in the transaction.

    The accumulator functions below mirror the Cairo routing
    literally: an entry feeds the tez lane when its asset equals
    [ASSET_TEZ] and the primary lane otherwise (the [else] branch).
    Note the primary lane is "not tez", NOT "equals primary" — the
    gate is what makes those coincide, and the proof goes through
    the gate hypothesis exactly where the circuit relies on it. *)

Section TwoAccumulator.

  Variable asset_tez : Felt.

  (** [tez_in] / [tez_out]: mirrors
      [if asset_i == ASSET_TEZ { tez += v }]. *)
  Fixpoint acc_tez (assets : list Felt) (values : list nat) : nat :=
    match assets, values with
    | nil, _ | _, nil => 0
    | a :: arest, v :: vrest =>
        (if Felt_eq_dec a asset_tez then v else 0) + acc_tez arest vrest
    end.

  (** [primary_in] / [primary_out]: mirrors the [else { primary += v }]
      branch.  Collects every non-tez entry. *)
  Fixpoint acc_primary (assets : list Felt) (values : list nat) : nat :=
    match assets, values with
    | nil, _ | _, nil => 0
    | a :: arest, v :: vrest =>
        (if Felt_eq_dec a asset_tez then 0 else v) + acc_primary arest vrest
    end.

  (** The per-entry asset gate: mirrors
      [assert(asset_i == ASSET_TEZ || asset_i == primary)]. *)
  Definition asset_gate (primary : Felt) (assets : list Felt) : Prop :=
    Forall (fun a => a = asset_tez \/ a = primary) assets.

  (** *** Bridge lemmas: accumulators vs [Spec.Transfer.sum_at] *)

  (** The tez accumulator is literally [sum_at asset_tez]. *)
  Lemma acc_tez_is_sum_at (assets : list Felt) (values : list nat) :
    acc_tez assets values = Spec.Transfer.sum_at asset_tez assets values.
  Proof.
    revert values.
    induction assets as [| a arest IH]; intros [| v vrest]; simpl;
      try reflexivity.
    now rewrite IH.
  Qed.

  (** Under the gate, and when [primary <> asset_tez], the primary
      accumulator is [sum_at primary]: every non-tez entry IS a
      primary entry.  This is the step that fails without the gate —
      an ungated third asset would feed the primary lane while
      [sum_at primary] ignores it. *)
  Lemma acc_primary_is_sum_at
      (primary : Felt) (Hne : primary <> asset_tez)
      (assets : list Felt) (values : list nat)
      (Hgate : asset_gate primary assets) :
    acc_primary assets values = Spec.Transfer.sum_at primary assets values.
  Proof.
    revert values.
    induction assets as [| a arest IH]; intros [| v vrest]; simpl;
      try reflexivity.
    inversion Hgate as [| ? ? Ha Hrest]; subst.
    rewrite (IH Hrest).
    destruct (Felt_eq_dec a asset_tez) as [Hatez | Hantez];
      destruct (Felt_eq_dec a primary) as [Haprim | Hanprim];
      try reflexivity.
    - (* a = tez AND a = primary: contradicts primary <> tez *)
      exfalso. apply Hne. now rewrite <- Haprim.
    - (* a <> tez AND a <> primary: contradicts the gate *)
      destruct Ha as [Ha | Ha]; contradiction.
  Qed.

  (** An asset that appears nowhere in a list sums to zero over it. *)
  Lemma sum_at_absent_zero
      (t : Felt) (assets : list Felt) (values : list nat)
      (Habsent : Forall (fun a => a <> t) assets) :
    Spec.Transfer.sum_at t assets values = 0.
  Proof.
    revert values.
    induction assets as [| a arest IH]; intros [| v vrest]; simpl;
      try reflexivity.
    inversion Habsent as [| ? ? Ha Hrest]; subst.
    rewrite (IH Hrest).
    destruct (Felt_eq_dec a t) as [Heq | _]; [contradiction | reflexivity].
  Qed.

  (** *** Headline theorem

      The Cairo strategy implies the abstract spec: if every input
      and output asset passes the gate and both accumulator
      equations hold, then for EVERY asset [a], inputs of [a] equal
      outputs of [a], plus the public fee when [a] is tez.

      Three cases:
      - [a = tez]: the tez-lane equation, verbatim.
      - [a = primary <> tez]: the primary-lane equation, transported
        through [acc_primary_is_sum_at] on both sides.
      - [a] not in [{tez, primary}]: the gate makes both sides empty. *)
  Theorem two_accumulator_conservation
      (primary : Felt)
      (input_assets : list Felt) (input_values : list nat)
      (output_assets : list Felt) (output_values : list nat)
      (fee : nat)
      (Hgate_in  : asset_gate primary input_assets)
      (Hgate_out : asset_gate primary output_assets)
      (Htez_lane : acc_tez input_assets input_values
                   = acc_tez output_assets output_values + fee)
      (Hprimary_lane : acc_primary input_assets input_values
                       = acc_primary output_assets output_values) :
    forall a : Felt,
      Spec.Transfer.sum_at a input_assets input_values
      = Spec.Transfer.sum_at a output_assets output_values
        + (if Felt_eq_dec a asset_tez then fee else 0).
  Proof.
    intros a.
    destruct (Felt_eq_dec a asset_tez) as [Hatez | Hantez].
    - (* a = tez: the tez lane *)
      subst a. rewrite <- !acc_tez_is_sum_at. exact Htez_lane.
    - rewrite Nat.add_0_r.
      destruct (Felt_eq_dec a primary) as [Haprim | Hanprim].
      + (* a = primary (and a <> tez): the primary lane *)
        subst a.
        rewrite <- (acc_primary_is_sum_at _ Hantez _ input_values Hgate_in).
        rewrite <- (acc_primary_is_sum_at _ Hantez _ output_values Hgate_out).
        exact Hprimary_lane.
      + (* a outside {tez, primary}: both sides empty *)
        assert (Habs_in : Forall (fun x => x <> a) input_assets).
        { eapply Forall_impl; [| exact Hgate_in].
          cbn. intros x [Hx | Hx]; subst; congruence. }
        assert (Habs_out : Forall (fun x => x <> a) output_assets).
        { eapply Forall_impl; [| exact Hgate_out].
          cbn. intros x [Hx | Hx]; subst; congruence. }
        now rewrite (sum_at_absent_zero _ _ _ Habs_in),
                    (sum_at_absent_zero _ _ _ Habs_out).
  Qed.

  (** *** Corollary in the Spec's vocabulary

      Restates the theorem as the [Spec.Transfer]
      [phi_value_conservation] conjunct of [Phi_transfer], closing
      the value-conservation leg of the
      [TransferRelation -> Phi_transfer] refinement. *)
  Corollary two_accumulator_implies_phi_value_conservation
      (primary : Felt)
      (input_assets : list Felt) (input_values : list nat)
      (output_assets : list Felt) (output_values : list nat)
      (fee : nat) :
    asset_gate primary input_assets ->
    asset_gate primary output_assets ->
    acc_tez input_assets input_values
      = acc_tez output_assets output_values + fee ->
    acc_primary input_assets input_values
      = acc_primary output_assets output_values ->
    Spec.Transfer.phi_value_conservation asset_tez
      input_assets input_values output_assets output_values fee.
  Proof.
    intros Hin Hout Htez Hprim.
    exact (two_accumulator_conservation _ _ _ _ _ _ Hin Hout Htez Hprim).
  Qed.

End TwoAccumulator.

(** ** The Cairo-shaped transfer relation

    [TransferRelation] below is the Rocq model of
    [cairo/src/transfer.cairo::verify], written check-for-check in
    the source order of the Cairo so the two can be compared by eye
    (and, next, by the QCheck2 differential harness).  Conventions:

    - One [CairoInput] record bundles the per-input witness columns
      that Cairo passes as parallel [Span]s; the bundling IS the
      Cairo length-equality asserts (a record row cannot be
      ragged).  Same for the four positional [CairoOutput]s.
    - Values the circuit RECOMPUTES from the witness ([nk_tag],
      [otag], [rcm], the input [cm]) are definitions over the
      record, not fields — mirroring that Cairo never trusts them
      from the prover.
    - Hash families, the u64→felt embedding, and the WOTS digit
      decomposition are section parameters, realized at extraction
      (the same realization style as [Impl.Wots]).

    The headline theorem [transfer_relation_sound] discharges the
    [Relation -> Phi] obligation for every conjunct of
    [Spec.Transfer.Phi_transfer].  Per-input Merkle inclusion and
    XMSS verification are carried inside the relation (they are the
    Cairo asserts) but [Phi_transfer] deliberately does not restate
    them — their soundness consequences (binding, uniqueness) live
    in [Spec.Merkle] / [Spec.Xmss]. *)

From Spec Require Merkle Xmss Hashes.

Section TransferRelation.

  (** Hash families — same shapes as [Spec.Transfer.PhiTransfer]. *)
  Variable H_sighash : Felt -> Felt -> Felt.
  Variable H_commit : Felt -> Felt -> Felt -> Felt -> Felt -> Felt.
  Variable H_nf : Felt -> Felt -> Felt.
  Variable H_owner : Felt -> Felt -> Felt -> Felt.
  Variable H_rcm : Felt -> Felt.            (* derive_rcm *)
  Variable H_nktag : Felt -> Felt.          (* derive_nk_tag *)
  (** Commitment-tree node hash ([blake_hash::hash2], mrkl domain). *)
  Variable H_merkle : Felt -> Felt -> Felt.
  (** Auth-tree node hash: [xmss_node_hash(pub_seed, TAG_XMSS_TREE,
      0, level, node_idx, l, r)].  Takes [pub_seed] explicitly since
      it is a per-input witness value. *)
  Variable H_tree_node : Felt -> nat -> nat -> Felt -> Felt -> Felt.
  (** L-tree node hash: [xmss_node_hash(pub_seed, TAG_XMSS_LTREE,
      key_idx, level, node_idx, l, r)] — note the extra [key_idx]
      slot that domain-separates it from the auth tree. *)
  Variable H_ltree_node : Felt -> nat -> nat -> nat -> Felt -> Felt -> Felt.
  (** WOTS chain step [F pub_seed adrs x] and its ADRS encoding. *)
  Variable F_chain : Felt -> Felt -> Felt -> Felt.
  Variable ADRS_chain : nat -> nat -> nat -> Felt.

  Variable asset_tez : Felt.
  (** Sighash type tag 0x01 as a felt. *)
  Variable tag_transfer_felt : Felt.
  (** The u64 → felt embedding Cairo gets via [v.into()]. *)
  Variable felt_of_nat : nat -> Felt.
  (** [sighash_to_wots_digits]: felt → 133 base-4 digits. *)
  Variable wots_digits : Felt -> list nat.

  (** Per-input witness — one row of Cairo's parallel spans. *)
  Record CairoInput : Type := mkCairoInput {
    ci_nf              : Felt;       (* public: nf_list[i] *)
    ci_nk_spend        : Felt;
    ci_auth_root       : Felt;
    ci_pub_seed        : Felt;
    ci_auth_idx        : nat;
    ci_d_j             : Felt;
    ci_v               : nat;
    ci_rseed           : Felt;
    ci_pos             : nat;        (* cm_path_indices[i] *)
    ci_asset           : Felt;
    ci_merkle_siblings : list Felt;
    ci_auth_siblings   : list Felt;
    ci_wots_sig        : list Felt;
  }.

  (** Cairo recomputes — never trusts — these:
        [let nk_tag = derive_nk_tag(nk_spend);
         let otag = owner_tag(auth_root, auth_pub_seed, nk_tag);
         let rcm = derive_rcm(rseed);
         let cm = commit(d_j, v, asset_i, rcm, otag);] *)
  Definition ci_otag (c : CairoInput) : Felt :=
    H_owner (ci_auth_root c) (ci_pub_seed c) (H_nktag (ci_nk_spend c)).
  Definition ci_rcm (c : CairoInput) : Felt := H_rcm (ci_rseed c).
  Definition ci_cm (c : CairoInput) : Felt :=
    H_commit (ci_d_j c) (felt_of_nat (ci_v c)) (ci_asset c)
             (ci_rcm c) (ci_otag c).

  (** Per-output witness — output slot k's fields.  [co_cm] and
      [co_memo] are public; the rest is witness.  Cairo takes the
      recipient's [nk_tag] directly (the sender cannot know
      [nk_spend]), unlike inputs where it is derived. *)
  Record CairoOutput : Type := mkCairoOutput {
    co_cm        : Felt;             (* public *)
    co_d_j       : Felt;
    co_v         : nat;
    co_rseed     : Felt;
    co_auth_root : Felt;
    co_pub_seed  : Felt;
    co_nk_tag    : Felt;
    co_memo      : Felt;             (* public *)
    co_asset     : Felt;
  }.

  Definition co_otag (o : CairoOutput) : Felt :=
    H_owner (co_auth_root o) (co_pub_seed o) (co_nk_tag o).
  Definition co_rcm (o : CairoOutput) : Felt := H_rcm (co_rseed o).

  (** The output-side commitment equation
      [assert(hash::commit(d_j_k, v_k, asset_k, rcm_k, otag_k) == cm_k)]. *)
  Definition output_cm_ok (o : CairoOutput) : Prop :=
    co_cm o = H_commit (co_d_j o) (felt_of_nat (co_v o)) (co_asset o)
                       (co_rcm o) (co_otag o).

  (** The sighash fold, in Cairo's exact order:
      [fold(0x01, auth_domain, root, nf_0..nf_{n-1}, fee,
            cm_1, cm_2, cm_3, cm_4, mh_1, mh_2, mh_3, mh_4)]. *)
  Definition relation_sighash
      (auth_domain root : Felt) (nfs : list Felt) (fee : nat)
      (o1 o2 o3 o4 : CairoOutput) : Felt :=
    Spec.Hashes.sighash_fold H_sighash
      (Spec.Hashes.sighash_fold H_sighash tag_transfer_felt
         (auth_domain :: root :: nfs))
      [felt_of_nat fee;
       co_cm o1; co_cm o2; co_cm o3; co_cm o4;
       co_memo o1; co_memo o2; co_memo o3; co_memo o4].

  (** Per-input checks, in Cairo's order inside the input loop. *)
  Definition input_checks
      (root sighash : Felt) (primary : Felt) (c : CairoInput) : Prop :=
    (* [assert(asset_i == ASSET_TEZ || asset_i == primary, ...)] *)
    (ci_asset c = asset_tez \/ ci_asset c = primary)
    (* [merkle::verify(cm, root, siblings, path_idx)] *)
    /\ Spec.Xmss.merkle_verify H_merkle
         (ci_cm c) root (ci_merkle_siblings c) (ci_pos c)
    (* [xmss_recover_pk] → [xmss_ltree] → [xmss_verify_auth] *)
    /\ Spec.Xmss.xmss_verify_cairo_sep
         (H_tree_node (ci_pub_seed c))
         (H_ltree_node (ci_pub_seed c) (ci_auth_idx c))
         F_chain ADRS_chain
         (ci_pub_seed c) (ci_auth_idx c)
         (wots_digits sighash) (ci_wots_sig c)
         (ci_auth_siblings c) (ci_auth_root c)
    (* [assert(nf == *nf_list.at(i), 'transfer: bad nf')] *)
    /\ ci_nf c = Spec.Hashes.nullifier H_nf
                   (ci_nk_spend c) (ci_cm c) (felt_of_nat (ci_pos c)).

  (** The full relation — [cairo/src/transfer.cairo::verify].
      Conjuncts in Cairo source order. *)
  Definition TransferRelation
      (auth_domain root : Felt) (fee : nat)
      (primary : Felt)             (* primary_non_tez_asset witness *)
      (inputs : list CairoInput)
      (o1 o2 o3 o4 : CairoOutput)  (* recipient, change_1, change_2, producer *)
    : Prop :=
    let sighash := relation_sighash auth_domain root
                     (map ci_nf inputs) fee o1 o2 o3 o4 in
    (* [assert(n >= 1)], [assert(n <= MAX_INPUTS)] *)
    (1 <= length inputs <= 7)
    (* [assert(asset_4 == ASSET_TEZ, 'transfer: producer must be tez')] *)
    /\ co_asset o4 = asset_tez
    (* the input loop *)
    /\ Forall (input_checks root sighash primary) inputs
    (* output asset gates for slots 1-3 *)
    /\ (co_asset o1 = asset_tez \/ co_asset o1 = primary)
    /\ (co_asset o2 = asset_tez \/ co_asset o2 = primary)
    /\ (co_asset o3 = asset_tez \/ co_asset o3 = primary)
    (* the four output commitment equations *)
    /\ output_cm_ok o1 /\ output_cm_ok o2
    /\ output_cm_ok o3 /\ output_cm_ok o4
    (* [assert(v_4 > 0_u64, 'transfer prod fee')] *)
    /\ co_v o4 > 0
    (* the two accumulator equations *)
    /\ acc_tez asset_tez (map ci_asset inputs) (map ci_v inputs)
       = acc_tez asset_tez
           [co_asset o1; co_asset o2; co_asset o3; co_asset o4]
           [co_v o1; co_v o2; co_v o3; co_v o4] + fee
    /\ acc_primary asset_tez (map ci_asset inputs) (map ci_v inputs)
       = acc_primary asset_tez
           [co_asset o1; co_asset o2; co_asset o3; co_asset o4]
           [co_v o1; co_v o2; co_v o3; co_v o4].

  (** Views into the Spec records: how a Cairo witness row presents
      to [Phi_transfer]. *)
  Definition input_view (c : CairoInput) : Spec.Transfer.InputData :=
    Spec.Transfer.mkInput
      (ci_cm c) (ci_d_j c) (felt_of_nat (ci_v c)) (ci_v c)
      (ci_asset c) (ci_rcm c) (ci_otag c)
      (ci_nk_spend c) (felt_of_nat (ci_pos c)) (ci_nf c).

  Definition output_view (o : CairoOutput) : Spec.Transfer.OutputData :=
    Spec.Transfer.mkOutput
      (co_cm o) (co_d_j o) (felt_of_nat (co_v o)) (co_v o)
      (co_asset o) (co_rcm o) (co_otag o) (co_memo o).

  (** *** Soundness: the Cairo relation implies the Spec predicate. *)
  Theorem transfer_relation_sound
      (auth_domain root : Felt) (fee : nat) (primary : Felt)
      (inputs : list CairoInput) (o1 o2 o3 o4 : CairoOutput) :
    TransferRelation auth_domain root fee primary inputs o1 o2 o3 o4 ->
    Spec.Transfer.Phi_transfer H_sighash H_commit H_nf asset_tez
      (relation_sighash auth_domain root (map ci_nf inputs) fee o1 o2 o3 o4)
      auth_domain root tag_transfer_felt (felt_of_nat fee) fee
      (map input_view inputs)
      (output_view o1) (output_view o2) (output_view o3) (output_view o4).
  Proof.
    intros (Hcount & Hprod_tez & Hloop & Hg1 & Hg2 & Hg3
            & Hcm1 & Hcm2 & Hcm3 & Hcm4 & Hfee_pos & Htez & Hprim).
    unfold Spec.Transfer.Phi_transfer.
    repeat apply conj.
    - (* phi_input_count: 1 <= n *)
      rewrite length_map. apply Hcount.
    - (* phi_input_count: n <= 7 *)
      rewrite length_map. apply Hcount.
    - (* input lists parallel *)
      unfold Spec.Transfer.phi_input_lists_parallel.
      now rewrite !length_map.
    - (* output lists parallel *)
      reflexivity.
    - (* per-input commitment well-formedness: definitional — the
         relation COMPUTES the cm from the witness *)
      rewrite Forall_map. apply Forall_forall. intros c _.
      reflexivity.
    - (* per-input nullifier correctness: the loop's nf assert *)
      rewrite Forall_map.
      eapply Forall_impl; [| exact Hloop].
      intros c (_ & _ & _ & Hnf). exact Hnf.
    - (* per-output commitment well-formedness: the four asserts *)
      repeat constructor; assumption.
    - (* per-asset value conservation: the two-accumulator theorem *)
      unfold Spec.Transfer.phi_value_conservation.
      intros a. cbn [map Spec.Transfer.out_asset Spec.Transfer.out_v
                     Spec.Transfer.in_asset Spec.Transfer.in_v
                     input_view output_view].
      rewrite !map_map. cbn.
      apply (two_accumulator_conservation asset_tez primary
               (map ci_asset inputs) (map ci_v inputs)
               [co_asset o1; co_asset o2; co_asset o3; co_asset o4]
               [co_v o1; co_v o2; co_v o3; co_v o4]
               fee).
      + (* input gate, extracted from the loop conjunct *)
        unfold asset_gate. rewrite Forall_map.
        eapply Forall_impl; [| exact Hloop].
        intros c (Hgate & _). exact Hgate.
      + (* output gate: slots 1-3 gated, slot 4 pinned to tez *)
        unfold asset_gate.
        apply Forall_cons; [exact Hg1 |].
        apply Forall_cons; [exact Hg2 |].
        apply Forall_cons; [exact Hg3 |].
        apply Forall_cons; [left; exact Hprod_tez |].
        apply Forall_nil.
      + exact Htez.
      + exact Hprim.
    - (* sighash completeness: definitional *)
      unfold Spec.Transfer.phi_sighash_complete, relation_sighash.
      cbn. now rewrite map_map.
    - (* producer asset pinned to tez *)
      exact Hprod_tez.
    - (* producer fee positive *)
      exact Hfee_pos.
  Qed.

End TransferRelation.
