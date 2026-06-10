(** * Impl.Transfer

    Mirror of [cairo/src/transfer.cairo].

    The Cairo file implements the [N -> 3] transfer relation: spend
    [N] (1 ≤ N ≤ 7) input notes, produce three output commitments
    (recipient, change, producer-fee). For each input [i], it checks:
    - the input note's commitment is Merkle-included in [root]
      (via [Tzel.Merkle]),
    - the published nullifier is correctly derived from the witness,
    - a one-time WOTS+ signature under the auth tree leaf at the
      claimed index verifies the sighash (via [Tzel.Xmss]).

    For each output [j ∈ {1,2,3}], it checks the commitment is
    well-formed: [cm_j = H_commit(d_j, v_j, rcm(rseed_j), otag_j)].

    It then checks value conservation:
    [sum_in = v_1 + v_2 + v_3 + fee].

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

    Status: safety predicate defined in [Spec.Transfer];
    implementation-side refinement pending.
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
