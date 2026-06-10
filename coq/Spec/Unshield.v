(** * Spec.Unshield — unshield circuit safety predicate (multiasset)

    Source: [cairo/src/unshield.cairo::verify] (pre-multiasset:
    16 + 7 assertions).

    Unshield withdraws funds from the private pool to L1.  It
    consumes [N] (1 ≤ N ≤ 7) input notes and produces (multiasset):

    - A public L1 exit of [v_pub] mutez of asset [asset_pub] to
      [recipient].  In v1 [asset_pub = tez] is forced because the
      tez bridge is the only bridge.
    - Two private change-slot notes [cm_change_1], [cm_change_2]
      (mirroring transfer's two change slots), free to hold any
      asset the input balance supports.  Either may be a zero-value
      placeholder.
    - A mandatory producer-fee note [cm_producer] pinned to
      [asset = tez].

    Input side mirrors transfer: per-input Merkle inclusion,
    nullifier derivation, XMSS signature verification, and each
    input carries a private asset tag.

    ** Per-asset balance.  For every asset [α]:

      sum_{i : input_asset_i = α} v_i
        = (output side at α)
        + (if α = tez then v_pub + fee_public else 0)

    where "output side at α" sums the change-slot and producer-fee
    contributions whose asset equals α.

    Sighash uses tag 0x02 to prevent cross-circuit replay.
*)

From Stdlib Require Import List Arith.
Import ListNotations.
From Common Require Import Felt.
From Spec Require Import Hashes.
From Spec Require Import Transfer.

Section PhiUnshield.

  Variable H_sighash : Felt -> Felt -> Felt.
  Variable H_commit : Felt -> Felt -> Felt -> Felt -> Felt -> Felt.
  Variable H_nf : Felt -> Felt -> Felt.
  Variable H_owner : Felt -> Felt -> Felt -> Felt.
  Variable H_rcm : Felt -> Felt.

  (** Canonical tez asset tag. *)
  Variable asset_tez : Felt.

  (** The published placeholder for an ABSENT change slot.  Cairo's
      [change_commitment_or_zero] returns literal felt [0] (and
      zero-asserts every witness field) when [has_change] is false.
      Realized as 0 — the same value [asset_tez] is realized at, but
      kept a separate symbol: one is an asset tag, the other a
      published "no commitment here" marker. *)
  Variable felt_zero : Felt.

  (** 1. Per-asset value conservation.

      Inputs: parallel lists [(input_assets, input_values)].
      Outputs: parallel lists [(output_assets, output_values)] that
      enumerate the change-slot notes and the producer-fee note
      (three entries total: change_1, change_2, producer).
      Public side: [(v_pub, asset_pub)] for the L1 exit and [fee] for
      the rollup-burned tez fee.

      Cairo (multiasset): per-asset accumulators for tez and the
      witness-supplied "primary non-tez asset"; final equality
      assertion per accumulator.  Implies this semantic predicate. *)
  Definition phi_unshield_value_conservation
      (input_assets : list Felt) (input_values : list nat)
      (output_assets : list Felt) (output_values : list nat)
      (v_pub : nat) (asset_pub : Felt)
      (fee : nat) : Prop :=
    forall a : Felt,
      sum_at a input_assets input_values
      = sum_at a output_assets output_values
        + (if Felt_eq_dec a asset_pub then v_pub else 0)
        + (if Felt_eq_dec a asset_tez then fee else 0).

  (** 2. Nullifier correctness (per input).
      Cairo: [assert(nf == *nf_list.at(i), 'unshield: bad nf')]. *)
  Definition phi_unshield_nullifier := phi_nullifier_correct.

  (** 3. Producer fee positive.
      Cairo: [assert(v_fee > 0_u64, 'unshield prod fee')]. *)
  Definition phi_unshield_fee_positive (v_fee : nat) : Prop :=
    v_fee > 0.

  (** 4. Input count in range.
      Cairo: [assert(n >= 1)] and [assert(n <= MAX_INPUTS)]. *)
  Definition phi_unshield_input_count := phi_input_count.

  (** 5. (Lifted in Phase E.5.) The public exit asset = tez pin was
      removed when bug #1 (Cairo unshield [v_pub] lane-routing
      bypass) was fixed.  Pre-fix versions of the circuit
      unconditionally added [v_pub] to [tez_out] regardless of
      [asset_pub], which an attacker could exploit to mint FA2
      tokens on L1 backed by other users' tez deposits.  Post-fix,
      [asset_pub] can be any asset in [{ASSET_TEZ, A}] (the
      witness-declared primary non-tez asset), the kernel routes
      the L1 burn through [ticketer_for_asset(asset_pub)], and the
      circuit routes [v_pub] to the correct lane.

      This stub is kept so dependent indices in [Phi_unshield] don't
      shift; it always holds. *)
  Definition phi_unshield_exit_asset_registered (_asset_pub : Felt) : Prop :=
    True.

  (** 6. Producer fee asset = tez.  Permanent constraint. *)
  Definition phi_unshield_producer_asset_tez
      (asset_producer : Felt) : Prop :=
    asset_producer = asset_tez.

  (** 7. Output commitment well-formedness.

      Each of [cm_change_1], [cm_change_2], [cm_producer] is
      reconstructed from witness fields including the asset tag
      (same shape as [Spec.Transfer.phi_output_wellformed]). *)
  Definition phi_unshield_output_wellformed
      (cm d_j v asset rcm owner_tag : Felt) : Prop :=
    cm = H_commit d_j v asset rcm owner_tag.

  (** 7c. Absent change slot.  Cairo's [change_commitment_or_zero]
      publishes [cm = 0] when [has_change] is false and asserts the
      slot is pinned empty: value 0, memo hash 0, every witness
      field 0.  Protocol meaning: an "absent" slot cannot smuggle
      value ([v = 0] makes it contribute nothing to any per-asset
      sum) and cannot deliver a memo.  The asset field is the felt
      0 = ASSET_TEZ (the Cairo constant), recorded here as
      [asset_tez] so the conservation predicate stays well-typed
      over the slot.

      Note the published 0 is NOT a commitment: soundness of the
      "0-cm is never a real note" reading rests on [H_commit] never
      hitting 0, a preimage-style side condition on the hash family
      (kernel-side it is enforced structurally: a zero [cm_change]
      is skipped, never inserted into the tree). *)
  Definition phi_unshield_change_absent
      (cm memo asset : Felt) (v : nat) : Prop :=
    cm = felt_zero /\ memo = felt_zero /\ asset = asset_tez /\ v = 0.

  (** A change slot is either present (well-formed commitment) or
      absent (zero-pinned).  The producer slot has no absent form. *)
  Definition phi_unshield_change_slot
      (cm d_j v_felt asset rcm owner_tag memo : Felt) (v : nat) : Prop :=
    phi_unshield_output_wellformed cm d_j v_felt asset rcm owner_tag
    \/ phi_unshield_change_absent cm memo asset v.

  (** 7b. Input commitment well-formedness (per input).  Same as
      [Spec.Transfer.phi_input_wellformed]; included here for
      symmetry of the Phi assembly.  Binds each input's witness
      [(d_j, v, asset, rcm, otag)] to its [cm], which is then used
      as the leaf in the Merkle inclusion check.  Without this,
      witness values for v / asset are unbound and the per-asset
      balance can be cooked. *)
  Definition phi_unshield_input_wellformed
      (cm d_j v asset rcm owner_tag : Felt) : Prop :=
    cm = H_commit d_j v asset rcm owner_tag.

  (** 8. Sighash completeness.

      Cairo (multiasset): sighash = fold(0x02, auth_domain, root,
      nf_0..nf_{n-1}, v_pub, asset_pub, fee, recipient,
      cm_change_1, cm_change_2, cm_producer,
      memo_change_1, memo_change_2, memo_producer).

      [asset_pub] is included because it is public at L1 (the
      bridge identifies it); change-slot assets are hidden and
      bound only via [cm_*].

      Missing [recipient] would allow redirecting the L1 exit.
      Missing [asset_pub] would allow swapping the exit asset
      after signing (when multi-bridge lands).

      Field ORDER follows the Cairo fold exactly: the (cm, memo)
      pairs are INTERLEAVED per slot ([cm_change, mh_change,
      cm_change_2, mh_change_2, cm_fee, mh_fee]) — an earlier
      draft of this predicate grouped all cms before all memos,
      which is binding-equivalent but would fail a byte-level
      model<->circuit differential. *)
  Definition phi_unshield_sighash
      (sighash tag_felt auth_domain root : Felt)
      (nullifiers : list Felt)
      (v_pub_felt asset_pub fee_felt recipient
       cm_change_1 cm_change_2 cm_producer
       memo_change_1 memo_change_2 memo_producer : Felt) : Prop :=
    sighash = sighash_fold H_sighash
                (sighash_fold H_sighash tag_felt
                   (auth_domain :: root :: nullifiers))
                [v_pub_felt; asset_pub; fee_felt; recipient;
                 cm_change_1; memo_change_1;
                 cm_change_2; memo_change_2;
                 cm_producer; memo_producer].

  (** 9. Input list well-formedness (parallel asset / value lists). *)
  Definition phi_unshield_input_lists_parallel
      (input_assets : list Felt) (input_values : list nat) : Prop :=
    length input_assets = length input_values.

  (** 10. Output list well-formedness (parallel asset / value lists).
      Unshield has exactly 3 private output slots (change_1,
      change_2, producer), so both lists must have length 3; this
      conjunct enforces parallelism, the count invariant is
      Relation-level. *)
  Definition phi_unshield_output_lists_parallel
      (output_assets : list Felt) (output_values : list nat) : Prop :=
    length output_assets = length output_values.

  (** ** Assembled [Phi_unshield]

      Unshield has [N] (1..7) input notes (same shape as transfer),
      3 private output slots (change_1, change_2, producer), and a
      public L1 exit ([v_pub] of [asset_pub] to [recipient]).

      Re-uses [InputData] / [OutputData] from [Spec.Transfer] so the
      structure stays parallel between the two circuits. *)

  Definition Phi_unshield
      (* public *)
      (sighash auth_domain root tag_felt fee_felt
       v_pub_felt asset_pub recipient : Felt)
      (fee v_pub : nat)
      (* witness — inputs *)
      (inputs : list InputData)
      (* witness — 3 private outputs *)
      (out_change_1 out_change_2 out_producer : OutputData)
    : Prop :=
    let n             := length inputs in
    let input_assets  := map in_asset inputs in
    let input_values  := map in_v     inputs in
    let input_nfs     := map in_nf    inputs in
    let outputs := [out_change_1; out_change_2; out_producer] in
    let output_assets := map out_asset outputs in
    let output_values := map out_v     outputs in
    (* structural *)
    phi_unshield_input_count n
    /\ phi_unshield_input_lists_parallel  input_assets  input_values
    /\ phi_unshield_output_lists_parallel output_assets output_values
    (* per-input *)
    /\ Forall (fun i =>
         phi_unshield_input_wellformed
           (in_cm i) (in_d_j i) (in_v_felt i) (in_asset i)
           (in_rcm i) (in_otag i)) inputs
    /\ Forall (fun i =>
         phi_unshield_nullifier H_nf
           (in_nf i) (in_nk_spend i) (in_cm i) (in_pos i)) inputs
    (* per-output: producer is mandatory; the two change slots are
       present-or-absent (Cairo [change_commitment_or_zero]) *)
    /\ phi_unshield_output_wellformed
         (out_cm out_producer) (out_d_j out_producer)
         (out_v_felt out_producer) (out_asset out_producer)
         (out_rcm out_producer) (out_otag out_producer)
    /\ phi_unshield_change_slot
         (out_cm out_change_1) (out_d_j out_change_1)
         (out_v_felt out_change_1) (out_asset out_change_1)
         (out_rcm out_change_1) (out_otag out_change_1)
         (out_memo out_change_1) (out_v out_change_1)
    /\ phi_unshield_change_slot
         (out_cm out_change_2) (out_d_j out_change_2)
         (out_v_felt out_change_2) (out_asset out_change_2)
         (out_rcm out_change_2) (out_otag out_change_2)
         (out_memo out_change_2) (out_v out_change_2)
    (* balance — per-asset with public exit and tez fee *)
    /\ phi_unshield_value_conservation
         input_assets input_values output_assets output_values
         v_pub asset_pub fee
    (* sighash *)
    /\ phi_unshield_sighash
         sighash tag_felt auth_domain root input_nfs
         v_pub_felt asset_pub fee_felt recipient
         (out_cm out_change_1) (out_cm out_change_2) (out_cm out_producer)
         (out_memo out_change_1) (out_memo out_change_2)
         (out_memo out_producer)
    (* asset / fee pins *)
    /\ phi_unshield_exit_asset_registered asset_pub
    /\ phi_unshield_producer_asset_tez    (out_asset out_producer)
    /\ phi_unshield_fee_positive          (out_v     out_producer).

  (** ** Sanity-check consequences of [Phi_unshield]. *)

  Lemma Phi_unshield_input_count
      sighash auth_domain root tag_felt fee_felt
      v_pub_felt asset_pub recipient fee v_pub
      inputs c1 c2 p :
    Phi_unshield sighash auth_domain root tag_felt fee_felt
                 v_pub_felt asset_pub recipient fee v_pub
                 inputs c1 c2 p ->
    1 <= length inputs <= 7.
  Proof. unfold Phi_unshield, phi_unshield_input_count,
                 phi_input_count. tauto. Qed.

  (** Phase E.5 lifted the [asset_pub = asset_tez] pin (bug #1 fix).
      The unshield exit asset is now any registered asset; the
      circuit's per-asset balance routes [v_pub] correctly under
      [phi_unshield_value_conservation_2acc].  Producer tez pin
      still holds. *)

  Lemma Phi_unshield_producer_is_tez_positive
      sighash auth_domain root tag_felt fee_felt
      v_pub_felt asset_pub recipient fee v_pub
      inputs c1 c2 p :
    Phi_unshield sighash auth_domain root tag_felt fee_felt
                 v_pub_felt asset_pub recipient fee v_pub
                 inputs c1 c2 p ->
    out_asset p = asset_tez /\ out_v p > 0.
  Proof.
    unfold Phi_unshield,
           phi_unshield_producer_asset_tez,
           phi_unshield_fee_positive.
    tauto.
  Qed.

  Lemma Phi_unshield_balance
      sighash auth_domain root tag_felt fee_felt
      v_pub_felt asset_pub recipient fee v_pub
      inputs c1 c2 p :
    Phi_unshield sighash auth_domain root tag_felt fee_felt
                 v_pub_felt asset_pub recipient fee v_pub
                 inputs c1 c2 p ->
    forall a : Felt,
      sum_at a (map in_asset inputs) (map in_v inputs)
      = sum_at a
          (map out_asset [c1; c2; p])
          (map out_v     [c1; c2; p])
        + (if Felt_eq_dec a asset_pub then v_pub else 0)
        + (if Felt_eq_dec a asset_tez then fee   else 0).
  Proof.
    unfold Phi_unshield, phi_unshield_value_conservation.
    intros H a.
    destruct H as [_ [_ [_ [_ [_ [_ [_ [_ [Hbal _]]]]]]]]].
    apply Hbal.
  Qed.

End PhiUnshield.

(** ** Unshield non-malleability (signature binds the whole tx)

    The unshield analogue of [Spec.Transfer.transfer_sighash_binds]:
    two accepted unshields sharing a sighash AND input count publish
    byte-identical public outputs — including the L1 exit triple
    [(v_pub, asset_pub, recipient)] that releases real funds, both
    change commitments, the producer commitment, and all memo hashes.

    Concretely discharges the "the malleability argument ports to
    unshield" claim: the proof is the same assembly as transfer,
    differing only in the (interleaved) field layout. *)

Section UnshieldMalleability.

  Variable H_sighash : Felt -> Felt -> Felt.

  Theorem unshield_sighash_binds
      (Hinj : Hashes.injective_2 H_sighash)
      (sighash tag auth_domain auth_domain' root root' : Felt)
      (nfs nfs' : list Felt)
      (vp vp' ap ap' fee fee' rcp rcp' : Felt)
      (c1 c2 cp c1' c2' cp' : Felt)
      (m1 m2 mp m1' m2' mp' : Felt) :
    length nfs = length nfs' ->
    phi_unshield_sighash H_sighash sighash tag auth_domain root nfs
      vp ap fee rcp c1 c2 cp m1 m2 mp ->
    phi_unshield_sighash H_sighash sighash tag auth_domain' root' nfs'
      vp' ap' fee' rcp' c1' c2' cp' m1' m2' mp' ->
    auth_domain = auth_domain' /\ root = root' /\ nfs = nfs'
    /\ vp = vp' /\ ap = ap' /\ fee = fee' /\ rcp = rcp'
    /\ c1 = c1' /\ m1 = m1' /\ c2 = c2' /\ m2 = m2'
    /\ cp = cp' /\ mp = mp'.
  Proof.
    intros Hlen H1 H2.
    unfold phi_unshield_sighash in H1, H2.
    rewrite <- Hashes.sighash_fold_app in H1, H2.
    assert (Heq :
      Hashes.sighash_fold H_sighash tag
        ((auth_domain :: root :: nfs)
         ++ [vp; ap; fee; rcp; c1; m1; c2; m2; cp; mp])
      = Hashes.sighash_fold H_sighash tag
        ((auth_domain' :: root' :: nfs')
         ++ [vp'; ap'; fee'; rcp'; c1'; m1'; c2'; m2'; cp'; mp'])).
    { rewrite <- H1, <- H2. reflexivity. }
    assert (Hlenfull :
      length ((auth_domain :: root :: nfs)
              ++ [vp; ap; fee; rcp; c1; m1; c2; m2; cp; mp])
      = length ((auth_domain' :: root' :: nfs')
              ++ [vp'; ap'; fee'; rcp'; c1'; m1'; c2'; m2'; cp'; mp'])).
    { rewrite !length_app. simpl. rewrite Hlen. reflexivity. }
    pose proof (Hashes.sighash_binds_fields H_sighash Hinj tag _ _ Hlenfull Heq)
      as Hfields.
    simpl in Hfields. injection Hfields as Had Hroot Hrest.
    destruct (Hashes.app_eq_len_l nfs nfs' _ _ Hlen Hrest)
      as [Hnfs Htail].
    injection Htail as Hvp Hap Hfee Hrcp Hc1 Hm1 Hc2 Hm2 Hcp Hmp.
    repeat split; assumption.
  Qed.

End UnshieldMalleability.
