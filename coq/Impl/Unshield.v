(** * Impl.Unshield

    Mirror of [cairo/src/unshield.cairo].

    Unshield consumes [N] (1 ≤ N ≤ 7) input notes, emits an L1 outbox
    transfer of [v_pub] units of [asset_pub] to a tz/KT1 recipient
    (the kernel routes the burn through the ticketer registered for
    [asset_pub]; tez exits go out as mutez), creates up to two
    private change notes (one per asset lane under the
    two-accumulator design), and creates a producer-fee note
    (pinned to tez). The
    structure mirrors transfer for the input side (Merkle inclusion
    + nullifier + WOTS+ verification per input) but the outputs differ:
    one public exit, two optional change slots, one producer fee.

    Soundness target:

      unshield_sound:
        UnshieldRelation pub wit ->
        Phi_unshield pub

    where [Phi_unshield pub] enumerates the per-input authenticity
    obligations from transfer, plus output well-formedness and the
    per-asset balance: for every asset [a],
    [sum_in(a) = sum_out(a) + v_pub·[a = asset_pub] + fee·[a = tez]]
    ([Spec.Unshield.phi_unshield_value_conservation]).

    The L1-side authorization (that the outbox transfer is honored
    by the kernel and L1) is a kernel-level property, not in scope
    here. The circuit-side obligation is "the spend authorization
    is bound to the specific recipient and amount published as
    public outputs," which the sighash already captures.

    Status: safety predicate defined in [Spec.Unshield]; the
    value-conservation leg of the refinement is PROVED below
    ([unshield_two_accumulator_conservation]); the full
    Cairo-shaped [UnshieldRelation] and assembled [Relation -> Phi]
    theorem are pending.
*)

From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Merkle.
From Impl Require Import Wots.
From Impl Require Import Xmss.
From Spec Require Unshield.

From Impl Require Transfer.
From Stdlib Require Import List Arith Lia.
Import ListNotations.

(** ** The two-accumulator balance scheme, unshield variant

    [cairo/src/unshield.cairo] uses the same two-accumulator strategy
    as transfer (see [Impl.Transfer]), with one extra contribution:
    the public exit [v_pub] is routed into the lane selected by
    [asset_pub]:

      [if asset_pub == ASSET_TEZ { tez_out += v_pub }
       else { primary_out += v_pub }]

    guarded by [assert(asset_pub == ASSET_TEZ || asset_pub ==
    primary_non_tez_asset)].  We model the exit as one additional
    output entry [(asset_pub, v_pub)] prepended to the private output
    lists — [Impl.Transfer.acc_tez (asset_pub :: outs) (v_pub :: vals)]
    computes exactly the Cairo [tez_out] total, and likewise for the
    primary lane.

    ** Phase E.5 / bug #1.  The [Hgate_exit] hypothesis below is the
    constraint the buggy pre-E.5 circuit was missing: it
    unconditionally added [v_pub] to [tez_out] regardless of
    [asset_pub].  Under that (broken) routing, the tez-lane equation
    for an FA2 exit balances against TEZ inputs, so a prover holding
    only tez notes could mint an FA2 exit on L1.  Formally: without
    [Hgate_exit] (and with the broken routing) the conclusion below
    is not derivable — [sum_at asset_pub] of the inputs can be 0
    while the exit contributes [v_pub > 0].  The fixed circuit's
    gate + per-lane routing is what this corollary certifies. *)

Section UnshieldTwoAccumulator.

  Variable asset_tez : Felt.

  (** [if x = y] and [if y = x] over decidable Felt equality agree. *)
  Lemma if_felt_eq_dec_sym (x y : Felt) (v : nat) :
    (if Felt_eq_dec x y then v else 0)
    = (if Felt_eq_dec y x then v else 0).
  Proof.
    destruct (Felt_eq_dec x y) as [He | Hn];
      destruct (Felt_eq_dec y x) as [He' | Hn'];
      congruence.
  Qed.

  Corollary unshield_two_accumulator_conservation
      (primary asset_pub : Felt)
      (input_assets : list Felt) (input_values : list nat)
      (output_assets : list Felt) (output_values : list nat)
      (v_pub fee : nat)
      (* per-entry gates: inputs, private outputs, and the exit *)
      (Hgate_in  : Impl.Transfer.asset_gate asset_tez primary input_assets)
      (Hgate_out : Impl.Transfer.asset_gate asset_tez primary output_assets)
      (Hgate_exit : asset_pub = asset_tez \/ asset_pub = primary)
      (* the two accumulator equations, with the exit folded in *)
      (Htez_lane :
        Impl.Transfer.acc_tez asset_tez input_assets input_values
        = Impl.Transfer.acc_tez asset_tez
            (asset_pub :: output_assets) (v_pub :: output_values) + fee)
      (Hprimary_lane :
        Impl.Transfer.acc_primary asset_tez input_assets input_values
        = Impl.Transfer.acc_primary asset_tez
            (asset_pub :: output_assets) (v_pub :: output_values)) :
    Spec.Unshield.phi_unshield_value_conservation asset_tez
      input_assets input_values output_assets output_values
      v_pub asset_pub fee.
  Proof.
    intros a.
    pose proof (Impl.Transfer.two_accumulator_conservation
                  asset_tez primary
                  input_assets input_values
                  (asset_pub :: output_assets) (v_pub :: output_values)
                  fee
                  Hgate_in
                  (Forall_cons _ Hgate_exit Hgate_out)
                  Htez_lane Hprimary_lane a) as H.
    simpl in H.
    rewrite H, (if_felt_eq_dec_sym asset_pub a). lia.
  Qed.

End UnshieldTwoAccumulator.

(** ** The Cairo-shaped unshield relation

    [UnshieldRelation] is the Rocq model of
    [cairo/src/unshield.cairo::verify], in Cairo source order —
    the unshield counterpart of [Impl.Transfer.TransferRelation]
    (see that module for the modeling conventions).  The input
    loop is IDENTICAL to transfer's, so the per-input predicate
    [Impl.Transfer.input_checks] is reused verbatim — only the
    sighash fed to the WOTS verification differs.

    Unshield-specific shape:
    - a public exit [(v_pub, asset_pub, recipient)] instead of a
      recipient slot;
    - two OPTIONAL change slots ([change_commitment_or_zero]: an
      absent slot publishes literal 0 and zero-asserts every
      witness field);
    - a mandatory producer-fee slot pinned to tez;
    - the same two-accumulator balance with [v_pub] routed by
      [asset_pub] (the Phase E.5 fix). *)

Section UnshieldRelation.

  Variable H_sighash : Felt -> Felt -> Felt.
  Variable H_commit : Felt -> Felt -> Felt -> Felt -> Felt -> Felt.
  Variable H_nf : Felt -> Felt -> Felt.
  Variable H_owner : Felt -> Felt -> Felt -> Felt.
  Variable H_rcm : Felt -> Felt.
  Variable H_nktag : Felt -> Felt.
  Variable H_merkle : Felt -> Felt -> Felt.
  Variable H_tree_node : Felt -> nat -> nat -> Felt -> Felt -> Felt.
  Variable H_ltree_node : Felt -> nat -> nat -> nat -> Felt -> Felt -> Felt.
  Variable F_chain : Felt -> Felt -> Felt -> Felt.
  Variable ADRS_chain : nat -> nat -> nat -> Felt.

  Variable asset_tez : Felt.
  (** Sighash type tag 0x02 as a felt. *)
  Variable tag_unshield_felt : Felt.
  (** The felt 0 published for an absent change slot. *)
  Variable felt_zero : Felt.
  Variable felt_of_nat : nat -> Felt.
  Variable wots_digits : Felt -> list nat.

  (** Local abbreviations over the shared transfer-relation pieces. *)
  Notation CairoInput := Impl.Transfer.CairoInput.
  Notation CairoOutput := Impl.Transfer.CairoOutput.
  Notation ci_nf := Impl.Transfer.ci_nf.
  Notation ci_asset := Impl.Transfer.ci_asset.
  Notation ci_v := Impl.Transfer.ci_v.
  Notation co_cm := Impl.Transfer.co_cm.
  Notation co_v := Impl.Transfer.co_v.
  Notation co_memo := Impl.Transfer.co_memo.
  Notation co_asset := Impl.Transfer.co_asset.

  Definition u_input_checks :=
    Impl.Transfer.input_checks
      H_commit H_nf H_owner H_rcm H_nktag H_merkle
      H_tree_node H_ltree_node F_chain ADRS_chain
      asset_tez felt_of_nat wots_digits.

  Definition u_output_cm_ok :=
    Impl.Transfer.output_cm_ok H_commit H_owner H_rcm felt_of_nat.

  Definition u_input_view :=
    Impl.Transfer.input_view H_commit H_owner H_rcm H_nktag felt_of_nat.

  Definition u_output_view :=
    Impl.Transfer.output_view H_owner H_rcm felt_of_nat.

  (** [change_commitment_or_zero]: when [has] is set the slot is a
      well-formed commitment; otherwise the published cm is literal
      0 and EVERY witness field is zero-asserted (eight asserts in
      the Cairo [else] branch).  [co_asset o = asset_tez] mirrors
      [assert(asset_change == 0, ...)]: the Cairo constant
      [ASSET_TEZ] is that same literal 0. *)
  Definition change_slot_checks (has : bool) (o : CairoOutput) : Prop :=
    if has then u_output_cm_ok o
    else co_cm o = felt_zero
         /\ co_v o = 0
         /\ co_memo o = felt_zero
         /\ Impl.Transfer.co_d_j o = felt_zero
         /\ Impl.Transfer.co_rseed o = felt_zero
         /\ Impl.Transfer.co_auth_root o = felt_zero
         /\ Impl.Transfer.co_pub_seed o = felt_zero
         /\ Impl.Transfer.co_nk_tag o = felt_zero
         /\ co_asset o = asset_tez.

  (** The sighash fold, in Cairo's exact order — note the
      INTERLEAVED (cm, memo) pairs, unlike transfer's grouped
      layout:
      [fold(0x02, auth_domain, root, nf_0..nf_{n-1}, v_pub,
            asset_pub, fee, recipient, cm_change, mh_change,
            cm_change_2, mh_change_2, cm_fee, mh_fee)]. *)
  Definition u_relation_sighash
      (auth_domain root : Felt) (nfs : list Felt)
      (v_pub : nat) (asset_pub : Felt) (fee : nat) (recipient : Felt)
      (c1 c2 p : CairoOutput) : Felt :=
    Spec.Hashes.sighash_fold H_sighash
      (Spec.Hashes.sighash_fold H_sighash tag_unshield_felt
         (auth_domain :: root :: nfs))
      [felt_of_nat v_pub; asset_pub; felt_of_nat fee; recipient;
       co_cm c1; co_memo c1;
       co_cm c2; co_memo c2;
       co_cm p;  co_memo p].

  (** The full relation — [cairo/src/unshield.cairo::verify],
      conjuncts in Cairo source order. *)
  Definition UnshieldRelation
      (auth_domain root : Felt)
      (v_pub : nat) (asset_pub : Felt) (fee : nat) (recipient : Felt)
      (primary : Felt)
      (inputs : list CairoInput)
      (has_change_1 has_change_2 : bool)
      (c1 c2 p : CairoOutput)   (* change_1, change_2, producer *)
    : Prop :=
    let sighash := u_relation_sighash auth_domain root
                     (map ci_nf inputs) v_pub asset_pub fee recipient
                     c1 c2 p in
    (* [assert(n >= 1)], [assert(n <= MAX_INPUTS)] *)
    (1 <= length inputs <= 7)
    (* [assert(asset_fee == ASSET_TEZ, 'unshield: producer must be tez')] *)
    /\ co_asset p = asset_tez
    (* [change_commitment_or_zero] for both change slots *)
    /\ change_slot_checks has_change_1 c1
    /\ change_slot_checks has_change_2 c2
    (* producer commitment equation (computed inline in Cairo) *)
    /\ u_output_cm_ok p
    (* change-slot asset gates *)
    /\ (co_asset c1 = asset_tez \/ co_asset c1 = primary)
    /\ (co_asset c2 = asset_tez \/ co_asset c2 = primary)
    (* the input loop — identical to transfer's *)
    /\ Forall (u_input_checks root sighash primary) inputs
    (* [assert(v_fee > 0_u64, 'unshield prod fee')] *)
    /\ co_v p > 0
    (* [assert(asset_pub == ASSET_TEZ || asset_pub == primary, ...)] —
       the Phase E.5 fix *)
    /\ (asset_pub = asset_tez \/ asset_pub = primary)
    (* the two accumulator equations, exit folded into the out lists *)
    /\ Impl.Transfer.acc_tez asset_tez
         (map ci_asset inputs) (map ci_v inputs)
       = Impl.Transfer.acc_tez asset_tez
           (asset_pub :: [co_asset c1; co_asset c2; co_asset p])
           (v_pub     :: [co_v c1; co_v c2; co_v p]) + fee
    /\ Impl.Transfer.acc_primary asset_tez
         (map ci_asset inputs) (map ci_v inputs)
       = Impl.Transfer.acc_primary asset_tez
           (asset_pub :: [co_asset c1; co_asset c2; co_asset p])
           (v_pub     :: [co_v c1; co_v c2; co_v p]).

  (** *** Soundness: the Cairo relation implies the Spec predicate. *)
  Theorem unshield_relation_sound
      (auth_domain root recipient : Felt)
      (v_pub fee : nat) (asset_pub primary : Felt)
      (inputs : list CairoInput)
      (has_change_1 has_change_2 : bool)
      (c1 c2 p : CairoOutput) :
    UnshieldRelation auth_domain root v_pub asset_pub fee recipient
                     primary inputs has_change_1 has_change_2 c1 c2 p ->
    Spec.Unshield.Phi_unshield H_sighash H_commit H_nf asset_tez felt_zero
      (u_relation_sighash auth_domain root (map ci_nf inputs)
         v_pub asset_pub fee recipient c1 c2 p)
      auth_domain root tag_unshield_felt (felt_of_nat fee)
      (felt_of_nat v_pub) asset_pub recipient fee v_pub
      (map u_input_view inputs)
      (u_output_view c1) (u_output_view c2) (u_output_view p).
  Proof.
    intros (Hcount & Hprod_tez & Hslot1 & Hslot2 & Hcmp & Hg1 & Hg2
            & Hloop & Hfee_pos & Hgate_exit & Htez & Hprim).
    unfold Spec.Unshield.Phi_unshield.
    repeat apply conj.
    - (* input count: 1 <= n *)
      rewrite length_map. apply Hcount.
    - (* input count: n <= 7 *)
      rewrite length_map. apply Hcount.
    - (* input lists parallel *)
      unfold Spec.Unshield.phi_unshield_input_lists_parallel.
      now rewrite !length_map.
    - (* output lists parallel *)
      reflexivity.
    - (* per-input commitment well-formedness: definitional *)
      rewrite Forall_map. apply Forall_forall. intros c _.
      reflexivity.
    - (* per-input nullifier correctness: from the loop *)
      rewrite Forall_map.
      eapply Forall_impl; [| exact Hloop].
      intros c (_ & _ & _ & Hnf). exact Hnf.
    - (* producer commitment well-formedness *)
      exact Hcmp.
    - (* change slot 1: present or absent *)
      destruct has_change_1; cbn in Hslot1.
      + left. exact Hslot1.
      + right.
        destruct Hslot1 as (Hcm & Hv & Hmh & _ & _ & _ & _ & _ & Hasset).
        exact (conj Hcm (conj Hmh (conj Hasset Hv))).
    - (* change slot 2 *)
      destruct has_change_2; cbn in Hslot2.
      + left. exact Hslot2.
      + right.
        destruct Hslot2 as (Hcm & Hv & Hmh & _ & _ & _ & _ & _ & Hasset).
        exact (conj Hcm (conj Hmh (conj Hasset Hv))).
    - (* per-asset value conservation: the two-accumulator corollary *)
      cbn [map Spec.Transfer.out_asset Spec.Transfer.out_v
           Spec.Transfer.in_asset Spec.Transfer.in_v].
      rewrite !map_map. cbn.
      apply (unshield_two_accumulator_conservation asset_tez primary
               asset_pub
               (map ci_asset inputs) (map ci_v inputs)
               [co_asset c1; co_asset c2; co_asset p]
               [co_v c1; co_v c2; co_v p]
               v_pub fee).
      + (* input gate, from the loop conjunct *)
        unfold Impl.Transfer.asset_gate. rewrite Forall_map.
        eapply Forall_impl; [| exact Hloop].
        intros c (Hgate & _). exact Hgate.
      + (* private-output gate: c1, c2 gated; producer pinned tez *)
        unfold Impl.Transfer.asset_gate.
        apply Forall_cons; [exact Hg1 |].
        apply Forall_cons; [exact Hg2 |].
        apply Forall_cons; [left; exact Hprod_tez |].
        apply Forall_nil.
      + (* exit gate: the Phase E.5 assert *)
        exact Hgate_exit.
      + exact Htez.
      + exact Hprim.
    - (* sighash completeness: definitional, interleaved order *)
      unfold Spec.Unshield.phi_unshield_sighash, u_relation_sighash.
      cbn. now rewrite map_map.
    - (* exit asset registered: lifted to the kernel, stub conjunct *)
      exact I.
    - (* producer asset pinned to tez *)
      exact Hprod_tez.
    - (* producer fee positive *)
      exact Hfee_pos.
  Qed.

End UnshieldRelation.
