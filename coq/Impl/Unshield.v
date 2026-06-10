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
From Spec Require Merkle.
From Spec Require Xmss.
From Spec Require Hashes.

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

  Lemma u_xmss_honest :
    forall (ps : Felt) (msg : list nat) (sks sib : list Felt) (leaf : Felt),
      length msg = length sks ->
      Forall (fun d => d <= Spec.Hashes.wots_chain_len) msg ->
      Spec.Xmss.ltree (H_ltree_node ps 0)
        (Spec.Xmss.gen_pk F_chain ADRS_chain ps 0 0 sks) = Some leaf ->
      length sib = Spec.Hashes.auth_depth ->
      Spec.Xmss.xmss_verify_cairo_sep
        (H_tree_node ps) (H_ltree_node ps 0) F_chain ADRS_chain ps 0
        msg (Spec.Xmss.sign F_chain ADRS_chain ps 0 0 msg sks) sib
        (Spec.Merkle.auth_root (H_tree_node ps)
           (Spec.Xmss.nat_to_bits Spec.Hashes.auth_depth 0) sib leaf 0 0).
  Proof.
    intros ps msg sks sib leaf Hlen Hbd Hleaf Hsib.
    unfold Spec.Xmss.xmss_verify_cairo_sep.
    rewrite (Spec.Xmss.recover_all_correct F_chain ADRS_chain ps 0 0 msg sks Hlen Hbd).
    rewrite Hleaf.
    unfold Spec.Xmss.auth_verify. split; [exact Hsib | split].
    - assert (2 ^ Spec.Hashes.auth_depth <> 0) by (apply Nat.pow_nonzero; lia). lia.
    - reflexivity.
  Qed.

  Lemma u_sign_len_eq :
    forall (ps : Felt) (ki sc : nat) (digits : list nat) (sks : list Felt),
      length digits = length sks ->
      length (Spec.Xmss.sign F_chain ADRS_chain ps ki sc digits sks) = length digits.
  Proof.
    intros ps ki sc digits. revert sc.
    induction digits as [| d ds IH]; intros sc [| sk rest] Hlen; cbn in *;
      try discriminate Hlen; [reflexivity |].
    f_equal. apply IH. lia.
  Qed.

  (** NON-VACUITY: a single concrete honest unshield satisfies every
      conjunct of [UnshieldRelation] at once (1 tez input spending a
      note in the tree, both change slots absent, a tez producer note,
      and a balanced 2-accumulator), so [unshield_relation_sound] is
      not vacuously true.  [primary <> asset_tez] is the standard
      "primary is a non-tez asset" side condition. *)
  Theorem unshield_relation_inhabited
      (auth_domain recipient primary : Felt) (sks : list Felt)
      (Hsks_len : length sks = Spec.Hashes.wots_chains)
      (Hsks_ne : sks <> nil)
      (Hwd_len : forall sh, length (wots_digits sh) = Spec.Hashes.wots_chains)
      (Hwd_bd : forall sh, Forall (fun d => d <= Spec.Hashes.wots_chain_len) (wots_digits sh)) :
    exists root v_pub asset_pub fee inputs has1 has2 c1 c2 p,
      UnshieldRelation auth_domain root v_pub asset_pub fee recipient primary
                       inputs has1 has2 c1 c2 p.
  Proof.
    pose (z := felt_zero).
    pose (sib := repeat z Spec.Hashes.auth_depth).
    assert (Hgpk : Spec.Xmss.gen_pk F_chain ADRS_chain z 0 0 sks <> nil).
    { destruct sks; [contradiction | cbn [Spec.Xmss.gen_pk]; discriminate]. }
    destruct (Spec.Xmss.ltree_succeeds (H_ltree_node z 0)
                (Spec.Xmss.gen_pk F_chain ADRS_chain z 0 0 sks) Hgpk) as [leaf Hleaf].
    pose (ar := Spec.Merkle.auth_root (H_tree_node z)
                  (Spec.Xmss.nat_to_bits Spec.Hashes.auth_depth 0) sib leaf 0 0).
    pose (icm := H_commit z (felt_of_nat 2) asset_tez (H_rcm z) (H_owner ar z (H_nktag z))).
    pose (root := Spec.Merkle.merkle_root H_merkle
                    (Spec.Xmss.nat_to_bits Spec.Hashes.tree_depth 0)
                    (repeat z Spec.Hashes.tree_depth) icm).
    pose (inf := Spec.Hashes.nullifier H_nf z icm (felt_of_nat 0)).
    pose (c0 := Impl.Transfer.mkCairoOutput z z 0 z z z z z asset_tez).
    pose (pp := Impl.Transfer.mkCairoOutput
                  (H_commit z (felt_of_nat 1) asset_tez (H_rcm z) (H_owner z z z))
                  z 1 z z z z z asset_tez).
    pose (sh := u_relation_sighash auth_domain root (inf :: nil) 0 asset_tez 1 recipient c0 c0 pp).
    pose (inp := Impl.Transfer.mkCairoInput
                   inf z ar z 0 z 2 z 0 asset_tez
                   (repeat z Spec.Hashes.tree_depth) sib
                   (Spec.Xmss.sign F_chain ADRS_chain z 0 0 (wots_digits sh) sks)).
    exists root, 0, asset_tez, 1, (inp :: nil), false, false, c0, c0, pp.
    assert (Hdlen : length (wots_digits sh) = length sks)
      by (rewrite Hwd_len; exact (eq_sym Hsks_len)).
    unfold UnshieldRelation. cbv zeta.
    refine (conj _ (conj _ (conj _ (conj _ (conj _ (conj _ (conj _ (conj _ (conj _ (conj _ (conj _ _))))))))))).
    - (* 1 <= length inputs <= 7 *) cbn [length]. lia.
    - (* co_asset p = tez *) reflexivity.
    - (* change_slot_checks false c0 *) cbn [change_slot_checks]. repeat split; reflexivity.
    - (* change_slot_checks false c0 *) cbn [change_slot_checks]. repeat split; reflexivity.
    - (* u_output_cm_ok p *) reflexivity.
    - (* co_asset c1 in {tez,primary} *) left; reflexivity.
    - (* co_asset c2 in {tez,primary} *) left; reflexivity.
    - (* Forall input_checks *)
      apply Forall_cons; [| apply Forall_nil].
      unfold u_input_checks, Impl.Transfer.input_checks.
      refine (conj _ (conj _ (conj _ _))).
      + (* asset gate *) left. reflexivity.
      + (* merkle_verify *)
        unfold Spec.Xmss.merkle_verify. split; [| split].
        * change (Impl.Transfer.ci_merkle_siblings inp) with (repeat z Spec.Hashes.tree_depth).
          apply repeat_length.
        * assert (2 ^ Spec.Hashes.tree_depth <> 0) by (apply Nat.pow_nonzero; lia).
          change (Impl.Transfer.ci_pos inp) with 0. lia.
        * reflexivity.
      + (* xmss *)
        change (Impl.Transfer.ci_pub_seed inp) with z.
        change (Impl.Transfer.ci_auth_idx inp) with 0.
        change (Impl.Transfer.ci_auth_root inp) with ar.
        change (Impl.Transfer.ci_auth_siblings inp) with sib.
        change (Impl.Transfer.ci_wots_sig inp) with
          (Spec.Xmss.sign F_chain ADRS_chain z 0 0 (wots_digits sh) sks).
        apply (u_xmss_honest z (wots_digits sh) sks sib leaf Hdlen (Hwd_bd sh) Hleaf).
        unfold sib. apply repeat_length.
      + (* nullifier *)
        reflexivity.
    - (* co_v p > 0 *) cbn. lia.
    - (* asset_pub in {tez,primary} *) left; reflexivity.
    - (* acc_tez equation *)
      change (map Impl.Transfer.ci_asset (inp :: nil)) with (asset_tez :: @nil Felt);
      change (map Impl.Transfer.ci_v (inp :: nil)) with (2 :: @nil nat);
      change (Impl.Transfer.co_asset c0) with asset_tez;
      change (Impl.Transfer.co_v c0) with 0;
      change (Impl.Transfer.co_asset pp) with asset_tez;
      change (Impl.Transfer.co_v pp) with 1.
      cbn [Impl.Transfer.acc_tez].
      destruct (Felt.Felt_eq_dec asset_tez asset_tez) as [_ | Hne];
        [lia | exfalso; apply Hne; reflexivity].
    - (* acc_primary equation *)
      change (map Impl.Transfer.ci_asset (inp :: nil)) with (asset_tez :: @nil Felt);
      change (map Impl.Transfer.ci_v (inp :: nil)) with (2 :: @nil nat);
      change (Impl.Transfer.co_asset c0) with asset_tez;
      change (Impl.Transfer.co_v c0) with 0;
      change (Impl.Transfer.co_asset pp) with asset_tez;
      change (Impl.Transfer.co_v pp) with 1.
      cbn [Impl.Transfer.acc_primary].
      destruct (Felt.Felt_eq_dec asset_tez asset_tez) as [_ | Hne];
        [lia | exfalso; apply Hne; reflexivity].
  Qed.

End UnshieldRelation.
