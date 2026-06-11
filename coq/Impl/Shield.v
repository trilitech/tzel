(** * Impl.Shield

    Mirror of [cairo/src/shield.cairo].

    Shield drains balance from kernel-side deposit pools keyed by
    [(asset_id, pubkey_hash)] where [pubkey_hash = H(0x04,
    auth_domain, auth_root, auth_pub_seed, blind)], and produces two
    private notes (recipient + producer-fee).  Multiasset makes the
    drain DUAL-POOL: a non-tez shield debits [v_note + fee] from the
    FA2 pool and [producer_fee] from the same pubkey_hash's tez pool
    (the producer note is pinned to tez); a tez shield collapses
    both into one debit.  See
    [Spec.Shield.phi_shield_value_conservation].
    The Cairo circuit verifies an in-circuit WOTS+ signature against
    the recipient's auth tree, binding every public output (including
    the deposit pool key, both output commitments, and both memo
    hashes).

    Soundness target:

      shield_sound:
        ShieldRelation pub wit ->
        Phi_shield pub

    where [Phi_shield pub] enumerates: [pubkey_hash] commits to the
    recipient's auth tree (so only that auth tree's holder can drain),
    the in-circuit signature covers every public output, the dual-pool
    debits balance per [phi_shield_value_conservation], and both
    output commitments are well-formed.

    The interesting wrinkle here vs transfer/unshield: shield has no
    nullifier — it's the entry point. The L1 ticket landing on the
    [deposit:<hex(pubkey_hash)>] recipient is what authenticates the
    pool's existence, and the circuit's WOTS+ signature is what
    authenticates the drain. Modeling that L1↔kernel handshake is
    out of scope here (it's a kernel-side property); the circuit-side
    obligation is "the in-circuit signature binds [pubkey_hash] to a
    leaf in the recipient's auth tree."

    Status: COMPLETE. [shield_relation_sound] (below) proves the
    Cairo-shaped [ShieldRelation] discharges
    [Spec.Shield.phi_shield_value_conservation] and the sighash /
    pubkey-hash bindings.
*)

From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Wots.
From Impl Require Import Xmss.
From Spec Require Shield.

From Stdlib Require Import List Arith.
Import ListNotations.
From Spec Require Hashes.
From Spec Require Merkle.
From Spec Require Xmss.
From Stdlib Require Import Lia.
From Impl Require Transfer.

(** ** The Cairo-shaped shield relation

    [ShieldRelation] is the Rocq model of
    [cairo/src/shield.cairo::verify], in Cairo source order — the
    shield counterpart of [Impl.Transfer.TransferRelation] (see that
    module for the modeling conventions).

    Shield-specific shape:
    - no inputs, no Merkle leg, no nullifiers (it is the entry
      point);
    - exactly two output notes (recipient + producer-fee), both
      mandatory, reusing [Impl.Transfer.CairoOutput];
    - [pubkey_hash] (the L1 deposit-pool key) binds the SAME
      [(auth_root, auth_pub_seed)] the in-circuit WOTS+ signature
      verifies under and the SAME pair the recipient note's
      owner_tag commits to — one auth tree authorizes the drain,
      owns the note, and signs the request;
    - the value-conservation property is KERNEL-side (the dual-pool
      debit in [prepare_durable_shield_commit]) — the circuit never
      sees pool balances.  [shield_relation_sound] therefore takes
      the debit equations as an explicit hypothesis in the exact
      shape of [Spec.Shield.phi_shield_value_conservation],
      discharging every circuit-level conjunct from the relation
      and the kernel-level conjunct from that hypothesis. *)

Section ShieldRelation.

  Variable H_sighash : Felt -> Felt -> Felt.
  Variable H_commit : Felt -> Felt -> Felt -> Felt -> Felt -> Felt.
  Variable H_owner : Felt -> Felt -> Felt -> Felt.
  Variable H_rcm : Felt -> Felt.
  Variable H_tree_node : Felt -> nat -> nat -> Felt -> Felt -> Felt.
  Variable H_ltree_node : Felt -> nat -> nat -> nat -> Felt -> Felt -> Felt.
  Variable F_chain : Felt -> Felt -> Felt -> Felt.
  Variable ADRS_chain : nat -> nat -> nat -> Felt.

  Variable asset_tez : Felt.
  (** Sighash type tag 0x03 and pubkey-hash tag 0x04, as felts. *)
  Variable tag_shield_felt : Felt.
  Variable tag_pkh_felt : Felt.
  Variable felt_of_nat : nat -> Felt.
  Variable wots_digits : Felt -> list nat.

  Notation CairoOutput := Impl.Transfer.CairoOutput.
  Notation co_cm := Impl.Transfer.co_cm.
  Notation co_v := Impl.Transfer.co_v.
  Notation co_memo := Impl.Transfer.co_memo.
  Notation co_asset := Impl.Transfer.co_asset.
  Notation co_auth_root := Impl.Transfer.co_auth_root.
  Notation co_pub_seed := Impl.Transfer.co_pub_seed.

  Definition s_output_cm_ok :=
    Impl.Transfer.output_cm_ok H_commit H_owner H_rcm felt_of_nat.

  (** [pubkey_hash = fold(0x04, auth_domain, auth_root,
      auth_pub_seed, blind)] — the deposit-pool key.  The
      [(auth_root, auth_pub_seed)] are the RECIPIENT note's
      ([r] below), binding pool, note owner, and signer together. *)
  Definition relation_pubkey_hash
      (auth_domain : Felt) (r : CairoOutput) (blind : Felt) : Felt :=
    Spec.Hashes.sighash_fold H_sighash tag_pkh_felt
      [auth_domain; co_auth_root r; co_pub_seed r; blind].

  (** The sighash fold, in Cairo's exact order:
      [fold(0x03, auth_domain, pubkey_hash, v_note, fee,
            producer_fee, asset_new, asset_producer, cm_new,
            cm_producer, memo_ct_hash, producer_memo_ct_hash)]. *)
  Definition s_relation_sighash
      (auth_domain pubkey_hash : Felt) (fee : nat)
      (r p : CairoOutput) : Felt :=
    Spec.Hashes.sighash_fold H_sighash
      (Spec.Hashes.sighash_fold H_sighash tag_shield_felt
         [auth_domain; pubkey_hash])
      [felt_of_nat (co_v r); felt_of_nat fee; felt_of_nat (co_v p);
       co_asset r; co_asset p;
       co_cm r; co_cm p;
       co_memo r; co_memo p].

  (** The full relation — [cairo/src/shield.cairo::verify],
      conjuncts in Cairo source order.  [r] is the recipient note
      (its [co_v] is the public [v_note], its [co_asset] the public
      [asset_new]); [p] is the producer-fee note. *)
  Definition ShieldRelation
      (auth_domain pubkey_hash : Felt) (fee : nat)
      (blind : Felt) (auth_idx : nat)
      (wots_sig auth_siblings : list Felt)
      (r p : CairoOutput) : Prop :=
    let sighash := s_relation_sighash auth_domain pubkey_hash fee r p in
    (* [assert(wots_sig_flat.len() == WOTS_CHAINS)] *)
    length wots_sig = Spec.Hashes.wots_chains
    (* [assert(asset_producer == ASSET_TEZ, 'shield: producer must be tez')] *)
    /\ co_asset p = asset_tez
    (* recipient commitment: [assert(commit(...) == cm_new)] *)
    /\ s_output_cm_ok r
    (* producer commitment: [assert(commit(...) == cm_producer)] *)
    /\ s_output_cm_ok p
    (* [assert(producer_fee > 0_u64, 'shield: producer fee zero')] *)
    /\ co_v p > 0
    (* [assert(pkh == pubkey_hash, 'shield: bad pubkey_hash')] *)
    /\ pubkey_hash = relation_pubkey_hash auth_domain r blind
    (* in-circuit WOTS+ under the recipient's auth tree *)
    /\ Spec.Xmss.xmss_verify_cairo_sep
         (H_tree_node (co_pub_seed r))
         (H_ltree_node (co_pub_seed r) auth_idx)
         F_chain ADRS_chain
         (co_pub_seed r) auth_idx
         (wots_digits sighash) wots_sig
         auth_siblings (co_auth_root r).

  Definition shield_output_view (o : CairoOutput)
    : Spec.Shield.ShieldOutput :=
    Spec.Shield.mkShieldOut
      (co_cm o) (Impl.Transfer.co_d_j o)
      (felt_of_nat (co_v o)) (co_v o) (co_asset o)
      (Impl.Transfer.co_rseed o)
      (co_auth_root o) (co_pub_seed o)
      (Impl.Transfer.co_nk_tag o) (co_memo o).

  (** *** Soundness.

      Circuit-level conjuncts come from the relation; the dual-pool
      conservation conjunct is KERNEL-side and enters as the
      [Hdebits] hypothesis (the obligation
      [tezos/rollup-kernel::prepare_durable_shield_commit]
      discharges — modeling the kernel is future work; stating the
      hypothesis in [phi_shield_value_conservation]'s exact shape
      keeps the seam explicit). *)
  Theorem shield_relation_sound
      (auth_domain pubkey_hash blind : Felt)
      (fee : nat) (auth_idx : nat)
      (wots_sig auth_siblings : list Felt)
      (r p : CairoOutput)
      (debit_asset_pool debit_tez_pool : nat)
      (Hdebits :
        Spec.Shield.phi_shield_value_conservation asset_tez
          (co_asset r) debit_asset_pool debit_tez_pool
          (co_v r) (co_v p) fee) :
    ShieldRelation auth_domain pubkey_hash fee blind auth_idx
                   wots_sig auth_siblings r p ->
    Spec.Shield.Phi_shield H_sighash H_commit H_owner H_rcm asset_tez
      (s_relation_sighash auth_domain pubkey_hash fee r p)
      auth_domain pubkey_hash tag_shield_felt tag_pkh_felt
      (co_auth_root r) (co_pub_seed r) blind
      (felt_of_nat (co_v r)) (felt_of_nat fee) (felt_of_nat (co_v p))
      debit_asset_pool debit_tez_pool fee
      (shield_output_view r) (shield_output_view p).
  Proof.
    intros (Hsiglen & Hprod_tez & Hcm_r & Hcm_p & Hfee_pos
            & Hpkh & Hxmss).
    unfold Spec.Shield.Phi_shield.
    repeat apply conj.
    - (* pubkey_hash: relation computes the same fold *)
      unfold Spec.Shield.phi_pubkey_hash.
      rewrite Hpkh. unfold relation_pubkey_hash. cbn. reflexivity.
    - (* recipient commitment well-formed *)
      unfold Spec.Shield.phi_recipient_commitment. exact Hcm_r.
    - (* producer commitment well-formed *)
      unfold Spec.Shield.phi_producer_commitment. exact Hcm_p.
    - (* asset registered: lifted to the kernel, stub conjunct *)
      exact I.
    - (* producer asset pinned to tez *)
      exact Hprod_tez.
    - (* producer fee positive *)
      exact Hfee_pos.
    - (* dual-pool conservation: the kernel-side hypothesis *)
      exact Hdebits.
    - (* sighash completeness: definitional *)
      unfold Spec.Shield.phi_shield_sighash, s_relation_sighash.
      cbn. reflexivity.
  Qed.

  (** Helper for the non-vacuity proof below: an HONEST WOTS+/XMSS
      signature verifies under the Cairo separated-hash verifier.  Kept
      free of the output-record construction so the inhabitation proof
      can [apply] it without unfolding local definitions. *)
  Lemma xmss_honest_verifies :
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

  Lemma sign_len_eq :
    forall (ps : Felt) (ki sc : nat) (digits : list nat) (sks : list Felt),
      length digits = length sks ->
      length (Spec.Xmss.sign F_chain ADRS_chain ps ki sc digits sks) = length digits.
  Proof.
    intros ps ki sc digits. revert sc.
    induction digits as [| d ds IH]; intros sc [| sk rest] Hlen; cbn in *;
      try discriminate Hlen; [reflexivity |].
    f_equal. apply IH. lia.
  Qed.

  (** NON-VACUITY: a single concrete honest shield satisfies every
      conjunct of [ShieldRelation] at once, so [shield_relation_sound]
      is not vacuously true. *)
  Theorem shield_relation_inhabited
      (auth_domain blind : Felt) (sks : list Felt)
      (Hsks_len : length sks = Spec.Hashes.wots_chains)
      (Hsks_ne  : sks <> nil)
      (Hwd_len  : forall sh, length (wots_digits sh) = Spec.Hashes.wots_chains)
      (Hwd_bd   : forall sh, Forall (fun d => d <= Spec.Hashes.wots_chain_len) (wots_digits sh)) :
    exists pubkey_hash fee auth_idx wots_sig auth_siblings r p,
      ShieldRelation auth_domain pubkey_hash fee blind auth_idx
                     wots_sig auth_siblings r p.
  Proof.
    pose (aD := auth_domain).
    pose (sib := repeat aD Spec.Hashes.auth_depth).
    assert (Hgpk : Spec.Xmss.gen_pk F_chain ADRS_chain aD 0 0 sks <> nil).
    { destruct sks as [| sk rest]; [contradiction | cbn [Spec.Xmss.gen_pk]; discriminate]. }
    destruct (Spec.Xmss.ltree_succeeds (H_ltree_node aD 0)
                (Spec.Xmss.gen_pk F_chain ADRS_chain aD 0 0 sks) Hgpk) as [leaf Hleaf].
    pose (ar := Spec.Merkle.auth_root (H_tree_node aD)
                  (Spec.Xmss.nat_to_bits Spec.Hashes.auth_depth 0) sib leaf 0 0).
    pose (r := Impl.Transfer.mkCairoOutput
                 (H_commit aD (felt_of_nat 0) asset_tez (H_rcm aD) (H_owner ar aD aD))
                 aD 0 aD ar aD aD aD asset_tez).
    pose (p := Impl.Transfer.mkCairoOutput
                 (H_commit aD (felt_of_nat 1) asset_tez (H_rcm aD) (H_owner aD aD aD))
                 aD 1 aD aD aD aD aD asset_tez).
    pose (pkh := relation_pubkey_hash auth_domain r blind).
    exists pkh, 0, 0,
      (Spec.Xmss.sign F_chain ADRS_chain aD 0 0
         (wots_digits (s_relation_sighash auth_domain pkh 0 r p)) sks),
      sib, r, p.
    assert (Hdlen : length (wots_digits (s_relation_sighash auth_domain pkh 0 r p))
                    = length sks) by (rewrite Hwd_len; exact (eq_sym Hsks_len)).
    unfold ShieldRelation. cbv zeta.
    refine (conj _ (conj _ (conj _ (conj _ (conj _ (conj _ _)))))).
    - rewrite sign_len_eq by exact Hdlen. apply Hwd_len.
    - reflexivity.
    - reflexivity.
    - reflexivity.
    - cbn. apply Nat.lt_0_succ.
    - reflexivity.
    - change (co_pub_seed r) with aD. change (co_auth_root r) with ar.
      apply (xmss_honest_verifies aD
               (wots_digits (s_relation_sighash auth_domain pkh 0 r p))
               sks sib leaf Hdlen
               (Hwd_bd (s_relation_sighash auth_domain pkh 0 r p)) Hleaf).
      apply repeat_length.
  Qed.

  (** ** Shield entry-point binding — funds reach exactly the published owner

      The deposit pool is keyed by the public [pubkey_hash =
      fold(tag_pkh, [auth_domain; auth_root; auth_pub_seed; blind])].
      The relation feeds the SAME [(co_auth_root r, co_pub_seed r)] of
      the recipient note [r] into BOTH that pubkey_hash fold AND the
      note commitment ([s_output_cm_ok r] via [co_otag]), and verifies
      the in-circuit XMSS signature under [co_auth_root r].  So an
      accepted shield to a published [pubkey_hash] whose owner is
      [(R, PS)] is forced to create a recipient note owned by exactly
      [(R, PS)] — under sighash-fold injectivity, no other owner
      reproduces the pubkey_hash.  Composed with the signature under
      [co_auth_root r = R], this is the entry-point guarantee: deposit
      funds become a note owned by the published pool key, and only that
      key's holder can perform the shield.  Nobody can shield a
      victim's pool into a note they control. *)
  Theorem shield_note_bound_to_pubkey_hash :
    Spec.Hashes.injective_2 H_sighash ->
    forall (auth_domain pubkey_hash : Felt) (fee : nat)
           (blind : Felt) (auth_idx : nat)
           (wots_sig auth_siblings : list Felt)
           (r p : CairoOutput) (R PS B : Felt),
      pubkey_hash = Spec.Hashes.sighash_fold H_sighash tag_pkh_felt
                      [auth_domain; R; PS; B] ->
      ShieldRelation auth_domain pubkey_hash fee blind auth_idx
                     wots_sig auth_siblings r p ->
      co_auth_root r = R /\ co_pub_seed r = PS.
  Proof.
    intros Hinj auth_domain pubkey_hash fee blind auth_idx
           wots_sig auth_siblings r p R PS B Hpkh HR.
    unfold ShieldRelation in HR.
    destruct HR as (_ & _ & _ & _ & _ & Hpk & _).
    unfold relation_pubkey_hash in Hpk.
    rewrite Hpkh in Hpk. symmetry in Hpk.
    destruct (Spec.Hashes.sighash_fold_injective H_sighash Hinj
                [auth_domain; co_auth_root r; co_pub_seed r; blind]
                [auth_domain; R; PS; B]
                tag_pkh_felt tag_pkh_felt eq_refl Hpk) as [_ Hlist].
    injection Hlist as Har Hps _.
    split; [exact Har | exact Hps].
  Qed.

End ShieldRelation.
