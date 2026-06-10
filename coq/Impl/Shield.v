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

    Status: safety predicate defined in [Spec.Shield];
    implementation-side refinement pending.
*)

From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Wots.
From Impl Require Import Xmss.
From Spec Require Shield.

From Stdlib Require Import List Arith.
Import ListNotations.
From Spec Require Hashes.
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

End ShieldRelation.
