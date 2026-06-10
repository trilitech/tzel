(** * Spec.Shield — shield circuit safety predicate (multiasset)

    Source: [cairo/src/shield.cairo::verify] (pre-multiasset: 6
    assertions).

    Shield deposits funds from L1 into the private pool.  The
    circuit:
    - Verifies the signer controls the pubkey_hash (via XMSS sig).
    - Checks the recipient commitment is well-formed.
    - Checks the producer-fee commitment is well-formed.
    - Ensures the producer fee is positive.

    There is NO Merkle inclusion check (nothing is consumed) and
    NO general value conservation in the rollup — the deposited
    amount comes from L1, which the kernel checks separately.

    The sighash uses tag 0x03 to prevent cross-circuit replay
    with transfer (0x01) or unshield (0x02).

    ** Multiasset (Phase E lift).

    Shield's L1 boundary exposes the tez bridge AND one bridge per
    registered FA2 ticketer KT1 (deployment-defined via the kernel's
    [COMPILE_TIME_FA2_BRIDGES] constant).  Both [cm_new] and
    [cm_producer] are asset-tagged through the 5-ary [H_commit]:

      cm_new      = H_commit(d_j, v_note, asset_new, rcm, otag_new)
      cm_producer = H_commit(d_j', v_fee, asset_tez, rcm', otag')

    [asset_new] is sender-chosen; the kernel re-checks it against
    its registered-asset list (this Coq spec abstracts over the
    registry and only models the in-circuit invariants).
    [asset_producer] remains pinned to [asset_tez] in-circuit by
    [phi_shield_producer_asset_tez] below, by the same liquidity
    argument as in [Spec.Transfer]'s [phi_producer_asset_tez].

    Earlier versions of this spec included a [phi_shield_asset_tez]
    conjunct that pinned [asset_new] to [asset_tez].  That pin was
    lifted in Phase E.3 (Cairo commit removing the
    [assert(asset_new == ASSET_TEZ)] in [shield.cairo::verify]) so
    FA2 shields can produce recipient notes carrying a non-tez
    asset.  The lemma [Phi_shield_recipient_is_tez] is therefore
    not provable from [Phi_shield] alone — recipients can carry any
    registered asset.
*)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Common Require Import Felt.
From Spec Require Import Hashes.
From Spec Require Import Transfer.

Section PhiShield.

  Variable H_sighash : Felt -> Felt -> Felt.
  Variable H_commit : Felt -> Felt -> Felt -> Felt -> Felt -> Felt.
  Variable H_owner : Felt -> Felt -> Felt -> Felt.
  Variable H_rcm : Felt -> Felt.

  (** Canonical tez asset tag. *)
  Variable asset_tez : Felt.

  (** 1. Pubkey hash correctness: the pubkey_hash published on L1
      commits to the signer's auth material.
      Cairo: [assert(pkh == pubkey_hash, 'shield: bad pubkey_hash')].
      [pkh = fold(0x04, auth_domain, auth_root, auth_pub_seed, blind)].
      Missing this decouples the L1 deposit address from the circuit
      authorization — anyone could claim the deposit. *)
  Definition phi_pubkey_hash
      (pubkey_hash tag_pkh auth_domain auth_root
       auth_pub_seed blind : Felt) : Prop :=
    pubkey_hash = sighash_fold H_sighash
                    (sighash_fold H_sighash tag_pkh
                       [auth_domain; auth_root])
                    [auth_pub_seed; blind].

  (** 2. Recipient commitment well-formed.

      Cairo (multiasset): [assert(hash::commit(d_j, v_note, asset_new,
      rcm, otag) == cm_new)].

      Missing the asset binding here is the "asset substitution at
      shield" bug — the prover could mint a commitment for an
      arbitrary asset while the L1 deposit is for tez.  In v1 this
      is additionally guarded by [phi_shield_asset_tez] below; the
      hash-level binding is the structural defense. *)
  Definition phi_recipient_commitment
      (cm_new d_j v_felt asset rcm auth_root auth_pub_seed nk_tag
       : Felt) : Prop :=
    let otag := H_owner auth_root auth_pub_seed nk_tag in
    let rcm_val := H_rcm rcm in
    cm_new = H_commit d_j v_felt asset rcm_val otag.

  (** 3. Producer commitment well-formed.
      Cairo: [assert(hash::commit(...) == cm_producer)]. *)
  Definition phi_producer_commitment
      (cm_producer producer_d_j producer_fee_felt producer_asset
       producer_rcm producer_auth_root producer_auth_pub_seed
       producer_nk_tag : Felt) : Prop :=
    let otag := H_owner producer_auth_root producer_auth_pub_seed
                        producer_nk_tag in
    let rcm_val := H_rcm producer_rcm in
    cm_producer = H_commit producer_d_j producer_fee_felt
                           producer_asset rcm_val otag.

  (** 4. (Lifted in Phase E.3.) The recipient-asset = tez pin was
      removed in commit 0c0c8b… of the multiasset branch — the
      Cairo [shield.cairo::verify] no longer asserts
      [asset_new == ASSET_TEZ].  The asset binding now lives in the
      kernel's registered-asset list (modelled abstractly here).

      This stub is kept so dependent indices in [Phi_shield] don't
      shift; it always holds. *)
  Definition phi_shield_asset_registered (_asset_new : Felt) : Prop :=
    True.

  (** 5. Producer fee asset = tez.

      Permanent constraint (not v1-only).  See [Spec.Transfer]
      [phi_producer_asset_tez] for the liquidity rationale. *)
  Definition phi_shield_producer_asset_tez
      (asset_producer : Felt) : Prop :=
    asset_producer = asset_tez.

  (** 6. Producer fee positive.
      Cairo: [assert(producer_fee > 0_u64, 'shield: producer fee zero')]. *)
  Definition phi_shield_producer_fee (producer_fee : nat) : Prop :=
    producer_fee > 0.

  (** 7. Value conservation against the deposit pools (dual-pool).

      Shield drains kernel-side deposit pools keyed by
      [(asset_id, pubkey_hash)].  The producer-fee note is pinned to
      tez (conjunct 5), so a non-tez shield needs TWO debits — the
      kernel's [prepare_durable_shield_commit] implements exactly
      this split:

      - [asset_new = tez]: one pool, one equation.
          [debit_asset_pool = v_note + v_producer + fee],
          and no separate tez debit ([debit_tez_pool = 0]).
      - [asset_new ≠ tez]: the FA2 pool funds the note and the
          public fee; the SAME pubkey_hash's tez pool funds the
          producer note.
          [debit_asset_pool = v_note + fee]  and
          [debit_tez_pool = v_producer].

      Without the second debit, an FA2 shield would mint
      [v_producer] tez in the commitment tree out of nothing (the
      producer note is a tez note no pool paid for).  This was
      PR #36 review-attention item 2. *)
  Definition phi_shield_value_conservation
      (asset_new : Felt)
      (debit_asset_pool debit_tez_pool : nat)
      (v_note v_producer fee : nat) : Prop :=
    if Felt_eq_dec asset_new asset_tez
    then debit_asset_pool = v_note + v_producer + fee
         /\ debit_tez_pool = 0
    else debit_asset_pool = v_note + fee
         /\ debit_tez_pool = v_producer.

  (** Whatever the asset, the TOTAL debited across both pools equals
      the total value leaving into notes + the public fee — the
      headline "no value minted by shield" consequence. *)
  Lemma phi_shield_value_conservation_total
      (asset_new : Felt) (debit_asset_pool debit_tez_pool : nat)
      (v_note v_producer fee : nat) :
    phi_shield_value_conservation asset_new
      debit_asset_pool debit_tez_pool v_note v_producer fee ->
    debit_asset_pool + debit_tez_pool = v_note + v_producer + fee.
  Proof.
    unfold phi_shield_value_conservation.
    destruct (Felt_eq_dec asset_new asset_tez) as [_ | _];
      intros [H1 H2]; lia.
  Qed.

  (** 8. Sighash completeness.

      Cairo (multiasset): sighash = fold(0x03, auth_domain,
      pubkey_hash, v_note, fee, producer_fee, asset_new,
      asset_producer, cm_new, cm_producer, memo, producer_memo).

      Unlike transfer, the asset fields ARE in the sighash here
      because shield is the asset's entry point — the asset tag is
      public at L1 anyway (the bridge identifies it).  Binding it
      in the sighash prevents the prover from claiming "I shielded
      asset X" while drafting commitments for asset Y; kernel
      reconciliation against L1 catches this anyway, but the
      circuit-level binding is the structural defense. *)
  Definition phi_shield_sighash
      (sighash tag_felt auth_domain pubkey_hash
       v_note_felt fee_felt producer_fee_felt
       asset_new asset_producer
       cm_new cm_producer memo producer_memo : Felt) : Prop :=
    sighash = sighash_fold H_sighash
                (sighash_fold H_sighash tag_felt
                   [auth_domain; pubkey_hash])
                [v_note_felt; fee_felt; producer_fee_felt;
                 asset_new; asset_producer;
                 cm_new; cm_producer;
                 memo; producer_memo].

  (** ** Assembled [Phi_shield]

      Shield has no inputs (entry point) and two output slots
      (recipient note + producer-fee note).  The public side is
      the dual-pool drain ([debit_asset_pool] / [debit_tez_pool],
      keyed by [(asset, pubkey_hash)]). *)

  Record ShieldOutput : Type := mkShieldOut {
    so_cm        : Felt;
    so_d_j       : Felt;
    so_v_felt    : Felt;
    so_v         : nat;
    so_asset     : Felt;
    so_rcm       : Felt;
    so_auth_root : Felt;
    so_pub_seed  : Felt;
    so_nk_tag    : Felt;
    so_memo      : Felt;
  }.

  Definition Phi_shield
      (* public *)
      (sighash auth_domain pubkey_hash tag_felt tag_pkh
       auth_root_pkh auth_pub_seed_pkh blind
       v_note_felt fee_felt producer_fee_felt : Felt)
      (debit_asset_pool debit_tez_pool fee : nat)
      (* witness — two output slots *)
      (out_recipient out_producer : ShieldOutput)
    : Prop :=
    phi_pubkey_hash pubkey_hash tag_pkh auth_domain
        auth_root_pkh auth_pub_seed_pkh blind
    /\ phi_recipient_commitment
         (so_cm  out_recipient) (so_d_j out_recipient)
         (so_v_felt out_recipient) (so_asset out_recipient)
         (so_rcm out_recipient) (so_auth_root out_recipient)
         (so_pub_seed out_recipient) (so_nk_tag out_recipient)
    /\ phi_producer_commitment
         (so_cm  out_producer) (so_d_j out_producer)
         (so_v_felt out_producer) (so_asset out_producer)
         (so_rcm out_producer) (so_auth_root out_producer)
         (so_pub_seed out_producer) (so_nk_tag out_producer)
    /\ phi_shield_asset_registered   (so_asset out_recipient)
    /\ phi_shield_producer_asset_tez (so_asset out_producer)
    /\ phi_shield_producer_fee       (so_v     out_producer)
    /\ phi_shield_value_conservation
         (so_asset out_recipient)
         debit_asset_pool debit_tez_pool
         (so_v out_recipient) (so_v out_producer) fee
    /\ phi_shield_sighash
         sighash tag_felt auth_domain pubkey_hash
         v_note_felt fee_felt producer_fee_felt
         (so_asset out_recipient) (so_asset out_producer)
         (so_cm    out_recipient) (so_cm    out_producer)
         (so_memo  out_recipient) (so_memo  out_producer).

  (** ** Sanity-check consequences of [Phi_shield]. *)

  (** Phase E.3 lifted the [asset_new = asset_tez] pin.  The
      recipient-is-tez lemma no longer holds from [Phi_shield] alone;
      the recipient asset is whatever the kernel's registered-asset
      list permits (abstracted away from this Coq spec).  Producer
      tez pin still holds. *)

  Lemma Phi_shield_producer_is_tez_positive
      sighash auth_domain pubkey_hash tag_felt tag_pkh
      auth_root_pkh auth_pub_seed_pkh blind
      v_note_felt fee_felt producer_fee_felt
      debit_asset_pool debit_tez_pool fee r p :
    Phi_shield sighash auth_domain pubkey_hash tag_felt tag_pkh
               auth_root_pkh auth_pub_seed_pkh blind
               v_note_felt fee_felt producer_fee_felt
               debit_asset_pool debit_tez_pool fee r p ->
    so_asset p = asset_tez /\ so_v p > 0.
  Proof.
    unfold Phi_shield, phi_shield_producer_asset_tez,
           phi_shield_producer_fee.
    tauto.
  Qed.

  (** Total conservation: regardless of the recipient asset, the
      sum of pool debits equals the value leaving into the two
      notes plus the public fee.  Specializes per-branch via
      [phi_shield_value_conservation] directly. *)
  Lemma Phi_shield_balance
      sighash auth_domain pubkey_hash tag_felt tag_pkh
      auth_root_pkh auth_pub_seed_pkh blind
      v_note_felt fee_felt producer_fee_felt
      debit_asset_pool debit_tez_pool fee r p :
    Phi_shield sighash auth_domain pubkey_hash tag_felt tag_pkh
               auth_root_pkh auth_pub_seed_pkh blind
               v_note_felt fee_felt producer_fee_felt
               debit_asset_pool debit_tez_pool fee r p ->
    debit_asset_pool + debit_tez_pool = so_v r + so_v p + fee.
  Proof.
    unfold Phi_shield. intros H.
    destruct H as [_ [_ [_ [_ [_ [_ [Hcons _]]]]]]].
    exact (phi_shield_value_conservation_total _ _ _ _ _ _ Hcons).
  Qed.

End PhiShield.
