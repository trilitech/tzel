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
