(** * Spec.GrandConservation — unified circuit-level no-inflation

    [Spec.Transfer.batch_value_conservation] and
    [Spec.Unshield.batch_unshield_value_conservation] each proved no
    value is created across a batch of ONE operation kind.  This
    module UNIFIES all three flows — shield (value in from a deposit),
    transfer (value moved within the pool), unshield (value out to L1)
    — into a single operation type and a single conservation law, and
    proves value is conserved per asset across ANY MIXED batch of
    them.

    Each operation has input note lists, output note lists, and three
    scalar lanes that the kinds populate differently:
    - a DEPOSIT lane [(deposit_asset, deposit_value)]: shield credits
      it from L1; transfer/unshield leave [deposit_value = 0];
    - an EXIT lane [(exit_asset, exit_value)]: unshield withdraws it to
      L1; shield/transfer leave [exit_value = 0];
    - a tez [fee] burned by the rollup.

    Unified conservation, for every asset [a]:

        (notes consumed at a)  +  (deposited at a)
          =  (notes produced at a)  +  (withdrawn at a)
             +  (a = tez ? fee : 0).

    A shield instantiates this with empty input notes and a nonzero
    deposit; an unshield with a nonzero exit; a transfer with neither —
    so the single predicate [op_conserves] specializes to each circuit
    relation (see [unshield_is_op] below).

    [grand_conservation]: across any list of mixed operations, the
    per-asset totals balance — no sequence of shields, transfers, and
    unshields, in any order, can create or destroy value of any asset.
    Derived from the soundness of each operation's circuit relation. *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Common Require Import Felt.
From Spec Require Import Transfer.

Section GrandConservation.

  Variable asset_tez : Felt.

  Record Op : Type := mkOp {
    op_in_assets    : list Felt;
    op_in_values    : list nat;
    op_out_assets   : list Felt;
    op_out_values   : list nat;
    op_deposit_asset : Felt;
    op_deposit_value : nat;   (* shield: > 0; else 0 *)
    op_exit_asset    : Felt;
    op_exit_value    : nat;    (* unshield: > 0; else 0 *)
    op_fee           : nat;    (* tez, rollup-burned *)
  }.

  Definition op_wf (o : Op) : Prop :=
    length (op_in_assets o) = length (op_in_values o)
    /\ length (op_out_assets o) = length (op_out_values o).

  (** The unified per-operation conservation law. *)
  Definition op_conserves (o : Op) : Prop :=
    forall a : Felt,
      sum_at a (op_in_assets o) (op_in_values o)
        + (if Felt_eq_dec a (op_deposit_asset o) then op_deposit_value o else 0)
      = sum_at a (op_out_assets o) (op_out_values o)
        + (if Felt_eq_dec a (op_exit_asset o) then op_exit_value o else 0)
        + (if Felt_eq_dec a asset_tez then op_fee o else 0).

  (** Per-asset totals over a batch. *)
  Definition total_deposit (a : Felt) (ops : list Op) : nat :=
    list_sum (map (fun o => if Felt_eq_dec a (op_deposit_asset o)
                            then op_deposit_value o else 0) ops).

  Definition total_exit (a : Felt) (ops : list Op) : nat :=
    list_sum (map (fun o => if Felt_eq_dec a (op_exit_asset o)
                            then op_exit_value o else 0) ops).

  (** ** THE GRAND CONSERVATION LAW.

      Across any mixed batch of shields / transfers / unshields, for
      every asset: total notes consumed + total deposited = total
      notes produced + total withdrawn + total tez fees.  No mix of
      operations creates or destroys value. *)
  Theorem grand_conservation (ops : list Op) :
    Forall op_wf ops ->
    Forall op_conserves ops ->
    forall a : Felt,
      sum_at a (concat (map op_in_assets ops))
               (concat (map op_in_values ops))
      + total_deposit a ops
      = sum_at a (concat (map op_out_assets ops))
                 (concat (map op_out_values ops))
        + total_exit a ops
        + (if Felt_eq_dec a asset_tez then list_sum (map op_fee ops) else 0).
  Proof.
    unfold total_deposit, total_exit.
    induction ops as [| o ops IH]; intros Hwf Hc a.
    - cbn. destruct (Felt_eq_dec a asset_tez); reflexivity.
    - inversion Hwf as [| ? ? [Hwin Hwout] Hwf']; subst.
      inversion Hc as [| ? ? Ho Hc']; subst.
      cbn [map concat list_sum].
      rewrite (sum_at_app _ _ _ _ _ Hwin).
      rewrite (sum_at_app _ _ _ _ _ Hwout).
      specialize (Ho a). specialize (IH Hwf' Hc' a).
      simpl list_sum.
      destruct (Felt_eq_dec a asset_tez);
        destruct (Felt_eq_dec a (op_deposit_asset o));
        destruct (Felt_eq_dec a (op_exit_asset o)); lia.
  Qed.

  (* ============================================================= *)
  (** ** The three flows are instances of [op_conserves]            *)
  (* ============================================================= *)

  (** An UNSHIELD operation: empty deposit lane, exit lane carries the
      L1 withdrawal.  Its [op_conserves] is exactly the unshield
      circuit relation [phi_unshield_value_conservation]
      (sum_at in = sum_at out + v_pub@asset_pub + fee@tez). *)
  Definition unshield_op
      (in_a : list Felt) (in_v : list nat)
      (out_a : list Felt) (out_v : list nat)
      (v_pub : nat) (asset_pub : Felt) (fee : nat) : Op :=
    mkOp in_a in_v out_a out_v asset_tez 0 asset_pub v_pub fee.

  Lemma unshield_is_op :
    forall in_a in_v out_a out_v v_pub asset_pub fee,
      op_conserves (unshield_op in_a in_v out_a out_v v_pub asset_pub fee)
      <->
      (forall a : Felt,
        sum_at a in_a in_v
        = sum_at a out_a out_v
          + (if Felt_eq_dec a asset_pub then v_pub else 0)
          + (if Felt_eq_dec a asset_tez then fee else 0)).
  Proof.
    intros. unfold op_conserves, unshield_op. cbn [op_in_assets op_in_values
      op_out_assets op_out_values op_deposit_asset op_deposit_value
      op_exit_asset op_exit_value op_fee].
    split; intros HH a; specialize (HH a).
    - (* deposit lane is + 0 *)
      destruct (Felt_eq_dec a asset_tez); lia.
    - destruct (Felt_eq_dec a asset_tez); lia.
  Qed.

  (** A SHIELD operation: empty input notes, deposit lane carries the
      L1 deposit, no exit.  Its [op_conserves] says the deposited
      value equals the produced notes plus fee. *)
  Definition shield_op
      (out_a : list Felt) (out_v : list nat)
      (dep_v : nat) (dep_asset : Felt) (fee : nat) : Op :=
    mkOp [] [] out_a out_v dep_asset dep_v asset_tez 0 fee.

  Lemma shield_is_op :
    forall out_a out_v dep_v dep_asset fee,
      op_conserves (shield_op out_a out_v dep_v dep_asset fee)
      <->
      (forall a : Felt,
        (if Felt_eq_dec a dep_asset then dep_v else 0)
        = sum_at a out_a out_v
          + (if Felt_eq_dec a asset_tez then fee else 0)).
  Proof.
    intros. unfold op_conserves, shield_op. cbn [op_in_assets op_in_values
      op_out_assets op_out_values op_deposit_asset op_deposit_value
      op_exit_asset op_exit_value op_fee sum_at].
    split; intros HH a; specialize (HH a).
    - destruct (Felt_eq_dec a asset_tez); lia.
    - destruct (Felt_eq_dec a asset_tez); lia.
  Qed.

  (** A TRANSFER operation: the third flow — neither deposit nor exit
      lane (both zeroed, parked on [asset_tez]), so value only moves
      among notes, minus the tez fee.  Its [op_conserves] is exactly
      the transfer circuit relation's conservation
      (sum_at in = sum_at out + fee@tez), completing the trichotomy:
      shield (deposit lane), unshield (exit lane), transfer (neither). *)
  Definition transfer_op
      (in_a : list Felt) (in_v : list nat)
      (out_a : list Felt) (out_v : list nat)
      (fee : nat) : Op :=
    mkOp in_a in_v out_a out_v asset_tez 0 asset_tez 0 fee.

  Lemma transfer_is_op :
    forall in_a in_v out_a out_v fee,
      op_conserves (transfer_op in_a in_v out_a out_v fee)
      <->
      (forall a : Felt,
        sum_at a in_a in_v
        = sum_at a out_a out_v
          + (if Felt_eq_dec a asset_tez then fee else 0)).
  Proof.
    intros. unfold op_conserves, transfer_op. cbn [op_in_assets op_in_values
      op_out_assets op_out_values op_deposit_asset op_deposit_value
      op_exit_asset op_exit_value op_fee].
    split; intros HH a; specialize (HH a);
      destruct (Felt_eq_dec a asset_tez); lia.
  Qed.

End GrandConservation.
