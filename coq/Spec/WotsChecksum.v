(** * Spec.WotsChecksum — the WOTS+ checksum hypothesis is realizable

    [Spec.Xmss.wots_one_time_unforgeable] / [config_update_unforgeable]
    take the checksum well-formedness [base4_val cs = checksum msg] as a
    hypothesis — it is what makes a forward-only forgery impossible (any
    increase in a message digit decreases the checksum, so the checksum
    chains can't be advanced).  This module proves that hypothesis is
    REALIZED by the actual decomposition the Cairo computes
    ([cairo/src/blake_hash.cairo]: the 5 checksum digits are the base-4
    encoding of [sum(3 - digit[i])]), not merely assumed: for any valid
    128-digit message, encoding the checksum as 5 base-4 digits and
    reading it back yields the checksum.

    So the unforgeability premise is not vacuous and is faithful to the
    circuit's checksum construction. *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Spec Require Import Xmss.

(** The Cairo's checksum-digit construction: [cs & 3], then [cs >> 2],
    five times — i.e. the 5 low base-4 digits of [n]
    ([blake_hash.cairo] lines 367-371). *)
Definition base4_encode5 (n : nat) : list nat :=
  [ n mod 4 ; (n / 4) mod 4 ; (n / 16) mod 4 ; (n / 64) mod 4 ; (n / 256) mod 4 ].

(** Reading back the 5 base-4 digits recovers [n], for [n < 4^5]. *)
Lemma base4_val_encode5 : forall n, n < 1024 -> base4_val (base4_encode5 n) = n.
Proof.
  intros n Hn. unfold base4_encode5. cbn [base4_val].
  pose proof (Nat.div_mod n 4 ltac:(lia)) as H1.
  pose proof (Nat.div_mod (n / 4) 4 ltac:(lia)) as H2.
  pose proof (Nat.div_mod (n / 16) 4 ltac:(lia)) as H3.
  pose proof (Nat.div_mod (n / 64) 4 ltac:(lia)) as H4.
  rewrite (Nat.Div0.div_div n 4 4) in H2.
  rewrite (Nat.Div0.div_div n 16 4) in H3.
  rewrite (Nat.Div0.div_div n 64 4) in H4.
  change (4 * 4) with 16 in H2.
  change (16 * 4) with 64 in H3.
  change (64 * 4) with 256 in H4.
  assert (Htop : n / 256 < 4) by lia.
  assert (Hm : n / 256 mod 4 = n / 256) by (apply Nat.mod_small; exact Htop).
  lia.
Qed.

(** The checksum is bounded: each of the [length msg] digits contributes
    at most 3. *)
Lemma checksum_bound : forall msg,
  Forall (fun d => d <= 3) msg -> checksum msg <= 3 * length msg.
Proof.
  intros msg H. unfold checksum.
  induction msg as [| d ds IH]; cbn [map list_sum length].
  - lia.
  - inversion H as [| ? ? Hd Hrest]; subst.
    cbn [Datatypes.length]. specialize (IH Hrest). lia.
Qed.

(** THE REALIZATION: for any valid 128-digit WOTS+ message, the Cairo's
    5-digit base-4 checksum encoding satisfies exactly the hypothesis
    [wots_one_time_unforgeable] needs. *)
Theorem checksum_hypothesis_realized : forall msg,
  length msg = 128 ->
  Forall (fun d => d <= 3) msg ->
  base4_val (base4_encode5 (checksum msg)) = checksum msg.
Proof.
  intros msg Hlen Hbd.
  apply base4_val_encode5.
  pose proof (checksum_bound msg Hbd) as Hb. rewrite Hlen in Hb. lia.
Qed.


(** The 5 checksum digits are valid base-4 digits (each [< 4]) and there
    are exactly 5 of them — the structural half of the well-formedness
    the inhabitation hypotheses ([Hwd_bd]/[Hwd_len]) require for the
    checksum tail. *)
Lemma base4_encode5_length : forall n, length (base4_encode5 n) = 5.
Proof. intros n. reflexivity. Qed.

Lemma base4_encode5_bound : forall n,
  Forall (fun d => d <= 3) (base4_encode5 n).
Proof.
  intros n. unfold base4_encode5.
  assert (B : forall x, x mod 4 <= 3)
    by (intro x; pose proof (Nat.mod_upper_bound x 4 ltac:(lia)); lia).
  repeat (apply Forall_cons; [apply B |]). apply Forall_nil.
Qed.

(** The complete characterization of the Cairo's checksum encoding: it
    has the right length, valid base-4 digits, AND reads back to the
    checksum — i.e. it satisfies everything the unforgeability premise
    and the inhabitation hypotheses ask of the checksum tail. *)
Theorem checksum_encoding_wellformed : forall msg,
  length msg = 128 ->
  Forall (fun d => d <= 3) msg ->
  length (base4_encode5 (checksum msg)) = 5
  /\ Forall (fun d => d <= 3) (base4_encode5 (checksum msg))
  /\ base4_val (base4_encode5 (checksum msg)) = checksum msg.
Proof.
  intros msg Hlen Hbd.
  split; [apply base4_encode5_length |].
  split; [apply base4_encode5_bound | apply checksum_hypothesis_realized; assumption].
Qed.

