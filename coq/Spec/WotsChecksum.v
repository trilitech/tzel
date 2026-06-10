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
From Common Require Import Felt.
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


(** WOTS+ one-time unforgeability for the REAL message format: 128
    message digits with the Cairo's concrete 5-digit base-4 checksum
    tail.  All four checksum well-formedness premises of
    [Spec.Xmss.wots_one_time_unforgeable] (the two digit bounds and the
    two [base4_val = checksum] facts) are now DISCHARGED by the
    encoding's proven properties — so the only remaining hypotheses are
    the attacker's forward-only moves (each forged digit and checksum
    digit at least the original).  A forward-only forger cannot change
    the message. *)
Theorem wots_unforgeable_concrete_checksum :
  forall msg msg' : list nat,
    length msg = 128 -> length msg' = 128 ->
    Forall (fun d => d <= 3) msg -> Forall (fun d => d <= 3) msg' ->
    Forall2 (fun d' d => d' >= d) msg' msg ->
    Forall2 (fun d' d => d' >= d)
      (base4_encode5 (checksum msg')) (base4_encode5 (checksum msg)) ->
    msg' = msg.
Proof.
  intros msg msg' Hl Hl' Hb Hb' Hm Hc.
  apply (wots_one_time_unforgeable msg msg'
           (base4_encode5 (checksum msg)) (base4_encode5 (checksum msg'))).
  - exact (eq_trans Hl (eq_sym Hl')).
  - exact Hb.
  - exact Hb'.
  - apply base4_encode5_bound.
  - apply base4_encode5_bound.
  - exact (checksum_hypothesis_realized msg Hl Hb).
  - exact (checksum_hypothesis_realized msg' Hl' Hb').
  - exact Hm.
  - exact Hc.
Qed.


(** The same discharge at the XMSS level — the actual one-time
    signature scheme the circuit verifies ([xmss_verify]).  For the real
    digit format (128 message digits ++ the Cairo's 5-digit base-4
    checksum tail), two accepting XMSS verifications under the same
    auth path, related by a forward-only forgery, must be of the SAME
    message.  All checksum premises discharged by the encoding. *)
Theorem xmss_unforgeable_concrete_checksum :
  forall (F : Felt -> Felt -> Felt -> Felt) (ADRS_chain : nat -> nat -> nat -> Felt)
         (H_node : nat -> nat -> Felt -> Felt -> Felt) (pub_seed : Felt) (key_idx : nat)
         (msg1 msg2 : list nat) (sig1 sig2 : list Felt)
         (auth_bits : list bool) (auth_siblings : list Felt) (auth_root_val : Felt),
    Hashes.node_injective H_node ->
    length auth_bits = length auth_siblings ->
    length (msg1 ++ base4_encode5 (checksum msg1)) = length sig1 ->
    length (msg2 ++ base4_encode5 (checksum msg2)) = length sig2 ->
    length msg1 = 128 -> length msg2 = 128 ->
    Forall (fun d => d <= 3) msg1 -> Forall (fun d => d <= 3) msg2 ->
    xmss_verify F ADRS_chain H_node pub_seed key_idx
      (msg1 ++ base4_encode5 (checksum msg1)) sig1 auth_bits auth_siblings auth_root_val ->
    xmss_verify F ADRS_chain H_node pub_seed key_idx
      (msg2 ++ base4_encode5 (checksum msg2)) sig2 auth_bits auth_siblings auth_root_val ->
    Forall2 (fun d2 d1 => d2 >= d1) msg2 msg1 ->
    Forall2 (fun d2 d1 => d2 >= d1)
      (base4_encode5 (checksum msg2)) (base4_encode5 (checksum msg1)) ->
    msg1 = msg2.
Proof.
  intros F ADRS_chain H_node pub_seed key_idx msg1 msg2 sig1 sig2
    auth_bits auth_siblings auth_root_val
    Hni Hab Hs1 Hs2 Hl1 Hl2 Hb1 Hb2 Hv1 Hv2 Hm Hc.
  pose proof (xmss_one_time_unforgeable F ADRS_chain H_node pub_seed key_idx
    msg1 (base4_encode5 (checksum msg1)) msg2 (base4_encode5 (checksum msg2))
    sig1 sig2 auth_bits auth_siblings auth_root_val
    Hni Hab Hs1 Hs2 (eq_trans Hl1 (eq_sym Hl2))
    (eq_trans (base4_encode5_length _) (eq_sym (base4_encode5_length _)))
    Hb1 Hb2 (base4_encode5_bound _) (base4_encode5_bound _)
    (checksum_hypothesis_realized msg1 Hl1 Hb1)
    (checksum_hypothesis_realized msg2 Hl2 Hb2)
    Hv1 Hv2 Hm Hc) as [_ Hmsg].
  exact Hmsg.
Qed.

