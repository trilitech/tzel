(** * Spec.LedgerBounded — the no-overflow facts, proved

    [Spec.LedgerNf] models values as unbounded [nat], so its
    arithmetic cannot wrap.  That is the NO-OVERFLOW IDEALIZATION.
    This module proves the facts that make the idealization faithful
    to the real bounded arithmetic, rather than asserting them:

    1. [tx_conservation_mod_iff]: for ANY modulus [M] larger than the
       biggest honest transaction sum ([max_notes * value_bound]), a
       conservation check performed in arithmetic mod [M] is
       EQUIVALENT to true-integer conservation.  Instantiating [M] =
       2^128 covers the Cairo's [u128] accumulators; [M] = the
       ~2^251 field prime covers a field check.  Either way no
       wraparound can fake or hide conservation.

    2. [headroom_u128]: the side condition [max_notes * value_bound <
       M] holds for the real widths — up to 11 [u64] notes summed
       into a [u128] (11 * 2^64 < 2^128), checked in binary [N] (a
       [nat] literal for 2^128 is not representable).

    3. [totals_bounded_by_deposit]: globally, in every reachable
       state exited and live are each <= deposited.  So under a
       supply cap deposited <= B (the real asset supply, ~2^63
       mutez), all running totals stay <= B and cannot overflow a
       width that holds B.  The supply cap is a hypothesis about the
       world; the IMPLICATION is proved. *)

From Stdlib Require Import List Arith Lia NArith.
Import ListNotations.
From Common Require Import Felt.
From Spec Require Import LedgerNf.

(* ================================================================ *)
(** ** Modular-equality coincides with equality below the modulus    *)
(* ================================================================ *)

Lemma mod_eq_iff (M a b : nat) :
  a < M -> b < M -> (a mod M = b mod M <-> a = b).
Proof.
  intros Ha Hb. rewrite (Nat.mod_small a M Ha), (Nat.mod_small b M Hb).
  tauto.
Qed.

(* ================================================================ *)
(** ** Bounded sums don't overflow                                    *)
(* ================================================================ *)

Lemma nsum_le_len (vs : list nat) (vb : nat) :
  Forall (fun x => x < vb) vs -> nsum vs <= length vs * (vb - 1).
Proof.
  induction 1 as [| x xs Hx Hxs IH]; simpl; nia.
Qed.

Lemma nsum_lt (vs : list nat) (vb mx ab : nat) :
  1 <= vb -> mx * vb < ab -> length vs <= mx ->
  Forall (fun x => x < vb) vs -> nsum vs < ab.
Proof.
  intros Hvb Hhead Hlen Hall.
  pose proof (nsum_le_len vs vb Hall) as Hle.
  assert (length vs * (vb - 1) <= mx * vb) by nia.
  lia.
Qed.

(** A note's per-asset contribution never exceeds its value. *)
Lemma note_contrib_le (a : Felt) (spent : list Felt) (n : Note) :
  note_contrib a spent n <= n_value n.
Proof.
  unfold note_contrib.
  destruct (Felt_eq_dec (n_asset n) a) as [_ | _].
  - destruct (is_spent (n_nf n) spent); lia.
  - lia.
Qed.

(** A per-asset note total fits below [ab] when the notes are
    value-bounded and few enough. *)
Lemma note_sum_lt (a : Felt) (notes : list Note) (vb mx ab : nat) :
  1 <= vb -> mx * vb < ab -> length notes <= mx ->
  Forall (fun n => n_value n < vb) notes ->
  note_sum a notes < ab.
Proof.
  intros Hvb Hhead Hlen Hall.
  unfold note_sum, live_sum.
  apply (nsum_lt _ vb mx ab Hvb Hhead).
  - rewrite length_map. exact Hlen.
  - apply Forall_map. eapply Forall_impl; [| exact Hall].
    intros n Hn. eapply Nat.le_lt_trans; [ apply note_contrib_le | exact Hn ].
Qed.

(* ================================================================ *)
(** ** Per-transaction: modular conservation = true conservation      *)
(* ================================================================ *)

(** A transaction's consumed and output (produced ++ exits) note
    lists are value-bounded and length-bounded. *)
Definition tx_bounded (vb mx : nat) (consumed outputs : list Note) : Prop :=
  Forall (fun n => n_value n < vb) consumed /\ length consumed <= mx
  /\ Forall (fun n => n_value n < vb) outputs /\ length outputs <= mx.

(** THE THEOREM.  For any modulus [ab] with headroom [mx * vb < ab],
    checking conservation in arithmetic mod [ab] gives the same
    verdict as true-integer conservation.  So neither a [u128]
    accumulator nor a field-element subtraction can wrap in a way
    that fakes (or hides) conservation. *)
Theorem tx_conservation_mod_iff
    (a : Felt) (consumed outputs : list Note) (vb mx ab : nat) :
  1 <= vb -> mx * vb < ab ->
  tx_bounded vb mx consumed outputs ->
  (note_sum a consumed mod ab = note_sum a outputs mod ab
   <-> note_sum a consumed = note_sum a outputs).
Proof.
  intros Hvb Hhead [Hc1 [Hc2 [Ho1 Ho2]]].
  apply mod_eq_iff.
  - apply (note_sum_lt a consumed vb mx ab Hvb Hhead Hc2 Hc1).
  - apply (note_sum_lt a outputs vb mx ab Hvb Hhead Ho2 Ho1).
Qed.

(* ================================================================ *)
(** ** The headroom side condition holds for the real widths          *)
(* ================================================================ *)

(** [nat] cannot represent 2^128 (it is unary), so we discharge the
    side condition in binary [N]: up to 11 u64 values sum strictly
    below a u128 accumulator.  The 11 covers a transfer's worst case
    (7 inputs, or 4 outputs + change/fee slots).  The ~2^251 field
    prime has even more headroom, so a field check is covered a
    fortiori. *)
Lemma headroom_u128 : (11 * 2 ^ 64 < 2 ^ 128)%N.
Proof. vm_compute. reflexivity. Qed.

(* ================================================================ *)
(** ** Global: totals are bounded by deposits                          *)
(* ================================================================ *)

(** In every reachable state, the total exited and the total live
    value of any asset are each at most the total deposited. *)
Theorem totals_bounded_by_deposit :
  forall s a, Steps genesis s ->
    exit_sum a s <= dep_sum a s /\ live a s <= dep_sum a s.
Proof.
  intros s a H.
  pose proof (reachable_conserved s a H) as Hc.
  split; lia.
Qed.

(** Consequence: under a supply cap [deposited <= B] (the real asset
    supply, e.g. ~2^63 mutez), all running totals stay <= B, so a
    kernel storing them at any width that holds [B] never overflows.
    The cap is a fact about the world; this implication is proved. *)
Corollary totals_under_supply_cap :
  forall s a B, Steps genesis s ->
    dep_sum a s <= B ->
    dep_sum a s <= B /\ exit_sum a s <= B /\ live a s <= B.
Proof.
  intros s a B H Hcap.
  destruct (totals_bounded_by_deposit s a H) as [He Hl].
  repeat split; lia.
Qed.
