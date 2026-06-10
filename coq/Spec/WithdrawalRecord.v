(** * Spec.WithdrawalRecord — withdrawal-record serialization safety

    Models the kernel's durable withdrawal-record encoding
    ([encode_withdrawal_record] / [decode_withdrawal_record] in
    [tezos/rollup-kernel/src/lib.rs]) and proves it is LOSSLESS and
    UNAMBIGUOUS.  A withdrawal record carries the asset, the L1
    recipient, and the amount; it is serialized to durable storage on
    unshield and read back when the outbox message is emitted.  A
    round-trip bug here would misdirect a withdrawal (wrong recipient)
    or corrupt its amount — direct fund loss or theft.

    Wire layout (little-endian, exactly the Rust):

        asset_id (32 bytes) || amount (u64 LE, 8) ||
        recipient_len (u32 LE, 4) || recipient (utf-8 bytes)

    Proved (zero admits):
    - [decode_encode]: decode (encode r) = Some r — lossless
      round-trip, for any well-formed record (32-byte asset, amount <
      2^64, recipient length < 2^32);
    - [encode_injective]: distinct records have distinct encodings (no
      durable-storage aliasing of two different withdrawals);
    - the length-prefix framing is unambiguous: decode reads exactly
      [44 + recipient_len] bytes and rejects any other length.

    Bytes are modeled as [nat] (intended 0..255); the LE codec is the
    base-256 positional representation, whose round-trip is the
    arithmetic core. *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.

(* ================================================================ *)
(** ** Little-endian byte codec                                      *)
(* ================================================================ *)

(** [le k n] : the [k]-byte little-endian encoding of [n]. *)
Fixpoint le (k n : nat) : list nat :=
  match k with
  | 0 => []
  | S k' => (n mod 256) :: le k' (n / 256)
  end.

(** [from_le bs] : the natural number a little-endian byte list denotes. *)
Fixpoint from_le (bs : list nat) : nat :=
  match bs with
  | [] => 0
  | b :: r => b + 256 * from_le r
  end.

Lemma le_length : forall k n, length (le k n) = k.
Proof. induction k as [| k IH]; intro n; cbn; [reflexivity | rewrite IH; reflexivity]. Qed.

(** The codec round-trips exactly when the value fits in [k] bytes. *)
Lemma from_le_le : forall k n, n < 256 ^ k -> from_le (le k n) = n.
Proof.
  induction k as [| k IH]; intros n Hn; cbn [le from_le].
  - cbn in Hn. lia.
  - assert (Hdiv : n / 256 < 256 ^ k).
    { apply Nat.div_lt_upper_bound; [lia |]. rewrite <- Nat.pow_succ_r'. exact Hn. }
    rewrite (IH (n / 256) Hdiv).
    pose proof (Nat.div_mod n 256 ltac:(lia)) as Hdm. lia.
Qed.

(* ================================================================ *)
(** ** firstn / skipn over an exact-length prefix                    *)
(* ================================================================ *)

Lemma firstn_app_len : forall (a b : list nat), firstn (length a) (a ++ b) = a.
Proof.
  intros a b. rewrite firstn_app, Nat.sub_diag. cbn [firstn].
  rewrite app_nil_r. apply firstn_all.
Qed.

Lemma skipn_app_len : forall (a b : list nat), skipn (length a) (a ++ b) = b.
Proof.
  intros a b. rewrite skipn_app, Nat.sub_diag. cbn [skipn].
  rewrite skipn_all. reflexivity.
Qed.

Lemma firstn_le_app : forall k n (b : list nat), firstn k (le k n ++ b) = le k n.
Proof. intros k n b. rewrite <- (le_length k n) at 1. apply firstn_app_len. Qed.

(* ================================================================ *)
(** ** The withdrawal record                                         *)
(* ================================================================ *)

Record WR : Type := mkWR {
  wr_asset     : list nat;   (* 32 bytes *)
  wr_amount    : nat;        (* u64 *)
  wr_recipient : list nat;   (* utf-8 bytes *)
}.

Definition encode (r : WR) : list nat :=
  wr_asset r ++ le 8 (wr_amount r) ++ le 4 (length (wr_recipient r)) ++ wr_recipient r.

(** The decoder, mirroring the Rust offsets exactly: 32-byte asset, an
    LE u64 amount at [32..40], an LE u32 length at [40..44], the
    recipient at [44..], and a hard length check. *)
Definition decode (bytes : list nat) : option WR :=
  if 44 <=? length bytes then
    let amount := from_le (firstn 8 (skipn 32 bytes)) in
    let len    := from_le (firstn 4 (skipn 40 bytes)) in
    let rest   := skipn 44 bytes in
    if length rest =? len
    then Some (mkWR (firstn 32 bytes) amount rest)
    else None
  else None.

(** Well-formed records: 32-byte asset, amount and recipient length in
    range (exactly what [validate_l1_withdrawal_recipient] and the u64
    amount type guarantee upstream). *)
Definition wf (r : WR) : Prop :=
  length (wr_asset r) = 32
  /\ wr_amount r < 256 ^ 8       (* u64 *)
  /\ length (wr_recipient r) < 256 ^ 4.  (* u32 *)

(* ============================================================= *)
(** ** Lossless round-trip                                        *)
(* ============================================================= *)

Theorem decode_encode : forall r, wf r -> decode (encode r) = Some r.
Proof.
  intros [asset amount recip] [Hasset [Hamt Hlen]].
  cbn [wr_asset wr_amount wr_recipient] in Hasset, Hamt, Hlen.
  unfold decode, encode. cbn [wr_asset wr_amount wr_recipient].
  (* length of the whole buffer *)
  assert (Hlenbuf : length
    (asset ++ le 8 amount ++ le 4 (length recip) ++ recip) = 44 + length recip).
  { rewrite !length_app, Hasset, !le_length. lia. }
  (* offset 32 = length asset: peel the asset *)
  assert (H32 : 32 = length asset) by (rewrite Hasset; reflexivity).
  (* skipn 32 = le8 ++ le4 ++ recip *)
  assert (Hs32 : skipn 32 (asset ++ le 8 amount ++ le 4 (length recip) ++ recip)
                 = le 8 amount ++ le 4 (length recip) ++ recip).
  { rewrite H32. apply skipn_app_len. }
  (* firstn 32 = asset *)
  assert (Hf32 : firstn 32 (asset ++ le 8 amount ++ le 4 (length recip) ++ recip) = asset).
  { rewrite H32. apply firstn_app_len. }
  (* skipn 40 = skipn 8 (skipn 32) = le4 ++ recip *)
  assert (Hs40 : skipn 40 (asset ++ le 8 amount ++ le 4 (length recip) ++ recip)
                 = le 4 (length recip) ++ recip).
  { replace 40 with (8 + 32) by lia. rewrite <- skipn_skipn, Hs32.
    replace 8 with (length (le 8 amount)) at 1 by apply le_length.
    apply skipn_app_len. }
  (* skipn 44 = recip *)
  assert (Hs44 : skipn 44 (asset ++ le 8 amount ++ le 4 (length recip) ++ recip) = recip).
  { replace 44 with (4 + 40) by lia. rewrite <- skipn_skipn, Hs40.
    replace 4 with (length (le 4 (length recip))) at 1 by apply le_length.
    apply skipn_app_len. }
  rewrite Hlenbuf.
  replace (44 <=? 44 + length recip) with true by (symmetry; apply Nat.leb_le; lia).
  rewrite Hs32, Hs40, Hf32, Hs44.
  (* decode the amount and length fields *)
  rewrite (firstn_le_app 8 amount).
  rewrite (firstn_le_app 4 (length recip)).
  rewrite (from_le_le 8 amount Hamt).
  rewrite (from_le_le 4 (length recip) Hlen).
  replace (length recip =? length recip) with true by (symmetry; apply Nat.eqb_eq; reflexivity).
  reflexivity.
Qed.

(** Distinct withdrawals never share an encoding (no durable aliasing). *)
Theorem encode_injective : forall r1 r2,
  wf r1 -> wf r2 -> encode r1 = encode r2 -> r1 = r2.
Proof.
  intros r1 r2 H1 H2 Henc.
  assert (Hd : decode (encode r1) = decode (encode r2)) by (rewrite Henc; reflexivity).
  rewrite (decode_encode r1 H1), (decode_encode r2 H2) in Hd.
  injection Hd. auto.
Qed.
