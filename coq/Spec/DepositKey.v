(** * Spec.DepositKey — deposit pool keys are collision-free per pool

    [Spec.StoragePaths] proved different storage TYPES never collide.
    This proves the WITHIN-type key of the deposit-pool namespace is
    injective: [deposit_balance_path] keys a pool by

        hex(asset_id) ++ "/" ++ hex(pubkey_hash)

    (two fixed-width 64-char hex fields and a "/" separator — see
    [deposit_balance_path] in [tezos/rollup-kernel/src/lib.rs]).  If
    two distinct pools [(asset, pubkey)] could produce the same key,
    their balances would COMMINGLE in one durable slot — a deposit to
    one would credit the other, enabling theft.

    Proved (zero admits):
    - [append_eq_fixed]: equal-length prefixes split an equality
      uniquely — the fixed-width framing lemma;
    - [deposit_key_injective]: distinct [(asset, pubkey)] give distinct
      keys (so distinct pools never share a durable slot), GIVEN hex is
      injective and fixed-width;
    - and those two hex facts are GROUNDED, not assumed: a concrete
      byte-level hex (each byte -> two nibble chars) is proved
      injective ([hexs_inj]) and fixed-width ([hexs_len]), via nibble-map
      injectivity ([nib_inj]) established with a left inverse. *)

From Stdlib Require Import String Ascii List Arith Lia.
Import ListNotations.
From Spec Require Import StoragePaths.
Open Scope string_scope.

(* ================================================================ *)
(** ** Fixed-width framing                                           *)
(* ================================================================ *)

(** Two equal-length string prefixes split an append equality
    uniquely.  This is what makes the "/"-separated, fixed-width hex
    key unambiguous. *)
Lemma append_eq_fixed : forall a1 a2 b1 b2 : string,
  String.length a1 = String.length a2 ->
  (a1 ++ b1) = (a2 ++ b2) -> a1 = a2 /\ b1 = b2.
Proof.
  induction a1 as [| c a1 IH]; intros [| d a2] b1 b2 Hlen Heq; cbn in *.
  - split; [reflexivity | exact Heq].
  - discriminate Hlen.
  - discriminate Hlen.
  - injection Heq as Hcd Htail. injection Hlen as Hlen. subst d.
    destruct (IH a2 b1 b2 Hlen Htail) as [Ha Hb]. subst. split; reflexivity.
Qed.

(* ================================================================ *)
(** ** The deposit key, over an abstract fixed-width injective hex    *)
(* ================================================================ *)

Section DepositKey.

  Variable Felt : Type.
  Variable hex : Felt -> string.
  Variable W : nat.
  Hypothesis hex_len : forall x, String.length (hex x) = W.
  Hypothesis hex_inj : forall x y, hex x = hex y -> x = y.

  Definition sep : string := "/".

  Definition deposit_key (asset pubkey : Felt) : string :=
    hex asset ++ sep ++ hex pubkey.

  (** Distinct pools never share a durable key: the path map is
      injective in (asset, pubkey). *)
  Theorem deposit_key_injective : forall a1 p1 a2 p2,
    deposit_key a1 p1 = deposit_key a2 p2 -> a1 = a2 /\ p1 = p2.
  Proof.
    intros a1 p1 a2 p2 Heq. unfold deposit_key in Heq.
    assert (Hlen : String.length (hex a1) = String.length (hex a2))
      by (rewrite !hex_len; reflexivity).
    destruct (append_eq_fixed _ _ _ _ Hlen Heq) as [Hasset Hrest].
    split.
    - apply hex_inj. exact Hasset.
    - apply hex_inj. exact (append_inj_l sep (hex p1) (hex p2) Hrest).
  Qed.

End DepositKey.

(* ================================================================ *)
(** ** Grounding: a concrete hex is injective and fixed-width         *)
(* ================================================================ *)

(** Nibble (0..15) to lowercase hex char. *)
Definition nib (n : nat) : ascii :=
  match n with
  | 0 => "0"%char | 1 => "1"%char | 2 => "2"%char | 3 => "3"%char
  | 4 => "4"%char | 5 => "5"%char | 6 => "6"%char | 7 => "7"%char
  | 8 => "8"%char | 9 => "9"%char | 10 => "a"%char | 11 => "b"%char
  | 12 => "c"%char | 13 => "d"%char | 14 => "e"%char | _ => "f"%char
  end.

(** A left inverse, used only to prove [nib] injective on 0..15. *)
Definition unnib (a : ascii) : nat :=
  if ascii_dec a "0"%char then 0 else if ascii_dec a "1"%char then 1
  else if ascii_dec a "2"%char then 2 else if ascii_dec a "3"%char then 3
  else if ascii_dec a "4"%char then 4 else if ascii_dec a "5"%char then 5
  else if ascii_dec a "6"%char then 6 else if ascii_dec a "7"%char then 7
  else if ascii_dec a "8"%char then 8 else if ascii_dec a "9"%char then 9
  else if ascii_dec a "a"%char then 10 else if ascii_dec a "b"%char then 11
  else if ascii_dec a "c"%char then 12 else if ascii_dec a "d"%char then 13
  else if ascii_dec a "e"%char then 14 else if ascii_dec a "f"%char then 15
  else 99.

Lemma unnib_nib : forall n, n < 16 -> unnib (nib n) = n.
Proof.
  intros n Hn.
  do 16 (destruct n as [| n]; [vm_compute; reflexivity |]).
  exfalso. lia.
Qed.

Lemma nib_inj : forall x y, x < 16 -> y < 16 -> nib x = nib y -> x = y.
Proof.
  intros x y Hx Hy Heq.
  rewrite <- (unnib_nib x Hx), <- (unnib_nib y Hy), Heq. reflexivity.
Qed.

(** One byte -> two hex chars. *)
Definition hex_byte (b : nat) : string :=
  String (nib (b / 16)) (String (nib (b mod 16)) EmptyString).

(** A felt as a byte list -> hex string. *)
Fixpoint hexs (bs : list nat) : string :=
  match bs with
  | [] => EmptyString
  | b :: r => hex_byte b ++ hexs r
  end.

Lemma hexs_len : forall bs, String.length (hexs bs) = 2 * length bs.
Proof.
  induction bs as [| b r IH]; cbn [hexs length].
  - reflexivity.
  - unfold hex_byte. cbn [String.length String.append]. rewrite IH. lia.
Qed.

(** [hex_byte] is injective on bytes (< 256, so both nibbles < 16). *)
Lemma hex_byte_inj : forall b1 b2,
  b1 < 256 -> b2 < 256 -> hex_byte b1 = hex_byte b2 -> b1 = b2.
Proof.
  intros b1 b2 H1 H2 Heq. unfold hex_byte in Heq.
  injection Heq as Hhi Hlo.
  assert (Hhi16 : b1 / 16 < 16) by (apply Nat.Div0.div_lt_upper_bound; lia).
  assert (Hhi16' : b2 / 16 < 16) by (apply Nat.Div0.div_lt_upper_bound; lia).
  pose proof (nib_inj _ _ Hhi16 Hhi16' Hhi) as Hdiv.
  pose proof (nib_inj _ _ (Nat.mod_upper_bound b1 16 ltac:(lia))
                       (Nat.mod_upper_bound b2 16 ltac:(lia)) Hlo) as Hmod.
  pose proof (Nat.div_mod b1 16 ltac:(lia)) as E1.
  pose proof (Nat.div_mod b2 16 ltac:(lia)) as E2.
  lia.
Qed.

(** [hexs] is injective on equal-length byte lists with bytes < 256
    (32-byte felts qualify). *)
Lemma hexs_inj : forall bs1 bs2,
  length bs1 = length bs2 ->
  Forall (fun b => b < 256) bs1 -> Forall (fun b => b < 256) bs2 ->
  hexs bs1 = hexs bs2 -> bs1 = bs2.
Proof.
  induction bs1 as [| b1 r1 IH]; intros [| b2 r2] Hlen Hf1 Hf2 Heq; cbn in *.
  - reflexivity.
  - discriminate Hlen.
  - discriminate Hlen.
  - inversion Hf1 as [| ? ? Hb1 Hr1]; subst.
    inversion Hf2 as [| ? ? Hb2 Hr2]; subst.
    injection Hlen as Hlen.
    assert (Hbytelen : String.length (hex_byte b1) = String.length (hex_byte b2))
      by reflexivity.
    destruct (append_eq_fixed _ _ _ _ Hbytelen Heq) as [Hhead Htail].
    rewrite (hex_byte_inj b1 b2 Hb1 Hb2 Hhead).
    rewrite (IH r2 Hlen Hr1 Hr2 Htail). reflexivity.
  Qed.

(** Concrete deposit-key injectivity for 32-byte felts (byte lists,
    each byte < 256), grounding the abstract framing in the real hex
    encoding — no assumed [hex_inj], it is [hexs_inj] above. *)
Definition slash : string := "/".

Definition deposit_key_bytes (asset pubkey : list nat) : string :=
  hexs asset ++ slash ++ hexs pubkey.

Theorem deposit_key_bytes_injective : forall a1 p1 a2 p2,
  length a1 = 32 -> length a2 = 32 -> length p1 = 32 -> length p2 = 32 ->
  Forall (fun b => b < 256) a1 -> Forall (fun b => b < 256) a2 ->
  Forall (fun b => b < 256) p1 -> Forall (fun b => b < 256) p2 ->
  deposit_key_bytes a1 p1 = deposit_key_bytes a2 p2 ->
  a1 = a2 /\ p1 = p2.
Proof.
  intros a1 p1 a2 p2 Ha1 Ha2 Hp1 Hp2 Fa1 Fa2 Fp1 Fp2 Heq.
  unfold deposit_key_bytes in Heq.
  assert (Hlen : String.length (hexs a1) = String.length (hexs a2))
    by (rewrite !hexs_len, Ha1, Ha2; reflexivity).
  destruct (append_eq_fixed _ _ _ _ Hlen Heq) as [Hasset Hrest].
  split.
  - apply hexs_inj; [rewrite Ha1, Ha2; reflexivity | exact Fa1 | exact Fa2 | exact Hasset].
  - apply hexs_inj; [rewrite Hp1, Hp2; reflexivity | exact Fp1 | exact Fp2 |].
    exact (append_inj_l slash (hexs p1) (hexs p2) Hrest).
Qed.
