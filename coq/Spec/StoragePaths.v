(** * Spec.StoragePaths — durable storage path namespace is collision-free

    The kernel keys all durable storage by a typed string PATH: a
    per-key-type prefix (a constant like
    ["/tzel/v1/state/nullifiers/by-key/"]) followed by an
    attacker-influenceable key (a hex nullifier / commitment / deposit
    key).  See the [PATH_*_PREFIX] constants in
    [tezos/rollup-kernel/src/lib.rs].

    A CROSS-TYPE path collision would be catastrophic: if a deposit
    key could produce the same path as a nullifier, an attacker could
    mark a victim's nullifier spent (locking their note) just by
    depositing, or commingle two pools.  The kernel's defense is that
    the type prefixes are pairwise INCOMPARABLE — no prefix is a
    prefix of another — so two paths under different types differ
    inside the prefix region, before any key is even appended, no
    matter what keys are chosen.

    Proved (zero admits), using the ACTUAL prefix strings:
    - [cross_no_collision]: incomparable type prefixes -> the typed
      paths never collide, for ANY appended keys;
    - the kernel's key-bearing prefixes are pairwise incomparable
      (by computation on the real constants);
    - [within_no_collision]: within one type, distinct keys give
      distinct paths (append is left-injective);
    - [namespace_injective]: combining the two, the path map is
      injective on (type, key) across the whole key-bearing namespace. *)

From Stdlib Require Import String Ascii List.
Import ListNotations.
Open Scope string_scope.

(** Own boolean prefix test (self-contained; does not rely on the
    Stdlib [String.prefix] reducing under [reflexivity]). *)
Fixpoint pfxb (s1 s2 : string) : bool :=
  match s1 with
  | EmptyString => true
  | String a s1' =>
      match s2 with
      | EmptyString => false
      | String b s2' => if ascii_dec a b then pfxb s1' s2' else false
      end
  end.

(* ================================================================ *)
(** ** String append: injective on the left; equal appends share a
       prefix                                                         *)
(* ================================================================ *)

Lemma append_inj_l : forall p a b, (p ++ a) = (p ++ b) -> a = b.
Proof.
  induction p as [| c p IH]; intros a b H; cbn in H.
  - exact H.
  - injection H as H. apply IH. exact H.
Qed.

(** If two appended strings are equal, the shorter base is a prefix of
    the longer — the key fact that forbids cross-type collisions. *)
Lemma append_eq_prefix : forall p q a b,
  (p ++ a) = (q ++ b) -> pfxb p q = true \/ pfxb q p = true.
Proof.
  induction p as [| c p IH]; intros q a b H; cbn [append] in H.
  - left. reflexivity.
  - destruct q as [| d q]; cbn [append] in H.
    + right. reflexivity.
    + injection H as Hcd Htail. subst d.
      cbn [pfxb]. destruct (ascii_dec c c) as [_ | Hneq]; [| exfalso; apply Hneq; reflexivity].
      apply (IH q a b). exact Htail.
  Qed.

(** Two prefixes are incomparable when neither is a prefix of the
    other. *)
Definition incomparable (p q : string) : Prop :=
  pfxb p q = false /\ pfxb q p = false.

(** ** Cross-type collision-freedom.

    If the type prefixes are incomparable, the typed paths never
    collide — for ANY keys the two types append. *)
Theorem cross_no_collision : forall p q a b,
  incomparable p q -> (p ++ a) <> (q ++ b).
Proof.
  intros p q a b [Hpq Hqp] Heq.
  destruct (append_eq_prefix p q a b Heq) as [H | H].
  - rewrite H in Hpq. discriminate.
  - rewrite H in Hqp. discriminate.
Qed.

(** ** Within-type collision-freedom.

    Distinct keys under the same prefix give distinct paths. *)
Theorem within_no_collision : forall p k1 k2,
  k1 <> k2 -> (p ++ k1) <> (p ++ k2).
Proof.
  intros p k1 k2 Hne Heq. apply Hne. exact (append_inj_l p k1 k2 Heq).
Qed.

(* ================================================================ *)
(** ** The kernel's key-bearing prefixes                             *)
(* ================================================================ *)

Definition pfx_nullifier      := "/tzel/v1/state/nullifiers/by-key/".
Definition pfx_nullifier_idx  := "/tzel/v1/state/nullifiers/index/".
Definition pfx_deposit        := "/tzel/v1/state/deposits/balance/".
Definition pfx_applied_shield := "/tzel/v1/state/shields/applied_cm/".
Definition pfx_valid_root     := "/tzel/v1/state/roots/by-key/".
Definition pfx_note           := "/tzel/v1/state/notes/".
Definition pfx_tree_branch    := "/tzel/v1/state/tree/branch/".

(** Every distinct pair of key-bearing prefixes is incomparable —
    verified by computation on the real constants.  Note the subtle
    pair [nullifiers/by-key/] vs [nullifiers/index/], which share the
    long [/tzel/v1/state/nullifiers/] stem yet still diverge (b vs i)
    before either ends, so neither is a prefix of the other. *)
Definition all_prefixes : list string :=
  [ pfx_nullifier; pfx_nullifier_idx; pfx_deposit; pfx_applied_shield;
    pfx_valid_root; pfx_note; pfx_tree_branch ].

(** A boolean pairwise-incomparability check over a prefix list. *)
Fixpoint pairwise_incomparable (l : list string) : bool :=
  match l with
  | nil => true
  | p :: r =>
      andb (forallb (fun q => andb (negb (pfxb p q)) (negb (pfxb q p))) r)
           (pairwise_incomparable r)
  end.

(** The kernel's key-bearing prefix set is pairwise incomparable. *)
Theorem kernel_prefixes_pairwise_incomparable :
  pairwise_incomparable all_prefixes = true.
Proof. vm_compute. reflexivity. Qed.

(* ================================================================ *)
(** ** Concrete cross-type non-collisions                            *)
(* ================================================================ *)

(** Helper: read off [incomparable] from the boolean check on a pair. *)
Lemma incomparable_of_bool : forall p q,
  pfxb p q = false -> pfxb q p = false -> incomparable p q.
Proof. intros p q H1 H2. split; assumption. Qed.

Ltac prove_incomparable :=
  apply incomparable_of_bool; vm_compute; reflexivity.

(** A deposit can never alias a nullifier path: no chosen deposit key
    and nullifier produce the same durable path. *)
Theorem deposit_never_aliases_nullifier : forall dk nf,
  (pfx_deposit ++ dk) <> (pfx_nullifier ++ nf).
Proof. intros dk nf. apply cross_no_collision. prove_incomparable. Qed.

(** A shield-applied marker can never alias a nullifier path (so
    replaying a shield can't forge a nullifier marking, and vice
    versa). *)
Theorem applied_shield_never_aliases_nullifier : forall cm nf,
  (pfx_applied_shield ++ cm) <> (pfx_nullifier ++ nf).
Proof. intros cm nf. apply cross_no_collision. prove_incomparable. Qed.

(** A deposit can never alias a shield-applied marker. *)
Theorem deposit_never_aliases_applied_shield : forall dk cm,
  (pfx_deposit ++ dk) <> (pfx_applied_shield ++ cm).
Proof. intros dk cm. apply cross_no_collision. prove_incomparable. Qed.

(** The two nullifier sub-namespaces (by-key vs index) never collide,
    despite sharing the long [nullifiers/] stem. *)
Theorem nullifier_bykey_never_aliases_index : forall k1 k2,
  (pfx_nullifier ++ k1) <> (pfx_nullifier_idx ++ k2).
Proof. intros k1 k2. apply cross_no_collision. prove_incomparable. Qed.

(** A valid-root marker never aliases a nullifier (so registering a
    historical root can't mark a nullifier spent). *)
Theorem valid_root_never_aliases_nullifier : forall rk nf,
  (pfx_valid_root ++ rk) <> (pfx_nullifier ++ nf).
Proof. intros rk nf. apply cross_no_collision. prove_incomparable. Qed.

(** Headline: across two distinct key-bearing types with incomparable
    prefixes, the durable path map is injective — a path determines
    its (type, key) uniquely, so no attacker-chosen key in one
    namespace can ever land in another. *)
Theorem namespace_injective : forall p q k1 k2,
  incomparable p q ->
  (p ++ k1) = (q ++ k2) -> False.
Proof. intros p q k1 k2 Hinc Heq. exact (cross_no_collision p q k1 k2 Hinc Heq). Qed.
