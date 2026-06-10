(** * Spec.AssetRegistry — registry round-trip consistency

    Models the kernel's asset registry ([compose_asset_registry_with],
    [asset_for_ticketer], [ticketer_for_asset] in [core/src/lib.rs])
    and proves the routing-correctness property the security review
    flagged: deposit routing (ticketer -> asset) and withdrawal
    routing (asset -> ticketer) are PROPER MUTUAL INVERSES.  Both
    lookups are first-match, so this is FALSE without:

    - [derive_asset_id] injective on distinct ticketers (a
      collision-resistance assumption — [asset_id = H("tzel:asset:" ||
      ticketer)]), and
    - [derive_asset_id t <> ASSET_TEZ] for every FA2 ticketer (the
      tez tag is 0; FA2 ids are nonzero hashes — domain separation),

    plus the registry's own [dedup] of an FA2 ticketer that equals the
    tez ticketer.  Without these, two ticketers could share an
    asset_id (or an FA2 ticketer alias the tez one), and a deposit of
    asset A could unlock a withdrawal routed to the WRONG bridge.

    The collision-resistance / nonzero hypotheses are exactly the kind
    [Spec.Hashes] takes for nullifiers/commitments; here they make the
    cross-layer asset routing provably unambiguous. *)

From Stdlib Require Import List Arith.
Import ListNotations.

Section Registry.

  Variable Ticketer Asset : Type.
  Variable Ticketer_eq_dec : forall x y : Ticketer, {x = y} + {x <> y}.
  Variable Asset_eq_dec    : forall x y : Asset, {x = y} + {x <> y}.

  Variable asset_tez : Asset.
  Variable derive : Ticketer -> Asset.   (* derive_asset_id *)
  Hypothesis derive_inj :
    forall t1 t2, derive t1 = derive t2 -> t1 = t2.
  Hypothesis derive_not_tez :
    forall t, derive t <> asset_tez.

  (** [compose_asset_registry_with]: a tez entry, then FA2 entries
      [(t, derive t)] skipping any ticketer equal to the tez one. *)
  Fixpoint dedup_fa2 (tez : Ticketer) (l : list Ticketer) : list (Ticketer * Asset) :=
    match l with
    | [] => []
    | t :: r =>
        if Ticketer_eq_dec t tez
        then dedup_fa2 tez r
        else (t, derive t) :: dedup_fa2 tez r
    end.

  Definition compose (tez : Ticketer) (fa2 : list Ticketer) : list (Ticketer * Asset) :=
    (tez, asset_tez) :: dedup_fa2 tez fa2.

  (** First-match lookups. *)
  Fixpoint a4t (reg : list (Ticketer * Asset)) (t : Ticketer) : option Asset :=
    match reg with
    | [] => None
    | (t', a) :: r => if Ticketer_eq_dec t' t then Some a else a4t r t
    end.

  Fixpoint t4a (reg : list (Ticketer * Asset)) (a : Asset) : option Ticketer :=
    match reg with
    | [] => None
    | (t, a') :: r => if Asset_eq_dec a' a then Some t else t4a r a
    end.

  (* ============================================================= *)
  (** ** Lookup basics                                              *)
  (* ============================================================= *)

  Lemma a4t_some_in : forall reg t a, a4t reg t = Some a -> In (t, a) reg.
  Proof.
    induction reg as [| [t0 a0] r IH]; intros t a H; cbn in H.
    - discriminate.
    - destruct (Ticketer_eq_dec t0 t) as [-> | Hne].
      + injection H as ->. left. reflexivity.
      + right. apply IH. exact H.
  Qed.

  Lemma t4a_some_in : forall reg a t, t4a reg a = Some t -> In (t, a) reg.
  Proof.
    induction reg as [| [t0 a0] r IH]; intros a t H; cbn in H.
    - discriminate.
    - destruct (Asset_eq_dec a0 a) as [-> | Hne].
      + injection H as ->. left. reflexivity.
      + right. apply IH. exact H.
  Qed.

  Lemma in_map_snd : forall (reg : list (Ticketer * Asset)) t a,
    In (t, a) reg -> In a (map snd reg).
  Proof.
    intros reg t a Hin. apply (in_map snd) in Hin. exact Hin.
  Qed.

  Lemma in_map_fst : forall (reg : list (Ticketer * Asset)) t a,
    In (t, a) reg -> In t (map fst reg).
  Proof.
    intros reg t a Hin. apply (in_map fst) in Hin. exact Hin.
  Qed.

  (* ============================================================= *)
  (** ** Round-trip under distinct keys                             *)
  (* ============================================================= *)

  (** The crux: with distinct ticketers AND distinct asset_ids, the
      two first-match lookups invert each other. *)
  Lemma roundtrip_ta : forall reg t a,
    NoDup (map snd reg) ->
    a4t reg t = Some a -> t4a reg a = Some t.
  Proof.
    induction reg as [| [t0 a0] r IH]; intros t a Hnd Ha; cbn in Ha.
    - discriminate.
    - cbn [map] in Hnd. inversion Hnd as [| ? ? Hnotin Hndr]; subst.
      destruct (Ticketer_eq_dec t0 t) as [-> | Hne].
      + (* head ticketer matches: a = a0 *)
        injection Ha as ->. cbn.
        destruct (Asset_eq_dec a a) as [_ | Hcontra]; [reflexivity | congruence].
      + (* recurse; head asset a0 differs from a since a is in the tail *)
        assert (Hina : In a (map snd r)).
        { apply (in_map_snd r t a). apply a4t_some_in. exact Ha. }
        cbn. destruct (Asset_eq_dec a0 a) as [-> | Hne2].
        * exfalso. apply Hnotin. exact Hina.
        * apply IH; assumption.
  Qed.

  Lemma roundtrip_at : forall reg t a,
    NoDup (map fst reg) ->
    t4a reg a = Some t -> a4t reg t = Some a.
  Proof.
    induction reg as [| [t0 a0] r IH]; intros t a Hnd Ht; cbn in Ht.
    - discriminate.
    - cbn [map] in Hnd. inversion Hnd as [| ? ? Hnotin Hndr]; subst.
      destruct (Asset_eq_dec a0 a) as [-> | Hne].
      + injection Ht as ->. cbn.
        destruct (Ticketer_eq_dec t t) as [_ | Hcontra]; [reflexivity | congruence].
      + assert (Hint : In t (map fst r)).
        { apply (in_map_fst r t a). apply t4a_some_in. exact Ht. }
        cbn. destruct (Ticketer_eq_dec t0 t) as [-> | Hne2].
        * exfalso. apply Hnotin. exact Hint.
        * apply IH; assumption.
  Qed.

  (* ============================================================= *)
  (** ** The composed registry has distinct keys                    *)
  (* ============================================================= *)

  (** Every entry in [dedup_fa2] is an FA2 entry [(t, derive t)] for a
      ticketer in the input that is not the tez one. *)
  Lemma dedup_fa2_entry : forall tez l t a,
    In (t, a) (dedup_fa2 tez l) -> a = derive t /\ t <> tez.
  Proof.
    intros tez l. induction l as [| u r IH]; intros t a Hin; cbn in Hin.
    - contradiction.
    - destruct (Ticketer_eq_dec u tez) as [-> | Hne].
      + apply IH. exact Hin.
      + destruct Hin as [Heq | Hin].
        * injection Heq as -> ->. split; [reflexivity | exact Hne].
        * apply IH. exact Hin.
  Qed.

  (** Helper used above: membership of an FA2 entry implies membership
      of its ticketer in the source list. *)
  Lemma a4t_some_in_dedup : forall tez l t a,
    In (t, a) (dedup_fa2 tez l) -> In t l.
  Proof.
    intros tez l. induction l as [| u r IH]; intros t a Hin; cbn in Hin.
    - contradiction.
    - destruct (Ticketer_eq_dec u tez) as [-> | Hne].
      + right. apply (IH t a). exact Hin.
      + destruct Hin as [Heq | Hin].
        * injection Heq as -> _. left. reflexivity.
        * right. apply (IH t a). exact Hin.
  Qed.

  Lemma dedup_fa2_ticketers : forall tez l,
    NoDup l -> NoDup (map fst (dedup_fa2 tez l)).
  Proof.
    intros tez l. induction l as [| u r IH]; intro Hnd; cbn.
    - constructor.
    - inversion Hnd as [| ? ? Hnotin Hndr]; subst.
      destruct (Ticketer_eq_dec u tez) as [-> | Hne].
      + apply IH. exact Hndr.
      + cbn. constructor.
        * (* u not among the tail's ticketers *)
          intro Hin. apply in_map_iff in Hin.
          destruct Hin as [[t' a'] [Hfst Hin']]. cbn in Hfst. subst t'.
          destruct (dedup_fa2_entry tez r u a' Hin') as [_ Hne'].
          apply Hnotin.
          (* In u r : recover from membership of (u,a') *)
          apply (a4t_some_in_dedup tez r u a' Hin').
        * apply IH. exact Hndr.
  Qed.

  (** The FA2 asset_ids are distinct (derive injective on the
      distinct, tez-filtered ticketers). *)
  Lemma dedup_fa2_assets : forall tez l,
    NoDup l -> NoDup (map snd (dedup_fa2 tez l)).
  Proof.
    intros tez l. induction l as [| u r IH]; intro Hnd; cbn.
    - constructor.
    - inversion Hnd as [| ? ? Hnotin Hndr]; subst.
      destruct (Ticketer_eq_dec u tez) as [-> | Hne].
      + apply IH. exact Hndr.
      + cbn. constructor.
        * (* derive u not among the tail's asset_ids *)
          intro Hin. apply in_map_iff in Hin.
          destruct Hin as [[t' a'] [Hsnd Hin']]. cbn in Hsnd. subst a'.
          destruct (dedup_fa2_entry tez r t' (derive u) Hin') as [Hderiv _].
          (* derive t' = derive u -> t' = u (injective) -> In u r -> contra *)
          symmetry in Hderiv. apply derive_inj in Hderiv. subst t'.
          apply Hnotin. apply (a4t_some_in_dedup tez r u (derive u) Hin').
        * apply IH. exact Hndr.
  Qed.

  (* ============================================================= *)
  (** ** The registry's keys are distinct                           *)
  (* ============================================================= *)

  (** [compose] yields distinct ticketers (the tez one is not in the
      filtered FA2 part). *)
  Lemma compose_ticketers_nodup : forall tez fa2,
    NoDup fa2 -> NoDup (map fst (compose tez fa2)).
  Proof.
    intros tez fa2 Hnd. unfold compose. cbn [map fst].
    constructor.
    - (* tez not among the FA2 ticketers (all <> tez by dedup) *)
      intro Hin. apply in_map_iff in Hin.
      destruct Hin as [[t' a'] [Hfst Hin']]. cbn in Hfst. subst t'.
      destruct (dedup_fa2_entry tez fa2 tez a' Hin') as [_ Hne]. apply Hne. reflexivity.
    - apply dedup_fa2_ticketers. exact Hnd.
  Qed.

  (** [compose] yields distinct asset_ids (tez tag <> any FA2 hash,
      and the FA2 hashes are distinct). *)
  Lemma compose_assets_nodup : forall tez fa2,
    NoDup fa2 -> NoDup (map snd (compose tez fa2)).
  Proof.
    intros tez fa2 Hnd. unfold compose. cbn [map snd].
    constructor.
    - (* asset_tez not among the FA2 asset_ids (each is derive _ <> tez) *)
      intro Hin. apply in_map_iff in Hin.
      destruct Hin as [[t' a'] [Hsnd Hin']]. cbn in Hsnd. subst a'.
      destruct (dedup_fa2_entry tez fa2 t' asset_tez Hin') as [Hderiv _].
      apply (derive_not_tez t'). rewrite <- Hderiv. reflexivity.
    - apply dedup_fa2_assets. exact Hnd.
  Qed.

  (* ============================================================= *)
  (** ** Top-level: deposit and withdrawal routing are inverse      *)
  (* ============================================================= *)

  (** For a well-formed registry, deposit routing then withdrawal
      routing returns the SAME ticketer: a ticketer the registry maps
      to asset [a] is exactly the one a withdrawal of [a] routes back
      to.  This is the cross-layer consistency the security review
      asked for — no deposit of asset A can unlock a withdrawal sent
      to a different bridge. *)
  Theorem deposit_withdraw_roundtrip : forall tez fa2 t a,
    NoDup fa2 ->
    a4t (compose tez fa2) t = Some a ->
    t4a (compose tez fa2) a = Some t.
  Proof.
    intros tez fa2 t a Hnd Ha.
    apply roundtrip_ta; [apply compose_assets_nodup; exact Hnd | exact Ha].
  Qed.

  (** And the other direction: withdrawal routing then deposit routing
      returns the same asset. *)
  Theorem withdraw_deposit_roundtrip : forall tez fa2 t a,
    NoDup fa2 ->
    t4a (compose tez fa2) a = Some t ->
    a4t (compose tez fa2) t = Some a.
  Proof.
    intros tez fa2 t a Hnd Ht.
    apply roundtrip_at; [apply compose_ticketers_nodup; exact Hnd | exact Ht].
  Qed.

  (** A ticketer present in the (tez-filtered) list is found by the
      deposit lookup, returning its derived asset. *)
  Lemma a4t_dedup_in : forall tez l u,
    In u l -> u <> tez -> a4t (dedup_fa2 tez l) u = Some (derive u).
  Proof.
    intros tez l. induction l as [| w r IH]; intros u Hin Hne; cbn.
    - contradiction.
    - destruct (Ticketer_eq_dec w tez) as [-> | Hwt].
      + (* w = tez: u <> tez so u is in r *)
        destruct Hin as [Heq | Hin]; [subst; contradiction (Hne eq_refl) |].
        apply IH; assumption.
      + cbn. destruct (Ticketer_eq_dec w u) as [-> | Hwu].
        * reflexivity.
        * destruct Hin as [Heq | Hin]; [subst; contradiction (Hwu eq_refl) |].
          apply IH; assumption.
  Qed.

  (** Concretely: a registered FA2 ticketer [u] (in the list, not the
      tez one) routes deposits to [derive u] and withdrawals of
      [derive u] back to [u]. *)
  Theorem fa2_routes_correctly : forall tez fa2 u,
    NoDup fa2 -> In u fa2 -> u <> tez ->
    a4t (compose tez fa2) u = Some (derive u)
    /\ t4a (compose tez fa2) (derive u) = Some u.
  Proof.
    intros tez fa2 u Hnd Hin Hne.
    assert (Ha : a4t (compose tez fa2) u = Some (derive u)).
    { unfold compose. cbn [a4t].
      destruct (Ticketer_eq_dec tez u) as [Hte | _].
      - exfalso. apply Hne. symmetry. exact Hte.
      - apply a4t_dedup_in; assumption. }
    split; [exact Ha |].
    apply deposit_withdraw_roundtrip; assumption.
  Qed.
End Registry.
