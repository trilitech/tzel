(** * Spec.KernelLedger — end-to-end kernel value conservation

    [Spec.KernelPool] proved per-pool solvency; [Spec.LedgerNf] proved
    the note system conserves and never inflates.  This module joins
    them into ONE aggregate per-asset accounting over the kernel's
    whole value lifecycle, and proves the end-to-end law: nothing can
    be withdrawn beyond what was deposited.

    Per asset [a] the state tracks five running totals:
    - [ks_dep a]   — deposited from L1 (bridge tickets in);
    - [ks_pool a]  — sitting in deposit pools, not yet shielded;
    - [ks_notes a] — live value in the commitment tree;
    - [ks_burned a]— fees burned (rollup / DAL producer public fees);
    - [ks_wd a]    — withdrawn to L1 (unshield public exits).

    The invariant maintained by every transition:

      ks_dep a = ks_pool a + ks_notes a + ks_burned a + ks_wd a

    "every deposited unit is in exactly one place — a pool, a live
    note, burned, or withdrawn".  Hence [no_inflation]: withdrawn(a)
    <= deposited(a).

    The transitions mirror the kernel's value moves:
    - [kstep_deposit]    L1 -> pool.
    - [kstep_shield_tez] tez pool -> recipient + producer notes, fee
      burned (single pool: v_note + producer_fee + fee).
    - [kstep_shield_fa2] the DUAL-POOL FA2 shield (PR #36 item 2): the
      FA2 pool funds v_note + fee, and the SAME pubkey_hash's TEZ pool
      funds producer_fee — so the tez producer note is backed by a
      real tez debit, NOT minted.  This is the only transition that
      touches two assets at once, and it is exactly where "no
      unbacked tez" lives.
    - [kstep_withdraw]   note -> L1 (unshield public exit).
    - [kstep_burn_fee]   note -> burned (the public fee of a transfer
      or unshield; the producer-fee note and all change are
      note-internal and conserved per asset by [Spec.LedgerNf], so
      they do not move any per-asset aggregate).

    Faithfulness boundary: the per-asset note-internal conservation a
    transfer relies on is the [Spec.LedgerNf] result; this module adds
    the pool<->note<->L1 boundary on top of it, at the aggregate
    (per-asset sum) level. *)

From Stdlib Require Import Arith Lia.
From Common Require Import Felt.

Section KernelLedger.

  (** The canonical tez asset tag. *)
  Variable asset_tez : Felt.

  Record KState : Type := mkKState {
    ks_dep    : Felt -> nat;
    ks_pool   : Felt -> nat;
    ks_notes  : Felt -> nat;
    ks_burned : Felt -> nat;
    ks_wd     : Felt -> nat;
  }.

  Definition zerof : Felt -> nat := fun _ => 0.
  Definition kgenesis : KState := mkKState zerof zerof zerof zerof zerof.

  (** Pointwise update of one asset's entry. *)
  Definition upd (f : Felt -> nat) (a : Felt) (v : nat) : Felt -> nat :=
    fun x => if Felt_eq_dec x a then v else f x.

  Lemma upd_same (f : Felt -> nat) (a : Felt) (v : nat) : upd f a v a = v.
  Proof. unfold upd. destruct (Felt_eq_dec a a); congruence. Qed.

  Lemma upd_other (f : Felt -> nat) (a b : Felt) (v : nat) :
    b <> a -> upd f a v b = f b.
  Proof. intro Hne. unfold upd. destruct (Felt_eq_dec b a); congruence. Qed.

  Definition invariant (s : KState) : Prop :=
    forall a : Felt,
      ks_dep s a = ks_pool s a + ks_notes s a + ks_burned s a + ks_wd s a.

  (** ** Transitions *)

  Inductive KStep : KState -> KState -> Prop :=
  | kstep_deposit :
      forall s a v,
        KStep s (mkKState
                   (upd (ks_dep s) a (ks_dep s a + v))
                   (upd (ks_pool s) a (ks_pool s a + v))
                   (ks_notes s) (ks_burned s) (ks_wd s))
  | kstep_shield_tez :
      forall s v_note producer_fee fee,
        v_note + producer_fee + fee <= ks_pool s asset_tez ->
        KStep s (mkKState
                   (ks_dep s)
                   (upd (ks_pool s) asset_tez
                        (ks_pool s asset_tez - (v_note + producer_fee + fee)))
                   (upd (ks_notes s) asset_tez
                        (ks_notes s asset_tez + (v_note + producer_fee)))
                   (upd (ks_burned s) asset_tez (ks_burned s asset_tez + fee))
                   (ks_wd s))
  | kstep_shield_fa2 :
      forall s A v_note fee producer_fee,
        A <> asset_tez ->
        v_note + fee <= ks_pool s A ->
        producer_fee <= ks_pool s asset_tez ->
        KStep s (mkKState
                   (ks_dep s)
                   (upd (upd (ks_pool s) A (ks_pool s A - (v_note + fee)))
                        asset_tez (ks_pool s asset_tez - producer_fee))
                   (upd (upd (ks_notes s) A (ks_notes s A + v_note))
                        asset_tez (ks_notes s asset_tez + producer_fee))
                   (upd (ks_burned s) A (ks_burned s A + fee))
                   (ks_wd s))
  | kstep_withdraw :
      forall s a v_pub,
        v_pub <= ks_notes s a ->
        KStep s (mkKState
                   (ks_dep s) (ks_pool s)
                   (upd (ks_notes s) a (ks_notes s a - v_pub))
                   (ks_burned s)
                   (upd (ks_wd s) a (ks_wd s a + v_pub)))
  | kstep_burn_fee :
      forall s fee,
        fee <= ks_notes s asset_tez ->
        KStep s (mkKState
                   (ks_dep s) (ks_pool s)
                   (upd (ks_notes s) asset_tez (ks_notes s asset_tez - fee))
                   (upd (ks_burned s) asset_tez (ks_burned s asset_tez + fee))
                   (ks_wd s)).

  Inductive KSteps : KState -> KState -> Prop :=
  | ksteps_refl  : forall s, KSteps s s
  | ksteps_trans : forall s s' s'', KStep s s' -> KSteps s' s'' -> KSteps s s''.

  Lemma genesis_invariant : invariant kgenesis.
  Proof. intro a. reflexivity. Qed.

  Lemma step_preserves_invariant :
    forall s s', invariant s -> KStep s s' -> invariant s'.
  Proof.
    intros s s' Hinv Hstep.
    destruct Hstep as [ s b v
                      | s v_note producer_fee fee Htez
                      | s A v_note fee producer_fee HAne HA Htez
                      | s b v_pub Hnotes
                      | s fee Hfee ];
      intro a; cbn [ks_dep ks_pool ks_notes ks_burned ks_wd].
    - (* deposit at b *)
      destruct (Felt_eq_dec a b) as [-> | Hne].
      + rewrite !upd_same. specialize (Hinv b). lia.
      + rewrite !(upd_other _ _ _ _ Hne). apply Hinv.
    - (* shield_tez at asset_tez *)
      destruct (Felt_eq_dec a asset_tez) as [-> | Hne].
      + rewrite !upd_same. specialize (Hinv asset_tez). lia.
      + rewrite !(upd_other _ _ _ _ Hne). apply Hinv.
    - (* shield_fa2 at A and asset_tez *)
      destruct (Felt_eq_dec a A) as [-> | HneA].
      + (* a = A (note A <> asset_tez) *)
        rewrite !(upd_other _ _ _ _ HAne). rewrite !upd_same.
        specialize (Hinv A). lia.
      + destruct (Felt_eq_dec a asset_tez) as [-> | Hnetez].
        * (* a = asset_tez *)
          rewrite !upd_same.
          rewrite (upd_other _ _ _ _ (fun e : asset_tez = A => HAne (eq_sym e))).
          specialize (Hinv asset_tez). lia.
        * (* a is neither *)
          rewrite !(upd_other _ _ _ _ Hnetez).
          rewrite !(upd_other _ _ _ _ HneA).
          apply Hinv.
    - (* withdraw at b *)
      destruct (Felt_eq_dec a b) as [-> | Hne].
      + rewrite !upd_same. specialize (Hinv b). lia.
      + rewrite !(upd_other _ _ _ _ Hne). apply Hinv.
    - (* burn_fee at asset_tez *)
      destruct (Felt_eq_dec a asset_tez) as [-> | Hne].
      + rewrite !upd_same. specialize (Hinv asset_tez). lia.
      + rewrite !(upd_other _ _ _ _ Hne). apply Hinv.
  Qed.

  Lemma steps_preserve_invariant :
    forall s s', KSteps s s' -> invariant s -> invariant s'.
  Proof.
    intros s s' Hsteps.
    induction Hsteps as [s | s s' s'' Hstep Hrest IH]; intro Hinv.
    - exact Hinv.
    - apply IH. eapply step_preserves_invariant; eauto.
  Qed.

  Theorem reachable_invariant :
    forall s, KSteps kgenesis s -> invariant s.
  Proof.
    intros s H. exact (steps_preserve_invariant kgenesis s H genesis_invariant).
  Qed.

  (** ** End-to-end no inflation

      In every reachable kernel state, for every asset, the total
      withdrawn to L1 is at most the total deposited from L1 — across
      the entire pool / note / fee / withdrawal lifecycle, including
      the FA2 dual-pool shield. *)
  Theorem no_inflation :
    forall s a, KSteps kgenesis s -> ks_wd s a <= ks_dep s a.
  Proof.
    intros s a H. pose proof (reachable_invariant s H a). lia.
  Qed.

  (** A sharper statement of "no unbacked tez": withdrawn + still-live
      + burned never exceeds deposited, for every asset, so the
      producer-fee tez minted by FA2 shields is fully backed. *)
  Theorem outflows_backed :
    forall s a, KSteps kgenesis s ->
      ks_wd s a + ks_notes s a + ks_burned s a <= ks_dep s a.
  Proof.
    intros s a H. pose proof (reachable_invariant s H a). lia.
  Qed.

End KernelLedger.
