(** * Spec.EndToEndMulti — L1<->L2 cross-system solvency, all assets

    [Spec.EndToEnd] proved the cross-system solvency law (L1 FA2
    custody = L2 pool + live notes) for ONE FA2 asset.  This module
    generalizes it to the MULTIASSET setting: the state is per-asset
    ([Felt -> nat]) and the invariant holds for EVERY asset
    simultaneously.  So the bridge holds, for each asset
    independently, exactly the FA2 that backs that asset's L2 claims.

    The per-asset value flow mirrors [EndToEnd]:
    - a DEPOSIT of asset [α] credits L1 custody[α] (a bridge mint) and
      L2 pool[α] (the rollup receiving the minted ticket) atomically;
    - a SHIELD of [α] moves pool[α] -> notes[α] (no L1 effect);
    - an UNSHIELD of [α] debits notes[α] (the unshield) and custody[α]
      (the outbox ticket the bridge burns).
    Each operation touches a single asset; the per-asset accounting is
    independent across assets (FA2-denominated fees are zero — rollup
    and producer fees are tez, handled on the tez lane in
    [Spec.KernelLedger]).

    The L2 pool/note movements are exactly the circuit operations
    whose value conservation [Spec.GrandConservation.grand_conservation]
    proves; this module shows that, given those movements, the L1
    custody stays in lockstep with the L2 claims for every asset.

    Proved (zero admits), for all reachable states and ALL assets:
    - [l1_collateral_equals_l2_claims]: custody a = pool a + notes a;
    - [notes_backed_by_l1]: notes a <= custody a (every live note
      redeemable);
    - [roundtrip_solvency]: out a <= in a (withdrawn <= deposited). *)

From Stdlib Require Import Arith Lia.
From Common Require Import Felt.

Section EndToEndMulti.

  (** Per-asset state of the whole L1<->L2 system. *)
  Record MState : Type := mkMState {
    m_custody : Felt -> nat;   (* L1: FA2 held by the bridge, per asset *)
    m_pool    : Felt -> nat;   (* L2: deposit-pool value, per asset *)
    m_notes   : Felt -> nat;   (* L2: live note value, per asset *)
    m_in      : Felt -> nat;   (* cumulative deposited from L1, per asset *)
    m_out     : Felt -> nat;   (* cumulative withdrawn to L1, per asset *)
  }.

  Definition zero (_ : Felt) : nat := 0.
  Definition mgenesis : MState := mkMState zero zero zero zero zero.

  Definition upd (f : Felt -> nat) (a : Felt) (v : nat) : Felt -> nat :=
    fun x => if Felt_eq_dec x a then v else f x.

  Lemma upd_same f a v : upd f a v a = v.
  Proof. unfold upd. destruct (Felt_eq_dec a a); congruence. Qed.

  Lemma upd_other f a b v : b <> a -> upd f a v b = f b.
  Proof. intro Hne. unfold upd. destruct (Felt_eq_dec b a); congruence. Qed.

  Inductive MStep : MState -> MState -> Prop :=
  | mstep_deposit :
      forall s al n,
        MStep s (mkMState
                   (upd (m_custody s) al (m_custody s al + n))
                   (upd (m_pool s)    al (m_pool s al + n))
                   (m_notes s)
                   (upd (m_in s)      al (m_in s al + n))
                   (m_out s))
  | mstep_shield :
      forall s al v,
        v <= m_pool s al ->
        MStep s (mkMState
                   (m_custody s)
                   (upd (m_pool s)  al (m_pool s al - v))
                   (upd (m_notes s) al (m_notes s al + v))
                   (m_in s)
                   (m_out s))
  | mstep_unshield :
      forall s al v,
        v <= m_notes s al ->
        MStep s (mkMState
                   (upd (m_custody s) al (m_custody s al - v))
                   (m_pool s)
                   (upd (m_notes s)   al (m_notes s al - v))
                   (m_in s)
                   (upd (m_out s)     al (m_out s al + v))).

  Inductive MSteps : MState -> MState -> Prop :=
  | msteps_refl  : forall s, MSteps s s
  | msteps_trans : forall s s' s'', MStep s s' -> MSteps s' s'' -> MSteps s s''.

  (** The per-asset cross-system invariant, for EVERY asset. *)
  Definition minvariant (s : MState) : Prop :=
    forall a : Felt,
      m_custody s a = m_pool s a + m_notes s a
      /\ m_custody s a = m_in s a - m_out s a
      /\ m_out s a <= m_in s a.

  Lemma mgenesis_inv : minvariant mgenesis.
  Proof. intro a. cbn. repeat split; lia. Qed.

  Lemma mstep_preserves : forall s s', minvariant s -> MStep s s' -> minvariant s'.
  Proof.
    intros s s' Hinv Hstep b.
    destruct Hstep as [s al n | s al v Hv | s al v Hv];
      cbn [m_custody m_pool m_notes m_in m_out];
      destruct (Felt_eq_dec b al) as [-> | Hne].
    (* deposit, b = al *)
    - rewrite !upd_same. destruct (Hinv al) as [Hc [Hacc Hle]]. repeat split; lia.
    (* deposit, b <> al *)
    - rewrite !(upd_other _ _ _ _ Hne). exact (Hinv b).
    (* shield, b = al *)
    - rewrite !upd_same. destruct (Hinv al) as [Hc [Hacc Hle]]. repeat split; lia.
    (* shield, b <> al *)
    - rewrite !(upd_other _ _ _ _ Hne). exact (Hinv b).
    (* unshield, b = al *)
    - rewrite !upd_same. destruct (Hinv al) as [Hc [Hacc Hle]]. repeat split; lia.
    (* unshield, b <> al *)
    - rewrite !(upd_other _ _ _ _ Hne). exact (Hinv b).
  Qed.

  Lemma msteps_preserve : forall s s', MSteps s s' -> minvariant s -> minvariant s'.
  Proof.
    intros s s' H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Hinv.
    - exact Hinv.
    - apply IH. eapply mstep_preserves; eauto.
  Qed.

  Theorem reachable_minvariant :
    forall s, MSteps mgenesis s -> minvariant s.
  Proof. intros s H. exact (msteps_preserve mgenesis s H mgenesis_inv). Qed.

  (** ** The multiasset cross-system solvency law.

      For EVERY asset, the FA2 the bridge holds on L1 equals exactly
      the value claimable on L2 (pool + live notes) of that asset. *)
  Theorem l1_collateral_equals_l2_claims :
    forall s a, MSteps mgenesis s ->
      m_custody s a = m_pool s a + m_notes s a.
  Proof. intros s a H. destruct (reachable_minvariant s H a) as [Hc _]. exact Hc. Qed.

  (** Every live note of every asset is backed by real L1 FA2. *)
  Theorem notes_backed_by_l1 :
    forall s a, MSteps mgenesis s -> m_notes s a <= m_custody s a.
  Proof. intros s a H. pose proof (l1_collateral_equals_l2_claims s a H). lia. Qed.

  (** No L1 FA2 of any asset is stranded beyond its L2 claims. *)
  Theorem no_stranded_l1 :
    forall s a, MSteps mgenesis s -> m_custody s a <= m_pool s a + m_notes s a.
  Proof. intros s a H. pose proof (l1_collateral_equals_l2_claims s a H). lia. Qed.

  (** Per-asset round-trip: total withdrawn never exceeds total
      deposited, for every asset. *)
  Theorem roundtrip_solvency :
    forall s a, MSteps mgenesis s -> m_out s a <= m_in s a.
  Proof. intros s a H. destruct (reachable_minvariant s H a) as [_ [_ Hle]]. exact Hle. Qed.

  (** A withdrawal of any asset can always be honored on L1. *)
  Theorem withdrawal_honored :
    forall s a v, MSteps mgenesis s -> v <= m_notes s a -> v <= m_custody s a.
  Proof. intros s a v H Hv. pose proof (notes_backed_by_l1 s a H). lia. Qed.

End EndToEndMulti.
