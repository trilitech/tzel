(** * Spec.ShieldReplay — shield replay protection (no duplicate notes)

    The kernel records each successfully-applied shield's [client_cm]
    in an append-only marker set ([applied_shield_path] /
    [has_marker] in [tezos/rollup-kernel/src/lib.rs]) and rejects any
    shield whose [client_cm] is already present.  Without this, an
    attacker could top up a drained pool and RESUBMIT a victim's old
    shield proof, minting a DUPLICATE of the victim's recipient note
    at a fresh tree position — independently spendable (nullifiers
    are per-position), doubling the recipient's balance at the
    attacker's expense.

    The mechanism is an append-only set with "accept iff fresh,
    insert on apply" — structurally identical to the kernel's
    nullifier set.  Rather than duplicate the proof, we INSTANTIATE
    the generic machinery of [Spec.KernelNullifier] (whose section is
    polymorphic over the marker type) at the commitment type, and
    layer on the shield-specific security consequence.

    This is the honest observation that one verified mechanism (the
    append-only dedup set) covers TWO distinct attack surfaces:
    double-spend (nullifiers) and shield-replay note-duplication
    (client commitments). *)

From Stdlib Require Import List.
Import ListNotations.
From Spec Require Import KernelNullifier.

Section ShieldReplay.

  (** Note commitments (the [client_cm] of a shield). *)
  Variable Cm : Type.
  Variable Cm_eq_dec : forall x y : Cm, {x = y} + {x <> y}.

  (** The applied-shield set is the generic dedup set at [Cm]; a shield
      presenting commitment [c] is "applied" by the singleton step
      [[c]]. *)
  Definition applied := NfState Cm.
  Definition applied_genesis : applied := nf_genesis Cm.

  (** A shield carrying [client_cm = c] is acceptable iff [c] has not
      already been applied. *)
  Definition shield_acceptable (s : applied) (c : Cm) : Prop :=
    acceptable Cm s [c].

  Lemma shield_acceptable_iff : forall s c,
    shield_acceptable s c <-> ~ In c s.
  Proof.
    intros s c. unfold shield_acceptable, acceptable. split.
    - intros [_ Hfresh]. apply Hfresh. left. reflexivity.
    - intro Hni. split.
      + repeat constructor. intro Hin. inversion Hin.
      + intros n Hin. cbn in Hin. destruct Hin as [-> | []]. exact Hni.
  Qed.

  (* ============================================================= *)
  (** ** Shield-replay theorems (instances of the generic dedup)     *)
  (* ============================================================= *)

  (** The applied-shield set never holds a duplicate: no commitment is
      ever recorded by two shields. *)
  Theorem applied_set_nodup :
    forall s, NfSteps Cm applied_genesis s -> NoDup s.
  Proof. exact (reachable_nodup Cm). Qed.

  (** Replay rejected: a shield re-presenting an already-applied
      commitment cannot take a step. *)
  Theorem shield_replay_rejected :
    forall s c, In c s -> ~ shield_acceptable s c.
  Proof.
    intros s c Hin Hacc.
    apply (respend_rejected Cm s [c] c Hin).
    - left. reflexivity.
    - exact Hacc.
  Qed.

  (** Once applied, a commitment stays applied — the set only grows. *)
  Theorem applied_is_permanent :
    forall s s' c, NfSteps Cm s s' -> In c s -> In c s'.
  Proof. exact (spent_is_permanent Cm). Qed.

  (** ** No duplicate note from replay.

      The headline consequence.  Once a shield with commitment [c] has
      been applied, NO reachable future state will accept another
      shield carrying [c] — so the recipient's note [c] is minted at
      most once.  An attacker resubmitting the victim's proof is
      always rejected; the balance cannot be doubled. *)
  Theorem no_duplicate_shielded_note :
    forall s s' c,
      NfSteps Cm s s' ->
      In c s ->                       (* c already shielded *)
      ~ shield_acceptable s' c.       (* no future shield can re-mint c *)
  Proof.
    intros s s' c Hsteps Hin.
    apply shield_replay_rejected.
    exact (applied_is_permanent s s' c Hsteps Hin).
  Qed.

End ShieldReplay.
