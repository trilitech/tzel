(** * Spec.KernelPool — the rollup kernel's deposit-pool solvency

    Models the per-pool deposit accounting in
    [tezos/rollup-kernel/src/lib.rs] ([credit_deposit] /
    [debit_deposit]) and proves the kernel-side conservation law that
    complements the circuit/ledger no-inflation ([Spec.LedgerNf]).

    The kernel keeps one balance per [(asset_id, pubkey_hash)] pool:
    - an L1 bridge deposit CREDITS the pool ([credit_deposit], a
      [checked_add] that REJECTS u64 overflow);
    - a shield DEBITS the pool ([debit_deposit], which REJECTS when
      the stored balance is smaller than the amount).

    Pools are path-keyed in durable storage, so distinct
    [(asset_id, pubkey_hash)] pools never interfere; modeling a single
    pool therefore captures the accounting, and the per-asset
    aggregate is the independent sum over its pools.

    Properties proved (zero admits):
    - [pool_invariant]: at every reachable pool state,
        balance = credited - debited   AND   debited <= credited.
    - [kernel_solvency]: hence [debited <= credited] always — no
      sequence of deposits and shields can debit (shield out) more of
      a pool than was deposited into it.  This is the kernel's
      "can't shield value that was never deposited" guarantee.
    - [balance_never_negative]: the balance equals [credited -
      debited] in [nat] and is therefore never driven below zero —
      the [debit_deposit] underflow check ([current < amount] -> err)
      is exactly the step precondition.
    - [credit_overflow_rejected]: a credit that would exceed the u64
      bound takes no step (mirrors [checked_add] returning [None]). *)

From Stdlib Require Import Arith Lia.

(** A pool tracks its current balance and the running totals credited
    (deposited) and debited (shielded out). *)
Record Pool : Type := mkPool {
  p_balance  : nat;
  p_credited : nat;
  p_debited  : nat;
}.

Definition pool_genesis : Pool := mkPool 0 0 0.

(** The u64 ceiling the kernel's [checked_add] guards against.  Left
    abstract — solvency does not depend on its value; it only makes
    the credit step reject overflow, mirroring the real kernel. *)
Parameter u64_max : nat.

(** Faithful one-step transitions. *)
Inductive PStep : Pool -> Pool -> Prop :=
| pstep_credit :
    forall p amt,
      (* checked_add succeeds only below the u64 ceiling *)
      p_balance p + amt < u64_max ->
      PStep p (mkPool (p_balance p + amt)
                      (p_credited p + amt)
                      (p_debited p))
| pstep_debit :
    forall p amt,
      (* debit_deposit rejects when the balance is too small *)
      amt <= p_balance p ->
      PStep p (mkPool (p_balance p - amt)
                      (p_credited p)
                      (p_debited p + amt)).

Inductive PSteps : Pool -> Pool -> Prop :=
| psteps_refl  : forall p, PSteps p p
| psteps_trans : forall p p' p'', PStep p p' -> PSteps p' p'' -> PSteps p p''.

(** The accounting invariant. *)
Definition pool_invariant (p : Pool) : Prop :=
  p_balance p = p_credited p - p_debited p
  /\ p_debited p <= p_credited p.

Lemma genesis_invariant : pool_invariant pool_genesis.
Proof. cbn. split; reflexivity. Qed.

Lemma step_preserves_invariant :
  forall p p', pool_invariant p -> PStep p p' -> pool_invariant p'.
Proof.
  intros p p' [Hbal Hle] Hstep.
  inversion Hstep; subst; unfold pool_invariant; cbn; split; lia.
Qed.

Lemma steps_preserve_invariant :
  forall p p', PSteps p p' -> pool_invariant p -> pool_invariant p'.
Proof.
  intros p p' Hsteps.
  induction Hsteps as [p | p p' p'' Hstep Hrest IH]; intro Hinv.
  - exact Hinv.
  - apply IH. eapply step_preserves_invariant; eauto.
Qed.

(** Every reachable pool state satisfies the invariant. *)
Theorem pool_invariant_reachable :
  forall p, PSteps pool_genesis p -> pool_invariant p.
Proof.
  intros p H. exact (steps_preserve_invariant pool_genesis p H genesis_invariant).
Qed.

(** ** Kernel solvency

    No reachable pool has shielded out (debited) more than was
    deposited (credited).  This is the kernel-side complement of the
    circuit no-inflation: value cannot be shielded that was never
    deposited. *)
Theorem kernel_solvency :
  forall p, PSteps pool_genesis p -> p_debited p <= p_credited p.
Proof.
  intros p H. destruct (pool_invariant_reachable p H) as [_ Hle]. exact Hle.
Qed.

(** The balance is exactly deposited-minus-shielded and so is never
    negative (it is a [nat], and equals [credited - debited] which is
    well-defined because [debited <= credited]). *)
Theorem balance_never_negative :
  forall p, PSteps pool_genesis p ->
    p_balance p = p_credited p - p_debited p.
Proof.
  intros p H. destruct (pool_invariant_reachable p H) as [Hbal _]. exact Hbal.
Qed.

(** ** Faithfulness corner: overflow-checked credit

    A credit of a positive [amt] that would breach the u64 ceiling
    takes NO step — the kernel's [checked_add] returns [None] and the
    deposit is rejected, never silently wrapped.  (The positivity
    hypothesis excludes the degenerate [amt = 0] target, which a
    debit-of-0 trivially reaches.) *)
Theorem credit_overflow_rejected :
  forall p amt,
    0 < amt ->
    u64_max <= p_balance p + amt ->
    ~ PStep p (mkPool (p_balance p + amt)
                      (p_credited p + amt)
                      (p_debited p)).
Proof.
  intros p amt Hpos Hover Hstep.
  inversion Hstep; subst; lia.
Qed.
