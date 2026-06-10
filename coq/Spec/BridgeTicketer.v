(** * Spec.BridgeTicketer — the FA2 bridge ticketer's collateralization

    Models the L1 Michelson contract [tezos/fa2_bridge_ticketer.tz]
    and proves its central safety property: the bridge is ALWAYS
    EXACTLY collateralized — the FA2 it holds in custody equals the
    total value of the tickets it has minted and not yet burned.

    The contract has two entrypoints:
    - [%mint(amount, ...)]: pulls [amount] of the FA2 token from
      SENDER into SELF, then mints a ticket of value [amount] (creator
      = SELF, content (0, None)) and sends it to the rollup.  The two
      operations are one atomic tx tree, so a failed FA2 pull reverts
      the ticket mint — no ticket without backing.  Zero-amount mints
      are rejected.
    - [%burn(ticket, receiver)]: READ_TICKETs, verifies [ticketer ==
      SELF_ADDRESS] (so only a ticket THIS bridge minted is accepted —
      a foreign ticket is rejected), checks content is (0, None),
      then transfers [amount] FA2 from SELF to the receiver.  The
      ticket is consumed by READ_TICKET (Michelson tickets are
      linear), so it leaves circulation.

    State (the two resources the bridge keeps in lockstep):
    - [bt_custody]     — FA2 currently held by SELF;
    - [bt_outstanding] — total value of SELF-minted tickets in
                         circulation (minted, not yet burned).
    Plus running totals [bt_in] (all FA2 ever pulled) and [bt_out]
    (all FA2 ever released) for the deposit/withdrawal bound.

    Invariant: [bt_custody = bt_outstanding].

    Out of scope (L1 guarantees taken as given): ticket linearity
    (no duplication) and ticket-creator authenticity — these are the
    Michelson/protocol semantics that justify modeling a burn as only
    able to consume an authentic outstanding ticket. *)

From Stdlib Require Import Arith Lia.

Record BState : Type := mkBState {
  bt_custody     : nat;
  bt_outstanding : nat;
  bt_in          : nat;
  bt_out         : nat;
}.

Definition bgenesis : BState := mkBState 0 0 0 0.

Inductive BStep : BState -> BState -> Prop :=
| bstep_mint :
    forall s n,
      0 < n ->                       (* zero-amount mint rejected *)
      BStep s (mkBState
                 (bt_custody s + n)
                 (bt_outstanding s + n)
                 (bt_in s + n)
                 (bt_out s))
| bstep_burn :
    forall s n,
      (* the burned ticket is authentic (creator = SELF) and in
         circulation: at most the outstanding value can be burned *)
      n <= bt_outstanding s ->
      BStep s (mkBState
                 (bt_custody s - n)
                 (bt_outstanding s - n)
                 (bt_in s)
                 (bt_out s + n)).

Inductive BSteps : BState -> BState -> Prop :=
| bsteps_refl  : forall s, BSteps s s
| bsteps_trans : forall s s' s'', BStep s s' -> BSteps s' s'' -> BSteps s s''.

(** The collateralization invariant, plus the deposit/withdrawal
    accounting that ties custody to the running totals. *)
Definition binvariant (s : BState) : Prop :=
  bt_custody s = bt_outstanding s
  /\ bt_custody s = bt_in s - bt_out s
  /\ bt_out s <= bt_in s.

Lemma genesis_binvariant : binvariant bgenesis.
Proof. unfold binvariant, bgenesis; cbn [bt_custody bt_outstanding bt_in bt_out]; repeat split; lia. Qed.

Lemma bstep_preserves :
  forall s s', binvariant s -> BStep s s' -> binvariant s'.
Proof.
  intros s s' [Hcoll [Hacc Hle]] Hstep.
  destruct Hstep as [s n Hpos | s n Hburn];
    unfold binvariant; cbn [bt_custody bt_outstanding bt_in bt_out];
    repeat split; lia.
Qed.

Lemma bsteps_preserve :
  forall s s', BSteps s s' -> binvariant s -> binvariant s'.
Proof.
  intros s s' Hsteps.
  induction Hsteps as [s | s s' s'' Hstep Hrest IH]; intro Hinv.
  - exact Hinv.
  - apply IH. eapply bstep_preserves; eauto.
Qed.

Theorem reachable_binvariant :
  forall s, BSteps bgenesis s -> binvariant s.
Proof.
  intros s H. exact (bsteps_preserve bgenesis s H genesis_binvariant).
Qed.

(** ** The bridge is always exactly collateralized.

    FA2 held in custody equals the value of outstanding tickets — in
    every reachable state.  Two consequences:
    - [>=] every outstanding ticket is redeemable (custody suffices);
    - [<=] no FA2 is stranded beyond the tickets that back it. *)
Theorem fully_collateralized :
  forall s, BSteps bgenesis s -> bt_custody s = bt_outstanding s.
Proof.
  intros s H. destruct (reachable_binvariant s H) as [Hc _]. exact Hc.
Qed.

(** Redeemability: any authentic outstanding ticket value [n] can be
    burned — the custody to release it is present (custody = n + the
    rest), so the FA2 transfer never fails for want of funds. *)
Theorem ticket_redeemable :
  forall s n, BSteps bgenesis s -> n <= bt_outstanding s ->
    n <= bt_custody s.
Proof.
  intros s n H Hn. rewrite (fully_collateralized s H). exact Hn.
Qed.

(** Bridge solvency: total FA2 released to L1 never exceeds total FA2
    deposited from L1.  No sequence of mints/burns can drain more
    than was put in. *)
Theorem bridge_solvency :
  forall s, BSteps bgenesis s -> bt_out s <= bt_in s.
Proof.
  intros s H. destruct (reachable_binvariant s H) as [_ [_ Hle]]. exact Hle.
Qed.

(** No unbacked release: the FA2 currently held equals deposits minus
    withdrawals, so custody is never negative and every release was
    matched by a deposit (no minting of FA2 the bridge never received). *)
Theorem custody_backed :
  forall s, BSteps bgenesis s -> bt_custody s = bt_in s - bt_out s.
Proof.
  intros s H. destruct (reachable_binvariant s H) as [_ [Hacc _]]. exact Hacc.
Qed.

(** A burn of MORE than the outstanding ticket value takes no step —
    the [ticketer == SELF] + linearity checks make over-burning
    impossible.  (Stated as: any actual burn step consumes at most
    the outstanding value.) *)
Theorem no_overburn :
  forall s s' n,
    BStep s s' ->
    s' = mkBState (bt_custody s - n) (bt_outstanding s - n)
                  (bt_in s) (bt_out s + n) ->
    0 < n ->
    n <= bt_outstanding s.
Proof.
  intros s s' n Hstep Heq Hpos.
  destruct Hstep; injection Heq; intros; lia.
Qed.
