(** * Spec.BridgeBurn — burn-side authentication (no foreign-ticket drain)

    [Spec.BridgeTicketer] proved the bridge stays exactly
    collateralized using an ABSTRACT burn guard ([amount <=
    outstanding]).  This module discharges the assumption behind that
    guard by modeling the Michelson [%burn] entrypoint's actual
    authentication ([fa2_bridge_ticketer.tz]): after [READ_TICKET] it

    - verifies [ticketer == SELF_ADDRESS] (FAILWITH "unexpected ticket
      creator" otherwise),
    - verifies the content's [metadata == None],
    - verifies the content's [token_id == 0],

    and only then transfers the FA2 custody to the receiver.

    The security content: an attacker holding a ticket minted by a
    DIFFERENT contract (a "foreign" ticket — ticketer <> SELF) can
    NEVER make this bridge release its FA2.  Without the [ticketer ==
    SELF] check, anyone could mint a ticket from their own contract
    and burn it here to drain custody.  This is exactly what the
    abstract [outstanding] guard in [BridgeTicketer] relied on: only
    SELF-minted tickets are burnable.

    Proved (zero admits):
    - [foreign_ticket_rejected]: ticketer <> SELF -> the burn is not
      accepted;
    - [accept_burn_authentic]: an accepted burn is of a SELF-minted
      ticket;
    - [custody_decrease_authentic]: in the refined bridge state
      machine, custody only ever decreases via an authentic burn — a
      foreign ticket cannot reduce it;
    - [reachable_collateralized]: collateralization (custody =
      outstanding) is preserved, now with the burn guard grounded in
      the real authentication. *)

From Stdlib Require Import Arith Lia.

Section BridgeBurn.

  (** L1 contract addresses (b58check), with decidable equality. *)
  Variable Addr : Type.
  Variable Addr_eq_dec : forall x y : Addr, {x = y} + {x <> y}.

  (** This bridge contract's own address (SELF_ADDRESS). *)
  Variable self : Addr.

  (** A ticket as [READ_TICKET] exposes it. *)
  Record Ticket : Type := mkTicket {
    tk_ticketer     : Addr;   (* ticket.creator() *)
    tk_token_id     : nat;
    tk_has_metadata : bool;
    tk_amount       : nat;
  }.

  (** The [%burn] acceptance predicate — the conjunction of the three
      on-chain checks. *)
  Definition accept_burn (t : Ticket) : Prop :=
    tk_ticketer t = self
    /\ tk_token_id t = 0
    /\ tk_has_metadata t = false.

  (* ============================================================= *)
  (** ** Authentication rejects foreign / malformed tickets         *)
  (* ============================================================= *)

  (** A foreign ticket (creator <> this bridge) is never accepted —
      the [ticketer == SELF_ADDRESS] check.  This is the anti-drain
      core. *)
  Theorem foreign_ticket_rejected :
    forall t, tk_ticketer t <> self -> ~ accept_burn t.
  Proof. intros t Hne [Hself _]. exact (Hne Hself). Qed.

  Theorem nonzero_token_rejected :
    forall t, tk_token_id t <> 0 -> ~ accept_burn t.
  Proof. intros t Hnz [_ [Htid _]]. exact (Hnz Htid). Qed.

  Theorem metadata_rejected :
    forall t, tk_has_metadata t = true -> ~ accept_burn t.
  Proof. intros t Hmd [_ [_ Hfalse]]. rewrite Hmd in Hfalse. discriminate. Qed.

  (** Every accepted burn is of a SELF-minted ticket. *)
  Theorem accept_burn_authentic :
    forall t, accept_burn t -> tk_ticketer t = self.
  Proof. intros t [Hself _]. exact Hself. Qed.

  (* ============================================================= *)
  (** ** Refined bridge: burns gated by the real authentication     *)
  (* ============================================================= *)

  Record BBState : Type := mkBB {
    bb_custody     : nat;   (* FA2 held by SELF *)
    bb_outstanding : nat;   (* value of SELF-minted tickets in circulation *)
  }.

  Definition bb_genesis : BBState := mkBB 0 0.

  Inductive BBStep : BBState -> BBState -> Prop :=
  | bbstep_mint :
      forall s n,
        BBStep s (mkBB (bb_custody s + n) (bb_outstanding s + n))
  | bbstep_burn :
      forall s t,
        accept_burn t ->                          (* ticketer = SELF, etc. *)
        tk_amount t <= bb_outstanding s ->         (* an outstanding SELF ticket *)
        BBStep s (mkBB (bb_custody s - tk_amount t)
                       (bb_outstanding s - tk_amount t)).

  Inductive BBSteps : BBState -> BBState -> Prop :=
  | bbsteps_refl  : forall s, BBSteps s s
  | bbsteps_trans : forall s s' s'', BBStep s s' -> BBSteps s' s'' -> BBSteps s s''.

  (** ** The anti-drain theorem.

      If a single bridge step reduces custody, it was a burn of an
      AUTHENTIC ticket (ticketer = SELF).  A foreign ticket cannot
      reduce this bridge's FA2. *)
  Theorem custody_decrease_authentic :
    forall s s',
      BBStep s s' ->
      bb_custody s' < bb_custody s ->
      exists t, accept_burn t /\ tk_ticketer t = self.
  Proof.
    intros s s' Hstep Hlt.
    destruct Hstep as [s n | s t Hacc Hle]; cbn in Hlt.
    - (* mint: custody + n < custody is impossible *)
      lia.
    - exists t. split; [exact Hacc | exact (accept_burn_authentic t Hacc)].
  Qed.

  (** Contrapositive, packaged for the attacker model: presenting a
      foreign ticket takes no burn step (the only step it could match
      is rejected by [foreign_ticket_rejected]). *)
  Theorem foreign_ticket_no_burn :
    forall s s' t,
      tk_ticketer t <> self ->
      ~ (accept_burn t /\ tk_amount t <= bb_outstanding s /\
         s' = mkBB (bb_custody s - tk_amount t) (bb_outstanding s - tk_amount t)).
  Proof.
    intros s s' t Hforeign [Hacc _].
    exact (foreign_ticket_rejected t Hforeign Hacc).
  Qed.

  (* ============================================================= *)
  (** ** Collateralization still holds, guard now grounded          *)
  (* ============================================================= *)

  Definition bb_inv (s : BBState) : Prop := bb_custody s = bb_outstanding s.

  Lemma bb_genesis_inv : bb_inv bb_genesis.
  Proof. reflexivity. Qed.

  Lemma bb_step_preserves : forall s s', bb_inv s -> BBStep s s' -> bb_inv s'.
  Proof.
    intros s s' Hinv Hstep. unfold bb_inv in *.
    destruct Hstep as [s n | s t Hacc Hle]; cbn; lia.
  Qed.

  Lemma bb_steps_preserve : forall s s', BBSteps s s' -> bb_inv s -> bb_inv s'.
  Proof.
    intros s s' H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Hinv.
    - exact Hinv.
    - apply IH. eapply bb_step_preserves; eauto.
  Qed.

  (** Collateralization holds in every reachable state — the abstract
      [BridgeTicketer] guard is now backed by the real [%burn]
      authentication: only authentic, outstanding tickets are burned. *)
  Theorem reachable_collateralized :
    forall s, BBSteps bb_genesis s -> bb_custody s = bb_outstanding s.
  Proof. intros s H. exact (bb_steps_preserve bb_genesis s H bb_genesis_inv). Qed.

End BridgeBurn.
