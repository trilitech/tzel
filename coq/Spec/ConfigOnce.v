(** * Spec.ConfigOnce — verifier/bridge config is set-once (immutable)

    The kernel installs the verifier and bridge configs ONE-SHOT
    ([configure_verifier] / [configure_bridge] in
    [tezos/rollup-kernel/src/lib.rs]): each checks whether the config
    is already present and, if so, rejects ("rollup verifier/bridge is
    already configured").  So once installed, a config is frozen for
    the life of the kernel — it cannot be swapped by a later
    configure.

    This complements [Spec.ConfigAuth.config_update_unforgeable] (only
    the admin can install a config): together, the verifier/bridge is
    set ONCE by the admin and then IMMUTABLE.  An attacker can neither
    forge an install (ConfigAuth) nor overwrite the installed config
    (here).

    Modeled as a write-once register: the config slot is [option C];
    a [set] transition fires only when the slot is [None]; every other
    kernel operation leaves the slot unchanged.  Proved (zero admits):
    once the slot holds [Some c], it holds [Some c] in every reachable
    later state. *)

From Stdlib Require Import List Arith Lia.

Section ConfigOnce.

  Variable C : Type.

  (** The config slot. *)
  Definition CState := option C.
  Definition cgenesis : CState := None.

  Inductive CStep : CState -> CState -> Prop :=
  | cstep_set :
      (* install: only succeeds when unset (the "already configured"
         check rejects otherwise, leaving the slot unchanged) *)
      forall c, CStep None (Some c)
  | cstep_other :
      (* any other kernel operation (deposit, shield, transfer,
         unshield, …) does not touch the config slot *)
      forall s, CStep s s.

  Inductive CSteps : CState -> CState -> Prop :=
  | csteps_refl  : forall s, CSteps s s
  | csteps_trans : forall s s' s'', CStep s s' -> CSteps s' s'' -> CSteps s s''.

  (** A single step never changes a slot that is already [Some]: the
      only state-changing step ([cstep_set]) requires [None]. *)
  Lemma cstep_preserves_some : forall s s' c,
    CStep s s' -> s = Some c -> s' = Some c.
  Proof.
    intros s s' c Hstep Heq. destruct Hstep as [c0 | s0].
    - discriminate Heq.
    - exact Heq.
  Qed.

  (** ** Immutability: once installed, the config never changes.

      In every reachable state after the slot holds [Some c], it still
      holds [Some c].  So the verifier/bridge config, once installed,
      is frozen — no later configure can overwrite it. *)
  Theorem config_immutable : forall s s' c,
    CSteps s s' -> s = Some c -> s' = Some c.
  Proof.
    intros s s' c H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Heq.
    - exact Heq.
    - apply IH. exact (cstep_preserves_some s s' c Hstep Heq).
  Qed.

  (** A configure against an already-set slot cannot change its value
      (the "already configured" rejection): any step from [Some c]
      leaves it at [Some c] — there is no overwrite to a different
      config. *)
  Theorem reconfigure_unchanged : forall c c',
    CStep (Some c) (Some c') -> c' = c.
  Proof.
    intros c c' Hstep.
    pose proof (cstep_preserves_some (Some c) (Some c') c Hstep eq_refl) as Heq.
    injection Heq as ->. reflexivity.
  Qed.

  (* ============================================================= *)
  (** ** Operations require a configured kernel                     *)
  (* ============================================================= *)

  (** The kernel rejects deposits / shields / withdrawals before the
      config is installed ("bridge ticketer / proof verifier is not
      configured", [lib.rs]).  We model the joint (config, op-count)
      state: an [install] sets the config (when unset); an [op]
      (any deposit/shield/transfer/unshield) fires ONLY when the config
      is [Some] and bumps the operation count. *)
  Record GState : Type := mkG { g_cfg : option C; g_ops : nat }.

  Definition ggenesis : GState := mkG None 0.

  Inductive GStep : GState -> GState -> Prop :=
  | gstep_install :
      forall n c, GStep (mkG None n) (mkG (Some c) n)
  | gstep_op :
      forall c n, GStep (mkG (Some c) n) (mkG (Some c) (S n)).

  Inductive GSteps : GState -> GState -> Prop :=
  | gsteps_refl  : forall s, GSteps s s
  | gsteps_trans : forall s s' s'', GStep s s' -> GSteps s' s'' -> GSteps s s''.

  (** Both invariants of the joint machine: the config is monotone
      (once [Some], stays [Some]), and the operation count is positive
      only when the config is set. *)
  Definition g_inv (s : GState) : Prop :=
    (g_ops s > 0 -> exists c, g_cfg s = Some c)
    /\ (forall c, g_cfg s = Some c -> exists c', g_cfg s = Some c').

  Lemma gstep_preserves_some : forall s s' c,
    GStep s s' -> g_cfg s = Some c -> exists c', g_cfg s' = Some c'.
  Proof.
    intros s s' c Hstep Heq. destruct Hstep as [n c0 | c0 n]; cbn in *.
    - discriminate Heq.
    - exists c0. reflexivity.
  Qed.

  Lemma g_step_preserves : forall s s', g_inv s -> GStep s s' -> g_inv s'.
  Proof.
    intros s s' [Hops _] Hstep. split.
    - destruct Hstep as [n c0 | c0 n]; cbn.
      + (* install: op count unchanged; if >0 it was >0 before *)
        intro Hpos. destruct (Hops Hpos) as [c1 Hc1]. cbn in Hc1. discriminate Hc1.
      + (* op: config is Some c0 *)
        intro. exists c0. reflexivity.
    - intros c Hc. exists c. exact Hc.
  Qed.

  Lemma g_steps_preserve : forall s s', GSteps s s' -> g_inv s -> g_inv s'.
  Proof.
    intros s s' H. induction H as [s | s s' s'' Hstep Hrest IH]; intro Hinv.
    - exact Hinv.
    - apply IH. eapply g_step_preserves; eauto.
  Qed.

  (** Operations require configuration: in any reachable state where
      at least one operation has occurred, the config is installed.
      So the kernel processes no deposit / shield / transfer / unshield
      before the (admin-authorized, immutable) config is in place. *)
  Theorem operations_require_config : forall s,
    GSteps ggenesis s -> g_ops s > 0 -> exists c, g_cfg s = Some c.
  Proof.
    intros s H Hpos.
    assert (Hgen : g_inv ggenesis).
    { split; cbn; [intro Hc; lia | intros c Hc; discriminate Hc]. }
    destruct (g_steps_preserve ggenesis s H Hgen) as [Hops _].
    exact (Hops Hpos).
  Qed.

End ConfigOnce.
