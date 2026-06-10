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

From Stdlib Require Import List.

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

End ConfigOnce.
