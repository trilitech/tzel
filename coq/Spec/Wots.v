(** * Spec.Wots — abstract WOTS+ chain step

    Whitepaper-derived spec for the chain-hashing primitive used in
    the in-circuit XMSS verifier.

    Source: [docs/whitepaper.tex] §"Authorization tree and in-circuit
    verification" plus the cited references RFC 8391 (XMSS), Buchmann
    et al. (XMSS), and Hülsing (WOTS+). The whitepaper deliberately
    stays at the level of the standard scheme — base [w = 4], 133
    chains of length [w − 1] — and the chain math is the standard
    one. We transcribe it here, NOT the Cairo source: the [Impl]
    layer is allowed to look at the Cairo, but [Spec] derives from
    the protocol-level documents only.

    The chain step abstracts over the hash family [F] and the address
    encoding [ADRS]. A chain at position [(key_idx, chain_idx)],
    starting from value [x] under public seed [pub_seed], applies
    [F pub_seed (ADRS key_idx chain_idx step) x] iteratively, with
    [step] running through [start_step ..= start_step + n − 1].
*)

From Stdlib Require Import Arith.
From Common Require Import Felt.

Section ChainStep.

  (** Abstract 3-input hash. The whitepaper specifies BLAKE2s with a
      personalized IV; we keep it abstract here because the chain
      math doesn't depend on which concrete hash we pick — only on
      the algebraic structure of "a function from three felts to a
      felt." Cryptographic properties (collision resistance,
      preimage resistance, PRF) get axiomatized when soundness
      proofs need them. *)
  Variable F : Felt -> Felt -> Felt -> Felt.

  (** Address encoding. [ADRS key_idx chain_idx step] returns the
      packed address used as the second hash input. The whitepaper
      and RFC 8391 specify the bit layout in detail; the chain math
      is independent of it, so we abstract here. *)
  Variable ADRS : nat -> nat -> nat -> Felt.

  (** One step of the WOTS+ chain at position [step] under address
      [(key_idx, chain_idx)]:

         step (x, pub_seed, key_idx, chain_idx, step_no)
            = F pub_seed (ADRS key_idx chain_idx step_no) x
  *)
  Definition step (x pub_seed : Felt)
                  (key_idx chain_idx step_no : nat) : Felt :=
    F pub_seed (ADRS key_idx chain_idx step_no) x.

  (** [n]-step chain starting from [x] at [start_step], applying
      [step] [n] times with the step number incrementing each
      iteration. *)
  Fixpoint iter (n : nat)
                (x pub_seed : Felt)
                (key_idx chain_idx start_step : nat) : Felt :=
    match n with
    | O => x
    | S k =>
        iter k
             (step x pub_seed key_idx chain_idx start_step)
             pub_seed key_idx chain_idx (S start_step)
    end.

  (** One-step unfolding of [iter]. By [Definition] expansion this
      is [reflexivity], but having it as an explicit lemma lets
      [rewrite] do exactly one unfold step — which we need in the
      [iter_succ] / [iter_compose] proofs because [simpl] / [cbn]
      keep unfolding [iter] past the form where the inductive
      hypothesis matches. *)
  Lemma iter_S_unfold
        (n : nat) (x pub_seed : Felt)
        (key_idx chain_idx start_step : nat) :
    iter (S n) x pub_seed key_idx chain_idx start_step =
    iter n (step x pub_seed key_idx chain_idx start_step)
         pub_seed key_idx chain_idx (S start_step).
  Proof. reflexivity. Qed.

  (** Chain extension: an [n+1]-step chain equals one [step]
      applied to the [n]-step output. The slightly subtle bit is
      the step counter: the appended [step] uses [start_step + n]
      because [iter] has already advanced the counter [n] times. *)
  Lemma iter_succ
        (n : nat) (x pub_seed : Felt)
        (key_idx chain_idx start_step : nat) :
    iter (S n) x pub_seed key_idx chain_idx start_step =
    step (iter n x pub_seed key_idx chain_idx start_step)
         pub_seed key_idx chain_idx (start_step + n).
  Proof.
    revert x start_step.
    induction n as [|k IH]; intros x start_step.
    - cbn [iter]. now rewrite Nat.add_0_r.
    - rewrite (iter_S_unfold (S k)).
      rewrite IH.
      rewrite (iter_S_unfold k).
      rewrite Nat.add_succ_r.
      reflexivity.
  Qed.

  (** Chain concatenation: an [(n + m)]-step chain equals an
      [m]-step chain run on the [n]-step output, with the step
      counter offset by [n]. *)
  Lemma iter_compose
        (n m : nat) (x pub_seed : Felt)
        (key_idx chain_idx start_step : nat) :
    iter (n + m) x pub_seed key_idx chain_idx start_step =
    iter m
         (iter n x pub_seed key_idx chain_idx start_step)
         pub_seed key_idx chain_idx (start_step + n).
  Proof.
    revert x start_step.
    induction n as [|k IH]; intros x start_step.
    - cbn [iter Nat.add]. now rewrite Nat.add_0_r.
    - rewrite (iter_S_unfold (k + m)).
      rewrite IH.
      rewrite (iter_S_unfold k).
      rewrite Nat.add_succ_r.
      reflexivity.
  Qed.

  (** WOTS+ chain recovery.

      During verification, a signature element has been chained
      forward [d] steps from the secret key:
        [sig_elem = iter d sk pub_seed key_idx chain_idx 0]

      Recovery extends the chain by [total_steps - d] more steps to
      reconstruct the public key endpoint.  This theorem states that
      the recovery produces the same result as chaining [total_steps]
      from the secret key directly.

      In the protocol, [total_steps = w − 1 = 3] and
      [d ∈ {0, 1, 2, 3}].  Proof follows from [iter_compose]. *)
  Theorem recover_correct
          (total_steps d : nat) (sk pub_seed : Felt)
          (key_idx chain_idx : nat) :
    d <= total_steps ->
    iter (total_steps - d)
         (iter d sk pub_seed key_idx chain_idx 0)
         pub_seed key_idx chain_idx d =
    iter total_steps sk pub_seed key_idx chain_idx 0.
  Proof.
    intros Hle.
    rewrite <- iter_compose.
    rewrite (Nat.add_comm d (total_steps - d)).
    rewrite (Nat.sub_add d total_steps Hle).
    reflexivity.
  Qed.

  (** Chain injectivity: if the same number of hash steps from
      different starting values produce the same output, then the
      starting values must be equal.

      This is the per-chain binding property: two different signature
      elements for the same digit can't produce the same endpoint.
      Combined with [recover_correct], this means a valid signature
      element is uniquely determined by its digit and the secret key.

      Requires: [F] is injective in its third argument (the chain
      element), given fixed first two arguments (pub_seed, ADRS).
      This models second-preimage resistance of the hash. *)
  Theorem iter_injective
      (H_F_inj : forall a b x1 x2, F a b x1 = F a b x2 -> x1 = x2) :
    forall n (x1 x2 pub_seed : Felt)
           (key_idx chain_idx start_step : nat),
      iter n x1 pub_seed key_idx chain_idx start_step =
      iter n x2 pub_seed key_idx chain_idx start_step ->
      x1 = x2.
  Proof.
    induction n as [| k IH]; intros x1 x2 pub_seed key_idx chain_idx
                              start_step Heq.
    - exact Heq.
    - rewrite (iter_S_unfold k x1 pub_seed key_idx chain_idx start_step)
        in Heq.
      rewrite (iter_S_unfold k x2 pub_seed key_idx chain_idx start_step)
        in Heq.
      apply IH in Heq.
      unfold step in Heq.
      exact (H_F_inj _ _ _ _ Heq).
  Qed.

End ChainStep.
