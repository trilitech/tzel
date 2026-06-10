(** * Spec.KernelDeposit — deposit anti-spoofing

    Models the kernel's bridge-deposit acceptance
    ([parse_bridge_deposit] + [validate_bridge_deposit] in
    [tezos/rollup-kernel/src/lib.rs]) and proves the anti-spoofing
    property: the kernel credits a deposit pool for asset [A] ONLY in
    response to an authentic ticket minted by the registered ticketer
    for [A].  An attacker cannot conjure a pool credit without
    controlling that ticketer.

    The checks the kernel performs on a candidate deposit:
    - [creator = sender]: the ticket's creator (stamped authentically
      by the L1 ticket machinery) equals the transfer sender — so a
      FORWARDED ticket (someone relaying a victim's ticket) is
      rejected, and a faked ticket would require BEING the ticketer;
    - [token_id = 0] and [metadata = None]: canonical ticket content;
    - the sender is a REGISTERED ticketer ([asset_for_ticketer] is
      [Some]); the credited asset is exactly that lookup;
    - the recipient is a canonical [deposit:<hex(pubkey_hash)>] key;
    - the verifier is configured (so the pool key is anchorable).

    Ticket authenticity itself (that [creator] is truly the minting
    contract) is an L1 / smart-rollup guarantee, out of scope — taken
    as the meaning of [creator = sender] here.  Everything downstream
    of that the kernel enforces, and that is what we prove. *)

From Stdlib Require Import Arith.

Section KernelDeposit.

  (** L1 contract addresses (b58check) and L2 asset ids, with
      decidable equality (both are byte strings in the kernel). *)
  Variable Addr  : Type.
  Variable Asset : Type.
  Variable Addr_eq_dec : forall x y : Addr, {x = y} + {x <> y}.

  (** The asset registry: [asset_for_ticketer].  Maps a (canonical)
      ticketer address to the asset its tickets denote, or [None] if
      the ticketer is not registered. *)
  Variable reg : Addr -> option Asset.

  (** A candidate deposit as the kernel sees it after parsing. *)
  Record Deposit : Type := mkDeposit {
    d_creator             : Addr;   (* ticket.creator() (authentic) *)
    d_sender              : Addr;   (* transfer.sender *)
    d_token_id            : nat;    (* ticket content token_id *)
    d_has_metadata        : bool;   (* ticket content metadata <> None *)
    d_recipient_canonical : bool;   (* deposit:<hex pubkey_hash> ? *)
    d_verifier_configured : bool;
    d_amount              : nat;
  }.

  (** The acceptance predicate — the conjunction of every check, in
      the kernel's order. *)
  Definition accept (d : Deposit) : Prop :=
    d_creator d = d_sender d
    /\ d_token_id d = 0
    /\ d_has_metadata d = false
    /\ d_recipient_canonical d = true
    /\ d_verifier_configured d = true
    /\ reg (d_sender d) <> None.

  (** The asset a deposit would credit (the registry lookup on the
      authentic ticketer). *)
  Definition credited_asset (d : Deposit) : option Asset :=
    reg (d_sender d).

  (* ============================================================= *)
  (** ** Each spoofing vector is rejected                            *)
  (* ============================================================= *)

  (** A forwarded ticket (creator <> sender) is never accepted — this
      is the relaying attack the [creator = sender] check blocks. *)
  Theorem forwarded_ticket_rejected :
    forall d, d_creator d <> d_sender d -> ~ accept d.
  Proof. intros d Hne [Heq _]. exact (Hne Heq). Qed.

  (** A deposit from an unregistered ticketer is never accepted. *)
  Theorem unregistered_sender_rejected :
    forall d, reg (d_sender d) = None -> ~ accept d.
  Proof. intros d Hnone [_ [_ [_ [_ [_ Hsome]]]]]. exact (Hsome Hnone). Qed.

  (** A non-canonical ticket (token_id <> 0) is never accepted. *)
  Theorem nonzero_token_rejected :
    forall d, d_token_id d <> 0 -> ~ accept d.
  Proof. intros d Hnz [_ [Htid _]]. exact (Hnz Htid). Qed.

  (** A ticket carrying metadata is never accepted. *)
  Theorem metadata_rejected :
    forall d, d_has_metadata d = true -> ~ accept d.
  Proof.
    intros d Hmd [_ [_ [Hfalse _]]]. rewrite Hmd in Hfalse. discriminate.
  Qed.

  (** A deposit before verifier configuration is never accepted. *)
  Theorem unconfigured_rejected :
    forall d, d_verifier_configured d = false -> ~ accept d.
  Proof.
    intros d Hf [_ [_ [_ [_ [Htrue _]]]]]. rewrite Hf in Htrue. discriminate.
  Qed.

  (* ============================================================= *)
  (** ** Positive characterisation                                   *)
  (* ============================================================= *)

  (** Every accepted deposit is AUTHENTIC (creator = sender) and
      credits a REGISTERED asset. *)
  Theorem accept_authentic_and_registered :
    forall d, accept d ->
      d_creator d = d_sender d
      /\ exists A, credited_asset d = Some A.
  Proof.
    intros d [Hcs [_ [_ [_ [_ Hsome]]]]]. split; [exact Hcs |].
    unfold credited_asset. destruct (reg (d_sender d)) as [A |].
    - exists A. reflexivity.
    - exfalso. apply Hsome. reflexivity.
  Qed.

  (** ** The anti-spoofing theorem.

      To credit asset [A] you must control the registered ticketer
      for [A].  Precisely: if a deposit is accepted and credits [A],
      then its authentic ticket creator is a ticketer the registry
      maps to [A].  Under registry injectivity (one ticketer per
      asset — [derive_asset_id] is a collision-resistant hash of the
      ticketer, so distinct ticketers give distinct assets) that
      ticketer is UNIQUE: only its holder can credit [A]. *)
  Theorem credit_requires_owning_ticketer :
    forall d A,
      accept d ->
      credited_asset d = Some A ->
      d_creator d = d_sender d /\ reg (d_creator d) = Some A.
  Proof.
    intros d A Hacc Hcred.
    destruct Hacc as [Hcs _].
    split; [exact Hcs |].
    unfold credited_asset in Hcred. rewrite Hcs. exact Hcred.
  Qed.

  (** Under registry injectivity, the crediting ticketer is the unique
      one for [A]: any accepted deposit crediting [A] has the SAME
      sender. *)
  Theorem credit_ticketer_unique
      (reg_inj : forall t1 t2 A,
                   reg t1 = Some A -> reg t2 = Some A -> t1 = t2) :
    forall d1 d2 A,
      accept d1 -> credited_asset d1 = Some A ->
      accept d2 -> credited_asset d2 = Some A ->
      d_sender d1 = d_sender d2.
  Proof.
    intros d1 d2 A H1 Hc1 H2 Hc2.
    unfold credited_asset in Hc1, Hc2.
    exact (reg_inj _ _ _ Hc1 Hc2).
  Qed.

End KernelDeposit.
