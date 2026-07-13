(** * Spec.Xmss — abstract XMSS signature verification

    Source: whitepaper §"Authorization tree and in-circuit
    verification" + RFC 8391.

    Defines:
    - L-tree compression: pairwise hashing of WOTS+ chain endpoints
      into a single auth-tree leaf (RFC 8391 §4.1.5).
    - WOTS+ endpoint recovery: chaining each signature element
      forward by [chain_len − digit] steps to reconstruct the
      public key chain endpoints.
    - Full XMSS verification predicate combining recovery, L-tree,
      and auth-tree path verification.

    The headline soundness target (not yet proved):

      [xmss_verify] holds ->
      exists pk, the recovered leaf is at position [key_idx]
      in the auth tree with root [auth_root_val],
      and the leaf equals [ltree(pk)].
*)

From Stdlib Require Import List Arith Lia.
From Common Require Import Felt.
From Spec Require Import Hashes.
From Spec Require Import Wots.
From Spec Require Import Merkle.

(* ================================================================ *)
(** ** Two-at-a-time list induction                                  *)
(* ================================================================ *)

(** Standard induction handles one list element per step; L-tree's
    [pair_nodes] consumes two at a time.  This principle provides
    three cases: empty, singleton, and two-or-more. *)
Lemma pair_ind (P : list Felt -> Prop) :
  P nil ->
  (forall x, P (x :: nil)) ->
  (forall x y rest, P rest -> P (x :: y :: rest)) ->
  forall l, P l.
Proof.
  intros H0 H1 H2.
  assert (Hpair : forall l, P l /\ (forall x, P (x :: l))).
  { induction l as [| a tl IH].
    - split; [exact H0 | intro x; exact (H1 x)].
    - destruct IH as [IHl IHcl].
      split; [exact (IHcl a) | intro x; exact (H2 x a tl IHl)].
  }
  intro l; exact (proj1 (Hpair l)).
Qed.

(* ================================================================ *)
(** ** L-tree: pairwise compression of WOTS+ endpoints               *)
(* ================================================================ *)

Section LTree.

  (** Node hash parameterized by level and node index within the
      level.  In the protocol: [H4(pub_seed, ADRS(TAG_XMSS_LTREE,
      key_idx, level, node_idx, 0), left, right)].  The [pub_seed]
      and [key_idx] are baked into the section variable — the L-tree
      definition is parameterized over them. *)
  Variable H_node : nat -> nat -> Felt -> Felt -> Felt.

  (** Compress adjacent pairs at one level.  If the list has odd
      length, the last element carries over unpaired (standard L-tree
      behavior per RFC 8391 §4.1.5). *)
  Fixpoint pair_nodes (nodes : list Felt)
                       (level node_idx : nat) : list Felt :=
    match nodes with
    | a :: b :: rest =>
        H_node level node_idx a b
          :: pair_nodes rest level (S node_idx)
    | _ => nodes
    end.

  (** [pair_nodes] never increases the list length. *)
  Lemma pair_nodes_length_le : forall nodes level nidx,
    length (pair_nodes nodes level nidx) <= length nodes.
  Proof.
    intro nodes. pattern nodes. apply pair_ind; clear nodes.
    - intros level nidx. simpl. apply Nat.le_refl.
    - intros x level nidx. simpl. apply Nat.le_refl.
    - intros x y rest IH level nidx. simpl.
      specialize (IH level (S nidx)). lia.
  Qed.

  (** Iterate [pair_nodes] until a single node remains.
      [fuel] bounds the number of compression levels; setting
      [fuel := length nodes] is always sufficient for non-empty
      input. *)
  Fixpoint ltree_aux (fuel : nat) (nodes : list Felt)
                      (level : nat) : option Felt :=
    match nodes with
    | x :: nil => Some x
    | nil => None
    | _ =>
        match fuel with
        | O => None
        | S f => ltree_aux f (pair_nodes nodes level 0) (S level)
        end
    end.

  (** L-tree compression with automatic fuel. *)
  Definition ltree (nodes : list Felt) : option Felt :=
    ltree_aux (length nodes) nodes 0.

  (** Singleton collapses immediately. *)
  Lemma ltree_singleton (x : Felt) :
    ltree (x :: nil) = Some x.
  Proof. reflexivity. Qed.

  (** Pair compresses to a single hash. *)
  Lemma ltree_pair (a b : Felt) :
    ltree (a :: b :: nil) = Some (H_node 0 0 a b).
  Proof. reflexivity. Qed.

  (** [pair_nodes] output length depends only on input length,
      not on the values or hash parameters.  Needed for the
      [ltree_injective] proof. *)
  Lemma pair_nodes_same_length : forall nodes1 nodes2 level nidx,
    length nodes1 = length nodes2 ->
    length (pair_nodes nodes1 level nidx) =
    length (pair_nodes nodes2 level nidx).
  Proof.
    intro nodes1. pattern nodes1. apply pair_ind; clear nodes1.
    - intros nodes2 level nidx Hlen.
      destruct nodes2; [reflexivity | discriminate].
    - intros x nodes2 level nidx Hlen.
      destruct nodes2 as [| y [| z rest2]];
        [discriminate | reflexivity | simpl in Hlen; discriminate].
    - intros a b rest1 IH nodes2 level nidx Hlen.
      destruct nodes2 as [| c [| d rest2]];
        [discriminate | simpl in Hlen; discriminate |].
      simpl. f_equal. apply IH. simpl in Hlen. congruence.
  Qed.

  (** Triple: exercises the odd-element carry.  The last element
      [c] is unpaired at level 0, then paired with the hash of
      [(a, b)] at level 1. *)
  Lemma ltree_triple (a b c : Felt) :
    ltree (a :: b :: c :: nil) =
    Some (H_node 1 0 (H_node 0 0 a b) c).
  Proof. reflexivity. Qed.

  (** [pair_nodes] is injective under per-slot CR of the node hash:
      same output implies same input. *)
  Lemma pair_nodes_injective :
    node_injective H_node ->
    forall nodes1 nodes2 level nidx,
      length nodes1 = length nodes2 ->
      pair_nodes nodes1 level nidx = pair_nodes nodes2 level nidx ->
      nodes1 = nodes2.
  Proof.
    intro Hinj. intro nodes1.
    pattern nodes1. apply pair_ind; clear nodes1.
    - intros nodes2 level nidx Hlen Heq.
      destruct nodes2; [reflexivity | discriminate].
    - intros x nodes2 level nidx Hlen Heq.
      destruct nodes2 as [| y [| z rest]]; simpl in *;
        [discriminate | congruence | discriminate].
    - intros a1 b1 rest1 IH nodes2 level nidx Hlen Heq.
      destruct nodes2 as [| a2 [| b2 rest2]]; simpl in *;
        [discriminate | discriminate |].
      injection Heq as Hhash Hrest.
      destruct (Hinj _ _ _ _ _ _ Hhash) as [Ha Hb].
      f_equal; [exact Ha | f_equal; [exact Hb |]].
      apply (IH rest2 level (S nidx)).
      + congruence.
      + exact Hrest.
  Qed.

  (** [ltree_aux] succeeds on non-empty input when fuel is
      sufficient.  The fuel bound [length nodes <= S fuel] is mild:
      [ltree] uses [fuel := length nodes] which always satisfies it.
      Proof by induction on [fuel]: at each step, [pair_nodes]
      strictly shrinks the list (from ≥ 2 elements to ≤ n − 1). *)
  Lemma ltree_aux_succeeds : forall fuel nodes level,
    nodes <> nil ->
    length nodes <= S fuel ->
    exists v, ltree_aux fuel nodes level = Some v.
  Proof.
    induction fuel as [| f IH]; intros nodes level Hne Hlen.
    - (* fuel = 0: nodes must be a singleton *)
      destruct nodes as [| x [| y rest]].
      + contradiction.
      + exists x. reflexivity.
      + simpl in Hlen. lia.
    - (* fuel = S f *)
      destruct nodes as [| x [| y rest]].
      + contradiction.
      + exists x. reflexivity.
      + change (exists v,
          ltree_aux f (pair_nodes (x :: y :: rest) level 0) (S level)
          = Some v).
        apply IH.
        * simpl. congruence.
        * specialize (pair_nodes_length_le rest level 1).
          simpl in Hlen. simpl. lia.
  Qed.

  (** [ltree] succeeds on any non-empty input. *)
  Theorem ltree_succeeds (nodes : list Felt) :
    nodes <> nil ->
    exists v, ltree nodes = Some v.
  Proof.
    intro Hne. unfold ltree.
    apply ltree_aux_succeeds; [exact Hne | lia].
  Qed.

  (** [ltree_aux] is injective under CR: same output on equal-length
      inputs implies the inputs are equal. *)
  Lemma ltree_aux_injective :
    node_injective H_node ->
    forall fuel nodes1 nodes2 level,
      length nodes1 = length nodes2 ->
      ltree_aux fuel nodes1 level = ltree_aux fuel nodes2 level ->
      ltree_aux fuel nodes1 level <> None ->
      nodes1 = nodes2.
  Proof.
    intro Hinj.
    induction fuel as [| f IH]; intros nodes1 nodes2 level Hlen Heq Hne.
    - (* fuel = 0 *)
      destruct nodes1 as [| x1 [| y1 rest1]].
      + exfalso. apply Hne. reflexivity.
      + destruct nodes2 as [| x2 [| y2 rest2]];
          [discriminate | simpl in Heq; congruence
          | simpl in Hlen; discriminate].
      + exfalso. apply Hne. reflexivity.
    - (* fuel = S f *)
      destruct nodes1 as [| x1 [| y1 rest1]].
      + exfalso. apply Hne. reflexivity.
      + destruct nodes2 as [| x2 [| y2 rest2]];
          [discriminate | simpl in Heq; congruence
          | simpl in Hlen; discriminate].
      + destruct nodes2 as [| x2 [| y2 rest2]];
          [simpl in Hlen; discriminate
          | simpl in Hlen; discriminate |].
        change (ltree_aux f (pair_nodes (x1 :: y1 :: rest1) level 0) (S level) =
                ltree_aux f (pair_nodes (x2 :: y2 :: rest2) level 0) (S level))
          in Heq.
        change (ltree_aux f (pair_nodes (x1 :: y1 :: rest1) level 0) (S level) <> None)
          in Hne.
        apply (pair_nodes_injective Hinj _ _ level 0);
          [exact Hlen |].
        apply (IH _ _ (S level)).
        * apply pair_nodes_same_length. exact Hlen.
        * exact Heq.
        * exact Hne.
  Qed.

  (** L-tree is injective under CR: same output on equal-length
      non-empty inputs implies the inputs are pointwise equal. *)
  Theorem ltree_injective :
    node_injective H_node ->
    forall nodes1 nodes2,
      length nodes1 = length nodes2 ->
      ltree nodes1 = ltree nodes2 ->
      ltree nodes1 <> None ->
      nodes1 = nodes2.
  Proof.
    intros Hinj nodes1 nodes2 Hlen Heq Hne.
    unfold ltree in *.
    rewrite <- Hlen in Heq.
    apply (ltree_aux_injective Hinj (length nodes1) nodes1 nodes2 0
             Hlen Heq Hne).
  Qed.

End LTree.

(* ================================================================ *)
(** ** WOTS+ endpoint recovery                                       *)
(* ================================================================ *)

Section WotsRecover.

  Variable F : Felt -> Felt -> Felt -> Felt.
  Variable ADRS_chain : nat -> nat -> nat -> Felt.
  Variable pub_seed : Felt.

  (** Recover one WOTS+ chain endpoint from a signature element.
      [digit] is the base-[w] digit for this chain position;
      the signature element is chained forward [chain_len − digit]
      more steps to reach the public key endpoint. *)
  Definition recover_endpoint (key_idx chain_idx digit : nat)
      (sig_elem : Felt) : Felt :=
    Wots.iter F ADRS_chain (wots_chain_len - digit)
              sig_elem pub_seed key_idx chain_idx digit.

  (** Recover all chain endpoints from a WOTS+ signature.
      [digits] and [sig] must have equal length (= [wots_chains]).
      The chain index starts at [start_chain] and increments. *)
  Fixpoint recover_all (key_idx start_chain : nat)
      (digits : list nat) (sig : list Felt) : list Felt :=
    match digits, sig with
    | d :: ds, s :: ss =>
        recover_endpoint key_idx start_chain d s
          :: recover_all key_idx (S start_chain) ds ss
    | _, _ => nil
    end.

  (** Recovery of a single chain is correct: if the signature
      element was produced by chaining [d] steps from the secret
      key, then recovering chains the remaining steps to give the
      full public key endpoint.  Direct corollary of
      [Wots.recover_correct]. *)
  Theorem recover_endpoint_correct
          (key_idx chain_idx digit : nat) (sk : Felt) :
    digit <= wots_chain_len ->
    recover_endpoint key_idx chain_idx digit
      (Wots.iter F ADRS_chain digit sk pub_seed key_idx chain_idx 0) =
    Wots.iter F ADRS_chain wots_chain_len sk pub_seed key_idx chain_idx 0.
  Proof.
    intro Hle.
    unfold recover_endpoint.
    apply Wots.recover_correct. exact Hle.
  Qed.

  (** Generate WOTS+ public key endpoints from secret keys.
      Each secret key is chained forward [wots_chain_len] steps. *)
  Fixpoint gen_pk (key_idx start_chain : nat)
      (sks : list Felt) : list Felt :=
    match sks with
    | sk :: rest =>
        Wots.iter F ADRS_chain wots_chain_len
                  sk pub_seed key_idx start_chain 0
          :: gen_pk key_idx (S start_chain) rest
    | nil => nil
    end.

  (** Sign: chain each secret key forward by its digit.  The
      resulting list is the WOTS+ signature. *)
  Fixpoint sign (key_idx start_chain : nat)
      (digits : list nat) (sks : list Felt) : list Felt :=
    match digits, sks with
    | d :: ds, sk :: rest =>
        Wots.iter F ADRS_chain d sk pub_seed key_idx start_chain 0
          :: sign key_idx (S start_chain) ds rest
    | _, _ => nil
    end.

  (** Correctness of WOTS+ recovery: verifying a correctly-produced
      signature recovers the public key.  This is the completeness
      direction — correct signatures pass verification.  Each chain's
      recovery invokes [Wots.recover_correct] under the hood. *)
  Theorem recover_all_correct (key_idx start_chain : nat)
      (digits : list nat) (sks : list Felt) :
    length digits = length sks ->
    Forall (fun d => d <= wots_chain_len) digits ->
    recover_all key_idx start_chain digits
                (sign key_idx start_chain digits sks) =
    gen_pk key_idx start_chain sks.
  Proof.
    revert start_chain sks.
    induction digits as [| d ds IH]; intros start_chain sks Hlen Hdigits.
    - destruct sks; [reflexivity | discriminate].
    - destruct sks as [| sk rest]; [discriminate |].
      simpl. f_equal.
      + apply recover_endpoint_correct.
        inversion Hdigits; assumption.
      + apply IH.
        * simpl in Hlen. congruence.
        * inversion Hdigits; assumption.
  Qed.

  (** Per-chain binding: for the SAME digit, two signature elements
      that recover to the same endpoint must be equal.  Follows from
      [Wots.iter_injective] (chain injectivity under hash SPR). *)
  Theorem recover_endpoint_binding
      (H_F_inj : hash3_third_injective F)
      (key_idx chain_idx digit : nat) (sig1 sig2 : Felt) :
    digit <= wots_chain_len ->
    recover_endpoint key_idx chain_idx digit sig1 =
    recover_endpoint key_idx chain_idx digit sig2 ->
    sig1 = sig2.
  Proof.
    intros Hle Heq. unfold recover_endpoint in Heq.
    exact (Wots.iter_injective F ADRS_chain H_F_inj
             (wots_chain_len - digit) sig1 sig2 pub_seed
             key_idx chain_idx digit Heq).
  Qed.

  (** [recover_all] preserves length when digits and signature
      have equal length. *)
  Lemma recover_all_length : forall key_idx start_chain digits sig,
    length digits = length sig ->
    length (recover_all key_idx start_chain digits sig) = length digits.
  Proof.
    intros key_idx start_chain digits.
    revert start_chain.
    induction digits as [| d ds IH]; intros start_chain sig Hlen.
    - destruct sig; [reflexivity | discriminate].
    - destruct sig as [| s ss]; [discriminate |].
      simpl. f_equal. apply IH. simpl in Hlen. congruence.
  Qed.

  (** [recover_all] on non-empty equal-length inputs is non-empty. *)
  Lemma recover_all_nonempty (key_idx start_chain : nat)
      (d : nat) (ds : list nat) (s : Felt) (ss : list Felt) :
    recover_all key_idx start_chain (d :: ds) (s :: ss) <> nil.
  Proof. simpl. congruence. Qed.

End WotsRecover.

(* ================================================================ *)
(** ** Full XMSS verification predicate                              *)
(* ================================================================ *)

Section XmssVerify.

  Variable F : Felt -> Felt -> Felt -> Felt.
  Variable ADRS_chain : nat -> nat -> nat -> Felt.
  Variable H_node : nat -> nat -> Felt -> Felt -> Felt.
  Variable pub_seed : Felt.

  (** XMSS signature verification.  Given per-chain WOTS digits,
      signature elements, and an auth-tree path, the predicate holds
      iff:
      1. WOTS+ recovery yields chain endpoints,
      2. L-tree compression of the endpoints yields a leaf,
      3. the auth-tree path from that leaf reaches [auth_root_val].

      Sighash computation and digit decomposition are handled
      upstream — this definition starts from the digits. *)
  Definition xmss_verify
      (key_idx : nat) (digits : list nat) (sig : list Felt)
      (auth_bits : list bool) (auth_siblings : list Felt)
      (auth_root_val : Felt) : Prop :=
    let endpoints :=
      recover_all F ADRS_chain pub_seed key_idx 0 digits sig in
    match ltree H_node endpoints with
    | Some leaf =>
        Merkle.auth_root H_node auth_bits auth_siblings
                         leaf key_idx 0 = auth_root_val
    | None => False
    end.

  (** Full XMSS completeness: if a signer has valid secret keys,
      produces a correct signature using valid digits, and provides
      the correct auth path, then [xmss_verify] holds.

      This assembles the pieces:
      - [recover_all_correct]: recovery produces the public key
      - [ltree_succeeds]: L-tree compression succeeds
      - Auth-root equality: the auth path reaches the stored root *)
  Theorem xmss_completeness
      (key_idx : nat) (digits : list nat) (sks : list Felt)
      (auth_bits : list bool) (auth_siblings : list Felt)
      (auth_root_val : Felt) :
    length digits = length sks ->
    sks <> nil ->
    Forall (fun d => d <= wots_chain_len) digits ->
    (* The auth path from the L-tree leaf reaches the root *)
    (forall leaf,
       ltree H_node (gen_pk F ADRS_chain pub_seed key_idx 0 sks) = Some leaf ->
       Merkle.auth_root H_node auth_bits auth_siblings
                        leaf key_idx 0 = auth_root_val) ->
    xmss_verify key_idx digits
                (sign F ADRS_chain pub_seed key_idx 0 digits sks)
                auth_bits auth_siblings auth_root_val.
  Proof.
    intros Hlen Hne Hdigits Hauth.
    unfold xmss_verify.
    rewrite (recover_all_correct F ADRS_chain pub_seed
               key_idx 0 digits sks Hlen Hdigits).
    destruct (ltree_succeeds H_node
               (gen_pk F ADRS_chain pub_seed key_idx 0 sks)) as [leaf Hleaf].
    - (* gen_pk sks <> nil when sks <> nil *)
      destruct sks; [contradiction | simpl; congruence].
    - rewrite Hleaf. apply Hauth. exact Hleaf.
  Qed.

  (** ** XMSS soundness (under CR + WOTS unforgeability)

      The soundness direction: if [xmss_verify] holds, then the
      signer knew a valid secret key for the leaf at [key_idx].

      We factor this into two pieces:

      1. [xmss_verify] implies a unique leaf is at [key_idx]
         (from [auth_binding]).
      2. The leaf came from L-tree compression of recovered
         endpoints, which under WOTS unforgeability implies
         knowledge of the secret key.

      Piece (2) requires the WOTS+ one-time unforgeability axiom
      from the literature (Hülsing et al. 2017).  We state it as
      a hypothesis — axiomatizing it rather than proving it from
      PRF/SPR, per the "light path" in STATUS.md. *)

  (** Given that verification succeeds, the recovered leaf is
      uniquely determined: any other leaf that verifies against
      the same root at the same position must be equal (under CR
      of the node hash). *)
  Theorem xmss_verify_unique_leaf
      (key_idx : nat)
      (digits1 digits2 : list nat)
      (sig1 sig2 : list Felt)
      (auth_bits : list bool) (auth_siblings : list Felt)
      (auth_root_val : Felt) :
    node_injective H_node ->
    length auth_bits = length auth_siblings ->
    xmss_verify key_idx digits1 sig1 auth_bits auth_siblings auth_root_val ->
    xmss_verify key_idx digits2 sig2 auth_bits auth_siblings auth_root_val ->
    (* Both verify -> both recover the same leaf *)
    forall leaf1 leaf2,
      ltree H_node (recover_all F ADRS_chain pub_seed key_idx 0 digits1 sig1)
        = Some leaf1 ->
      ltree H_node (recover_all F ADRS_chain pub_seed key_idx 0 digits2 sig2)
        = Some leaf2 ->
      leaf1 = leaf2.
  Proof.
    intros Hinj Hpath Hv1 Hv2 leaf1 leaf2 Hl1 Hl2.
    unfold xmss_verify in Hv1, Hv2.
    rewrite Hl1 in Hv1. rewrite Hl2 in Hv2.
    (* Both auth paths from different leaves reach the same root *)
    exact (proj1 (Merkle.auth_binding H_node Hinj
                    auth_bits auth_siblings auth_siblings
                    leaf1 leaf2 key_idx 0
                    Hpath Hpath
                    (eq_trans Hv1 (eq_sym Hv2)))).
  Qed.

End XmssVerify.

(* ================================================================ *)
(** ** XMSS soundness: assembled from binding + unforgeability       *)
(* ================================================================ *)

(** The full XMSS soundness theorem: if two signatures both verify
    against the same auth root and key index, and both produce
    non-empty endpoint lists of equal length, then:

    (a) They recover the same L-tree leaf (from [auth_binding]).
    (b) They recover the same WOTS+ endpoints (from [ltree_injective]).

    The final step — "same endpoints implies same secret key" — is
    the WOTS+ one-time unforgeability property from Hülsing et al.
    We don't prove it; it would require a game-based reduction to
    PRF/second-preimage-resistance of BLAKE2s.  Instead, we
    establish the mechanical fact that XMSS soundness reduces to
    WOTS+ unforgeability: any break of XMSS implies a break of
    WOTS+. *)

Theorem xmss_soundness_reduces_to_wots
    (F : Felt -> Felt -> Felt -> Felt)
    (ADRS_chain : nat -> nat -> nat -> Felt)
    (H_node : nat -> nat -> Felt -> Felt -> Felt)
    (pub_seed : Felt)
    (key_idx : nat)
    (digits1 digits2 : list nat) (sig1 sig2 : list Felt)
    (auth_bits : list bool) (auth_siblings : list Felt)
    (auth_root_val : Felt) :
  node_injective H_node ->
  length auth_bits = length auth_siblings ->
  (* Both signatures verify *)
  xmss_verify F ADRS_chain H_node pub_seed
    key_idx digits1 sig1 auth_bits auth_siblings auth_root_val ->
  xmss_verify F ADRS_chain H_node pub_seed
    key_idx digits2 sig2 auth_bits auth_siblings auth_root_val ->
  (* Both produce endpoint lists of equal length *)
  length (recover_all F ADRS_chain pub_seed key_idx 0 digits1 sig1) =
  length (recover_all F ADRS_chain pub_seed key_idx 0 digits2 sig2) ->
  (* Then: the recovered WOTS+ endpoints are identical *)
  recover_all F ADRS_chain pub_seed key_idx 0 digits1 sig1 =
  recover_all F ADRS_chain pub_seed key_idx 0 digits2 sig2.
Proof.
  intros Hinj Hpath Hv1 Hv2 Hreclen.
  unfold xmss_verify in Hv1, Hv2.
  set (eps1 := recover_all F ADRS_chain pub_seed key_idx 0 digits1 sig1) in *.
  set (eps2 := recover_all F ADRS_chain pub_seed key_idx 0 digits2 sig2) in *.
  (* Case-split on L-tree results; rewrite into hypotheses *)
  destruct (ltree H_node eps1) as [leaf1 |] eqn:Hl1;
    rewrite ?Hl1 in Hv1; simpl in Hv1; [| contradiction].
  destruct (ltree H_node eps2) as [leaf2 |] eqn:Hl2;
    rewrite ?Hl2 in Hv2; simpl in Hv2; [| contradiction].
  (* Auth binding: same root at same position -> same leaf *)
  assert (Hleaf : leaf1 = leaf2).
  { exact (proj1 (Merkle.auth_binding H_node Hinj
                    auth_bits auth_siblings auth_siblings
                    leaf1 leaf2 key_idx 0
                    Hpath Hpath
                    (eq_trans Hv1 (eq_sym Hv2)))). }
  subst leaf2.
  (* L-tree injective: same leaf -> same endpoints *)
  apply (ltree_injective H_node Hinj eps1 eps2 Hreclen).
  - rewrite Hl1, Hl2. reflexivity.
  - rewrite Hl1. discriminate.
Qed.

(* ================================================================ *)
(** ** Bit decomposition and nat-based auth-tree walk                *)
(* ================================================================ *)

(** Decompose a natural number into [n] LSB-first bits.  Mirrors
    the Cairo loop's [idx & 1] / [idx /= 2] pattern. *)
Fixpoint nat_to_bits (n idx : nat) : list bool :=
  match n with
  | O => nil
  | S k => Nat.odd idx :: nat_to_bits k (idx / 2)
  end.

Lemma nat_to_bits_length (n idx : nat) :
  length (nat_to_bits n idx) = n.
Proof.
  revert idx.
  induction n as [| k IH]; intros idx; simpl.
  - reflexivity.
  - f_equal. apply IH.
Qed.

Section AuthWalk.

  Variable H_node : nat -> nat -> Felt -> Felt -> Felt.

  (** Nat-based auth-tree walk.  Directly mirrors the Cairo
      [xmss_verify_auth] loop (without pre-computing a bit list).
      Walks [n] levels, halving [idx] each step. *)
  Fixpoint auth_walk (n : nat) (siblings : list Felt)
      (current : Felt) (idx level : nat) : Felt :=
    match n, siblings with
    | S k, s :: ss =>
        auth_walk k ss
          (if Nat.odd idx
           then H_node level (idx / 2) s current
           else H_node level (idx / 2) current s)
          (idx / 2) (S level)
    | _, _ => current
    end.

  (** [auth_walk] equals [auth_root] when the bits are derived from
      the index via [nat_to_bits].  This bridges the Cairo's integer-
      based loop to the spec's list-of-booleans formulation. *)
  Theorem auth_walk_bits (n : nat) (siblings : list Felt)
      (current : Felt) (idx level : nat) :
    length siblings = n ->
    auth_walk n siblings current idx level =
    Merkle.auth_root H_node (nat_to_bits n idx) siblings
                     current idx level.
  Proof.
    revert siblings current idx level.
    induction n as [| k IH]; intros siblings current idx level Hlen.
    - destruct siblings; [reflexivity | discriminate].
    - destruct siblings as [| s ss]; [discriminate |].
      simpl. apply IH. simpl in Hlen. congruence.
  Qed.

End AuthWalk.

(* ================================================================ *)
(** ** WOTS+ checksum argument and unforgeability                    *)
(* ================================================================ *)

(** The WOTS+ checksum prevents an adversary from changing all digits
    upward (which would be trivially computable by forward chaining).
    The argument: if [d'_i >= d_i] for all 133 chains and both digit
    vectors have correct checksums, then [d' = d].

    Contrapositive: if [d ≠ d'], at least one chain has [d'_j < d_j],
    forcing the adversary to invert the hash (find a preimage). *)

(** Sum of a list of nats. *)
Fixpoint list_sum (xs : list nat) : nat :=
  match xs with
  | nil => 0
  | x :: rest => x + list_sum rest
  end.

(** Base-4 value of digits (LSB first). *)
Fixpoint base4_val (ds : list nat) : nat :=
  match ds with
  | nil => 0
  | d :: rest => d + 4 * base4_val rest
  end.

(** WOTS+ checksum: [sum(3 - d_i)] over message digits. *)
Definition checksum (msg : list nat) : nat :=
  list_sum (map (fun d => 3 - d) msg).

(** Helper: nat subtraction anti-monotonicity with sub_add. *)
Lemma sub_le_implies_le (a b n : nat) :
  a <= n -> b <= n -> n - a <= n - b -> b <= a.
Proof.
  intros Ha Hb Hsub.
  pose proof (Nat.sub_add a n Ha).
  pose proof (Nat.sub_add b n Hb).
  lia.
Qed.

(** Pointwise >= implies sum >=. *)
Lemma list_sum_forall2_ge (xs ys : list nat) :
  Forall2 (fun x y => x >= y) xs ys ->
  list_sum xs >= list_sum ys.
Proof.
  induction 1 as [| x y xs ys Hge _ IH]; simpl; lia.
Qed.

(** Pointwise >= with equal sums implies pointwise =. *)
Lemma list_sum_forall2_eq (xs ys : list nat) :
  Forall2 (fun x y => x >= y) xs ys ->
  list_sum xs = list_sum ys ->
  xs = ys.
Proof.
  induction 1 as [| x y xs ys Hge Hf2 IH]; intro Hsum.
  - reflexivity.
  - simpl in Hsum.
    pose proof (list_sum_forall2_ge _ _ Hf2).
    f_equal; [lia | apply IH; lia].
Qed.

(** base4_val is monotone under pointwise >=. *)
Lemma base4_val_forall2_ge (xs ys : list nat) :
  Forall2 (fun x y => x >= y) xs ys ->
  base4_val xs >= base4_val ys.
Proof.
  induction 1 as [| x y xs ys Hge _ IH]; simpl; lia.
Qed.

(** base4_val + pointwise >= + range constraints => equal.
    Key step: [x + 4a = y + 4b] with [x,y < 4] and [x >= y]
    forces [x = y] and [a = b]. *)
Lemma base4_val_forall2_eq (xs ys : list nat) :
  Forall2 (fun x y => x >= y) xs ys ->
  Forall (fun x => x <= 3) xs ->
  Forall (fun y => y <= 3) ys ->
  base4_val xs = base4_val ys ->
  xs = ys.
Proof.
  induction 1 as [| x y xs ys Hge Hf2 IH];
    intros Hxr Hyr Hval.
  - reflexivity.
  - inversion Hxr as [| ? ? Hx Hxr']; subst.
    inversion Hyr as [| ? ? Hy Hyr']; subst.
    simpl in Hval.
    pose proof (base4_val_forall2_ge _ _ Hf2).
    assert (x = y) by lia.
    assert (base4_val xs = base4_val ys) by lia.
    f_equal; [assumption | apply IH; assumption].
Qed.

(** Checksum is anti-monotone: larger digits => smaller checksum. *)
Lemma checksum_anti_mono (msg msg' : list nat) :
  Forall (fun d => d <= 3) msg ->
  Forall (fun d => d <= 3) msg' ->
  Forall2 (fun d' d => d' >= d) msg' msg ->
  checksum msg' <= checksum msg.
Proof.
  intros Hr Hr' Hge.
  unfold checksum.
  enough (list_sum (map (fun d => 3 - d) msg) >=
          list_sum (map (fun d => 3 - d) msg')).
  { lia. }
  apply list_sum_forall2_ge.
  clear Hr Hr'.
  induction Hge as [| d' d ms ms' Hge _ IH]; constructor; [lia | exact IH].
Qed.

(** Pointwise >= on digits with equal checksums => equal digits. *)
Lemma checksum_ge_eq (msg msg' : list nat) :
  Forall (fun d => d <= 3) msg ->
  Forall (fun d => d <= 3) msg' ->
  Forall2 (fun d' d => d' >= d) msg' msg ->
  checksum msg' = checksum msg ->
  msg' = msg.
Proof.
  intros Hmr Hmr'.
  revert msg Hmr.
  induction Hmr' as [| d' ms' Hd' Hr' IH]; intros msg Hmr Hmge Hcseq.
  - inversion Hmge. reflexivity.
  - destruct msg as [| d ms]; [inversion Hmge |].
    inversion Hmge as [| ? ? ? ? Hge Hf2]; subst.
    pose proof (Forall_inv Hmr) as Hd.
    pose proof (Forall_inv_tail Hmr) as Hr.
    pose proof (checksum_anti_mono _ _ Hr Hr' Hf2) as Hanti.
    (* d' = d: sub_le_implies_le needs 3-d <= 3-d' *)
    assert (Hdle : d' <= d).
    { apply (sub_le_implies_le d d' 3 Hd Hd').
      (* Goal: 3-d <= 3-d'.  From: (3-d')+cs'=(3-d)+cs, cs'<=cs *)
      unfold checksum in Hcseq, Hanti.
      set (f := fun d0 : nat => 3 - d0) in *.
      (* Step 1: (3-d') + sum(f ms') <= (3-d') + sum(f ms) *)
      assert (H1 : f d' + list_sum (map f ms') <= f d' + list_sum (map f ms))
        by (apply Nat.add_le_mono_l; exact Hanti).
      (* Step 2: substitute equation *)
      change (list_sum (map f (d' :: ms')))
        with (f d' + list_sum (map f ms')) in Hcseq.
      change (list_sum (map f (d :: ms)))
        with (f d + list_sum (map f ms)) in Hcseq.
      (* Step 3: (3-d)+sum(f ms) <= (3-d')+sum(f ms) *)
      assert (H2 : f d + list_sum (map f ms) <= f d' + list_sum (map f ms))
        by (rewrite <- Hcseq; exact H1).
      (* Step 4: cancel sum(f ms) *)
      exact (proj2 (Nat.add_le_mono_r _ _ _) H2). }
    assert (Hdeq : d' = d) by (apply Nat.le_antisymm; assumption).
    subst d'. f_equal.
    apply IH; [assumption | assumption |].
    (* checksum ms' = checksum ms: from Hcseq with d'=d cancelled *)
    unfold checksum in Hcseq |- *.
    change (list_sum (map (fun d0 => 3 - d0) (d :: ms')))
      with ((3 - d) + list_sum (map (fun d0 => 3 - d0) ms')) in Hcseq.
    change (list_sum (map (fun d0 => 3 - d0) (d :: ms)))
      with ((3 - d) + list_sum (map (fun d0 => 3 - d0) ms)) in Hcseq.
    apply (Nat.add_cancel_l _ _ (3 - d)). exact Hcseq.
Qed.

(** *** The no-dominance theorem

    If all digits of [D'] are >= the digits of [D], and both have
    correct checksums, then [D' = D].  This is the mathematical
    core of WOTS+ one-time security. *)
Theorem wots_no_dominance
    (msg msg' cs cs' : list nat) :
  length msg = length msg' ->
  Forall (fun d => d <= 3) msg ->
  Forall (fun d => d <= 3) msg' ->
  Forall (fun d => d <= 3) cs ->
  Forall (fun d => d <= 3) cs' ->
  base4_val cs = checksum msg ->
  base4_val cs' = checksum msg' ->
  Forall2 (fun d' d => d' >= d) msg' msg ->
  Forall2 (fun d' d => d' >= d) cs' cs ->
  msg' = msg /\ cs' = cs.
Proof.
  intros Hmlen Hmr Hmr' Hcr Hcr' Hcs Hcs' Hmge Hcge.
  (* Checksum decreases: msg digits up => checksum down *)
  assert (Hcsle : checksum msg' <= checksum msg)
    by (apply checksum_anti_mono; assumption).
  (* base4_val increases: cs digits up => value up *)
  assert (Hbge : base4_val cs' >= base4_val cs)
    by (apply base4_val_forall2_ge; assumption).
  (* But cs' encodes checksum msg' and cs encodes checksum msg *)
  (* So: base4_val cs' = checksum msg' <= checksum msg = base4_val cs *)
  (* And: base4_val cs' >= base4_val cs *)
  (* Therefore: base4_val cs' = base4_val cs *)
  assert (Hbeq : base4_val cs' = base4_val cs) by lia.
  (* Checksum digits equal *)
  assert (Hceq : cs' = cs)
    by (apply base4_val_forall2_eq; assumption).
  (* Checksums equal *)
  assert (Hcseq : checksum msg' = checksum msg) by lia.
  (* Message digits equal *)
  assert (Hmeq : msg' = msg)
    by (apply checksum_ge_eq; assumption).
  split; assumption.
Qed.

(** Contrapositive: different digits => at least one chain goes backward. *)
Corollary wots_exists_backward
    (msg msg' cs cs' : list nat) :
  length msg = length msg' ->
  length cs = length cs' ->
  Forall (fun d => d <= 3) msg ->
  Forall (fun d => d <= 3) msg' ->
  Forall (fun d => d <= 3) cs ->
  Forall (fun d => d <= 3) cs' ->
  base4_val cs = checksum msg ->
  base4_val cs' = checksum msg' ->
  msg ++ cs <> msg' ++ cs' ->
  (* Then: not all digits of D' are >= digits of D *)
  ~ (Forall2 (fun d' d => d' >= d) msg' msg /\
     Forall2 (fun d' d => d' >= d) cs' cs).
Proof.
  intros Hmlen Hclen Hmr Hmr' Hcr Hcr' Hcs Hcs' Hne [Hmge Hcge].
  apply Hne.
  destruct (wots_no_dominance msg msg' cs cs'
              Hmlen Hmr Hmr' Hcr Hcr' Hcs Hcs' Hmge Hcge)
    as [Hmeq Hceq].
  rewrite Hmeq, Hceq. reflexivity.
Qed.

(* ================================================================ *)
(** ** Full verification predicates matching Cairo assertions         *)
(* ================================================================ *)

(** These definitions mirror the EXACT assertions in the Cairo code.
    Each Cairo [assert] becomes a conjunct.  If a conjunct is removed,
    the corresponding soundness proof fails, identifying the gap.

    Source: [cairo/src/merkle.cairo::verify] and
    [cairo/src/xmss_common.cairo::xmss_verify_auth]. *)

Section CairoAssertions.

  Variable H_merkle : Felt -> Felt -> Felt.
  Variable H_node : nat -> nat -> Felt -> Felt -> Felt.

  (** Commitment-tree Merkle verification.  Three assertions from
      [cairo/src/merkle.cairo::verify]:
      1. [siblings.len() == TREE_DEPTH]
      2. [idx == 0] after walking (path_indices < 2^TREE_DEPTH)
      3. [current == root] *)
  Definition merkle_verify
      (leaf root : Felt) (siblings : list Felt)
      (path_indices : nat) : Prop :=
    length siblings = tree_depth /\
    path_indices < 2 ^ tree_depth /\
    merkle_root H_merkle (nat_to_bits tree_depth path_indices)
                siblings leaf = root.

  (** XMSS auth-tree verification.  Three assertions from
      [cairo/src/xmss_common.cairo::xmss_verify_auth]:
      1. [siblings.len() == AUTH_DEPTH]
      2. [idx == 0] (key_idx < 2^AUTH_DEPTH)
      3. [current == auth_root] *)
  Definition auth_verify
      (leaf auth_root_val : Felt) (siblings : list Felt)
      (key_idx : nat) : Prop :=
    length siblings = auth_depth /\
    key_idx < 2 ^ auth_depth /\
    auth_root H_node (nat_to_bits auth_depth key_idx)
              siblings leaf key_idx 0 = auth_root_val.

  (** The [merkle_verify] definition correctly uses [nat_to_bits]
      to decompose the index, matching Cairo's [idx & 1] / [idx /= 2]
      loop.  The equivalence is established by [auth_walk_bits]. *)

  (** Full XMSS signature verification matching the Cairo flow:
      [xmss_recover_pk] → [xmss_ltree] → [xmss_verify_auth].

      This is the Cairo-faithful version of [xmss_verify] that
      includes all three auth assertions and uses [nat_to_bits]
      for bit decomposition (matching Cairo's integer loop). *)
  Definition xmss_verify_cairo
      (F : Felt -> Felt -> Felt -> Felt)
      (ADRS_chain : nat -> nat -> nat -> Felt)
      (pub_seed : Felt)
      (key_idx : nat) (digits : list nat) (sig : list Felt)
      (auth_siblings : list Felt) (auth_root_val : Felt) : Prop :=
    let endpoints :=
      recover_all F ADRS_chain pub_seed key_idx 0 digits sig in
    match ltree H_node endpoints with
    | Some leaf => auth_verify leaf auth_root_val auth_siblings key_idx
    | None => False
    end.

  (** The Cairo-faithful [xmss_verify_cairo] is strictly stronger than
      the spec-level [xmss_verify]: it includes the depth check and
      the key-index range check.  This theorem shows the Cairo version
      implies the spec version (the spec-level proofs transfer). *)
  Theorem xmss_verify_cairo_implies_spec
      (F : Felt -> Felt -> Felt -> Felt)
      (ADRS_chain : nat -> nat -> nat -> Felt)
      (pub_seed : Felt)
      (key_idx : nat) (digits : list nat) (sig : list Felt)
      (auth_siblings : list Felt) (auth_root_val : Felt) :
    xmss_verify_cairo F ADRS_chain pub_seed
      key_idx digits sig auth_siblings auth_root_val ->
    xmss_verify F ADRS_chain H_node pub_seed
      key_idx digits sig
      (nat_to_bits auth_depth key_idx)
      auth_siblings auth_root_val.
  Proof.
    unfold xmss_verify_cairo, xmss_verify, auth_verify.
    destruct (ltree H_node _) as [leaf |]; [| contradiction].
    intros [_ [_ Hroot]]. exact Hroot.
  Qed.

End CairoAssertions.

(** The [idx == 0] assertion in the Cairo verifier.  After dividing
    [idx] by 2 a total of [n] times, the result is zero iff
    [idx < 2^n].  This is the mathematical content of
    [assert(idx == 0, 'xmss key idx out of range')]. *)
Lemma idx_zero_iff_in_range (idx n : nat) :
  idx / 2 ^ n = 0 <-> idx < 2 ^ n.
Proof.
  assert (Hpos : 2 ^ n <> 0) by (induction n; simpl; lia).
  split.
  - intro Hdiv.
    pose proof (Nat.div_mod idx (2 ^ n) Hpos) as Heq.
    rewrite Hdiv, Nat.mul_0_r, Nat.add_0_l in Heq.
    rewrite Heq. apply Nat.mod_upper_bound. exact Hpos.
  - apply Nat.div_small.
Qed.
