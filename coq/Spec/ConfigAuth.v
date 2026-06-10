(** * Spec.ConfigAuth — kernel config-update authorization is unforgeable

    The kernel authenticates verifier- and bridge-config updates with a
    WOTS+ signature from the admin key, checked against a COMPILED-IN
    expected leaf ([authenticate_verifier_config] /
    [authenticate_bridge_config] in [tezos/rollup-kernel/src/lib.rs]:
    [verify_wots_signature_against_leaf(sighash(config), pub_seed,
    key_idx, signature, expected_leaf)]).  So config substitution — an
    attacker swapping in a malicious verifier or bridge config — is
    prevented by WOTS+ one-time unforgeability.

    This is the kernel-GOVERNANCE analogue of the transaction-level
    [Spec.Xmss.xmss_one_time_unforgeable]: a forward-only forger cannot
    authenticate a config the admin did not sign.  The authentication
    is against a fixed LEAF directly (the admin key), with no Merkle
    auth path — so it reuses [ltree_injective] (same leaf => same WOTS
    endpoints) and [wots_one_time_unforgeable] (forward-only + checksum
    => same signed message). *)

From Stdlib Require Import List Arith Lia.
Import ListNotations.
From Common Require Import Felt.
From Spec Require Import Hashes Xmss WotsChecksum.

(** A config update authenticates iff its WOTS+ signature, recovered
    over the config's sighash digits, L-tree-compresses to the
    compiled admin [leaf]. *)
Definition config_authenticates
    (F : Felt -> Felt -> Felt -> Felt)
    (ADRS : nat -> nat -> nat -> Felt)
    (H_node : nat -> nat -> Felt -> Felt -> Felt)
    (pub_seed : Felt) (key_idx : nat)
    (digits : list nat) (sig : list Felt) (leaf : Felt) : Prop :=
  ltree H_node (recover_all F ADRS pub_seed key_idx 0 digits sig) = Some leaf.

(** Only the admin can update the config: two config updates that both
    authenticate against the SAME compiled admin leaf, where the second
    is a forward-only forgery of the first, (a) recover the same admin
    WOTS public key and (b) sign the SAME config.  So an attacker
    cannot authenticate any config other than the one the admin
    actually signed. *)
Theorem config_update_unforgeable
    (F : Felt -> Felt -> Felt -> Felt)
    (ADRS : nat -> nat -> nat -> Felt)
    (H_node : nat -> nat -> Felt -> Felt -> Felt)
    (pub_seed : Felt) (key_idx : nat)
    (msg1 cs1 msg2 cs2 : list nat) (sig1 sig2 : list Felt) (leaf : Felt) :
  node_injective H_node ->
  length (msg1 ++ cs1) = length sig1 ->
  length (msg2 ++ cs2) = length sig2 ->
  length msg1 = length msg2 ->
  length cs1 = length cs2 ->
  Forall (fun d => d <= 3) msg1 -> Forall (fun d => d <= 3) msg2 ->
  Forall (fun d => d <= 3) cs1 -> Forall (fun d => d <= 3) cs2 ->
  base4_val cs1 = checksum msg1 -> base4_val cs2 = checksum msg2 ->
  config_authenticates F ADRS H_node pub_seed key_idx (msg1 ++ cs1) sig1 leaf ->
  config_authenticates F ADRS H_node pub_seed key_idx (msg2 ++ cs2) sig2 leaf ->
  Forall2 (fun d2 d1 => d2 >= d1) msg2 msg1 ->
  Forall2 (fun d2 d1 => d2 >= d1) cs2 cs1 ->
  recover_all F ADRS pub_seed key_idx 0 (msg1 ++ cs1) sig1
    = recover_all F ADRS pub_seed key_idx 0 (msg2 ++ cs2) sig2
  /\ msg1 = msg2.
Proof.
  intros Hinj Hs1 Hs2 Hmlen Hclen Hm1 Hm2 Hc1 Hc2 Hcs1 Hcs2 Ha1 Ha2 Hmge Hcge.
  unfold config_authenticates in Ha1, Ha2.
  assert (Hreclen :
    length (recover_all F ADRS pub_seed key_idx 0 (msg1 ++ cs1) sig1)
    = length (recover_all F ADRS pub_seed key_idx 0 (msg2 ++ cs2) sig2)).
  { rewrite (recover_all_length F ADRS pub_seed key_idx 0 (msg1 ++ cs1) sig1 Hs1).
    rewrite (recover_all_length F ADRS pub_seed key_idx 0 (msg2 ++ cs2) sig2 Hs2).
    rewrite !length_app. lia. }
  split.
  - (* same admin WOTS public key, via L-tree injectivity *)
    apply (ltree_injective H_node Hinj
             (recover_all F ADRS pub_seed key_idx 0 (msg1 ++ cs1) sig1)
             (recover_all F ADRS pub_seed key_idx 0 (msg2 ++ cs2) sig2)
             Hreclen).
    + rewrite Ha1, Ha2. reflexivity.
    + rewrite Ha1. discriminate.
  - (* same config, via WOTS one-time unforgeability *)
    symmetry.
    apply (wots_one_time_unforgeable msg1 msg2 cs1 cs2
             Hmlen Hm1 Hm2 Hc1 Hc2 Hcs1 Hcs2 Hmge Hcge).
Qed.


(** The concrete-checksum discharge for CONFIG governance — the third
    and last of the unforgeability theorems.  An attacker cannot
    authenticate a config update for a different message under the
    Cairo's real checksum encoding: two config authentications under the
    admin leaf, related by a forward-only forgery, are of the same
    config sighash.  All checksum premises discharged. *)
Theorem config_update_concrete_checksum
    (F : Felt -> Felt -> Felt -> Felt) (ADRS : nat -> nat -> nat -> Felt)
    (H_node : nat -> nat -> Felt -> Felt -> Felt) (pub_seed : Felt) (key_idx : nat)
    (msg1 msg2 : list nat) (sig1 sig2 : list Felt) (leaf : Felt) :
  Hashes.node_injective H_node ->
  length (msg1 ++ base4_encode5 (checksum msg1)) = length sig1 ->
  length (msg2 ++ base4_encode5 (checksum msg2)) = length sig2 ->
  length msg1 = 128 -> length msg2 = 128 ->
  Forall (fun d => d <= 3) msg1 -> Forall (fun d => d <= 3) msg2 ->
  config_authenticates F ADRS H_node pub_seed key_idx
    (msg1 ++ base4_encode5 (checksum msg1)) sig1 leaf ->
  config_authenticates F ADRS H_node pub_seed key_idx
    (msg2 ++ base4_encode5 (checksum msg2)) sig2 leaf ->
  Forall2 (fun d2 d1 => d2 >= d1) msg2 msg1 ->
  Forall2 (fun d2 d1 => d2 >= d1)
    (base4_encode5 (checksum msg2)) (base4_encode5 (checksum msg1)) ->
  msg1 = msg2.
Proof.
  intros Hni Hs1 Hs2 Hl1 Hl2 Hb1 Hb2 Ha1 Ha2 Hm Hc.
  pose proof (config_update_unforgeable F ADRS H_node pub_seed key_idx
    msg1 (base4_encode5 (checksum msg1)) msg2 (base4_encode5 (checksum msg2))
    sig1 sig2 leaf
    Hni Hs1 Hs2 (eq_trans Hl1 (eq_sym Hl2))
    (eq_trans (base4_encode5_length _) (eq_sym (base4_encode5_length _)))
    Hb1 Hb2 (base4_encode5_bound _) (base4_encode5_bound _)
    (checksum_hypothesis_realized msg1 Hl1 Hb1)
    (checksum_hypothesis_realized msg2 Hl2 Hb2)
    Ha1 Ha2 Hm Hc) as [_ Hmsg].
  exact Hmsg.
Qed.

