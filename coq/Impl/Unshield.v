(** * Impl.Unshield

    Mirror of [cairo/src/unshield.cairo].

    Unshield consumes [N] (1 ≤ N ≤ 7) input notes, emits an L1 outbox
    transfer of [v_pub] mutez to a tz/KT1 recipient, optionally creates
    a private change note, and creates a producer-fee note. The
    structure mirrors transfer for the input side (Merkle inclusion
    + nullifier + WOTS+ verification per input) but the outputs differ:
    one public exit, optional change, one producer fee.

    Soundness target:

      unshield_sound:
        UnshieldRelation pub wit ->
        Phi_unshield pub

    where [Phi_unshield pub] enumerates the per-input authenticity
    obligations from transfer, plus output well-formedness and the
    value-balance equation [sum_in = v_pub + fee + producer_fee
    + (v_change if has_change else 0)].

    The L1-side authorization (that the outbox transfer is honored
    by the kernel and L1) is a kernel-level property, not in scope
    here. The circuit-side obligation is "the spend authorization
    is bound to the specific recipient and amount published as
    public outputs," which the sighash already captures.

    Status: safety predicate defined in [Spec.Unshield];
    implementation-side refinement pending.
*)

From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Merkle.
From Impl Require Import Wots.
From Impl Require Import Xmss.
From Spec Require Unshield.
