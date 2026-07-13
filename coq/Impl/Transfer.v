(** * Impl.Transfer

    Mirror of [cairo/src/transfer.cairo].

    The Cairo file implements the [N -> 3] transfer relation: spend
    [N] (1 ≤ N ≤ 7) input notes, produce three output commitments
    (recipient, change, producer-fee). For each input [i], it checks:
    - the input note's commitment is Merkle-included in [root]
      (via [Tzel.Merkle]),
    - the published nullifier is correctly derived from the witness,
    - a one-time WOTS+ signature under the auth tree leaf at the
      claimed index verifies the sighash (via [Tzel.Xmss]).

    For each output [j ∈ {1,2,3}], it checks the commitment is
    well-formed: [cm_j = H_commit(d_j, v_j, rcm(rseed_j), otag_j)].

    It then checks value conservation:
    [sum_in = v_1 + v_2 + v_3 + fee].

    The sighash binds every public output, so a malicious prover
    cannot redirect outputs without re-signing.

    Soundness target (the headline):

      transfer_sound:
        TransferRelation pub wit ->
        Phi_transfer pub /\ exists witness_evidence ...

    where [Phi_transfer pub] is the protocol-level safety predicate:
    every nullifier was correctly derived from a real Merkle-included
    note, the value triple balances, every output commitment is
    well-formed, and a valid spend authorization existed.

    The proof here is mostly assembly — given [merkle_path_sound],
    [xmss_verify_sound], and [commit_injective] (all from earlier
    modules), the transfer-level soundness drops out from the Cairo
    asserts. The interesting case is when the proof DOESN'T drop out:
    that's where a missing assert lives.

    Status: safety predicate defined in [Spec.Transfer];
    implementation-side refinement pending.
*)

From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Merkle.
From Impl Require Import Wots.
From Impl Require Import Xmss.
From Spec Require Transfer.
