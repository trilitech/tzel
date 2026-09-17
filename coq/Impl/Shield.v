(** * Impl.Shield

    Mirror of [cairo/src/shield.cairo].

    Shield drains some balance from a deposit pool keyed by
    [pubkey_hash = H(0x04, auth_domain, auth_root, auth_pub_seed,
    blind)] and produces two private notes (recipient + producer-fee).
    The Cairo circuit verifies an in-circuit WOTS+ signature against
    the recipient's auth tree, binding every public output (including
    the deposit pool key, both output commitments, and both memo
    hashes).

    Soundness target:

      shield_sound:
        ShieldRelation pub wit ->
        Phi_shield pub

    where [Phi_shield pub] enumerates: [pubkey_hash] commits to the
    recipient's auth tree (so only that auth tree's holder can drain),
    the in-circuit signature covers every public output, the drained
    amount equals [v_note + fee + producer_fee], and both output
    commitments are well-formed.

    The interesting wrinkle here vs transfer/unshield: shield has no
    nullifier — it's the entry point. The L1 ticket landing on the
    [deposit:<hex(pubkey_hash)>] recipient is what authenticates the
    pool's existence, and the circuit's WOTS+ signature is what
    authenticates the drain. Modeling that L1↔kernel handshake is
    out of scope here (it's a kernel-side property); the circuit-side
    obligation is "the in-circuit signature binds [pubkey_hash] to a
    leaf in the recipient's auth tree."

    Status: safety predicate defined in [Spec.Shield];
    implementation-side refinement pending.
*)

From Common Require Import Felt.
From Impl Require Import Hashes.
From Impl Require Import Wots.
From Impl Require Import Xmss.
From Spec Require Shield.
