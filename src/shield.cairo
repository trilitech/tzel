/// Shield circuit: deposit public tokens into a private note.
///
/// This is the simplest circuit — it just proves that a commitment is
/// well-formed. The on-chain contract deducts `v_pub` from the sender's
/// public balance and appends `cm_new` to the commitment tree T.
///
/// # Public inputs (read from proof output by the on-chain verifier)
///   - `v_pub`  — the deposited amount
///   - `cm_new` — the new note commitment (appended to T)
///   - `sender` — depositor's address (binds proof to prevent front-running)
///
/// # Private inputs (known only to the prover)
///   - `pk`  — recipient's paying key (who can later spend the note)
///   - `rho` — random nonce (unique per note)
///   - `r`   — blinding factor (makes commitment hiding)
///
/// # Constraint
///   cm_new = H(pk, v_pub, rho, r)
///
/// The prover demonstrates knowledge of a valid opening of the commitment
/// without revealing pk, rho, or r.

use starkprivacy::blake_hash as hash;

pub fn verify(
    v_pub: u64,
    cm_new: felt252,
    sender: felt252,
    pk: felt252,
    rho: felt252,
    r: felt252,
) -> Array<felt252> {
    // The only constraint: the commitment must be correctly computed.
    assert(hash::commit(pk, v_pub, rho, r) == cm_new, 'shield: bad commitment');

    // Return public outputs. The on-chain verifier reads these from the
    // proof to update state: deduct v_pub from sender, append cm_new to T.
    // `sender` is included so a front-runner can't steal the proof and
    // submit it from a different address.
    array![v_pub.into(), cm_new, sender]
}
