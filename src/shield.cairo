/// Shield circuit: deposit public tokens into a private note.
///
/// # Public outputs (read from proof by the on-chain contract)
///   - `v_pub`  — the deposited amount
///   - `cm_new` — the new note commitment (appended to T)
///   - `ak`     — authorization key (contract verifies spend signature)
///   - `sender` — depositor's address (prevents front-running)
///
/// # Private inputs (known to the prover, NOT to the contract)
///   - `pk`  — paying key = H(nsk), where nsk is the note's nullifier key
///   - `rho` — random nonce (unique per note)
///   - `r`   — blinding factor (makes commitment hiding)
///
/// # Constraint
///   cm_new = H(H(pk, ak), v_pub, rho, r)
///
/// # Delegated proving
///
/// The prover receives (pk, ak, v_pub, rho, r) — enough to compute the
/// commitment and generate the proof. They do NOT receive `ask` (the
/// authorization signing key). After the prover returns the proof, the
/// user signs the outputs with `ask`. The contract checks the signature
/// against `ak` (output by the proof).

use starkprivacy::blake_hash as hash;

pub fn verify(
    v_pub: u64,
    cm_new: felt252,
    ak: felt252,
    sender: felt252,
    pk: felt252,
    rho: felt252,
    r: felt252,
) -> Array<felt252> {
    assert(hash::commit(pk, ak, v_pub, rho, r) == cm_new, 'shield: bad commitment');

    // Public outputs. The contract:
    //   1. Verifies the STARK proof
    //   2. Checks Sig(ask, outputs) against ak
    //   3. Checks msg.sender == sender
    //   4. Deducts v_pub from sender, appends cm_new to T
    array![v_pub.into(), cm_new, ak, sender]
}
