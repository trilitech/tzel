/// Shield circuit: deposit public tokens into a private note.
///
/// Public inputs:  v_pub, cm_new
/// Private inputs: pk, rho, r
///
/// Proves: cm_new = H(pk, v_pub, rho, r)

use starkprivacy::blake_hash as hash;

pub fn verify(v_pub: u64, cm_new: felt252, pk: felt252, rho: felt252, r: felt252) -> Array<felt252> {
    assert(hash::commit(pk, v_pub, rho, r) == cm_new, 'shield: bad commitment');

    // Public outputs — the on-chain verifier reads these from the proof.
    array![v_pub.into(), cm_new]
}
