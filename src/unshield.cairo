/// Unshield circuit: withdraw a private note to a public amount.
///
/// Public inputs:  root, nf, v_pub, recipient
/// Private inputs: sk, rho, r, siblings, path_indices
///
/// Proves:
///   1. pk  = H(sk)
///   2. cm  = H(pk, v_pub, rho, r)
///   3. cm is in T under root
///   4. nf  = H(sk, rho)
///
/// `recipient` is included as a public input so the proof is bound to a
/// specific destination address and cannot be front-run or claimed by
/// another party.

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

pub fn verify(
    root: felt252,
    nf: felt252,
    v_pub: u64,
    recipient: felt252,
    sk: felt252,
    rho: felt252,
    r: felt252,
    siblings: Span<felt252>,
    path_indices: u64,
) -> Array<felt252> {
    let pk = hash::derive_pk(sk);
    let cm = hash::commit(pk, v_pub, rho, r);
    merkle::verify(cm, root, siblings, path_indices);
    assert(hash::nullifier(sk, rho) == nf, 'unshield: bad nullifier');

    // Public outputs — the on-chain verifier reads these from the proof.
    array![root, nf, v_pub.into(), recipient]
}
