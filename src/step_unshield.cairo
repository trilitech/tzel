/// Test executable: Unshield note A — withdraw 1000 to a recipient.
///
/// Proves that:
///   1. The prover knows sk_alice such that pk = H(sk_alice)
///   2. cm_a = H(pk, 1000, rho, r) exists in the tree
///   3. nf = H(sk_alice, rho) is the correct nullifier
///
/// The on-chain effect would be: add nf to NF_set, credit 1000 to recipient.
///
/// Tree state: [cm_a] (same as after step_shield)

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, tree, unshield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let recipient: felt252 = 0xCAFE; // Destination address (test value)

    // Build the Merkle tree with a single leaf and compute the auth path.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm];
    let (siblings, idx, root) = tree::auth_path(leaves.span(), 0, zh.span());

    // Compute the nullifier that the contract will add to NF_set.
    let nf = hash::nullifier(a.sk, a.rho);

    // Run the unshield circuit — proves ownership and tree membership.
    unshield::verify(root, nf, a.v, recipient, a.sk, a.rho, a.r, siblings.span(), idx)
}
