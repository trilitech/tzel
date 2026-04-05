/// Step: Unshield note A (1000) from Alice to a recipient.
/// Tree: [cm_a]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, tree, unshield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let recipient: felt252 = 0xCAFE;

    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm];
    let (siblings, idx, root) = tree::auth_path(leaves.span(), 0, zh.span());

    let nf = hash::nullifier(a.sk, a.rho);
    unshield::verify(root, nf, a.v, recipient, a.sk, a.rho, a.r, siblings.span(), idx)
}
