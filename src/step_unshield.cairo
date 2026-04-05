/// Test executable: Unshield note A — withdraw 1000 to a recipient.
///
/// The proof outputs [root, nf, v_pub, ak, recipient]. The contract
/// verifies the STARK proof and a signature under ak. The prover has
/// nsk (for the proof) but not ask (for the signature).
///
/// Tree state: [cm_a]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, tree, unshield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let recipient: felt252 = 0xCAFE;

    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm];
    let (siblings, idx, root) = tree::auth_path(leaves.span(), 0, zh.span());

    let nf = hash::nullifier(a.nsk, a.rho);
    unshield::verify(root, nf, a.v, a.ak, recipient, a.nsk, a.rho, a.r, siblings.span(), idx)
}
