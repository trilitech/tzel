/// Test: Unshield note A — withdraw 1000 (N=1, no change).
/// Tree: [cm_a]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, tree, unshield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let (_, ak) = common::derive_ask(common::alice_account().ask_base, 0);
    let recipient: felt252 = 0xCAFE;

    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm];
    let (siblings, idx, root) = tree::auth_path(leaves.span(), 0, zh.span());

    // Compute nullifier: nf = H_nf(nk_spend, cm, pos) where pos = leaf index.
    let nf = hash::nullifier(a.nk_spend, a.cm, idx);

    unshield::verify(
        root,
        array![nf].span(),
        a.v,
        recipient,
        // per-input (N=1)
        array![a.nk_spend].span(),
        array![ak].span(),
        array![a.d_j].span(),
        array![a.v].span(),
        array![a.rseed].span(),
        siblings.span(),
        array![idx].span(),
        // no change
        false, 0, 0, 0, 0, 0, 0,
    )
}
