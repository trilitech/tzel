/// Step 2: Unshield note A — withdraw 1000 to a recipient (N=1, no change).
/// Tree: [cm_a]

use starkprivacy::{common, tree, unshield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let (_, ak) = common::derive_ask(common::alice_account().ask_base, 0);
    let recipient: felt252 = 0xCAFE;

    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm];
    let (siblings, idx, root) = tree::auth_path(leaves.span(), 0, zh.span());

    // N=1: single-element arrays for per-input data.
    unshield::verify(
        root,
        array![a.nf].span(),
        a.v,
        recipient,
        array![a.nk].span(),
        array![ak].span(),
        array![a.d_j].span(),
        array![a.v].span(),
        array![a.rseed].span(),
        siblings.span(),
        array![idx].span(),
        false, 0, 0, 0, 0, // no change
    )
}
