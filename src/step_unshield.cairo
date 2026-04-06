/// Test: Unshield note A -- withdraw 1000 (N=1, no change).
/// Tree: [cm_a]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, tree, unshield};

#[executable]
fn main() -> Array<felt252> {
    let (a, ai_a) = common::note_a();
    let recipient: felt252 = 0xCAFE;

    // Commitment tree path.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm];
    let (cm_siblings, idx, root) = tree::auth_path(leaves.span(), 0, zh.span());

    // Auth tree path for the one-time key.
    let auth_siblings_a = ai_a.auth_path;

    // Compute nullifier: nf = H_nf(nk_spend, cm, pos).
    let nf = hash::nullifier(a.nk_spend, a.cm, idx);

    unshield::verify(
        root,
        array![nf].span(),
        a.v,
        recipient,
        // per-input (N=1)
        array![a.nk_spend].span(),
        array![a.auth_root].span(),
        array![a.auth_leaf_hash].span(),
        auth_siblings_a.span(),
        array![a.auth_key_idx.into()].span(),
        array![a.d_j].span(),
        array![a.v].span(),
        array![a.rseed].span(),
        cm_siblings.span(),
        array![idx].span(),
        // no change
        false, 0, 0, 0, 0, 0, 0,
    )
}
