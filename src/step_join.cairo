/// Step 3: Join A(1000) + B(500) → C(1500, bob) + W(0, alice) using N=2 transfer.
/// Also shields dummy note Z first. Tree: [cm_a, cm_b, cm_z]

use starkprivacy::{common, shield, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let b = common::note_b();
    let z = common::note_z();
    let c = common::note_c();
    let w = common::note_w();

    // Shield dummy note Z for later use.
    let (_, ak_z) = common::derive_ask(common::dummy_account().ask_base, 0);
    let sender: felt252 = 0xA11CE_ADD8;
    shield::verify(z.v, z.cm, ak_z, sender, z.d_j, z.rseed);

    // Build tree and Merkle paths.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm];
    let (sib_a, idx_a, root) = tree::auth_path(leaves.span(), 0, zh.span());
    let (sib_b, idx_b, _) = tree::auth_path(leaves.span(), 1, zh.span());

    let (_, ak_a) = common::derive_ask(common::alice_account().ask_base, 0);
    let (_, ak_b) = common::derive_ask(common::alice_account().ask_base, 1);

    // Concatenate siblings into flat array for N=2.
    let mut siblings_flat: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < sib_a.len() { siblings_flat.append(*sib_a.at(i)); i += 1; };
    let mut i: u32 = 0;
    while i < sib_b.len() { siblings_flat.append(*sib_b.at(i)); i += 1; };

    transfer::verify(
        root,
        array![a.nf, b.nf].span(),
        c.cm, w.cm,
        // per-input arrays (N=2)
        array![a.nk, b.nk].span(),
        array![ak_a, ak_b].span(),
        array![a.d_j, b.d_j].span(),
        array![a.v, b.v].span(),
        array![a.rseed, b.rseed].span(),
        siblings_flat.span(),
        array![idx_a, idx_b].span(),
        // output C (Bob), output W (Alice)
        c.d_j, c.v, c.rseed, c.ak,
        w.d_j, w.v, w.rseed, w.ak,
    )
}
