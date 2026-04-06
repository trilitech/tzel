/// Test: Join A(1000) + B(500) → C(1500) + W(0) using N=2 transfer.
/// Also shields dummy note Z. Tree: [cm_a, cm_b, cm_z]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, shield, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let b = common::note_b();
    let z = common::note_z();
    let c = common::note_c();
    let w = common::note_w();

    // Shield dummy note Z.
    let (_, ak_z) = common::derive_ask(common::dummy_account().ask_base, 0);
    shield::verify(z.v, z.cm, ak_z, 0xA11CE_ADD8, 0, z.nk_tag, z.d_j, z.rseed);

    // Build tree and Merkle paths.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm];
    let (sib_a, idx_a, root) = tree::auth_path(leaves.span(), 0, zh.span());
    let (sib_b, idx_b, _) = tree::auth_path(leaves.span(), 1, zh.span());

    let (_, ak_a) = common::derive_ask(common::alice_account().ask_base, 0);
    let (_, ak_b) = common::derive_ask(common::alice_account().ask_base, 1);

    // Compute position-dependent nullifiers.
    let nf_a = hash::nullifier(a.nk_spend, a.cm, idx_a);
    let nf_b = hash::nullifier(b.nk_spend, b.cm, idx_b);

    // Flatten siblings for N=2.
    let mut sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < sib_a.len() { sibs.append(*sib_a.at(i)); i += 1; };
    let mut i: u32 = 0;
    while i < sib_b.len() { sibs.append(*sib_b.at(i)); i += 1; };

    transfer::verify(
        root,
        array![nf_a, nf_b].span(),
        c.cm, w.cm,
        // per-input (N=2)
        array![a.nk_spend, b.nk_spend].span(),
        array![ak_a, ak_b].span(),
        array![a.d_j, b.d_j].span(),
        array![a.v, b.v].span(),
        array![a.rseed, b.rseed].span(),
        sibs.span(),
        array![idx_a, idx_b].span(),
        // output C + output W (with nk_tag for each)
        c.d_j, c.v, c.rseed, c.ak, c.nk_tag, 0xBEEF,
        w.d_j, w.v, w.rseed, w.ak, w.nk_tag, 0xCAFE,
    )
}
