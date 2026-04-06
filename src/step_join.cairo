/// Test: Join A(1000) + B(500) -> C(1500) + W(0) using N=2 transfer.
/// Also shields dummy note Z. Tree: [cm_a, cm_b, cm_z]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, shield, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    let (a, ai_a) = common::note_a();
    let (b, ai_b) = common::note_b();
    let (z, _ai_z) = common::note_z();
    let (c, _ai_c) = common::note_c();
    let (w, _ai_w) = common::note_w();

    // Shield dummy note Z.
    shield::verify(z.v, z.cm, 0xA11CE_ADD8, 0, z.auth_root, z.nk_tag, z.d_j, z.rseed);

    // Build commitment tree and Merkle paths.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm];
    let (cm_sib_a, idx_a, root) = tree::auth_path(leaves.span(), 0, zh.span());
    let (cm_sib_b, idx_b, _) = tree::auth_path(leaves.span(), 1, zh.span());

    // Compute position-dependent nullifiers.
    let nf_a = hash::nullifier(a.nk_spend, a.cm, idx_a);
    let nf_b = hash::nullifier(b.nk_spend, b.cm, idx_b);

    // Flatten commitment siblings for N=2.
    let mut cm_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < cm_sib_a.len() { cm_sibs.append(*cm_sib_a.at(i)); i += 1; };
    let mut i: u32 = 0;
    while i < cm_sib_b.len() { cm_sibs.append(*cm_sib_b.at(i)); i += 1; };

    // Flatten auth siblings for N=2.
    let auth_path_a = ai_a.auth_path;
    let auth_path_b = ai_b.auth_path;
    let mut auth_sibs: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < auth_path_a.len() { auth_sibs.append(*auth_path_a.at(i)); i += 1; };
    let mut i: u32 = 0;
    while i < auth_path_b.len() { auth_sibs.append(*auth_path_b.at(i)); i += 1; };

    transfer::verify(
        root,
        array![nf_a, nf_b].span(),
        c.cm, w.cm,
        // per-input (N=2)
        array![a.nk_spend, b.nk_spend].span(),
        array![a.auth_root, b.auth_root].span(),
        array![a.auth_leaf_hash, b.auth_leaf_hash].span(),
        auth_sibs.span(),
        array![a.auth_key_idx.into(), b.auth_key_idx.into()].span(),
        array![a.d_j, b.d_j].span(),
        array![a.v, b.v].span(),
        array![a.rseed, b.rseed].span(),
        cm_sibs.span(),
        array![idx_a, idx_b].span(),
        // output C
        c.d_j, c.v, c.rseed, c.auth_root, c.nk_tag, 0xBEEF,
        // output W
        w.d_j, w.v, w.rseed, w.auth_root, w.nk_tag, 0xCAFE,
    )
}
