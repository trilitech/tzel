/// Test: Split C(1500) -> D(800) + E(700) using N=1 transfer.
/// Tree: [cm_a, cm_b, cm_z, cm_c, cm_w]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    let (a, _ai_a) = common::note_a();
    let (b, _ai_b) = common::note_b();
    let (z, _ai_z) = common::note_z();
    let (c, ai_c) = common::note_c();
    let (w, _ai_w) = common::note_w();
    let (d, _ai_d) = common::note_d();
    let (e, _ai_e) = common::note_e();

    // Build commitment tree and Merkle path for note C at index 3.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm, c.cm, w.cm];
    let (cm_sib_c, idx_c, root) = tree::auth_path(leaves.span(), 3, zh.span());

    // Auth tree path for the one-time key.
    let auth_sib_c = ai_c.auth_path;

    // Compute nullifier.
    let nf_c = hash::nullifier(c.nk_spend, c.cm, idx_c);

    // N=1: single input, no flattening needed.
    transfer::verify(
        root,
        array![nf_c].span(),
        d.cm, e.cm,
        array![c.nk_spend].span(),
        array![c.auth_root].span(),
        array![c.auth_leaf_hash].span(),
        auth_sib_c.span(),
        array![c.auth_key_idx.into()].span(),
        array![c.d_j].span(),
        array![c.v].span(),
        array![c.rseed].span(),
        cm_sib_c.span(),
        array![idx_c].span(),
        // output D
        d.d_j, d.v, d.rseed, d.auth_root, d.nk_tag, 0,
        // output E
        e.d_j, e.v, e.rseed, e.auth_root, e.nk_tag, 0,
    )
}
