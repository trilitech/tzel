/// Test: Split C(1500) → D(800) + E(700) using N=1 transfer.
/// Tree: [cm_a, cm_b, cm_z, cm_c, cm_w]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let b = common::note_b();
    let z = common::note_z();
    let c = common::note_c();
    let w = common::note_w();
    let d = common::note_d();
    let e = common::note_e();

    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm, c.cm, w.cm];
    let (sib_c, idx_c, root) = tree::auth_path(leaves.span(), 3, zh.span());

    let (_, ak_c) = common::derive_ask(common::bob_account().ask_base, 0);
    let nf_c = hash::nullifier(c.nk_spend, c.cm, idx_c);

    // N=1: single input, no dummies needed.
    transfer::verify(
        root,
        array![nf_c].span(),
        d.cm, e.cm,
        array![c.nk_spend].span(),
        array![ak_c].span(),
        array![c.d_j].span(),
        array![c.v].span(),
        array![c.rseed].span(),
        sib_c.span(),
        array![idx_c].span(),
        d.d_j, d.v, d.rseed, d.ak, d.nk_tag, 0,
        e.d_j, e.v, e.rseed, e.ak, e.nk_tag, 0,
    )
}
