/// Step 4: Split C(1500) + Z(0) → D(800) + E(700).
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

    // Build tree with all prior commitments
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm, c.cm, w.cm];

    let (sib_c, idx_c, root) = tree::auth_path(leaves.span(), 3, zh.span());
    let (sib_z, idx_z, _) = tree::auth_path(leaves.span(), 2, zh.span());

    transfer::verify(
        root,
        hash::nullifier(c.sk, c.rho),
        hash::nullifier(z.sk, z.rho),
        d.cm, e.cm,
        c.sk, c.v, c.rho, c.r, sib_c.span(), idx_c,
        z.sk, z.v, z.rho, z.r, sib_z.span(), idx_z,
        d.pk, d.v, d.rho, d.r,
        e.pk, e.v, e.rho, e.r,
    )
}
