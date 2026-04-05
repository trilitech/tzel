/// Step 3: Join A(1000) + B(500) → C(1500) + W(0).
/// Tree: [cm_a, cm_b, cm_z] (includes dummy shield for later split)

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, shield, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let b = common::note_b();
    let z = common::note_z();
    let c = common::note_c();
    let w = common::note_w();

    // Also prove the dummy shield (needed for split input later)
    shield::verify(z.v, z.cm, z.pk, z.rho, z.r);

    // Build tree and Merkle paths
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm];

    let (sib_a, idx_a, root) = tree::auth_path(leaves.span(), 0, zh.span());
    let (sib_b, idx_b, _) = tree::auth_path(leaves.span(), 1, zh.span());

    transfer::verify(
        root,
        hash::nullifier(a.sk, a.rho),
        hash::nullifier(b.sk, b.rho),
        c.cm, w.cm,
        a.sk, a.v, a.rho, a.r, sib_a.span(), idx_a,
        b.sk, b.v, b.rho, b.r, sib_b.span(), idx_b,
        c.pk, c.v, c.rho, c.r,
        w.pk, w.v, w.rho, w.r,
    )
}
