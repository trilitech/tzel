/// Test executable: Join A(1000) + B(500) → C(1500) + W(0).
///
/// The proof outputs [root, nf_a, nf_b, cm_c, cm_w, ak_a, ak_b].
/// The contract verifies signatures under both ak_a and ak_b, ensuring
/// both input note owners authorized the spend.
///
/// Tree state: [cm_a, cm_b, cm_z] → adds [cm_c, cm_w]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, shield, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let b = common::note_b();
    let z = common::note_z();
    let c = common::note_c();
    let w = common::note_w();

    // Shield the dummy note Z for later use in step_split.
    let sender: felt252 = 0xA11CE_ADD8;
    shield::verify(z.v, z.cm, z.ak, sender, z.pk, z.rho, z.r);

    // Build tree and Merkle paths.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm];
    let (sib_a, idx_a, root) = tree::auth_path(leaves.span(), 0, zh.span());
    let (sib_b, idx_b, _) = tree::auth_path(leaves.span(), 1, zh.span());

    transfer::verify(
        root,
        hash::nullifier(a.nsk, a.rho),
        hash::nullifier(b.nsk, b.rho),
        c.cm, w.cm,
        a.nsk, a.ak, a.v, a.rho, a.r, sib_a.span(), idx_a,
        b.nsk, b.ak, b.v, b.rho, b.r, sib_b.span(), idx_b,
        c.pk, c.ak, c.v, c.rho, c.r,
        w.pk, w.ak, w.v, w.rho, w.r,
    )
}
