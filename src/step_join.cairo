/// Test executable: Join A(1000) + B(500) → C(1500) + W(0).
///
/// This is a "merge" operation: Alice combines two notes into one note
/// for Bob (1500) plus a zero-value waste output W.
///
/// The step also proves a Shield for dummy note Z (v=0), which will be
/// needed as the second input in step_split. In a real system, Z would
/// have been shielded in a separate transaction.
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

    // Shield the dummy note Z (v=0) so it exists in the tree for step_split.
    let sender: felt252 = 0xA11CE_ADD8;
    shield::verify(z.v, z.cm, sender, z.pk, z.rho, z.r);

    // Build the tree containing A, B, Z and compute Merkle paths for A and B.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm];
    let (sib_a, idx_a, root) = tree::auth_path(leaves.span(), 0, zh.span());
    let (sib_b, idx_b, _) = tree::auth_path(leaves.span(), 1, zh.span());

    // Run the transfer circuit:
    //   Inputs:  A(1000, Alice) + B(500, Alice) = 1500
    //   Outputs: C(1500, Bob) + W(0, dummy)     = 1500
    transfer::verify(
        root,
        hash::nullifier(a.sk, a.rho), // nf_a — will be added to NF_set
        hash::nullifier(b.sk, b.rho), // nf_b — will be added to NF_set
        c.cm, w.cm,                   // output commitments — appended to T
        // spent note A witness
        a.sk, a.v, a.rho, a.r, sib_a.span(), idx_a,
        // spent note B witness
        b.sk, b.v, b.rho, b.r, sib_b.span(), idx_b,
        // new note C (1500 to Bob)
        c.pk, c.v, c.rho, c.r,
        // new note W (0 waste)
        w.pk, w.v, w.rho, w.r,
    )
}
