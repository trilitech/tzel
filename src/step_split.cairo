/// Test executable: Split C(1500) + Z(0) → D(800) + E(700).
///
/// Bob splits his 1500-value note C into two:
///   - D(800) back to Alice
///   - E(700) to himself
///
/// The second input Z is a zero-value dummy note (shielded in step_join)
/// consumed to fill the 2-input slot. Its nullifier is still added to
/// NF_set — each dummy can only be "spent" once.
///
/// Tree state: [cm_a, cm_b, cm_z, cm_c, cm_w] → adds [cm_d, cm_e]

use starkprivacy::blake_hash as hash;
use starkprivacy::{common, transfer, tree};

#[executable]
fn main() -> Array<felt252> {
    // Reconstruct all prior notes to build the tree at this point.
    let a = common::note_a();
    let b = common::note_b();
    let z = common::note_z();
    let c = common::note_c();
    let w = common::note_w();
    let d = common::note_d();
    let e = common::note_e();

    // Build the tree with all 5 prior commitments and get paths for C and Z.
    let zh = tree::zero_hashes();
    let leaves: Array<felt252> = array![a.cm, b.cm, z.cm, c.cm, w.cm];
    let (sib_c, idx_c, root) = tree::auth_path(leaves.span(), 3, zh.span()); // C is at index 3
    let (sib_z, idx_z, _) = tree::auth_path(leaves.span(), 2, zh.span());   // Z is at index 2

    // Run the transfer circuit:
    //   Inputs:  C(1500, Bob) + Z(0, dummy) = 1500
    //   Outputs: D(800, Alice) + E(700, Bob) = 1500
    transfer::verify(
        root,
        hash::nullifier(c.sk, c.rho), // nf_c — Bob's note consumed
        hash::nullifier(z.sk, z.rho), // nf_z — dummy consumed
        d.cm, e.cm,                   // output commitments
        // spent note C witness (Bob's 1500)
        c.sk, c.v, c.rho, c.r, sib_c.span(), idx_c,
        // spent note Z witness (dummy 0)
        z.sk, z.v, z.rho, z.r, sib_z.span(), idx_z,
        // new note D (800 to Alice)
        d.pk, d.v, d.rho, d.r,
        // new note E (700 to Bob)
        e.pk, e.v, e.rho, e.r,
    )
}
