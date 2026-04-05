/// Test executable: Shield 1000 to Alice (note A, index 0).
///
/// The proof outputs [v_pub, cm_new, ak, sender]. The contract verifies
/// the STARK proof and a signature over the outputs under ak.
///
/// Tree state: [] → [cm_a]

use starkprivacy::{common, shield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let sender: felt252 = 0xA11CE_ADD8;
    shield::verify(a.v, a.cm, a.ak, sender, a.pk, a.rho, a.r)
}
