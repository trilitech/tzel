/// Test executable: Shield 1000 to Alice.
///
/// Proves that cm_a is a valid commitment to (pk_alice, 1000, rho, r).
/// The on-chain effect would be: deduct 1000 from sender, append cm_a to T.
///
/// Tree state: [] → [cm_a]

use starkprivacy::{common, shield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let sender: felt252 = 0xA11CE_ADD8; // Alice's public address (test value)
    shield::verify(a.v, a.cm, sender, a.pk, a.rho, a.r)
}
