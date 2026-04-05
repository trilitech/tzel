/// Step 1: Shield 1000 to Alice.
/// Tree: [] → [cm_a]

use starkprivacy::{common, shield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    shield::verify(a.v, a.cm, a.pk, a.rho, a.r)
}
