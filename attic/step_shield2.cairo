/// Step 2: Shield 500 to Alice.
/// Tree: [cm_a] → [cm_a, cm_b]

use starkprivacy::{common, shield};

#[executable]
fn main() {
    let b = common::note_b();
    shield::verify(b.v, b.cm, b.pk, b.rho, b.r);
}
