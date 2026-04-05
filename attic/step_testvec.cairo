/// Emit test vectors for cross-implementation key derivation checks.
/// master_sk = 0xA11CE, index = 0 → note_a's keys.

use starkprivacy::common;

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    // Output every derived value so the Rust demo can compare.
    array![a.nsk, a.pk, a.ak, a.cm, a.rho, a.r, a.v.into()]
}
