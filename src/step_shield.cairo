/// Test: Shield 1000 to Alice at address 0.
/// Tree: [] -> [cm_a]

use starkprivacy::{common, shield};

#[executable]
fn main() -> Array<felt252> {
    let (a, _ai_a) = common::note_a();
    let sender: felt252 = 0xA11CE_ADD8;
    let memo_ct_hash: felt252 = 0xDEAD;
    shield::verify(a.v, a.cm, sender, memo_ct_hash, a.auth_root, a.nk_tag, a.d_j, a.rseed)
}
