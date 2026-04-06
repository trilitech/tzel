/// Test: Shield 1000 to Alice at address 0.
/// Tree: [] → [cm_a]

use starkprivacy::{common, shield};

#[executable]
fn main() -> Array<felt252> {
    let a = common::note_a();
    let (_, ak) = common::derive_ask(common::alice_account().ask_base, 0);
    let sender: felt252 = 0xA11CE_ADD8;
    let memo_ct_hash: felt252 = 0xDEAD;
    shield::verify(a.v, a.cm, ak, sender, memo_ct_hash, a.nk_tag, a.d_j, a.rseed)
}
