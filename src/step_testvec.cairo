/// Output test vectors for cross-implementation testing.
/// Outputs: nk, d_j, nk_spend, nk_tag, auth_root, cm, nf (for note_a at position 0).

use starkprivacy::blake_hash as hash;
use starkprivacy::common;

#[executable]
fn main() -> Array<felt252> {
    let acc = common::alice_account();
    let d_j = common::alice_addr_0();
    let (nk_spend, nk_tag) = common::derive_nk_keys(acc.nk, d_j);
    let (a, _ai_a) = common::note_a();
    // nf at position 0
    let nf = hash::nullifier(nk_spend, a.cm, 0);

    // Return: nk, d_j, nk_spend, nk_tag, auth_root, cm, nf
    array![acc.nk, d_j, nk_spend, nk_tag, a.auth_root, a.cm, nf]
}
