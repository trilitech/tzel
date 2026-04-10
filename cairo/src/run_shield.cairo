/// Parameterized shield executable — takes witness data as input.
/// Arguments (flattened felt252 array):
///   [v_pub, cm_new, sender, memo_ct_hash, auth_root, nk_tag, d_j, rseed]

use tzel::shield;

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    assert(args.len() == 8, 'shield: need 8 args');
    let v_pub: u64 = (*args.at(0)).try_into().unwrap();
    let cm_new = *args.at(1);
    let sender = *args.at(2);
    let memo_ct_hash = *args.at(3);
    let auth_root = *args.at(4);
    let nk_tag = *args.at(5);
    let d_j = *args.at(6);
    let rseed = *args.at(7);
    shield::verify(v_pub, cm_new, sender, memo_ct_hash, auth_root, nk_tag, d_j, rseed)
}
