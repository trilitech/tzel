/// Parameterized shield executable — takes witness data as input.
/// Arguments (flattened felt252 array):
///   [v_pub, cm_new, sender, memo_ct_hash, auth_root, auth_pub_seed, nk_tag, d_j, rseed]

use tzel::shield;

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    assert(args.len() == 9, 'shield: need 9 args');
    let v_pub: u64 = (*args.at(0)).try_into().unwrap();
    let cm_new = *args.at(1);
    let sender = *args.at(2);
    let memo_ct_hash = *args.at(3);
    let auth_root = *args.at(4);
    let auth_pub_seed = *args.at(5);
    let nk_tag = *args.at(6);
    let d_j = *args.at(7);
    let rseed = *args.at(8);
    shield::verify(v_pub, cm_new, sender, memo_ct_hash, auth_root, auth_pub_seed, nk_tag, d_j, rseed)
}
