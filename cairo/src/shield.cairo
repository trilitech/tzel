/// Shield circuit: deposit public tokens into a private note.
///
/// # Public outputs
///   [v_pub, cm_new, sender, memo_ct_hash]
///
/// # Constraint
///   owner_tag = H_owner(auth_root, nk_tag)
///   rcm = H("rcm", rseed)
///   cm_new = H_commit(d_j, v_pub, rcm, owner_tag)
///
/// auth_root and nk_tag come from the recipient's payment address.
/// Neither appears in public outputs — they are private inputs.
/// Shield requires no spend authorization (sender authenticated by msg.sender).

use tzel::blake_hash as hash;

pub fn verify(
    v_pub: u64,
    cm_new: felt252,
    sender: felt252,
    memo_ct_hash: felt252,
    // private inputs
    auth_root: felt252,
    nk_tag: felt252,
    d_j: felt252,
    rseed: felt252,
) -> Array<felt252> {
    let otag = hash::owner_tag(auth_root, nk_tag);
    let rcm = hash::derive_rcm(rseed);
    assert(hash::commit(d_j, v_pub, rcm, otag) == cm_new, 'shield: bad commitment');

    array![v_pub.into(), cm_new, sender, memo_ct_hash]
}
