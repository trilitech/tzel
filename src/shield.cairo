/// Shield circuit: deposit public tokens into a private note.
///
/// # Public outputs
///   [v_pub, cm_new, ak, sender, memo_ct_hash]
///
/// # Constraint
///   owner_tag = H_owner(ak, nk_tag)
///   rcm = H("rcm", rseed)
///   cm_new = H_commit(d_j, v_pub, rcm, owner_tag)
///
/// The sender computes nk_tag from the payment address and provides it.
/// The commitment binds to both ak and nk_tag via the owner tag.

use starkprivacy::blake_hash as hash;

pub fn verify(
    v_pub: u64,
    cm_new: felt252,
    ak: felt252,
    sender: felt252,
    memo_ct_hash: felt252,
    // private inputs
    nk_tag: felt252,
    d_j: felt252,
    rseed: felt252,
) -> Array<felt252> {
    let otag = hash::owner_tag(ak, nk_tag);
    let rcm = hash::derive_rcm(rseed);
    assert(hash::commit(d_j, v_pub, rcm, otag) == cm_new, 'shield: bad commitment');

    array![v_pub.into(), cm_new, ak, sender, memo_ct_hash]
}
