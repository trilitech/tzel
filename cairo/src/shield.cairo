/// Shield circuit: deposit public tokens into a private note.
///
/// # Public outputs
///   [v_pub, cm_new, sender, memo_ct_hash]
///
/// # Constraint
///   owner_tag = H_owner(auth_root, auth_pub_seed, nk_tag)
///   rcm = H("rcm", rseed)
///   cm_new = H_commit(d_j, v_pub, rcm, owner_tag)
///
/// auth_root, auth_pub_seed, and nk_tag come from the recipient's payment address.
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
    auth_pub_seed: felt252,
    nk_tag: felt252,
    d_j: felt252,
    rseed: felt252,
) -> Array<felt252> {
    let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
    let rcm = hash::derive_rcm(rseed);
    assert(hash::commit(d_j, v_pub, rcm, otag) == cm_new, 'shield: bad commitment');

    array![v_pub.into(), cm_new, sender, memo_ct_hash]
}

#[cfg(test)]
mod tests {
    use tzel::blake_hash as hash;
    use super::verify;

    #[derive(Copy, Drop)]
    struct ShieldFixture {
        v_pub: u64,
        cm_new: felt252,
        sender: felt252,
        memo_ct_hash: felt252,
        auth_root: felt252,
        auth_pub_seed: felt252,
        nk_tag: felt252,
        d_j: felt252,
        rseed: felt252,
    }

    fn build_fixture() -> ShieldFixture {
        let v_pub = 19_u64;
        let sender = 0x1111;
        let memo_ct_hash = 0x2222;
        let auth_root = 0x3333;
        let auth_pub_seed = 0x4444;
        let nk_tag = 0x5555;
        let d_j = 0x6666;
        let rseed = 0x7777;
        let rcm = hash::derive_rcm(rseed);
        let otag = hash::owner_tag(auth_root, auth_pub_seed, nk_tag);
        let cm_new = hash::commit(d_j, v_pub, rcm, otag);

        ShieldFixture {
            v_pub, cm_new, sender, memo_ct_hash, auth_root, auth_pub_seed, nk_tag, d_j, rseed,
        }
    }

    #[test]
    fn test_shield_accepts_valid_statement() {
        let fixture = build_fixture();
        let outputs = verify(
            fixture.v_pub,
            fixture.cm_new,
            fixture.sender,
            fixture.memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
        );
        assert(outputs.len() == 4, 'shield outputs len');
        assert(*outputs.at(0) == fixture.v_pub.into(), 'shield out v');
        assert(*outputs.at(1) == fixture.cm_new, 'shield out cm');
        assert(*outputs.at(2) == fixture.sender, 'shield out sender');
        assert(*outputs.at(3) == fixture.memo_ct_hash, 'shield out memo');
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_commitment() {
        let fixture = build_fixture();
        verify(
            fixture.v_pub,
            fixture.cm_new + 1,
            fixture.sender,
            fixture.memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_owner_material() {
        let fixture = build_fixture();
        verify(
            fixture.v_pub,
            fixture.cm_new,
            fixture.sender,
            fixture.memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed + 1,
            fixture.nk_tag,
            fixture.d_j,
            fixture.rseed,
        );
    }

    #[test]
    #[should_panic(expected: ('shield: bad commitment',))]
    fn test_shield_rejects_mutated_note_body() {
        let fixture = build_fixture();
        verify(
            fixture.v_pub,
            fixture.cm_new,
            fixture.sender,
            fixture.memo_ct_hash,
            fixture.auth_root,
            fixture.auth_pub_seed,
            fixture.nk_tag,
            fixture.d_j + 1,
            fixture.rseed,
        );
    }
}
