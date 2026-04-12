use tzel::{blake_hash as hash, merkle};

pub const WOTS_W: u32 = 4;
pub const WOTS_CHAINS: u32 = 133;

const POW64: felt252 = 0x10000000000000000;
const POW96: felt252 = 0x1000000000000000000000000;
const POW128: felt252 = 0x100000000000000000000000000000000;
const POW160: felt252 = 0x10000000000000000000000000000000000000000;

const TAG_XMSS_CHAIN: felt252 = 0x68632D73736D78;
const TAG_XMSS_LTREE: felt252 = 0x746C2D73736D78;
const TAG_XMSS_TREE: felt252 = 0x72742D73736D78;

pub fn pack_adrs(tag: felt252, key_idx: u32, a: u32, b: u32, c: u32) -> felt252 {
    tag + (key_idx.into()) * POW64 + (a.into()) * POW96 + (b.into()) * POW128 + (c.into()) * POW160
}

pub fn xmss_chain_step(
    x: felt252, pub_seed: felt252, key_idx: u32, chain_idx: u32, step: u32,
) -> felt252 {
    let adrs = pack_adrs(TAG_XMSS_CHAIN, key_idx, chain_idx, step, 0);
    hash::hash3_generic(pub_seed, adrs, x)
}

pub fn xmss_recover_pk(
    sighash: felt252, pub_seed: felt252, key_idx: u32, wots_sig: Span<felt252>,
) -> Array<felt252> {
    let digits = hash::sighash_to_wots_digits(sighash);
    let mut recovered_pk: Array<felt252> = array![];
    let mut j: u32 = 0;
    while j < WOTS_CHAINS {
        let digit = *digits.at(j);
        let mut current = *wots_sig.at(j);
        let mut step = digit;
        while step < WOTS_W - 1 {
            current = xmss_chain_step(current, pub_seed, key_idx, j, step);
            step += 1;
        }
        recovered_pk.append(current);
        j += 1;
    }
    recovered_pk
}

pub fn xmss_node_hash(
    pub_seed: felt252,
    tag: felt252,
    key_idx: u32,
    level: u32,
    node_idx: u32,
    left: felt252,
    right: felt252,
) -> felt252 {
    let adrs = pack_adrs(tag, key_idx, level, node_idx, 0);
    hash::hash4_generic(pub_seed, adrs, left, right)
}

fn xmss_ltree_level(pub_seed: felt252, key_idx: u32, nodes: Span<felt252>, level: u32) -> felt252 {
    if nodes.len() == 1 {
        return *nodes.at(0);
    }

    let mut next: Array<felt252> = array![];
    let mut i: u32 = 0;
    let mut node_idx: u32 = 0;
    while i < nodes.len() {
        if i + 1 == nodes.len() {
            next.append(*nodes.at(i));
            i += 1;
        } else {
            next
                .append(
                    xmss_node_hash(
                        pub_seed,
                        TAG_XMSS_LTREE,
                        key_idx,
                        level,
                        node_idx,
                        *nodes.at(i),
                        *nodes.at(i + 1),
                    ),
                );
            i += 2;
            node_idx += 1;
        };
    }
    xmss_ltree_level(pub_seed, key_idx, next.span(), level + 1)
}

pub fn xmss_ltree(pub_seed: felt252, key_idx: u32, nodes: Span<felt252>) -> felt252 {
    xmss_ltree_level(pub_seed, key_idx, nodes, 0)
}

pub fn xmss_verify_auth(
    leaf: felt252, auth_root: felt252, pub_seed: felt252, key_idx: u32, siblings: Span<felt252>,
) {
    assert(siblings.len() == merkle::AUTH_DEPTH, 'xmss auth path length');
    let mut current = leaf;
    let mut idx = key_idx;
    let mut level: u32 = 0;
    while level < merkle::AUTH_DEPTH {
        let sibling = *siblings.at(level);
        let node_idx = idx / 2;
        current =
            if idx & 1 == 1 {
                xmss_node_hash(pub_seed, TAG_XMSS_TREE, 0, level, node_idx, sibling, current)
            } else {
                xmss_node_hash(pub_seed, TAG_XMSS_TREE, 0, level, node_idx, current, sibling)
            };
        idx = idx / 2;
        level += 1;
    }
    assert(idx == 0, 'xmss key idx out of range');
    assert(current == auth_root, 'xmss auth root mismatch');
}

#[cfg(test)]
mod tests {
    use tzel::{blake_hash as hash, merkle};
    use super::{
        POW128, POW160, POW64, POW96, TAG_XMSS_LTREE, TAG_XMSS_TREE, WOTS_CHAINS, WOTS_W, pack_adrs,
        xmss_chain_step, xmss_ltree, xmss_recover_pk, xmss_verify_auth,
    };

    #[derive(Drop)]
    struct XmssFixture {
        sighash: felt252,
        pub_seed: felt252,
        key_idx: u32,
        wots_sig: Array<felt252>,
        siblings: Array<felt252>,
        auth_root: felt252,
    }

    fn zero_siblings(depth: u32) -> Array<felt252> {
        let mut siblings: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < depth {
            siblings.append(0);
            i += 1;
        }
        siblings
    }

    fn one_shifted_by(depth: u32) -> u32 {
        let mut value: u32 = 1;
        let mut i: u32 = 0;
        while i < depth {
            value *= 2;
            i += 1;
        }
        value
    }

    fn copy_and_mutate(values: Span<felt252>, target: u32) -> Array<felt252> {
        let mut mutated: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < values.len() {
            mutated.append(if i == target {
                *values.at(i) + 1
            } else {
                *values.at(i)
            });
            i += 1;
        }
        mutated
    }

    fn ref_pack_adrs(tag: felt252, key_idx: u32, a: u32, b: u32, c: u32) -> felt252 {
        tag
            + (key_idx.into()) * POW64
            + (a.into()) * POW96
            + (b.into()) * POW128
            + (c.into()) * POW160
    }

    fn ref_chain_step(
        x: felt252, pub_seed: felt252, key_idx: u32, chain_idx: u32, step: u32,
    ) -> felt252 {
        let adrs = ref_pack_adrs(super::TAG_XMSS_CHAIN, key_idx, chain_idx, step, 0);
        hash::hash3_generic(pub_seed, adrs, x)
    }

    fn ref_node_hash(
        pub_seed: felt252,
        tag: felt252,
        key_idx: u32,
        level: u32,
        node_idx: u32,
        left: felt252,
        right: felt252,
    ) -> felt252 {
        let adrs = ref_pack_adrs(tag, key_idx, level, node_idx, 0);
        hash::hash4_generic(pub_seed, adrs, left, right)
    }

    fn ref_ltree_level(
        pub_seed: felt252, key_idx: u32, nodes: Span<felt252>, level: u32,
    ) -> felt252 {
        if nodes.len() == 1 {
            return *nodes.at(0);
        }

        let mut next: Array<felt252> = array![];
        let mut i: u32 = 0;
        let mut node_idx: u32 = 0;
        while i < nodes.len() {
            if i + 1 == nodes.len() {
                next.append(*nodes.at(i));
                i += 1;
            } else {
                next
                    .append(
                        ref_node_hash(
                            pub_seed,
                            TAG_XMSS_LTREE,
                            key_idx,
                            level,
                            node_idx,
                            *nodes.at(i),
                            *nodes.at(i + 1),
                        ),
                    );
                i += 2;
                node_idx += 1;
            }
        }
        ref_ltree_level(pub_seed, key_idx, next.span(), level + 1)
    }

    fn ref_ltree(pub_seed: felt252, key_idx: u32, nodes: Span<felt252>) -> felt252 {
        ref_ltree_level(pub_seed, key_idx, nodes, 0)
    }

    fn ref_root_from_auth_path(
        leaf: felt252, pub_seed: felt252, mut key_idx: u32, siblings: Span<felt252>,
    ) -> felt252 {
        let mut current = leaf;
        let mut level: u32 = 0;
        while level < merkle::AUTH_DEPTH {
            let sibling = *siblings.at(level);
            let node_idx = key_idx / 2;
            current =
                if key_idx & 1 == 1 {
                    ref_node_hash(pub_seed, TAG_XMSS_TREE, 0, level, node_idx, sibling, current)
                } else {
                    ref_node_hash(pub_seed, TAG_XMSS_TREE, 0, level, node_idx, current, sibling)
                };
            key_idx /= 2;
            level += 1;
        }
        current
    }

    fn root_from_signature_inputs(
        sighash: felt252,
        pub_seed: felt252,
        key_idx: u32,
        wots_sig: Span<felt252>,
        siblings: Span<felt252>,
    ) -> felt252 {
        let recovered_pk = xmss_recover_pk(sighash, pub_seed, key_idx, wots_sig);
        let leaf = xmss_ltree(pub_seed, key_idx, recovered_pk.span());
        ref_root_from_auth_path(leaf, pub_seed, key_idx, siblings)
    }

    fn verify_signature_inputs(
        sighash: felt252,
        pub_seed: felt252,
        key_idx: u32,
        wots_sig: Span<felt252>,
        siblings: Span<felt252>,
        auth_root: felt252,
    ) {
        let recovered_pk = xmss_recover_pk(sighash, pub_seed, key_idx, wots_sig);
        let leaf = xmss_ltree(pub_seed, key_idx, recovered_pk.span());
        xmss_verify_auth(leaf, auth_root, pub_seed, key_idx, siblings);
    }

    fn build_valid_fixture() -> XmssFixture {
        let sighash = 0x123456789ABCD;
        let pub_seed = 0x9876543210FED;
        let key_idx = 11_u32;

        let digits = hash::sighash_to_wots_digits(sighash);
        let mut wots_sig: Array<felt252> = array![];
        let mut recovered_pk: Array<felt252> = array![];
        let mut j: u32 = 0;
        while j < WOTS_CHAINS {
            let mut current = hash::hash1(j.into() + 0xA500);
            let digit = *digits.at(j);
            let mut step: u32 = 0;
            while step < digit {
                current = ref_chain_step(current, pub_seed, key_idx, j, step);
                step += 1;
            }
            wots_sig.append(current);
            while step < WOTS_W - 1 {
                current = ref_chain_step(current, pub_seed, key_idx, j, step);
                step += 1;
            }
            recovered_pk.append(current);
            j += 1;
        }

        let leaf = ref_ltree(pub_seed, key_idx, recovered_pk.span());
        let mut siblings: Array<felt252> = array![];
        let mut level: u32 = 0;
        while level < merkle::AUTH_DEPTH {
            siblings.append(hash::hash1(level.into() + 0xB700));
            level += 1;
        }

        let auth_root = ref_root_from_auth_path(leaf, pub_seed, key_idx, siblings.span());
        XmssFixture { sighash, pub_seed, key_idx, wots_sig, siblings, auth_root }
    }

    #[test]
    fn test_pack_adrs_layout() {
        let tag = 7;
        let key_idx = 11_u32;
        let a = 13_u32;
        let b = 17_u32;
        let c = 19_u32;
        let expected = tag
            + key_idx.into() * POW64
            + a.into() * POW96
            + b.into() * POW128
            + c.into() * POW160;
        assert(pack_adrs(tag, key_idx, a, b, c) == expected, 'pack adrs');
    }

    #[test]
    fn test_xmss_chain_step_domain_separated_by_adrs() {
        let x = 0x1234;
        let pub_seed = 0x5678;
        let base = xmss_chain_step(x, pub_seed, 9, 3, 1);
        assert(base != xmss_chain_step(x, pub_seed, 10, 3, 1), 'key idx');
        assert(base != xmss_chain_step(x, pub_seed, 9, 4, 1), 'chain idx');
        assert(base != xmss_chain_step(x, pub_seed, 9, 3, 2), 'step');
    }

    #[test]
    fn test_xmss_ltree_handles_odd_number_of_nodes() {
        let pub_seed = 0xA1;
        let key_idx = 7_u32;
        let nodes: Array<felt252> = array![0x11, 0x22, 0x33];

        let level0 = ref_node_hash(pub_seed, TAG_XMSS_LTREE, key_idx, 0, 0, 0x11, 0x22);
        let expected = ref_node_hash(pub_seed, TAG_XMSS_LTREE, key_idx, 1, 0, level0, 0x33);

        assert(xmss_ltree(pub_seed, key_idx, nodes.span()) == expected, 'odd ltree');
    }

    #[test]
    fn test_xmss_verify_auth_accepts_valid_path() {
        let leaf = 0x9876;
        let pub_seed = 0x1111;
        let key_idx = 5_u32;
        let siblings = zero_siblings(merkle::AUTH_DEPTH);
        let root = ref_root_from_auth_path(leaf, pub_seed, key_idx, siblings.span());

        xmss_verify_auth(leaf, root, pub_seed, key_idx, siblings.span());
    }

    #[test]
    #[should_panic(expected: ('xmss key idx out of range',))]
    fn test_xmss_verify_auth_rejects_out_of_range_key_idx() {
        let leaf = 0x5555;
        let pub_seed = 0xAAAA;
        let siblings = zero_siblings(merkle::AUTH_DEPTH);
        let root = ref_root_from_auth_path(leaf, pub_seed, 0, siblings.span());

        xmss_verify_auth(leaf, root, pub_seed, one_shifted_by(merkle::AUTH_DEPTH), siblings.span());
    }

    #[test]
    fn test_xmss_signature_roundtrip_accepts_valid_witness() {
        let fixture = build_valid_fixture();
        verify_signature_inputs(
            fixture.sighash,
            fixture.pub_seed,
            fixture.key_idx,
            fixture.wots_sig.span(),
            fixture.siblings.span(),
            fixture.auth_root,
        );
    }

    #[test]
    fn test_every_wots_chain_element_is_bound_into_authenticated_root() {
        let fixture = build_valid_fixture();
        let mut j: u32 = 0;
        while j < WOTS_CHAINS {
            let mutated_wots_sig = copy_and_mutate(fixture.wots_sig.span(), j);
            let mutated_root = root_from_signature_inputs(
                fixture.sighash,
                fixture.pub_seed,
                fixture.key_idx,
                mutated_wots_sig.span(),
                fixture.siblings.span(),
            );
            assert(mutated_root != fixture.auth_root, 'wots mutation escaped');
            j += 1;
        }
    }

    #[test]
    fn test_every_auth_sibling_is_bound_into_authenticated_root() {
        let fixture = build_valid_fixture();
        let mut level: u32 = 0;
        while level < merkle::AUTH_DEPTH {
            let mutated_siblings = copy_and_mutate(fixture.siblings.span(), level);
            let mutated_root = root_from_signature_inputs(
                fixture.sighash,
                fixture.pub_seed,
                fixture.key_idx,
                fixture.wots_sig.span(),
                mutated_siblings.span(),
            );
            assert(mutated_root != fixture.auth_root, 'auth sibling mutation escaped');
            level += 1;
        }
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_xmss_signature_rejects_mutated_signature_element() {
        let fixture = build_valid_fixture();
        let mutated_wots_sig = copy_and_mutate(fixture.wots_sig.span(), 17);
        verify_signature_inputs(
            fixture.sighash,
            fixture.pub_seed,
            fixture.key_idx,
            mutated_wots_sig.span(),
            fixture.siblings.span(),
            fixture.auth_root,
        );
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_xmss_signature_rejects_mutated_auth_sibling() {
        let fixture = build_valid_fixture();
        let mutated_siblings = copy_and_mutate(fixture.siblings.span(), 4);
        verify_signature_inputs(
            fixture.sighash,
            fixture.pub_seed,
            fixture.key_idx,
            fixture.wots_sig.span(),
            mutated_siblings.span(),
            fixture.auth_root,
        );
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_xmss_signature_rejects_mutated_sighash() {
        let fixture = build_valid_fixture();
        verify_signature_inputs(
            fixture.sighash + 1,
            fixture.pub_seed,
            fixture.key_idx,
            fixture.wots_sig.span(),
            fixture.siblings.span(),
            fixture.auth_root,
        );
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_xmss_signature_rejects_mutated_pub_seed() {
        let fixture = build_valid_fixture();
        verify_signature_inputs(
            fixture.sighash,
            fixture.pub_seed + 1,
            fixture.key_idx,
            fixture.wots_sig.span(),
            fixture.siblings.span(),
            fixture.auth_root,
        );
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_xmss_signature_rejects_mutated_key_idx() {
        let fixture = build_valid_fixture();
        verify_signature_inputs(
            fixture.sighash,
            fixture.pub_seed,
            fixture.key_idx ^ 1,
            fixture.wots_sig.span(),
            fixture.siblings.span(),
            fixture.auth_root,
        );
    }

    #[test]
    #[should_panic(expected: ('xmss auth root mismatch',))]
    fn test_xmss_signature_rejects_mutated_auth_root() {
        let fixture = build_valid_fixture();
        verify_signature_inputs(
            fixture.sighash,
            fixture.pub_seed,
            fixture.key_idx,
            fixture.wots_sig.span(),
            fixture.siblings.span(),
            fixture.auth_root + 1,
        );
    }
}
