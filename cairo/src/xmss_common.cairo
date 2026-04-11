use tzel::blake_hash as hash;
use tzel::merkle;

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
    tag
        + (key_idx.into()) * POW64
        + (a.into()) * POW96
        + (b.into()) * POW128
        + (c.into()) * POW160
}

pub fn xmss_chain_step(
    x: felt252, pub_seed: felt252, key_idx: u32, chain_idx: u32, step: u32
) -> felt252 {
    let adrs = pack_adrs(TAG_XMSS_CHAIN, key_idx, chain_idx, step, 0);
    hash::hash3_generic(pub_seed, adrs, x)
}

pub fn xmss_recover_pk(
    sighash: felt252, pub_seed: felt252, key_idx: u32, wots_sig: Span<felt252>
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
        };
        recovered_pk.append(current);
        j += 1;
    };
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

fn xmss_ltree_level(
    pub_seed: felt252, key_idx: u32, nodes: Span<felt252>, level: u32
) -> felt252 {
    if nodes.len() == 1 {
        return *nodes.at(0);
    };

    let mut next: Array<felt252> = array![];
    let mut i: u32 = 0;
    let mut node_idx: u32 = 0;
    while i < nodes.len() {
        if i + 1 == nodes.len() {
            next.append(*nodes.at(i));
            i += 1;
        } else {
            next.append(xmss_node_hash(
                pub_seed,
                TAG_XMSS_LTREE,
                key_idx,
                level,
                node_idx,
                *nodes.at(i),
                *nodes.at(i + 1),
            ));
            i += 2;
            node_idx += 1;
        };
    };
    xmss_ltree_level(pub_seed, key_idx, next.span(), level + 1)
}

pub fn xmss_ltree(pub_seed: felt252, key_idx: u32, nodes: Span<felt252>) -> felt252 {
    xmss_ltree_level(pub_seed, key_idx, nodes, 0)
}

pub fn xmss_verify_auth(
    leaf: felt252, auth_root: felt252, pub_seed: felt252, key_idx: u32, siblings: Span<felt252>
) {
    assert(siblings.len() == merkle::AUTH_DEPTH, 'xmss auth path length');
    let mut current = leaf;
    let mut idx = key_idx;
    let mut level: u32 = 0;
    while level < merkle::AUTH_DEPTH {
        let sibling = *siblings.at(level);
        let node_idx = idx / 2;
        current = if idx & 1 == 1 {
            xmss_node_hash(pub_seed, TAG_XMSS_TREE, 0, level, node_idx, sibling, current)
        } else {
            xmss_node_hash(pub_seed, TAG_XMSS_TREE, 0, level, node_idx, current, sibling)
        };
        idx = idx / 2;
        level += 1;
    };
    assert(idx == 0, 'xmss key idx out of range');
    assert(current == auth_root, 'xmss auth root mismatch');
}
