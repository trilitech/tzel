/// Merkle path verification for the commitment tree.

use starkprivacy::blake_hash::hash2;

/// Fixed depth of the commitment Merkle tree.
#[cfg(feature: 'depth16')]
pub const TREE_DEPTH: u32 = 16;
#[cfg(feature: 'depth32')]
pub const TREE_DEPTH: u32 = 32;
#[cfg(feature: 'depth48')]
pub const TREE_DEPTH: u32 = 48;

/// Assert that `leaf` belongs to a Merkle tree with the given `root`.
///
/// `siblings`: one sibling hash per level, ordered leaf-to-root.
/// `path_indices`: bitmask — bit i = 1 means the node is a right child at level i.
pub fn verify(leaf: felt252, root: felt252, siblings: Span<felt252>, path_indices: u64) {
    assert(siblings.len() == TREE_DEPTH, 'bad path length');

    let mut current = leaf;
    let mut idx = path_indices;
    let mut i: u32 = 0;

    while i < TREE_DEPTH {
        let sibling = *siblings.at(i);
        let bit = idx & 1;
        idx = idx / 2;

        current = if bit == 1 {
            hash2(sibling, current)
        } else {
            hash2(current, sibling)
        };

        i += 1;
    };

    assert(current == root, 'merkle root mismatch');
}
