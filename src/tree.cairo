/// Sparse Merkle tree helpers for witness generation.
///
/// Builds a left-packed tree: leaves occupy positions 0..n-1, the rest are
/// filled with level-specific zero hashes.  Only used for testing / witness
/// construction — not part of the proven circuits.

use starkprivacy::blake_hash::hash2;
use starkprivacy::merkle::TREE_DEPTH;

/// Compute zero hashes: z[0] = 0 (empty leaf), z[i+1] = H(z[i], z[i]).
/// Returns TREE_DEPTH + 1 elements.
pub fn zero_hashes() -> Array<felt252> {
    let mut z: Array<felt252> = array![];
    z.append(0);
    let mut i: u32 = 0;
    while i < TREE_DEPTH {
        let prev = *z.at(i);
        z.append(hash2(prev, prev));
        i += 1;
    };
    z
}

/// Compute a Merkle authentication path for the leaf at `index`.
/// Returns (siblings, path_indices, root).
pub fn auth_path(
    leaves: Span<felt252>,
    index: u32,
    zero_hashes: Span<felt252>,
) -> (Array<felt252>, u64, felt252) {
    assert(leaves.len() > 0, 'empty tree');
    assert(index < leaves.len(), 'index out of range');

    // Copy leaves into working array
    let mut current: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i < leaves.len() {
        current.append(*leaves.at(i));
        i += 1;
    };

    let mut siblings: Array<felt252> = array![];
    let mut idx: u32 = index;
    let mut level: u32 = 0;

    while level < TREE_DEPTH {
        let len = current.len();

        // Sibling: real node if it exists, otherwise zero hash for this level
        let sibling_idx = idx ^ 1;
        let sibling = if sibling_idx < len {
            *current.at(sibling_idx)
        } else {
            *zero_hashes.at(level)
        };
        siblings.append(sibling);

        // Build the next level up
        let mut next: Array<felt252> = array![];
        let mut j: u32 = 0;
        while j < len {
            let left = *current.at(j);
            let right = if j + 1 < len {
                *current.at(j + 1)
            } else {
                *zero_hashes.at(level)
            };
            next.append(hash2(left, right));
            j += 2;
        };

        current = next;
        idx = idx / 2;
        level += 1;
    };

    let root = *current.at(0);
    let path_indices: u64 = index.into();
    (siblings, path_indices, root)
}
