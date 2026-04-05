/// Sparse Merkle tree helpers for witness generation.
///
/// These functions build a left-packed Merkle tree from a list of leaf
/// commitments, filling empty positions with level-specific "zero hashes".
/// They are used to construct Merkle authentication paths for the prover's
/// witness — they run inside the Cairo VM but are NOT part of the proven
/// circuit constraints. The actual Merkle verification is in merkle.cairo.
///
/// In production, the tree state lives on-chain or in an off-chain indexer.
/// These helpers simulate that for testing.

use starkprivacy::blake_hash::hash2;
use starkprivacy::merkle::TREE_DEPTH;

/// Compute the "zero hash" at each level of the tree.
///
/// z[0] = 0 (the empty leaf — no commitment occupies this slot)
/// z[i+1] = H(z[i], z[i])  (an internal node with two empty children)
///
/// Returns TREE_DEPTH + 1 elements: z[0] through z[TREE_DEPTH].
/// These are deterministic constants for a given hash function.
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
///
/// Given a list of leaf commitments (left-packed at positions 0..n-1),
/// builds the full sparse Merkle tree and extracts:
///   - `siblings`: the sibling hash at each of the TREE_DEPTH levels
///   - `path_indices`: the leaf index (encodes left/right turns as bits)
///   - `root`: the computed Merkle root
///
/// # How it works
///
/// We maintain a "current level" array, starting with the leaves.
/// At each level:
///   1. Look up the sibling of the tracked node (real if it exists, else zero_hash).
///   2. Build the next level by hashing consecutive pairs (padding with zero_hash).
///   3. Divide the tracked index by 2 to move up.
///
/// After TREE_DEPTH levels, `current` contains a single element: the root.
pub fn auth_path(
    leaves: Span<felt252>,
    index: u32,
    zero_hashes: Span<felt252>,
) -> (Array<felt252>, u64, felt252) {
    assert(leaves.len() > 0, 'empty tree');
    assert(index < leaves.len(), 'index out of range');

    // Copy leaves into a mutable working array.
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

        // The sibling is the node at idx XOR 1 (flip the lowest bit).
        // If that position is beyond the real nodes, use the zero hash
        // for this level (represents an empty subtree).
        let sibling_idx = idx ^ 1;
        let sibling = if sibling_idx < len {
            *current.at(sibling_idx)
        } else {
            *zero_hashes.at(level)
        };
        siblings.append(sibling);

        // Build the next level: hash consecutive pairs. If the last node
        // has no partner (odd count), pair it with the zero hash.
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
        idx = idx / 2; // Move up: parent index = child index / 2
        level += 1;
    };

    let root = *current.at(0);
    // path_indices is simply the leaf index — its binary representation
    // encodes the left/right decisions at each level.
    let path_indices: u64 = index.into();
    (siblings, path_indices, root)
}
