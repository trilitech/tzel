/// Merkle path verification for the commitment tree.
///
/// The commitment tree T is a sparse Merkle tree of fixed depth. Every
/// note commitment is a leaf. Empty positions hold level-specific "zero
/// hashes" (see tree.cairo). The tree is append-only: new commitments
/// are added at the next available leaf position, and old roots remain
/// valid forever.
///
/// # Security argument
///
/// To forge a Merkle membership proof, an attacker would need to find a
/// collision in hash2 (BLAKE2s at 64 bytes), which has 2^125.5 collision
/// resistance after 251-bit truncation. The on-chain contract accepts any
/// historical root, so a proof against a stale root is fine — double-spend
/// is prevented by the global nullifier set, not by root freshness.

use tzel::blake_hash::hash2;

/// Fixed depth of the commitment Merkle tree.
///
/// Depth 48 supports 2^48 ≈ 281 trillion leaves — more than enough for
/// any realistic deployment. Smaller depths (16, 32) are available via
/// Scarb feature flags for faster testing.
#[cfg(feature: 'depth16')]
pub const TREE_DEPTH: u32 = 16;
#[cfg(feature: 'depth32')]
pub const TREE_DEPTH: u32 = 32;
#[cfg(feature: 'depth48')]
pub const TREE_DEPTH: u32 = 48;

/// Depth of the per-address auth key tree.
/// 2^16 = 65536 one-time signing keys per address.
pub const AUTH_DEPTH: u32 = 16;

/// Assert that `leaf` belongs to a Merkle tree with the given `root`.
///
/// # Arguments
/// - `leaf`: the commitment to prove membership for
/// - `root`: the expected Merkle root
/// - `siblings`: one sibling hash per level, ordered leaf-to-root
/// - `path_indices`: bitmask encoding left/right turns at each level;
///    bit i = 1 means the node is the RIGHT child at level i
///
/// # How it works
///
/// Starting from the leaf, we walk up the tree. At each level we combine
/// the current node with its sibling (in the correct left/right order,
/// determined by the bit in path_indices) to compute the parent. After
/// TREE_DEPTH levels, the result must equal `root`.
pub fn verify(leaf: felt252, root: felt252, siblings: Span<felt252>, path_indices: u64) {
    // The Merkle path must have exactly one sibling per tree level.
    assert(siblings.len() == TREE_DEPTH, 'bad path length');

    let mut current = leaf;
    let mut idx = path_indices;
    let mut i: u32 = 0;

    while i < TREE_DEPTH {
        let sibling = *siblings.at(i);

        // Extract the lowest bit: 0 = we are the left child, 1 = right child.
        let bit = idx & 1;
        idx = idx / 2;

        // Combine in the correct order:
        //   left child:  hash2(current, sibling)
        //   right child: hash2(sibling, current)
        current = if bit == 1 {
            hash2(sibling, current)
        } else {
            hash2(current, sibling)
        };

        i += 1;
    }

    // Reject if path_indices had bits above TREE_DEPTH. Without this check
    // an attacker could use path_indices = real_pos + k·2^TREE_DEPTH, which
    // passes Merkle verification (same low bits) but produces a distinct
    // nullifier (which hashes the full path_indices), enabling double-spend.
    assert(idx == 0, 'path_indices out of range');

    // After traversing all levels, current must equal the expected root.
    assert(current == root, 'merkle root mismatch');
}

#[cfg(test)]
mod tests {
    use super::{TREE_DEPTH, hash2, verify};

    fn zero_siblings(depth: u32) -> Array<felt252> {
        let mut siblings: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < depth {
            siblings.append(0);
            i += 1;
        }
        siblings
    }

    fn root_from_path(
        leaf: felt252, siblings: Span<felt252>, mut path_indices: u64, depth: u32,
    ) -> felt252 {
        let mut current = leaf;
        let mut i: u32 = 0;
        while i < depth {
            let sibling = *siblings.at(i);
            let bit = path_indices & 1;
            path_indices /= 2;
            current = if bit == 1 {
                hash2(sibling, current)
            } else {
                hash2(current, sibling)
            };
            i += 1;
        }
        current
    }

    fn one_shifted_by(depth: u32) -> u64 {
        let mut value: u64 = 1;
        let mut i: u32 = 0;
        while i < depth {
            value *= 2;
            i += 1;
        }
        value
    }

    #[test]
    fn test_verify_valid_merkle_path_leftmost() {
        let leaf = 0x1234;
        let siblings = zero_siblings(TREE_DEPTH);
        let root = root_from_path(leaf, siblings.span(), 0, TREE_DEPTH);
        verify(leaf, root, siblings.span(), 0);
    }

    #[test]
    fn test_verify_valid_merkle_path_nonzero_index() {
        let leaf = 0x5678;
        let siblings = zero_siblings(TREE_DEPTH);
        let path_indices = 5_u64;
        let root = root_from_path(leaf, siblings.span(), path_indices, TREE_DEPTH);
        verify(leaf, root, siblings.span(), path_indices);
    }

    #[test]
    #[should_panic(expected: ('merkle root mismatch',))]
    fn test_verify_rejects_wrong_sibling() {
        let leaf = 0x4321;
        let siblings_ok = zero_siblings(TREE_DEPTH);
        let root = root_from_path(leaf, siblings_ok.span(), 0, TREE_DEPTH);
        let mut siblings_bad: Array<felt252> = array![1];
        let mut i: u32 = 1;
        while i < TREE_DEPTH {
            siblings_bad.append(0);
            i += 1;
        }
        verify(leaf, root, siblings_bad.span(), 0);
    }

    #[test]
    #[should_panic(expected: ('path_indices out of range',))]
    fn test_verify_rejects_path_indices_aliasing() {
        let leaf = 0x2222;
        let siblings = zero_siblings(TREE_DEPTH);
        let root = root_from_path(leaf, siblings.span(), 0, TREE_DEPTH);
        verify(leaf, root, siblings.span(), one_shifted_by(TREE_DEPTH));
    }

}
