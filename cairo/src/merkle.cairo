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
/// 2^10 = 1024 one-time signing keys per address.
pub const AUTH_DEPTH: u32 = 10;

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
    };

    // Reject if path_indices had bits above TREE_DEPTH. Without this check
    // an attacker could use path_indices = real_pos + k·2^TREE_DEPTH, which
    // passes Merkle verification (same low bits) but produces a distinct
    // nullifier (which hashes the full path_indices), enabling double-spend.
    assert(idx == 0, 'path_indices out of range');

    // After traversing all levels, current must equal the expected root.
    assert(current == root, 'merkle root mismatch');
}

/// Verify membership in an auth key tree (depth = AUTH_DEPTH).
/// Same algorithm as `verify` but for the smaller per-address auth tree.
pub fn verify_auth(leaf: felt252, root: felt252, siblings: Span<felt252>, path_indices: u64) {
    assert(siblings.len() == AUTH_DEPTH, 'bad auth path length');

    let mut current = leaf;
    let mut idx = path_indices;
    let mut i: u32 = 0;

    while i < AUTH_DEPTH {
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

    assert(idx == 0, 'auth_index out of range');
    assert(current == root, 'auth root mismatch');
}
