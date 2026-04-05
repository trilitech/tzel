/// Unshield circuit: withdraw a private note to a public amount.
///
/// Destroys a private note and credits its value to a public address.
/// The prover demonstrates they own the note (know sk) and that it
/// exists in the commitment tree, without revealing which commitment
/// they are spending.
///
/// # Public inputs (read from proof output by the on-chain verifier)
///   - `root`      — Merkle root of T at proof time (any historical root)
///   - `nf`        — nullifier of the spent note (added to NF_set)
///   - `v_pub`     — withdrawn amount (credited to recipient)
///   - `recipient` — destination address (binds proof to prevent front-running)
///
/// # Private inputs (known only to the prover)
///   - `sk`            — spending key (proves ownership)
///   - `rho`, `r`      — note nonce and blinding factor
///   - `siblings`      — Merkle authentication path
///   - `path_indices`  — leaf position bitmask
///
/// # Constraints
///   1. pk  = H(sk)                        — derive paying key
///   2. cm  = H(pk, v_pub, rho, r)         — recompute commitment
///   3. cm is in T under root (via path)   — Merkle membership
///   4. nf  = H(sk, rho)                   — nullifier correctness
///
/// The nullifier binds deterministically to the note: each note has
/// exactly one valid nullifier, so the on-chain NF_set catches replays.

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

pub fn verify(
    root: felt252,
    nf: felt252,
    v_pub: u64,
    recipient: felt252,
    sk: felt252,
    rho: felt252,
    r: felt252,
    siblings: Span<felt252>,
    path_indices: u64,
) -> Array<felt252> {
    // 1. Derive the paying key from the spending key.
    let pk = hash::derive_pk(sk);

    // 2. Recompute the commitment from the note data.
    let cm = hash::commit(pk, v_pub, rho, r);

    // 3. Verify the commitment is in the Merkle tree under root.
    merkle::verify(cm, root, siblings, path_indices);

    // 4. Check the nullifier is correctly derived from sk and rho.
    //    This ensures the prover can't fabricate an arbitrary nullifier
    //    to spend the same note with a different nf.
    assert(hash::nullifier(sk, rho) == nf, 'unshield: bad nullifier');

    // Return public outputs. The on-chain verifier:
    //   - Checks root is a valid historical root of T
    //   - Checks nf is not in NF_set, then adds it
    //   - Credits v_pub to recipient's public balance
    array![root, nf, v_pub.into(), recipient]
}
