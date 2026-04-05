/// Unshield circuit: withdraw a private note to a public address.
///
/// # Public outputs
///   - `root`      — Merkle root of T (any historical root)
///   - `nf`        — nullifier (added to NF_set)
///   - `v_pub`     — withdrawn amount (credited to recipient)
///   - `ak`        — authorization key (contract verifies spend signature)
///   - `recipient` — destination address (prevents front-running)
///
/// # Private inputs (given to the prover)
///   - `nsk`           — nullifier secret key (derives pk and nf)
///   - `rho`, `r`      — note nonce and blinding factor
///   - `siblings`      — Merkle authentication path
///   - `path_indices`  — leaf position bitmask
///
/// # Constraints
///   1. pk  = H(nsk)
///   2. cm  = H(H(pk, ak), v_pub, rho, r)
///   3. cm is in T under root
///   4. nf  = H(nsk, rho)
///
/// # Delegated proving
///
/// The prover receives (nsk, ak, v_pub, rho, r, Merkle path). They can
/// generate the proof but cannot authorize the spend — that requires
/// `ask` (which only the user knows) to sign the outputs.

use starkprivacy::blake_hash as hash;
use starkprivacy::merkle;

pub fn verify(
    root: felt252,
    nf: felt252,
    v_pub: u64,
    ak: felt252,
    recipient: felt252,
    nsk: felt252,
    rho: felt252,
    r: felt252,
    siblings: Span<felt252>,
    path_indices: u64,
) -> Array<felt252> {
    // 1. Derive the paying key from the nullifier secret key.
    let pk = hash::derive_pk(nsk);

    // 2. Recompute the commitment, binding to both pk and ak.
    let cm = hash::commit(pk, ak, v_pub, rho, r);

    // 3. Verify the commitment is in the Merkle tree.
    merkle::verify(cm, root, siblings, path_indices);

    // 4. Verify the nullifier is correctly derived.
    assert(hash::nullifier(nsk, rho) == nf, 'unshield: bad nullifier');

    // Public outputs. The contract:
    //   1. Verifies the STARK proof
    //   2. Checks Sig(ask, outputs) against ak
    //   3. Checks root ∈ valid_roots, nf ∉ NF_set
    //   4. Adds nf to NF_set, credits v_pub to recipient
    array![root, nf, v_pub.into(), ak, recipient]
}
