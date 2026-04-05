/// Shared test note data for all step executables.
///
/// Each step executable (step_shield, step_unshield, step_join, step_split)
/// needs to construct witnesses with consistent note data. This module
/// provides deterministic keys and notes so each step can independently
/// reconstruct the tree state it needs.
///
/// WARNING: These are TEST keys and nonces — hardcoded and publicly known.
/// A production system must use cryptographically random sk, rho, and r.

use starkprivacy::blake_hash as hash;

/// A note with all its secret and public data.
#[derive(Drop, Copy)]
pub struct Note {
    pub sk: felt252,   // Spending key (secret)
    pub pk: felt252,   // Paying key = H(sk) (public)
    pub v: u64,        // Amount
    pub rho: felt252,  // Random nonce (unique per note)
    pub r: felt252,    // Blinding factor
    pub cm: felt252,   // Commitment = H(pk, v, rho, r)
}

/// Return test keys for three parties: Alice, Bob, and a dummy identity.
pub fn keys() -> (felt252, felt252, felt252, felt252, felt252, felt252) {
    let sk_alice: felt252 = 0xA11CE;
    let sk_bob: felt252 = 0xB0B;
    let sk_dummy: felt252 = 0xDEAD;
    let pk_alice = hash::derive_pk(sk_alice);
    let pk_bob = hash::derive_pk(sk_bob);
    let pk_dummy = hash::derive_pk(sk_dummy);
    (sk_alice, pk_alice, sk_bob, pk_bob, sk_dummy, pk_dummy)
}

// ── Test scenario notes ──────────────────────────────────────────────
//
// The test scenario is a sequence of four operations on a growing tree:
//
//   Step 1 (shield):   deposit 1000 → note A (Alice)           tree: [A]
//   Step 2 (unshield): withdraw note A → 1000 to recipient     tree: [A]
//   Step 3 (join):     A(1000) + B(500) → C(1500) + W(0)      tree: [A, B, Z]
//                      also shields dummy note Z for later use
//   Step 4 (split):    C(1500) + Z(0) → D(800) + E(700)       tree: [A, B, Z, C, W]
//
// Each note has a unique (rho, r) pair. Rho uniqueness is critical for
// nullifier uniqueness — reusing rho across notes would allow linking
// their nullifiers.

/// Note A: 1000 to Alice (shielded in step 1, spent in step 3)
pub fn note_a() -> Note {
    let (sk_alice, pk_alice, _, _, _, _) = keys();
    let (rho, r, v) = (0x1001, 0x2001, 1000_u64);
    Note { sk: sk_alice, pk: pk_alice, v, rho, r, cm: hash::commit(pk_alice, v, rho, r) }
}

/// Note B: 500 to Alice (shielded off-screen, spent in step 3)
pub fn note_b() -> Note {
    let (sk_alice, pk_alice, _, _, _, _) = keys();
    let (rho, r, v) = (0x1002, 0x2002, 500_u64);
    Note { sk: sk_alice, pk: pk_alice, v, rho, r, cm: hash::commit(pk_alice, v, rho, r) }
}

/// Note Z: 0-value dummy (shielded in step 3, spent as padding in step 4)
pub fn note_z() -> Note {
    let (_, _, _, _, sk_dummy, pk_dummy) = keys();
    let (rho, r, v) = (0x1003, 0x2003, 0_u64);
    Note { sk: sk_dummy, pk: pk_dummy, v, rho, r, cm: hash::commit(pk_dummy, v, rho, r) }
}

/// Note C: 1500 to Bob (created in step 3 join, spent in step 4 split)
pub fn note_c() -> Note {
    let (_, _, sk_bob, pk_bob, _, _) = keys();
    let (rho, r, v) = (0x1004, 0x2004, 1500_u64);
    Note { sk: sk_bob, pk: pk_bob, v, rho, r, cm: hash::commit(pk_bob, v, rho, r) }
}

/// Note W: 0-value dummy (created in step 3 join as waste output)
pub fn note_w() -> Note {
    let (_, _, _, _, sk_dummy, pk_dummy) = keys();
    let (rho, r, v) = (0x1005, 0x2005, 0_u64);
    Note { sk: sk_dummy, pk: pk_dummy, v, rho, r, cm: hash::commit(pk_dummy, v, rho, r) }
}

/// Note D: 800 to Alice (created in step 4 split)
pub fn note_d() -> Note {
    let (sk_alice, pk_alice, _, _, _, _) = keys();
    let (rho, r, v) = (0x1006, 0x2006, 800_u64);
    Note { sk: sk_alice, pk: pk_alice, v, rho, r, cm: hash::commit(pk_alice, v, rho, r) }
}

/// Note E: 700 to Bob (created in step 4 split)
pub fn note_e() -> Note {
    let (_, _, sk_bob, pk_bob, _, _) = keys();
    let (rho, r, v) = (0x1007, 0x2007, 700_u64);
    Note { sk: sk_bob, pk: pk_bob, v, rho, r, cm: hash::commit(pk_bob, v, rho, r) }
}
