/// Shared note data for all steps. Deterministic keys and nonces so each
/// step can independently reconstruct the tree state it needs.

use starkprivacy::blake_hash as hash;

#[derive(Drop, Copy)]
pub struct Note {
    pub sk: felt252,
    pub pk: felt252,
    pub v: u64,
    pub rho: felt252,
    pub r: felt252,
    pub cm: felt252,
}

pub fn keys() -> (felt252, felt252, felt252, felt252, felt252, felt252) {
    let sk_alice: felt252 = 0xA11CE;
    let sk_bob: felt252 = 0xB0B;
    let sk_dummy: felt252 = 0xDEAD;
    let pk_alice = hash::derive_pk(sk_alice);
    let pk_bob = hash::derive_pk(sk_bob);
    let pk_dummy = hash::derive_pk(sk_dummy);
    (sk_alice, pk_alice, sk_bob, pk_bob, sk_dummy, pk_dummy)
}

/// Build note A: 1000 to Alice
pub fn note_a() -> Note {
    let (sk_alice, pk_alice, _, _, _, _) = keys();
    let (rho, r, v) = (0x1001, 0x2001, 1000_u64);
    Note { sk: sk_alice, pk: pk_alice, v, rho, r, cm: hash::commit(pk_alice, v, rho, r) }
}

/// Build note B: 500 to Alice
pub fn note_b() -> Note {
    let (sk_alice, pk_alice, _, _, _, _) = keys();
    let (rho, r, v) = (0x1002, 0x2002, 500_u64);
    Note { sk: sk_alice, pk: pk_alice, v, rho, r, cm: hash::commit(pk_alice, v, rho, r) }
}

/// Build note Z: 0 dummy
pub fn note_z() -> Note {
    let (_, _, _, _, sk_dummy, pk_dummy) = keys();
    let (rho, r, v) = (0x1003, 0x2003, 0_u64);
    Note { sk: sk_dummy, pk: pk_dummy, v, rho, r, cm: hash::commit(pk_dummy, v, rho, r) }
}

/// Build note C: 1500 to Bob (join output)
pub fn note_c() -> Note {
    let (_, _, sk_bob, pk_bob, _, _) = keys();
    let (rho, r, v) = (0x1004, 0x2004, 1500_u64);
    Note { sk: sk_bob, pk: pk_bob, v, rho, r, cm: hash::commit(pk_bob, v, rho, r) }
}

/// Build note W: 0 dummy (join output)
pub fn note_w() -> Note {
    let (_, _, _, _, sk_dummy, pk_dummy) = keys();
    let (rho, r, v) = (0x1005, 0x2005, 0_u64);
    Note { sk: sk_dummy, pk: pk_dummy, v, rho, r, cm: hash::commit(pk_dummy, v, rho, r) }
}

/// Build note D: 800 to Alice (split output)
pub fn note_d() -> Note {
    let (sk_alice, pk_alice, _, _, _, _) = keys();
    let (rho, r, v) = (0x1006, 0x2006, 800_u64);
    Note { sk: sk_alice, pk: pk_alice, v, rho, r, cm: hash::commit(pk_alice, v, rho, r) }
}

/// Build note E: 700 to Bob (split output)
pub fn note_e() -> Note {
    let (_, _, sk_bob, pk_bob, _, _) = keys();
    let (rho, r, v) = (0x1007, 0x2007, 700_u64);
    Note { sk: sk_bob, pk: pk_bob, v, rho, r, cm: hash::commit(pk_bob, v, rho, r) }
}
