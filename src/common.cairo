/// Shared test note data for all step executables.
///
/// # Key hierarchy (Sapling-style delegated proving)
///
/// ```text
///   master_sk
///   ├── nsk_i = H("nsk", master_sk, i)   — nullifier secret key (per-note, given to prover)
///   │   └── pk_i = H(nsk_i)              — paying key (public)
///   └── ask_i = H("ask", master_sk, i)   — authorization signing key (per-note, NEVER shared)
///       └── ak_i = H(ask_i)              — authorization verifying key (public, in proof output)
/// ```
///
/// The commitment binds to both keys: cm = H(H(pk, ak), v, rho, r).
/// The prover sees (nsk, ak) but not (ask, master_sk).
///
/// In these tests, we derive per-note keys from a master key using
/// domain-separated hashing. In production, the wallet does this
/// automatically for each new note.
///
/// WARNING: Test keys are hardcoded and publicly known.

use starkprivacy::blake_hash as hash;

/// A note with all its secret and public data.
#[derive(Drop, Copy)]
pub struct Note {
    pub nsk: felt252,  // Nullifier secret key (given to prover)
    pub pk: felt252,   // Paying key = H(nsk) (public)
    pub ask: felt252,  // Authorization signing key (NEVER given to prover)
    pub ak: felt252,   // Authorization verifying key = H(ask) (public)
    pub v: u64,        // Amount
    pub rho: felt252,  // Random nonce (unique per note)
    pub r: felt252,    // Blinding factor
    pub cm: felt252,   // Commitment = H(H(pk, ak), v, rho, r)
}

/// Derive per-note keys from a master secret and a note index.
///
/// nsk = H("nsk" as felt, master_sk, index)  — for nullifier computation
/// ask = H("ask" as felt, master_sk, index)  — for spend authorization
///
/// The prover receives nsk (to compute pk and nf inside the circuit)
/// and ak = H(ask) (included in the commitment). They never receive ask.
fn derive_note_keys(master_sk: felt252, index: felt252) -> (felt252, felt252, felt252, felt252) {
    // Domain-separated derivation using hash2.
    // "nsk" and "ask" are encoded as small felt constants for domain tags.
    // Key derivation uses the generic (unpersonalized) hash2, NOT the Merkle-
    // personalized hash2. This matches the Rust demo's hash_two.
    let nsk = hash::hash2_generic(hash::hash2_generic(0x6E736B, master_sk), index); // 0x6E736B = "nsk"
    let ask = hash::hash2_generic(hash::hash2_generic(0x61736B, master_sk), index); // 0x61736B = "ask"
    let pk = hash::derive_pk(nsk);
    let ak = hash::derive_ak(ask);
    (nsk, pk, ask, ak)
}

/// Build a note from a master key, note index, value, nonce, and blinding factor.
fn make_note(master_sk: felt252, index: felt252, v: u64, rho: felt252, r: felt252) -> Note {
    let (nsk, pk, ask, ak) = derive_note_keys(master_sk, index);
    let cm = hash::commit(pk, ak, v, rho, r);
    Note { nsk, pk, ask, ak, v, rho, r, cm }
}

// ── Test master keys ─────────────────────────────────────────────────
//
// Three identities for the test scenario. Each has a master_sk from
// which all per-note keys are derived.

const MASTER_ALICE: felt252 = 0xA11CE;
const MASTER_BOB: felt252 = 0xB0B;
const MASTER_DUMMY: felt252 = 0xDEAD;

// ── Test scenario notes ──────────────────────────────────────────────
//
// The test scenario is a sequence of four operations:
//
//   Step 1 (shield):   deposit 1000 → note A (Alice, index 0)
//   Step 2 (unshield): withdraw note A → 1000 to recipient
//   Step 3 (join):     A(1000) + B(500) → C(1500) + W(0)
//                      also shields dummy note Z for later use
//   Step 4 (split):    C(1500) + Z(0) → D(800) + E(700)
//
// Each note has a unique index, producing unique (nsk, ask, pk, ak).

pub fn note_a() -> Note { make_note(MASTER_ALICE, 0, 1000, 0x1001, 0x2001) }
pub fn note_b() -> Note { make_note(MASTER_ALICE, 1, 500,  0x1002, 0x2002) }
pub fn note_z() -> Note { make_note(MASTER_DUMMY, 0, 0,    0x1003, 0x2003) }
pub fn note_c() -> Note { make_note(MASTER_BOB,   0, 1500, 0x1004, 0x2004) }
pub fn note_w() -> Note { make_note(MASTER_DUMMY, 1, 0,    0x1005, 0x2005) }
pub fn note_d() -> Note { make_note(MASTER_ALICE, 2, 800,  0x1006, 0x2006) }
pub fn note_e() -> Note { make_note(MASTER_BOB,   1, 700,  0x1007, 0x2007) }
