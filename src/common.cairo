/// Shared test data for step executables (v2 key hierarchy with nullifier binding).
///
/// # Key hierarchy
///
///   master_sk
///   ├── spend_seed → nk (account nullifier root), ask_base, ovk
///   │   └── nk_spend_j = H_nksp(nk, d_j) — per-address secret nullifier key
///   │       └── nk_tag_j = H_nktg(nk_spend_j) — per-address public binding tag
///   └── incoming_seed → dsk → d_j (diversified address)
///
/// Commitment: cm = H_commit(d_j, v, rcm, H_owner(ak_j, nk_tag_j))
/// Nullifier:  nf = H_nf(nk_spend_j, cm, pos)  — position-dependent
///
/// WARNING: Test keys are hardcoded and publicly known.

use starkprivacy::blake_hash as hash;

// ── Account ──────────────────────────────────────────────────────────

#[derive(Drop, Copy)]
pub struct Account {
    pub nk: felt252,            // account nullifier root
    pub ask_base: felt252,      // authorization derivation root
    pub incoming_seed: felt252,  // root for address derivation
}

pub fn derive_account(master_sk: felt252) -> Account {
    let spend_seed = hash::hash2_generic(0x7370656E64, master_sk);   // "spend"
    let nk = hash::hash2_generic(0x6E6B, spend_seed);               // "nk"
    let ask_base = hash::hash2_generic(0x61736B, spend_seed);       // "ask"
    let incoming_seed = hash::hash2_generic(0x696E636F6D696E67, master_sk); // "incoming"
    Account { nk, ask_base, incoming_seed }
}

/// Per-address authorization keys.
pub fn derive_ask(ask_base: felt252, j: felt252) -> (felt252, felt252) {
    let ask_j = hash::hash2_generic(ask_base, j);
    let ak_j = hash::hash1(ask_j);
    (ask_j, ak_j)
}

// ── Address ──────────────────────────────────────────────────────────

/// Derive diversifier d_j.
pub fn derive_address(incoming_seed: felt252, j: felt252) -> felt252 {
    let dsk = hash::hash2_generic(0x64736B, incoming_seed); // "dsk"
    hash::hash2_generic(dsk, j)
}

/// Derive per-address nullifier keys from account nk and diversifier d_j.
/// Returns (nk_spend_j, nk_tag_j).
///   nk_spend_j — secret, given to prover for this specific note
///   nk_tag_j   — public, included in payment address
pub fn derive_nk_keys(nk: felt252, d_j: felt252) -> (felt252, felt252) {
    let nk_spend = hash::derive_nk_spend(nk, d_j);
    let nk_tag = hash::derive_nk_tag(nk_spend);
    (nk_spend, nk_tag)
}

// ── Note ─────────────────────────────────────────────────────────────

#[derive(Drop, Copy)]
pub struct Note {
    pub nk_spend: felt252,  // per-address secret nullifier key (given to prover)
    pub nk_tag: felt252,    // per-address public binding tag (in payment address)
    pub ak: felt252,        // per-address authorization verifying key
    pub d_j: felt252,       // diversified address
    pub v: u64,             // amount
    pub rseed: felt252,     // per-note randomness
    pub cm: felt252,        // commitment
}

/// Build a note. The commitment binds to owner_tag = H_owner(ak, nk_tag).
/// The nullifier is NOT stored here because it requires `pos` (tree position),
/// which is only known after the note is inserted into the tree.
pub fn make_note(nk: felt252, ak: felt252, d_j: felt252, v: u64, rseed: felt252) -> Note {
    let (nk_spend, nk_tag) = derive_nk_keys(nk, d_j);
    let rcm = hash::derive_rcm(rseed);
    let otag = hash::owner_tag(ak, nk_tag);
    let cm = hash::commit(d_j, v, rcm, otag);
    Note { nk_spend, nk_tag, ak, d_j, v, rseed, cm }
}

// ── Test accounts and notes ──────────────────────────────────────────

const MASTER_ALICE: felt252 = 0xA11CE;
const MASTER_BOB: felt252 = 0xB0B;
const MASTER_DUMMY: felt252 = 0xDEAD;

pub fn alice_account() -> Account { derive_account(MASTER_ALICE) }
pub fn bob_account() -> Account { derive_account(MASTER_BOB) }
pub fn dummy_account() -> Account { derive_account(MASTER_DUMMY) }

pub fn alice_addr_0() -> felt252 { derive_address(alice_account().incoming_seed, 0) }
pub fn alice_addr_1() -> felt252 { derive_address(alice_account().incoming_seed, 1) }
pub fn alice_addr_2() -> felt252 { derive_address(alice_account().incoming_seed, 2) }
pub fn bob_addr_0() -> felt252 { derive_address(bob_account().incoming_seed, 0) }
pub fn bob_addr_1() -> felt252 { derive_address(bob_account().incoming_seed, 1) }
pub fn dummy_addr_0() -> felt252 { derive_address(dummy_account().incoming_seed, 0) }
pub fn dummy_addr_1() -> felt252 { derive_address(dummy_account().incoming_seed, 1) }

fn alice_ak(j: felt252) -> felt252 { let (_, ak) = derive_ask(alice_account().ask_base, j); ak }
fn bob_ak(j: felt252) -> felt252 { let (_, ak) = derive_ask(bob_account().ask_base, j); ak }
fn dummy_ak(j: felt252) -> felt252 { let (_, ak) = derive_ask(dummy_account().ask_base, j); ak }

// Test scenario notes.
pub fn note_a() -> Note { make_note(alice_account().nk, alice_ak(0), alice_addr_0(), 1000, 0x1001) }
pub fn note_b() -> Note { make_note(alice_account().nk, alice_ak(1), alice_addr_1(), 500, 0x1002) }
pub fn note_z() -> Note { make_note(dummy_account().nk, dummy_ak(0), dummy_addr_0(), 0, 0x1003) }
pub fn note_c() -> Note { make_note(bob_account().nk, bob_ak(0), bob_addr_0(), 1500, 0x1004) }
pub fn note_w() -> Note { make_note(dummy_account().nk, dummy_ak(1), dummy_addr_1(), 0, 0x1005) }
pub fn note_d() -> Note { make_note(alice_account().nk, alice_ak(2), alice_addr_2(), 800, 0x1006) }
pub fn note_e() -> Note { make_note(bob_account().nk, bob_ak(1), bob_addr_1(), 700, 0x1007) }
