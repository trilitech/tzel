/// BLAKE2s-256 hash primitives for StarkPrivacy v2.
///
/// # Key hierarchy
///
/// ```text
///   master_sk
///   ├── spend_seed = H("spend", master_sk)
///   │   ├── nk       = H("nk",  spend_seed)    — account nullifier root
///   │   │   └── nk_spend_j = H_nksp(nk, d_j)   — per-address secret nullifier key
///   │   │       └── nk_tag_j = H_nktg(nk_spend_j) — per-address public binding tag
///   │   └── ask_base = H("ask", spend_seed)     — authorization derivation root
///   │       └── ask_j = H(ask_base, j)          — per-address auth secret
///   │           └── auth_root_j = Merkle root of one-time key tree
///   │
///   └── incoming_seed = H("incoming", master_sk)
///       └── dsk = H("dsk", incoming_seed)
///           └── d_j = H(dsk, j)                 — diversified address
/// ```
///
/// # Note structure
///
///   owner_tag_j = H_owner(auth_root_j, nk_tag_j)
///   cm = H_commit(d_j, v, rcm, owner_tag_j)  — commitment
///   nf = H_nf(nk_spend_j, cm, pos)           — nullifier (position-dependent)
///
/// # Domain separation
///
/// Each hash use has a unique IV via BLAKE2s personalization (P[6..7]):
///   - Generic:   key derivation, derive_rcm
///   - mrklSP__:  Merkle internal nodes
///   - nulfSP__:  nullifiers
///   - cmmtSP__:  note commitments
///   - nkspSP__:  nk_spend_j derivation (per-address secret nullifier key)
///   - nktgSP__:  nk_tag_j derivation (per-address public binding tag)
///   - ownrSP__:  owner_tag_j (fuses auth_root + nk_tag into commitment)

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxTrait;

// ── Arithmetic helpers ───────────────────────────────────────────────
const MASK32: u128 = 0xFFFFFFFF;
const POW32: u128 = 0x100000000;
const POW64: u128 = 0x10000000000000000;
const POW96: u128 = 0x1000000000000000000000000;

// ── Personalized BLAKE2s IVs ─────────────────────────────────────────

/// Generic IV — no personalization. Key derivation only.
fn blake2s_iv() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ])
}

/// Merkle-node IV — "mrklSP__".
fn blake2s_iv_merkle() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x73E8ABC6, 0x04BF9D4A,
    ])
}

/// Nullifier IV — "nulfSP__".
fn blake2s_iv_nullifier() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x79EFACC5, 0x04BF9D4A,
    ])
}

/// Commitment IV — "cmmtSP__".
fn blake2s_iv_commit() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x6BEEB4C8, 0x04BF9D4A,
    ])
}

/// nk_spend derivation IV — "nkspSP__".
/// Derives per-address secret nullifier key from account nk.
fn blake2s_iv_nk_spend() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x6FF0B2C5, 0x04BF9D4A,
    ])
}

/// nk_tag derivation IV — "nktgSP__".
/// Derives per-address public binding tag from nk_spend.
fn blake2s_iv_nk_tag() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x78F7B2C5, 0x04BF9D4A,
    ])
}

/// Owner-tag IV — "ownrSP__".
/// Fuses auth_root and nk_tag into the commitment.
fn blake2s_iv_owner() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x6DEDAEC4, 0x04BF9D4A,
    ])
}

/// WOTS+ chain hash IV — "wotsSP__".
/// Dedicated domain for WOTS+ hash chain iterations.
fn blake2s_iv_wots() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x6CF7B6DC, 0x04BF9D4A,
    ])
}

/// PK fold IV — "pkfdSP__".
/// Dedicated domain for folding WOTS+ public key chains to a leaf hash.
fn blake2s_iv_pkfold() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x7BE5B2DB, 0x04BF9D4A,
    ])
}

/// Sighash IV — "sighSP__".
/// Used to compute the transaction sighash that WOTS+ signatures bind to.
fn blake2s_iv_sighash() -> Box<[u32; 8]> {
    BoxTrait::new([
        0x6B08E647_u32, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x77E4B0D8, 0x04BF9D4A,
    ])
}

// ── Encoding helpers ─────────────────────────────────────────────────

fn felt_to_u32x8(val: felt252) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    let v: u256 = val.into();
    let lo = v.low;
    let hi = v.high;
    (
        (lo & MASK32).try_into().unwrap(),
        ((lo / POW32) & MASK32).try_into().unwrap(),
        ((lo / POW64) & MASK32).try_into().unwrap(),
        ((lo / POW96) & MASK32).try_into().unwrap(),
        (hi & MASK32).try_into().unwrap(),
        ((hi / POW32) & MASK32).try_into().unwrap(),
        ((hi / POW64) & MASK32).try_into().unwrap(),
        ((hi / POW96) & MASK32).try_into().unwrap(),
    )
}

fn u32x8_to_felt(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32, h5: u32, h6: u32, h7: u32) -> felt252 {
    let low: u128 = h0.into() + h1.into() * POW32 + h2.into() * POW64 + h3.into() * POW96;
    let h7_masked: u128 = h7.into() & 0x07FFFFFF;
    let high: u128 = h4.into() + h5.into() * POW32 + h6.into() * POW64 + h7_masked * POW96;
    let out = u256 { low, high };
    out.try_into().unwrap()
}

// ── Core hash functions ──────────────────────────────────────────────

/// H(a) — single-element hash (32 bytes, generic IV). Key derivation.
pub fn hash1(a: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0, 0]);
    let result = blake2s_finalize(blake2s_iv(), 32, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H(a, b) with caller-specified IV.
fn hash2_with_iv(iv: Box<[u32; 8]>, a: felt252, b: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let result = blake2s_finalize(iv, 64, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// H(a, b) — generic (no personalization). Key derivation only.
pub fn hash2_generic(a: felt252, b: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv(), a, b)
}

/// H_merkle(a, b) — Merkle tree internal nodes.
pub fn hash2(a: felt252, b: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_merkle(), a, b)
}

/// H_commit(a, b, c, d) — 128-byte commitment hash.
fn hash4(a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let (b0, b1, b2, b3, b4, b5, b6, b7) = felt_to_u32x8(b);
    let (c0, c1, c2, c3, c4, c5, c6, c7) = felt_to_u32x8(c);
    let (d0, d1, d2, d3, d4, d5, d6, d7) = felt_to_u32x8(d);
    let block1 = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7]);
    let state = blake2s_compress(blake2s_iv_commit(), 64, block1);
    let block2 = BoxTrait::new([c0, c1, c2, c3, c4, c5, c6, c7, d0, d1, d2, d3, d4, d5, d6, d7]);
    let result = blake2s_finalize(state, 128, block2);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

// ── Protocol functions ───────────────────────────────────────────────

/// Derive commitment randomness: rcm = H(H("rcm"), rseed).
pub fn derive_rcm(rseed: felt252) -> felt252 {
    hash2_generic(hash1(0x72636D), rseed)
}

/// Derive per-address secret nullifier key: nk_spend_j = H_nksp(nk, d_j).
///
/// This is the secret given to the delegated prover for a specific note.
/// It is per-address (different d_j → different nk_spend_j), so the prover
/// doesn't learn the account-wide nk. Uses dedicated "nkspSP__" domain.
pub fn derive_nk_spend(nk: felt252, d_j: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_nk_spend(), nk, d_j)
}

/// Derive per-address public binding tag: nk_tag_j = H_nktg(nk_spend_j).
///
/// This is included in the payment address. The sender uses it to compute
/// the commitment. It is per-address and one-way from nk_spend_j, so it
/// reveals nothing about nk. Uses dedicated "nktgSP__" domain.
pub fn derive_nk_tag(nk_spend: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(nk_spend);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0, 0]);
    let result = blake2s_finalize(blake2s_iv_nk_tag(), 32, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// Compute owner tag: owner_tag_j = H_owner(auth_root_j, nk_tag_j).
///
/// Fuses the auth key tree root and the nullifier binding tag into a single
/// value for the commitment. Binds the note to both the spending authority
/// (auth_root) and the nullifier key chain (nk_tag). Uses "ownrSP__" domain.
pub fn owner_tag(auth_root: felt252, nk_tag: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_owner(), auth_root, nk_tag)
}

/// Note commitment: cm = H_commit(d_j, v, rcm, owner_tag_j).
///
/// Binds to the diversified address, value, randomness, and the owner tag
/// (which fuses auth_root and nk_tag). This ensures:
///   - The prover can't substitute a different auth_root (breaks Merkle proof)
///   - The prover can't use a different nk (changes nk_tag → changes
///     owner_tag → changes cm → breaks Merkle proof)
pub fn commit(d_j: felt252, v: u64, rcm: felt252, owner_tag: felt252) -> felt252 {
    hash4(d_j, v.into(), rcm, owner_tag)
}

/// Nullifier: nf = H_nf(nk_spend_j, cm, pos).
///
/// Position-dependent nullifier. Each note at a different tree position
/// gets a unique nullifier, even if the commitment is identical (prevents
/// the "faerie gold" attack where a malicious sender mints duplicate
/// commitments that collapse to one spendable nullifier).
///
/// nk_spend_j is per-address (not account-level), so the delegated prover
/// only learns the nullifier key for the specific note being spent.
pub fn nullifier(nk_spend: felt252, cm: felt252, pos: u64) -> felt252 {
    // H_nf(nk_spend, H(cm, pos)) — nest pos inside cm to fit hash2's 2-input interface.
    let cm_pos = hash2_with_iv(blake2s_iv_nullifier(), cm, pos.into());
    hash2_with_iv(blake2s_iv_nullifier(), nk_spend, cm_pos)
}

// ── WOTS+ hash functions ────────────────────────────────────────────

/// WOTS+ chain hash: H_wots(x). Dedicated domain for chain iterations.
pub fn hash1_wots(a: felt252) -> felt252 {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = felt_to_u32x8(a);
    let msg = BoxTrait::new([a0, a1, a2, a3, a4, a5, a6, a7, 0, 0, 0, 0, 0, 0, 0, 0]);
    let result = blake2s_finalize(blake2s_iv_wots(), 32, msg);
    let [h0, h1, h2, h3, h4, h5, h6, h7] = result.unbox();
    u32x8_to_felt(h0, h1, h2, h3, h4, h5, h6, h7)
}

/// WOTS+ PK fold: H_pkfold(a, b). Dedicated domain for folding pk chains.
pub fn hash2_pkfold(a: felt252, b: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_pkfold(), a, b)
}

// ── WOTS+ sighash support ───────────────────────────────────────────

/// Fold two values into a sighash using the dedicated sighash IV.
pub fn sighash_fold(a: felt252, b: felt252) -> felt252 {
    hash2_with_iv(blake2s_iv_sighash(), a, b)
}

/// Decompose a sighash (felt252) into 133 base-4 WOTS+ digits (128 message + 5 checksum).
/// The felt252 is interpreted as 32 LE bytes → 128 base-4 digits (2 bits each).
/// The checksum is sum(3 - digit[i]) for i in 0..128, encoded as 5 base-4 digits.
pub fn sighash_to_wots_digits(sighash: felt252) -> Array<u32> {
    let (w0, w1, w2, w3, w4, w5, w6, w7) = felt_to_u32x8(sighash);
    let words: [u32; 8] = [w0, w1, w2, w3, w4, w5, w6, w7];

    let mut digits: Array<u32> = array![];
    let mut checksum: u32 = 0;

    // Extract 16 base-4 digits per u32 word (32 bits / 2 = 16 digits)
    let mut wi: u32 = 0;
    while wi < 8 {
        let mut word = *words.span().at(wi);
        let mut bi: u32 = 0;
        while bi < 16 {
            let digit = word & 3;
            digits.append(digit);
            checksum += 3 - digit;
            word = word / 4;
            bi += 1;
        };
        wi += 1;
    };

    // Append 5 checksum digits (base-4 encoding of checksum)
    let mut cs = checksum;
    let mut ci: u32 = 0;
    while ci < 5 {
        digits.append(cs & 3);
        cs = cs / 4;
        ci += 1;
    };

    digits
}
