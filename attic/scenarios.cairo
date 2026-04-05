/// End-to-end test scenarios exercising all circuit types.
///
/// Sequence:
///   1. Shield 1000 → note A (Alice)
///   2. Shield  500 → note B (Alice)
///   3. Shield    0 → note Z (dummy, for later split input)
///   4. Join   A + B → C(1500, Bob) + W(0, dummy)
///   5. Split  C + Z → D(800, Alice) + E(700, Bob)

#[cfg(feature: 'blake')]
use starkprivacy::blake_hash as hash;
#[cfg(not(feature: 'blake'))]
use starkprivacy::hash;
use starkprivacy::{shield, transfer, tree};

#[executable]
fn main() {
    // ── Keys ──────────────────────────────────────────────────────────
    let sk_alice: felt252 = 0xA11CE;
    let sk_bob: felt252 = 0xB0B;
    let sk_dummy: felt252 = 0xDEAD;

    let pk_alice = hash::derive_pk(sk_alice);
    let pk_bob = hash::derive_pk(sk_bob);
    let pk_dummy = hash::derive_pk(sk_dummy);

    let zh = tree::zero_hashes();
    let zh_span = zh.span();

    // ── 1. Shield 1000 to Alice ───────────────────────────────────────
    let (rho_a, r_a, v_a): (felt252, felt252, u64) = (0x1001, 0x2001, 1000);
    let cm_a = hash::commit(pk_alice, v_a, rho_a, r_a);
    shield::verify(v_a, cm_a, pk_alice, rho_a, r_a);

    // ── 2. Shield 500 to Alice ────────────────────────────────────────
    let (rho_b, r_b, v_b): (felt252, felt252, u64) = (0x1002, 0x2002, 500);
    let cm_b = hash::commit(pk_alice, v_b, rho_b, r_b);
    shield::verify(v_b, cm_b, pk_alice, rho_b, r_b);

    // ── 3. Shield 0 (dummy for split) ─────────────────────────────────
    let (rho_z, r_z, v_z): (felt252, felt252, u64) = (0x1003, 0x2003, 0);
    let cm_z = hash::commit(pk_dummy, v_z, rho_z, r_z);
    shield::verify(v_z, cm_z, pk_dummy, rho_z, r_z);

    // Tree state: [cm_a, cm_b, cm_z]
    let leaves_3: Array<felt252> = array![cm_a, cm_b, cm_z];

    // ── 4. Join: A(1000) + B(500) → C(1500) + W(0) ──────────────────
    let (sib_a, idx_a, root_join) = tree::auth_path(leaves_3.span(), 0, zh_span);
    let (sib_b, idx_b, _) = tree::auth_path(leaves_3.span(), 1, zh_span);

    let nf_a = hash::nullifier(sk_alice, rho_a);
    let nf_b = hash::nullifier(sk_alice, rho_b);

    let (rho_c, r_c, v_c): (felt252, felt252, u64) = (0x1004, 0x2004, 1500);
    let cm_c = hash::commit(pk_bob, v_c, rho_c, r_c);

    let (rho_w, r_w, v_w): (felt252, felt252, u64) = (0x1005, 0x2005, 0);
    let cm_w = hash::commit(pk_dummy, v_w, rho_w, r_w);

    transfer::verify(
        root_join, nf_a, nf_b, cm_c, cm_w,
        sk_alice, v_a, rho_a, r_a, sib_a.span(), idx_a,
        sk_alice, v_b, rho_b, r_b, sib_b.span(), idx_b,
        pk_bob, v_c, rho_c, r_c,
        pk_dummy, v_w, rho_w, r_w,
    );

    // Tree state: [cm_a, cm_b, cm_z, cm_c, cm_w]
    let leaves_5: Array<felt252> = array![cm_a, cm_b, cm_z, cm_c, cm_w];

    // ── 5. Split: C(1500) + Z(0) → D(800) + E(700) ──────────────────
    let (sib_c, idx_c, root_split) = tree::auth_path(leaves_5.span(), 3, zh_span);
    let (sib_z, idx_z, _) = tree::auth_path(leaves_5.span(), 2, zh_span);

    let nf_c = hash::nullifier(sk_bob, rho_c);
    let nf_z = hash::nullifier(sk_dummy, rho_z);

    let (rho_d, r_d, v_d): (felt252, felt252, u64) = (0x1006, 0x2006, 800);
    let cm_d = hash::commit(pk_alice, v_d, rho_d, r_d);

    let (rho_e, r_e, v_e): (felt252, felt252, u64) = (0x1007, 0x2007, 700);
    let cm_e = hash::commit(pk_bob, v_e, rho_e, r_e);

    transfer::verify(
        root_split, nf_c, nf_z, cm_d, cm_e,
        sk_bob, v_c, rho_c, r_c, sib_c.span(), idx_c,
        sk_dummy, v_z, rho_z, r_z, sib_z.span(), idx_z,
        pk_alice, v_d, rho_d, r_d,
        pk_bob, v_e, rho_e, r_e,
    );
}
