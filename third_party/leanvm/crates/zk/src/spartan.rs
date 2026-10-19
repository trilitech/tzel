//! A zero-knowledge Spartan over `E`: the outer proof that a rank-one system holds.
//!
//! The rows form the cube `{0,1}^l`, row `x = sum_i x_i 2^i`, variable 0 bound first.
//!
//! It proves `sum_x eq(tau, x) F(x) = 0` for `F = A~ * B~ + C~`, the rows' products, in characteristic two.
//!
//! It ends in two linear claims, which the caller discharges by opening its own commitment:
//!
//! - the row claim: `sum_x eq(r, x) (A_x + gamma B_x + gamma^2 C_x) = a + gamma b + gamma^2 c`;
//! - the mask claim: the mask `g` at the sumcheck's point.
//!
//! # Zero knowledge
//!
//! - The mask is `g(X) = g_c + sum_j (g_j0 + g_j1 X_j) X_j`, of degree two in each variable, as `F` is.
//! - Each round's two sent coefficients carry `alpha` times the round's own fresh `(g_j0, g_j1)`.
//! - The mask's sum is hidden by `g_c`.
//! - The final `(a, b, c)` are hidden by two dummy rows whose fresh operands sit in rows of their own.
//!
//! This is the eq-weighted MLE-check of the Binius64 construction.

use fiat_shamir::ProverState;
use fiat_shamir::TranscriptError;
use fiat_shamir::arith::{Arith, Native, RoundPolynomial, Verifier};
use primitives::field::F192;
use primitives::multilinear::{eq_table, interp};

/// The claim the rows' sides take at the sumcheck's point, three sides batched by `gamma`.
///
/// ```text
///     sum_x eq(point, x) (A_x + gamma B_x + gamma^2 C_x) . z  =  value
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RowClaim<E = F192> {
    /// The rows' point.
    pub(crate) point: Vec<E>,
    /// The challenge batching the three sides.
    pub(crate) gamma: E,
    /// What the batched sides take at the point.
    pub(crate) value: E,
}

/// The claim the mask takes at the sumcheck's point: its inner product with `weight` is `value`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaskClaim<E = F192> {
    /// `[1, r_0, r_0^2, r_1, r_1^2, ...]`, so that the mask's inner product with it is `g(r)`.
    pub(crate) weight: Vec<E>,
    /// `g(r)`.
    pub(crate) value: E,
}

/// What the outer proof leaves to the caller's opening: a claim on the rows, and one on the mask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Claims<E = F192> {
    /// The rows' claim.
    pub(crate) rows: RowClaim<E>,
    /// The mask's claim.
    pub(crate) mask: MaskClaim<E>,
}

/// The mask's coefficients over `l` variables: `[g_c, g_00, g_01, g_10, g_11, ...]`.
#[must_use]
pub(crate) const fn mask_len(log_rows: usize) -> usize {
    1 + 2 * log_rows
}

/// The variables of a system of `n_rows` rows: at least one.
#[must_use]
pub(crate) const fn log_rows(n_rows: usize) -> usize {
    let log = n_rows.next_power_of_two().trailing_zeros() as usize;
    if log == 0 { 1 } else { log }
}

/// Prove that the rows' sides `[A z, B z, C z]` satisfy `A z * B z = C z`, with the mask the caller committed.
///
/// Sides that do not satisfy the rows give a proof the verifier refuses.
///
/// # Panics
///
/// Panics on sides of unequal length, or a mask of the wrong length.
#[must_use]
pub(crate) fn prove(ps: &mut ProverState, sides: [Vec<F192>; 3], mask: &[F192]) -> Claims {
    let n_rows = sides[0].len();
    assert!(sides.iter().all(|s| s.len() == n_rows), "three sides of one height");
    let l = log_rows(n_rows);
    assert_eq!(mask.len(), mask_len(l), "a mask of the system's size");
    let [mut az, mut bz, mut cz] = sides.map(|mut s| {
        s.resize(1 << l, F192::ZERO);
        s
    });
    let (g_c, g) = (mask[0], mask[1..].as_chunks::<2>().0);

    let tau: Vec<F192> = ps.verifier_messages(l);
    // sum_j tau_j g_j(1): the mask's share of the variables still free.
    let mut suffix = (tau.iter().zip(g)).fold(F192::ZERO, |acc, (&t, &[g0, g1])| acc + t * (g0 + g1));
    ps.prover_message(&(g_c + suffix));
    let alpha: F192 = ps.verifier_message();

    // g_c + sum_{j<i} g_j(r_j) r_j: the mask's share of the variables bound.
    let mut prefix = g_c;
    let mut r = Vec::with_capacity(l);
    for (i, &[g0, g1]) in g.iter().enumerate() {
        // Round i: the variable i's own mask term leaves the suffix.
        suffix += tau[i] * (g0 + g1);
        let eq = eq_table(&tau[i + 1..]);
        let mut coeffs = [F192::ZERO; 3];
        let pairs = (az.as_chunks::<2>().0.iter().zip(bz.as_chunks::<2>().0)).zip(cz.as_chunks::<2>().0);
        for (((a, b), c), &e) in pairs.zip(&eq) {
            // The pair's line in the variable, A * B + C at X: constant, linear and square coefficients.
            let (da, db) = (a[0] + a[1], b[0] + b[1]);
            coeffs[0] += e * (a[0] * b[0] + c[0]);
            coeffs[1] += e * (a[0] * db + da * b[0] + c[0] + c[1]);
            coeffs[2] += e * da * db;
        }
        coeffs[0] += alpha * (prefix + suffix);
        coeffs[1] += alpha * g0;
        coeffs[2] += alpha * g1;
        RoundPolynomial { coeffs }.send(ps, true);
        let ri: F192 = ps.verifier_message();
        prefix += (g0 + g1 * ri) * ri;
        for table in [&mut az, &mut bz, &mut cz] {
            fold_low(table, ri);
        }
        r.push(ri);
    }

    let [a, b, c] = [az[0], bz[0], cz[0]];
    ps.prover_messages(&[a, b, c]);
    let gamma: F192 = ps.verifier_message();
    let weight = mask_weight(&mut Native, &r);
    let value = (mask.iter().zip(&weight)).fold(F192::ZERO, |acc, (&g, &w)| acc + g * w);
    Claims {
        rows: RowClaim {
            point: r,
            gamma,
            value: a + gamma * (b + gamma * c),
        },
        mask: MaskClaim { weight, value },
    }
}

/// Verify the outer proof of a system of `n_rows` rows, as far as a verifier without the witness can.
///
/// # Errors
///
/// Refuses a malformed proof: the claims it returns are what the caller checks.
pub(crate) fn verify<V: Verifier>(v: &mut V, n_rows: usize) -> Result<Claims<V::E>, TranscriptError> {
    let l = log_rows(n_rows);
    let tau = v.verifier_messages(l);
    let s_g = v.prover_message()?;
    let alpha = v.verifier_message();
    // The system's sum is zero, so the claim is the mask's alone.
    let mut s = v.mul(alpha, s_g);
    let mut r = Vec::with_capacity(l);
    for &t in &tau {
        let coeffs = RoundPolynomial::read(v, 3, s, Some(t))?.coeffs;
        let ri = v.verifier_message();
        s = v.poly_eval(&coeffs, ri);
        r.push(ri);
    }

    let [a, b, c] = [v.prover_message()?, v.prover_message()?, v.prover_message()?];
    // s = F(r) + alpha g(r), so g(r) = (s + a b + c) / alpha.
    let f = v.mul_add(a, b, c);
    let masked = v.add(s, f);
    let alpha_inv = v.inv(alpha);
    let mask = v.mul(masked, alpha_inv);
    let gamma = v.verifier_message();
    let bc = v.mul_add(c, gamma, b);
    let value = v.mul_add(bc, gamma, a);
    let weight = mask_weight(v, &r);
    Ok(Claims {
        rows: RowClaim { point: r, gamma, value },
        mask: MaskClaim { weight, value: mask },
    })
}

/// `[1, r_0, r_0^2, r_1, r_1^2, ...]`.
fn mask_weight<A: Arith>(ar: &mut A, r: &[A::E]) -> Vec<A::E> {
    let mut weight = Vec::with_capacity(mask_len(r.len()));
    weight.push(ar.one());
    for &ri in r {
        let sq = ar.square(ri);
        weight.extend([ri, sq]);
    }
    weight
}

/// Bind a table's lowest variable to `r`.
fn fold_low(table: &mut Vec<F192>, r: F192) {
    let half = table.len() / 2;
    for k in 0..half {
        table[k] = interp(table[2 * k], table[2 * k + 1], r);
    }
    table.truncate(half);
}

#[cfg(test)]
mod tests {
    use super::*;
    use fiat_shamir::{ProofTranscript, SessionId, VerifierState};
    use primitives::multilinear::eq_table as eq;
    use primitives::test_util::Rng;

    /// A random satisfied system of `n` rows, as its three sides.
    fn sides(rng: &mut Rng, n: usize) -> [Vec<F192>; 3] {
        let a = rng.ext_vec(n);
        let b = rng.ext_vec(n);
        let c = a.iter().zip(&b).map(|(&x, &y)| x * y).collect();
        [a, b, c]
    }

    fn run(sides: [Vec<F192>; 3], mask: &[F192]) -> (Claims, ProofTranscript) {
        let mut ps = ProverState::new(&SessionId::new(b"spartan-test"), &0u64);
        let claims = prove(&mut ps, sides, mask);
        (claims, ps.into_proof())
    }

    fn check(n_rows: usize, proof: &ProofTranscript) -> Result<Claims, TranscriptError> {
        let mut vs = VerifierState::new(&SessionId::new(b"spartan-test"), &0u64, proof);
        let claims = verify(&mut vs, n_rows)?;
        vs.check_eof()?;
        Ok(claims)
    }

    /// Whether both claims hold against the sides and the mask.
    fn holds(claims: &Claims, sides: &[Vec<F192>; 3], mask: &[F192]) -> bool {
        let e = eq(&claims.rows.point);
        let g = claims.rows.gamma;
        let rows = (0..sides[0].len()).fold(F192::ZERO, |acc, x| {
            acc + e[x] * (sides[0][x] + g * (sides[1][x] + g * sides[2][x]))
        });
        let mask_value = (mask.iter().zip(&claims.mask.weight)).fold(F192::ZERO, |acc, (&m, &w)| acc + m * w);
        rows == claims.rows.value && mask_value == claims.mask.value
    }

    #[test]
    fn honest_claims_hold() {
        // 300 rows: a cube of 2^9, its last 212 rows zero.
        let mut rng = Rng::new(1);
        let s = sides(&mut rng, 300);
        let mask = rng.ext_vec(mask_len(log_rows(300)));
        let (proved, proof) = run(s.clone(), &mask);
        let verified = check(300, &proof).unwrap();
        assert_eq!(proved, verified);
        assert!(holds(&verified, &s, &mask));
    }

    #[test]
    fn an_unsatisfied_row_fails_a_claim() {
        // Mutation: row 7's product is off by one, so F(7) = 1 and the sum is no longer zero.
        let mut rng = Rng::new(2);
        let mut s = sides(&mut rng, 300);
        s[2][7] += F192::ONE;
        let mask = rng.ext_vec(mask_len(log_rows(300)));
        let (_, proof) = run(s.clone(), &mask);
        let claims = check(300, &proof).unwrap();
        assert!(!holds(&claims, &s, &mask));
    }

    #[test]
    fn a_tampered_proof_fails_a_claim() {
        // The proof is s_g, then (c_1, c_2) per round, then (a, b, c): 24 bytes each.
        let mut rng = Rng::new(3);
        let s = sides(&mut rng, 300);
        let mask = rng.ext_vec(mask_len(log_rows(300)));
        let (_, proof) = run(s.clone(), &mask);
        let a = 1 + 2 * log_rows(300);
        for (what, at) in [("s_g", 0), ("a round coefficient", 3), ("a", a)] {
            let mut tampered = proof.clone();
            tampered.narg[24 * at] ^= 1;
            let refused = check(300, &tampered).map_or(true, |claims| !holds(&claims, &s, &mask));
            assert!(refused, "a tampered {what} is accepted");
        }
    }

    #[test]
    fn every_sent_scalar_moves_with_the_mask() {
        // One system, two masks: no scalar of one proof appears at the same place in the other.
        //
        // Without the mask, the rounds would be functions of the system alone.
        let mut rng = Rng::new(4);
        let s = sides(&mut rng, 300);
        let l = log_rows(300);
        let (_, first) = run(s.clone(), &rng.ext_vec(mask_len(l)));
        let (_, second) = run(s, &rng.ext_vec(mask_len(l)));
        let n = first.narg.len() / 24;
        // The last three, (a, b, c), are the system's own: the dummy rows hide them in the outer proof.
        for i in 0..n - 3 {
            assert_ne!(
                first.narg[24 * i..24 * (i + 1)],
                second.narg[24 * i..24 * (i + 1)],
                "scalar {i}"
            );
        }
    }
}
