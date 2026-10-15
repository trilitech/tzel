//! The outer proof: the keys satisfy what the recorder recorded.
//!
//! After the recorded transcript, a zero-knowledge proof holds, in order:
//!
//! ```text
//!     hidden   each auxiliary value, under the keys after the hidden scalars'
//!     clear    the outer Spartan over the system's rows
//!     clear    the key commitment's opening of the Spartan's two claims, batched by one challenge
//! ```
//!
//! The system is a rank-one system over `z = (1, slots)`, the key stack's slots:
//!
//! ```text
//!     rows 0 .. n        the record's, over the keys
//!     rows n, n + 1      the dummies: z_0 z_1 = z_2 and z_3 z_4 = z_5, on fresh uniform slots
//! ```

use crate::keys::{DUMMY_SLOT, KEY_SLOT, KeyCommitment, Keys, MASK_SLOT, MAX_KEYS, MAX_LOG_ROWS, N_SLOTS};
use crate::record::{Record, Recorder};
use crate::spartan::{self, Claims, log_rows};
use fiat_shamir::arith::{Arith, Native};
use fiat_shamir::{ProverState, TranscriptError};
use pcs::verifier::OpeningVerifier;
use pcs::whir::WhirError;
use primitives::field::F192;
use thiserror::Error;

/// Why an outer proof is refused.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum OuterError {
    /// The transcript needs more keys than the key commitment holds.
    #[error("{keys} keys, more than the {max} the key commitment holds")]
    TooManyKeys {
        /// Keys the transcript takes.
        keys: usize,
        /// Keys the commitment holds.
        max: usize,
    },
    /// The system has more rows than its mask covers.
    #[error("2^{log_rows} outer rows, more than 2^{max}")]
    TooManyRows {
        /// The rows' variables.
        log_rows: usize,
        /// The most the mask covers.
        max: usize,
    },
    /// The proof ends early.
    #[error(transparent)]
    Transcript(#[from] TranscriptError),
    /// The key commitment's opening is refused.
    #[error("the key opening: {0}")]
    KeyOpening(WhirError),
}

/// The dummy rows: each row's three slots.
const DUMMY_ROWS: [[usize; 3]; 2] = [
    [DUMMY_SLOT, DUMMY_SLOT + 1, DUMMY_SLOT + 2],
    [DUMMY_SLOT + 3, DUMMY_SLOT + 4, DUMMY_SLOT + 5],
];

/// The system's rows: the record's, then the dummies.
const fn n_rows<E: Copy>(record: &Record<E>) -> usize {
    record.n_rows() + DUMMY_ROWS.len()
}

/// Check the record fits the key commitment.
const fn check_size<E: Copy>(record: &Record<E>) -> Result<(), OuterError> {
    let keys = record.n_keys() + record.n_aux();
    if keys > MAX_KEYS {
        return Err(OuterError::TooManyKeys { keys, max: MAX_KEYS });
    }
    let log_rows = log_rows(n_rows(record));
    if log_rows > MAX_LOG_ROWS {
        return Err(OuterError::TooManyRows {
            log_rows,
            max: MAX_LOG_ROWS,
        });
    }
    Ok(())
}

/// The key opening's claim: the rows' claim pulled back onto the slots, plus `lambda` times the mask's claim.
///
/// ```text
///     sum_s weights[s] slot_s  =  rows' value + constant + lambda g(r)     (characteristic two)
/// ```
fn opening_claim<A: Arith>(
    ar: &mut A,
    record: &Record<A::E>,
    claims: &Claims<A::E>,
    sent: &[A::E],
    lambda: A::E,
) -> (Vec<Option<A::E>>, A::E) {
    // Row x takes eq(r, x) on A, gamma eq(r, x) on B, gamma^2 eq(r, x) on C.
    let rows = &claims.rows;
    let eq = ar.eq_table_prefix(&rows.point, n_rows(record));
    let on_b: Vec<A::E> = eq.iter().map(|&e| ar.mul(e, rows.gamma)).collect();
    let on_c: Vec<A::E> = on_b.iter().map(|&e| ar.mul(e, rows.gamma)).collect();
    let mut slots = vec![None; N_SLOTS];
    let mut bump = |ar: &mut A, slot: usize, w: A::E| {
        slots[slot] = Some(slots[slot].map_or(w, |s| ar.add(s, w)));
    };

    // The record's rows, on the keys.
    let n = record.n_rows();
    let keys = record.weigh(ar, [&eq[..n], &on_b[..n], &on_c[..n]], sent);
    for (i, w) in keys.keys.into_iter().enumerate() {
        if let Some(w) = w {
            bump(ar, KEY_SLOT + i, w);
        }
    }

    // The dummy rows, on their slots.
    for (d, row) in DUMMY_ROWS.iter().enumerate() {
        for (&slot, weights) in row.iter().zip([&eq, &on_b, &on_c]) {
            bump(ar, slot, weights[n + d]);
        }
    }

    // The mask's claim, scaled by lambda, on the mask's slots.
    for (i, &w) in claims.mask.weight.iter().enumerate() {
        let lw = ar.mul(lambda, w);
        bump(ar, MASK_SLOT + i, lw);
    }

    let value = ar.add(rows.value, keys.constant);
    let value = ar.mul_add(lambda, claims.mask.value, value);
    (slots, value)
}

/// Prove the outer proof of a recorded transcript.
///
/// - `record` is what the prover's replay of its own proof recorded.
/// - `ps` has sent exactly the record's hidden scalars, under the keys' first keys.
///
/// # Panics
///
/// Panics if the record outgrows the key commitment.
///
/// Keys that do not satisfy the record give a proof the verifier refuses.
pub fn prove(ps: &mut ProverState, record: &Record<F192>, keys: &Keys) {
    if let Err(e) = check_size(record) {
        panic!("the outer proof: {e}");
    }
    assert_eq!(
        ps.keys_used(),
        record.n_keys(),
        "the replay read every hidden scalar the prover sent"
    );

    // The auxiliary values, each under its key: what goes out is the value plus the key.
    let values = record.evaluate(keys.keys());
    let sent: Vec<F192> = (values.aux().iter().zip(&keys.keys()[record.n_keys()..]))
        .map(|(&v, &k)| v + k)
        .collect();
    ps.set_hidden(true);
    ps.prover_messages(values.aux());
    ps.set_hidden(false);

    // The Spartan over the record's rows, then the dummies.
    let mut sides = record.sides(&values);
    for row in DUMMY_ROWS {
        for (side, slot) in sides.iter_mut().zip(row) {
            side.push(keys.slots()[slot]);
        }
    }
    let claims = spartan::prove(ps, sides, keys.mask(log_rows(n_rows(record))));

    // The key opening, its two claims batched.
    let lambda: F192 = ps.verifier_message();
    let (slots, value) = opening_claim(&mut Native, record, &claims, &sent, lambda);
    let weights: Vec<F192> = slots.iter().map(|w| w.unwrap_or(F192::ZERO)).collect();
    keys.open(ps, &weights, value);
}

/// Verify the outer proof of a recorded transcript, the recorder having read the transcript up to it.
///
/// It returns the inner verifier, for the caller to check the proof's end.
///
/// # Errors
///
/// Refuses a record the key commitment cannot hold, a malformed proof, or a key opening its verifier refuses.
pub fn verify<V: OpeningVerifier>(recorder: Recorder<V>, commitment: &KeyCommitment<V::Root>) -> Result<V, OuterError> {
    let (mut v, record) = recorder.finish();
    check_size(&record)?;

    // The auxiliary values as sent: each is that plus the next key.
    let sent = v.prover_messages(record.n_aux())?;

    let claims = spartan::verify(&mut v, n_rows(&record))?;
    let lambda = v.verifier_message();
    let (slots, value) = opening_claim(&mut v, &record, &claims, &sent, lambda);
    commitment
        .verify(&mut v, &slots, value)
        .map_err(OuterError::KeyOpening)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::randomness::Randomness;
    use fiat_shamir::{ProofTranscript, SessionId, VerifierState};

    const SESSION: &[u8] = b"outer-test";

    /// A toy protocol's prover: it sends `x, y, x y, 1 / x` and a bit hidden, then `x + y` in the clear.
    ///
    /// `forge` replaces what it sends for `(x y, 1 / x, bit)`.
    fn prove_toy(seed: u8, x: F192, y: F192, forge: Option<[F192; 3]>) -> ProofTranscript {
        let seed = Randomness::Fixed([seed; 32]).seed();
        let mut ps = ProverState::new(&SessionId::new(SESSION), &0u64);
        let keys = Keys::commit(&mut ps, 1, &seed);
        ps.set_keys(keys.keys().to_vec());

        // The hidden part of the transcript.
        let [xy, inv, bit] = forge.unwrap_or_else(|| [x * y, x.inv(), F192::ONE]);
        ps.set_hidden(true);
        ps.prover_messages(&[x, y, xy, inv, bit]);
        ps.set_hidden(false);
        ps.prover_message(&(x + y));

        // The prover replays the verifier over its own proof, then proves the outer proof.
        let replay = ps.proof().clone();
        let mut recorder = Recorder::new(VerifierState::new(&SessionId::new(SESSION), &0u64, &replay));
        let _ = verify_toy(&mut recorder);
        let (_, record) = recorder.finish();
        prove(&mut ps, &record, &keys);
        ps.into_proof()
    }

    /// The toy protocol's verifier, generic over the verifier it runs on: it returns the key commitment.
    fn verify_toy<V: OpeningVerifier>(v: &mut V) -> Result<KeyCommitment<V::Root>, WhirError> {
        let commitment = KeyCommitment::read(v, 1)?;
        v.set_hidden(true);
        let [x, y, xy, inv, bit] = std::array::from_fn(|_| v.prover_message().unwrap_or_else(|_| v.zero()));
        v.set_hidden(false);
        let sum = v.prover_message()?;
        // x y = xy, x / x = 1 through the inverse's own row, a bit, and the clear sum.
        let p = v.mul(x, y);
        v.ensure_eq(p, xy, || ()).ok();
        let q = v.mul(x, inv);
        let one = v.one();
        v.ensure_eq(q, one, || ()).ok();
        let b2 = v.mul(bit, bit);
        v.ensure_eq(b2, bit, || ()).ok();
        let s = v.add(x, y);
        v.ensure_eq(s, sum, || ()).ok();
        Ok(commitment)
    }

    /// Verify a toy proof whole.
    fn check(proof: &ProofTranscript) -> Result<(), OuterError> {
        let vs = VerifierState::new(&SessionId::new(SESSION), &0u64, proof);
        let mut recorder = Recorder::new(vs);
        let commitment = verify_toy(&mut recorder).map_err(OuterError::KeyOpening)?;
        let vs = verify(recorder, &commitment)?;
        vs.check_eof()?;
        Ok(())
    }

    #[test]
    fn an_honest_outer_proof_verifies() {
        let (x, y) = (F192::new(3, 5, 7), F192::new(11, 13, 17));
        assert_eq!(check(&prove_toy(1, x, y, None)), Ok(()));
    }

    #[test]
    fn a_false_hidden_statement_is_refused() {
        // Each forgery breaks one recorded row while the clear part still checks.
        //
        //     x y + 1   breaks the product row
        //     1/x + 1   breaks the inverse's equality
        //     bit = y   breaks the bit's row
        let (x, y) = (F192::new(3, 5, 7), F192::new(11, 13, 17));
        for forged in [
            [x * y + F192::ONE, x.inv(), F192::ONE],
            [x * y, x.inv() + F192::ONE, F192::ONE],
            [x * y, x.inv(), y],
        ] {
            assert!(check(&prove_toy(1, x, y, Some(forged))).is_err(), "forgery {forged:?}");
        }
    }

    #[test]
    fn a_tampered_auxiliary_value_is_refused() {
        // The toy's auxiliary values follow its 32-byte root and six scalars.
        let (x, y) = (F192::new(3, 5, 7), F192::new(11, 13, 17));
        let mut forged = prove_toy(1, x, y, None);
        forged.narg[32 + 6 * 24] ^= 1;
        assert!(check(&forged).is_err());
    }

    #[test]
    fn two_witnesses_send_unrelated_scalars() {
        // Same shape, other witness, other randomness: every hidden scalar differs.
        let a = prove_toy(1, F192::new(3, 5, 7), F192::new(11, 13, 17), None);
        let b = prove_toy(2, F192::new(4, 6, 8), F192::new(12, 14, 16), None);
        assert_eq!(a.narg.len(), b.narg.len());
        let hidden = 32..32 + 5 * 24;
        assert!((hidden.step_by(24)).all(|i| a.narg[i..i + 24] != b.narg[i..i + 24]));
    }
}
