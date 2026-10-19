//! The key commitment: every one-time-pad key, the outer proof's dummy operands and its mask.
//!
//! Its shape is fixed, so both sides know it before anything is sent:
//!
//! ```text
//!     lane 0      slots of E, three words each: 6 dummy operands, the mask, then the keys in the order they pad
//!     lanes 1-3   zero
//!     lanes 4-7   uniform: the hiding commitment's random group
//! ```
//!
//! Its openings hide themselves.
//!
//! - Their weight lives on lane 0 alone.
//! - The random group makes the lane-folded witness uniform, as for any hiding commitment.
//! - Before the lane fold, each round reveals the target and sums of the random lanes against the weight, which are uniform too.

use crate::randomness::{Purpose, Seed, uniform_e};
use crate::spartan::mask_len;
use fiat_shamir::ProverState;
use pcs::stack::{CommittedStack, StackCommitment, Weighted};
use pcs::verifier::OpeningVerifier;
use pcs::whir::{INITIAL_FOLDING_FACTOR, MIN_LOG_N_HIDING, WhirError, config_for_rate_hiding, hiding_lanes};
use primitives::field::{F64, F192};

/// The key stack's size: `2^KEY_MU` words, the smallest a hiding opening takes.
const KEY_MU: usize = MIN_LOG_N_HIDING;

/// The words of a lane.
const LANE: usize = 1 << (KEY_MU - INITIAL_FOLDING_FACTOR);

/// The lanes committed: lane 0, the zero lanes, then the random group.
const LANES: usize = hiding_lanes(1);

/// The slots of `E` lane 0 holds, three words each.
pub(crate) const N_SLOTS: usize = LANE / 3;

/// The first of the six dummy operands: two uniform pairs, then their products.
pub(crate) const DUMMY_SLOT: usize = 0;

/// The dummy operands.
const N_DUMMIES: usize = 6;

/// The first of the mask's coefficients.
pub(crate) const MASK_SLOT: usize = DUMMY_SLOT + N_DUMMIES;

/// The largest outer system, in variables of its row cube: the mask's room is sized for it.
pub(crate) const MAX_LOG_ROWS: usize = 24;

/// The first key.
pub(crate) const KEY_SLOT: usize = MASK_SLOT + mask_len(MAX_LOG_ROWS);

/// The most keys one proof uses: its hidden scalars, then its auxiliary values.
pub(crate) const MAX_KEYS: usize = N_SLOTS - KEY_SLOT;

/// A proof's keys, its outer proof's dummies and mask, committed: the prover's side of the key commitment.
pub struct Keys {
    /// Every slot of lane 0: dummy operands, mask, keys, all uniform but the dummies' two products.
    slots: Vec<F192>,
    /// The committed words: lane 0's slots, the zero lanes and the random group.
    words: Vec<F64>,
    /// The commitment to the words.
    committed: CommittedStack,
}

impl Keys {
    /// Draw a proof's keys, dummies and mask from its seed, commit them at L0 rate `2^-log_inv_rate`, and send the root.
    ///
    /// # Panics
    ///
    /// Panics on a rate the hiding table does not cover.
    #[must_use]
    pub fn commit(ps: &mut ProverState, log_inv_rate: usize, seed: &Seed) -> Self {
        let mut stream = seed.stream(Purpose::Keys);
        let mut slots: Vec<F192> = (0..N_SLOTS).map(|_| uniform_e(&mut stream)).collect();
        // The dummies' products, so that the dummy rows hold.
        slots[DUMMY_SLOT + 2] = slots[DUMMY_SLOT] * slots[DUMMY_SLOT + 1];
        slots[DUMMY_SLOT + 5] = slots[DUMMY_SLOT + 3] * slots[DUMMY_SLOT + 4];

        // Slot s is words 3s, 3s + 1 and 3s + 2 of lane 0, its limbs lowest first.
        let mut words = vec![F64::ZERO; LANES * LANE];
        for (slot, w) in slots.iter().zip(words.as_chunks_mut::<3>().0) {
            *w = [F64(slot.c0), F64(slot.c1), F64(slot.c2)];
        }
        let config = config_for_rate_hiding(KEY_MU, log_inv_rate).expect("a supported rate");
        let committed =
            CommittedStack::new_hiding(&mut words, KEY_MU, config, &mut seed.stream(Purpose::KeyCommitment));
        ps.prover_message(&committed.root());
        Self {
            slots,
            words,
            committed,
        }
    }

    /// The keys, in the order the hidden messages use them.
    #[must_use]
    pub fn keys(&self) -> &[F192] {
        &self.slots[KEY_SLOT..]
    }

    /// Every slot.
    pub(crate) fn slots(&self) -> &[F192] {
        &self.slots
    }

    /// The outer proof's mask for a system of `2^log_rows` rows.
    pub(crate) fn mask(&self, log_rows: usize) -> &[F192] {
        &self.slots[MASK_SLOT..MASK_SLOT + mask_len(log_rows)]
    }

    /// Prove `sum_s weights[s] slot_s = value`.
    #[expect(
        clippy::disallowed_methods,
        reason = "the outer proof's claim: its value and weights are functions of sent messages and earlier challenges"
    )]
    pub(crate) fn open(&self, ps: &mut ProverState, weights: &[F192], value: F192) {
        let weight = word_weights(weights, F192::ZERO, |w, y| w * y);
        self.committed
            .open_weighted(ps, &self.words, Weighted { weight: &weight, value });
    }
}

/// The key commitment as its verifier holds it.
///
/// Its root is a digest, or whatever a verifier holds it as.
pub struct KeyCommitment<R> {
    /// The commitment to the key stack.
    commitment: StackCommitment<R>,
}

impl<R: Copy> KeyCommitment<R> {
    /// Read the key commitment's root, for openings at L0 rate `2^-log_inv_rate`.
    ///
    /// # Errors
    ///
    /// Refuses a rate the hiding table does not cover, or a proof that ends first.
    pub fn read<V: OpeningVerifier<Root = R>>(v: &mut V, log_inv_rate: usize) -> Result<Self, WhirError> {
        let config = config_for_rate_hiding(KEY_MU, log_inv_rate)?;
        let root = v.next_root()?;
        Ok(Self {
            commitment: StackCommitment::new(root, KEY_MU, LANES, config),
        })
    }

    /// Verify the opening of `sum_s weights[s] slot_s = value`, a weight absent where it is zero.
    ///
    /// # Errors
    ///
    /// Refuses the opening as the hiding WHIR verifier does.
    #[expect(
        clippy::disallowed_methods,
        reason = "the outer proof's claim: its value and weights are functions of sent messages and earlier challenges"
    )]
    pub(crate) fn verify<V: OpeningVerifier<Root = R>>(
        &self,
        v: &mut V,
        weights: &[Option<V::E>],
        value: V::E,
    ) -> Result<(), WhirError> {
        let zero = v.zero();
        let weight = word_weights(weights, zero, |w, y| w.map_or(zero, |w| v.mul_const(w, y)));
        self.commitment.verify_weighted(v, Weighted { weight: &weight, value })
    }
}

/// Each slot's weight spread on lane 0's words: slot `s` is `w_0 + w_1 y + w_2 y^2` of its words `3s`, `3s + 1`, `3s + 2`.
///
/// `spread(w, y^l)` is word `3s + l`'s weight; the lane's words past the last slot weigh `zero`.
fn word_weights<W: Copy, E: Copy>(weights: &[W], zero: E, mut spread: impl FnMut(W, F192) -> E) -> Vec<E> {
    let powers = [F192::new(1, 0, 0), F192::new(0, 1, 0), F192::new(0, 0, 1)];
    let mut out = Vec::with_capacity(LANE);
    for &w in weights {
        out.extend(powers.map(|y| spread(w, y)));
    }
    out.resize(LANE, zero);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::randomness::Randomness;
    use fiat_shamir::{SessionId, VerifierState};
    use pcs::merkle::Hash;
    use primitives::test_util::Rng;

    #[test]
    fn a_key_opening_verifies_and_binds_its_claim() {
        // A claim on a few slots: a dummy, a mask coefficient, the first key and the last slot.
        let seed = Randomness::Fixed([5; 32]).seed();
        let session = SessionId::new(b"key-opening-test");
        let mut ps = ProverState::new(&session, &0u64);
        let keys = Keys::commit(&mut ps, 1, &seed);
        let mut rng = Rng::new(9);
        let mut weights = vec![None; N_SLOTS];
        for s in [DUMMY_SLOT, MASK_SLOT + 3, KEY_SLOT, N_SLOTS - 1] {
            weights[s] = Some(rng.ext());
        }
        let value =
            (weights.iter().zip(keys.slots())).fold(F192::ZERO, |acc, (w, &x)| acc + w.map_or(F192::ZERO, |w| w * x));
        let dense: Vec<F192> = weights.iter().map(|w| w.unwrap_or(F192::ZERO)).collect();
        keys.open(&mut ps, &dense, value);
        let proof = ps.into_proof();

        let check = |value: F192| -> Result<(), WhirError> {
            let mut vs = VerifierState::new(&session, &0u64, &proof);
            let commitment = KeyCommitment::<Hash>::read(&mut vs, 1).expect("a root");
            commitment.verify(&mut vs, &weights, value)?;
            vs.check_eof().map_err(WhirError::from)
        };
        assert_eq!(check(value), Ok(()));
        // Mutation: a value off by one, which the opening's terminal check refuses.
        assert!(check(value + F192::ONE).is_err());
    }
}
