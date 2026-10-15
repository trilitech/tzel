//! A zero-knowledge prover's randomness: ChaCha20 under a seed from the operating system.
//!
//! Nothing it draws comes from the transcript.
//!
//! A proof drawn from the transcript alone would be a function of the witness, which a verifier could recompute for each guess.

use primitives::field::F192;
use rand_chacha::ChaCha20Rng;
#[cfg(not(target_arch = "wasm32"))]
use rand_core::{OsRng, TryRngCore};
use rand_core::{RngCore, SeedableRng};
use std::fmt::{self, Debug, Formatter};

/// Where a zero-knowledge prover draws its randomness.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Randomness {
    /// A fresh seed from the operating system for every proof.
    Os,
    /// One fixed seed, for reproducible tests.
    ///
    /// Two proofs under one seed share their keys: their difference shows the difference of their hidden values.
    #[doc(hidden)]
    Fixed([u8; 32]),
}

impl Randomness {
    /// One proof's seed.
    ///
    /// # Panics
    ///
    /// Panics if the operating system gives no randomness.
    #[must_use]
    pub fn seed(self) -> Seed {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::Os => {
                let mut seed = [0u8; 32];
                OsRng
                    .try_fill_bytes(&mut seed)
                    .expect("the operating system gives randomness");
                Seed(seed)
            }
            #[cfg(target_arch = "wasm32")]
            Self::Os => panic!("Randomness::Os is not available on wasm32 targets"),
            Self::Fixed(seed) => Seed(seed),
        }
    }
}

impl Debug for Randomness {
    /// A fixed seed is never printed: it is a proof's secret.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os => f.write_str("Os"),
            Self::Fixed(_) => f.write_str("Fixed(..)"),
        }
    }
}

/// One proof's secret seed, cut into an independent stream per purpose.
///
/// It is neither printed nor copied.
pub struct Seed([u8; 32]);

impl Seed {
    /// The stream drawn for a purpose: ChaCha20 under the seed, at the purpose's own stream number.
    #[must_use]
    pub fn stream(&self, purpose: Purpose) -> ChaCha20Rng {
        let mut rng = ChaCha20Rng::from_seed(self.0);
        rng.set_stream(purpose as u64);
        rng
    }
}

/// What a stream of a proof's randomness is drawn for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// The one-time-pad keys, the outer proof's dummy operands and its mask.
    Keys = 0,
    /// The main commitment's random group and padding.
    Commitment = 1,
    /// The key commitment's random group and padding.
    KeyCommitment = 2,
}

/// A uniform element of `E`.
pub(crate) fn uniform_e(rng: &mut impl RngCore) -> F192 {
    F192::new(rng.next_u64(), rng.next_u64(), rng.next_u64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_purpose_draws_its_own_stream() {
        // One seed, two purposes: no word of one stream is the other's at the same place.
        let seed = Randomness::Fixed([9; 32]).seed();
        let (mut keys, mut stack) = (seed.stream(Purpose::Keys), seed.stream(Purpose::Commitment));
        assert!((0..64).all(|_| keys.next_u64() != stack.next_u64()));
    }

    #[test]
    fn a_fixed_seed_is_never_printed() {
        assert_eq!(format!("{:?}", Randomness::Fixed([0xAB; 32])), "Fixed(..)");
    }
}
