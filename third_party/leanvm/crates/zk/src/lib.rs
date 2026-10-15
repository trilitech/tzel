//! Zero knowledge by composition: a proof's scalars under one-time pads, and an outer proof that they pass the verifier's checks.
//!
//! - A recorder runs the verifier's own code over the padded transcript, its hidden values a linear graph over the keys.
//! - What it records is a rank-one system over the keys, which an outer zero-knowledge Spartan proves.
//! - The keys, the Spartan's dummies and its mask live in a hiding commitment of their own, whose opening discharges the Spartan's claims.

mod keys;
pub mod outer;
mod randomness;
mod record;
mod spartan;

pub use keys::{KeyCommitment, Keys};
pub use outer::OuterError;
pub use randomness::{Purpose, Randomness, Seed};
pub use record::{Node, Record, Recorder, Value};
