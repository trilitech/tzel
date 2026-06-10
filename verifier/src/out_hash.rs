//! `compute_output_hash_values` — the leaf-statement output-hash derivation
//! shared by [`crate::snark`] (the Groth16 `verify_snark` OutHash binding).
//!
//! Stage-1 of the chip's `expected_OutHash` (see `snark.rs` module docs):
//! `Blake2Felt252` over the bootloader `output_preimage`, split into 28 ×
//! 9-bit M31 limbs, packed into QM31s, then `QM31::blake` → the 8-lane
//! `output_hash` (2 QM31s). The remaining stages live in `snark.rs`.

use circuits::blake::HashValue;
use circuits::ivalue::IValue;
use circuits_stark_verifier::proof_from_stark_proof::pack_into_qm31s;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::Blake2Felt252;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;

const FELT252_N_WORDS: usize = 28;
const FELT252_BITS_PER_WORD: usize = 9;

fn qm31_to_m31s(q: QM31) -> Vec<u32> {
    vec![q.0 .0 .0, q.0 .1 .0, q.1 .0 .0, q.1 .1 .0]
}

fn felt252_to_m31_words(value: Felt) -> [M31; FELT252_N_WORDS] {
    let limbs = value.to_le_digits();
    std::array::from_fn(|index| {
        let mask = (1u64 << FELT252_BITS_PER_WORD) - 1;
        let shift = FELT252_BITS_PER_WORD * index;
        let low_limb = shift / 64;
        let shift_low = shift & 0x3f;
        let high_limb = (shift + FELT252_BITS_PER_WORD - 1) / 64;
        let word = if low_limb == high_limb {
            (limbs[low_limb] >> shift_low) & mask
        } else {
            ((limbs[low_limb] >> shift_low) | (limbs[high_limb] << (64 - shift_low))) & mask
        };
        M31::from(word as u32)
    })
}

pub(crate) fn compute_output_hash_values(output_preimage: &[Felt]) -> Vec<u32> {
    let outputs = Blake2Felt252::encode_felt252_data_and_calc_blake_hash(output_preimage);
    let outputs = felt252_to_m31_words(outputs);
    let output_qm31s = pack_into_qm31s(outputs.into_iter());
    let output_hash: HashValue<QM31> =
        QM31::blake(output_qm31s.as_slice(), output_qm31s.len() * 16);
    vec![output_hash.0, output_hash.1]
        .into_iter()
        .flat_map(qm31_to_m31s)
        .collect()
}
