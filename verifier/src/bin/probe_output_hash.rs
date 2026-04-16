use circuits::ivalue::IValue;
use circuits_stark_verifier::proof_from_stark_proof::pack_into_qm31s;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::Blake2Felt252;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;

const FELT252_N_WORDS: usize = 28;
const FELT252_BITS_PER_WORD: usize = 9;

#[cfg(target_arch = "wasm32")]
fn verifier_probe_getrandom_unsupported(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(verifier_probe_getrandom_unsupported);

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

fn main() {
    let data = [Felt::from(1u64), Felt::from(2u64), Felt::from(3u64)];
    let outputs = Blake2Felt252::encode_felt252_data_and_calc_blake_hash(&data);
    let output_words = felt252_to_m31_words(outputs);
    let output_qm31s = pack_into_qm31s(output_words.into_iter());
    let _ = QM31::blake(output_qm31s.as_slice(), output_qm31s.len() * 16);
}
