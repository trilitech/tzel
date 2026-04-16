use circuits::ivalue::IValue;
use circuits_stark_verifier::proof_from_stark_proof::pack_into_qm31s;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::Blake2Felt252;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use tzel_core::u64_to_felt;
use tzel_verifier::{ProofBundle, VerifyMeta};

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

fn compute_public_output_values(output_preimage: &[tzel_core::F]) -> Vec<u32> {
    let output_felts = output_preimage
        .iter()
        .copied()
        .map(|bytes| Felt::from_bytes_le(&bytes))
        .collect::<Vec<_>>();
    let output_hash = Blake2Felt252::encode_felt252_data_and_calc_blake_hash(&output_felts);
    let output_words = felt252_to_m31_words(output_hash);
    let output_qm31s = pack_into_qm31s(output_words.into_iter());
    let output_hash = QM31::blake(output_qm31s.as_slice(), output_qm31s.len() * 16);
    vec![output_hash.0, output_hash.1]
        .into_iter()
        .flat_map(|q| [q.0 .0 .0, q.0 .1 .0, q.1 .0 .0, q.1 .1 .0])
        .collect()
}

fn sample_meta(public_output_values: Vec<u32>) -> VerifyMeta {
    VerifyMeta {
        n_pow_bits: 0,
        n_preprocessed_columns: 0,
        n_trace_columns: 0,
        n_interaction_columns: 0,
        trace_columns_per_component: Vec::new(),
        interaction_columns_per_component: Vec::new(),
        cumulative_sum_columns: Vec::new(),
        n_components: 0,
        fri_log_trace_size: 0,
        fri_log_blowup: 0,
        fri_log_last_layer: 0,
        fri_n_queries: 0,
        fri_fold_step: 0,
        interaction_pow_bits: 0,
        circuit_pow_bits: 0,
        circuit_fri_log_blowup: 0,
        circuit_fri_log_last_layer: 0,
        circuit_fri_n_queries: 0,
        circuit_fri_fold_step: 0,
        circuit_lifting: None,
        output_addresses: Vec::new(),
        n_blake_gates: 0,
        preprocessed_column_ids: Vec::new(),
        preprocessed_root: vec![0; 8],
        public_output_values,
    }
}

fn main() {
    let output_preimage = vec![u64_to_felt(22), u64_to_felt(1), u64_to_felt(2)];
    let proof_bytes = zstd::encode_all(&[][..], 0).unwrap();
    let bundle = ProofBundle {
        proof_bytes,
        output_preimage: output_preimage.clone(),
        verify_meta: Some(sample_meta(compute_public_output_values(&output_preimage))),
    };
    let _ = bundle.verify();
}
