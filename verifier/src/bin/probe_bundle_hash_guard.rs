use tzel_core::u64_to_felt;
use tzel_verifier::{ProofBundle, VerifyMeta};

#[cfg(target_arch = "wasm32")]
fn verifier_probe_getrandom_unsupported(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(verifier_probe_getrandom_unsupported);

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
    let bundle = ProofBundle {
        proof_bytes: vec![1, 2, 3],
        output_preimage,
        verify_meta: Some(sample_meta(vec![0; 8])),
    };
    let _ = bundle.verify();
}
