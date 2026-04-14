use anyhow::{Result, anyhow};
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuits::blake::HashValue;
use circuits::ivalue::IValue;
use circuits_stark_verifier::proof::ProofConfig;
use circuits_stark_verifier::proof_from_stark_proof::pack_into_qm31s;
use starknet_types_core::hash::Blake2Felt252;
use starknet_types_core::felt::Felt;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use tzel_core::F as RawF;

fn raw_to_felt(raw: &RawF) -> Felt {
    Felt::from_bytes_le(raw)
}

fn qm31_to_m31s(q: QM31) -> Vec<u32> {
    vec![q.0.0.0, q.0.1.0, q.1.0.0, q.1.1.0]
}

fn compute_output_hash_values(output_preimage: &[Felt]) -> Vec<u32> {
    let outputs = Blake2Felt252::encode_felt252_data_and_calc_blake_hash(output_preimage);
    let outputs = stwo_cairo_common::prover_types::cpu::Felt252 {
        limbs: outputs.to_raw(),
    }
    .get_limbs();
    let output_qm31s = pack_into_qm31s(outputs.into_iter());
    let output_hash: HashValue<QM31> =
        QM31::blake(output_qm31s.as_slice(), output_qm31s.len() * 16);
    vec![output_hash.0, output_hash.1]
        .into_iter()
        .flat_map(qm31_to_m31s)
        .collect()
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyMeta {
    pub n_pow_bits: u32,
    pub n_preprocessed_columns: usize,
    pub n_trace_columns: usize,
    pub n_interaction_columns: usize,
    pub trace_columns_per_component: Vec<usize>,
    pub interaction_columns_per_component: Vec<usize>,
    pub cumulative_sum_columns: Vec<bool>,
    pub n_components: usize,
    pub fri_log_trace_size: usize,
    pub fri_log_blowup: u32,
    pub fri_log_last_layer: u32,
    pub fri_n_queries: usize,
    pub fri_fold_step: u32,
    pub interaction_pow_bits: u32,
    pub circuit_pow_bits: u32,
    pub circuit_fri_log_blowup: u32,
    pub circuit_fri_log_last_layer: u32,
    pub circuit_fri_n_queries: usize,
    pub circuit_fri_fold_step: u32,
    pub circuit_lifting: Option<u32>,
    pub output_addresses: Vec<usize>,
    pub n_blake_gates: usize,
    pub preprocessed_column_ids: Vec<String>,
    pub preprocessed_root: Vec<u32>,
    pub public_output_values: Vec<u32>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    #[serde(with = "tzel_core::hex_bytes")]
    pub proof_bytes: Vec<u8>,
    #[serde(with = "tzel_core::hex_f_vec")]
    pub output_preimage: Vec<RawF>,
    #[serde(default)]
    pub verify_meta: Option<VerifyMeta>,
}

impl ProofBundle {
    pub fn from_output_parts(
        proof_bytes: Vec<u8>,
        output_preimage: Vec<RawF>,
        verify_meta: VerifyMeta,
    ) -> Self {
        Self {
            proof_bytes,
            output_preimage,
            verify_meta: Some(verify_meta),
        }
    }

    pub fn proof_bytes(&self) -> Vec<u8> {
        self.proof_bytes.clone()
    }

    pub fn output_preimage_felts(&self) -> Vec<Felt> {
        self.output_preimage.iter().map(raw_to_felt).collect()
    }

    pub fn verify(&self) -> Result<()> {
        use circuit_air::verify::{CircuitConfig, CircuitPublicData, verify_circuit};

        let meta = self
            .verify_meta
            .as_ref()
            .ok_or_else(|| anyhow!("proof bundle missing verify_meta"))?;

        let preimage_felts = self.output_preimage_felts();
        let expected_output_hash_values = compute_output_hash_values(&preimage_felts);
        if meta.public_output_values.len() < expected_output_hash_values.len() {
            return Err(anyhow!("verify_meta public_output_values too short"));
        }
        if meta.public_output_values[..expected_output_hash_values.len()]
            != expected_output_hash_values
        {
            return Err(anyhow!(
                "output_preimage does not match verified public_output_values — the preimage may have been tampered with"
            ));
        }

        let proof_config = ProofConfig {
            n_proof_of_work_bits: meta.n_pow_bits,
            n_preprocessed_columns: meta.n_preprocessed_columns,
            n_trace_columns: meta.n_trace_columns,
            n_interaction_columns: meta.n_interaction_columns,
            trace_columns_per_component: meta.trace_columns_per_component.clone(),
            interaction_columns_per_component: meta.interaction_columns_per_component.clone(),
            cumulative_sum_columns: meta.cumulative_sum_columns.clone(),
            n_components: meta.n_components,
            fri: circuits_stark_verifier::fri_proof::FriConfig {
                log_trace_size: meta.fri_log_trace_size,
                log_blowup_factor: meta.fri_log_blowup as usize,
                n_queries: meta.fri_n_queries,
                log_n_last_layer_coefs: meta.fri_log_last_layer as usize,
                fold_step: meta.fri_fold_step as usize,
            },
            interaction_pow_bits: meta.interaction_pow_bits,
        };

        let qm31_from = |vals: &[u32]| -> QM31 {
            QM31::from_m31(
                M31::from(vals[0]),
                M31::from(vals[1]),
                M31::from(vals[2]),
                M31::from(vals[3]),
            )
        };

        let pr = &meta.preprocessed_root;
        let circuit_config = CircuitConfig {
            config: stwo::core::pcs::PcsConfig {
                pow_bits: meta.circuit_pow_bits,
                fri_config: stwo::core::fri::FriConfig {
                    log_blowup_factor: meta.circuit_fri_log_blowup,
                    log_last_layer_degree_bound: meta.circuit_fri_log_last_layer,
                    n_queries: meta.circuit_fri_n_queries,
                    fold_step: meta.circuit_fri_fold_step,
                },
                lifting_log_size: meta.circuit_lifting,
            },
            output_addresses: meta.output_addresses.clone(),
            n_blake_gates: meta.n_blake_gates,
            preprocessed_column_ids: meta
                .preprocessed_column_ids
                .iter()
                .map(
                    |s| stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId {
                        id: s.clone().into(),
                    },
                )
                .collect(),
            preprocessed_root: HashValue(qm31_from(&pr[0..4]), qm31_from(&pr[4..8])),
        };

        let public_data = CircuitPublicData {
            output_values: meta
                .public_output_values
                .chunks(4)
                .map(qm31_from)
                .collect(),
        };

        let compressed = self.proof_bytes();
        let proof_bytes =
            zstd::decode_all(&compressed[..]).map_err(|e| anyhow!("zstd decompress: {e}"))?;
        let mut data = proof_bytes.as_slice();
        let proof = deserialize_proof_with_config(&mut data, &proof_config)
            .map_err(|e| anyhow!("deserialize proof: {e}"))?;

        verify_circuit(circuit_config, proof, public_data)
            .map_err(|e| anyhow!("circuit verification FAILED: {e}"))?;

        Ok(())
    }
}
