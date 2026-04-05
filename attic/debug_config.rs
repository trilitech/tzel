use circuit_cairo_air::all_components::all_components;
use circuit_cairo_air::preprocessed_columns::PREPROCESSED_COLUMNS_ORDER;
use circuits_stark_verifier::constraint_eval::CircuitEval;
use circuits_stark_verifier::empty_component::EmptyComponent;
use circuits_stark_verifier::proof::ProofConfig;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;

pub fn debug_configs() {}

/// Build a ProofConfig that matches the actual proof by using the claim's enable bits.
/// Components disabled in the claim get EmptyComponent (0 columns).
pub fn build_proof_config_from_enable_bits(enable_bits: &[bool]) -> ProofConfig {
    let pcs = PcsConfig {
        pow_bits: 27,
        fri_config: FriConfig {
            log_blowup_factor: 3,
            log_last_layer_degree_bound: 0,
            n_queries: 23,
            fold_step: 4,
        },
        lifting_log_size: Some(23),
    };

    let all = all_components::<QM31>();
    assert_eq!(
        all.len(),
        enable_bits.len(),
        "enable_bits length mismatch"
    );

    let components: Vec<Box<dyn CircuitEval<QM31>>> = all
        .into_iter()
        .zip(enable_bits.iter())
        .map(|((_name, comp), &enabled)| {
            if enabled {
                comp
            } else {
                Box::new(EmptyComponent {}) as _
            }
        })
        .collect();

    ProofConfig::from_components(
        &components,
        PREPROCESSED_COLUMNS_ORDER.len(),
        &pcs,
        24,
    )
}
