use circuit_air::verify::{verify_circuit, CircuitConfig, CircuitPublicData};
use circuits::context::Context;
use circuits_stark_verifier::proof::Proof;
use stwo::core::fields::qm31::QM31;

#[cfg(target_arch = "wasm32")]
fn verifier_probe_getrandom_unsupported(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(verifier_probe_getrandom_unsupported);

fn main() {
    let f: fn(CircuitConfig, Proof<QM31>, CircuitPublicData) -> Result<Context<QM31>, String> =
        verify_circuit;
    let _ = f as usize;
}
