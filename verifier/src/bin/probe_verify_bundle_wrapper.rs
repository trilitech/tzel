use tzel_core::{u64_to_felt, Proof};
use tzel_verifier::verify_stark_bundle;

#[cfg(target_arch = "wasm32")]
fn verifier_probe_getrandom_unsupported(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(verifier_probe_getrandom_unsupported);

fn main() {
    let proof = Proof::Stark {
        proof_bytes: vec![1, 2, 3],
        output_preimage: vec![u64_to_felt(22), u64_to_felt(1), u64_to_felt(2)],
        verify_meta: Some(vec![0]),
    };
    let _ = verify_stark_bundle(&proof);
}
