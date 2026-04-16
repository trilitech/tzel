use tzel_core::{u64_to_felt, CircuitKind, ProgramHashes, Proof};
use tzel_verifier::validate_stark_circuit;

#[cfg(target_arch = "wasm32")]
fn verifier_probe_getrandom_unsupported(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(verifier_probe_getrandom_unsupported);

fn main() {
    let hashes = ProgramHashes {
        shield: u64_to_felt(11),
        transfer: u64_to_felt(22),
        unshield: u64_to_felt(33),
    };
    let proof = Proof::Stark {
        proof_bytes: vec![1, 2, 3],
        output_preimage: vec![u64_to_felt(22), u64_to_felt(1), u64_to_felt(2)],
        verify_meta: Some(vec![0]),
    };
    let _ = validate_stark_circuit(&proof, CircuitKind::Transfer, &hashes);
}
