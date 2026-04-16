use anyhow::Result;
use tzel_verifier::ProofBundle;

#[cfg(target_arch = "wasm32")]
fn verifier_probe_getrandom_unsupported(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(verifier_probe_getrandom_unsupported);

fn main() {
    let bundle = ProofBundle {
        proof_bytes: Vec::new(),
        output_preimage: Vec::new(),
        verify_meta: None,
    };
    let _ = bundle.verify();
}
