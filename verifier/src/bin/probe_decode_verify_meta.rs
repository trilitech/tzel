use tzel_verifier::decode_verify_meta;

#[cfg(target_arch = "wasm32")]
fn verifier_probe_getrandom_unsupported(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(verifier_probe_getrandom_unsupported);

fn main() {
    let _ = decode_verify_meta(&[0]);
}
