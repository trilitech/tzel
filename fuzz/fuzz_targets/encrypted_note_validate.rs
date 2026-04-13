#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tzel_core::EncryptedNote;

#[derive(Arbitrary, Debug)]
struct FuzzEncryptedNote {
    ct_d: Vec<u8>,
    tag: u16,
    ct_v: Vec<u8>,
    encrypted_data: Vec<u8>,
}

fuzz_target!(|input: FuzzEncryptedNote| {
    let enc = EncryptedNote {
        ct_d: input.ct_d,
        tag: input.tag,
        ct_v: input.ct_v,
        encrypted_data: input.encrypted_data,
    };
    let _ = enc.validate();
});
