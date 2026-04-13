#![no_main]

use libfuzzer_sys::fuzz_target;
use tzel_core::canonical_wire::{
    decode_encrypted_note, decode_note_memo, decode_payment_address, decode_published_note,
};

fuzz_target!(|data: &[u8]| {
    let _ = decode_payment_address(data);
    if let Ok(enc) = decode_encrypted_note(data) {
        let _ = enc.validate();
    }
    let _ = decode_published_note(data);
    let _ = decode_note_memo(data);
});
