#![no_main]

use libfuzzer_sys::fuzz_target;
use tzel_core::{felt_to_u64, felt_to_usize};

fuzz_target!(|felt: [u8; 32]| {
    let _ = felt_to_u64(&felt);
    let _ = felt_to_usize(&felt);
});
