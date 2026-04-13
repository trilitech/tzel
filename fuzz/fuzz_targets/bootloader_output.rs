#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tzel_core::parse_single_task_output_preimage;

#[derive(Arbitrary, Debug)]
struct FeltVec {
    items: Vec<[u8; 32]>,
}

fuzz_target!(|input: FeltVec| {
    let _ = parse_single_task_output_preimage(&input.items);
});
