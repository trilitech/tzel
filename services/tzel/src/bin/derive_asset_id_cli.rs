//! Print the L2 asset_id (hex) that the kernel derives for a given
//! FA2 ticketer KT1 address. Used by `scripts/originate_fa2_bridge.sh`
//! to keep the printed asset_id in lock-step with whatever
//! `tzel_core::derive_asset_id` actually computes — no risk of the
//! shell script and the kernel disagreeing about the derivation.
//!
//! Usage:
//!   cargo run --package tzel-services --bin derive_asset_id_cli -- <KT1...>
//!
//! Prints the asset_id as 64 lowercase hex chars on stdout. Any
//! parsing or hash error is printed to stderr and the program exits
//! with status 1.
//!
//! The input is routed through `validate_l1_ticketer_canonical` before
//! hashing: whitespace is trimmed, the address must be a KT1
//! (Originated) string, and the b58check round-trip must be exact.
//! Non-canonical input (e.g. a clipboard paste with a trailing
//! newline) is REJECTED rather than silently hashed to a divergent
//! `asset_id` that would never match what the kernel computes.

use tzel_core::{derive_asset_id, validate_l1_ticketer_canonical};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        eprintln!("usage: derive_asset_id_cli <ticketer-KT1-address>");
        std::process::exit(64);
    }
    let ticketer = match validate_l1_ticketer_canonical(&args[0]) {
        Ok(canonical) => canonical,
        Err(e) => {
            eprintln!("derive_asset_id_cli: {}", e);
            std::process::exit(1);
        }
    };
    let asset_id = derive_asset_id(&ticketer);
    println!("{}", hex::encode(asset_id));
}
