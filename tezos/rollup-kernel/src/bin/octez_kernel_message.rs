use std::env;

use hex::encode as hex_encode;
use tzel_core::kernel_wire::{encode_kernel_inbox_message, KernelBridgeConfig, KernelInboxMessage};

fn usage() -> ! {
    eprintln!("usage: octez_kernel_message configure-bridge <KT1...>");
    std::process::exit(2);
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        usage();
    };

    let message = match cmd.as_str() {
        "configure-bridge" => {
            let Some(ticketer) = args.next() else {
                usage();
            };
            if args.next().is_some() {
                usage();
            }
            KernelInboxMessage::ConfigureBridge(KernelBridgeConfig { ticketer })
        }
        _ => usage(),
    };

    let encoded = encode_kernel_inbox_message(&message).expect("kernel message should encode");
    println!("{}", hex_encode(encoded));
}
