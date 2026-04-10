use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    /// Write output to this file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Emit the canonical wire fixture instead of the protocol vectors file.
    #[arg(long)]
    canonical_wire: bool,
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    let json = if args.canonical_wire {
        tzel_services::canonical_wire::generate_canonical_wire_v1_json()
    } else {
        tzel_services::protocol_vectors::generate_protocol_v1_json()
    };
    if let Some(output) = args.output {
        std::fs::write(&output, json)
            .map_err(|e| format!("failed to write {}: {}", output.display(), e))?;
    } else {
        println!("{}", json);
    }
    Ok(())
}
