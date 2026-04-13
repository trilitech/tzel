use clap::Parser;

#[derive(Parser)]
#[command(name = "gen-proof-bench-args")]
struct Cli {
    /// One of: shield, transfer, unshield
    kind: String,

    /// Input count for transfer/unshield
    n_inputs: Option<usize>,
}

fn main() {
    let cli = Cli::parse();
    let (_circuit, witness) =
        tzel_services::proof_bench::build_named_bench_witness(&cli.kind, cli.n_inputs)
            .unwrap_or_else(|e| panic!("{}", e));
    println!("{}", serde_json::to_string(&witness.args).unwrap());
}
