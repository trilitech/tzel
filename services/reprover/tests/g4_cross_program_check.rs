//! G4 sanity check — does the multiverifier need a `enable_bits` prologue,
//! or do shield + transfer already produce identical Cairo verifier
//! topologies via the bootloader's normalization?
//!
//! Generates one leaf per program (shield + transfer) and prints:
//!   - enable_bits (which Cairo AIR components fired)
//!   - n_enabled / n_total
//!   - component_log_sizes (per-component trace log sizes)
//!   - whether the two leaves have matching enable_bits AND log_sizes
//!
//! If they match → cross-program aggregation works without a prologue;
//! G4 (force enable_bits canonical) is unnecessary for the current TZEL
//! programs, can be deferred.
//!
//! If they differ → G4 must build a Cairo prologue that exercises every
//! whitelisted opcode + builtin once, so all programs share a shape.
//!
//! Heavy (~80s for 2 leaves). Marked `#[ignore]`.

use std::path::PathBuf;

use cairo_air::flat_claims::FlatClaim;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo_cairo_prover::prover::prove_cairo;
use tzel_reprover::run_privacy_bootloader;

const CAIRO_PROVER_PARAMS: stwo_cairo_prover::prover::ProverParameters =
    privacy_prove::consts::CAIRO_PROVER_PARAMS;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("cairo/target/dev")
        .join(name)
}

fn args_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn dump_one(label: &str, exe: &str, args: &str) -> (Vec<bool>, Vec<u32>) {
    let exe_path = fixture(exe);
    let args_path = args_fixture(args);
    assert!(exe_path.exists(), "{} missing", exe_path.display());
    assert!(args_path.exists(), "{} missing", args_path.display());

    let (prover_input, _output) =
        run_privacy_bootloader(&exe_path, None, Some(args_path)).expect("bootloader");

    let t = std::time::Instant::now();
    let cairo_proof = prove_cairo::<Blake2sM31MerkleChannel>(prover_input, CAIRO_PROVER_PARAMS)
        .expect("cairo prove");
    eprintln!("[G4-CHECK] {} cairo proof in {:?}", label, t.elapsed());

    let FlatClaim {
        component_enable_bits,
        component_log_sizes,
        ..
    } = cairo_proof.claim.flatten_claim();
    let n_enabled = component_enable_bits.iter().filter(|&&b| b).count();
    eprintln!(
        "[G4-CHECK] {} : {} enabled / {} total components",
        label,
        n_enabled,
        component_enable_bits.len()
    );
    eprintln!("[G4-CHECK] {} enable_bits = {:?}", label, component_enable_bits);
    eprintln!(
        "[G4-CHECK] {} log_sizes = {:?}",
        label, component_log_sizes
    );
    (component_enable_bits, component_log_sizes)
}

#[test]
#[ignore]
fn shield_vs_transfer_topology() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let (shield_bits, shield_logs) =
        dump_one("shield", "run_shield.executable.json", "run_shield_args.json");
    let (transfer_bits, transfer_logs) = dump_one(
        "transfer",
        "run_transfer.executable.json",
        "run_transfer_args.json",
    );

    let same_bits = shield_bits == transfer_bits;
    let same_logs = shield_logs == transfer_logs;

    eprintln!("[G4-CHECK] enable_bits identical: {}", same_bits);
    eprintln!("[G4-CHECK] log_sizes identical:  {}", same_logs);

    if same_bits && same_logs {
        eprintln!(
            "[G4-CHECK] ✓ shield + transfer share an IDENTICAL Cairo AIR topology.\n\
                       The privacy bootloader already normalizes them. G4 (enable_bits\n\
                       canonical prologue) is NOT required for the current TZEL\n\
                       programs — cross-program aggregation should work directly."
        );
    } else {
        eprintln!("[G4-CHECK] ✗ topology mismatch between shield and transfer.");
        if !same_bits {
            let diff_count: usize = shield_bits
                .iter()
                .zip(transfer_bits.iter())
                .filter(|(a, b)| a != b)
                .count();
            eprintln!(
                "[G4-CHECK]   enable_bits differ in {} positions out of {}",
                diff_count,
                shield_bits.len()
            );
        }
        if !same_logs {
            eprintln!(
                "[G4-CHECK]   log_sizes differ — even if enable_bits match,\n\
                          per-component trace sizes still drift. Pure enable_bits\n\
                          normalization isn't enough; need log_size normalization too."
            );
        }
    }
}
