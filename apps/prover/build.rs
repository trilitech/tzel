//! Emits the `tzel_insecure_sandbox` cfg for THIS crate only, from the
//! `TZEL_INSECURE_SANDBOX=1` build-time env var. See
//! `tezos/rollup-kernel/build.rs` for the full rationale: scoping the cfg to
//! this crate (instead of a global `RUSTFLAGS=--cfg`) keeps the heavy prover
//! deps (stwo, cairo-lang-*, lambdaworks) on their no-cfg fingerprint so they
//! are reused across the prod and sandbox builds instead of recompiled.

fn main() {
    println!("cargo:rerun-if-env-changed=TZEL_INSECURE_SANDBOX");
    if std::env::var("TZEL_INSECURE_SANDBOX").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=tzel_insecure_sandbox");
    }
}
