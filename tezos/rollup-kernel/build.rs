//! Emits the `tzel_insecure_sandbox` cfg for THIS crate only, from the
//! `TZEL_INSECURE_SANDBOX=1` build-time env var.
//!
//! Why a build.rs instead of a global `RUSTFLAGS=--cfg tzel_insecure_sandbox`:
//! RUSTFLAGS is applied to EVERY crate in the dependency graph, so it changes
//! the fingerprint of the heavy prover/cairo deps (stwo, cairo-lang-*,
//! lambdaworks, …) even though they never read the cfg — forcing a full,
//! redundant recompile of them under the cfg fingerprint (separate from the
//! prod no-cfg build). Emitting the cfg from this crate's build.rs scopes it
//! to `tzel-rollup-kernel` alone: the deps keep their no-cfg fingerprint and
//! are reused across the prod and sandbox builds; only this crate recompiles
//! when the flag flips.
//!
//! Security: this is the SAME compile-time, env-gated mechanism as before
//! (no prod build sets `TZEL_INSECURE_SANDBOX`; the consumer scrubs it
//! alongside RUSTFLAGS and greps the artifact for the
//! `TZEL_INSECURE_SANDBOX_PROOF_SKIP` canary). The cfg is NOT a cargo feature,
//! so it cannot be enabled via transitive feature unification.

fn main() {
    println!("cargo:rerun-if-env-changed=TZEL_INSECURE_SANDBOX");
    if std::env::var("TZEL_INSECURE_SANDBOX").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=tzel_insecure_sandbox");
    }
}
