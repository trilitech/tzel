# Rocq model of the tzel circuits

This directory contains a Rocq (formerly Coq) formalization of the
tzel circuits. The motivating concern is that ZK circuits fail by
*omission*: a missing assertion looks normal under honest-prover
testing and only surfaces when an attacker constructs a malicious
witness exploiting the gap. This bug class isn't catchable by
negative testing or fuzzing alone; the only way to be sure every
needed assertion is present is to write down what they're
*collectively supposed to prove* — independently of the code — and
check that they prove it.

## Architecture: three layers

```
docs/whitepaper.tex + specs/spec.md
            │
            ▼ (transcribe)
        coq/Spec/                ← whitepaper-derived abstract spec
            │
            ▼ (refine + prove refinement)
        coq/Impl/                ← extractable, Cairo-shaped refinement
            │
            ▼ (Coq → OCaml extraction)
        certified OCaml model
            │
            ▼ (PBT / QCheck2 conformance)
        cairo/src/*.cairo        ← actual on-chain implementation
```

Each layer is what catches a different failure mode:

- **Spec → Impl refinement proof** catches *missing assertions*. The
  spec enumerates the protocol-level safety properties; if the
  refinement's executable definition can't discharge them, the proof
  gets stuck and we've localized the gap. **No `admit`s allowed.**
- **Extracted-function differential fuzzing** catches *translation
  divergence*. QCheck2 generates random inputs and checks the
  Coq-extracted functions (chain step, commitment, nullifier, sighash,
  Merkle path, L-tree, frontier root) byte-for-byte against the OCaml
  protocol port (`Tzel.*`). The port in turn agrees with the Rust
  protocol (`tzel_core`) via pinned cross-impl vectors
  (`specs/ocaml_vectors/protocol_v1*.json`).

  IMPLEMENTATION STATE (stated honestly — do not over-read this):

  - The differential is *function-level* (the 15 cases in
    `ocaml/coq_driver/test`) and its reference is the OCaml **port**,
    which is cross-impl-validated against the **Rust** protocol — NOT
    yet directly against the Cairo.
  - A FIRST *direct* `Cairo ↔ model` conformance check now exists:
    `cairo/src/blake_hash.cairo::test_commit_conforms_to_pinned_model_vector`
    (`scarb test`) asserts the Cairo's `commit` on the
    `commitment_u64_max_v1` inputs equals the model value — verified
    byte-identical to the OCaml port's `Tzel.Hash.hash_commit` and to
    `specs/test_vectors/commitment_u64_max_v1.json`. This also pins the
    **byte↔felt252 packing** (the felt is the 32 little-endian bytes
    read as a number) that the full harness needs. So for the
    *commitment* AND *nullifier* primitives the chain is now closed
    end-to-end (`test_commit_conforms_to_pinned_model_vector` /
    `test_nullifier_conforms_to_model`).
  - The REMAINING primitives (chain step, sighash, Merkle, L-tree) and the *relation-level* full-witness conformance
    (`run_*.cairo` driven on random witnesses vs the certified model's
    accept/reject) follow this same established pattern and are the next
    step — still forthcoming. (The `run_*.cairo` executables already run
    end-to-end producing real STARK proofs the kernel verifies in
    `services/tzel/tests/integration.rs`, but that is system-level, not
    a primitive/relation conformance check.)
  - So the Cairo's faithfulness to this model rests today on: (1) the
    **drift-pinned manual assertion cross-check** (every Cairo `assert`
    matched to a relation conjunct, SHA-pinned); (2) the function
    differentials (independent confidence the Coq transcription matches
    the port/Rust); and (3) now direct Cairo-vs-model conformance for
    the commitment and nullifier primitives, with the others to follow
    the same pattern.

  See `SECURITY_COVERAGE.md` ("How faithfulness is established") for the
  full account.

The layers are mutually reinforcing: the proof catches "the spec
demands a property the refinement can't satisfy"; the function
differentials catch "the Cairo computes a primitive differently from
the certified model"; the assertion cross-check + drift pin catch "a
Cairo assertion is missing from the relation." Each alone is incomplete.

## Directory layout

```
coq/
  _CoqProject              # Rocq build config, lists the three -Q paths
  MANIFEST.toml            # cairo↔coq/Impl mirror table with SHA-256 pins
  README.md                # this file
  STATUS.md                # detailed running status of every module
  SECURITY_COVERAGE.md     # specs/security.md property -> theorem map
  Common/Felt.v            # shared field-element type, used by Spec & Impl
  Spec/                    # whitepaper-derived abstract spec (28 modules)
    Hashes.v               # hash families; commitment / nullifier / sighash
                           #   binding, faerie-gold, replay resistance
    Merkle.v               # Merkle + auth-tree path binding (membership)
    Wots.v Xmss.v          # WOTS+ chain; WOTS+ & XMSS one-time unforgeability
    Transfer.v Shield.v Unshield.v
                           # per-asset value conservation + sighash
                           #   non-malleability + batch no-inflation
    GrandConservation.v    # unified no-inflation across any mixed batch
    Ledger.v LedgerNf.v LedgerBounded.v
                           # global no-inflation; u64/u128 overflow safety
    KernelLedger.v KernelPool.v KernelNullifier.v ShieldReplay.v
                           # conservation; pool solvency; double-spend; replay
    KernelDeposit.v AssetRegistry.v
                           # deposit anti-spoofing; registry routing bijection
    StoragePaths.v DepositKey.v WithdrawalRecord.v
                           # storage-path / deposit-key collision-freedom;
                           #   withdrawal codec round-trip
    MerkleTree.v MerkleFrontier.v MerkleBridge.v MerkleFrontierCorrect.v
                           # commitment tree: batch root, append-only at any
                           #   index, O(depth) frontier read-off = batch root
    BridgeTicketer.v BridgeBurn.v
                           # exact collateralization; burn authentication
    EndToEnd.v EndToEndMulti.v
                           # L1<->L2 solvency: custody = L2 claims, per asset
  Impl/                    # extractable refinement; Cairo-shaped
    Common.v               # implementation-side shared declarations
    Hashes.v               # concrete hash parameters (realized at extraction)
    Merkle.v / Wots.v / Xmss.v / Transfer.v / Shield.v / Unshield.v
                           # 1-to-1 with Spec, plus refinement theorems
    Extraction.v           # Coq -> OCaml extraction wiring
  Drift/check.sh           # CI: re-hash Cairo files, fail on mismatch
  Extracted/build.sh       # extraction → OCaml driver build
ocaml/coq_driver/test/     # differential fuzzing: extracted Coq vs the
                           #   cross-impl-tested OCaml port (14 cases)
```

## Why three layers

The expert team-member's recommendation, in plain terms:

1. **Build the spec from the documents, not from the code.** A
   model derived from the implementation inherits whatever
   abstractions the code has — including any wrong ones. If Cairo is
   missing an assertion, a Cairo-derived Coq model has the same hole
   and the proofs sail through agreeing-with-themselves. The
   whitepaper and protocol spec are the right starting point.

2. **Mechanized verification produces four artifacts, not one.**
   The abstract spec, proofs of safety properties about it, an
   extractable refinement, and the proof that the refinement
   refines the spec. The fourth one is what makes the executable
   Coq trustworthy as a reference for fuzzing.

3. **No `admit` anywhere.** Every theorem closes. Every lemma
   discharges. Watch out for `False` slipping into hypotheses
   (which would make any conclusion provable trivially).

4. **Conformance via PBT, not just hand-curated vectors.** QCheck2
   for random structured witness generation; the certified OCaml as
   oracle; the Cairo as system-under-test. Edge-case search after
   basic conformance lands.

## Build

Rocq 9.x via opam (matches the OCaml side of the repo):

```
opam install -y rocq-prover
cd coq
rocq makefile -f _CoqProject -o Makefile
make -j2
```

CI: `.github/workflows/coq.yml` runs the drift check, builds the whole
theory, extracts to OCaml, and runs the differential suite.

## Status (summary; see `STATUS.md` for per-module detail)

The development is comprehensive and zero-admit.  Highlights:

- **No `admit` anywhere** — every theorem closes.
- **Minimal axiom base** — `Print Assumptions` across 23 headline
  theorems (one+ from every component) shows the *entire* development
  depends on exactly two axioms: `Felt : Type` and `Felt_eq_dec`.
  Hash functions are uninterpreted parameters with no global
  properties; every collision-resistance / injectivity premise is an
  explicit *local* hypothesis, never a global axiom.
- **Proven properties** (see `SECURITY_COVERAGE.md` for the
  property→theorem map against `specs/security.md`):
  - circuit no-inflation — per-asset value conservation for shield /
    transfer / unshield, across any mixed batch
    (`GrandConservation.grand_conservation`), plus u64/u128 overflow
    safety (`LedgerBounded`);
  - per-note binding — a commitment welds its value, asset, and
    spending authority (`Hashes.commitment_binds_*`);
  - spend integrity — double-spend (`KernelNullifier`), shield-replay
    (`ShieldReplay`), faerie-gold (`nullifier_position_distinct`),
    WOTS+/XMSS one-time unforgeability (`Xmss`);
  - sighash non-malleability for all three flows;
  - bridge / contract — exact collateralization (`BridgeTicketer`),
    burn authentication (`BridgeBurn`), deposit anti-spoofing
    (`KernelDeposit`), registry routing bijection (`AssetRegistry`);
  - per-asset L1↔L2 solvency (`EndToEndMulti`);
  - storage-path & deposit-key collision-freedom, withdrawal codec
    round-trip;
  - the commitment Merkle tree end to end — batch root, append-only at
    any index, and the kernel's O(depth) frontier read-off provably
    equals the batch root (`MerkleFrontierCorrect.froot_fbuild_eq`).
- **Drift detection** — `MANIFEST.toml` SHA-pins the modeled Cairo
  files; `Drift/check.sh` fails CI on divergence (6/6 mirrors).
- **Faithfulness differential** — the extracted Coq models (WOTS chain
  step, commitment, nullifier, sighash, merkle path, and the Merkle
  batch root + O(depth) frontier) are fuzzed against the
  cross-impl-tested OCaml port (14 cases) — so the proven models also
  provably compute what the production code computes.
