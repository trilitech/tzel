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
- **Extracted-OCaml ↔ Cairo conformance fuzzing** catches *translation
  divergence*. QCheck2 generates random witnesses, runs both the
  certified OCaml model and the Cairo verifier, asserts they decide
  the same way. AFL+crowbar would be an alternative but has issues
  with downstream Tezos code (Lwt scheduler / GC); QCheck2 is
  simpler and the recommended tool.

The two together are mutually reinforcing: the proof catches "the
spec demands a property the refinement can't satisfy"; the fuzzer
catches "the Cairo behaves differently from the certified model on
some witness." Either alone is incomplete.

## Directory layout

```
coq/
  _CoqProject              # Rocq build config, lists the three -Q paths
  MANIFEST.toml            # cairo↔coq/Impl mirror table with SHA-256 pins
  README.md                # this file
  Common/Felt.v            # shared field-element type, used by Spec & Impl
  Spec/                    # whitepaper-derived abstract spec
    Hashes.v               # opaque hash families + cryptographic axioms
    Merkle.v               # Merkle path verification
    Wots.v                 # WOTS+ chain step + properties
    Xmss.v                 # XMSS verifier + soundness statement
    Transfer.v             # transfer relation + Phi_transfer + soundness
    Shield.v               # ditto
    Unshield.v             # ditto
  Impl/                    # extractable refinement; Cairo-shaped
    Common.v               # implementation-side shared declarations
    Hashes.v               # concrete hash parameters (realized at extraction)
    Merkle.v / Wots.v / Xmss.v / Transfer.v / Shield.v / Unshield.v
                           # 1-to-1 with Spec, plus refinement theorems
  Drift/check.sh           # CI: re-hash Cairo files, fail on mismatch
  Extracted/               # (planned) Coq → OCaml extraction outputs +
                           # QCheck2 conformance driver
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

CI: `.github/workflows/coq.yml` runs the drift check + builds the
theory. Extraction + QCheck2 conformance lands in a follow-up commit
once the first piece of Spec ↔ Impl refinement is proven.

## Status

- Restructure: ✓ Three-layer layout in place
- Drift detection: ✓ Manifest + CI script working
- First piece of Spec: `Spec/Wots.v` has the abstract chain step;
  proofs and Impl refinement land in the next commit
- Other Spec modules: stubs with intent docs
- Impl modules: structural mirrors of Cairo, mostly stub bodies
  with the chain step in `Impl/Wots.v` already defined
- Extraction + conformance: not yet built
