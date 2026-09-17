# Handoff brief — Rocq model on `coq-model` branch

Companion to `coq/STATUS.md`. STATUS lists what's done / not done in
structured form; this file is the discursive context — *why* things
are this way, *where* to find them, and the gotchas that will eat
half a day if you trip over them blind.

Written 2026-05-04 after landing the dune-driven real-hash wiring.

---

## 1. The protocol has three implementations. Don't confuse them.

```
cairo/src/*.cairo      — the on-chain implementation (Scarb / Cairo)
                         this is the canonical artifact; everything
                         else exists to check it.

ocaml/protocol/*.ml    — a parallel "protocol port" in OCaml. Used
                         for prover-side tooling (services, vectors,
                         interop tests). Bit-equivalent to the Cairo
                         under cargo test --test cross_impl_interop
                         (the "cross-impl interop check" that gets
                         cited everywhere — that's the link).

coq/{Spec,Impl}/*.v    — what we're working on. Three layers:
                           - Common/   shared types (Felt etc.)
                           - Spec/     whitepaper-derived ABSTRACT spec
                                       (does NOT look at Cairo)
                           - Impl/     extractable refinement, MAY
                                       look at Cairo's structure
                         Refinement theorems connect Spec ↔ Impl.
                         Extraction connects Impl ↔ OCaml port.
                         OCaml port ↔ Cairo via cross-impl interop.
                         Transitively: Spec ↔ Cairo.
```

The directionality matters. **`Spec/` must be transcribed from the
whitepaper + spec.md, NOT from the Cairo code.** Otherwise we're
just checking Cairo against a paraphrase of itself. The team expert
recommended this and we follow it religiously.

`Impl/` is allowed to mirror the Cairo's structure — that's the
whole point of refinement.

## 2. Architecture diagram (the one in STATUS.md, but with file pointers)

```
docs/whitepaper.tex + specs/spec.md
            │
            ▼ (transcribe)
        coq/Spec/Wots.v          ← step, iter, iter_succ, iter_compose, iter_S_unfold
        coq/Spec/Hashes.v        ← stub
        coq/Spec/Merkle.v        ← stub
        coq/Spec/Xmss.v          ← stub
        coq/Spec/Transfer.v      ← stub
        coq/Spec/Shield.v        ← stub
        coq/Spec/Unshield.v      ← stub
            │
            ▼ (refine + prove refinement)
        coq/Impl/Wots.v          ← xmss_chain_step + Theorem refines_spec (reflexivity)
        coq/Impl/Hashes.v        ← Parameter Hash3
        coq/Impl/Common.v        ← placeholder
        coq/Impl/{Merkle,Xmss,Transfer,Shield,Unshield}.v ← stubs
        coq/Impl/Extraction.v    ← realizes Felt, Hash3, pack_adrs_chain, nat
            │
            ▼ (Rocq -> OCaml extraction)
        coq/Impl/tzel_wots.{ml,mli}  ← generated, gitignored
            │
            ▼ (copy + dune build)
        ocaml/coq_driver/
          dune                    ← (executable (name main) (libraries tzel))
          main.ml                 ← CLI driver: args -> Tzel_wots.xmss_chain_step -> hex
          tzel_wots.{ml,mli}      ← copied in by build.sh, gitignored
            │
            ▼ (linked binary)
        ocaml/_build/default/coq_driver/main.exe
            │
            ▼ (symlinked for stable path)
        coq/Extracted/chain_step
            │
            ▼ (CI smoke OR future QCheck2 differential)
        cairo/src/*.cairo           ← actual on-chain implementation
        (Cairo runner not built yet — next concrete piece)
```

## 3. What I've shipped on this branch (in order)

```
a8d463a coq: scaffolding for Cairo↔Coq circuit model + drift detection
61f5cd5 coq: extract xmss_chain_step to OCaml end-to-end
        ↑ original extraction in old coq/Tzel/ layout, with placeholder hash
3df59f5 coq: restructure to Spec/Common/Impl per expert recommendation; STATUS.md
        ↑ DROPPED the extraction; everything in coq/Tzel/ moved/split
b570e47 coq: prove iter_succ + iter_compose in Spec.Wots; add Impl.Wots refinement
        ↑ landed broken — proofs failed on Rocq 9 (see §6 gotchas)
561ad7c coq: re-port Rocq -> OCaml extraction onto Spec/Impl/Common layout
        ↑ exposes b570e47's failure; smoke uses zero-stub hash
8bf71cf coq: fix Spec.Wots iter proofs for Rocq 9, switch to From Stdlib
        ↑ added iter_S_unfold, replaced simpl with controlled rewrite
5fa903c coq: set extraction output dir to Impl/ explicitly
        ↑ Set Extraction Output Directory "Impl" — Rocq 9 default was wrong
5dbd94f coq: wire Hash3/pack_adrs_chain to real OCaml port via dune driver
        ↑ MOST RECENT. Driver moved to ocaml/coq_driver/, links tzel,
          CI asserts the all-zero reference vector
          5ca134c7d8b26856b4dc9c748905318c23da49cac0fd56cc26c7885155466807
```

`main` was merged in once during this conversation (commit `838ec1e`)
to pull a whitepaper docs fix; nothing model-related came across.

## 4. The build pipeline, in detail

### Local build (no rocq locally — this is CI-only)

You probably can't build the Coq theory locally (no opam rocq-prover
in dev container). What you *can* do:

- **Hand-stub `tzel_wots.{ml,mli}` to sanity-check the dune side.**
  Drop a stub in `ocaml/coq_driver/` matching what extraction would
  emit, then `cd ocaml && dune build coq_driver/main.exe`. Done this
  twice now; both times the stub-driven binary produced
  `5ca134c7…155466807` on zero input — the same value the OCaml port
  produces directly. Useful for verifying the dune wiring without
  CI roundtrip.

- **The OCaml workspace builds locally** if you have all opam deps
  (`dune alcotest cstruct ctypes ctypes-foreign hex mirage-crypto
  yojson digestif`) plus mlkem-native. This is the same setup as
  CI's `unit-tests.yml` ocaml job.

### CI build (`.github/workflows/coq.yml`)

```
1. drift     — fast (~5s). Runs coq/Drift/check.sh which re-hashes
                Cairo files and compares to coq/MANIFEST.toml.
                Fails when Cairo changes invalidate a modeled file.
2. build     — slow (~5–6 min). Sets up OCaml 5.2.0, opam-installs
                all the things, builds mlkem-native, builds Rocq
                theory (which writes tzel_wots.{ml,mli} into
                coq/Impl/), runs coq/Extracted/build.sh which
                copies the extraction into ocaml/coq_driver/ and
                runs dune build, then asserts the zero-input
                reference vector.
```

`coq.yml` triggers on changes to `coq/**`, `cairo/src/**.cairo`,
`ocaml/coq_driver/**`, and `.github/workflows/coq.yml`.

## 5. Key files (lookup table)

| What you want                          | Where it lives                                  |
|----------------------------------------|-------------------------------------------------|
| Spec-layer chain step + proofs         | `coq/Spec/Wots.v`                               |
| Impl-layer chain step + refinement     | `coq/Impl/Wots.v`                               |
| Extraction directives                  | `coq/Impl/Extraction.v`                         |
| Module layout / imports                | `coq/_CoqProject`                               |
| Drift manifest                         | `coq/MANIFEST.toml` + `coq/Drift/check.sh`      |
| Dune driver                            | `ocaml/coq_driver/{dune,main.ml}`               |
| Build orchestrator                     | `coq/Extracted/build.sh`                        |
| OCaml hash + WOTS+ port                | `ocaml/protocol/{hash.ml,wots.ml}`              |
| Cairo chain step (canonical)           | `cairo/src/xmss_common.cairo`                   |
| Status (structured)                    | `coq/STATUS.md`                                 |
| Status (this file — narrative)         | `coq/HANDOFF.md`                                |
| Architecture refresher                 | `coq/README.md`                                 |
| CI workflow                            | `.github/workflows/coq.yml`                     |
| OCaml CI (for stack reference)         | `.github/workflows/unit-tests.yml`              |

## 6. Gotchas that bit me (don't repeat them)

### Rocq 9's `simpl` is more aggressive than Coq 8's

The lemma `iter_succ` was originally proved with
`simpl. rewrite IH. simpl.` That worked on the author's local Coq 8
but failed on Rocq 9 because `simpl` keeps unfolding `iter (S _) ...`
recursively as long as the size argument is a constructor — it
unfolds *both* `iter (S (S k))` and `iter (S k)`, leaving no
`iter (S k)` subterm for `rewrite IH` to match.

**Fix pattern:** define an explicit one-step unfolding lemma:

```coq
Lemma iter_S_unfold n x p k_ c_ s :
  iter (S n) x p k_ c_ s = iter n (step x p k_ c_ s) p k_ c_ (S s).
Proof. reflexivity. Qed.
```

Then `rewrite (iter_S_unfold N)` does *exactly one* unfold step.
Use this instead of `simpl` whenever IH-folding is fragile. See
`coq/Spec/Wots.v` for both `iter_succ` and `iter_compose` written
in this style.

### `From Coq Require Import` is deprecated in Rocq 9.0

Use `From Stdlib Require Import` instead. Already migrated in
`Spec/Wots.v` and `Impl/Extraction.v`. The local namespaces
(`From Common ...`, `From Spec ...`, `From Impl ...`) are
unaffected — those come from the `-Q` directives in `_CoqProject`.

### Extraction default output directory

Rocq 9 emits a warning and writes extracted files to wherever
`coqc` was invoked from (i.e. `coq/`, since make runs there).
*Not* where the `Extraction.v` file lives. Without `Set Extraction
Output Directory "Impl"`, files land in `coq/tzel_wots.ml` instead
of `coq/Impl/tzel_wots.ml` and `build.sh` can't find them.

### `(include_subdirs unqualified)` is set workspace-wide

`ocaml/dune` has `(include_subdirs unqualified)`. This forbids
`(executable ...)` stanzas in subdirs unless the subdir overrides
with `(include_subdirs no)`. So `ocaml/coq_driver/dune` starts with
`(include_subdirs no)` — keep that line if you ever rewrite the
file.

### Strict no-`admit` rule

The team policy is **zero `admit`s anywhere**. If a proof doesn't
close, don't paper over it. Either prove it, axiomatize it
explicitly with a comment justifying why (e.g. "standard XMSS
unforgeability — Hülsing et al."), or hold the lemma's commit until
the proof closes.

### Don't run `make` in `coq/` without `rocq makefile` first

The Makefile is gitignored; it's regenerated from `_CoqProject` by
`rocq makefile -f _CoqProject -o Makefile`. CI does this every run.
Locally, if you've never built before, `make` will fail with no
Makefile.

## 7. The drift check — how Cairo edits land here

`coq/MANIFEST.toml` pins SHA-256 of every Cairo file the model
mirrors. `coq/Drift/check.sh` re-hashes and fails CI on any
mismatch. When somebody edits Cairo, the drift check breaks; the
Coq author has to:

1. Read the Cairo diff.
2. Update the corresponding Impl module (or determine that the
   change is irrelevant to the model).
3. Update the SHA in `MANIFEST.toml`.
4. Re-prove anything affected.

This is the explicit signal that "the model and the canonical
implementation have diverged." Don't update the SHA without the
corresponding model update — that defeats the purpose.

## 8. Process & branch hygiene

- **Branch:** `coq-model`. Iterating independently of `main`. Push
  directly — no PR for now; the `main` workflow doesn't run the
  rocq job on coq-model files until they merge.
- **Merge from main occasionally** to pick up unrelated fixes. Done
  once already in this conversation — no model conflicts.
- **No squash on the model branch.** History should preserve the
  conceptual stepping-stones (scaffolding → restructure → first
  proof → first extraction → real hash → …).
- **Watch CI on every push.** The `coq.yml` workflow is the only
  way to catch Rocq syntax/proof issues without a local rocq install.
- **If you commit a proof that doesn't close, you'll find out via
  CI — see commit `b570e47`.** Don't push and walk away; wait.

## 9. The next concrete piece (what I'd start on)

**Cairo runner + QCheck2 differential.** Two pieces:

1. **`cairo/src/run_chain_step.cairo`** — an executable target
   added to `Scarb.toml`. Takes 5 felts as argv (or stdin), calls
   `xmss_common::xmss_chain_step`, prints the result hex. The
   shape is: `cairo-run` invocation produces a felt; we parse it.

   Look at how Scarb defines executables (Scarb.toml `[[executable]]`
   or similar — I haven't done this yet). The Cairo VM's
   serialization of felts to stdout is its own beast; if that's
   gnarly, an alternative is wrapping in a Rust harness using
   `cairo-vm` directly (the `tzel-services` Rust crate already does
   things like this).

2. **QCheck2 driver in OCaml.** Generate random
   `(x : 32 bytes, pub_seed : 32 bytes, key_idx, chain_idx, step)`,
   run both the extracted Coq driver (`coq/Extracted/chain_step`)
   and the Cairo runner on the same inputs, assert byte-equal hex.
   Place: probably `ocaml/coq_driver/test/` or
   `ocaml/test/test_extraction_diff.ml`. Initial budget: 30s/CI run.

   Divergences trigger triage:
   - Spec model bug → fix Spec, re-derive Impl refinement
   - Cairo bug → fix Cairo (rare!)
   - Generator bug → fix generator

The reason this is meaningful and not circular: the extracted-Coq
side runs `Tzel.Hash.hash3` / `Tzel.Wots.pack_adrs`, and the Cairo
side runs `cairo/src/blake_hash::hash3_generic` /
`cairo/src/xmss_common::pack_adrs`. These are *separate
implementations* of the same algebraic spec. The cross-impl interop
test already covers them at the OCaml-vs-Cairo level, but the diff
harness here covers them through the *extracted-from-Coq* path,
which is a different code path on the OCaml side (`tzel_wots.ml`
generated by Rocq).

Beyond chain step (more distant): Merkle path verification
(`Spec.Merkle` ↔ `Impl.Merkle`), L-tree compression, full XMSS
verifier, and the three top-level circuits
(transfer/shield/unshield) with their `Phi_*` soundness predicates.
Same shape, more proof work each time.

## 10. Anti-patterns / things to NOT do

- **Don't write Spec proofs from the Cairo.** Open the whitepaper
  and the cited references (RFC 8391, Hülsing 2017). The temptation
  to peek at the Cairo for "what should this lemma say" defeats the
  whole architecture.
- **Don't add `mathcomp` until the proofs need it.** Vanilla Rocq
  is fine for everything we have so far. `mathcomp-ssreflect` makes
  sense once tactic ergonomics start hurting; `mathcomp-algebra` if
  we end up reasoning about the StarkPrime field algebraically.
- **Don't skip the extraction smoke test.** It's the only signal
  that the Rocq-side definitions still produce extractable OCaml
  that does what we expect. A change to a `Parameter` declaration
  in `Impl/Hashes.v` could break extraction silently otherwise.
- **Don't refactor `_CoqProject` casually.** The `-Q Common Common`
  / `-Q Spec Spec` / `-Q Impl Impl` mappings are load-bearing for
  every `From X Require ...` line in the theory.

---

End of brief. STATUS.md has the structured next-piece. README.md
has the architecture overview. This file has the *reasons* and the
landmines. When in doubt, prefer reading whitepaper.tex over reading
Cairo.
