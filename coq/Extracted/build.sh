#!/usr/bin/env bash
#
# coq/Extracted/build.sh — link the extracted Rocq xmss_chain_step
# against the OCaml [tzel] protocol port and produce a runnable
# `chain_step` binary.
#
# Pipeline:
# 1. The Rocq theory has already been built (`make -C coq`), which
#    side-effects writing tzel_wots.ml + tzel_wots.mli into
#    coq/Impl/ via Set Extraction Output Directory.
# 2. Copy those generated files into ocaml/coq_driver/ alongside
#    main.ml. dune picks them up as part of the executable.
# 3. dune build the executable from the OCaml workspace; it links
#    the [tzel] library so the Hash3 / pack_adrs_chain realizations
#    in Extraction.v resolve to the real [Tzel.Hash.hash3] /
#    [Tzel.Wots.pack_adrs].
# 4. Symlink the built binary into Extracted/chain_step so the CI
#    smoke step (and ad-hoc invocations) keep using a stable path.

set -euo pipefail

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO="$(cd "$DIR/../.." >/dev/null 2>&1 && pwd)"

src_ml="$REPO/coq/Impl/tzel_wots.ml"
src_mli="$REPO/coq/Impl/tzel_wots.mli"
[[ -f "$src_ml" && -f "$src_mli" ]] || {
  echo "missing extracted files: build the Rocq theory first" >&2
  echo "  (cd coq && rocq makefile -f _CoqProject -o Makefile && make -j2)" >&2
  exit 1
}

driver_dir="$REPO/ocaml/coq_driver"
cp "$src_ml" "$src_mli" "$driver_dir/"

# Keep the differential test's snapshot in lockstep with the freshly
# extracted code.  The QCheck2 conformance test (coq_driver/test)
# links its OWN copy of tzel_wots.ml so it can be a tracked,
# reviewable artifact; if that snapshot drifts from what the Rocq
# theory now extracts, the test would silently validate stale code.
# Refresh it here and, in CI (REFRESH_TEST_SNAPSHOT unset), fail loudly
# if the tracked copy was out of date so the drift is visible in the
# diff rather than masked.
test_ml="$REPO/ocaml/coq_driver/test/tzel_wots.ml"
test_mli="$REPO/ocaml/coq_driver/test/tzel_wots.mli"
if ! diff -q "$src_ml" "$test_ml" >/dev/null 2>&1 \
   || ! diff -q "$src_mli" "$test_mli" >/dev/null 2>&1; then
  if [[ -n "${REFRESH_TEST_SNAPSHOT:-}" ]]; then
    cp "$src_ml" "$test_ml"
    cp "$src_mli" "$test_mli"
    echo "refreshed differential-test snapshot from fresh extraction"
  else
    echo "::error::coq_driver/test snapshot is stale vs fresh extraction." >&2
    echo "  Run: REFRESH_TEST_SNAPSHOT=1 ./coq/Extracted/build.sh && git add ocaml/coq_driver/test/tzel_wots.{ml,mli}" >&2
    exit 1
  fi
fi

( cd "$REPO/ocaml" && dune build coq_driver/main.exe )

ln -sf "$REPO/ocaml/_build/default/coq_driver/main.exe" "$DIR/chain_step"

echo "built: $DIR/chain_step"
