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

( cd "$REPO/ocaml" && dune build coq_driver/main.exe )

ln -sf "$REPO/ocaml/_build/default/coq_driver/main.exe" "$DIR/chain_step"

echo "built: $DIR/chain_step"
