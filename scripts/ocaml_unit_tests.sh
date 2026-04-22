#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root/ocaml"

export LIBRARY_PATH="$repo_root/ocaml/vendor/mlkem-native/test/build${LIBRARY_PATH:+:$LIBRARY_PATH}"

if command -v dune >/dev/null 2>&1; then
  exec dune exec -- ./test/test_main.exe
fi

exec opam exec -- dune exec -- ./test/test_main.exe
