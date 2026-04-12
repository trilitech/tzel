#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root/ocaml"

export LIBRARY_PATH="$repo_root/ocaml/vendor/mlkem-native/test/build${LIBRARY_PATH:+:$LIBRARY_PATH}"

exec dune exec -- ./test/test_main.exe
