#!/usr/bin/env bash
set -euo pipefail

echo "Installing tezos-smart-rollup-installer to \$HOME/.cargo/bin"
cargo install tezos-smart-rollup-installer --locked

echo
echo "Installed binary:"
command -v smart-rollup-installer || {
  echo "smart-rollup-installer was installed but is not on PATH." >&2
  echo "Add \$HOME/.cargo/bin to PATH and retry." >&2
  exit 1
}

smart-rollup-installer --help >/dev/null
echo "smart-rollup-installer is ready"
