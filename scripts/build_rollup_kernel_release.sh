#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${STATE_DIR:-}"
TARGET="${TARGET:-wasm32-unknown-unknown}"
CARGO_TOOLCHAIN="${CARGO_TOOLCHAIN:-}"

usage() {
  cat <<'EOF'
Usage: ./scripts/build_rollup_kernel_release.sh [options]

Build the release rollup kernel WASM with baked-in configuration-admin material.

Options:
  --workspace-root PATH  Repo root to build from (default: current repo)
  --state-dir PATH       Directory holding generated config-admin files
                         (default: <repo>/target/rollup-config-admin)
  --target NAME          Rust target to build (default: wasm32-unknown-unknown)
  --cargo-toolchain NAME Optional cargo toolchain prefix
  --help                 Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace-root)
      ROOT_DIR="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --cargo-toolchain)
      CARGO_TOOLCHAIN="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$STATE_DIR" ]]; then
  STATE_DIR="$ROOT_DIR/target/rollup-config-admin"
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

build_cargo() {
  local cmd=(cargo)
  if [[ -n "$CARGO_TOOLCHAIN" ]]; then
    cmd+=("$CARGO_TOOLCHAIN")
  fi
  cmd+=("$@")
  (cd "$ROOT_DIR" && "${cmd[@]}")
}

require_cmd cargo
require_cmd rustup

if [[ -n "$CARGO_TOOLCHAIN" ]]; then
  rustup target add "$TARGET" --toolchain "${CARGO_TOOLCHAIN#\+}"
else
  rustup target add "$TARGET"
fi

build_cargo build --release -p tzel-rollup-kernel --bin octez_kernel_message

"$ROOT_DIR/scripts/prepare_rollup_config_admin.sh" \
  --workspace-root "$ROOT_DIR" \
  --state-dir "$STATE_DIR" \
  --octez-kernel-message "$ROOT_DIR/target/release/octez_kernel_message" \
  --cargo-toolchain "$CARGO_TOOLCHAIN"

# shellcheck disable=SC1090
set -a
source "$STATE_DIR/rollup-config-admin-build.env"
set +a

build_cargo build --release -p tzel-rollup-kernel --target "$TARGET"

echo "built kernel wasm:"
echo "  $ROOT_DIR/target/$TARGET/release/tzel_rollup_kernel.wasm"
echo "using config admin env from:"
echo "  $STATE_DIR/rollup-config-admin-build.env"
