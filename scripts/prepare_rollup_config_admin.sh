#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${STATE_DIR:-}"
RUNTIME_ENV_FILE=""
BUILD_ENV_FILE=""
OCTEZ_KERNEL_MESSAGE=""
CARGO_TOOLCHAIN="${CARGO_TOOLCHAIN:-}"
FORCE=0

usage() {
  cat <<'EOF'
Usage: ./scripts/prepare_rollup_config_admin.sh [options]

Generate or reuse rollup configuration-admin material and write:
  - a runtime env file containing TZEL_ROLLUP_CONFIG_ADMIN_ASK_HEX
  - a build env file containing the public material baked into the kernel

Options:
  --workspace-root PATH       Repo root to build from (default: current repo)
  --state-dir PATH            Directory for generated files
                              (default: <repo>/target/rollup-config-admin)
  --runtime-env-file PATH     Output file for the secret ask env
  --build-env-file PATH       Output file for the derived public build env
  --octez-kernel-message PATH Prebuilt octez_kernel_message binary to use
  --cargo-toolchain NAME      Optional cargo toolchain prefix for helper build
  --force                     Regenerate the secret ask file
  --help                      Show this help
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
    --runtime-env-file)
      RUNTIME_ENV_FILE="$2"
      shift 2
      ;;
    --build-env-file)
      BUILD_ENV_FILE="$2"
      shift 2
      ;;
    --octez-kernel-message)
      OCTEZ_KERNEL_MESSAGE="$2"
      shift 2
      ;;
    --cargo-toolchain)
      CARGO_TOOLCHAIN="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
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

if [[ -z "$RUNTIME_ENV_FILE" ]]; then
  RUNTIME_ENV_FILE="$STATE_DIR/rollup-config-admin-runtime.env"
fi
if [[ -z "$BUILD_ENV_FILE" ]]; then
  BUILD_ENV_FILE="$STATE_DIR/rollup-config-admin-build.env"
fi
if [[ -z "$OCTEZ_KERNEL_MESSAGE" ]]; then
  OCTEZ_KERNEL_MESSAGE="$ROOT_DIR/target/release/octez_kernel_message"
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

generate_ask_hex() {
  python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
}

require_cmd python3

mkdir -p "$(dirname "$RUNTIME_ENV_FILE")" "$(dirname "$BUILD_ENV_FILE")"

if [[ ! -x "$OCTEZ_KERNEL_MESSAGE" ]]; then
  require_cmd cargo
  build_cargo build --release -p tzel-rollup-kernel --bin octez_kernel_message
fi

if [[ ! -f "$RUNTIME_ENV_FILE" || "$FORCE" -eq 1 ]]; then
  umask 077
  tmp_runtime="$(mktemp "${RUNTIME_ENV_FILE}.tmp.XXXXXX")"
  {
    echo "# shellcheck shell=bash"
    echo "export TZEL_ROLLUP_CONFIG_ADMIN_ASK_HEX=$(generate_ask_hex)"
  } >"$tmp_runtime"
  mv "$tmp_runtime" "$RUNTIME_ENV_FILE"
  chmod 600 "$RUNTIME_ENV_FILE"
fi

# shellcheck disable=SC1090
source "$RUNTIME_ENV_FILE"
if [[ -z "${TZEL_ROLLUP_CONFIG_ADMIN_ASK_HEX:-}" ]]; then
  echo "runtime env file did not set TZEL_ROLLUP_CONFIG_ADMIN_ASK_HEX: $RUNTIME_ENV_FILE" >&2
  exit 1
fi

tmp_build="$(mktemp "${BUILD_ENV_FILE}.tmp.XXXXXX")"
TZEL_ROLLUP_CONFIG_ADMIN_ASK_HEX="$TZEL_ROLLUP_CONFIG_ADMIN_ASK_HEX" \
  "$OCTEZ_KERNEL_MESSAGE" admin-material >"$tmp_build"
mv "$tmp_build" "$BUILD_ENV_FILE"
chmod 600 "$BUILD_ENV_FILE"

echo "rollup config admin runtime env: $RUNTIME_ENV_FILE"
echo "rollup config admin build env:   $BUILD_ENV_FILE"
