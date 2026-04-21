#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-/usr/local}"
EXECUTABLES_DEST="${EXECUTABLES_DEST:-/opt/tzel/cairo/target/dev}"
SCARB_BIN="${SCARB_BIN:-scarb}"
SKIP_BUILD=0
BUILD_ONLY=0
INSTALL_SP_CLIENT=1
PROVER_TOOLCHAIN="${PROVER_TOOLCHAIN:-+nightly-2025-07-14}"
CONFIG_ADMIN_DIR=""

usage() {
  cat <<'EOF'
Usage: ./scripts/install_tzel_binaries.sh [options]

Build and install the deployable TzEL binaries, rollup helper binaries, the
watch-only detection service, and the Cairo executable JSON files needed by the
prover and wallet.

Options:
  --prefix PATH             Install binaries into PATH/bin (default: /usr/local)
  --executables-dir PATH    Install Cairo executables into PATH (default: /opt/tzel/cairo/target/dev)
  --workspace-root PATH     Repo root to build from (default: current repo)
  --scarb-bin PATH          Scarb binary to use for Cairo builds (default: scarb)
  --prover-toolchain NAME   Toolchain prefix for reprove build (default: +nightly-2025-07-14)
  --config-admin-dir PATH   Install rollup config-admin env files into PATH
                            (default: <prefix>/etc/tzel)
  --build-only             Build artifacts but do not install them
  --skip-build              Reuse existing build artifacts instead of rebuilding them
  --no-sp-client            Do not install the developer sp-client binary
  --help                    Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --executables-dir)
      EXECUTABLES_DEST="$2"
      shift 2
      ;;
    --workspace-root)
      ROOT_DIR="$2"
      shift 2
      ;;
    --scarb-bin)
      SCARB_BIN="$2"
      shift 2
      ;;
    --prover-toolchain)
      PROVER_TOOLCHAIN="$2"
      shift 2
      ;;
    --config-admin-dir)
      CONFIG_ADMIN_DIR="$2"
      shift 2
      ;;
    --build-only)
      BUILD_ONLY=1
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --no-sp-client)
      INSTALL_SP_CLIENT=0
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

if [[ -z "$CONFIG_ADMIN_DIR" ]]; then
  CONFIG_ADMIN_DIR="${PREFIX%/}/etc/tzel"
fi

CONFIG_ADMIN_BUILD_DIR="$ROOT_DIR/target/rollup-config-admin"
CONFIG_ADMIN_RUNTIME_ENV="$CONFIG_ADMIN_BUILD_DIR/rollup-config-admin-runtime.env"
CONFIG_ADMIN_BUILD_ENV="$CONFIG_ADMIN_BUILD_DIR/rollup-config-admin-build.env"
CONFIG_ADMIN_OWNER="${SUDO_UID:-$(id -u)}"
CONFIG_ADMIN_GROUP="${SUDO_GID:-$(id -g)}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

ensure_config_admin_material() {
  if [[ -f "$CONFIG_ADMIN_RUNTIME_ENV" && -f "$CONFIG_ADMIN_BUILD_ENV" ]]; then
    return 0
  fi
  if [[ $SKIP_BUILD -eq 1 ]]; then
    cat >&2 <<EOF
missing rollup config-admin env files:
  - $CONFIG_ADMIN_RUNTIME_ENV
  - $CONFIG_ADMIN_BUILD_ENV

--skip-build installs must use the env files generated alongside the kernel build.
Copy target/rollup-config-admin from the build host, or rerun without --skip-build.
EOF
    exit 1
  fi
  "$ROOT_DIR/scripts/prepare_rollup_config_admin.sh" \
    --workspace-root "$ROOT_DIR" \
    --state-dir "$CONFIG_ADMIN_BUILD_DIR" \
    --octez-kernel-message "$ROOT_DIR/target/release/octez_kernel_message"
}

build_cargo() {
  local toolchain="$1"
  shift
  local cmd=(cargo)
  if [[ -n "$toolchain" ]]; then
    cmd+=("$toolchain")
  fi
  cmd+=("$@")
  (cd "$ROOT_DIR" && "${cmd[@]}")
}

if [[ $SKIP_BUILD -eq 0 ]]; then
  require_cmd cargo
  require_cmd "$SCARB_BIN"

  build_cargo "" build --release -p tzel-services --bin tzel-operator
  build_cargo "" build --release -p tzel-wallet-app --bin tzel-wallet --bin tzel-detect
  if [[ $INSTALL_SP_CLIENT -eq 1 ]]; then
    build_cargo "" build --release -p tzel-wallet-app --bin sp-client
  fi
  build_cargo "" build --release -p tzel-rollup-kernel --bin octez_kernel_message --bin verified_bridge_fixture_message
  "$ROOT_DIR/scripts/prepare_rollup_config_admin.sh" \
    --workspace-root "$ROOT_DIR" \
    --state-dir "$CONFIG_ADMIN_BUILD_DIR" \
    --octez-kernel-message "$ROOT_DIR/target/release/octez_kernel_message"
  (
    cd "$ROOT_DIR/apps/prover"
    cargo "$PROVER_TOOLCHAIN" build --release --bin reprove
  )
  (
    cd "$ROOT_DIR/cairo"
    "$SCARB_BIN" build
  )
fi

if [[ $BUILD_ONLY -eq 1 ]]; then
  ensure_config_admin_material
  echo "built release artifacts in:"
  echo "  - $ROOT_DIR/target/release/tzel-operator"
  echo "  - $ROOT_DIR/target/release/tzel-wallet"
  echo "  - $ROOT_DIR/target/release/tzel-detect"
  if [[ $INSTALL_SP_CLIENT -eq 1 ]]; then
    echo "  - $ROOT_DIR/target/release/sp-client"
  fi
  echo "  - $ROOT_DIR/target/release/octez_kernel_message"
  echo "  - $ROOT_DIR/target/release/verified_bridge_fixture_message"
  echo "  - $CONFIG_ADMIN_RUNTIME_ENV"
  echo "  - $CONFIG_ADMIN_BUILD_ENV"
  echo "  - $ROOT_DIR/apps/prover/target/release/reprove"
  echo "  - $ROOT_DIR/cairo/target/dev/run_{shield,transfer,unshield}.executable.json"
  exit 0
fi

BIN_DIR="${PREFIX%/}/bin"
ensure_config_admin_material

install -d "$BIN_DIR" "$EXECUTABLES_DEST" "$CONFIG_ADMIN_DIR"

install -m 0755 "$ROOT_DIR/target/release/tzel-operator" "$BIN_DIR/tzel-operator"
install -m 0755 "$ROOT_DIR/target/release/tzel-wallet" "$BIN_DIR/tzel-wallet"
install -m 0755 "$ROOT_DIR/target/release/tzel-detect" "$BIN_DIR/tzel-detect"
if [[ $INSTALL_SP_CLIENT -eq 1 ]]; then
  install -m 0755 "$ROOT_DIR/target/release/sp-client" "$BIN_DIR/sp-client"
fi
install -m 0755 "$ROOT_DIR/target/release/octez_kernel_message" "$BIN_DIR/octez_kernel_message.bin"
install -m 0755 "$ROOT_DIR/target/release/verified_bridge_fixture_message" "$BIN_DIR/verified_bridge_fixture_message"
install -m 0755 "$ROOT_DIR/apps/prover/target/release/reprove" "$BIN_DIR/reprove"
install -m 0755 "$ROOT_DIR/scripts/submit_rollup_config.sh" "$BIN_DIR/submit_rollup_config"
install -o "$CONFIG_ADMIN_OWNER" -g "$CONFIG_ADMIN_GROUP" -m 0600 \
  "$CONFIG_ADMIN_RUNTIME_ENV" "$CONFIG_ADMIN_DIR/rollup-config-admin-runtime.env"
install -o "$CONFIG_ADMIN_OWNER" -g "$CONFIG_ADMIN_GROUP" -m 0644 \
  "$CONFIG_ADMIN_BUILD_ENV" "$CONFIG_ADMIN_DIR/rollup-config-admin-build.env"

wrapper_tmp="$(mktemp)"
cat >"$wrapper_tmp" <<EOF
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="\${TZEL_ROLLUP_CONFIG_ADMIN_ENV_FILE:-$CONFIG_ADMIN_DIR/rollup-config-admin-runtime.env}"
if [[ -f "\$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "\$ENV_FILE"
fi
exec "\$SCRIPT_DIR/octez_kernel_message.bin" "\$@"
EOF
install -m 0755 "$wrapper_tmp" "$BIN_DIR/octez_kernel_message"
rm -f "$wrapper_tmp"

for executable in \
  run_shield.executable.json \
  run_transfer.executable.json \
  run_unshield.executable.json
do
  install -m 0644 "$ROOT_DIR/cairo/target/dev/${executable}" "$EXECUTABLES_DEST/${executable}"
done

echo "installed binaries into $BIN_DIR"
echo "  - tzel-operator"
echo "  - tzel-wallet"
echo "  - tzel-detect"
if [[ $INSTALL_SP_CLIENT -eq 1 ]]; then
  echo "  - sp-client"
fi
echo "  - octez_kernel_message"
echo "  - verified_bridge_fixture_message"
echo "  - reprove"
echo "  - submit_rollup_config"
echo "installed rollup config admin env files into $CONFIG_ADMIN_DIR"
echo "  - rollup-config-admin-runtime.env"
echo "  - rollup-config-admin-build.env"
echo "installed Cairo executables into $EXECUTABLES_DEST"
echo "  - run_shield.executable.json"
echo "  - run_transfer.executable.json"
echo "  - run_unshield.executable.json"
