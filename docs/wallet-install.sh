#!/bin/sh
# tzel-wallet installer.
#
# Pulls one Docker image (nginx + daemon + tzel CLI + UI) and runs it
# on http://127.0.0.1:${HOST_PORT} (default 8080; configurable via
# TZEL_WALLET_HOST_PORT). nginx serves the UI and proxies /api/* to the
# daemon on the same container. Self-custodial: keys live in
# $HOME/.tzel-wallet on this machine.
#
# Usage:
#   curl -sSL https://tzel.tezos.com/wallet-install.sh | sh
#   curl -sSL https://tzel.tezos.com/wallet-install.sh | sh -s -- --force   # recreate
#   curl -sSL https://tzel.tezos.com/wallet-install.sh | sh -s -- --stop    # stop + remove
#
# Supported: Linux x86_64/arm64, macOS (Docker Desktop). Windows: WSL2.

set -eu

IMAGE="${TZEL_WALLET_IMAGE:-ghcr.io/trilitech/tzel-wallet:latest}"
SCRIPT_URL="${TZEL_INSTALL_SCRIPT_URL:-https://tzel.tezos.com/wallet-install.sh}"
CONTAINER="${TZEL_WALLET_CONTAINER_NAME:-tzel-wallet}"
HOST_PORT="${TZEL_WALLET_HOST_PORT:-8080}"
DATA_DIR="${TZEL_DATA_DIR:-$HOME/.tzel-wallet}"

# Ushuaianet defaults — override via env to target a different network.
TZEL_NETWORK="${TZEL_NETWORK:-ushuaianet}"
TZEL_ROLLUP_RPC_URL="${TZEL_ROLLUP_RPC_URL:-http://rollup.tzel.tezos.com:8932}"
TZEL_PROVING_SERVICE_URL="${TZEL_PROVING_SERVICE_URL:-http://proving.tzel.tezos.com:9000}"
TZEL_NETWORK_NAME="${TZEL_NETWORK_NAME:-tzel-ushuaianet}"
TZEL_NETWORK_LABEL="${TZEL_NETWORK_LABEL:-Ushuaianet}"
TZEL_TZKT_BASE_URL="${TZEL_TZKT_BASE_URL:-https://ushuaianet.tzkt.io}"

# ---- helpers -----------------------------------------------------------

if [ -t 1 ]; then
  red=$(printf '\033[31m'); green=$(printf '\033[32m'); yellow=$(printf '\033[33m'); dim=$(printf '\033[2m'); off=$(printf '\033[0m')
else
  red=; green=; yellow=; dim=; off=
fi
say()  { printf '%s\n' "$*"; }
info() { printf '%s==>%s %s\n' "$green" "$off" "$*"; }
warn() { printf '%s!!%s %s\n' "$yellow" "$off" "$*"; }
die()  { printf '%sxx%s %s\n' "$red" "$off" "$*" >&2; exit 1; }

# ---- args --------------------------------------------------------------

force=0; stop=0
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    --stop)  stop=1 ;;
    -h|--help)
      sed -n '2,17p' "$0" | sed 's/^#[[:space:]]\{0,1\}//'
      exit 0
      ;;
    *) die "unknown argument: $arg  (try --help)" ;;
  esac
done

# ---- platform detection ------------------------------------------------

os=$(uname -s 2>/dev/null || echo unknown)
case "$os" in
  Linux|Darwin) ;;
  *)
    die "unsupported OS: $os. Use Linux or macOS (or WSL2 on Windows)."
    ;;
esac

# ---- docker presence ---------------------------------------------------

if ! command -v docker >/dev/null 2>&1; then
  if [ "$os" = "Darwin" ]; then
    die "docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and re-run."
  else
    die "docker not found. Install Docker Engine (https://docs.docker.com/engine/install/) and re-run."
  fi
fi
if ! docker info >/dev/null 2>&1; then
  die "docker is installed but not reachable. Start it (macOS: Docker Desktop) and re-run."
fi

# ---- --stop shortcut ---------------------------------------------------

if [ "$stop" -eq 1 ]; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    info "stopping + removing $CONTAINER"
    docker rm -f "$CONTAINER" >/dev/null
    say "Done. Your wallet data is preserved at $DATA_DIR"
  else
    say "No container named $CONTAINER — nothing to do."
  fi
  exit 0
fi

# ---- container lifecycle ----------------------------------------------

if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  if [ "$force" -eq 1 ]; then
    info "removing existing $CONTAINER (--force)"
    docker rm -f "$CONTAINER" >/dev/null
  else
    warn "$CONTAINER is already running. Re-run with --force to recreate."
    say  "   Open:  http://127.0.0.1:${HOST_PORT}"
    say  "   Logs:  docker logs -f $CONTAINER"
    say  "   Stop:  curl -sSL ${SCRIPT_URL} | sh -s -- --stop"
    exit 0
  fi
elif docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  info "removing stopped $CONTAINER"
  docker rm "$CONTAINER" >/dev/null
fi

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

if [ "${TZEL_SKIP_PULL:-0}" = "1" ]; then
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    die "TZEL_SKIP_PULL=1 but $IMAGE is not present locally. Build it first or unset TZEL_SKIP_PULL."
  fi
  info "skipping pull (TZEL_SKIP_PULL=1) — using local $IMAGE"
else
  info "pulling $IMAGE"
  docker pull "$IMAGE" >/dev/null
fi
# Print the resolved image digest so a user can pin the next install to
# the exact same artifact (TZEL_WALLET_IMAGE=...@sha256:<digest>) and so
# the install is auditable after the fact.
digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)
if [ -n "$digest" ]; then
  info "image digest: $digest"
fi

info "starting $CONTAINER on http://127.0.0.1:${HOST_PORT}"
# Build the -e flag list from any TZEL_* env vars set in the caller's
# environment. This lets operators retarget a different network without
# modifying this script:
#   TZEL_ROLLUP_RPC_URL=http://... TZEL_L1_RPC=https://... sh wallet-install.sh
env_flags=""
for var in TZEL_NETWORK TZEL_ROLLUP_RPC_URL TZEL_L1_RPC \
           TZEL_NETWORK_NAME TZEL_NETWORK_LABEL TZEL_TZKT_BASE_URL \
           TZEL_PROVING_SERVICE_URL; do
  eval "val=\${${var}:-}"
  if [ -n "$val" ]; then
    env_flags="$env_flags -e ${var}=${val}"
  fi
done
# shellcheck disable=SC2086
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  -p "127.0.0.1:${HOST_PORT}:80" \
  -v "${DATA_DIR}:/home/tzel/.tzel-wallet" \
  $env_flags \
  "$IMAGE" >/dev/null

# ---- liveness check ---------------------------------------------------

info "waiting for wallet to be ready"
ok=0
i=1
while [ "$i" -le 60 ]; do
  if curl -fsS "http://127.0.0.1:${HOST_PORT}/healthz" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 1
  i=$((i+1))
done
if [ "$ok" -ne 1 ]; then
  warn "wallet did not come up within 60 s. Check: docker logs -f $CONTAINER"
  warn "If a previous install left a broken container, re-run with --force to recreate it."
  exit 1
fi

# ---- done --------------------------------------------------------------

cat <<EOF

${green}Wallet is running.${off}
  Open:    ${green}http://127.0.0.1:${HOST_PORT}${off}
  Logs:    docker logs -f ${CONTAINER}
  Stop:    curl -sSL ${SCRIPT_URL} | sh -s -- --stop
  Data:    ${DATA_DIR}  ${dim}(back this up — no recovery without it)${off}

EOF
