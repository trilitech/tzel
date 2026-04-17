#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-/etc/tzel/shadownet.env}"
SERVICE_USER="${2:-tzel}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run this script with sudo so it can create and chown service directories" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing env file: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

SERVICE_GROUP="$(id -gn "$SERVICE_USER" 2>/dev/null || true)"
if [[ -z "$SERVICE_GROUP" ]]; then
  echo "missing service group for $SERVICE_USER" >&2
  exit 1
fi
TOKEN_OWNER_UID="${SUDO_UID:-0}"

required_vars=(
  TZEL_OCTEZ_NODE_BIN
  TZEL_OCTEZ_CLIENT_BIN
  TZEL_DAL_NODE_BIN
  TZEL_ROLLUP_NODE_BIN
  TZEL_OPERATOR_BIN
  TZEL_OCTEZ_NODE_DATA_DIR
  TZEL_OCTEZ_NODE_RPC_ADDR
  TZEL_OCTEZ_NODE_NET_ADDR
  TZEL_OCTEZ_CLIENT_DIR
  TZEL_DAL_DATA_DIR
  TZEL_ROLLUP_DATA_DIR
  TZEL_OPERATOR_STATE_DIR
  TZEL_OPERATOR_BEARER_TOKEN_FILE
  TZEL_SOURCE_ALIAS
)

for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "missing required env var: $var" >&2
    exit 1
  fi
done

check_cmd() {
  local label="$1"
  local path="$2"
  if [[ ! -x "$path" ]]; then
    echo "missing executable for $label: $path" >&2
    exit 1
  fi
}

check_cmd "octez-node" "$TZEL_OCTEZ_NODE_BIN"
check_cmd "octez-client" "$TZEL_OCTEZ_CLIENT_BIN"
check_cmd "octez-dal-node" "$TZEL_DAL_NODE_BIN"
check_cmd "octez-smart-rollup-node" "$TZEL_ROLLUP_NODE_BIN"
check_cmd "tzel-operator" "$TZEL_OPERATOR_BIN"
if ! command -v python3 >/dev/null 2>&1; then
  echo "missing executable for python3" >&2
  exit 1
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" \
  "$TZEL_OCTEZ_NODE_DATA_DIR" \
  "$TZEL_OCTEZ_CLIENT_DIR" \
  "$TZEL_DAL_DATA_DIR" \
  "$TZEL_ROLLUP_DATA_DIR" \
  "$TZEL_OPERATOR_STATE_DIR"
mkdir -p "$(dirname "$TZEL_OPERATOR_BEARER_TOKEN_FILE")"

if [[ ! -f "$TZEL_OPERATOR_BEARER_TOKEN_FILE" ]]; then
  echo "generating operator bearer token"
  python3 - <<'PY' >"$TZEL_OPERATOR_BEARER_TOKEN_FILE"
import secrets
print(secrets.token_urlsafe(32))
PY
fi
chown "$TOKEN_OWNER_UID:$SERVICE_GROUP" "$TZEL_OPERATOR_BEARER_TOKEN_FILE"
chmod 640 "$TZEL_OPERATOR_BEARER_TOKEN_FILE"

if [[ ! -f "$TZEL_OCTEZ_NODE_DATA_DIR/config.json" ]]; then
  echo "initializing octez-node config for shadownet"
  "$TZEL_OCTEZ_NODE_BIN" config init \
    --data-dir "$TZEL_OCTEZ_NODE_DATA_DIR" \
    --network shadownet \
    --rpc-addr "$TZEL_OCTEZ_NODE_RPC_ADDR" \
    --net-addr "$TZEL_OCTEZ_NODE_NET_ADDR"
fi

if [[ ! -f "$TZEL_OCTEZ_NODE_DATA_DIR/identity.json" ]]; then
  echo "generating octez-node identity"
  "$TZEL_OCTEZ_NODE_BIN" identity generate --data-dir "$TZEL_OCTEZ_NODE_DATA_DIR" 0
fi

chown -R "$SERVICE_USER:$SERVICE_USER" \
  "$TZEL_OCTEZ_NODE_DATA_DIR" \
  "$TZEL_OCTEZ_CLIENT_DIR" \
  "$TZEL_DAL_DATA_DIR" \
  "$TZEL_ROLLUP_DATA_DIR" \
  "$TZEL_OPERATOR_STATE_DIR"

echo "initialized local state directories:"
echo "  node: $TZEL_OCTEZ_NODE_DATA_DIR"
echo "  client: $TZEL_OCTEZ_CLIENT_DIR"
echo "  dal: $TZEL_DAL_DATA_DIR"
echo "  rollup: $TZEL_ROLLUP_DATA_DIR"
echo "  operator: $TZEL_OPERATOR_STATE_DIR"
echo "  operator bearer token: $TZEL_OPERATOR_BEARER_TOKEN_FILE"
echo "next:"
echo "  1. import the operator key into $TZEL_OCTEZ_CLIENT_DIR for alias $TZEL_SOURCE_ALIAS"
echo "  2. start the services"
