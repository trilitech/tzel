#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-/etc/tzel/shadownet.env}"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing env file: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

required_vars=(
  TZEL_OCTEZ_NODE_BIN
  TZEL_OCTEZ_CLIENT_BIN
  TZEL_DAL_NODE_BIN
  TZEL_ROLLUP_NODE_BIN
  TZEL_OPERATOR_BIN
  TZEL_OPERATOR_BEARER_TOKEN_FILE
  TZEL_L1_RPC_URL
  TZEL_DAL_RPC_ADDR
  TZEL_DAL_PUBLIC_ADDR
  TZEL_ROLLUP_RPC_HOST
  TZEL_ROLLUP_RPC_PORT
  TZEL_OPERATOR_LISTEN
  TZEL_ROLLUP_ADDRESS
  TZEL_OCTEZ_CLIENT_DIR
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
  echo "ok: $label -> $path"
}

check_http() {
  local label="$1"
  local url="$2"
  if ! curl -fsS "$url" >/dev/null; then
    echo "failed: $label -> $url" >&2
    exit 1
  fi
  echo "ok: $label -> $url"
}

check_cmd "octez-node" "$TZEL_OCTEZ_NODE_BIN"
check_cmd "octez-client" "$TZEL_OCTEZ_CLIENT_BIN"
check_cmd "octez-dal-node" "$TZEL_DAL_NODE_BIN"
check_cmd "octez-smart-rollup-node" "$TZEL_ROLLUP_NODE_BIN"
check_cmd "tzel-operator" "$TZEL_OPERATOR_BIN"

if [[ ! -f "$TZEL_OPERATOR_BEARER_TOKEN_FILE" ]]; then
  echo "missing operator bearer token file: $TZEL_OPERATOR_BEARER_TOKEN_FILE" >&2
  exit 1
fi
if [[ ! -r "$TZEL_OPERATOR_BEARER_TOKEN_FILE" ]]; then
  echo "operator bearer token file is not readable: $TZEL_OPERATOR_BEARER_TOKEN_FILE" >&2
  exit 1
fi
if [[ -z "$(tr -d '[:space:]' < "$TZEL_OPERATOR_BEARER_TOKEN_FILE")" ]]; then
  echo "operator bearer token file is empty: $TZEL_OPERATOR_BEARER_TOKEN_FILE" >&2
  exit 1
fi
echo "ok: operator bearer token -> $TZEL_OPERATOR_BEARER_TOKEN_FILE"

if ! "$TZEL_OCTEZ_CLIENT_BIN" -d "$TZEL_OCTEZ_CLIENT_DIR" show address "$TZEL_SOURCE_ALIAS" -S >/dev/null 2>&1; then
  echo "missing operator alias in octez-client dir: $TZEL_SOURCE_ALIAS ($TZEL_OCTEZ_CLIENT_DIR)" >&2
  exit 1
fi
echo "ok: operator alias -> $TZEL_SOURCE_ALIAS"

check_http "l1 rpc" "$TZEL_L1_RPC_URL/chains/main/blocks/head/hash"
check_http "dal synchronized" "http://$TZEL_DAL_RPC_ADDR/synchronized"
check_http "dal profiles" "http://$TZEL_DAL_RPC_ADDR/profiles"
check_http "rollup head" "http://$TZEL_ROLLUP_RPC_HOST:$TZEL_ROLLUP_RPC_PORT/global/block/head/hash"
check_http "operator health" "http://$TZEL_OPERATOR_LISTEN/healthz"

if [[ "${TZEL_DETECT_ENABLE:-0}" == "1" ]]; then
  detect_required_vars=(
    TZEL_DETECT_BIN
    TZEL_DETECT_WALLET
    TZEL_DETECT_LISTEN
  )
  for var in "${detect_required_vars[@]}"; do
    if [[ -z "${!var:-}" ]]; then
      echo "missing required detect env var: $var" >&2
      exit 1
    fi
  done
  check_cmd "tzel-detect" "$TZEL_DETECT_BIN"
  if [[ ! -f "$TZEL_DETECT_WALLET" ]]; then
    echo "missing detect wallet file: $TZEL_DETECT_WALLET" >&2
    exit 1
  fi
  echo "ok: detect wallet -> $TZEL_DETECT_WALLET"
  check_http "detect health" "http://$TZEL_DETECT_LISTEN/healthz"
fi

echo "public DAL address: $TZEL_DAL_PUBLIC_ADDR"
echo "rollup address: $TZEL_ROLLUP_ADDRESS"
echo "preflight passed"
