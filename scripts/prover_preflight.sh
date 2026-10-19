#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-/etc/tzel/prover.env}"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing env file: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

required_vars=(
  TZEL_REPROVE_BIN
)

for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "missing required env var: $var" >&2
    exit 1
  fi
done

check_exec() {
  local label="$1"
  local path="$2"
  if [[ ! -x "$path" ]]; then
    echo "missing executable for $label: $path" >&2
    exit 1
  fi
  echo "ok: $label -> $path"
}

check_exec "reprove" "$TZEL_REPROVE_BIN"
if [[ -n "${TZEL_WALLET_BIN:-}" ]]; then
  check_exec "tzel-wallet" "$TZEL_WALLET_BIN"
fi

for executable in \
  tzel_run_shield.executable.json \
  tzel_run_transfer.executable.json \
  tzel_run_unshield.executable.json
do
  hash="$("$TZEL_REPROVE_BIN" "$executable" --program-hash)"
  if [[ -z "$hash" ]]; then
    echo "reprove returned empty program hash for $executable" >&2
    exit 1
  fi
  echo "ok: program hash $executable -> $hash"
done

echo "prover preflight passed"
