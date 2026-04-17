#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-/etc/tzel/shadownet.env}"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing env file: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

TZEL_WALLET_BIN="${TZEL_WALLET_BIN:-/usr/local/bin/tzel-wallet}"
TZEL_REPROVE_BIN="${TZEL_REPROVE_BIN:-/usr/local/bin/reprove}"
TZEL_EXECUTABLES_DIR="${TZEL_EXECUTABLES_DIR:-/opt/tzel/cairo/target/dev}"
TZEL_SMOKE_WORKDIR="${TZEL_SMOKE_WORKDIR:-$(mktemp -d /tmp/tzel-shadownet-smoke.XXXXXX)}"
TZEL_SMOKE_DEPOSIT_AMOUNT="${TZEL_SMOKE_DEPOSIT_AMOUNT:-300000}"
TZEL_SMOKE_SHIELD_AMOUNT="${TZEL_SMOKE_SHIELD_AMOUNT:-200000}"
TZEL_SMOKE_SEND_AMOUNT="${TZEL_SMOKE_SEND_AMOUNT:-50000}"
TZEL_SMOKE_UNSHIELD_AMOUNT="${TZEL_SMOKE_UNSHIELD_AMOUNT:-20000}"
TZEL_SMOKE_WITHDRAW_AMOUNT="${TZEL_SMOKE_WITHDRAW_AMOUNT:-20000}"
TZEL_SMOKE_POLL_SECS="${TZEL_SMOKE_POLL_SECS:-5}"
TZEL_SMOKE_MAX_POLLS="${TZEL_SMOKE_MAX_POLLS:-120}"

required_vars=(
  TZEL_ROLLUP_ADDRESS
  TZEL_BRIDGE_TICKETER
  TZEL_SOURCE_ALIAS
  TZEL_OCTEZ_CLIENT_BIN
  TZEL_OCTEZ_CLIENT_DIR
  TZEL_L1_RPC_URL
  TZEL_ROLLUP_RPC_HOST
  TZEL_ROLLUP_RPC_PORT
  TZEL_OPERATOR_LISTEN
  TZEL_OPERATOR_BEARER_TOKEN_FILE
)

for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "missing required env var: $var" >&2
    exit 1
  fi
done

if [[ -z "${TZEL_SMOKE_L1_RECIPIENT:-}" ]]; then
  echo "set TZEL_SMOKE_L1_RECIPIENT to a tz1/KT1 withdrawal recipient" >&2
  exit 1
fi
if [[ ! -f "${TZEL_OPERATOR_BEARER_TOKEN_FILE}" ]]; then
  echo "missing operator bearer token file: ${TZEL_OPERATOR_BEARER_TOKEN_FILE}" >&2
  exit 1
fi

ROLLUP_NODE_URL="http://${TZEL_ROLLUP_RPC_HOST}:${TZEL_ROLLUP_RPC_PORT}"
OPERATOR_URL="http://${TZEL_OPERATOR_LISTEN}"
ALICE_WALLET="${TZEL_SMOKE_WORKDIR}/alice.wallet"
BOB_WALLET="${TZEL_SMOKE_WORKDIR}/bob.wallet"
BOB_ADDRESS_JSON="${TZEL_SMOKE_WORKDIR}/bob.address.json"

cleanup() {
  if [[ "${TZEL_SMOKE_PRESERVE:-0}" != "1" ]]; then
    rm -rf "${TZEL_SMOKE_WORKDIR}"
  else
    echo "preserved smoke workdir: ${TZEL_SMOKE_WORKDIR}" >&2
  fi
}
trap cleanup EXIT

require_cmd() {
  if [[ ! -x "$1" ]]; then
    echo "missing executable: $1" >&2
    exit 1
  fi
}

wallet_cmd() {
  local wallet="$1"
  shift
  "${TZEL_WALLET_BIN}" --wallet "${wallet}" "$@"
}

wallet_prove_cmd() {
  local wallet="$1"
  shift
  "${TZEL_WALLET_BIN}" \
    --wallet "${wallet}" \
    --reprove-bin "${TZEL_REPROVE_BIN}" \
    --executables-dir "${TZEL_EXECUTABLES_DIR}" \
    "$@"
}

extract_submission_id() {
  sed -n 's/^Submission id: //p' | tail -n1
}

extract_public_balance() {
  sed -n 's/^Public rollup balance (.*): //p' | tail -n1
}

extract_private_available() {
  sed -n 's/^Private available: //p' | tail -n1
}

wait_for_submission_terminal() {
  local wallet="$1"
  local submission_id="$2"
  local attempt output
  for ((attempt = 1; attempt <= TZEL_SMOKE_MAX_POLLS; attempt++)); do
    output="$(wallet_cmd "${wallet}" status --submission-id "${submission_id}")"
    printf '%s\n' "${output}"
    if grep -q '^Status: submitted_to_l1 ' <<<"${output}"; then
      return 0
    fi
    if grep -q '^Status: failed ' <<<"${output}"; then
      echo "submission ${submission_id} failed" >&2
      return 1
    fi
    sleep "${TZEL_SMOKE_POLL_SECS}"
  done
  echo "timed out waiting for submission ${submission_id}" >&2
  return 1
}

wait_for_public_balance_at_least() {
  local wallet="$1"
  local expected="$2"
  local attempt output balance
  for ((attempt = 1; attempt <= TZEL_SMOKE_MAX_POLLS; attempt++)); do
    output="$(wallet_cmd "${wallet}" balance)"
    printf '%s\n' "${output}"
    balance="$(extract_public_balance <<<"${output}")"
    if [[ -n "${balance}" && "${balance}" =~ ^[0-9]+$ && "${balance}" -ge "${expected}" ]]; then
      return 0
    fi
    sleep "${TZEL_SMOKE_POLL_SECS}"
  done
  echo "timed out waiting for public balance >= ${expected}" >&2
  return 1
}

wait_for_public_balance_equals() {
  local wallet="$1"
  local expected="$2"
  local attempt output balance
  for ((attempt = 1; attempt <= TZEL_SMOKE_MAX_POLLS; attempt++)); do
    output="$(wallet_cmd "${wallet}" balance)"
    printf '%s\n' "${output}"
    balance="$(extract_public_balance <<<"${output}")"
    if [[ -n "${balance}" && "${balance}" =~ ^[0-9]+$ && "${balance}" -eq "${expected}" ]]; then
      return 0
    fi
    sleep "${TZEL_SMOKE_POLL_SECS}"
  done
  echo "timed out waiting for public balance == ${expected}" >&2
  return 1
}

wait_for_private_available_at_least() {
  local wallet="$1"
  local expected="$2"
  local attempt output balance
  for ((attempt = 1; attempt <= TZEL_SMOKE_MAX_POLLS; attempt++)); do
    wallet_cmd "${wallet}" sync >/dev/null
    output="$(wallet_cmd "${wallet}" balance)"
    printf '%s\n' "${output}"
    balance="$(extract_private_available <<<"${output}")"
    if [[ -n "${balance}" && "${balance}" =~ ^[0-9]+$ && "${balance}" -ge "${expected}" ]]; then
      return 0
    fi
    sleep "${TZEL_SMOKE_POLL_SECS}"
  done
  echo "timed out waiting for private available >= ${expected}" >&2
  return 1
}

init_profile() {
  local wallet="$1"
  local public_account="$2"
  wallet_cmd "${wallet}" profile init-shadownet \
    --rollup-node-url "${ROLLUP_NODE_URL}" \
    --rollup-address "${TZEL_ROLLUP_ADDRESS}" \
    --bridge-ticketer "${TZEL_BRIDGE_TICKETER}" \
    --operator-url "${OPERATOR_URL}" \
    --operator-bearer-token "$(cat "${TZEL_OPERATOR_BEARER_TOKEN_FILE}")" \
    --source-alias "${TZEL_SOURCE_ALIAS}" \
    --public-account "${public_account}" \
    --octez-client-bin "${TZEL_OCTEZ_CLIENT_BIN}" \
    --octez-client-dir "${TZEL_OCTEZ_CLIENT_DIR}" \
    --octez-node-endpoint "${TZEL_L1_RPC_URL}"
}

require_cmd "${TZEL_WALLET_BIN}"
require_cmd "${TZEL_REPROVE_BIN}"
require_cmd "${TZEL_OCTEZ_CLIENT_BIN}"

mkdir -p "${TZEL_SMOKE_WORKDIR}"

wallet_cmd "${ALICE_WALLET}" init
wallet_cmd "${BOB_WALLET}" init
init_profile "${ALICE_WALLET}" alice
init_profile "${BOB_WALLET}" bob

wallet_cmd "${BOB_WALLET}" receive | tail -n +2 > "${BOB_ADDRESS_JSON}"

wallet_cmd "${ALICE_WALLET}" check
wallet_cmd "${BOB_WALLET}" check

wallet_cmd "${ALICE_WALLET}" deposit --amount "${TZEL_SMOKE_DEPOSIT_AMOUNT}" --public-account alice
wait_for_public_balance_at_least "${ALICE_WALLET}" "${TZEL_SMOKE_DEPOSIT_AMOUNT}"

shield_output="$(wallet_prove_cmd "${ALICE_WALLET}" shield --amount "${TZEL_SMOKE_SHIELD_AMOUNT}")"
printf '%s\n' "${shield_output}"
shield_submission_id="$(extract_submission_id <<<"${shield_output}")"
if [[ -z "${shield_submission_id}" ]]; then
  echo "failed to extract shield submission id" >&2
  exit 1
fi
wait_for_submission_terminal "${ALICE_WALLET}" "${shield_submission_id}"
wait_for_private_available_at_least "${ALICE_WALLET}" "${TZEL_SMOKE_SHIELD_AMOUNT}"

send_output="$(wallet_prove_cmd "${ALICE_WALLET}" send --to "${BOB_ADDRESS_JSON}" --amount "${TZEL_SMOKE_SEND_AMOUNT}")"
printf '%s\n' "${send_output}"
send_submission_id="$(extract_submission_id <<<"${send_output}")"
if [[ -z "${send_submission_id}" ]]; then
  echo "failed to extract send submission id" >&2
  exit 1
fi
wait_for_submission_terminal "${ALICE_WALLET}" "${send_submission_id}"
wait_for_private_available_at_least "${BOB_WALLET}" "${TZEL_SMOKE_SEND_AMOUNT}"

unshield_output="$(wallet_prove_cmd "${BOB_WALLET}" unshield --amount "${TZEL_SMOKE_UNSHIELD_AMOUNT}" --recipient bob)"
printf '%s\n' "${unshield_output}"
unshield_submission_id="$(extract_submission_id <<<"${unshield_output}")"
if [[ -z "${unshield_submission_id}" ]]; then
  echo "failed to extract unshield submission id" >&2
  exit 1
fi
wait_for_submission_terminal "${BOB_WALLET}" "${unshield_submission_id}"
wait_for_public_balance_at_least "${BOB_WALLET}" "${TZEL_SMOKE_UNSHIELD_AMOUNT}"

withdraw_output="$(wallet_cmd "${BOB_WALLET}" withdraw --amount "${TZEL_SMOKE_WITHDRAW_AMOUNT}" --sender bob --recipient "${TZEL_SMOKE_L1_RECIPIENT}")"
printf '%s\n' "${withdraw_output}"
wait_for_public_balance_equals "${BOB_WALLET}" "$((TZEL_SMOKE_UNSHIELD_AMOUNT - TZEL_SMOKE_WITHDRAW_AMOUNT))"

echo "Shadownet smoke completed successfully."
echo "Workdir: ${TZEL_SMOKE_WORKDIR}"
