#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for cmd in octez-node octez-client octez-smart-rollup-node smart-rollup-installer cargo curl python3 xxd; do
  command -v "${cmd}" >/dev/null 2>&1 || {
    echo "missing required command: ${cmd}" >&2
    exit 1
  }
done

WORKDIR="${TZEL_OCTEZ_SANDBOX_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/tzel-octez-sandbox.XXXXXX")}"
PRESERVE="${TZEL_OCTEZ_SANDBOX_PRESERVE:-0}"
RUST_TOOLCHAIN="${TZEL_ROLLUP_RUST_TOOLCHAIN:-stable}"
NODE_RPC_PORT="${TZEL_OCTEZ_NODE_RPC_PORT:-18732}"
NODE_NET_PORT="${TZEL_OCTEZ_NODE_NET_PORT:-19732}"
ROLLUP_RPC_PORT="${TZEL_OCTEZ_ROLLUP_RPC_PORT:-18932}"
CLIENT_DIR="${WORKDIR}/client"
MOCKUP_DIR="${WORKDIR}/mockup"
NODE_DIR="${WORKDIR}/node"
ROLLUP_DIR="${WORKDIR}/rollup"
ROLLUP_PREIMAGES_DIR="${ROLLUP_DIR}/wasm_2_0_0"
LOG_DIR="${WORKDIR}/logs"
RAW_PARAMS="${WORKDIR}/protocol-constants.json"
BOOTSTRAP_ACCOUNTS="${WORKDIR}/bootstrap-accounts.json"
PARAMS_FILE="${WORKDIR}/sandbox-parameters.json"
NODE_SANDBOX_FILE="${WORKDIR}/sandbox-node.json"
INSTALLER_HEX="${WORKDIR}/installer.hex"
NODE_LOG="${LOG_DIR}/octez-node.log"
ROLLUP_LOG="${LOG_DIR}/octez-smart-rollup-node.log"
NODE_ENDPOINT="http://127.0.0.1:${NODE_RPC_PORT}"
ROLLUP_ENDPOINT="http://127.0.0.1:${ROLLUP_RPC_PORT}"
ALPHA_HASH="ProtoALphaALphaALphaALphaALphaALphaALphaALphaDdp3zK"
ACTIVATOR_SK="unencrypted:edsk31vznjHSSpGExDMHYASz45VZqXN4DPxvsa4hAyY8dHM28cZzp6"
ACTIVATOR_PK="edpkuSLWfVU1Vq7Jg9FucPyKmma6otcMHac9zG4oU1KMHSTBpJuGQ2"
SAMPLE_TICKETER="KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc"

mkdir -p "${CLIENT_DIR}" "${NODE_DIR}" "${ROLLUP_DIR}" "${ROLLUP_PREIMAGES_DIR}" "${LOG_DIR}"

cleanup() {
  local code=$?
  if [[ -n "${ROLLUP_PID:-}" ]]; then
    kill "${ROLLUP_PID}" >/dev/null 2>&1 || true
    wait "${ROLLUP_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${NODE_PID:-}" ]]; then
    kill "${NODE_PID}" >/dev/null 2>&1 || true
    wait "${NODE_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${PRESERVE}" == "1" ]]; then
    echo "preserved sandbox workdir: ${WORKDIR}" >&2
  else
    rm -rf "${WORKDIR}"
  fi
  exit "${code}"
}
trap cleanup EXIT

wait_for() {
  local description="$1"
  local retries="$2"
  shift 2
  local i
  for ((i = 0; i < retries; i++)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${description}" >&2
  return 1
}

operator_public_key() {
  octez-client -d "${CLIENT_DIR}" show address operator -S | awk '/Public Key:/ {print $3}'
}

mockup_public_key() {
  local alias_name="$1"
  octez-client --mode mockup -d "${MOCKUP_DIR}" show address "${alias_name}" -S | awk '/Public Key:/ {print $3}'
}

build_alpha_sandbox_params() {
  local operator_pk="$1"
  rm -rf "${MOCKUP_DIR}"
  mkdir -p "${MOCKUP_DIR}"
  octez-client --mode mockup -d "${MOCKUP_DIR}" create mockup >/dev/null
  octez-client --mode mockup -d "${MOCKUP_DIR}" config init \
    --protocol-constants "${RAW_PARAMS}" \
    --bootstrap-accounts "${BOOTSTRAP_ACCOUNTS}" >/dev/null

  local pk1 pk2 pk3 pk4 pk5
  pk1="$(mockup_public_key bootstrap1)"
  pk2="$(mockup_public_key bootstrap2)"
  pk3="$(mockup_public_key bootstrap3)"
  pk4="$(mockup_public_key bootstrap4)"
  pk5="$(mockup_public_key bootstrap5)"

  python3 - "${RAW_PARAMS}" "${BOOTSTRAP_ACCOUNTS}" "${PARAMS_FILE}" "${operator_pk}" "${pk1}" "${pk2}" "${pk3}" "${pk4}" "${pk5}" <<'PY'
import json, sys

constants_path, accounts_path, out_path, operator_pk, *bootstrap_pks = sys.argv[1:]
with open(constants_path, "r", encoding="utf-8") as f:
    data = json.load(f)
with open(accounts_path, "r", encoding="utf-8") as f:
    accounts = json.load(f)

bootstrap_accounts = []
for account, pk in zip(accounts, bootstrap_pks):
    bootstrap_accounts.append([pk, account["amount"]])
bootstrap_accounts.append([operator_pk, "3800000000000"])

data["bootstrap_accounts"] = bootstrap_accounts
data.pop("chain_id", None)
data.pop("initial_timestamp", None)
data["minimal_block_delay"] = "1"
data["delay_increment_per_round"] = "1"

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

import_bootstrap_identities() {
  python3 - "${BOOTSTRAP_ACCOUNTS}" <<'PY' | while read -r alias_name secret; do
import json, sys
for item in json.load(open(sys.argv[1], "r", encoding="utf-8")):
    print(item["name"], item["sk_uri"])
PY
    octez-client -d "${CLIENT_DIR}" import secret key "${alias_name}" "${secret}" --force >/dev/null
  done
}

prepare_client_material() {
  octez-client -d "${CLIENT_DIR}" import secret key activator "${ACTIVATOR_SK}" --force >/dev/null
  octez-client -d "${CLIENT_DIR}" gen keys operator --force >/dev/null
  local operator_pk
  operator_pk="$(operator_public_key)"
  build_alpha_sandbox_params "${operator_pk}"
  import_bootstrap_identities
  cat > "${NODE_SANDBOX_FILE}" <<EOF
{
  "genesis_pubkey": "${ACTIVATOR_PK}"
}
EOF
}

init_node() {
  octez-node config init \
    --data-dir "${NODE_DIR}" \
    --network sandbox \
    --rpc-addr "127.0.0.1:${NODE_RPC_PORT}" \
    --allow-all-rpc "127.0.0.1:${NODE_RPC_PORT}" \
    --net-addr "127.0.0.1:${NODE_NET_PORT}" \
    --no-bootstrap-peers \
    --connections 0 \
    --synchronisation-threshold 0 >/dev/null
  octez-node identity generate --data-dir "${NODE_DIR}" 0 >/dev/null
}

start_node() {
  octez-node run \
    --data-dir "${NODE_DIR}" \
    --network sandbox \
    --sandbox "${NODE_SANDBOX_FILE}" \
    --rpc-addr "127.0.0.1:${NODE_RPC_PORT}" \
    --allow-all-rpc "127.0.0.1:${NODE_RPC_PORT}" \
    --net-addr "127.0.0.1:${NODE_NET_PORT}" \
    --no-bootstrap-peers \
    --connections 0 \
    --synchronisation-threshold 0 \
    >"${NODE_LOG}" 2>&1 &
  NODE_PID=$!
  wait_for "octez node rpc" 60 octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" rpc get /version
}

activate_alpha() {
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" \
    -b genesis \
    activate protocol "${ALPHA_HASH}" \
    with fitness 1 and key activator and parameters "${PARAMS_FILE}" \
    --timestamp "$(date -u +%FT%TZ)" >/dev/null
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" bake for operator --minimal-timestamp >/dev/null
}

build_kernel_and_tools() {
  local kernel_cargo_args=()
  local cargo_toolchain_args=()
  local rustup_toolchain_args=()
  if [[ -n "${TZEL_ROLLUP_KERNEL_CARGO_ARGS:-}" ]]; then
    read -r -a kernel_cargo_args <<< "${TZEL_ROLLUP_KERNEL_CARGO_ARGS}"
  fi
  if [[ -n "${RUST_TOOLCHAIN}" ]]; then
    cargo_toolchain_args=("+${RUST_TOOLCHAIN}")
    rustup_toolchain_args=(--toolchain "${RUST_TOOLCHAIN}")
  fi
  rustup target list --installed "${rustup_toolchain_args[@]}" | grep -qx 'wasm32-unknown-unknown' \
    || rustup target add "${rustup_toolchain_args[@]}" wasm32-unknown-unknown >/dev/null
  cargo "${cargo_toolchain_args[@]}" build -q -p tzel-rollup-kernel --target wasm32-unknown-unknown --release "${kernel_cargo_args[@]}"
  cargo "${cargo_toolchain_args[@]}" build -q -p tzel-rollup-kernel --bin octez_kernel_message "${kernel_cargo_args[@]}"
}

originate_rollup() {
  local kernel_wasm boot_sector out
  kernel_wasm="${ROOT}/target/wasm32-unknown-unknown/release/tzel_rollup_kernel.wasm"
  smart-rollup-installer get-reveal-installer \
    -P "${ROLLUP_PREIMAGES_DIR}" \
    -u "${kernel_wasm}" \
    -o "${INSTALLER_HEX}" >/dev/null
  boot_sector="$(tr -d '\n' < "${INSTALLER_HEX}")"
  out="$(octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -w none \
    originate smart rollup tzel from operator of kind wasm_2_0_0 of type bytes with kernel "${boot_sector}" --burn-cap 999)"
  printf '%s\n' "${out}" > "${LOG_DIR}/originate-smart-rollup.out"
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" bake for operator --minimal-timestamp >/dev/null
  octez-client -d "${CLIENT_DIR}" show known smart rollup tzel | rg -o 'sr1[1-9A-HJ-NP-Za-km-z]+' | head -n1
}

start_rollup_node() {
  local rollup_addr="$1"
  octez-smart-rollup-node \
    -d "${CLIENT_DIR}" \
    -E "${NODE_ENDPOINT}" \
    run \
    --data-dir "${ROLLUP_DIR}" \
    --mode observer \
    --rollup "${rollup_addr}" \
    --rpc-addr 127.0.0.1 \
    --rpc-port "${ROLLUP_RPC_PORT}" \
    --acl-override allow-all \
    --no-degraded \
    >"${ROLLUP_LOG}" 2>&1 &
  ROLLUP_PID=$!
  wait_for "smart rollup node rpc" 60 curl -fsS "${ROLLUP_ENDPOINT}/openapi"
}

send_configure_bridge_message() {
  local message_hex
  message_hex="$("${ROOT}/target/debug/octez_kernel_message" configure-bridge "${SAMPLE_TICKETER}")"
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    send smart rollup message "hex:[ \"${message_hex}\" ]" from operator >/dev/null
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" bake for operator --minimal-timestamp >/dev/null
}

await_bridge_ticketer() {
  local encoded_ticketer response
  encoded_ticketer="$(printf '%s' "${SAMPLE_TICKETER}" | xxd -ps -c 0)"
  local url="${ROLLUP_ENDPOINT}/global/block/head/durable/wasm_2_0_0/value?key=/tzel/v1/state/bridge/ticketer"
  local i
  for ((i = 0; i < 90; i++)); do
    response="$(curl -fsS "${url}" || true)"
    if [[ "${response}" == *"${SAMPLE_TICKETER}"* || "${response}" == *"${encoded_ticketer}"* ]]; then
      return 0
    fi
    sleep 1
  done
  echo "bridge ticketer did not appear in rollup durable storage" >&2
  echo "node log: ${NODE_LOG}" >&2
  echo "rollup log: ${ROLLUP_LOG}" >&2
  return 1
}

main() {
  prepare_client_material
  init_node
  start_node
  activate_alpha
  build_kernel_and_tools
  local rollup_addr
  rollup_addr="$(originate_rollup)"
  start_rollup_node "${rollup_addr}"
  send_configure_bridge_message
  await_bridge_ticketer
  echo "octez rollup sandbox smoke passed"
}

main "$@"
