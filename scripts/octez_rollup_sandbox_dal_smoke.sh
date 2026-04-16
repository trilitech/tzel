#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for cmd in octez-node octez-client octez-smart-rollup-node octez-dal-node smart-rollup-installer cargo curl python3 xxd rustup; do
  command -v "${cmd}" >/dev/null 2>&1 || {
    echo "missing required command: ${cmd}" >&2
    exit 1
  }
done

WORKDIR="${TZEL_OCTEZ_DAL_SANDBOX_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/tzel-octez-dal-sandbox.XXXXXX")}"
PRESERVE="${TZEL_OCTEZ_SANDBOX_PRESERVE:-0}"
RUST_TOOLCHAIN="${TZEL_ROLLUP_RUST_TOOLCHAIN:-stable}"
pick_free_port() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

NODE_RPC_PORT="${TZEL_OCTEZ_NODE_RPC_PORT:-$(pick_free_port)}"
NODE_NET_PORT="${TZEL_OCTEZ_NODE_NET_PORT:-$(pick_free_port)}"
ROLLUP_RPC_PORT="${TZEL_OCTEZ_ROLLUP_RPC_PORT:-$(pick_free_port)}"
DAL_RPC_PORT="${TZEL_OCTEZ_DAL_RPC_PORT:-$(pick_free_port)}"
DAL_NET_PORT="${TZEL_OCTEZ_DAL_NET_PORT:-$(pick_free_port)}"
OPERATOR_PORT="${TZEL_OPERATOR_PORT:-$(pick_free_port)}"
DAL_ATTESTATION_LAG="${TZEL_OCTEZ_DAL_ATTESTATION_LAG:-2}"
DAL_OPERATOR_PROFILES="${TZEL_OCTEZ_DAL_OPERATOR_PROFILES:-0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}"
DAL_EXPECTED_POW="${TZEL_OCTEZ_DAL_EXPECTED_POW:-0}"
CLIENT_DIR="${WORKDIR}/client"
MOCKUP_DIR="${WORKDIR}/mockup"
NODE_DIR="${WORKDIR}/node"
ROLLUP_DIR="${WORKDIR}/rollup"
ROLLUP_PREIMAGES_DIR="${ROLLUP_DIR}/wasm_2_0_0"
DAL_DIR="${WORKDIR}/dal"
OPERATOR_STATE_DIR="${WORKDIR}/operator-state"
LOG_DIR="${WORKDIR}/logs"
DAL_CHUNKS_FILE="${WORKDIR}/dal-chunks.tsv"
DAL_CHUNKS_DIR="${WORKDIR}/dal-chunks"
RAW_PARAMS="${WORKDIR}/protocol-constants.json"
BOOTSTRAP_ACCOUNTS="${WORKDIR}/bootstrap-accounts.json"
PARAMS_FILE="${WORKDIR}/sandbox-parameters.json"
NODE_SANDBOX_FILE="${WORKDIR}/sandbox-node.json"
INSTALLER_HEX="${WORKDIR}/installer.hex"
NODE_LOG="${LOG_DIR}/octez-node.log"
DAL_LOG="${LOG_DIR}/octez-dal-node.log"
ROLLUP_LOG="${LOG_DIR}/octez-smart-rollup-node.log"
NODE_ENDPOINT="http://127.0.0.1:${NODE_RPC_PORT}"
ROLLUP_ENDPOINT="http://127.0.0.1:${ROLLUP_RPC_PORT}"
DAL_ENDPOINT="http://127.0.0.1:${DAL_RPC_PORT}"
FIXTURE_PATH="${ROOT}/tezos/rollup-kernel/testdata/verified_bridge_flow.json"
TICKETER_SCRIPT="${ROOT}/tezos/tez_bridge_ticketer.tz"
ALPHA_HASH="ProtoALphaALphaALphaALphaALphaALphaALphaALphaDdp3zK"
ACTIVATOR_SK="unencrypted:edsk31vznjHSSpGExDMHYASz45VZqXN4DPxvsa4hAyY8dHM28cZzp6"
ACTIVATOR_PK="edpkuSLWfVU1Vq7Jg9FucPyKmma6otcMHac9zG4oU1KMHSTBpJuGQ2"

mkdir -p \
  "${CLIENT_DIR}" \
  "${NODE_DIR}" \
  "${ROLLUP_DIR}" \
  "${ROLLUP_PREIMAGES_DIR}" \
  "${DAL_DIR}" \
  "${DAL_CHUNKS_DIR}" \
  "${OPERATOR_STATE_DIR}" \
  "${LOG_DIR}"

cleanup() {
  local code=$?
  if [[ -n "${ROLLUP_PID:-}" ]]; then
    kill "${ROLLUP_PID}" >/dev/null 2>&1 || true
    wait "${ROLLUP_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${DAL_PID:-}" ]]; then
    kill "${DAL_PID}" >/dev/null 2>&1 || true
    wait "${DAL_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${NODE_PID:-}" ]]; then
    kill "${NODE_PID}" >/dev/null 2>&1 || true
    wait "${NODE_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${PRESERVE}" == "1" ]]; then
    echo "preserved DAL sandbox workdir: ${WORKDIR}" >&2
  else
    rm -rf "${WORKDIR}"
  fi
  exit "${code}"
}

on_err() {
  local code=$?
  echo "sandbox DAL smoke failed at line ${BASH_LINENO[0]}: ${BASH_COMMAND}" >&2
  return "${code}"
}

trap on_err ERR
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

bootstrap_public_key_hash() {
  local alias_name="$1"
  octez-client -d "${CLIENT_DIR}" show address "${alias_name}" -S | awk '/Hash:/ {print $2}'
}

mockup_public_key() {
  local alias_name="$1"
  octez-client --mode mockup -d "${MOCKUP_DIR}" show address "${alias_name}" -S | awk '/Public Key:/ {print $3}'
}

current_block_level() {
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" rpc get /chains/main/blocks/head/header \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["level"])'
}

bake_block() {
  local dal_args=()
  if [[ "${1:-}" == "with-dal" ]]; then
    dal_args=(--dal-node "${DAL_ENDPOINT}")
  fi
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" \
    bake for operator bootstrap1 bootstrap2 bootstrap3 bootstrap4 bootstrap5 \
    --minimal-timestamp "${dal_args[@]}" >/dev/null
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

  python3 - "${RAW_PARAMS}" "${BOOTSTRAP_ACCOUNTS}" "${PARAMS_FILE}" "${operator_pk}" "${DAL_ATTESTATION_LAG}" "${pk1}" "${pk2}" "${pk3}" "${pk4}" "${pk5}" <<'PY'
import json, sys

constants_path, accounts_path, out_path, operator_pk, attestation_lag, *bootstrap_pks = sys.argv[1:]
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
data.setdefault("dal_parametric", {})["attestation_lag"] = int(attestation_lag)

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
  bake_block
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
  cargo "${cargo_toolchain_args[@]}" build -q -p tzel-rollup-kernel --bin octez_kernel_message --bin verified_bridge_fixture_message "${kernel_cargo_args[@]}"
}

fixture_metadata() {
  "${ROOT}/target/debug/verified_bridge_fixture_message" metadata "${FIXTURE_PATH}"
}

fixture_shield_raw_hex() {
  "${ROOT}/target/debug/verified_bridge_fixture_message" shield-raw "${FIXTURE_PATH}"
}

extract_fixture_fields() {
  local metadata_json="$1"
  python3 -c '
import json, sys
data = json.load(sys.stdin)
print(data["auth_domain"])
print(data["shield_program_hash"])
print(data["transfer_program_hash"])
print(data["unshield_program_hash"])
print(data["shield_sender"])
print(data["shield_amount"])
' <<<"${metadata_json}"
}

mutez_to_tez() {
  python3 - "$1" <<'PY'
import sys
amount = int(sys.argv[1])
whole = amount // 1_000_000
fractional = amount % 1_000_000
if fractional == 0:
    print(whole)
else:
    print(f"{whole}.{fractional:06d}".rstrip("0"))
PY
}

start_dal_node() {
  local attester_profiles="$1"
  octez-dal-node run \
    --data-dir "${DAL_DIR}" \
    --endpoint "${NODE_ENDPOINT}" \
    --expected-pow "${DAL_EXPECTED_POW}" \
    --rpc-addr "127.0.0.1:${DAL_RPC_PORT}" \
    --net-addr "127.0.0.1:${DAL_NET_PORT}" \
    --public-addr "127.0.0.1:${DAL_NET_PORT}" \
    --operator-profiles "${DAL_OPERATOR_PROFILES}" \
    --attester-profiles "${attester_profiles}" \
    --fetch-trusted-setup=true \
    >"${DAL_LOG}" 2>&1 &
  DAL_PID=$!
  wait_for "DAL node rpc" 60 curl -fsS "${DAL_ENDPOINT}/protocol_parameters"
}

originate_rollup() {
  local kernel_wasm boot_sector out
  kernel_wasm="${ROOT}/target/wasm32-unknown-unknown/release/tzel_rollup_kernel.wasm"
  smart-rollup-installer get-reveal-installer \
    -P "${ROLLUP_PREIMAGES_DIR}" \
    -u "${kernel_wasm}" \
    -o "${INSTALLER_HEX}" >/dev/null
  boot_sector="$(tr -d '\n' < "${INSTALLER_HEX}")"
  out="$(octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    originate smart rollup tzel from operator of kind wasm_2_0_0 of type '(pair bytes (ticket (pair nat (option bytes))))' with kernel "${boot_sector}" --burn-cap 999)"
  printf '%s\n' "${out}" > "${LOG_DIR}/originate-smart-rollup.out"
  bake_block with-dal
  printf '%s\n' "${out}" | grep -Eo 'sr1[1-9A-HJ-NP-Za-km-z]+' | head -n1
}

originate_ticketer() {
  local out
  out="$(octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    originate contract tzel_bridge_ticketer transferring 0 from operator \
    running "${TICKETER_SCRIPT}" --init Unit --burn-cap 999)"
  printf '%s\n' "${out}" > "${LOG_DIR}/originate-ticketer.out"
  bake_block with-dal
  printf '%s\n' "${out}" | grep -Eo 'KT1[1-9A-HJ-NP-Za-km-z]+' | head -n1
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
    --dal-node "${DAL_ENDPOINT}" \
    --acl-override allow-all \
    --no-degraded \
    >"${ROLLUP_LOG}" 2>&1 &
  ROLLUP_PID=$!
  wait_for "smart rollup node rpc" 60 curl -fsS "${ROLLUP_ENDPOINT}/openapi"
}

send_configure_verifier_message() {
  local rollup_address="$1"
  local auth_domain="$2"
  local shield_hash="$3"
  local transfer_hash="$4"
  local unshield_hash="$5"
  local message_hex
  message_hex="$("${ROOT}/target/debug/octez_kernel_message" configure-verifier "${rollup_address}" "${auth_domain}" "${shield_hash}" "${transfer_hash}" "${unshield_hash}")"
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    send smart rollup message "hex:[ \"${message_hex}\" ]" from operator >/dev/null
  bake_block with-dal
}

send_configure_bridge_message() {
  local rollup_address="$1"
  local ticketer="$2"
  local message_hex
  message_hex="$("${ROOT}/target/debug/octez_kernel_message" configure-bridge "${rollup_address}" "${ticketer}")"
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    send smart rollup message "hex:[ \"${message_hex}\" ]" from operator >/dev/null
  bake_block with-dal
}

read_rollup_u64() {
  local key="$1"
  curl -fsS "${ROLLUP_ENDPOINT}/global/block/head/durable/wasm_2_0_0/value?key=${key}" \
    | python3 -c '
import json, string, sys

raw = sys.stdin.read().strip()
payload = json.loads(raw) if raw.startswith("\"") else raw
payload = payload.strip()
if payload.startswith(("0x", "0X")):
    payload = payload[2:]
if payload and len(payload) % 2 == 0 and all(ch in string.hexdigits for ch in payload):
    data = bytes.fromhex(payload)
else:
    data = payload.encode()
if len(data) != 8:
    raise SystemExit(f"expected 8 bytes, got {len(data)} from {raw!r}")
print(int.from_bytes(data, "little"))
'
}

await_rollup_u64() {
  local key="$1"
  local expected="$2"
  local description="$3"
  local current i
  for ((i = 0; i < 180; i++)); do
    current="$(read_rollup_u64 "${key}" 2>/dev/null || true)"
    if [[ "${current}" == "${expected}" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${description}: expected ${expected}" >&2
  return 1
}

await_bridge_ticketer() {
  local ticketer="$1"
  local encoded_ticketer response
  encoded_ticketer="$(printf '%s' "${ticketer}" | xxd -ps -c 0)"
  local url="${ROLLUP_ENDPOINT}/global/block/head/durable/wasm_2_0_0/value?key=/tzel/v1/state/bridge/ticketer"
  local i
  for ((i = 0; i < 180; i++)); do
    response="$(curl -fsS "${url}" || true)"
    if [[ "${response}" == *"${ticketer}"* || "${response}" == *"${encoded_ticketer}"* ]]; then
      return 0
    fi
    sleep 1
  done
  echo "bridge ticketer did not appear in rollup durable storage" >&2
  return 1
}

deposit_to_bridge() {
  local ticketer="$1"
  local rollup_address="$2"
  local recipient="$3"
  local amount_mutez="$4"
  local recipient_hex tez_amount
  recipient_hex="$(printf '%s' "${recipient}" | xxd -ps -c 0)"
  tez_amount="$(mutez_to_tez "${amount_mutez}")"
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    transfer "${tez_amount}" from operator to "${ticketer}" \
    --entrypoint mint \
    --arg "(Pair 0x${recipient_hex} \"${rollup_address}\")" \
    --burn-cap 999 >/dev/null
  bake_block with-dal
}

payload_hash_hex() {
  python3 - "$1" <<'PY'
import hashlib, pathlib, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
digest = bytearray(hashlib.blake2s(data, digest_size=32).digest())
digest[31] &= 0x07
print(digest.hex())
PY
}

prepare_dal_chunks() {
  local payload_file="$1"
  local slot_size="$2"
  local number_of_slots="$3"
  rm -f "${DAL_CHUNKS_DIR}"/*
  python3 - "${payload_file}" "${slot_size}" "${number_of_slots}" "${DAL_CHUNKS_DIR}" <<'PY' > "${DAL_CHUNKS_FILE}"
import pathlib, sys

payload = pathlib.Path(sys.argv[1]).read_bytes()
slot_size = int(sys.argv[2])
number_of_slots = int(sys.argv[3])
chunks_dir = pathlib.Path(sys.argv[4])
chunks = [payload[i:i + slot_size] for i in range(0, len(payload), slot_size)]
for idx, chunk in enumerate(chunks):
    slot_index = idx % number_of_slots
    chunk_path = chunks_dir / f"chunk-{idx:04d}.bin"
    chunk_path.write_bytes(chunk)
    print(f"{slot_index}\t{len(chunk)}\t{chunk_path}")
PY
}

post_dal_chunk() {
  local slot_index="$1"
  local chunk_path="$2"
  local output_path="$3"
  python3 - "${DAL_ENDPOINT}" "${slot_index}" "${chunk_path}" "${output_path}" <<'PY'
import json, pathlib, sys, urllib.request

endpoint, slot_index, chunk_path, output_path = sys.argv[1:]
url = f"{endpoint.rstrip('/')}/slots?slot_index={slot_index}&padding=%00"
payload = pathlib.Path(chunk_path).read_bytes()
body = json.dumps({"invalid_utf8_string": list(payload)}).encode()
req = urllib.request.Request(
    url,
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req) as resp:
    pathlib.Path(output_path).write_bytes(resp.read())
PY
}

publish_dal_commitment_and_bake() {
  local commitment="$1"
  local slot_index="$2"
  local proof="$3"
  local current_level
  current_level="$(current_block_level)"
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    publish dal commitment "${commitment}" from operator for slot "${slot_index}" with proof "${proof}" >/dev/null
  bake_block with-dal
  printf '%s\n' "$(( current_level + 1 ))"
}

fetch_dal_slot_status() {
  local published_level="$1"
  local slot_index="$2"
  curl -fsS "${DAL_ENDPOINT}/levels/${published_level}/slots/${slot_index}/status" \
    | python3 -c 'import json, sys; data = json.load(sys.stdin); print(data if isinstance(data, str) else data.get("kind", ""))'
}

await_dal_attested() {
  local published_level="$1"
  local slot_index="$2"
  local i status
  for ((i = 0; i < 120; i++)); do
    status="$(fetch_dal_slot_status "${published_level}" "${slot_index}" 2>/dev/null || true)"
    case "${status}" in
      attested)
        return 0
        ;;
      unattested)
        echo "DAL slot ${slot_index} at level ${published_level} became unattested" >&2
        return 1
        ;;
      *)
        bake_block with-dal
        ;;
    esac
  done
  echo "timed out waiting for DAL slot ${slot_index} at level ${published_level} to attest" >&2
  return 1
}

publish_shield_via_dal_and_inject_pointer() {
  local rollup_address="$1"
  local payload_file="$2"
  local payload_len payload_hash number_of_slots slot_size
  payload_len="$(stat -c%s "${payload_file}")"
  payload_hash="$(payload_hash_hex "${payload_file}")"
  read -r number_of_slots slot_size < <(
    curl -fsS "${DAL_ENDPOINT}/protocol_parameters" \
      | python3 -c 'import json, sys; data = json.load(sys.stdin); print(data["number_of_slots"], data["cryptobox_parameters"]["slot_size"])'
  )
  prepare_dal_chunks "${payload_file}" "${slot_size}" "${number_of_slots}"

  local pointer_args=()
  while IFS=$'\t' read -r slot_index chunk_len chunk_path; do
    local publish_json_file commitment commitment_proof published_level
    publish_json_file="$(mktemp "${WORKDIR}/dal-publish.XXXXXX.json")"
    post_dal_chunk "${slot_index}" "${chunk_path}" "${publish_json_file}"
    mapfile -t publish_fields < <(python3 -c '
import json, sys
data = json.load(sys.stdin)
print(data["commitment"])
print(data["commitment_proof"])
' < "${publish_json_file}")
    commitment="${publish_fields[0]}"
    commitment_proof="${publish_fields[1]}"
    published_level="$(publish_dal_commitment_and_bake "${commitment}" "${slot_index}" "${commitment_proof}")"
    await_dal_attested "${published_level}" "${slot_index}"
    pointer_args+=("${published_level}" "${slot_index}" "${chunk_len}")
  done < "${DAL_CHUNKS_FILE}"

  local message_hex
  message_hex="$("${ROOT}/target/debug/octez_kernel_message" dal-pointer "${rollup_address}" shield "${payload_hash}" "${payload_len}" "${pointer_args[@]}")"
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    send smart rollup message "hex:[ \"${message_hex}\" ]" from operator >/dev/null
  bake_block with-dal
}

main() {
  prepare_client_material
  init_node
  start_node
  activate_alpha
  build_kernel_and_tools

  local attester_profiles
  attester_profiles="$(printf '%s,%s,%s,%s,%s' \
    "$(bootstrap_public_key_hash bootstrap1)" \
    "$(bootstrap_public_key_hash bootstrap2)" \
    "$(bootstrap_public_key_hash bootstrap3)" \
    "$(bootstrap_public_key_hash bootstrap4)" \
    "$(bootstrap_public_key_hash bootstrap5)")"

  start_dal_node "${attester_profiles}"

  local rollup_address ticketer_address
  rollup_address="$(originate_rollup)"
  ticketer_address="$(originate_ticketer)"
  start_rollup_node "${rollup_address}"
  local fixture_fields
  fixture_fields="$(extract_fixture_fields "$(fixture_metadata)")"
  mapfile -t fixture_lines <<<"${fixture_fields}"
  local auth_domain_hex shield_hash_hex transfer_hash_hex unshield_hash_hex shield_sender shield_amount
  auth_domain_hex="${fixture_lines[0]}"
  shield_hash_hex="${fixture_lines[1]}"
  transfer_hash_hex="${fixture_lines[2]}"
  unshield_hash_hex="${fixture_lines[3]}"
  shield_sender="${fixture_lines[4]}"
  shield_amount="${fixture_lines[5]}"

  send_configure_verifier_message "${rollup_address}" "${auth_domain_hex}" "${shield_hash_hex}" "${transfer_hash_hex}" "${unshield_hash_hex}"
  send_configure_bridge_message "${rollup_address}" "${ticketer_address}"
  await_bridge_ticketer "${ticketer_address}"

  deposit_to_bridge "${ticketer_address}" "${rollup_address}" "${shield_sender}" "${shield_amount}"

  local balance_key
  balance_key="/tzel/v1/state/balances/by-key/$(printf '%s' "${shield_sender}" | xxd -ps -c 0)"
  await_rollup_u64 "${balance_key}" "${shield_amount}" "public bridge balance"

  local shield_payload_file
  shield_payload_file="${WORKDIR}/shield-payload.bin"
  fixture_shield_raw_hex | xxd -r -p > "${shield_payload_file}"
  publish_shield_via_dal_and_inject_pointer "${rollup_address}" "${shield_payload_file}"

  await_rollup_u64 "${balance_key}" "0" "public balance drain after shield"
  await_rollup_u64 "/tzel/v1/state/tree/size" "1" "shielded note insertion"

  echo "octez rollup sandbox DAL smoke passed"
  echo "rollup=${rollup_address}"
  echo "ticketer=${ticketer_address}"
}

main "$@"
