#!/usr/bin/env bash
# Orchestrator (Mode A) sandbox smoke.
#
# Validates the on-chain dispatch path end to end on a local Octez sandbox:
#
#   tzel_orchestrator.tz %shield (KT1, internal TRANSFER_TOKENS bytes)
#     -> smart rollup inbox internal Transfer<MichelsonBytes>
#     -> kernel decode_rollup_message pass 2 (rollup-kernel/src/lib.rs)
#     -> decode_kernel_inbox_message -> apply_kernel_message
#
# Two calls, two deterministic kernel-side rejections (the verifier is
# intentionally left unconfigured — no DAL machinery needed; the assertion
# target is the kernel dispatch, not proof validity):
#
#   1. %shield with a truncated stub body. A *complete* wire-valid Shield
#      body carries two mandatory encrypted notes (~3.4 KiB each) and can
#      never fit in the 4096-byte L1 smart-rollup inbox message cap, so the
#      shield entrypoint is exercised with a deliberately truncated body.
#      The kernel must record `Error("invalid inbox message: ...")` in
#      last_result.bin — proving the internal transfer was routed to
#      decode_kernel_inbox_message (an ignored/foreign message writes
#      nothing).
#   2. %unshield with a complete wire-valid stub body
#      (`octez_kernel_message raw-stub-unshield`, one note, ~3.7 KiB —
#      the only user-facing request that fits under the cap). It decodes
#      cleanly, reaches apply_kernel_message and is rejected with
#      `Error("proof verifier is not configured")` — proving the full
#      Mode A dispatch chain.
#
# Differences from the bridge/DAL smoke:
#   - the rollup is originated `of type bytes` (not the ticket pair) so the
#     orchestrator's `Tezos.get_contract_opt (bytes contract)` resolves. The
#     production ticket-bearing parameter type is NOT compatible with Mode A
#     today (see TZEL_ORCHESTRATOR_README.md §6 / report).
#   - no DAL node, no verifier/bridge configuration, no deposits.
set -Eeuo pipefail
shopt -s inherit_errexit

ORCH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Reuse the DAL smoke harness as a function library (its `main` is guarded by
# the BASH_SOURCE check at the bottom of the file). This brings in WORKDIR,
# ports, dirs, cleanup/on_err, prepare_workdir, prepare_client_material,
# init_node, start_node, activate_alpha, build_kernel_and_tools, bake_block,
# wait_for, current_block_level, helpers...
source "${ORCH_ROOT}/scripts/octez_rollup_sandbox_dal_smoke.sh"

ORCHESTRATOR_MLIGO="${ORCH_ROOT}/tezos/tzel_orchestrator.mligo"
ORCHESTRATOR_TZ_CHECKED_IN="${ORCH_ROOT}/tezos/tzel_orchestrator.tz"
ORCHESTRATOR_TZ="${WORKDIR}/tzel_orchestrator.tz"
EXPECTED_DECODE_ERROR="invalid inbox message"
EXPECTED_DISPATCH_ERROR="proof verifier is not configured"

# Like require_commands but without octez-dal-node (this smoke does not use
# DAL). ligo is optional: when absent we fall back to the checked-in .tz.
require_commands_orchestrator() {
  for cmd in octez-node octez-client octez-smart-rollup-node smart-rollup-installer cargo curl python3 xxd rustup; do
    command -v "${cmd}" >/dev/null 2>&1 || {
      echo "missing required command: ${cmd}" >&2
      exit 1
    }
  done
}

operator_address() {
  octez-client -d "${CLIENT_DIR}" show address operator -S | awk '/Hash:/ {print $2}'
}

compile_orchestrator() {
  if command -v ligo >/dev/null 2>&1; then
    ligo compile contract "${ORCHESTRATOR_MLIGO}" > "${ORCHESTRATOR_TZ}"
    echo "compiled orchestrator with local ligo" >&2
  else
    cp "${ORCHESTRATOR_TZ_CHECKED_IN}" "${ORCHESTRATOR_TZ}"
    echo "no ligo binary found; using checked-in tezos/tzel_orchestrator.tz" >&2
  fi
}

# Mode A needs the rollup parameter type to be plain `bytes` so a Michelson
# contract can TRANSFER_TOKENS to it (the bridge ticket pair type cannot be
# produced by the orchestrator). The kernel parses the resulting internal
# Transfer<MichelsonBytes> through decode_rollup_message pass 2.
originate_rollup_bytes() {
  local kernel_wasm boot_sector out
  kernel_wasm="${ORCH_ROOT}/target/wasm32-unknown-unknown/release/tzel_rollup_kernel.wasm"
  smart-rollup-installer get-reveal-installer \
    -P "${ROLLUP_PREIMAGES_DIR}" \
    -u "${kernel_wasm}" \
    -o "${INSTALLER_HEX}" >/dev/null
  boot_sector="$(tr -d '\n' < "${INSTALLER_HEX}")"
  out="$(octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    originate smart rollup tzel from operator of kind wasm_2_0_0 of type 'bytes' with kernel "${boot_sector}" --burn-cap 999)"
  printf '%s\n' "${out}" > "${LOG_DIR}/originate-smart-rollup.out"
  bake_block
  printf '%s\n' "${out}" | grep -Eo 'sr1[1-9A-HJ-NP-Za-km-z]+' | head -n1
}

start_rollup_node_no_dal() {
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

originate_orchestrator() {
  local rollup_addr="$1"
  local admin_addr init_storage out
  admin_addr="$(operator_address)"
  # Michelson layout of the CameLIGO record (verified with
  # `ligo compile storage`):
  #   (Pair admin rollup (Left rollup | Right Unit) paused nonce)
  # Left <addr> = Forward_to_rollup <addr> (Mode A).
  init_storage="(Pair \"${admin_addr}\" \"${rollup_addr}\" (Left \"${rollup_addr}\") False 0)"
  out="$(octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    originate contract tzel_orchestrator transferring 0 from operator \
    running "${ORCHESTRATOR_TZ}" --init "${init_storage}" --burn-cap 999)"
  printf '%s\n' "${out}" > "${LOG_DIR}/originate-orchestrator.out"
  bake_block
  printf '%s\n' "${out}" | grep -Eo 'KT1[1-9A-HJ-NP-Za-km-z]+' | head -n1
}

# raw-stub-* print the full kernel inbox envelope:
#   version_le (2B) ++ tag (1B) ++ wire body.
# The orchestrator prepends version+tag itself, so strip the first 3 bytes.
stub_body_hex() {
  local kind="$1"
  local envelope_hex
  envelope_hex="$("${ORCH_ROOT}/target/debug/octez_kernel_message" "raw-stub-${kind}")"
  printf '%s\n' "${envelope_hex:6}"
}

call_orchestrator() {
  local entrypoint="$1"
  local body_hex="$2"
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    transfer 0 from operator to tzel_orchestrator \
    --entrypoint "${entrypoint}" \
    --arg "0x${body_hex}" \
    --burn-cap 5 > "${LOG_DIR}/call-${entrypoint}.out"
  bake_block
}

fetch_last_result_bytes_hex() {
  curl -fsS "${ROLLUP_ENDPOINT}/global/block/head/durable/wasm_2_0_0/value?key=/tzel/v1/state/last_result.bin" \
    | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
# The rollup node answers HTTP 200 with JSON null when the key is absent.
if raw in ("", "null"):
    sys.exit(3)
payload = json.loads(raw) if raw.startswith("\"") else raw
payload = payload.strip()
if payload.startswith(("0x", "0X")):
    payload = payload[2:]
print(payload)
'
}

assert_no_last_result_yet() {
  if fetch_last_result_bytes_hex >/dev/null 2>&1; then
    echo "unexpected: /tzel/v1/state/last_result.bin already set before the shield call" >&2
    return 1
  fi
}

# Wait until the kernel has dispatched our message: last_result.bin must be a
# WireKernelResultEnvelope { version: 17u16 LE, result: Error(message) } whose
# message contains the expected deterministic rejection. Bake while waiting so
# the rollup node keeps advancing. A stale value from a previous step (not
# containing the expected substring) keeps the loop polling.
await_kernel_error_result() {
  local expected="$1"
  local i result_hex last_seen=""
  for ((i = 0; i < 90; i++)); do
    result_hex="$(fetch_last_result_bytes_hex 2>/dev/null || true)"
    if [[ -n "${result_hex}" ]]; then
      last_seen="${result_hex}"
      if python3 - "${result_hex}" "${expected}" <<'PY'
import sys
data = bytes.fromhex(sys.argv[1])
expected = sys.argv[2].encode()
if expected not in data:
    sys.exit(1)
# WireKernelResultEnvelope: version 17u16 LE ++ result tag (255 = Error)
# ++ u32 BE message length ++ message.
assert data[:2] == (17).to_bytes(2, "little"), f"bad result envelope version: {data[:4].hex()}"
assert data[2] == 255, f"expected Error result tag 255, got {data[2]} ({data.hex()})"
print("kernel dispatch result:", data[7:].decode("utf-8", "replace"))
PY
      then
        return 0
      fi
    fi
    bake_block
    sleep 1
  done
  echo "timed out waiting for kernel error result containing: ${expected}" >&2
  if [[ -n "${last_seen}" ]]; then
    echo "last_result.bin currently holds: ${last_seen}" >&2
  fi
  return 1
}

assert_orchestrator_nonce() {
  local expected="$1"
  local storage
  storage="$(octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" \
    get contract storage for tzel_orchestrator | tr -s '[:space:]' ' ')"
  if [[ "${storage}" != *"False ${expected}"* ]]; then
    echo "unexpected orchestrator storage (wanted nonce ${expected}): ${storage}" >&2
    return 1
  fi
}

orchestrator_main() {
  require_commands_orchestrator
  prepare_workdir
  trap on_err ERR
  trap cleanup EXIT
  prepare_client_material
  init_node
  start_node
  activate_alpha
  build_kernel_and_tools
  compile_orchestrator

  local rollup_address orchestrator_address
  rollup_address="$(originate_rollup_bytes)"
  echo "rollup (type bytes): ${rollup_address}"
  start_rollup_node_no_dal "${rollup_address}"

  orchestrator_address="$(originate_orchestrator "${rollup_address}")"
  echo "orchestrator: ${orchestrator_address}"
  assert_orchestrator_nonce 0
  assert_no_last_result_yet

  # Step 1 — %shield with a truncated stub body (a full Shield can never fit
  # in the 4096-byte inbox cap). Proves the orchestrator's internal transfer
  # is routed into decode_kernel_inbox_message.
  local shield_body_hex
  shield_body_hex="$(stub_body_hex shield)"
  shield_body_hex="${shield_body_hex:0:128}"
  echo "truncated stub shield body: ${#shield_body_hex} hex chars"
  call_orchestrator shield "${shield_body_hex}"
  await_kernel_error_result "${EXPECTED_DECODE_ERROR}"
  assert_orchestrator_nonce 1

  # Step 2 — %unshield with a complete wire-valid stub body. Proves the
  # full dispatch chain into apply_kernel_message (rejected at the proof
  # verifier configuration check).
  local unshield_body_hex
  unshield_body_hex="$(stub_body_hex unshield)"
  echo "stub unshield body: ${#unshield_body_hex} hex chars"
  call_orchestrator unshield "${unshield_body_hex}"
  await_kernel_error_result "${EXPECTED_DISPATCH_ERROR}"
  assert_orchestrator_nonce 2

  echo "octez orchestrator sandbox smoke passed"
  echo "rollup=${rollup_address}"
  echo "orchestrator=${orchestrator_address}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  orchestrator_main "$@"
fi
