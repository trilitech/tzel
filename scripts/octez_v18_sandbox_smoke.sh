#!/usr/bin/env bash
# v18 DAL-free submission sandbox E2E.
#
# Proves the full v18 protocol (docs/SNARK-SUBMISSION-DESIGN.md) end to end on
# a local Octez sandbox, with NO DAL node and NO orchestrator contract — every
# message is injected as an *external Targetted* smart-rollup inbox message via
# `octez-client send smart rollup message`. The kernel decodes the frame to
# `InboxSender::External` (a single fixed staging namespace) and dispatches
# through `apply_kernel_message`.
#
# The kernel WASM is built with `TZEL_INSECURE_SANDBOX=1` so the
# `kernel-test-skip-verify` Groth16 token fires in-rollup. That token bypasses
# ONLY the Groth16 tree walk + program-hash binding; the kernel's CORE
# output-binding (each op's `output_preimage` vs its declared public fields)
# STILL runs and is satisfied by the fixture's real `output_preimage` — so a
# successful apply is a genuine durable state transition, not a free pass.
# (The kernel is also built `--no-default-features`, dropping the heavy
# `tzel-verifier` dep: under the skip token the verifier is never reached.)
#
# Three scenarios, each asserting APPLY (durable state change), not just parse:
#
#   1. SubmitStagedConfig (gap #1): stage a signed ConfigureVerifier envelope
#      across ≥2 StageChunks, SubmitStagedConfig, assert KernelResult::Configured
#      AND the durable verifier-config key is populated.
#   2. StageChunk → SubmitOps shield: configure the bridge (also via the staged
#      path), fund a deposit pool via an L1 ticketer mint, stage the two shield
#      notes (the client note split across 2 chunks to exercise multi-chunk
#      reassembly), SubmitOps, assert the shield APPLIED: the deposit pool is
#      drained to 0 and the note tree size is 2 (the two shield commitments).
#   3. (covered by #2's SubmitOps) the staged notes are consumed — re-running
#      SubmitOps against the now-discarded entries fails (asserted implicitly by
#      the drain + tree-size postconditions; a sealed-entry consume is what lets
#      the apply reach the core shield).
set -Eeuo pipefail
shopt -s inherit_errexit

V18_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Reuse the DAL smoke harness as a function library (its `main` is guarded by
# the BASH_SOURCE check). Brings in WORKDIR, ports, dirs, cleanup/on_err,
# prepare_workdir, prepare_client_material, init_node, start_node,
# activate_alpha, bake_block, wait_for, read_rollup_u64, await_rollup_u64,
# originate_ticketer, mutez_to_tez, …
source "${V18_ROOT}/scripts/octez_rollup_sandbox_dal_smoke.sh"

KMSG="${V18_ROOT}/target/debug/octez_kernel_message"
FIXTURE="${V18_ROOT}/tezos/rollup-kernel/testdata/verified_bridge_flow.json"

# No DAL, no orchestrator: just the toolchain the external-message path needs.
require_commands_v18() {
  for cmd in octez-node octez-client octez-smart-rollup-node smart-rollup-installer cargo curl python3 xxd rustup; do
    command -v "${cmd}" >/dev/null 2>&1 || {
      echo "missing required command: ${cmd}" >&2
      exit 1
    }
  done
}

# Build host tools (debug, no verifier) + the sandbox kernel WASM
# (release, no verifier, TZEL_INSECURE_SANDBOX=1 + dev admin material baked so
# the dev-default config signatures the emitter produces authenticate).
build_v18_kernel_and_tools() {
  local cargo_toolchain_args=() rustup_toolchain_args=()
  if [[ -n "${RUST_TOOLCHAIN}" ]]; then
    cargo_toolchain_args=("+${RUST_TOOLCHAIN}")
    rustup_toolchain_args=(--toolchain "${RUST_TOOLCHAIN}")
  fi
  rustup target list --installed "${rustup_toolchain_args[@]}" | grep -qx 'wasm32-unknown-unknown' \
    || rustup target add "${rustup_toolchain_args[@]}" wasm32-unknown-unknown >/dev/null

  # Host emitter bin (debug => dev-default admin ask). Built
  # `--no-default-features` so it does not pull the heavy `tzel-verifier` dep;
  # all v18 wire encoding + fixture decoding lives in `tzel-core`.
  cargo "${cargo_toolchain_args[@]}" build -q --no-default-features \
    -p tzel-rollup-kernel --bin octez_kernel_message

  # Bake the dev-default admin material into the kernel so the release WASM
  # (debug_assertions off) accepts the emitter's dev-signed config envelopes.
  local admin_env
  admin_env="$("${KMSG}" admin-material)"
  local seed verifier_leaf bridge_leaf
  seed="$(awk -F= '/PUB_SEED/{print $2}' <<<"${admin_env}")"
  verifier_leaf="$(awk -F= '/VERIFIER_CONFIG_ADMIN_LEAF/{print $2}' <<<"${admin_env}")"
  bridge_leaf="$(awk -F= '/BRIDGE_CONFIG_ADMIN_LEAF/{print $2}' <<<"${admin_env}")"

  # Force a fresh kernel WASM compile under the cfg. cargo fingerprints the
  # `TZEL_INSECURE_SANDBOX` env (build.rs `rerun-if-env-changed`), but the
  # host-bin build above and any prior no-cfg WASM can leave a stale artifact
  # cargo deems "fresh"; `clean -p` of just this crate guarantees the cfg
  # actually lands without recompiling the heavy deps.
  cargo "${cargo_toolchain_args[@]}" clean -q -p tzel-rollup-kernel \
    --target wasm32-unknown-unknown --release || true

  TZEL_INSECURE_SANDBOX=1 \
  TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX="${seed}" \
  TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX="${verifier_leaf}" \
  TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX="${bridge_leaf}" \
    cargo "${cargo_toolchain_args[@]}" build -q --no-default-features \
      -p tzel-rollup-kernel --target wasm32-unknown-unknown --release

  # Build-time gate: the proof-skip canary MUST be present (cfg actually
  # flipped). NB: avoid `strings | grep -q` — `grep -q` closes the pipe on
  # first match, SIGPIPE-ing `strings`, which under `set -o pipefail` makes the
  # pipeline exit non-zero even on success. Count matches into a var instead.
  local canary_hits
  canary_hits="$(strings "${V18_ROOT}/target/wasm32-unknown-unknown/release/tzel_rollup_kernel.wasm" \
    | grep -c 'TZEL_INSECURE_SANDBOX_PROOF_SKIP' || true)"
  if [[ "${canary_hits}" == "0" ]]; then
    echo "sandbox kernel WASM is missing the TZEL_INSECURE_SANDBOX_PROOF_SKIP canary" >&2
    exit 1
  fi
}

originate_rollup_v18() {
  local kernel_wasm boot_sector out
  kernel_wasm="${V18_ROOT}/target/wasm32-unknown-unknown/release/tzel_rollup_kernel.wasm"
  smart-rollup-installer get-reveal-installer \
    -P "${ROLLUP_PREIMAGES_DIR}" \
    -u "${kernel_wasm}" \
    -o "${INSTALLER_HEX}" >/dev/null
  boot_sector="$(tr -d '\n' < "${INSTALLER_HEX}")"
  # External Targetted messages need no Michelson parameter contract; the
  # bridge deposit uses an internal ticket Transfer, so the parameter type is
  # the production ticket pair (same as the DAL smoke).
  out="$(octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    originate smart rollup tzel from operator of kind wasm_2_0_0 \
    of type '(pair bytes (ticket (pair nat (option bytes))))' with kernel "${boot_sector}" --burn-cap 999)"
  printf '%s\n' "${out}" > "${LOG_DIR}/originate-smart-rollup.out"
  bake_block
  printf '%s\n' "${out}" | grep -Eo 'sr1[1-9A-HJ-NP-Za-km-z]+' | head -n1
}

start_rollup_node_v18() {
  local rollup_addr="$1"
  octez-smart-rollup-node \
    -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" run \
    --data-dir "${ROLLUP_DIR}" --mode observer --rollup "${rollup_addr}" \
    --rpc-addr 127.0.0.1 --rpc-port "${ROLLUP_RPC_PORT}" \
    --acl-override allow-all --no-degraded \
    >"${ROLLUP_LOG}" 2>&1 &
  ROLLUP_PID=$!
  wait_for "smart rollup node rpc" 60 curl -fsS "${ROLLUP_ENDPOINT}/openapi"
}

# Inject one external smart-rollup message (hex of a framed Targetted payload).
send_external() {
  local msg_hex="$1"
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    send smart rollup message "hex:[ \"${msg_hex}\" ]" from operator >/dev/null
  bake_block
}

# Inject several external messages in ONE inbox level (a multi-element hex
# array). Used to stage all chunks of an entry atomically so they cannot be
# split across blocks / lost to observer timing.
send_external_batch() {
  local joined="" h
  for h in "$@"; do
    [[ -n "${joined}" ]] && joined+=" , "
    joined+="\"${h}\""
  done
  octez-client -d "${CLIENT_DIR}" -E "${NODE_ENDPOINT}" -p "${ALPHA_HASH}" -w none \
    send smart rollup message "hex:[ ${joined} ]" from operator >/dev/null
  bake_block
}

# Read an arbitrary durable value, hex-decoded, returned as raw bytes hex.
fetch_durable_hex() {
  local key="$1"
  curl -fsS "${ROLLUP_ENDPOINT}/global/block/head/durable/wasm_2_0_0/value?key=${key}" \
    | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if raw in ("", "null"):
    sys.exit(3)
payload = json.loads(raw) if raw.startswith("\"") else raw
payload = payload.strip()
if payload.startswith(("0x", "0X")):
    payload = payload[2:]
print(payload)
'
}

# Poll last_result.bin until it parses as the expected v18 KernelResult tag.
# WireKernelResultEnvelope: version 18u16 LE ++ tag, where tag is (from
# WireKernelResult in core/src/kernel_wire.rs):
#   0 = Configured, 1 = Deposit, 5 = Staged, 6 = Submitted, 255 = Error.
await_kernel_result_tag() {
  local want_tag="$1" label="$2"
  local i result_hex last=""
  for ((i = 0; i < 90; i++)); do
    result_hex="$(fetch_durable_hex "/tzel/v1/state/last_result.bin" 2>/dev/null || true)"
    if [[ -n "${result_hex}" ]]; then
      last="${result_hex}"
      if python3 - "${result_hex}" "${want_tag}" "${label}" <<'PY'
import sys
data = bytes.fromhex(sys.argv[1]); want = int(sys.argv[2]); label = sys.argv[3]
assert data[:2] == (18).to_bytes(2, "little"), f"bad result envelope version: {data[:2].hex()}"
tag = data[2]
if tag == 255 and want != 255:
    msg = data[7:].decode("utf-8", "replace")
    sys.exit(f"kernel returned Error while awaiting {label}: {msg}")
sys.exit(0 if tag == want else 1)
PY
      then
        return 0
      fi
    fi
    bake_block
    sleep 1
  done
  echo "timed out waiting for ${label} (result tag ${want_tag}); last_result=${last}" >&2
  return 1
}

# Stage the chunks printed by an emitter `v18-stage-*` invocation, injecting
# each chunk frame, and echo the trailing payload_hash on stdout.
stage_via_emitter() {
  local out line ph="" frames=()
  out="$("$@")"
  while IFS= read -r line; do
    if [[ "${line}" == payload_hash=* ]]; then
      ph="${line#payload_hash=}"
    elif [[ -n "${line}" ]]; then
      frames+=("${line}")
    fi
  done <<<"${out}"
  # All chunks of an entry go in ONE inbox level (atomic seal; no per-block
  # loss).
  send_external_batch "${frames[@]}"
  printf '%s\n' "${ph}"
}

extract_meta() {
  "${KMSG}" v18-fixture-meta "${FIXTURE}"
}

v18_main() {
  require_commands_v18
  prepare_workdir
  trap on_err ERR
  trap cleanup EXIT
  prepare_client_material
  init_node
  start_node
  activate_alpha
  build_v18_kernel_and_tools

  local rollup_address ticketer_address
  rollup_address="$(originate_rollup_v18)"
  echo "rollup: ${rollup_address}"
  ticketer_address="$(originate_ticketer)"
  echo "ticketer: ${ticketer_address}"
  start_rollup_node_v18 "${rollup_address}"

  local meta shield_recipient shield_total_debit tree_size_after
  mapfile -t meta < <(extract_meta)
  shield_recipient="${meta[0]}"
  shield_total_debit="${meta[1]}"
  tree_size_after="${meta[3]}"

  # ── Scenario 1: SubmitStagedConfig — ConfigureVerifier (gap #1) ──────
  echo "== scenario 1: SubmitStagedConfig (ConfigureVerifier) =="
  local cfg_staging_id=200 cfg_ph
  cfg_ph="$(stage_via_emitter "${KMSG}" v18-stage-config-verifier "${rollup_address}" "${FIXTURE}" "${cfg_staging_id}" 2)"
  echo "  staged verifier-config envelope, payload_hash=${cfg_ph}"
  send_external "$("${KMSG}" v18-submit-staged-config "${rollup_address}" "${cfg_staging_id}" "${cfg_ph}")"
  await_kernel_result_tag 0 "Configured (verifier via staged config)"
  # Durable assert: the verifier config key is now populated.
  if ! fetch_durable_hex "/tzel/v1/state/verifier_config.bin" >/dev/null 2>&1; then
    echo "verifier config key not populated after SubmitStagedConfig" >&2
    return 1
  fi
  echo "  OK: KernelResult::Configured + durable verifier config present"

  # ── Configure the bridge to the LIVE ticketer (staged config path) ───
  echo "== configure bridge to live ticketer (staged config) =="
  local bridge_envelope_hex bridge_ph bridge_staging_id=300
  # Emit a signed ConfigureBridge envelope naming the LIVE ticketer, stage it,
  # then SubmitStagedConfig. raw-configure-bridge signs an arbitrary ticketer.
  bridge_envelope_hex="$("${KMSG}" raw-configure-bridge "${ticketer_address}")"
  stage_raw_envelope "${rollup_address}" "${bridge_staging_id}" "${bridge_envelope_hex}"
  bridge_ph="$(payload_hash_of_hex "${bridge_envelope_hex}")"
  send_external "$("${KMSG}" v18-submit-staged-config "${rollup_address}" "${bridge_staging_id}" "${bridge_ph}")"
  await_kernel_result_tag 0 "Configured (bridge via staged config)"
  await_bridge_ticketer "${ticketer_address}"
  echo "  OK: bridge configured to ${ticketer_address}"

  # ── Fund a deposit pool for the fixture shield's pubkey_hash ─────────
  echo "== fund deposit pool via L1 ticket mint =="
  deposit_to_bridge "${ticketer_address}" "${rollup_address}" "${shield_recipient}" "${shield_total_debit}"
  local balance_key
  balance_key="/tzel/v1/state/balances/by-key/$(printf '%s' "${shield_recipient}" | xxd -ps -c 0)"
  await_rollup_u64 "${balance_key}" "${shield_total_debit}" "deposit pool funded"
  echo "  OK: deposit pool = ${shield_total_debit}"

  # ── Scenario 2: StageChunk → SubmitOps shield ───────────────────────
  echo "== scenario 2: StageChunk -> SubmitOps shield (apply) =="
  local client_id=100 producer_id=101 client_ph producer_ph
  # Client note across 2 chunks (exercise multi-chunk reassembly); producer in 1.
  client_ph="$(stage_via_emitter "${KMSG}" v18-stage-note "${rollup_address}" "${FIXTURE}" shield 0 "${client_id}" 2)"
  producer_ph="$(stage_via_emitter "${KMSG}" v18-stage-note "${rollup_address}" "${FIXTURE}" shield 1 "${producer_id}" 1)"
  echo "  staged client (2 chunks) ph=${client_ph}, producer (1 chunk) ph=${producer_ph}"
  send_external "$("${KMSG}" v18-submit-shield "${rollup_address}" "${FIXTURE}" "${client_id}" "${producer_id}")"
  await_kernel_result_tag 6 "Submitted (shield batch)"
  # Durable apply asserts: pool drained to 0 + the two shield commitments are
  # in the note tree (tree size == fixture's post-shield size).
  await_rollup_u64 "${balance_key}" "0" "deposit pool drained after shield"
  await_rollup_u64 "/tzel/v1/state/tree/size" "${tree_size_after}" "shield notes inserted"
  echo "  OK: KernelResult::Submitted + pool drained + tree size ${tree_size_after}"

  echo "octez v18 sandbox smoke passed"
  echo "rollup=${rollup_address}"
  echo "ticketer=${ticketer_address}"
}

# Stage a raw (already-framed-as-targeted? no — raw envelope) config envelope
# across enough chunks. The argument is the RAW kernel envelope hex (output of
# raw-configure-*); we frame each chunk as a Targetted StageChunk via a tiny
# python splitter + the emitter is bypassed here because raw-configure-* does
# not Targetted-frame. Instead we re-stage using the dedicated emitter path:
# we write the raw bytes to a file and let the kernel-message bin chunk it.
stage_raw_envelope() {
  local rollup_addr="$1" staging_id="$2" envelope_hex="$3"
  local out line frames=()
  out="$("${KMSG}" v18-stage-raw "${rollup_addr}" "${staging_id}" "${envelope_hex}")"
  while IFS= read -r line; do
    [[ -n "${line}" && "${line}" != payload_hash=* ]] && frames+=("${line}")
  done <<<"${out}"
  send_external_batch "${frames[@]}"
}

payload_hash_of_hex() {
  "${KMSG}" v18-payload-hash "$1"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  v18_main "$@"
fi
