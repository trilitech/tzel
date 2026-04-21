#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  submit_rollup_config.sh --operator-url <url> --rollup-address <sr1...> [--bearer-token <token>] [--octez-kernel-message <path>] \
    configure-verifier <auth_domain_hex> <shield_hash_hex> <transfer_hash_hex> <unshield_hash_hex>

  submit_rollup_config.sh --operator-url <url> --rollup-address <sr1...> [--bearer-token <token>] [--octez-kernel-message <path>] \
    configure-bridge <KT1...>
EOF
  exit 2
}

OPERATOR_URL=""
ROLLUP_ADDRESS=""
BEARER_TOKEN="${TZEL_OPERATOR_BEARER_TOKEN:-}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
DEFAULT_OCTEZ_KERNEL_MESSAGE="octez_kernel_message"
if [[ -x "${SCRIPT_DIR}/octez_kernel_message" ]]; then
  DEFAULT_OCTEZ_KERNEL_MESSAGE="${SCRIPT_DIR}/octez_kernel_message"
fi
OCTEZ_KERNEL_MESSAGE="${TZEL_OCTEZ_KERNEL_MESSAGE_BIN:-$DEFAULT_OCTEZ_KERNEL_MESSAGE}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-url)
      OPERATOR_URL="$2"
      shift 2
      ;;
    --rollup-address)
      ROLLUP_ADDRESS="$2"
      shift 2
      ;;
    --bearer-token)
      BEARER_TOKEN="$2"
      shift 2
      ;;
    --octez-kernel-message)
      OCTEZ_KERNEL_MESSAGE="$2"
      shift 2
      ;;
    configure-verifier|configure-bridge)
      break
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$OPERATOR_URL" && -n "$ROLLUP_ADDRESS" ]] || usage
[[ $# -gt 0 ]] || usage

command -v curl >/dev/null 2>&1 || { echo "missing required command: curl" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "missing required command: python3" >&2; exit 1; }
if [[ "$OCTEZ_KERNEL_MESSAGE" == */* ]]; then
  [[ -x "$OCTEZ_KERNEL_MESSAGE" ]] || {
    echo "missing required command: $OCTEZ_KERNEL_MESSAGE" >&2
    exit 1
  }
else
  command -v "$OCTEZ_KERNEL_MESSAGE" >/dev/null 2>&1 || {
    echo "missing required command: $OCTEZ_KERNEL_MESSAGE" >&2
    exit 1
  }
fi

cmd="$1"
shift

case "$cmd" in
  configure-verifier)
    [[ $# -eq 4 ]] || usage
    payload_hex="$("$OCTEZ_KERNEL_MESSAGE" raw-configure-verifier "$1" "$2" "$3" "$4")"
    kind="configure_verifier"
    ;;
  configure-bridge)
    [[ $# -eq 1 ]] || usage
    payload_hex="$("$OCTEZ_KERNEL_MESSAGE" raw-configure-bridge "$1")"
    kind="configure_bridge"
    ;;
  *)
    usage
    ;;
esac

tmp_json="$(mktemp)"
trap 'rm -f "$tmp_json"' EXIT
python3 - "$kind" "$ROLLUP_ADDRESS" "$payload_hex" >"$tmp_json" <<'PY'
import json, sys
kind, rollup_address, payload = sys.argv[1:]
json.dump(
    {
        "kind": kind,
        "rollup_address": rollup_address,
        "payload": payload,
    },
    sys.stdout,
)
PY

curl_args=(
  -fsS
  -X POST
  -H "Content-Type: application/json"
  --data-binary "@${tmp_json}"
)
if [[ -n "$BEARER_TOKEN" ]]; then
  curl_args+=(-H "Authorization: Bearer ${BEARER_TOKEN}")
fi
response="$(curl "${curl_args[@]}" "${OPERATOR_URL%/}/v1/rollup/submissions")"
python3 -c '
import json, sys

payload = json.load(sys.stdin)
submission = payload.get("submission")
if not isinstance(submission, dict):
    print("operator response missing submission", file=sys.stderr)
    sys.exit(1)

status = submission.get("status")
if status == "failed":
    detail = submission.get("detail") or "operator reported failed submission"
    print(detail, file=sys.stderr)
    sys.exit(1)
' <<<"${response}"
printf '%s\n' "${response}"
