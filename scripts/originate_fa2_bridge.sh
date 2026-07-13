#!/usr/bin/env bash
# Originate an FA2 bridge ticketer on a Tezos network and emit the
# resulting KT1 address + the COMPILE_TIME_FA2_BRIDGES line to add to
# the kernel.
#
# Workflow:
#   1. Typecheck tezos/fa2_bridge_ticketer.tz under the target
#      protocol's mockup (sanity check before sending fees).
#   2. Originate the contract with storage = (fa2_contract_address,
#      token_id) using octez-client.
#   3. Wait for confirmation, extract the KT1 from the origination
#      receipt.
#   4. Print the COMPILE_TIME_FA2_BRIDGES entry to paste into
#      core/src/lib.rs, plus the asset_id the kernel will derive
#      from this ticketer.
#
# Inputs (positional or env-var):
#   $1 / FA2_CONTRACT_ADDR : the FA2 contract address (KT1...)
#   $2 / FA2_TOKEN_ID      : the FA2 token_id (nat) this ticketer
#                            will serve
#   $3 / FUNDING_ALIAS     : octez-client alias funding origination
#   $4 / NETWORK_NAME      : "ghostnet", "mainnet", or any configured
#                            octez-client endpoint
#   $5 / PROTOCOL_HASH     : protocol hash of the target network
#
# Example:
#   scripts/originate_fa2_bridge.sh \
#     KT1NwhsbHzS6kpc7Co3fnTjAcQU7ATKy8gJq 0 alice ghostnet \
#     PtSeouLouXkxhg39oWzjxDWaCydNfR3RxCUrNe4Q9Ro8BTehcbh
#
# Prerequisites: octez-client on PATH (gitlab.com/tezos/tezos
# releases → static binaries → x86_64-octez-client). The funding
# alias must already have enough tez to pay origination fees.

set -euo pipefail

FA2_CONTRACT_ADDR="${1:-${FA2_CONTRACT_ADDR:-}}"
FA2_TOKEN_ID="${2:-${FA2_TOKEN_ID:-}}"
FUNDING_ALIAS="${3:-${FUNDING_ALIAS:-}}"
NETWORK_NAME="${4:-${NETWORK_NAME:-}}"
PROTOCOL_HASH="${5:-${PROTOCOL_HASH:-}}"

usage() {
  cat <<'EOF'
Usage: originate_fa2_bridge.sh <fa2_contract> <token_id> <funding_alias> <network> <protocol_hash>

  fa2_contract   KT1... of the FA2 token contract
  token_id       which token_id (nat) this ticketer serves
  funding_alias  octez-client alias funding origination (must be configured + funded)
  network        octez-client network name (configured via 'octez-client config init')
  protocol_hash  protocol hash of the target network

Examples of protocol hashes (use the one matching your target network):
  Seoul:      PtSeouLouXkxhg39oWzjxDWaCydNfR3RxCUrNe4Q9Ro8BTehcbh
  Riotum:     PsRiotumaAMotcRoDWW1bysEhQy2n1M5fy8JgRp8jjRfHGmfeA7

The script reads tezos/fa2_bridge_ticketer.tz relative to the
repository root (the parent of scripts/).
EOF
  exit 64
}

if [[ -z "$FA2_CONTRACT_ADDR" || -z "$FA2_TOKEN_ID" || -z "$FUNDING_ALIAS" || -z "$NETWORK_NAME" || -z "$PROTOCOL_HASH" ]]; then
  usage
fi

# Locate the contract source relative to this script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACT="$REPO_ROOT/tezos/fa2_bridge_ticketer.tz"

if [[ ! -f "$CONTRACT" ]]; then
  echo "error: $CONTRACT not found" >&2
  exit 1
fi

if ! command -v octez-client >/dev/null 2>&1; then
  echo "error: octez-client not on PATH." >&2
  echo "Install: download x86_64-octez-client from gitlab.com/tezos/tezos releases" >&2
  exit 1
fi

# ─── Step 1: typecheck under mockup before paying any fees ────────
MOCKUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tzel-fa2-bridge-mockup.XXXXXX")"
trap 'rm -rf "$MOCKUP_DIR"' EXIT

echo "==> Typechecking $CONTRACT under protocol $PROTOCOL_HASH (mockup)..."
octez-client --base-dir "$MOCKUP_DIR" --mode mockup \
  --protocol "$PROTOCOL_HASH" create mockup >/dev/null
TYPECHECK_OUT="$(octez-client --base-dir "$MOCKUP_DIR" --mode mockup \
  --protocol "$PROTOCOL_HASH" typecheck script "$CONTRACT" 2>&1)"
if ! echo "$TYPECHECK_OUT" | grep -q "Well typed"; then
  echo "error: contract did not typecheck:" >&2
  echo "$TYPECHECK_OUT" >&2
  exit 1
fi
echo "    OK"

# ─── Step 2: originate ──────────────────────────────────────────
INIT_STORAGE="(Pair \"$FA2_CONTRACT_ADDR\" $FA2_TOKEN_ID)"
ORIG_ALIAS="tzel-fa2-bridge-${FA2_CONTRACT_ADDR:3:8}-${FA2_TOKEN_ID}"

echo "==> Originating $ORIG_ALIAS on $NETWORK_NAME ..."
echo "    storage: $INIT_STORAGE"
ORIG_OUT="$(octez-client originate contract "$ORIG_ALIAS" \
  transferring 0 from "$FUNDING_ALIAS" \
  running "$CONTRACT" \
  --init "$INIT_STORAGE" \
  --burn-cap 5 2>&1)" || {
    echo "$ORIG_OUT" >&2
    echo "error: origination failed" >&2
    exit 1
  }

# Extract the KT1 address from the origination receipt.
KT1="$(echo "$ORIG_OUT" | grep -oE 'KT1[a-km-zA-HJ-NP-Z1-9]{33}' | head -1 || true)"
if [[ -z "$KT1" ]]; then
  echo "error: could not extract KT1 from octez-client output:" >&2
  echo "$ORIG_OUT" >&2
  exit 1
fi
echo "    deployed at $KT1"

# ─── Step 3: print the kernel registry entry ─────────────────────
# The asset_id the kernel will derive is hash("tzel:asset:"||KT1).
# Use the wallet's own helper rather than reimplementing the hash
# here — guarantees the printed value matches what derive_asset_id
# actually returns.
ASSET_ID_HEX="$(
  cd "$REPO_ROOT" &&
  cargo run --quiet --package tzel-services --bin derive_asset_id_cli -- "$KT1" 2>/dev/null
)" || ASSET_ID_HEX=""

echo
echo "============================================================"
echo "FA2 bridge originated."
echo "============================================================"
echo "  Ticketer address (KT1):   $KT1"
echo "  FA2 contract:             $FA2_CONTRACT_ADDR"
echo "  Token id:                 $FA2_TOKEN_ID"
if [[ -n "$ASSET_ID_HEX" ]]; then
  echo "  Derived asset_id (hex):   $ASSET_ID_HEX"
fi
echo
echo "Next step: register this ticketer in the kernel binary."
echo "Add the following line to core/src/lib.rs:"
echo
echo "    pub const COMPILE_TIME_FA2_BRIDGES: &[&str] = &["
echo "        \"$KT1\","
echo "        // ...other registered ticketers..."
echo "    ];"
echo
echo "Then rebuild and redeploy the rollup kernel. Until the new"
echo "kernel is installed, the running kernel will reject deposits"
echo "from this ticketer with 'unexpected ticketer'."
