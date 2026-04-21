#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "scripts/octez_rollup_sandbox_smoke.sh now requires DAL-backed configuration; forwarding to scripts/octez_rollup_sandbox_dal_smoke.sh" >&2
exec "${ROOT}/scripts/octez_rollup_sandbox_dal_smoke.sh" "$@"
