#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script with sudo." >&2
  exit 1
fi

APT_KEYRING_DIR="/etc/apt/keyrings"
OCTEZ_KEYRING="${APT_KEYRING_DIR}/octez.gpg"
OCTEZ_LIST="/etc/apt/sources.list.d/octez.list"

echo "Installing Octez packages from the official Ubuntu noble repository."
echo "Host distro: $(. /etc/os-release && printf '%s %s' "${NAME}" "${VERSION_ID}")"
echo "Note: this is a pragmatic compatibility path for Ubuntu 25.10, not the officially matched distro."

apt-get update
apt-get install -y gpg curl

install -d -m 0755 "${APT_KEYRING_DIR}"
curl -fsSL https://packages.nomadic-labs.com/ubuntu/octez.asc \
  | gpg --batch --yes --dearmor -o "${OCTEZ_KEYRING}"

cat > "${OCTEZ_LIST}" <<'EOF'
deb [signed-by=/etc/apt/keyrings/octez.gpg] https://packages.nomadic-labs.com/ubuntu noble main
EOF

apt-get update
apt-get install -y \
  octez-client \
  octez-node \
  octez-baker \
  octez-smart-rollup-node

echo
echo "Installed Octez binaries:"
octez-client --version
octez-node --version
octez-smart-rollup-node --version
if command -v octez-smart-rollup-wasm-debugger >/dev/null 2>&1; then
  octez-smart-rollup-wasm-debugger --version
else
  echo "octez-smart-rollup-wasm-debugger not found on PATH after install"
  echo "If you need the debugger too, we may need to fetch the static Octez binary set."
fi
