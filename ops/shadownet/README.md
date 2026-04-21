# Shadownet Operator Box

This directory contains the minimum deployment assets for a public Shadownet
operator machine that runs:

- `octez-node`
- `octez-dal-node`
- `octez-smart-rollup-node`
- `tzel-operator`
- optionally `tzel-detect` for delegated watch-only scanning

## Why A Public Box Matters

For real shielded traffic, the DAL node that publishes slots must be reachable
by the rest of the DAL network. In practice that means:

- set a real `TZEL_DAL_PUBLIC_ADDR`
- open the DAL P2P port in the firewall
- run this on a public machine, not a local VM behind a private NAT

## Files

- `shadownet.env.example`
  - single environment file shared by all services
- `systemd/*.service`
  - systemd unit templates for the long-running rollup processes and optional detection service
- `../prover/`
  - standard prover deployment paths plus preflight for `reprove` and the Cairo executables
- `../../scripts/install_tzel_binaries.sh`
  - installs `tzel-operator`, `tzel-wallet`, `tzel-detect`, `sp-client`, `octez_kernel_message`,
    `verified_bridge_fixture_message`, `submit_rollup_config`, `reprove`, and the Cairo executable JSON files
  - installs `rollup-config-admin-{runtime,build}.env` and wraps `octez_kernel_message` so
    config messages stay usable after install
- `../../scripts/shadownet_operator_preflight.sh`
  - checks binaries, env vars, and local service RPCs, including `tzel-detect` when enabled
- `../../scripts/shadownet_live_e2e_smoke.sh`
  - uses two disposable wallets to run `deposit -> shield -> send -> unshield -> withdraw`
    against the configured public box

## Setup

1. Install Octez binaries.
   - `./scripts/install_octez_ubuntu.sh`
2. Build TzEL release artifacts as your normal user.
   - `./scripts/install_tzel_binaries.sh --build-only`
3. Install TzEL release artifacts.
   - `sudo ./scripts/install_tzel_binaries.sh --skip-build --prefix /usr/local --executables-dir /opt/tzel/cairo/target/dev`
4. Copy the env template.
   - `sudo mkdir -p /etc/tzel`
   - `sudo cp ops/shadownet/shadownet.env.example /etc/tzel/shadownet.env`
   - edit `/etc/tzel/shadownet.env`
5. Initialize local state and node identity.
   - `sudo ./scripts/init_shadownet_operator_box.sh /etc/tzel/shadownet.env`
   - this also creates `TZEL_OPERATOR_BEARER_TOKEN_FILE` if it does not exist
6. Export view material for the operator fee address and copy it onto the box.
   - example:
     - `/usr/local/bin/tzel-wallet --wallet operator-fee.wallet export-view --out operator-dal-fee.view.json`
   - place the exported file at `TZEL_OPERATOR_DAL_FEE_VIEW_MATERIAL`
   - `TZEL_OPERATOR_DAL_FEE_ADDRESS_INDEX` must match the address index used for `dal_fee_address`
7. Import the operator key once.
   - `sudo -u tzel octez-client -d /var/lib/tzel/octez-client import secret key tzelshadownet <SECRET_KEY>`
8. Copy the service units.
   - `sudo cp ops/shadownet/systemd/*.service /etc/systemd/system/`
9. Reload and start services.
   - `sudo systemctl daemon-reload`
   - `sudo systemctl enable --now octez-node octez-dal-node octez-rollup-node tzel-operator`
   - optionally enable `tzel-detect` after creating a watch wallet and setting `TZEL_DETECT_ENABLE=1`
   - `sudo systemctl enable --now tzel-detect`
10. Run preflight.
   - `./scripts/shadownet_operator_preflight.sh /etc/tzel/shadownet.env`
11. Run a wallet-facing smoke once the rollup is configured.
   - `TZEL_SMOKE_L1_RECIPIENT=tz1REPLACE_ME ./scripts/shadownet_live_e2e_smoke.sh /etc/tzel/shadownet.env`

## Expected Local RPCs

- L1 node RPC: `http://127.0.0.1:8732`
- DAL node RPC: `http://127.0.0.1:10732`
- rollup node RPC: `http://127.0.0.1:28944`
- operator HTTP: `http://127.0.0.1:8787`
- detection HTTP: `http://127.0.0.1:8789` when enabled

## Firewall

At minimum, allow inbound TCP for:

- the DAL node P2P port from `TZEL_DAL_NET_ADDR`
- the Octez node P2P port from `TZEL_OCTEZ_NODE_NET_ADDR`

Keep the RPC endpoints bound to loopback unless you explicitly want remote
access.

## Optional Detection Service

For delegated watch-only scanning, export watch material from a spending wallet:

```bash
/usr/local/bin/tzel-wallet --wallet alice.json export-view --out alice.view.json
/usr/local/bin/tzel-wallet --wallet /var/lib/tzel/watch/alice.watch.json watch init --material alice.view.json
/usr/local/bin/tzel-wallet --wallet /var/lib/tzel/watch/alice.watch.json profile init-shadownet \
  --rollup-node-url http://127.0.0.1:28944 \
  --rollup-address "$TZEL_ROLLUP_ADDRESS" \
  --bridge-ticketer "$TZEL_BRIDGE_TICKETER" \
  --dal-fee 1 \
  --dal-fee-address /var/lib/tzel/watch/producer-address.json \
  --source-alias "$TZEL_SOURCE_ALIAS"
```

Then set these in `/etc/tzel/shadownet.env`:

- `TZEL_DETECT_ENABLE=1`
- `TZEL_DETECT_WALLET=/var/lib/tzel/watch/alice.watch.json`
- optionally `TZEL_DETECT_LISTEN` and `TZEL_DETECT_INTERVAL_SECS`

The service only exposes sanitized watch status. It does not serve the embedded
viewing or detection material over HTTP.

## Wallet Diagnosis

Before handing the box to testers, verify that a freshly created wallet can read
the rollup state:

```bash
/usr/local/bin/tzel-wallet --wallet /tmp/tzel-check.wallet init
/usr/local/bin/tzel-wallet --wallet /tmp/tzel-check.wallet profile init-shadownet \
  --rollup-node-url http://127.0.0.1:28944 \
  --rollup-address "$TZEL_ROLLUP_ADDRESS" \
  --bridge-ticketer "$TZEL_BRIDGE_TICKETER" \
  --dal-fee 1 \
  --dal-fee-address /var/lib/tzel/watch/producer-address.json \
  --source-alias "$TZEL_SOURCE_ALIAS"
/usr/local/bin/tzel-wallet --wallet /tmp/tzel-check.wallet check
```

If `check` reports missing durable note payloads while the tree size is non-zero,
that rollup deployment does not support private note sync and should be
reoriginated before user testing.
