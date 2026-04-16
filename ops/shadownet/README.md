# Shadownet Operator Box

This directory contains the minimum deployment assets for a public Shadownet
operator machine that runs:

- `octez-node`
- `octez-dal-node`
- `octez-smart-rollup-node`
- `tzel-operator`

## Why A Public Box Matters

Live testing from this VM showed the following failure mode:

- DAL commitments were published successfully
- the slots later became `unattested`
- the rollup node then revealed `0` bytes for the DAL pages

For real shielded traffic, the DAL node that publishes slots must be reachable
by the rest of the DAL network. In practice that means:

- set a real `TZEL_DAL_PUBLIC_ADDR`
- open the DAL P2P port in the firewall
- run this on a public machine, not a local VM behind a private NAT

## Files

- `shadownet.env.example`
  - single environment file shared by all services
- `systemd/*.service`
  - systemd unit templates for the four long-running processes
- `../../scripts/shadownet_operator_preflight.sh`
  - checks binaries, env vars, and local service RPCs

## Setup

1. Install Octez binaries.
   - `./scripts/install_octez_ubuntu.sh`
2. Build the operator binary.
   - `cargo build --release -p tzel-services --bin tzel-operator`
3. Copy the env template.
   - `sudo mkdir -p /etc/tzel`
   - `sudo cp ops/shadownet/shadownet.env.example /etc/tzel/shadownet.env`
   - edit `/etc/tzel/shadownet.env`
4. Initialize local state and node identity.
   - `sudo ./scripts/init_shadownet_operator_box.sh /etc/tzel/shadownet.env`
5. Import the operator key once.
   - `sudo -u tzel octez-client -d /var/lib/tzel/octez-client import secret key tzelshadownet <SECRET_KEY>`
6. Copy the service units.
   - `sudo cp ops/shadownet/systemd/*.service /etc/systemd/system/`
7. Reload and start services.
   - `sudo systemctl daemon-reload`
   - `sudo systemctl enable --now octez-node octez-dal-node octez-rollup-node tzel-operator`
8. Run preflight.
   - `./scripts/shadownet_operator_preflight.sh /etc/tzel/shadownet.env`

## Expected Local RPCs

- L1 node RPC: `http://127.0.0.1:8732`
- DAL node RPC: `http://127.0.0.1:10732`
- rollup node RPC: `http://127.0.0.1:28944`
- operator HTTP: `http://127.0.0.1:8787`

## Firewall

At minimum, allow inbound TCP for:

- the DAL node P2P port from `TZEL_DAL_NET_ADDR`
- the Octez node P2P port from `TZEL_OCTEZ_NODE_NET_ADDR`

Keep the RPC endpoints bound to loopback unless you explicitly want remote
access.
