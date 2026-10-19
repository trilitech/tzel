# PQNet (`pqnet-10-16` / PQPark) Operator & Deployment Guide

This directory contains deployment assets and the runbook for deploying the
multi-asset `leanVM` version of TzEL on Nomadic Labs' PQPark quantum testnet
(`https://pqnet-10-16.pqpark.dal.nomadic-labs.com/`, or any subsequent PQPark
testnet).

## 1. Required Infrastructure

### Operator Host (`octez-node` + `octez-dal-node` + `octez-smart-rollup-node` + `tzel-operator`)

- **Compute & Memory**: Minimum **4 vCPU**, **16 GiB RAM** (recommended **8 vCPU / 32 GiB RAM** if running `reprove` proof generation on the same host).
- **Storage**: **60+ GiB SSD** (`octez-node` in rolling mode, `octez-dal-node` shard store for 960 KiB ZODA slots, `octez-smart-rollup-node` durable store + reveal preimages, and Rust build artifacts if compiling on-box).
- **OS & Packages**: Ubuntu 24.04 LTS (`x86_64`), `curl`, `jq`, `python3`, `docker.io` (or `skopeo` / `crane` to extract binaries from the PQPark image), Rust toolchain (`rustup` with `wasm32-unknown-unknown` target), and `smart-rollup-installer`.
- **Public Network & Firewall (Critical for DAL Attestation)**:
  - The host **must have a public IPv4 address** (not behind symmetric NAT) so in-cluster PQPark DAL attesters can pull ZODA shards from `octez-dal-node`.
  - Set `TZEL_DAL_PUBLIC_ADDR=<PUBLIC_IP>:11732` in `/etc/tzel/pqnet.env`.
  - Allow **inbound TCP**:
    - **`11732/tcp`** (`TZEL_DAL_NET_ADDR` — DAL P2P)
    - **`9732/tcp`** (`TZEL_OCTEZ_NODE_NET_ADDR` — L1 P2P)
  - Keep RPC ports (`8732`, `10732`, `28944`, `8787`, `8789`) bound to `127.0.0.1` (or behind an authenticated reverse proxy / SSH tunnel).

### Prover Sizing (`reprove` / `tzel-wallet`)

- With `leanVM`, client proof generation (`shield`, `send`, `unshield`) is CPU-bound and parallelized via Rayon:
  - **8–16 vCPU**, **16 GiB RAM** recommended on whichever machine runs `tzel-wallet` + `reprove`.
  - Each `leanVM` proof + transaction envelope is **~295 KiB**, which fits inside **a single 960 KiB DAL slot** on `pqnet-10-16` without multi-slot chunking.

---

## 2. `pqnet-10-16` Network & DAL Parameters

| Parameter | Value |
|---|---|
| Dashboard | `https://pqnet-10-16.pqpark.dal.nomadic-labs.com/` |
| Chain Name | `PQNET-pqnet-10-16` |
| Protocol Hash | `ProtoALphaALphaALphaALphaALphaALphaALphaALphaDdp3zK` |
| Octez Build | `zodal-poc-publish @ 30d8a549c6b4` |
| Docker Image | `europe-west1-docker.pkg.dev/nl-dal/pqpark/pq-octez:octez-20261016-30d8a549c6` |
| Network Config URL | `https://pqnet-10-16.pqpark.dal.nomadic-labs.com/network.json` |
| Public L1 RPC | `https://pqnet-10-16.pqpark.dal.nomadic-labs.com/rpc` |
| L1 Bootstrap Peer | `34.76.143.72:11735` (`minimal_block_delay = 6s`) |
| DAL Bootstrap Peers | `34.76.143.72:11736`, `34.76.143.72:11737` |
| Faucet API | `https://pqnet-10-16-faucet.pqpark.dal.nomadic-labs.com/api/send` |
| TzKT Explorer | `https://pqnet-10-16-tzkt.pqpark.dal.nomadic-labs.com/` |
| DAL `slot_size` | `983,040` bytes (`960 KiB`, `512` pages × `1,920` bytes) |
| DAL `number_of_slots` | `4` (indices `0..3`; `producer-0` uses slot `0`, TzEL uses `1..4`) |
| DAL `attestation_lag` | `10` (`attestation_lags = [3, 4, 6, 8, 10]`, `dynamic_lag_enable = true`) |

### Key Operational Notes for PQNet

1. **Use `pq-octez` Binaries (Not Stock Octez 24.x)**:
   `pqnet-10-16` runs `ProtoALpha...` with ZODA DAL (`zodal-poc-publish`) and post-quantum signature schemes (`tz5` ML-DSA-44, `tz6` XMSS). Extract `octez-node`, `octez-client`, `octez-dal-node`, and `octez-smart-rollup-node` directly from `europe-west1-docker.pkg.dev/nl-dal/pqpark/pq-octez:octez-20261016-30d8a549c6`.
2. **DAL Slot Range (`1..4`)**:
   `pqnet-10-16` has `number_of_slots = 4` (`0, 1, 2, 3`), and the in-cluster `producer-0` publishes on slot `0` every 4 levels. Configure `octez-dal-node` with `--operator-profiles=1,2,3` and `tzel-operator` with `--dal-slot-range=1..4` (pre-configured in [`pqnet.env.example`](./pqnet.env.example) and [`systemd/tzel-operator.service`](./systemd/tzel-operator.service)).
3. **Single-Slot `leanVM` Payloads**:
   Because `slot_size = 983,040` bytes (~960 KiB) and `MAX_DAL_CHUNK_PAYLOAD_BYTES` is capped at one slot, every `leanVM` shielded transaction (~295 KiB) and signed admin config message (`configure-verifier`, `configure-bridge`) fits in a **single DAL slot** (1 chunk).
4. **Use a `tz1` (`ed25519`) Alias for `TZEL_SOURCE_ALIAS` & L1 Withdrawal Recipients**:
   While `pqnet-10-16` supports `tz5` and `tz6` accounts on L1, the rollup kernel's outbox withdrawal encoding (`tezos-smart-rollup-encoding`) validates L1 withdrawal recipients as standard `tz1`/`tz2`/`tz3`/`KT1` addresses. Use a standard `ed25519` (`tz1...`) key for `TZEL_SOURCE_ALIAS` and L1 withdrawal `--recipient` addresses.

---

## 3. Step-by-Step Deployment

### Step 1: Extract `pq-octez` Binaries

```bash
IMAGE="europe-west1-docker.pkg.dev/nl-dal/pqpark/pq-octez:octez-20261016-30d8a549c6"
cid="$(docker create "$IMAGE")"
for bin in octez-node octez-client octez-dal-node octez-smart-rollup-node; do
  sudo docker cp "$cid:/usr/local/bin/$bin" "/usr/local/bin/$bin"
  sudo chmod 0755 "/usr/local/bin/$bin"
done
docker rm "$cid"
```

Ensure `smart-rollup-installer` is also installed on `PATH` (e.g. via `cargo install tezos-smart-rollup-installer --locked` or from Octez static releases).

### Step 2: Prepare `/etc/tzel/pqnet.env` and Initialize State Directories

Create the `tzel` service user if not already present, copy [`pqnet.env.example`](./pqnet.env.example), and set `TZEL_DAL_PUBLIC_ADDR` to the machine's public IP:

```bash
sudo useradd --system --home-dir /var/lib/tzel --shell /usr/sbin/nologin tzel || true
sudo mkdir -p /etc/tzel
sudo cp ops/pqnet/pqnet.env.example /etc/tzel/pqnet.env
# Edit /etc/tzel/pqnet.env and set TZEL_DAL_PUBLIC_ADDR=<PUBLIC_IP>:11732
```

### Step 3: Start `octez-node` and Fund the Operator Key

Initialize the node config and start `octez-node` so you can originate the L1 bridge contracts before building the kernel:

```bash
sudo -u tzel /usr/local/bin/octez-node config init \
  --data-dir /var/lib/tzel/octez-node \
  --network https://pqnet-10-16.pqpark.dal.nomadic-labs.com/network.json \
  --rpc-addr 127.0.0.1:8732 \
  --net-addr 0.0.0.0:9732
sudo -u tzel /usr/local/bin/octez-node identity generate \
  --data-dir /var/lib/tzel/octez-node 26

sudo cp ops/pqnet/systemd/octez-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now octez-node
```

Generate a `tz1` operator key and fund it via the PQNet faucet:

```bash
sudo -u tzel /usr/local/bin/octez-client -d /var/lib/tzel/octez-client \
  -E http://127.0.0.1:8732 gen keys tzelpqnet -s ed25519

OPERATOR_PKH="$(sudo -u tzel /usr/local/bin/octez-client -d /var/lib/tzel/octez-client \
  show address tzelpqnet | awk '/Hash:/ {print $2}')"
echo "Operator PKH: $OPERATOR_PKH"

curl -fsS -X POST https://pqnet-10-16-faucet.pqpark.dal.nomadic-labs.com/api/send \
  -H 'Content-Type: application/json' \
  -d "{\"to\":\"${OPERATOR_PKH}\",\"amount\":10000}"
```

### Step 4: Originate L1 Bridge Contracts (Tez + Optional FA2)

1. **Originate the native Tez bridge ticketer** (`tezos/tez_bridge_ticketer.tz`):

   ```bash
   sudo -u tzel /usr/local/bin/octez-client \
     -d /var/lib/tzel/octez-client \
     -E http://127.0.0.1:8732 \
     originate contract tzel_tez_bridge \
     transferring 0 from tzelpqnet \
     running tezos/tez_bridge_ticketer.tz \
     --init Unit --burn-cap 5 --force
   ```

   Record the resulting `KT1...` address and set `TZEL_BRIDGE_TICKETER=<KT1...>` in `/etc/tzel/pqnet.env`.

2. **(Multi-Asset / FA2) Originate a test FA2 token + FA2 bridge ticketer**:
   Because FA2 bridge ticketers are registered in `COMPILE_TIME_FA2_BRIDGES` in [`core/src/lib.rs`](../../core/src/lib.rs), originate the FA2 bridge ticketer **before** compiling the release rollup kernel:

   ```bash
   # Optional: originate the minimal test FA2 contract with 1,000,000,000 units of token_id 0 for $OPERATOR_PKH
   sudo -u tzel /usr/local/bin/octez-client \
     -d /var/lib/tzel/octez-client \
     -E http://127.0.0.1:8732 \
     originate contract tzel_test_fa2 \
     transferring 0 from tzelpqnet \
     running tezos/dev_minimal_fa2.tz \
     --init "{ Elt (Pair \"${OPERATOR_PKH}\" 0) 1000000000 }" \
     --burn-cap 5 --force

   FA2_KT1="$(sudo -u tzel /usr/local/bin/octez-client -d /var/lib/tzel/octez-client \
     show known contract tzel_test_fa2)"

   # Originate the FA2 bridge ticketer for (FA2_KT1, token_id = 0)
   sudo -u tzel /usr/local/bin/octez-client \
     -d /var/lib/tzel/octez-client \
     -E http://127.0.0.1:8732 \
     originate contract tzel_fa2_bridge_0 \
     transferring 0 from tzelpqnet \
     running tezos/fa2_bridge_ticketer.tz \
     --init "(Pair \"${FA2_KT1}\" 0)" \
     --burn-cap 5 --force

   FA2_TICKETER_KT1="$(sudo -u tzel /usr/local/bin/octez-client -d /var/lib/tzel/octez-client \
     show known contract tzel_fa2_bridge_0)"
   echo "FA2 Bridge Ticketer KT1: $FA2_TICKETER_KT1"
   ```

   Add `"$FA2_TICKETER_KT1"` to `COMPILE_TIME_FA2_BRIDGES` in [`core/src/lib.rs`](../../core/src/lib.rs) (see [`docs/multiasset_deployment.md`](../../docs/multiasset_deployment.md) for details).

### Step 5: Build & Install TzEL Binaries and Rollup Kernel

Build and install the TzEL release binaries (`tzel-operator`, `tzel-wallet`, `tzel-detect`, `reprove`, `submit_rollup_config`, `octez_kernel_message`, `verified_bridge_fixture_message`) and the release rollup kernel WASM:

```bash
./scripts/install_tzel_binaries.sh --build-only
sudo ./scripts/install_tzel_binaries.sh --skip-build --prefix /usr/local
./scripts/build_rollup_kernel_release.sh --state-dir /usr/local/etc/tzel
```

### Step 6: Originate the Smart Rollup and Populate Reveal Preimages

Generate the reveal installer kernel and copy the preimages into `/var/lib/tzel/octez-rollup-node/wasm_2_0_0`:

```bash
sudo install -d -o tzel -g tzel /var/lib/tzel/octez-rollup-node/wasm_2_0_0

smart-rollup-installer get-reveal-installer \
  -P /var/lib/tzel/octez-rollup-node/wasm_2_0_0 \
  -u target/wasm32-unknown-unknown/release/tzel_rollup_kernel.wasm \
  -o /tmp/tzel-installer.hex

sudo chown -R tzel:tzel /var/lib/tzel/octez-rollup-node

BOOT_SECTOR="$(tr -d '\n' < /tmp/tzel-installer.hex)"
sudo -u tzel /usr/local/bin/octez-client \
  -d /var/lib/tzel/octez-client \
  -E http://127.0.0.1:8732 \
  originate smart rollup tzel_pqnet from tzelpqnet \
  of kind wasm_2_0_0 \
  of type '(pair bytes (ticket (pair nat (option bytes))))' \
  with kernel "${BOOT_SECTOR}" \
  --burn-cap 999 --force
```

Record the originated `sr1...` address and set `TZEL_ROLLUP_ADDRESS=<sr1...>` in `/etc/tzel/pqnet.env`.

### Step 7: Initialize Operator Material and Start Remaining Services

Generate the operator DAL-fee wallet, receive address, and view material:

```bash
/usr/local/bin/tzel-wallet --wallet /tmp/operator-fee.wallet init
/usr/local/bin/tzel-wallet --wallet /tmp/operator-fee.wallet receive | tail -n +2 \
  | sudo tee /etc/tzel/operator-dal-fee-address.json >/dev/null
/usr/local/bin/tzel-wallet --wallet /tmp/operator-fee.wallet export-view \
  --out /tmp/operator-dal-fee.view.json
sudo install -m 0640 -o root -g tzel /tmp/operator-dal-fee.view.json /etc/tzel/operator-dal-fee.view.json
```

Initialize box directories/bearer token and start `octez-dal-node`, `octez-rollup-node`, and `tzel-operator`:

```bash
sudo ./scripts/init_shadownet_operator_box.sh /etc/tzel/pqnet.env tzel
sudo cp ops/pqnet/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now octez-node octez-dal-node octez-rollup-node tzel-operator
./scripts/shadownet_operator_preflight.sh /etc/tzel/pqnet.env
```

### Step 8: Configure Verifier and Bridge on the Live Rollup

Once `octez-dal-node` and `octez-rollup-node` are synced:

```bash
source /etc/tzel/pqnet.env
export OPERATOR_URL="http://${TZEL_OPERATOR_LISTEN}"
export OPERATOR_BEARER_TOKEN="$(sudo cat "${TZEL_OPERATOR_BEARER_TOKEN_FILE}")"

FIXTURE_JSON="tezos/rollup-kernel/testdata/verified_bridge_flow.json"
META_JSON="$(/usr/local/bin/verified_bridge_fixture_message metadata "$FIXTURE_JSON")"
AUTH_DOMAIN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["auth_domain"])' <<<"$META_JSON")"
SHIELD_HASH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["shield_program_hash"])' <<<"$META_JSON")"
TRANSFER_HASH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["transfer_program_hash"])' <<<"$META_JSON")"
UNSHIELD_HASH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["unshield_program_hash"])' <<<"$META_JSON")"

/usr/local/bin/submit_rollup_config \
  --operator-url "$OPERATOR_URL" \
  --bearer-token "$OPERATOR_BEARER_TOKEN" \
  --rollup-address "$TZEL_ROLLUP_ADDRESS" \
  configure-verifier \
  "$AUTH_DOMAIN" "$SHIELD_HASH" "$TRANSFER_HASH" "$UNSHIELD_HASH"

/usr/local/bin/submit_rollup_config \
  --operator-url "$OPERATOR_URL" \
  --bearer-token "$OPERATOR_BEARER_TOKEN" \
  --rollup-address "$TZEL_ROLLUP_ADDRESS" \
  configure-bridge \
  "$TZEL_BRIDGE_TICKETER"
```

### Step 9: Run Live End-to-End Smoke

Run the automated `deposit -> shield -> send -> unshield` smoke against `/etc/tzel/pqnet.env`:

```bash
TZEL_SMOKE_L1_RECIPIENT="$OPERATOR_PKH" \
  ./scripts/shadownet_live_e2e_smoke.sh /etc/tzel/pqnet.env
```

For manual wallet profiles on PQNet, pass `--octez-protocol "$TZEL_OCTEZ_PROTOCOL"` (or `--octez-protocol auto`) to `tzel-wallet profile init-shadownet` so `octez-client` uses `ProtoALphaALphaALphaALphaALphaALphaALphaALphaDdp3zK` instead of the Shadownet default (`PtTALLiN`). For FA2 multi-asset flows (`deposit --asset`, `shield --asset`, `send --asset`, `unshield --asset`), see [`docs/multiasset_deployment.md`](../../docs/multiasset_deployment.md) and §14 of [`docs/shadownet_tutorial.md`](../../docs/shadownet_tutorial.md).
