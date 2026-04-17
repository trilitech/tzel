# Shadownet Tutorial

This tutorial covers a Shadownet `deposit -> shield -> send` flow against a
deployed rollup using the operator box.

It assumes:

- a public operator machine running `octez-node`, `octez-dal-node`,
  `octez-smart-rollup-node`, and `tzel-operator`
- a live rollup `sr1...`
- a live bridge ticketer `KT1...`

It ends with:

1. Alice deposits on L1 and shields into a private note
2. Bob derives a receive address
3. Alice sends a private transfer to Bob
4. Bob syncs and sees the received note

Before you start, make sure the deployed rollup passes:

```bash
/usr/local/bin/tzel-wallet --wallet alice.wallet check
```

If `check` reports missing durable note payloads while the tree size is non-zero,
that deployment cannot support private note sync and should be replaced with a
fresh rollup origination using the committed kernel build.

## 1. Install The Required Binaries

From the repo root:

```bash
./scripts/install_tzel_binaries.sh --build-only

sudo ./scripts/install_tzel_binaries.sh \
  --skip-build \
  --prefix /usr/local \
  --executables-dir /opt/tzel/cairo/target/dev
```

The wallet commands below assume:

- `/usr/local/bin/tzel-wallet`
- `/usr/local/bin/reprove`
- `/usr/local/bin/octez_kernel_message`
- `/usr/local/bin/verified_bridge_fixture_message`
- Cairo executables in `/opt/tzel/cairo/target/dev`
- rollup config admin env files in `/usr/local/etc/tzel/rollup-config-admin-{runtime,build}.env`

## 2. Bring Up The Public Operator Box

On the public server:

```bash
./scripts/install_octez_ubuntu.sh
sudo mkdir -p /etc/tzel
sudo cp ops/shadownet/shadownet.env.example /etc/tzel/shadownet.env
```

Edit `/etc/tzel/shadownet.env`:

- set `TZEL_ROLLUP_ADDRESS=sr1...`
- set `TZEL_BRIDGE_TICKETER=KT1...`
- set `TZEL_DAL_PUBLIC_ADDR=<PUBLIC_IP_OR_DNS>:11732`
- make sure `TZEL_SOURCE_ALIAS` matches the account you will fund and use
- set `TZEL_OPERATOR_BEARER_TOKEN_FILE=/etc/tzel/operator-bearer-token`

Initialize state:

```bash
sudo ./scripts/init_shadownet_operator_box.sh /etc/tzel/shadownet.env
```

Import the funded Shadownet key:

```bash
sudo -u tzel octez-client -d /var/lib/tzel/octez-client import secret key tzelshadownet <SECRET_KEY>
```

Install and start the units:

```bash
sudo cp ops/shadownet/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now octez-node octez-dal-node octez-rollup-node tzel-operator
./scripts/shadownet_operator_preflight.sh /etc/tzel/shadownet.env
```

If this machine is behind a firewall, open:

- `TZEL_OCTEZ_NODE_NET_ADDR` TCP
- `TZEL_DAL_NET_ADDR` TCP

## 3. Configure The Live Rollup Once

These commands are one-time per deployed rollup.

Set the shell variables first:

```bash
export CLIENT_DIR=/var/lib/tzel/octez-client
export NODE_ENDPOINT=http://127.0.0.1:8732
export ROLLUP_ADDRESS=sr1REPLACE_ME
export BRIDGE_TICKETER=KT1REPLACE_ME
export SOURCE_ALIAS=tzelshadownet
```

Extract the verifier metadata from the checked-in verified fixture:

```bash
export FIXTURE_JSON=tezos/rollup-kernel/testdata/verified_bridge_flow.json
META_JSON="$(/usr/local/bin/verified_bridge_fixture_message metadata "$FIXTURE_JSON")"

export AUTH_DOMAIN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["auth_domain"])' <<<"$META_JSON")"
export SHIELD_HASH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["shield_program_hash"])' <<<"$META_JSON")"
export TRANSFER_HASH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["transfer_program_hash"])' <<<"$META_JSON")"
export UNSHIELD_HASH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["unshield_program_hash"])' <<<"$META_JSON")"
```

Send `configure-verifier`:

```bash
MSG_HEX="$(/usr/local/bin/octez_kernel_message configure-verifier \
  "$ROLLUP_ADDRESS" \
  "$AUTH_DOMAIN" \
  "$SHIELD_HASH" \
  "$TRANSFER_HASH" \
  "$UNSHIELD_HASH")"

octez-client -d "$CLIENT_DIR" -E "$NODE_ENDPOINT" \
  send smart rollup message "hex:[ \"$MSG_HEX\" ]" from "$SOURCE_ALIAS"
```

Send `configure-bridge`:

```bash
MSG_HEX="$(/usr/local/bin/octez_kernel_message configure-bridge \
  "$ROLLUP_ADDRESS" \
  "$BRIDGE_TICKETER")"

octez-client -d "$CLIENT_DIR" -E "$NODE_ENDPOINT" \
  send smart rollup message "hex:[ \"$MSG_HEX\" ]" from "$SOURCE_ALIAS"
```

Wait for both operations to be included, then verify local services again:

```bash
./scripts/shadownet_operator_preflight.sh /etc/tzel/shadownet.env
curl -fsS http://127.0.0.1:8787/healthz
curl -fsS http://127.0.0.1:28944/global/block/head/hash
curl -fsS http://127.0.0.1:10732/synchronized
```

For a single-command end-to-end smoke on a prepared public box, see:

```bash
TZEL_SMOKE_L1_RECIPIENT=tz1REPLACE_ME ./scripts/shadownet_live_e2e_smoke.sh /etc/tzel/shadownet.env
```

## 4. Decide Where To Run The Wallet

Simplest option: run the wallet on the operator box itself.

If you want to run it from another machine, create SSH tunnels first:

```bash
ssh -L 8787:127.0.0.1:8787 -L 28944:127.0.0.1:28944 <server>
```

Then use:

- `http://127.0.0.1:8787` for `operator_url`
- `http://127.0.0.1:28944` for `rollup_node_url`

Load the operator bearer token before creating wallet profiles:

```bash
export OPERATOR_BEARER_TOKEN="$(cat /etc/tzel/operator-bearer-token)"
```

## 5. Create Alice And Bob Wallets

Use a dedicated working directory:

```bash
mkdir -p /tmp/tzel-shadownet-live
cd /tmp/tzel-shadownet-live
```

Create wallet files:

```bash
/usr/local/bin/tzel-wallet --wallet alice.wallet init
/usr/local/bin/tzel-wallet --wallet bob.wallet init
```

Create Shadownet profiles:

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  profile init-shadownet \
  --rollup-node-url http://127.0.0.1:28944 \
  --rollup-address "$ROLLUP_ADDRESS" \
  --bridge-ticketer "$BRIDGE_TICKETER" \
  --operator-url http://127.0.0.1:8787 \
  --operator-bearer-token "$OPERATOR_BEARER_TOKEN" \
  --source-alias "$SOURCE_ALIAS" \
  --public-account alice

/usr/local/bin/tzel-wallet \
  --wallet bob.wallet \
  profile init-shadownet \
  --rollup-node-url http://127.0.0.1:28944 \
  --rollup-address "$ROLLUP_ADDRESS" \
  --bridge-ticketer "$BRIDGE_TICKETER" \
  --operator-url http://127.0.0.1:8787 \
  --operator-bearer-token "$OPERATOR_BEARER_TOKEN" \
  --source-alias "$SOURCE_ALIAS" \
  --public-account bob
```

Notes:

- `public-account` is the rollup-visible transparent account string, not an L1 address
- keep Alice and Bob distinct

## 6. Fund Alice On L1 And Wait For The Public Rollup Balance

Deposit into the bridge for Alice’s public rollup account:

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  deposit \
  --amount 300000 \
  --public-account alice
```

The wallet prints an L1 operation hash. Wait for it to land, then poll:

```bash
/usr/local/bin/tzel-wallet --wallet alice.wallet balance
```

Do not continue until Alice shows a non-zero line like:

```text
Public rollup balance (alice): 300000
```

## 7. Shield Alice’s Funds

Shield into a self-address first:

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  --reprove-bin /usr/local/bin/reprove \
  --executables-dir /opt/tzel/cairo/target/dev \
  shield \
  --amount 200000
```

Expected output includes:

- `Submitted shield of ...`
- `Submission id: sub-...`

Track the submission:

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  status \
  --submission-id sub-REPLACE_ME
```

Keep polling until the operator reports a final state. Then sync Alice:

```bash
/usr/local/bin/tzel-wallet --wallet alice.wallet sync
/usr/local/bin/tzel-wallet --wallet alice.wallet balance
```

Acceptance:

- Alice’s public rollup balance drops by the shielded amount
- Alice’s private available balance becomes non-zero

## 8. Derive Bob’s Receive Address

`receive` prints one label line followed by JSON. Save the JSON part to a file:

```bash
/usr/local/bin/tzel-wallet \
  --wallet bob.wallet \
  receive | sed -n '2,$p' > bob-address.json
```

Check the file:

```bash
cat bob-address.json
```

## 9. Send A Shielded Transfer From Alice To Bob

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  --reprove-bin /usr/local/bin/reprove \
  --executables-dir /opt/tzel/cairo/target/dev \
  send \
  --to bob-address.json \
  --amount 50000
```

Expected output includes:

- `Submitted transfer of ...`
- `Submission id: sub-...`

Poll operator status until final:

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  status \
  --submission-id sub-REPLACE_ME
```

Then sync both wallets:

```bash
/usr/local/bin/tzel-wallet --wallet alice.wallet sync
/usr/local/bin/tzel-wallet --wallet bob.wallet sync

/usr/local/bin/tzel-wallet --wallet alice.wallet balance
/usr/local/bin/tzel-wallet --wallet bob.wallet balance
```

Acceptance:

- Alice has a private balance reduced by the sent amount
- Bob has a private balance equal to the received note

## 10. Evidence To Keep

For the first successful live run, save:

- the L1 deposit op hash
- the operator submission ids for `shield` and `send`
- the operator status JSON for each
- the rollup address and bridge ticketer
- TzKT links for the L1 ops
- wallet `balance` and `sync` output before and after

## 11. Failure Modes To Watch

- `pending_dal` that never progresses:
  - DAL node is up, but slot publication / commitment inclusion is not advancing
- `unattested`:
  - the public DAL node is not reachable enough from the network
- `public balance` never changes after deposit:
  - bridge config is wrong or the rollup node is not following the right rollup
- `sync` finds nothing after a successful operator state:
  - rollup node is stale, wrong `rollup_node_url`, or wrong wallet profile

## 12. Minimal Success Bar

We can say “Shadownet shielded tx is working” when all of the following are true:

- one live `deposit -> shield` succeeds
- one live `send` succeeds
- Bob can independently sync and observe the received note
- the flow is reproducible on the public operator box
