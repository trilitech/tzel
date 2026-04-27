# Shadownet Tutorial

This tutorial covers a Shadownet `deposit -> shield -> send` flow against a
deployed rollup using the operator box.

> **Status note:** the protocol uses **deposit pools** keyed by a wallet-
> derived pubkey hash. The L1 deposit transaction credits the pool keyed
> by `deposit:<hex(pubkey_hash)>`, where `pubkey_hash` commits to the
> deployment's auth_domain plus the recipient's auth tree plus a
> per-deposit blind. Multiple L1 tickets to the same pool aggregate
> (top-ups). The shield circuit verifies an in-circuit WOTS+ signature
> from the recipient's auth tree, binding the entire shield request, so
> only the wallet that holds the auth tree's signing material can drain
> the pool. The rollup wallet flow below: `deposit` allocates a fresh
> pool and L1-tickets to it; `shield --pubkey-hash ... --amount ...`
> drains a chosen amount; `send` stays internal; `unshield` withdraws
> to an L1 tz/KT1 recipient.

The current rollup policy burns at least `100000` mutez (`0.1 tez`) on every
`shield`, `send`, and `unshield`. The first two accepted private transactions at
a given inbox level pay that floor; each additional private transaction at the
same level doubles the required burn fee, capped after 6 steps. Each of those
transactions also pays a separate private DAL-producer fee note.

If you omit `--fee`, `tzel-wallet` uses the rollup's currently quoted required
burn fee.

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
- `/usr/local/bin/submit_rollup_config`
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
export OPERATOR_URL=http://127.0.0.1:8787
export OPERATOR_BEARER_TOKEN="$(cat /etc/tzel/operator-bearer-token)"
export ROLLUP_ADDRESS=sr1REPLACE_ME
export BRIDGE_TICKETER=KT1REPLACE_ME
```

Extract the verifier configuration values from the checked-in verified fixture:

```bash
export FIXTURE_JSON=tezos/rollup-kernel/testdata/verified_bridge_flow.json
META_JSON="$(/usr/local/bin/verified_bridge_fixture_message metadata "$FIXTURE_JSON")"

export AUTH_DOMAIN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["auth_domain"])' <<<"$META_JSON")"
export SHIELD_HASH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["shield_program_hash"])' <<<"$META_JSON")"
export TRANSFER_HASH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["transfer_program_hash"])' <<<"$META_JSON")"
export UNSHIELD_HASH="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["unshield_program_hash"])' <<<"$META_JSON")"
```

Submit `configure-verifier` through the operator:

```bash
/usr/local/bin/submit_rollup_config \
  --operator-url "$OPERATOR_URL" \
  --bearer-token "$OPERATOR_BEARER_TOKEN" \
  --rollup-address "$ROLLUP_ADDRESS" \
  configure-verifier \
  "$AUTH_DOMAIN" \
  "$SHIELD_HASH" \
  "$TRANSFER_HASH" \
  "$UNSHIELD_HASH"
```

Submit `configure-bridge` through the operator:

```bash
/usr/local/bin/submit_rollup_config \
  --operator-url "$OPERATOR_URL" \
  --bearer-token "$OPERATOR_BEARER_TOKEN" \
  --rollup-address "$ROLLUP_ADDRESS" \
  configure-bridge \
  "$BRIDGE_TICKETER"
```

The operator automatically falls back to DAL when a config message is too large
for the direct inbox path, which is the normal case for the signed config
payloads now. Each command returns JSON with a `submission.id`; poll
`$OPERATOR_URL/v1/rollup/submissions/<id>` until both submissions reach
`submitted_to_l1`, then verify local services again:

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
/usr/local/bin/tzel-wallet --wallet producer.wallet init
```

Create a shielded address for the DAL slot producer payment:

```bash
/usr/local/bin/tzel-wallet \
  --wallet producer.wallet \
  receive | sed -n '2,$p' > producer-address.json
```

Create Shadownet profiles:

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  profile init-shadownet \
  --rollup-node-url http://127.0.0.1:28944 \
  --rollup-address "$ROLLUP_ADDRESS" \
  --bridge-ticketer "$BRIDGE_TICKETER" \
  --dal-fee 1 \
  --dal-fee-address producer-address.json \
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
  --dal-fee 1 \
  --dal-fee-address producer-address.json \
  --operator-url http://127.0.0.1:8787 \
  --operator-bearer-token "$OPERATOR_BEARER_TOKEN" \
  --source-alias "$SOURCE_ALIAS" \
  --public-account bob
```

Notes:

- `dal_fee_address` is the shielded address that receives the DAL inclusion fee note
- each `deposit` derives a fresh `pubkey_hash = H_pubkey(auth_domain, auth_root, auth_pub_seed, blind)` for a wallet-controlled auth tree, then L1-tickets the deposit amount to `deposit:<hex(pubkey_hash)>`. Multiple deposits to the same `pubkey_hash` aggregate (top-ups). The shield circuit verifies an in-circuit WOTS+ signature under the recipient's auth tree, binding the entire shield request — only the wallet that holds the auth tree's signing material can drain the pool.
- `public_account` in the profile is vestigial wallet metadata — unshield now emits an L1 outbox transfer directly to a tz/KT1 recipient supplied at unshield time.
- keep Alice and Bob distinct
- **Pool-bound shields are flexible:** the wallet picks `(v, fee, producer_fee)` at shield time, not deposit time. Pool overfunding is fine — the surplus stays available for future shields. Dust attackers depositing to a victim's `pubkey_hash` just add to the victim's pool balance (they're donating mutez they can't drain themselves).

## 6. Fund Alice On L1 And Wait For The Kernel Pool To See The Credit

Deposit into the bridge for Alice's next shield. The wallet derives a fresh `pubkey_hash` from her auth tree plus a per-deposit blind, then asks the bridge to send an L1 ticket to `deposit:<hex(pubkey_hash)>` for the chosen amount. The kernel credits the per-pool aggregated balance.

Before submitting the L1 ticket, the wallet runs preflight checks against the rollup's durable state and refuses if any disagrees:

1. The kernel verifier config (`/tzel/v1/state/verifier_config.bin`) is installed. Deposits before configuration are rejected by the kernel; the L1 ticket would burn for nothing.
2. The kernel's configured bridge ticketer (`/tzel/v1/state/bridge/ticketer`) equals `profile.bridge_ticketer`. A mismatch means the kernel won't accept tickets from this bridge contract.

(The producer-fee `operator_producer_owner_tag` gate runs at shield/transfer/unshield time, not at deposit time, since the producer-fee note is now picked at shield time.)

```bash
DEPOSIT_OUTPUT="$(
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  deposit \
  --amount 400000
)"
printf '%s\n' "$DEPOSIT_OUTPUT"
PUBKEY_HASH="$(awk '/Submitted L1 bridge deposit/ {print $NF}' <<<"$DEPOSIT_OUTPUT")"
```

The wallet prints an L1 operation hash and the pool's pubkey_hash. Wait for the
ticket to land, then poll:

```bash
/usr/local/bin/tzel-wallet --wallet alice.wallet balance
```

Do not continue until `tzel-wallet sync` shows the pool funded:

```text
Synced: ... pool_funded_total=400000, pools_awaiting_credit=0
```

## 7. Shield Alice's Funds

Shield into a self-address first:

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  --reprove-bin /usr/local/bin/reprove \
  --executables-dir /opt/tzel/cairo/target/dev \
  shield \
  --pubkey-hash "$PUBKEY_HASH" \
  --amount 300000
```

The wallet picks `fee = required_tx_fee_now` and `producer_fee` from the profile, signs the shield sighash with the next available WOTS+ key index in Alice's auth tree, generates the proof, and submits.

Expected output includes:

- `Submitted shield draining pool ...`
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

- The pool's balance is debited by `v + fee + producer_fee` (and the entry is removed if the pool reaches zero)
- Alice's private available balance becomes non-zero by exactly the recipient note's value

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

- Alice has a private balance reduced by the sent amount plus the fixed `100000` mutez burn and the configured DAL-producer fee
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
- `pool_funded_total=0` even after the L1 deposit lands:
  - bridge config is wrong, the kernel did not parse the ticket, or the rollup node is not following the right rollup
- `sync` finds nothing after a successful operator state:
  - rollup node is stale, wrong `rollup_node_url`, or wrong wallet profile
- Shield rejected with "deposit pool balance too small":
  - the pool wasn't credited with enough mutez for `v + fee + producer_fee`. Send another L1 ticket to the same `deposit:<hex(pubkey_hash)>` recipient (top-up); shielding can be retried once sync sees the larger balance.
- Shield rejected with "fee below minimum":
  - the rollup's `required_tx_fee` ticked up since the wallet quoted it. Re-run shield (the wallet re-quotes on each invocation); regenerate the proof if necessary.

## 12. Minimal Success Bar

We can say “Shadownet shielded tx is working” when all of the following are true:

- one live `deposit -> shield` succeeds
- one live `send` succeeds
- Bob can independently sync and observe the received note
- the flow is reproducible on the public operator box
