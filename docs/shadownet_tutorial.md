# Shadownet Tutorial

This tutorial covers a Shadownet `deposit -> shield -> send` flow against a
deployed rollup using the operator box.

> **Status note:** the protocol uses intent-bound shield deposit ids with
> per-deposit slots. The L1 deposit transaction commits to the entire shield
> (recipient, value, fees, encrypted-note bytes) by addressing the L1 ticket
> to `deposit:<hex(intent)>`, and the kernel allocates a fresh slot per
> ticket so dust deposits to the same intent cannot brick a legitimate one.
> The rollup wallet flow below is current: `deposit` creates the pending
> intent-bound deposit, `shield --deposit-id ...` drains the slot,
> `send` stays internal, and `unshield` withdraws directly to an L1 tz/KT1
> recipient.

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
- each `deposit` builds the entire shield (recipient note + producer-fee note) up front, computes the *intent-bound* deposit id (`shield_intent` over every shield public output), and addresses the L1 ticket to the canonical recipient string `deposit:<hex(intent)>`. Each L1 ticket allocates its own kernel-side **slot** keyed by a fresh kernel-controlled `slot_id` (depositors don't control the id), with content `(intent, amount)`. The L1 deposit transaction is itself the shield authorization — there is no `deposit_secret`, and any modification of the witness (recipient, value, fees) yields a different deposit id whose slots either don't exist or bind a different intent.
- `public_account` in the profile is vestigial wallet metadata — unshield now emits an L1 outbox transfer directly to a tz/KT1 recipient supplied at unshield time, and the per-account "transparent rollup balance" scheme has been removed.
- keep Alice and Bob distinct
- **Shield deposits are single-shot and exact-amount:** the wallet computes `v + fee + producer_fee` and instructs the bridge to deposit precisely that amount. There is no partial drain and no top-up — both would require updating `intent`, which contradicts the L1 commitment. An over- or under-deposit leaves an orphan slot but does not affect any other slot. **Dust-resistance:** an attacker observing the public `deposit:<hex(intent)>` recipient string cannot brick a victim's shield by sending 1 mutez to the same recipient — that just allocates an unrelated orphan slot.

## 6. Fund Alice On L1 And Wait For The Kernel To Allocate A Deposit Slot

Deposit into the bridge for Alice's next shield. The wallet builds the recipient and producer-fee notes, computes `intent = shield_intent(auth_domain, v, fee, producer_fee, cm_recipient, cm_producer, mh, mh_producer)`, and asks the bridge to send an L1 ticket to `deposit:<hex(intent)>` for exactly `v + fee + producer_fee` mutez. The kernel allocates a fresh slot for the ticket — keyed by a kernel-controlled monotonic `slot_id`, with content `(intent, amount)`. The wallet picks up the slot id during sync.

Before submitting the L1 ticket, the wallet runs three preflight checks against the rollup's durable state and refuses if any disagrees:

1. The kernel verifier config (`/tzel/v1/state/verifier_config.bin`) is installed. Deposits before configuration are rejected by the kernel; the L1 ticket would burn for nothing.
2. The kernel's configured bridge ticketer (`/tzel/v1/state/bridge/ticketer`) equals `profile.bridge_ticketer`. A mismatch means the kernel won't accept tickets from this bridge contract.
3. The kernel's published `operator_producer_owner_tag` equals the `owner_tag` derived from `profile.dal_fee_address`. Without this check a misconfigured profile silently routes the producer-fee note to a non-operator receiver — there is no in-circuit binding from `cm_producer`'s recipient back to the operator's address. (If the rollup published a zero owner_tag the wallet warns and proceeds, trusting the profile.)

The same `operator_producer_owner_tag` gate also runs for `transfer` and `unshield` since those also emit a producer-fee note.

```bash
DEPOSIT_OUTPUT="$(
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  deposit \
  --amount 300000
)"
printf '%s\n' "$DEPOSIT_OUTPUT"
DEPOSIT_ID="$(awk '/Submitted L1 bridge deposit/ {print $NF}' <<<"$DEPOSIT_OUTPUT")"
```

The wallet prints an L1 operation hash and the intent hex. Wait for it to land,
then poll:

```bash
/usr/local/bin/tzel-wallet --wallet alice.wallet balance
```

Do not continue until `tzel-wallet sync` reports the slot has been picked up:

```text
Synced: ... 1 slots assigned, ..., pending_deposit_total=400001
```

## 7. Shield Alice’s Funds

Shield into a self-address first:

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  --reprove-bin /usr/local/bin/reprove \
  --executables-dir /opt/tzel/cairo/target/dev \
  shield \
  --deposit-id "$DEPOSIT_ID"
```

Expected output includes:

- `Submitted shield draining deposit ...`
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

- The deposit slot for `(intent, debit)` disappears (single-shot, tombstoned)
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
- `0 slots assigned` even after the L1 deposit lands:
  - bridge config is wrong, the kernel did not parse the ticket, or the rollup node is not following the right rollup
- `sync` finds nothing after a successful operator state:
  - rollup node is stale, wrong `rollup_node_url`, or wrong wallet profile
- `WARNING: N orphan deposit slot(s) detected` during sync:
  - someone (typically a dust-attacking watcher) has deposited an L1 ticket with the same `(intent, amount)` as one of your settled shields. The kernel allocated extra open slots that your shield did not drain. Each orphan slot still holds real L1 mutez backed by the bridge.
  - To recover, run `tzel-wallet drain-orphan-slot --slot-id <id>` for each reported slot. The wallet re-shields the original recipient `cm` against the orphan slot using the stored deposit witness. The result is a duplicate `cm` at a new tree position with a distinct nullifier — fully spendable, but the two leaves are publicly correlatable to the same intent.
  - Orphan-drain only works if the wallet still holds the matching settled `PendingDeposit` (it does, because settled deposits are kept around precisely to enable this). A slot that was never witness-tracked by this wallet cannot be drained.

## 12. Minimal Success Bar

We can say “Shadownet shielded tx is working” when all of the following are true:

- one live `deposit -> shield` succeeds
- one live `send` succeeds
- Bob can independently sync and observe the received note
- the flow is reproducible on the public operator box
