# Ushuaianet Tutorial

This tutorial covers an Ushuaianet `deposit -> shield -> send -> unshield`
flow against the deployed TzEL rollup using the operator box.

> **Naming note:** the test network is **Ushuaianet** (replaces Shadownet —
> DAL slot latency 20 s vs 50 s, withdrawal period ~6.5 min vs 14 days, plus
> the `dal_fee_address` mechanism that only exists post-Ushuaianet).
>
> A few wallet-CLI subcommands and operator-box file paths still use the old
> `shadownet` spelling (`profile init-shadownet`, `/etc/tzel/shadownet.env`,
> `ops/shadownet/`, `scripts/shadownet_*.sh`, `--source-alias tzelshadownet`).
> They are kept as-is in this tutorial because renaming them would touch the
> wallet CLI surface, the systemd units, and CI tests; that rename is tracked
> separately. Everywhere else, "Ushuaianet" is the correct name.

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

## 0. Ushuaianet Network Parameters

The currently deployed TzEL rollup runs on **Ushuaianet**. The L1 / DAL /
explorer endpoints below are stable; the rollup-address and bridge-ticketer
are tied to a specific origination and are kept out of this tutorial as
literals — fetch them from the canonical config so the doc never drifts
from the live deployment.

| Parameter | Value |
|---|---|
| Octez network identifier | `ushuaianet` |
| Public L1 RPC | `https://rpc.ushuaianet.teztnets.com` |
| L1 snapshot (rolling) | `https://snapshots.tzinit.org/ushuaianet/rolling` |
| DAL bootstrap P2P | `dal.ushuaianet.teztnets.com:11732` |
| Faucet | `https://faucet.ushuaianet.teztnets.com` |
| TzKT explorer | `https://ushuaianet.tzkt.io` |
| TzEL rollup address | `sr1...` — see `tzel-infra/networks/ushuaianet.yml` (`tzel_rollup_address`) |
| TzEL bridge ticketer | `KT1...` — see `tzel-infra/networks/ushuaianet.yml` (`tzel_bridge_ticketer`) |
| Operator DAL fee (mutez) | `100000` |
| Operator fee address | see `tzel-infra/networks/ushuaianet-operator-fee-address.json` |

Both addresses live at:

```
https://github.com/trilitech/tzel-infra/blob/feat/ushaianet-4vm-refactor/networks/ushuaianet.yml
```

If you originated your own rollup, substitute the `sr1…` / `KT1…` values
from the `make originate NETWORK=ushaianet` output in `tzel-infra` for the
canonical ones below.

> **Withdrawal period:** Ushuaianet's commitment period is short — withdrawals
> become executable on L1 in roughly 6 to 7 minutes after the unshield batch
> is finalized, vs. ~14 days on Shadownet. The wallet's `unshield` command
> emits the L1 outbox transfer; you still need to call the rollup's
> `execute_outbox_message` once the period elapses (covered in §10).

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

- set `TZEL_ROLLUP_ADDRESS=<sr1...>` — pull from
  `tzel-infra/networks/ushuaianet.yml` (`tzel_rollup_address`) or your
  re-originated value (see §0)
- set `TZEL_BRIDGE_TICKETER=<KT1...>` — pull from
  `tzel-infra/networks/ushuaianet.yml` (`tzel_bridge_ticketer`) or your
  re-originated ticketer
- set `TZEL_OCTEZ_NETWORK=ushuaianet` (the env file template still shows the
  old default — override it explicitly so `octez-node config init` and
  `--network` pick up Ushuaianet)
- set `TZEL_L1_SNAPSHOT_URL=https://snapshots.tzinit.org/ushuaianet/rolling`
- set `TZEL_DAL_BOOTSTRAP_PEER=dal.ushuaianet.teztnets.com:11732`
- set `TZEL_DAL_PUBLIC_ADDR=<PUBLIC_IP_OR_DNS>:11732`
- make sure `TZEL_SOURCE_ALIAS` matches the account you will fund and use
- set `TZEL_OPERATOR_BEARER_TOKEN_FILE=/etc/tzel/operator-bearer-token`

> The legacy `ops/shadownet/shadownet.env.example` template predates the
> Ushuaianet rename and has Shadownet-era defaults. The `TZEL_OCTEZ_NETWORK`,
> `TZEL_L1_SNAPSHOT_URL`, and `TZEL_DAL_BOOTSTRAP_PEER` overrides above are
> what flip the box onto Ushuaianet without renaming the file.

Initialize state:

```bash
sudo ./scripts/init_shadownet_operator_box.sh /etc/tzel/shadownet.env
```

Import a funded Ushuaianet key (top up via the faucet at
`https://faucet.ushuaianet.teztnets.com` if needed — Ushuaianet baking
needs ~6000 ꜩ but the operator account only needs enough to cover gas
plus the bridge ticket amounts you intend to deposit):

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

These commands are one-time per deployed rollup. They must be run from a
checkout of `trilitech/tzel` at the kernel commit currently deployed on
Ushuaianet (`558c2b2` — i.e. `main` HEAD as of the Ushuaianet bring-up).
A divergent kernel will produce a different `auth_domain` /
`*_program_hash`, and the `configure-verifier` payload below would silently
mismatch the running rollup.

```bash
git fetch origin && git checkout 558c2b2
```

Set the shell variables first. Pull `ROLLUP_ADDRESS` and `BRIDGE_TICKETER`
from `tzel-infra/networks/ushuaianet.yml` (or your local
`make originate NETWORK=ushaianet` output if you re-originated):

```bash
export OPERATOR_URL=http://127.0.0.1:8787
export OPERATOR_BEARER_TOKEN="$(cat /etc/tzel/operator-bearer-token)"

# Fetch canonical addresses from tzel-infra (requires `yq`):
USHUAIANET_YML=https://raw.githubusercontent.com/trilitech/tzel-infra/feat/ushaianet-4vm-refactor/networks/ushuaianet.yml
export ROLLUP_ADDRESS="$(curl -fsSL "$USHUAIANET_YML" | yq -r .tzel_rollup_address)"
export BRIDGE_TICKETER="$(curl -fsSL "$USHUAIANET_YML" | yq -r .tzel_bridge_ticketer)"

# Or set them by hand:
# export ROLLUP_ADDRESS=sr1...
# export BRIDGE_TICKETER=KT1...
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

(The script name still has the legacy `shadownet_` prefix — see the naming
note at the top of this file. It uses whatever network is configured in
`shadownet.env`, so once the env file points at Ushuaianet the script
exercises Ushuaianet.)

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
mkdir -p /tmp/tzel-ushuaianet-live
cd /tmp/tzel-ushuaianet-live
```

Create wallet files:

```bash
/usr/local/bin/tzel-wallet --wallet alice.wallet init
/usr/local/bin/tzel-wallet --wallet bob.wallet init
```

> **Important — DAL fee address is the operator's wallet, not yours.**
> On every shield/transfer/unshield the kernel includes a tiny note encrypted
> with `dal_fee_address`. The operator's `enforce_dal_fee_policy` then
> detects+decrypts that note with the view material configured under
> `--dal-fee-view-material`. If you point `--dal-fee-address` at your own
> receive address (the simplest-looking thing to do), the operator's
> incoming-seed/address-index will not match, the note will be rejected, and
> the operator returns `502 DAL fee note is not detectable by the configured
> operator fee address`. This trap exists post-Ushuaianet and is documented
> in `tzel-infra/docs/gcp-deploy-runbook.md` §16.
>
> For Ushuaianet, the canonical operator-fee address is checked into
> `tzel-infra/networks/ushuaianet-operator-fee-address.json`. Use that file
> directly — do not regenerate a fresh "producer" wallet locally.

Fetch the canonical operator-fee address:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/trilitech/tzel-infra/feat/ushaianet-4vm-refactor/networks/ushuaianet-operator-fee-address.json \
  -o ushuaianet-operator-fee-address.json
```

(If you originated your own rollup, generate the equivalent file from the
operator-fee wallet on the operator VM — `wallet receive --json` followed by
`export-view`, in that order from the same wallet state, per
gcp-deploy-runbook §16.)

Create wallet profiles for Ushuaianet (the CLI subcommand is still spelled
`init-shadownet` — see the naming note at the top of this file):

```bash
/usr/local/bin/tzel-wallet \
  --wallet alice.wallet \
  profile init-shadownet \
  --rollup-node-url http://127.0.0.1:28944 \
  --rollup-address "$ROLLUP_ADDRESS" \
  --bridge-ticketer "$BRIDGE_TICKETER" \
  --dal-fee 100000 \
  --dal-fee-address ushuaianet-operator-fee-address.json \
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
  --dal-fee 100000 \
  --dal-fee-address ushuaianet-operator-fee-address.json \
  --operator-url http://127.0.0.1:8787 \
  --operator-bearer-token "$OPERATOR_BEARER_TOKEN" \
  --source-alias "$SOURCE_ALIAS" \
  --public-account bob
```

Notes:

- `dal_fee_address` is the operator's PaymentAddress (full record with
  `ek_v` and `ek_d`, not just the auth fields). Each shield/transfer/unshield
  encrypts the operator's DAL fee note to this address — see the callout above.
  `--dal-fee-address` reads the file once and inlines the JSON into the saved
  profile; editing the file later does not re-read it (gcp-deploy-runbook §17).
- each `deposit` derives a fresh `pubkey_hash = H_pubkey(auth_domain, auth_root, auth_pub_seed, blind)` for a wallet-controlled auth tree, then L1-tickets the deposit amount to `deposit:<hex(pubkey_hash)>`. Multiple deposits to the same `pubkey_hash` aggregate (top-ups). The shield circuit verifies an in-circuit WOTS+ signature under the recipient's auth tree, binding the entire shield request — only the wallet that holds the auth tree's signing material can drain the pool.
- `public_account` in the profile is vestigial wallet metadata — unshield now emits an L1 outbox transfer directly to a tz/KT1 recipient supplied at unshield time.
- keep Alice and Bob distinct
- **Pool-bound shields are flexible:** the wallet picks `(v, fee, producer_fee)` at shield time, not deposit time. Pool overfunding is fine — the surplus stays available for future shields. Dust attackers depositing to a victim's `pubkey_hash` just add to the victim's pool balance (they're donating mutez they can't drain themselves).

## 6. Fund Alice On L1 And Wait For The Kernel Pool To See The Credit

Deposit into the bridge for Alice's next shield. The wallet derives a fresh `pubkey_hash` from her auth tree plus a per-deposit blind, then asks the bridge to send an L1 ticket to `deposit:<hex(pubkey_hash)>` for the chosen amount. The kernel credits the per-pool aggregated balance.

Before submitting the L1 ticket, the wallet runs preflight checks against the rollup's durable state and refuses if any disagrees:

1. The kernel verifier config (`/tzel/v1/state/verifier_config.bin`) is installed. Deposits before configuration are rejected by the kernel; the L1 ticket would burn for nothing.
2. The kernel's configured bridge ticketer (`/tzel/v1/state/bridge/ticketer`) equals `profile.bridge_ticketer`. A mismatch means the kernel won't accept tickets from this bridge contract.

(The producer-fee receiver isn't checked by the kernel at all — it's enforced by the DAL slot publisher off-chain as their inclusion policy, since the producer fee is the publisher's revenue. The wallet picks `(v, fee, producer_fee, producer_owner_tag)` at shield/transfer/unshield time, not at deposit time, so any publisher-targeting work runs then.)

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

## 10. Unshield Bob's Funds Back To L1

Pick an L1 recipient (Bob's public Ushuaianet address, or any tz/KT1 you
control) and unshield. The wallet emits an L1 outbox transfer; the rollup's
commitment period must elapse before it can be executed.

```bash
export L1_RECIPIENT=tz1REPLACE_ME

/usr/local/bin/tzel-wallet \
  --wallet bob.wallet \
  --reprove-bin /usr/local/bin/reprove \
  --executables-dir /opt/tzel/cairo/target/dev \
  unshield \
  --to "$L1_RECIPIENT" \
  --amount 30000
```

Track the submission:

```bash
/usr/local/bin/tzel-wallet \
  --wallet bob.wallet \
  status \
  --submission-id sub-REPLACE_ME
```

Once the operator reports `submitted_to_l1`, the outbox message is queued.
**On Ushuaianet the commitment period is short — wait roughly 6 to 7 minutes**
(vs. ~14 days on Shadownet) for the rollup to publish the executable
commitment, then dispatch the outbox message:

```bash
/usr/local/bin/tzel-wallet \
  --wallet bob.wallet \
  execute-outbox \
  --submission-id sub-REPLACE_ME
```

(or, equivalently, call `octez-client send smart rollup message ...
execute_outbox_message ...` — see `gcp-deploy-runbook.md` for the manual
fallback.)

Verify the L1 transfer landed:

```bash
curl -fsS "https://rpc.ushuaianet.teztnets.com/chains/main/blocks/head/context/contracts/${L1_RECIPIENT}/balance"
```

## 11. Evidence To Keep

For the first successful live run, save:

- the L1 deposit op hash
- the operator submission ids for `shield`, `send`, and `unshield`
- the operator status JSON for each
- the rollup address and bridge ticketer
- TzKT links for the L1 ops (https://ushuaianet.tzkt.io/<op_hash>)
- the L1 outbox-execution op hash
- wallet `balance` and `sync` output before and after

## 12. Failure Modes To Watch

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
- Operator returns `502 DAL fee note is not detectable by the configured operator fee address`:
  - `dal_fee_address` was pointed at the user's wallet rather than the operator-fee wallet. Re-run `profile init-shadownet` with `--dal-fee-address ushuaianet-operator-fee-address.json` (or patch `wallet.json.network.json` in place — the field is embedded JSON, see gcp-deploy-runbook §17).
- `execute-outbox` rejected as "commitment not yet finalized":
  - the Ushuaianet commitment period (~6.5 min) has not elapsed. Wait and retry.

## 13. Minimal Success Bar

We can say "Ushuaianet shielded tx is working" when all of the following are true:

- one live `deposit -> shield` succeeds
- one live `send` succeeds (Bob can independently sync and observe the received note)
- one live `unshield -> execute-outbox` round-trip lands the funds back on L1
- the flow is reproducible on the public operator box from a clean wallet directory
