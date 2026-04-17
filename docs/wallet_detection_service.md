# Wallet Detection And Viewing Service

This repo supports a delegated watch-only flow built on top of `tzel-wallet`
and a small HTTP detection service in `tzel-detect`.

The intended separation is:

- the spending wallet keeps `master_sk`, XMSS state, and spend authority
- exported watch material feeds a separate watch wallet file
- `tzel-detect` owns only that watch wallet file and exposes sanitized status

## Modes

- `detect`
  - export only the detection root
  - can scan for candidate note matches by address index
  - cannot decrypt memo/value
  - cannot mark notes spent
  - can produce false positives by design

- `view`
  - export `incoming_seed` plus public address metadata
  - can decrypt and validate incoming notes
  - cannot spend
  - cannot mark notes spent because it does not have spend authority

## Export

From the spending wallet:

```bash
tzel-wallet --wallet alice.json export-detect --out alice.detect.json
tzel-wallet --wallet alice.json export-view --out alice.view.json
```

## Create A Watch Wallet

Create a watch-only state file from exported material:

```bash
tzel-wallet --wallet alice.watch.json watch init --material alice.view.json
```

Save a network profile against that watch wallet:

```bash
tzel-wallet --wallet alice.watch.json profile init-shadownet \
  --rollup-node-url http://127.0.0.1:28946 \
  --rollup-address sr1... \
  --bridge-ticketer KT1... \
  --source-alias alice \
  --public-account alice
```

## Sync Manually

```bash
tzel-wallet --wallet alice.watch.json watch sync
tzel-wallet --wallet alice.watch.json watch show
```

`watch show` returns sanitized state only. It does not print the embedded
viewing or detection material.

## Run The Detection Service

```bash
tzel-detect --wallet alice.watch.json --bind 127.0.0.1:8789 --interval-secs 5
```

Endpoints:

- `GET /healthz`
- `GET /v1/status`
- `POST /v1/sync`

`/v1/status` returns sanitized watch state:

- `detect` mode returns candidate matches
- `view` mode returns validated incoming notes and aggregate incoming total

## Installed Deployment

The shared installer places `tzel-detect` alongside the other deployable
TzEL binaries:

```bash
./scripts/install_tzel_binaries.sh --build-only
sudo ./scripts/install_tzel_binaries.sh --skip-build --prefix /usr/local --executables-dir /opt/tzel/cairo/target/dev
```

On the public Shadownet operator box, the optional systemd unit is:

- `ops/shadownet/systemd/tzel-detect.service`

That unit expects:

- `TZEL_DETECT_ENABLE=1`
- `TZEL_DETECT_BIN=/usr/local/bin/tzel-detect`
- `TZEL_DETECT_WALLET=/var/lib/tzel/watch/alice.watch.json`
- `TZEL_DETECT_LISTEN=127.0.0.1:8789`
- `TZEL_DETECT_INTERVAL_SECS=15`

See also:

- `ops/shadownet/README.md`
- `scripts/shadownet_operator_preflight.sh`

## Operational Notes

- detection-only mode is intentionally lossy and can emit candidate false positives
- viewing mode validates recovered note commitments using exported address metadata
- neither mode can infer spent status without the spend key
- the HTTP service intentionally returns status only; the watch wallet file
  remains the only place where viewing or detection material is stored
