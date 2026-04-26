# TzEL

<img src="docs/pq.png" alt="TzEL" width="50%">

**Post-quantum private transactions with STARK proofs.**

> **WARNING: This project is under active development. Neither the cryptographic scheme nor the implementation should be assumed secure. Do not use for real value. See `specs/spec.md` for the protocol definition used by the code in this repository.**

Privacy on blockchains today relies on elliptic curve cryptography that quantum computers will break. TzEL replaces every elliptic curve with post-quantum alternatives — BLAKE2s hashing, ML-KEM-768 lattice-based encryption, Winternitz-style one-time spend authorization verified inside the STARK, and recursive STARK proofs — with reference proofs around 300 KB and verification around 32--34 ms on an AWS `c8g.16xlarge`.

### Features

- **Post-quantum end-to-end.** No elliptic curves anywhere. BLAKE2s for commitments and nullifiers, ML-KEM-768 for encrypted memos, Winternitz-style one-time signatures for spend authorization (verified inside the STARK), and recursive STARKs for proofs.
- **~300 KB recursive zero-knowledge proofs.** Two-level recursive STARKs (Cairo AIR -> Stwo circuit reprover) with ZK blinding.
- **Delegated proving with spend-bound authorization.** Outsource proof generation to an untrusted server. Each spend uses a fresh one-time hash-signature key from a Merkle tree, and the signature is verified inside the STARK, so the prover cannot redirect funds by changing outputs. On an AWS `c8g.16xlarge`, the depth-48 recursive prover measured `4.856s` for shield, `5.235s` for transfer `N=2`, `7.746s` for transfer `N=7`, `5.259s` for unshield `N=2`, and `7.632s` for unshield `N=7`.
- **Fuzzy message detection.** ML-KEM-based detection keys let a lightweight indexer flag likely-incoming transactions without being able to read them.
- **Diversified addresses.** Generate unlimited unlinkable addresses from a single master key.
- **1 KB encrypted memos.** End-to-end encrypted with ML-KEM-768 + ChaCha20-Poly1305.
- **Flexible N->3 transfers.** Spend up to 7 notes in a single proof and produce recipient, change, and DAL-producer fee notes without dummy notes.

### How it works

A UTXO-based private transaction system where:
- **Deposits** credit a namespaced *intent-bound* rollup deposit key whose hash commits to the entire shield (recipient note, producer-fee note, fees, auth_domain). `shield` opens the preimage and consumes the deposit. Because every prover-rewritable field is folded into the deposit_id, shield is **safe to delegate to an untrusted prover** — no in-circuit signature is required.
- **Transfers** spend 1-7 private notes and create recipient, change, and DAL-producer fee notes
- **Withdrawals** (unshield) destroy private notes, emit an L1 outbox transfer to a tz/KT1 recipient, and create a DAL-producer fee note plus optional change
- **Every shield / transfer / unshield burns at least 100000 mutez (0.1 tez)**, with a simple per-level stepped fee under congestion in the current rollup deployment
- **Every shield / transfer / unshield also creates a separate private DAL-producer fee note**
- Every spend is proven with a **zero-knowledge STARK** that verifies the **WOTS+ signature inside the circuit** — the proof itself proves spend authorization

## Quick start

```bash
# Build everything
cargo build --release -p tzel-wallet-app -p tzel-ledger-app
cd apps/prover && cargo build --release && cd ../..
cd cairo && scarb build && cd ..

# Run the ledger with proof verification (verified mode)
# If you launch it from elsewhere, also pass --executables-dir /abs/path/to/cairo/target/dev
target/release/sp-ledger --port 8080 --reprove-bin apps/prover/target/release/reprove &

# Run the developer/test wallet harness. The `shield` command builds the
# recipient + producer-fee notes, computes the intent-bound deposit_id, calls
# the local ledger's `/deposit` endpoint to allocate a slot for the exact
# debit, then proves and submits with that slot id.
target/release/sp-client -w alice.json keygen
target/release/sp-client -w producer.json keygen
target/release/sp-client -w producer.json address | sed -n '2,$p' > producer-address.json
target/release/sp-client -w alice.json shield -l http://localhost:8080 --sender alice --amount 200001 --dal-fee 1 --dal-fee-address producer-address.json
target/release/sp-client -w alice.json scan -l http://localhost:8080
target/release/sp-client -w alice.json balance

# Run the STARK proofs (requires ~13 GB RAM)
./apps/prover/bench.sh
```

For deployment-oriented installs with standard paths instead of a workspace checkout:

- docs map: `docs/README.md`
- operator box: `ops/shadownet/README.md`
- prover layout: `ops/prover/README.md`
- watch-only detection service: `docs/wallet_detection_service.md`
- shared binary installer: `./scripts/install_tzel_binaries.sh --prefix /usr/local --executables-dir /opt/tzel/cairo/target/dev`
- live public-box smoke: `TZEL_SMOKE_L1_RECIPIENT=tz1... ./scripts/shadownet_live_e2e_smoke.sh /etc/tzel/shadownet.env`

> **WARNING:** The ledger refuses to start unless you pass either `--reprove-bin` (verified STARK proofs) or `--trust-me-bro` (development only, no cryptographic verification). In verified mode it also authenticates the expected `run_shield` / `run_transfer` / `run_unshield` executable hashes from `--executables-dir` (default `cairo/target/dev`). `--trust-me-bro` is never appropriate for real value.
>
> **REFERENCE IMPLEMENTATION NOTE:** `sp-ledger` is a localhost demo / reference implementation of the proof, nullifier, root, commitment, intent-binding, slot allocation, and memo-hash checks. For local shield testing, `sp-client shield` builds both the recipient and producer-fee notes client-side, computes the shield intent over them, and POSTs `/deposit` to allocate a slot for the exact `(intent, debit)` before submitting `/shield`. `/deposit` is demo-only and unauthenticated; it should not be exposed as a real public endpoint.
>
> **DEVELOPER WALLET NOTE:** `sp-client` is a developer/reference CLI used for local testing, demos, and integration flows. It persists plaintext secrets and wallet state in local JSON files and is not intended to be a hardened end-user wallet.

For local testing and fast integration loops, `--trust-me-bro` is useful: `sp-client` skips STARK proving and `sp-ledger` accepts unverified bundles so you can exercise the state-transition checks quickly. Keep that mode on localhost only and switch back to `--reprove-bin` for any path where proof verification actually matters.

## Architecture

```
+---------------------------------------------------------+
| User Wallet                                             |
|                                                         |
| master_sk --> Key Derivation --> Build Transaction      |
|              + WOTS+ sign sighash      |                |
|                     +------------------+--------------+ |
|                     | Delegated Prover (untrusted)    | |
| witness data:       |                                 | |
| nk_spend, d_j, --> | Cairo AIR proof                 | |
| v, rseed, paths,    |      |                          | |
| wots_sig            | Stwo circuit reprover           | |
|                     |      |                          | |
|                     | ZK proof (~300 KB)             | |
|                     | (WOTS+ sig verified in-circuit) | |
|                     +------+--------------------------+ |
|                            |                            |
|                      proof | (public outputs: auth      |
|                            |  domain/root, nullifiers,  |
|                            |  fees, commitments, memo   |
|                            |  hashes, recipient hashes) |
|                            v                            |
+-----------------------+---+-----------------------------+
                        | proof + note_data
                        v
+---------------------------------------------------------+
| On-chain Contract                                       |
|                                                         |
|  * Verify STARK proof (spend auth already proven)       |
|  * Check nullifiers not in global NF_set                |
|  * Check root in historical anchor set                  |
|  * Append new commitments to Merkle tree T              |
|  * Allocate per-deposit slots for L1 bridge tickets     |
|  * Queue / emit L1 withdrawals                          |
+---------------------------------------------------------+
```

## Key hierarchy

```
master_sk
+-- spend_seed
|   +-- nk              -- account nullifier root
|   |   +-- nk_spend_j  -- per-address nullifier key (given to prover)
|   |       +-- nk_tag_j -- public binding tag (in payment address)
|   +-- ask_base
|       +-- ask_j       -- per-address auth secret (never leaves wallet)
|           +-- auth_pub_seed_j
|           +-- auth_root_j -- Merkle root of 65536 one-time WOTS+ keys
|
+-- incoming_seed
|   +-- dsk
|   |   +-- d_j         -- per-address diversifier
|   +-- view_root
|   |   +-- seed_v_j    -- per-address ML-KEM viewing key seed
|   +-- detect_root
|       +-- seed_d_j    -- per-address ML-KEM detection key seed
|
+-- outgoing_seed       -- sender-side recovery key for created outputs
```

- **nk_spend** given to the prover (can generate proof but not sign)
- **ask** never leaves the wallet (derives one-time WOTS+ signing keys)
- **auth_root** and **auth_pub_seed** are bound into the commitment, stay private on-chain
- **d_j** identifies which address a note was sent to
- **outgoing_seed** decrypts sender-recovery ciphertexts only for outputs this wallet created

## Note structure

```
owner_tag = H_owner(auth_root, auth_pub_seed, nk_tag)
cm = H_commit(d_j, v, rcm, owner_tag)   -- commitment (in Merkle tree)
nf = H_nf(nk_spend, H_nf(cm, pos))      -- nullifier (prevents double-spend)
```

## Project structure

```
docs/                   Site assets
specs/                  Protocol spec and shared test vectors
apps/                   Thin shells (wallet, ledger, prover, demo)
tezos/                  Tezos-specific integration targets
  rollup-kernel/        Tezos smart-rollup kernel scaffold
core/                   Shared deterministic Rust protocol/state layer
verifier/               Shared Rust proof-verification bridge
services/               Rust libraries used by the shells and tests
  reprover/             STARK reproving binary/library
  tzel/                 Shell-facing Rust service crate
cairo/                  Cairo circuits and executable build
ocaml/                  Independent OCaml implementation
  protocol/             Pure protocol modules
  services/             Ledger/prover service modules
```

## Running benchmarks

```bash
./apps/prover/bench.sh
./apps/prover/bench.sh --depth 16
```

Latest reference numbers for the depth-48 recursive prover on an AWS `c8g.16xlarge`:

| Proof | Total prove time | Verify time | Peak RSS | Proof size |
| --- | ---: | ---: | ---: | ---: |
| Shield | `4.856s` | `32ms` | `13.19 GiB` | `297.6 KiB` |
| Transfer `N=2` | `5.235s` | `32ms` | `16.66 GiB` | `289.5 KiB` |
| Transfer `N=7` | `7.746s` | `32ms` | `24.96 GiB` | `289.2 KiB` |
| Unshield `N=2` | `5.259s` | `32ms` | `16.59 GiB` | `289.4 KiB` |
| Unshield `N=7` | `7.632s` | `34ms` | `24.76 GiB` | `301.3 KiB` |

## Rollup kernel MVP

The shared deterministic Rust layer is in `core/`.
Both the HTTP ledger path and the rollup-kernel MVP are meant to call that same
logic rather than fork state-transition code.

The Tezos smart-rollup kernel scaffold lives in
`tezos/rollup-kernel/`.

It:
- reads raw inbox messages from the WASM host
- persists basic durable state for inbox stats and the last message seen
- decodes Tezos Data Encoding inbox messages into shared TzEL request types
- treats `transfer` as the only fully internal rollup transaction, with bridge-`deposit` + `shield` handling rollup ingress and `unshield` (which directly emits an L1-outbox transfer to the requested tz/KT1 recipient) handling egress
- applies the shared transition logic from `tzel-core`
- persists path-addressed durable state for notes, per-deposit slots, roots, nullifiers, withdrawal queue, bridge ticketer, verifier config, and the commitment-tree frontier
- verifies proofs through the shared verifier path without linking prover code

Build it with:

```bash
./scripts/build_rollup_kernel_release.sh
```

## Known limitations

See `specs/security.md` for the full security notes and operational caveats. Key items:

- **Active development** -- protocol and implementation are not audited for production use
- **Reference ledger is localhost-only** -- `sp-ledger` is a demo/reference verifier for the protocol checks, not a real authenticated server
- **`sp-client` is a developer/test harness** -- it is useful for local testing and fixtures, not as a hardened end-user wallet
- **WOTS+ key reuse compromises funds** -- unlike multi-use signature schemes, reusing a WOTS+ key lets an attacker forge signatures and steal funds
- **One-time key exhaustion** -- each address has 65536 signing keys; rotate addresses before exhaustion
- **N is not private** -- nullifier count reveals input count
- **Detection is honest-sender** -- malicious sender can bypass detection

## License

Copyright (c) 2026 Arthur Breitman. All rights reserved.
