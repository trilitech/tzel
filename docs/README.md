# Documentation Map

This directory is the entry point for the project documentation.

## Start Here

- [../README.md](../README.md)
  - project overview, local quick start, workspace layout
  - also explains the split between the local developer wallet stack
    (`sp-client` + `sp-ledger`) and the rollup wallet stack (`tzel-wallet`)
- [../specs/spec.md](../specs/spec.md)
  - protocol definition
- [../specs/security.md](../specs/security.md)
  - security notes and known limitations
- [whitepaper.tex](./whitepaper.tex)
  - lite whitepaper for readers who want the motivation, architecture, and
    security model without the full normative encoding spec

## Tutorials And Guides

- [ushuaianet_tutorial.md](./ushuaianet_tutorial.md)
  - step-by-step `tzel-wallet` tutorial for the Ushuaianet
    `deposit -> shield -> send -> unshield` flow, with the current burned
    `100000` mutez rollup fee plus a private DAL-producer fee note
- [wallet_detection_service.md](./wallet_detection_service.md)
  - watch-only `tzel-wallet` flow and `tzel-detect`

## Wallets

- `sp-client`
  - local developer/test wallet that talks to `sp-ledger`
- `tzel-wallet`
  - rollup-backed wallet that talks to the rollup node, optional operator, and
    L1 tooling
- `tzel-detect`
  - watch-only service built on the same rollup-backed wallet model

## Deployment Docs

- [../ops/shadownet/README.md](../ops/shadownet/README.md)
  - public operator box setup
- [../ops/prover/README.md](../ops/prover/README.md)
  - prover deployment layout

## Component Docs

- [../tezos/rollup-kernel/README.md](../tezos/rollup-kernel/README.md)
  - rollup kernel build, storage layout, and local sandbox smokes

## Website Assets

- [index.html](./index.html)
  - landing page
- [pq.png](./pq.png)
  - landing page image asset

## Suggested Reading Order

1. [../README.md](../README.md)
2. [../specs/spec.md](../specs/spec.md)
3. [ushuaianet_tutorial.md](./ushuaianet_tutorial.md)
4. [../ops/shadownet/README.md](../ops/shadownet/README.md)
5. [wallet_detection_service.md](./wallet_detection_service.md)
