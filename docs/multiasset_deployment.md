# FA2 bridge deployment runbook

Adding a new FA2 token to the multiasset shielded pool. The L2 stack
(circuits, kernel, wallet) is asset-agnostic by construction; the
only governance-bound step is putting the new ticketer's KT1 address
into the kernel binary's compile-time registry.

This file walks the full chain from "we want to bridge token X" to
"users can shield/transfer/unshield X privately on the rollup."

## 0. Prerequisites

- `octez-client` static binary on `PATH` (download from
  [gitlab.com/tezos/tezos releases](https://gitlab.com/tezos/tezos/-/releases)
  → static binaries → `x86_64-octez-client`).
- A funded octez-client account on the target network (origination
  burns a few tez).
- The KT1 address of the FA2 contract you're bridging, and the
  `token_id` (nat) of the specific token in that contract.

## 1. Originate the ticketer

```sh
scripts/originate_fa2_bridge.sh \
    <fa2_contract_kt1>   \
    <token_id>           \
    <funding_alias>      \
    <network_name>       \
    <protocol_hash>
```

The script:

1. Typechecks `tezos/fa2_bridge_ticketer.tz` under the target
   protocol's mockup — sanity check before paying any fees.
2. Calls `octez-client originate contract` with storage
   `(Pair "<fa2_contract>" <token_id>)`.
3. Extracts the resulting `KT1...` from the origination receipt.
4. Prints the kernel registry entry to copy into
   `core/src/lib.rs`, plus the asset_id the kernel will derive
   (`hash("tzel:asset:" || KT1)`) so you can sanity-check it
   against what the wallet computes.

Note the derivation is structural: any rebuild of the kernel that
includes the same `KT1` in `COMPILE_TIME_FA2_BRIDGES` will derive the
same `asset_id`. There is no on-chain registry.

## 2. Register the KT1 in the kernel binary

Open `core/src/lib.rs`, find `COMPILE_TIME_FA2_BRIDGES`, and add the
new KT1 address as a string literal:

```rust
pub const COMPILE_TIME_FA2_BRIDGES: &[&str] = &[
    "KT1HbQepzV1nVGg8QVznG7z4RcHseD5kwqBn", // USDT-FA2
    "KT1...your-new-ticketer...",            // <- add this
];
```

The order doesn't matter — asset_id derivation is purely structural.
What matters is that **the running kernel binary contains the new
entry**. Until you redeploy the kernel, the existing kernel will
reject every deposit from the new ticketer with
`"unexpected ticketer"`.

## 3. Build + redeploy the kernel

This is a normal kernel upgrade — same governance surface as any
other circuit/protocol change. Follow your existing kernel-upgrade
procedure for the target network. The relevant commands are in
`scripts/build_rollup_kernel_release.sh`.

The kernel upgrade does NOT touch the rollup's durable storage; the
existing tez deposit pools, withdrawal queue, and commitment tree
all carry over unchanged. Only `compose_asset_registry`'s output
changes: it gains an entry for the new ticketer.

## 4. Smoke test

After the upgraded kernel is installed, run a round-trip with a
small amount on testnet:

```sh
# 4a. As the L1 token holder: authorise the ticketer to pull tokens
octez-client transfer 0 from <holder> to <fa2_contract_kt1> \
    --entrypoint update_operators                            \
    --arg '{ Left (Pair "<holder>" (Pair "<ticketer_kt1>" <token_id>)) }' \
    --burn-cap 5

# 4b. As the L2 wallet: prepare the deposit
tzel-wallet deposit --amount 1000 \
    --asset $(cargo run --quiet -p tzel-services --bin derive_asset_id_cli -- <ticketer_kt1>) \
    --prepare-only --json > deposit.json

# 4c. Sign+broadcast the deposit op from the L1 signer
#     (Temple / Beacon / Ledger), using the Michelson `params` field
#     of deposit.json against the ticketer's %mint entrypoint.

# 4d. Wait for kernel ingestion, then shield + send + unshield
tzel-wallet sync
tzel-wallet shield --pubkey-hash <pkh> --amount 1000 \
    --asset $(...)
tzel-wallet send --to <addr> --amount 500 \
    --asset $(...)
tzel-wallet unshield --amount 500 --recipient <l1-addr> \
    --asset $(...)
```

If step 4d's `unshield` outbox burn lands on the FA2 ticketer's
`%burn` entrypoint on L1 and the FA2 contract releases `500` tokens
to `<l1-addr>`, the bridge is working end-to-end.

## 5. Removing an asset (rare)

To un-register a ticketer:

1. Remove its KT1 string from `COMPILE_TIME_FA2_BRIDGES`.
2. Rebuild + redeploy the kernel.

After redeployment:

- New deposits from that ticketer will be rejected with
  `"unexpected ticketer"` (the old token's holders cannot move
  funds onto the rollup any more).
- **Existing shielded notes carrying the de-registered asset's
  asset_id remain spendable inside the L2** — the per-asset balance
  constraint is a private-circuit invariant, unaffected by registry
  membership. The 2-accumulator constraint accepts any asset_id the
  wallet supplies as `primary_non_tez_asset`.
- **Unshield to L1 for the de-registered asset will fail** — the
  outbox dispatcher's `ticketer_for_asset` lookup returns `None`
  and the kernel rejects the unshield before any state mutation.
  Holders of de-registered assets are stranded on the L2 unless the
  asset is re-registered at the same KT1.

This asymmetry is deliberate: removing a ticketer disables incoming
+ outgoing L1 flow but doesn't seize already-shielded balances.

## 6. Sanity checklist before going live

- `cargo test --workspace` passes — 469+ tests, 0 failed
- `cargo test -p tzel-rollup-kernel --test fa2_bridge_michelson` —
  including `fa2_bridge_typechecks_under_octez_client` which runs
  the real octez-client typechecker on the contract
- `cargo test -p tzel-rollup-kernel --test multiasset_routing` —
  25 kernel-side per-asset routing tests
- `cargo test -p tzel-rollup-kernel --lib end_to_end_fa2` — the
  end-to-end FA2 kernel flow test using a synthetic ticketer via
  the `test-fa2-bridges` override
- Testnet smoke test (step 4 above) on a real Tezos testnet

## Why not on-chain registration?

`COMPILE_TIME_FA2_BRIDGES` is a kernel-binary constant rather than a
durable-store entry that's mutable at runtime. This choice is
deliberate:

- **Same governance surface as any other circuit change.** Adding
  an asset goes through the same kernel-upgrade signoff as adding a
  new instruction to the Cairo circuit. No "registrar" privileged
  inbox message.
- **No DoS vector on registration.** A live runtime registration
  endpoint would have to accept signed messages from a privileged
  key; that key becomes a target. Compile-time registration moves
  the trust to whoever signs kernel upgrades, which is the existing
  trust assumption.
- **No deposit-during-rotation race.** If the asset_id derivation
  changed (e.g. someone rotated the ticketer address), an in-flight
  deposit could land in the old pool and become unrecoverable.
  Compile-time pinning prevents this; users always know which KT1
  the running kernel expects.
