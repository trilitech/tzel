# StarkPrivacy

![StarkPrivacy](hero.jpeg)

**Post-quantum private transactions with STARK proofs.**

> **WARNING: This project is under active development. Neither the cryptographic scheme nor the implementation should be assumed secure. Do not use for real value. The protocol design is evolving — see spec.md for the current state.**

Privacy on blockchains today relies on elliptic curve cryptography that quantum computers will break. StarkPrivacy replaces every elliptic curve with post-quantum alternatives — BLAKE2s hashing, ML-KEM-768 lattice-based encryption, WOTS+ (w=4) spend authorization verified inside the STARK, and STARKs — while keeping proofs small (~295 KB) and verification instant (~35 ms).

### Features

- **Post-quantum end-to-end.** No elliptic curves anywhere. BLAKE2s for commitments and nullifiers, ML-KEM-768 for encrypted memos, WOTS+ (w=4) for spend authorization (verified inside the STARK), STARKs for proofs.
- **~295 KB zero-knowledge proofs.** Two-level recursive STARKs (Cairo AIR -> Stwo circuit reprover) with ZK blinding.
- **Delegated proving with unlinkable authorization.** Outsource the expensive proof generation (~35s) to an untrusted server. Each spend uses a fresh one-time WOTS+ key from a Merkle tree, with the signature verified inside the STARK — the prover can't redirect funds (signature is bound to specific outputs), and nothing on-chain can be linked back to the spender's address.
- **Fuzzy message detection.** ML-KEM-based detection keys let a lightweight indexer flag likely-incoming transactions without being able to read them.
- **Diversified addresses.** Generate unlimited unlinkable addresses from a single master key.
- **1 KB encrypted memos.** End-to-end encrypted with ML-KEM-768 + ChaCha20-Poly1305.
- **Flexible N->2 transfers.** Consolidate up to 16 notes in a single proof. No dummy notes needed.

### How it works

A UTXO-based private transaction system where:
- **Deposits** (shield) move public tokens into private notes
- **Transfers** spend 1-16 private notes and create 2 new ones
- **Withdrawals** (unshield) destroy private notes and release value publicly
- Every spend is proven with a **zero-knowledge STARK** that verifies the **WOTS+ signature inside the circuit** — the proof itself proves spend authorization

## Quick start

```bash
# Run the CLI (ledger + wallet)
cd cli && cargo build --release
./target/release/sp-ledger --port 8080 &
./target/release/sp-client keygen
./target/release/sp-client fund -l http://localhost:8080 --addr alice --amount 1000
./target/release/sp-client shield -l http://localhost:8080 --sender alice --amount 1000
./target/release/sp-client scan -l http://localhost:8080
./target/release/sp-client balance

# Run the STARK proofs (requires ~13 GB RAM)
scarb build
./bench.sh
```

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
|                     | ZK proof (~295 KB)              | |
|                     | (WOTS+ sig verified in-circuit) | |
|                     +------+--------------------------+ |
|                            |                            |
|                      proof | (public outputs: root,     |
|                            |  nullifiers, commitments,  |
|                            |  memo hashes only)         |
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
|  * Credit / debit public balances                       |
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
|           +-- auth_root_j -- Merkle root of 1024 one-time WOTS+ keys
|
+-- incoming_seed
    +-- dsk
        +-- d_j         -- per-address diversifier
```

- **nk_spend** given to the prover (can generate proof but not sign)
- **ask** never leaves the wallet (derives one-time WOTS+ signing keys)
- **auth_root** bound into the commitment, stays private on-chain
- **d_j** identifies which address a note was sent to

## Note structure

```
owner_tag = H(auth_root, nk_tag)
cm = H_commit(d_j, v, rcm, owner_tag)   -- commitment (in Merkle tree)
nf = H_nf(nk_spend, H_nf(cm, pos))      -- nullifier (prevents double-spend)
```

## Project structure

```
src/                    Cairo circuits (constraint verification only)
  blake_hash.cairo      BLAKE2s with 10 personalized IVs
  merkle.cairo          Merkle tree + auth tree verification
  shield.cairo          Shield circuit (0->1)
  transfer.cairo        Transfer circuit (N->2) with WOTS+ verification
  unshield.cairo        Unshield circuit (N->change+withdrawal) with WOTS+
  run_shield.cairo      Parameterized shield entry point
  run_transfer.cairo    Parameterized transfer entry point
  run_unshield.cairo    Parameterized unshield entry point

reprover/               Two-level recursive STARK prover (Rust)

cli/                    CLI client + HTTP ledger
  src/bin/sp_ledger.rs  HTTP ledger server
  src/bin/sp_client.rs  CLI wallet
  src/lib.rs            Shared crypto

spec.md                 Protocol specification
bench.sh                Benchmark script
```

## Running benchmarks

```bash
./bench.sh                # Recursive proofs (ZK, ~295 KB)
./bench.sh --depth 16     # Faster testing with smaller Merkle tree
```

## Known limitations

See spec.md for a complete list. Key items:

- **Active development** -- protocol and implementation are not audited for production use
- **WOTS+ key reuse compromises funds** -- unlike multi-use signature schemes, reusing a WOTS+ key lets an attacker forge signatures and steal funds
- **One-time key exhaustion** -- each address has 1024 signing keys; rotate addresses before exhaustion
- **N is not private** -- nullifier count reveals input count
- **Detection is honest-sender** -- malicious sender can bypass detection

## License

Copyright (c) 2026 Arthur Breitman. All rights reserved.
