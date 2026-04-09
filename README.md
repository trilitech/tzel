# StarkPrivacy

![StarkPrivacy](docs/hero.jpeg)

**Post-quantum private transactions with STARK proofs.**

> **WARNING: This project is under active development. Neither the cryptographic scheme nor the implementation should be assumed secure. Do not use for real value. The protocol design is evolving — see `specs/spec.md` for the current state.**

Privacy on blockchains today relies on elliptic curve cryptography that quantum computers will break. StarkPrivacy replaces every elliptic curve with post-quantum alternatives — BLAKE2s hashing, ML-KEM-768 lattice-based encryption, Winternitz-style one-time spend authorization verified inside the STARK, and recursive STARK proofs — with current reference proofs around 300 KB and verification around 35 ms.

### Features

- **Post-quantum end-to-end.** No elliptic curves anywhere. BLAKE2s for commitments and nullifiers, ML-KEM-768 for encrypted memos, Winternitz-style one-time signatures for spend authorization (verified inside the STARK), and recursive STARKs for proofs.
- **~300 KB recursive zero-knowledge proofs.** Two-level recursive STARKs (Cairo AIR -> Stwo circuit reprover) with ZK blinding.
- **Delegated proving with spend-bound authorization.** Outsource proof generation to an untrusted server. Each spend uses a fresh one-time hash-signature key from a Merkle tree, and the signature is verified inside the STARK, so the prover cannot redirect funds by changing outputs. On the current reference stack, proof generation is measured in tens of seconds rather than milliseconds.
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
# Build everything
cd rust/cli && cargo build --release
cd ../reprover && cargo build --release
cd .. && scarb build

# Run the ledger with proof verification (verified mode)
# If you launch it from elsewhere, also pass --executables-dir /abs/path/to/target/dev
cli/target/release/sp-ledger --port 8080 --reprove-bin reprover/target/release/reprove &

# Run the wallet
cli/target/release/sp-client keygen
cli/target/release/sp-client fund -l http://localhost:8080 --addr alice --amount 1000
cli/target/release/sp-client shield -l http://localhost:8080 --sender alice --amount 1000
cli/target/release/sp-client scan -l http://localhost:8080
cli/target/release/sp-client balance

# Run the STARK proofs (requires ~13 GB RAM)
./bench.sh
cd ..
```

> **WARNING:** The ledger now refuses to start unless you pass either `--reprove-bin` (verified STARK proofs) or `--trust-me-bro` (development only, no cryptographic verification). In verified mode it also authenticates the expected `run_shield` / `run_transfer` / `run_unshield` executable hashes from `--executables-dir` (default `target/dev`). `--trust-me-bro` is never appropriate for real value.
>
> **REFERENCE IMPLEMENTATION NOTE:** `sp-ledger` is a localhost demo / reference implementation of the proof, nullifier, root, commitment, and memo-hash checks. Its public-balance layer intentionally uses submitted strings such as `"alice"` as stand-ins for chain-native caller identity. It is not a network-authenticated wallet service and should not be exposed as a real public endpoint.

For local testing and fast integration loops, `--trust-me-bro` is still useful: `sp-client` skips STARK proving and `sp-ledger` accepts unverified bundles so you can exercise the state-transition checks quickly. Keep that mode on localhost only and switch back to `--reprove-bin` for any path where proof verification actually matters.

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
docs/                   Site assets
specs/                  Protocol spec and shared test vectors
  spec.md               Protocol specification
  test_vectors/         Canonical wire/reference vectors
  ocaml_vectors/        Cross-implementation vector docs and fixtures
rust/                   Rust/Cairo reference implementation
  src/                  Cairo circuits
  reprover/             Two-level recursive STARK prover
  cli/                  CLI client + HTTP ledger
  bench.sh              Benchmark script
ocaml/                  Independent OCaml implementation
```

## Running benchmarks

```bash
cd rust && ./bench.sh                # Recursive proofs (currently ~300 KB)
cd rust && ./bench.sh --depth 16
```

## Known limitations

See `specs/spec.md` for a complete list. Key items:

- **Active development** -- protocol and implementation are not audited for production use
- **Reference ledger is localhost-only** -- `sp-ledger` is a demo/reference verifier for the protocol checks, not a real authenticated public-balance server
- **WOTS+ key reuse compromises funds** -- unlike multi-use signature schemes, reusing a WOTS+ key lets an attacker forge signatures and steal funds
- **One-time key exhaustion** -- each address has 1024 signing keys; rotate addresses before exhaustion
- **N is not private** -- nullifier count reveals input count
- **Detection is honest-sender** -- malicious sender can bypass detection

## License

Copyright (c) 2026 Arthur Breitman. All rights reserved.
