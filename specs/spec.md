# TzEL v2: Post-Quantum Private Transaction Spec

**WARNING: This protocol is under active development. Neither the design nor the implementation should be assumed secure. Do not use for real value.**

This document is the normative protocol and encoding specification. Security and operational commentary is collected in `specs/security.md`. Design rationale is collected in `specs/rationale.md`.

## Overview

A UTXO-based private transaction system with:

- **Merkle commitment tree** for note storage
- **Nullifiers** for double-spend prevention
- **Two-level recursive STARKs** (Cairo AIR + Stwo circuit reprover) with ZK blinding
- **Post-quantum cryptography**: BLAKE2s hashing, ML-KEM-768 for memos/detection, WOTS+ (w=4) for spend authorization verified inside the STARK, STARKs for proofs. No elliptic curves.
- **Delegated proving**: untrusted provers generate the STARK proof; the WOTS+ signature is included in the witness and verified inside the STARK, so the proof itself proves spend authorization
- **Unlinkable spend authorization**: each spend uses a fresh one-time WOTS+ key from a Merkle tree of WOTS+ public keys. The tree root stays private inside the STARK, so on-chain outputs cannot be linked back to the spender's address.
- **Penumbra-inspired key hierarchy**: spending and address material in separate branches
- **Per-address nullifier binding**: nullifier keys are bound into commitments via owner tags

---

## Key Hierarchy

Notation: quoted labels such as `"spend"`, `"view"`, or `"xmss-sk"` denote **fixed felt252 domain-tag constants**, not UTF-8 strings that are themselves hashed first. The exact encoding of these tag constants is defined below in [Domain Tag Constants](#domain-tag-constants). In particular:

- `H("spend", x)` means `H(TAG_SPEND, x)`
- `H("view", x)` means `H(TAG_VIEW, x)`
- `H("rcm")` means `H(TAG_RCM)`

```text
master_sk
├── spend_seed = H(TAG_SPEND, master_sk)
│   ├── nk         = H(TAG_NK,  spend_seed)        — account nullifier root (never leaves user)
│   │   └── nk_spend_j = H_nksp(nk, d_j)         — per-address secret nullifier key
│   │       └── nk_tag_j  = H_nktg(nk_spend_j)   — per-address public binding tag
│   ├── ask_base   = H(TAG_ASK, spend_seed)         — base authorization secret
│   │   └── ask_j  = H(ask_base, j)               — per-address auth secret
│   │       └── sk_root_i = H(TAG_XMSS_SK, ask_j, i_felt) — per-key WOTS+ secret root
│   │           └── pk_i = WOTS+.KeyGen(sk_root_i) — 133 chain endpoints (w=4)
│   │       └── (auth_root_j, pub_seed_j) = XMSS-style address auth public key
│
├── incoming_seed = H(TAG_INCOMING, master_sk)
│   ├── dsk         = H(TAG_DSK, incoming_seed)     — diversifier derivation key
│   │   └── d_j     = H(dsk, j)                   — diversified address index
│   ├── view_root   = H(TAG_VIEW, incoming_seed)    — root for per-address ML-KEM viewing keys
│   │   └── seed_v_j = KDF_view(view_root, j)     — exact KDF defined below
│   │       └── (ek_v_j, dk_v_j) = ML-KEM-768.KeyGenDet(seed_v_j)
│   └── detect_root = H(TAG_DETECT, view_root)      — root for per-address detection keys
│       └── seed_d_j = KDF_detect(detect_root, j) — exact KDF defined below
│           └── (ek_d_j, dk_d_j) = ML-KEM-768.KeyGenDet(seed_d_j)
│
└── outgoing_seed = H(TAG_OUTGOING, master_sk)       — sender-side recovery key for created outputs
```

**Spending branch** holds nullifier material (`nk`) and authorization (`ask`). **Incoming branch** holds address diversification and incoming memo keys. **Outgoing branch** lets the sender recover the notes it created without learning anything about other incoming notes. These branches are independent — address material reveals nothing about spending keys, and outgoing viewing material is not part of payment addresses.

Outgoing viewing is sender-side only: each output note carries an `outgoing_ct` encrypted to the creator's `outgoing_seed`. This ciphertext recovers enough note metadata for sender accounting and audit of sent outputs, but it does not give incoming viewing capability or spending authority.

Exact deterministic ML-KEM derivation for interoperability:

1. Encode address index `j` as `j_felt`: a 32-byte little-endian felt with the low 4 bytes set to `u32_le(j)` and the remaining 28 bytes zero.
2. `view_root = H(TAG_VIEW, incoming_seed)`
3. `view_h1 = H(TAG_MLKEM_V, view_root)`
4. `view_h2 = H(view_h1, j_felt)`
5. `seed_v_j = view_h2 || H(TAG_MLKEM_V2, view_h2)` (64 bytes total)
6. `detect_root = H(TAG_DETECT, view_root)`
7. `detect_h1 = H(TAG_MLKEM_D, detect_root)`
8. `detect_h2 = H(detect_h1, j_felt)`
9. `seed_d_j = detect_h2 || H(TAG_MLKEM_D2, detect_h2)` (64 bytes total)
10. `(ek_v_j, dk_v_j)` and `(ek_d_j, dk_d_j)` are derived deterministically from those 64-byte seeds. Interoperable implementations MUST match the shared vectors in `specs/ocaml_vectors/protocol_v1.json`.

### Auth Key Tree

Each address `j` has a Merkle tree of K one-time XMSS-style public keys (K = 2^AUTH_DEPTH, default AUTH_DEPTH = 16, giving 65536 keys per address). The construction is intentionally close to XMSS / WOTS+ (RFC 8391), but instantiated with BLAKE2s and a simplified single-field ADRS packing that fits the Cairo implementation. The public authentication key for an address is the pair `(auth_root_j, pub_seed_j)`, not just the root.

Per-address public seed:

1. `pub_seed_j = H(TAG_XMSS_PS, ask_j)`

Per-address one-time secret material for key index `i`:

1. `sk_root_i = H(TAG_XMSS_SK, ask_j, i_felt)`
2. `sk_i[c] = H(sk_root_i, c_felt)` for chain index `c` in `0..132`

WOTS parameters:

- `w = 4`
- `WOTS_CHAINS = 133` (128 message digits + 5 checksum digits)
- chain length = `w - 1 = 3`

ADRS packing:

- `ADRS = pack(tag, key_idx, a, b, c)` encoded as one felt252:
  - bytes `0..8`: 8-byte little-endian ASCII tag constant
  - bytes `8..12`: `key_idx` little-endian `u32`
  - bytes `12..16`: `a` little-endian `u32`
  - bytes `16..20`: `b` little-endian `u32`
  - bytes `20..24`: `c` little-endian `u32`
  - remaining bytes zero, with the top felt bits masked to fit felt252

XMSS-style hash roles:

- `H_chain(pub_seed, adrs, x) = H(pub_seed, adrs, x)` using unpersonalized BLAKE2s over the 96 raw bytes
- `H_node(pub_seed, adrs, left, right) = H(pub_seed, adrs, left, right)` using unpersonalized BLAKE2s over the 128 raw bytes
- `TAG_XMSS_CHAIN = "xmss-ch"`
- `TAG_XMSS_LTREE = "xmss-lt"`
- `TAG_XMSS_TREE = "xmss-tr"`

For key index `i`, chain index `c`, and WOTS digit `d_c`:

1. `pk_i[c] = H_chain^{w-1}(sk_i[c])`, where each chain step uses `ADRS = pack(TAG_XMSS_CHAIN, i, c, step, 0)`
2. `leaf_i = LTree(pub_seed_j, i, pk_i[0..132])`

`LTree(pub_seed_j, i, ...)` is the standard pairwise compression tree:

- at level `ell`, pair adjacent nodes
- hash each pair with `H_node(pub_seed_j, pack(TAG_XMSS_LTREE, i, ell, node_idx, 0), left, right)`
- if a level has odd length, carry the last node upward unchanged
- repeat until one node remains

The auth tree root is:

- `auth_root_j = XMSSMerkleRoot(pub_seed_j, leaf_0, ..., leaf_{K-1})`

where each internal node at tree level `ell` and node index `node_idx` is:

- `H_node(pub_seed_j, pack(TAG_XMSS_TREE, 0, ell, node_idx, 0), left, right)`

The `auth_root_j` and `pub_seed_j` are both included in the payment address and bound into commitments via `owner_tag`. Each key index is used at most once. When spending, the STARK:

1. computes the sighash from the public outputs
2. decomposes it into the 133 base-4 WOTS digits
3. recovers the WOTS public key endpoints by hashing each signature chain forward with `H_chain`
4. compresses those recovered endpoints with the XMSS L-tree
5. proves Merkle membership of that exact recovered leaf under `auth_root_j` using `pub_seed_j`

No auth leaf, public key, or signature appears in the public outputs — the STARK proof itself proves spend authorization.

After exhausting all K keys for an address, generate a new address (increment j).

### Per-Address Nullifier Keys

The account-level `nk` never leaves the user's device. Instead, each address derives:

- `nk_spend_j = H_nksp(nk, d_j)` — per-address secret, given to the prover for a specific note
- `nk_tag_j = H_nktg(nk_spend_j)` — per-address public tag, included in the payment address

These are bound into the commitment via an owner tag:

- `owner_tag_j = H_owner(auth_root_j, pub_seed_j, nk_tag_j)` — fuses the full XMSS public key + nullifier binding

This ensures the commitment cryptographically binds to the nullifier key material. Given a commitment `cm`, an attacker who wants to spend it with a fake `nk'` would need to find values that produce the same commitment under `H_commit`, which requires a second-preimage. Note that `auth_root_j` is public in the payment address (the sender needs it to create notes) but stays private on-chain (it never appears in proof outputs). The security rests on the collision resistance of `H_owner` and `H_commit`.

## Capability Levels

| Capability | Keys held | Can do |
|------------|-----------|--------|
| **Detection** | `dk_d_j` for one address, or `detect_root` for all addresses | Flag candidate transactions (with tunable false positives) |
| **Incoming view** | `incoming_seed` | Derive all `d_j`, `dk_v_j`, and `dk_d_j`; decrypt all incoming memos |
| **Outgoing view** | `outgoing_seed` | Decrypt sender-recovery ciphertexts for outputs created by this wallet |
| **Full view** | `(nk, incoming_seed)` | Incoming view + compute nullifiers + track spent/unspent for notes whose address metadata is known |
| **Spend** | `(nk, ask_base, incoming_seed)` | Full view + authorize transactions |

Detection ⊂ incoming view ⊂ full view ⊂ spend. Each level strictly adds capability. Outgoing view is orthogonal to that chain: it tracks sent outputs created with the account's `outgoing_seed`, but it cannot detect arbitrary incoming notes, compute nullifiers, or spend.

`incoming_seed` and `nk` alone do NOT reconstruct `(auth_root_j, pub_seed_j)`, so incoming-view and full-view holders cannot fully validate note spendability from keys alone. Independent note validation requires locally stored address metadata (or exported address records) containing at least `(d_j, auth_root_j, pub_seed_j, nk_tag_j)` for the recipient addresses being monitored.

## Payment Address

What the sender receives:

```
address_j = (d_j, auth_root_j, pub_seed_j, nk_tag_j, ek_v_j, ek_d_j)
```

- `d_j` — diversifier (32 bytes): identifies the address, appears in the note commitment
- `auth_root_j` — auth key tree root (32 bytes): bound into the commitment; stays private on-chain
- `pub_seed_j` — XMSS public seed (32 bytes): part of the address's public spend-auth key, bound into the commitment
- `nk_tag_j` — nullifier binding tag (32 bytes): binds the commitment to the owner's nullifier key
- `ek_v_j` — ML-KEM encapsulation key (~1184 bytes): sender encrypts memos with this
- `ek_d_j` — ML-KEM encapsulation key (~1184 bytes): sender creates detection clues with this

Multiple addresses can be generated from one account (varying j). Each address has unrelated `d_j` values. ML-KEM ciphertexts are randomized per encapsulation, so there is no deterministic ciphertext linkage between two notes sent to the same address. Stronger recipient unlinkability should be treated as relying on additional key-anonymity assumptions of the chosen KEM.

For circuit purposes, `d_j`, `auth_root_j`, and `nk_tag_j` matter. The ML-KEM keys are application-layer.

## Note Structure

```
rseed       — random per-note seed
rcm         = H(H(TAG_RCM), rseed)                              — commitment randomness
owner_tag   = H_owner(auth_root_j, pub_seed_j, nk_tag_j)        — fuses the XMSS public key + nullifier binding
asset_id    — 32-byte L2 asset tag (ASSET_TEZ = 0 for tez; FA2 = H("tzel:asset:" || ticketer_kt1))
cm          = H_commit(d_j, v, asset_id, rcm, owner_tag)        — note commitment (5-ary as of canonical wire v4)
nf          = H_nf(nk_spend_j, H_nf(cm, pos))                   — position-dependent nullifier
```

The commitment binds to the diversified address, value, **asset class**, and owner tag (which fuses the auth key tree root and nullifier key material). The nullifier uses the per-address `nk_spend_j` and includes the leaf position to prevent faerie gold attacks.

**Multiasset note**: `asset_id` is hidden inside the commitment preimage — it is NOT a separate field on the wire. Two notes with identical `(d_j, v, rcm, owner_tag)` but different `asset_id` produce different commitments, but an on-chain observer cannot tell which asset a given `cm` carries. The pre-multiasset spec (canonical wire v3 and earlier) used the 4-ary commitment `H_commit(d_j, v, rcm, owner_tag)`; the v4 wire bump adds the `asset_id` slot. `ASSET_TEZ = 0x00..00` preserves backward compatibility — a tez-only deployment computes the same `cm` as it did pre-multiasset.

### Position-Dependent Nullifiers

The nullifier includes the Merkle tree leaf index (`pos`):

```
nf = H_nf(nk_spend, H_nf(cm, pos))
```

This prevents an attacker from creating two identical commitments (same d_j, v, rcm, owner_tag) that resolve to a single nullifier. With position in the nullifier, each tree insertion produces a unique nullifier even for duplicate commitments.

## Multiasset

Notes can carry any registered L2 asset. Tez is the default; FA2 tokens are bridged via per-asset KT1 ticketer contracts.

### Asset identity

The L2 `asset_id` is a 32-byte felt:
- `ASSET_TEZ = 0x00..00` is reserved for tez.
- FA2 assets use `asset_id = H("tzel:asset:" || ticketer_kt1_address)` (BLAKE2s-251 with the same personalization as `hash`). One FA2 ticketer KT1 maps to exactly one L2 `asset_id`; the binding is structural rather than registered, so the ticketer address alone determines the asset.

The kernel composes a registered-asset list as `compose_asset_registry(tez_ticketer)` over a compile-time constant `COMPILE_TIME_FA2_BRIDGES: &[&str]`. The first entry is always the tez bridge; subsequent entries are FA2 ticketers. Defense-in-depth: `compose_asset_registry_with` skips any FA2 entry that equals the tez ticketer string, so a misconfigured registry cannot let first-match ordering mask an FA2 entry.

### Per-asset 2-accumulator balance

Transfer and unshield circuits prove value conservation per asset. Because Cairo cannot iterate over felts, the circuit takes a witness-declared "primary non-tez asset" `A` per transaction and pins every input and output asset to `{ASSET_TEZ, A}`. Two accumulators (`tez_in/tez_out`, `primary_in/primary_out`) close the per-asset balance:

```
tez_in = tez_out + fee  + (v_pub if asset_pub == ASSET_TEZ)
primary_in = primary_out + (v_pub if asset_pub == A)
```

For pure-tez transactions, no input/output has `asset = A`, so `primary_in = primary_out = 0` trivially. The burned `fee` is always tez. The producer-fee output is pinned to `ASSET_TEZ` in-circuit (`asset_4 = ASSET_TEZ` in transfer; `asset_producer = ASSET_TEZ` in shield; `asset_fee = ASSET_TEZ` in unshield).

A transaction therefore spans at most TWO assets: tez and the witness's primary. A 3-asset transfer (`tez + FA2_A + FA2_B`) is rejected at the per-input asset check; clients must serialize cross-asset moves as a sequence of 2-asset transactions.

### FA2 bridge ticketer

Each FA2 (contract, token_id) pair gets a dedicated bridge ticketer KT1 with immutable storage `(fa2_contract: address, token_id: nat)` and entrypoints:

- `%mint(amount: nat, receiver: bytes, rollup: address)` — pulls `amount` of `token_id` from the caller's FA2 balance into `SELF_ADDRESS`, then mints an L2 ticket with **canonical content `(0, None)`** addressed to the rollup with payload `(receiver, ticket)`. The receiver bytes are the `deposit:<hex(pubkey_hash)>` L2 string.
- `%burn(receiver: contract unit, ticket: ticket (pair nat (option bytes)))` — accepts only ticketer-self-minted tickets (verified via `READ_TICKET`), requires `content == (0, None)`, then calls the underlying FA2's `%transfer` to send `amount` of `storage.token_id` from `SELF_ADDRESS` to the receiver's L1 address.

**Critical invariant**: the L2 ticket content is canonical `(0, None)` regardless of `storage.token_id`. The FA2 token_id binding lives in the ticketer's immutable storage; the L2 layer's asset_id derives from the ticketer's KT1 alone. Earlier drafts stuffed `storage.token_id` into the L2 ticket content, which broke bridging for any FA2 with `token_id != 0` because the kernel rejects any deposit ticket whose `content.token_id != 0` (bug #3, fixed in commit `73ad6fb`).

### Deposit pool keying

The kernel's deposit-pool durable store is keyed by `(asset_id, pubkey_hash)`. Path: `/tzel/v1/state/deposits/balance/<hex(asset_id)>/<hex(pubkey_hash)>`. The same `pubkey_hash` can host distinct pools for tez and an FA2 simultaneously; the bug-#2 shield split-debit explicitly relies on this.

### Wire format

Canonical wire `version: 4` (was `3` pre-multiasset). The commitment is 5-ary; the encrypted note payload does NOT carry `asset_id` (a wire-format bump would invalidate every pre-multiasset on-chain ciphertext). The wallet's outgoing-recovery plaintext likewise omits `asset_id`; recovery iterates the candidate registry and picks the asset whose commitment recomputes to the on-chain `cm`.

### Asset removal

Removing an FA2 from `COMPILE_TIME_FA2_BRIDGES` is asymmetric:
- New deposits for that asset are rejected (sender ticketer no longer in registry).
- Existing pools / notes for that asset remain in durable state but become unshieldable (`asset_pub` no longer in registered set ⇒ unshield refuses to dispatch the L1 burn).
- Restoring the asset (re-adding the same KT1 string to the registry) restores spendability since the `asset_id` is structurally derived from the KT1, not registered.

## Transaction Types

The reference rollup currently enforces a burned transaction fee with a floor of:

```
MIN_TX_FEE = 100000 mutez   // 0.1 tez
```

Shield, transfer, and unshield transactions MUST publish `fee >= required_tx_fee`,
where `required_tx_fee >= MIN_TX_FEE`.

For the current POC rollup deployment:

- the first two accepted private transactions at a given inbox level require `100000` mutez
- each additional accepted private transaction at that same inbox level doubles the required fee
- the doubling schedule is capped after 6 steps
- when the inbox level advances, the required fee resets to the floor

That burned fee is deducted from consumed value and is not recreated as a public
or private output.

Each private transaction also carries a distinct `producer_fee > 0` that is
paid to the DAL slot producer as an ordinary shielded note output. This is a
separate resource price from the burned rollup fee above.

### Shield (public -> private)

**Public outputs:** `[auth_domain, pubkey_hash, v_pub, fee, producer_fee, cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash, asset_new]` (10 felts as of multiasset; was 9 in the pre-multiasset spec).

`pubkey_hash` is the deposit-pool key (see [Deposit-Pool Identifiers](#deposit-pool-identifiers) below). The shield circuit additionally verifies an **in-circuit WOTS+ signature** from the recipient's auth tree, mirroring the structure used by transfer and unshield. The signature binds the entire request payload, so a delegated prover that holds the witness still cannot redirect funds, change values, or swap recipients without the wallet's spending key.

**Circuit constraints:**
1. `rcm = H(H(TAG_RCM), rseed)`
2. `owner_tag = H_owner(auth_root, pub_seed, nk_tag)` where `auth_root`, `pub_seed`, and `nk_tag` are private inputs from the recipient's payment address
3. `cm_new = H_commit(d_j, v_pub, asset_new, rcm, owner_tag)`
4. `producer_rcm = H(H(TAG_RCM), producer_rseed)`
5. `producer_owner_tag = H_owner(producer_auth_root, producer_pub_seed, producer_nk_tag)`
6. `cm_producer = H_commit(producer_d_j, producer_fee, ASSET_TEZ, producer_rcm, producer_owner_tag)` — producer-fee output is permanently tez (DAL slot publisher liquidity argument)
7. `producer_fee > 0`
8. `pubkey_hash = H_pubkey(auth_domain, auth_root, pub_seed, blind)` (left-fold with the `sighSP__` personalization and leading type tag `0x04`); the `blind` is a private input the wallet derives deterministically from `master_sk` per deposit
9. WOTS+ signature verification under the recipient's auth tree: the circuit recovers the WOTS+ public-key endpoints from the signature, computes the `auth_leaf` via the L-tree, and verifies its inclusion in `auth_root`. The signed message is the shield sighash:
   ```
   sighash = fold(0x03, auth_domain, pubkey_hash, v_pub, fee, producer_fee,
                  cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash,
                  asset_new, asset_producer)
   ```
   `asset_new` is the recipient note's asset; `asset_producer` is always `ASSET_TEZ` (asserted in-circuit).

`memo_ct_hash` and `producer_memo_ct_hash` are computed client-side as `H(ct_d || tag || ct_v || nonce || encrypted_data || outgoing_ct)` and passed into the circuit as public inputs.

The L1 deposit transaction (signed by the depositor's L1 key) credits the deposit pool keyed by `pubkey_hash`. The actual `(v, fee, producer_fee, cm_recipient, cm_producer)` is chosen at *shield time*, not at deposit time, and the in-circuit WOTS+ sig is what binds it. This means the wallet must be online to sign each shield, but it also makes shielding much more flexible: the same pool can be drained over multiple shields, and the user can pick the recipient at shield time rather than committing at deposit time.

**Contract / ledger checks:** proof valid (including in-circuit WOTS+ verify), `H(posted_client_note_calldata) == memo_ct_hash`, `H(posted_producer_note_calldata) == producer_memo_ct_hash`, `fee >= required_tx_fee`, and the kernel's pinned public outputs (`auth_domain`, `pubkey_hash`, `v`, `fee`, `producer_fee`, `cm_new`, `cm_producer`, memo hashes, `asset_new`) match the request fields. The kernel also checks that `asset_new` is in the registered-asset list (`compose_asset_registry(tez_ticketer)` over the kernel-binary's `COMPILE_TIME_FA2_BRIDGES`); shields for unregistered assets are rejected. Consensus also requires the deposit pool(s) below to be sufficiently funded.

**Aggregated deposit pools.** Every L1 ticket the kernel observes for a `deposit:<hex(pubkey_hash)>` recipient credits a per-pool aggregated balance keyed by `(asset_id, pubkey_hash)`. The `asset_id` is determined by the L1 ticketer that minted the deposit ticket: tez ticketer → `ASSET_TEZ`; FA2 ticketer KT1 → `derive_asset_id(KT1) = H("tzel:asset:" || KT1)`. Two tickets to the same recipient string from the same ticketer sum into one balance — there is no per-ticket "slot" to brick. The same `pubkey_hash` can host distinct pools for tez and an FA2 simultaneously, which the bug-#2 fix below explicitly relies on. Properties:

- A wallet that doesn't reveal its `(auth_root, pub_seed, blind)` triple is the only entity that can produce a valid WOTS+ sig under `auth_root`, and therefore the only entity that can shield against the pool.
- Dust attackers who mirror-deposit to the same `(asset_id, pubkey_hash)` simply add to the victim's pool balance — they pay L1 token to subsidize the victim's eventual shield.
- The user can top up an existing pool by sending another L1 ticket; multiple deposits compose linearly.

**Shield debits one or two pools.** For a tez shield (`asset_new == ASSET_TEZ`) the kernel debits `v + fee + producer_fee` from `(ASSET_TEZ, pubkey_hash)`. For a non-tez shield (`asset_new = X`, an FA2), the kernel debits `v + fee` from `(X, pubkey_hash)` AND debits `producer_fee` from `(ASSET_TEZ, pubkey_hash)` — the producer-fee output note is permanently tez (asserted in-circuit), so the kernel must back it from the user's tez pool at the same `pubkey_hash`. **An FA2 shield therefore requires the user to have BOTH an FA2 pool AND a tez pool at the same `pubkey_hash`.** Without this split, an FA2 shield would mint `producer_fee` tez out of nothing — backed only by other users' tez deposits at unshield time. The user picks (recipient, value, fees, asset) at shield time. The kernel:
1. Verifies the proof (which includes the in-circuit WOTS+ sig and the in-circuit `asset_producer == ASSET_TEZ` assertion).
2. Pins the proof's public outputs to the request fields, including `asset_new`.
3. Reads `asset_balance = pool[(asset_new, pubkey_hash)]`. Rejects if it cannot cover the asset-side debit (`v + fee + producer_fee` for tez shields, `v + fee` for FA2 shields).
4. For FA2 shields ONLY: reads `tez_balance = pool[(ASSET_TEZ, pubkey_hash)]` and rejects if `tez_balance < producer_fee`.
5. Decrements the asset pool by the asset-side debit. For FA2 shields, ALSO decrements the tez pool by `producer_fee`. If either new balance is zero, that entry is removed.
6. Appends `cm_new` and `cm_producer` to the global note tree.

Pool overfunding is fine: the surplus stays available for future shields. Underfunding (or congestion-driven `required_tx_fee` exceeding what the pool covers) just makes shield reject at step 3 or 4 — the user can top up via another L1 ticket and retry. The shield circuit does not commit `fee` into the pool key, so a fee revision between deposit and shield does not strand the pool.

### Transfer (N->recipient + up to two change notes + producer fee, where 1 <= N <= 7)

Consumes N private notes and creates exactly 4 new private note slots (Phase C):

| slot | purpose | asset |
|------|---------|-------|
| `cm_1` | recipient note | sender-chosen (either `ASSET_TEZ` or the witness-declared primary non-tez asset `A`) |
| `cm_2` | change for `cm_1`'s asset | matches `cm_1`'s asset |
| `cm_3` | second change (for the OTHER asset under the 2-asset balance) | matches the other asset, OR is a zero-value placeholder for pure single-asset transfers |
| `cm_4` | producer fee | permanently `ASSET_TEZ` (DAL slot publisher liquidity argument; asserted in-circuit) |

`N` is a runtime parameter, not a program parameter — the program hash is the same for all N. Each input independently carries a hidden asset, but the circuit's witness pins a single "primary non-tez asset" `A` per transaction so the per-asset balance equations close over exactly two accumulators.

**Public outputs:** `[auth_domain, root, nf_0..nf_{N-1}, fee, cm_1, cm_2, cm_3, cm_4, memo_ct_hash_1, memo_ct_hash_2, memo_ct_hash_3, memo_ct_hash_4]` — `2 + N + 9` felts total.

XMSS-style WOTS+ signature verification happens inside the STARK. No auth leaves, public keys, or signatures appear in the public outputs. The witness-declared primary asset `A` is NOT public; only the commitments are, and the commitments hide which asset each note carries.

**Circuit constraints:**
1. For each input i (0..N):
   - `rcm_i = H(H(TAG_RCM), rseed_i)`
   - `nk_tag_i = H_nktg(nk_spend_i)`
   - `owner_tag_i = H_owner(auth_root_i, pub_seed_i, nk_tag_i)`
   - `cm_i = H_commit(d_j_i, v_i, asset_i, rcm_i, owner_tag_i)`
   - Merkle membership of `cm_i` at position `pos_i` against `root` (commitment tree)
   - `nf_i = H_nf(nk_spend_i, H_nf(cm_i, pos_i))`
   - `asset_i ∈ {ASSET_TEZ, A}` (the witness-declared primary non-tez asset)
   - XMSS-style WOTS+ verification: the circuit computes the sighash from the public outputs, decomposes it into 128 base-4 digits + 5 checksum digits, then for each of the 133 chains recovers the final public-key endpoint with `H_chain^{w-1-digit}(sig_j, pub_seed_i, ADRS_j)`. The digits are NOT witness data — they are deterministically derived inside the circuit.
   - `auth_leaf_i = LTree(pub_seed_i, key_idx_i, pk_0, ..., pk_132)` from those recovered chain endpoints
   - Merkle membership of that exact `auth_leaf_i` at position `key_idx_i` against `auth_root_i` using the XMSS tree-node hash (auth key tree)
2. For each output slot k ∈ {1, 2, 3, 4}:
   - `owner_tag_k = H_owner(auth_root_k, pub_seed_k, nk_tag_k)`
   - `cm_k = H_commit(d_j_k, v_k, asset_k, rcm_k, owner_tag_k)`
   - `asset_k ∈ {ASSET_TEZ, A}` (same in-pair constraint as inputs)
3. `asset_4 = ASSET_TEZ` (producer-fee note permanently tez)
4. `v_4 > 0`
5. **Per-asset balance (2-accumulator).** Let `tez_in = sum_{i: asset_i = ASSET_TEZ} v_i`, `primary_in = sum_{i: asset_i = A} v_i`, and analogously `tez_out / primary_out` over the 4 output slots. The circuit asserts both
   - `tez_in = tez_out + fee`  (the public burned fee is always tez)
   - `primary_in = primary_out`
6. All values are u64 (implicit range check)

**Contract / ledger checks:** proof valid, `fee >= required_tx_fee`, every public nullifier is unique within the transaction, and no public nullifier has already been spent. No signature verification needed — the STARK proof proves spend authorization.

### Unshield (N->withdrawal + up to two change notes + producer fee, where 1 <= N <= 7)

Consumes N private notes, queues an L1 withdrawal of `v_pub` units of `asset_pub` to a canonical Tezos recipient (the L1 burn dispatches via the bridge ticketer registered for `asset_pub`), and creates a producer-fee note plus up to two private change notes (one per asset under the 2-accumulator design).

**Public outputs:** `[auth_domain, root, nf_0..nf_{N-1}, v_pub, asset_pub, fee, recipient_id, cm_change, memo_ct_hash_change, cm_change_2, memo_ct_hash_change_2, cm_fee, memo_ct_hash_fee]` — `2 + N + 10` felts total.

`recipient_id` is defined in [L1 Withdrawal Recipient Encoding](#l1-withdrawal-recipient-encoding); semantically it is the hash of the canonical L1 recipient string. `asset_pub` is the asset of the unshielded value (`ASSET_TEZ` for a tez exit; an FA2 asset_id for an FA2 exit). The kernel dispatches the L1 burn to `ticketer_for_asset(asset_pub)` and refuses if `asset_pub` is not in the registered set.

`cm_change` / `cm_change_2` (and their memo hashes) are 0 if their respective slot is unused. The circuit's witness flags `has_change` and `has_change_2` gate the change-slot computations.

**Circuit constraints:**
1. Same per-input verification as Transfer (including auth tree membership proof, WOTS+ signature verification, and `asset_i ∈ {ASSET_TEZ, A}` per-input asset check where `A` is the witness-declared primary non-tez asset).
2. `asset_pub ∈ {ASSET_TEZ, A}` (the L1-exit asset must be in the same in-pair set as inputs/outputs). The audit found a CRITICAL bug in pre-fix versions of this constraint: an unconditional `tez_out += v_pub` mistakenly routed `v_pub` to the tez accumulator regardless of `asset_pub`, allowing a tez-only input set to mint FA2 tokens on L1. The fix (commit `2003bf5`) routes `v_pub` to `tez_out` or `primary_out` based on `asset_pub`.
3. If `has_change`:
   - `owner_tag_c = H_owner(auth_root_c, pub_seed_c, nk_tag_c)`
   - `cm_change = H_commit(d_j_c, v_change, asset_change, rcm_c, owner_tag_c)`
   - `asset_change ∈ {ASSET_TEZ, A}`
4. If `has_change_2`:
   - Analogous for `cm_change_2`, `asset_change_2 ∈ {ASSET_TEZ, A}`.
5. If `!has_change` (resp. `!has_change_2`): all witness data for that slot is constrained to zero to eliminate prover malleability.
6. `cm_fee = H_commit(d_j_fee, v_fee, ASSET_TEZ, rcm_fee, owner_tag_fee)` for the DAL producer note (always tez, asserted in-circuit).
7. `v_fee > 0`.
8. **Per-asset balance (2-accumulator).** Let `tez_in / primary_in` be the input-side per-asset sums and `tez_out / primary_out` be the output-side per-asset sums over the change slots. The circuit asserts:
   - `tez_in = tez_out + [asset_pub == ASSET_TEZ] * v_pub + v_fee + fee`
   - `primary_in = primary_out + [asset_pub == A] * v_pub`

**Contract / ledger checks:** proof valid, `fee >= required_tx_fee`, every public nullifier is unique within the transaction, no public nullifier has already been spent, `asset_pub` is in the registered-asset list. Verify recipient binding per [L1 Withdrawal Recipient Encoding](#l1-withdrawal-recipient-encoding), queue or emit the L1 withdrawal via `ticketer_for_asset(asset_pub)` for `v_pub`, append `cm_change` / `cm_change_2` to T (if their slots are used), append `cm_fee` to T. No signature verification needed — the STARK proof proves spend authorization.

## Contract Consensus Rules

The circuit proves constraints over private inputs. The on-chain contract enforces all remaining consensus rules. These are **not optional** — omitting any of them breaks the security model.

### Root validation (all spending transactions)

The contract maintains an append-only set of historical Merkle roots (anchors). For every transfer or unshield, the contract MUST verify that `root` (from the proof's public outputs) is a member of this set. Rejection of unknown roots prevents an attacker from constructing a fake tree containing self-chosen notes and "spending" them with a valid proof against that fake root.

### Authorization-domain validation (all spending transactions)

The contract or verifier environment MUST verify that `auth_domain` (from the proof's public outputs) equals the deployment's configured spend-authorization domain. Rejection of mismatched domains prevents replay of a valid spend authorization onto a mirrored deployment, fork, or verifier migration that shares the same Merkle root history.

The verifier configuration is **one-shot for the lifetime of the deployment**. The contract MUST reject every subsequent `configure_verifier` message — same fields, different `auth_domain`, different program hashes, anything — once a config is installed. Wallets that read `auth_domain` once therefore never have to worry about it changing under them. The earlier "auth_domain frozen but other fields reconfigurable on a pristine ledger" rule was retired with the deposit-pool redesign; it existed to close a stranding window for in-flight intent-bound deposits, which the pool design no longer has.

### Verifier configuration

The kernel persists a signed `KernelVerifierConfig` containing:

- `auth_domain` (frozen by the one-shot rule, see above)
- `verified_program_hashes` for `run_shield`, `run_transfer`, `run_unshield`

The signature covers all fields. There is no privileged rollup operator and no on-chain notion of a canonical producer-fee receiver — producer fees are paid in a permissionless market to whichever DAL slot publisher chooses to include the transaction.

The producer-fee receiver is **not enforced in-circuit and not enforced on chain**. The shield / transfer / unshield circuits prove only that `cm_producer = H_commit(producer_d_j, producer_fee, producer_rcm, producer_otag)` and that the witness is internally consistent. Enforcement of "the producer note is payable to me" is the DAL slot publisher's own inclusion policy — they refuse to bundle transactions whose producer note isn't routed to them, since that note is their revenue. A wallet that targets a publisher and routes the fee elsewhere simply doesn't get included.

### Wallet preflight gates

Bridge deposits and unshield/transfer submissions are irreversible at the L1 / inbox layer. The reference wallet refuses to submit until it has read durable storage and confirmed:

1. **Verifier configured** — `verifier_config.bin` exists. Deposits before configuration would land in a kernel that rejects them.
2. **Bridge ticketer matches** — `bridge/ticketer` equals the wallet profile's `bridge_ticketer`. The kernel rejects deposits whose `transfer.sender` doesn't match its configured ticketer; an L1 ticket against the wrong ticketer burns mutez to a pool that never appears.
4. **Rollup address matches** — the rollup node's `/global/smart_rollup_address` equals the wallet profile's `rollup_address`. The kernel reads at `rollup_node_url`; the L1 mint targets `rollup_address`. Without this cross-check, a stale or malicious profile that points the two at different rollups can pass the verifier / ticketer preflight while sending an irreversible L1 ticket to the wrong rollup.

These checks bind the wallet to the deployment it thinks it is talking to. They are reference behavior, not a consensus rule — a custom wallet that skips them merely loses funds privately. There is intentionally no producer-fee-receiver preflight: that fee is a market price the wallet pays to a DAL slot publisher of its own choosing, and the publisher gates inclusion themselves off-chain.

### Executable binding (all proof-verified transactions)

If proofs are produced through a bootloader or recursive verifier wrapper, the verifier environment MUST also authenticate which circuit executable was actually proved. In the reference implementation this means checking the bootloader-reported task program hash against the deployment's expected `run_shield`, `run_transfer`, or `run_unshield` executable hash before interpreting the public outputs. Verifying "some valid Cairo task" is not sufficient.

### Public nullifier uniqueness (all spending transactions)

The public output list determines `N`, the number of spent inputs, and exposes exactly `nf_0..nf_{N-1}`. Because those nullifiers and their count are public, pairwise distinctness is a consensus rule rather than a private circuit constraint. The contract MUST reject a transfer or unshield if the public nullifier list contains duplicates, and MUST also reject any `nf_i` that already exists in the global on-chain nullifier set. This prevents double-spends both within one transaction and across transactions. After all validation succeeds, the contract inserts all `nf_i` into the global set. The reference rollup kernel enforces this before appending output notes, queueing the withdrawal, or inserting nullifiers.

For proof-verified transactions, the ledger MUST bind `N` to the exact verified public-output vector. The single bootloader task output is a serialized Cairo array, so the ledger first validates and strips the array length prefix. The resulting Transfer vector MUST have exactly `2 + N + 9` public felts (fee + 4 cms + 4 memo hashes), and the resulting Unshield vector MUST have exactly `2 + N + 10` public felts (v_pub + asset_pub + fee + recipient + 2× (cm,mh) for changes + 1× (cm,mh) for the fee note). Shield uses a fixed-size 10-felt vector with no `N`. Accepting a longer vector and interpreting only a suffix is forbidden, because that would make the public input count ambiguous.

### Commitment binding (all transactions with outputs)

For each output note, the contract MUST verify that the `cm` in the posted note data exactly matches the corresponding `cm` in the proof's public outputs. This binds the on-chain note data (encrypted memo, detection ciphertext) to the proven commitment.

### Memo integrity (all transactions with outputs)

For each output note, the contract MUST verify `H(posted_note_calldata) == memo_ct_hash` where `memo_ct_hash` is from the proof's public outputs. This prevents relayers or sequencers from swapping or stripping memo data.

### Shield deposit binding

Bridge deposits for shielding MUST be addressed to the canonical recipient string `deposit:<hex(pubkey_hash)>` where `pubkey_hash = H_pubkey(auth_domain, auth_root, auth_pub_seed, blind)`. Each accepted L1 ticket credits a **per-pool aggregated balance keyed by `(asset_id, pubkey_hash)`**, where `asset_id` is determined by the ticketer KT1 that emitted the L1 ticket (`ASSET_TEZ` for the tez bridge ticketer; `derive_asset_id(KT1)` for an FA2 bridge ticketer). Multiple tickets from the same ticketer to the same recipient string aggregate (top-ups); dust attackers depositing to a victim's pool simply add to the victim's balance.

The shield proof verifies an in-circuit WOTS+ signature under the recipient's auth tree — the same signature scheme used by transfer and unshield. The signed message is the full shield sighash `fold(0x03, auth_domain, pubkey_hash, v_pub, fee, producer_fee, cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash, asset_new, asset_producer)`, so the prover cannot redirect funds, change values, swap recipients, OR change the asset — only the wallet that holds the corresponding signing key in the auth tree can produce a valid shield.

`ShieldReq` carries `(asset_id, pubkey_hash)` selecting the deposit pool plus the user-chosen `(v, fee, producer_fee, cm_recipient, cm_producer)` quintuple. The kernel MUST verify that the proof is valid, the pinned public outputs match the request fields (including `asset_new`), `asset_new` is in the registered-asset set, and the deposit pool(s) are sufficiently funded as described in the Shield section above (one pool for tez shields; both the FA2 pool and the tez pool at the same `pubkey_hash` for FA2 shields). On success the relevant pool(s) are debited; entries reaching zero are removed.

### Spend authorization (all spending transactions)

WOTS+ signature verification happens entirely inside the STARK circuit. The contract does not verify any signatures — it only verifies the STARK proof. A valid proof guarantees that:
1. Each input note's WOTS+ key is a leaf in the spender's auth tree (bound to the spent commitment)
2. A valid WOTS+ signature over the sighash was provided for each input

No public keys, auth leaves, or signatures appear in the public outputs or on-chain calldata.

### Sighash

The WOTS+ signature inside the STARK binds to the transaction's public outputs. The sighash is computed inside the circuit by folding all public outputs with a circuit-type tag using the `sighSP__` personalization:

```
// Transfer (type_tag = 0x01):
sighash = fold(0x01, auth_domain, root, nf_0, ..., nf_{N-1}, fee,
               cm_1, cm_2, cm_3, cm_4, mh_1, mh_2, mh_3, mh_4)

// Unshield (type_tag = 0x02):
sighash = fold(0x02, auth_domain, root, nf_0, ..., nf_{N-1}, v_pub, asset_pub, fee, recipient_id,
               cm_change, mh_change, cm_change_2, mh_change_2, cm_fee, mh_fee)
```

**Multiasset binding**: in transfer the per-output `asset_k` is NOT folded directly into the sighash, but every `cm_k` IS — and `cm_k = H_commit(d_j_k, v_k, asset_k, rcm_k, owner_tag_k)` already binds the asset. A delegated prover with the wallet's signature on `cm_k` cannot mutate `asset_k` without invalidating the signed `cm_k`. In unshield `asset_pub` IS folded directly (it's a public-output discriminator chosen by the user at sign time). In shield both `asset_new` and `asset_producer` are folded directly (see Shield section).

The fold algorithm is the sequential left fold used by the client and circuit:

```
fold(x_0, x_1, ..., x_n) =
  H_sigh(H_sigh(...H_sigh(x_0, x_1), x_2)..., x_n)
```

where `H_sigh(a, b) = BLAKE2s_251(personal="sighSP__", a || b)`.

`auth_domain` is a deployment-specific public input/output chosen by the verifier environment and enforced by the contract or ledger. It MUST uniquely identify the deployment context for spend authorizations. A practical derivation is `H(chain_id || contract_addr || verifier_or_program_id || deployment_salt)`, encoded canonically as a felt252.

The circuit-type tag prevents cross-circuit replay (a transfer signature cannot be used for an unshield). `auth_domain` prevents replay across mirrored deployments, forks, or verifier migrations that would otherwise share the same Merkle root history. Nullifier uniqueness still prevents replay of an already-consumed authorization on the same deployment.

**Still out of scope:** `expiry` and per-transaction `nonce` are not currently included in the sighash. As a result, a valid authorization can remain usable until one of its nullifiers is consumed. These remain higher-level anti-withholding / anti-latency controls, not part of the base spend authorization proof.

### Change output handling (unshield)

If `cm_change == 0` in the proof's public outputs, the contract MUST NOT append any commitment to the tree. If `cm_change != 0`, the contract appends it.

### Tree append ordering

The contract appends commitments to the tree in sequential order (each new commitment gets the next available leaf index) and snapshots the root after each transaction. The new root is added to the historical root set. See Canonical Encodings for Merkle tree structure details.

## Delegated Proving

1. User constructs the transaction, computing the WOTS+ signature over the sighash with `sk_i` for each input.
2. User gives the prover per-input: `(nk_spend_j, auth_root_j, pub_seed_j, wots_sig_i, auth_tree_path_i, d_j, v, rseed, commitment_tree_path, pos)`, plus output data including `auth_root`, `pub_seed`, and `nk_tag` for output notes.
3. Prover generates the STARK proof. The WOTS+ signature is verified inside the circuit.
4. Prover returns proof to user. Public outputs contain only `[auth_domain, root, nullifiers, fee, commitments, memo hashes]` (or `[auth_domain, root, nullifiers, v_pub, fee, recipient_id, cm_change, memo_ct_hash_change, cm_fee, memo_ct_hash_fee]` for unshield) — no auth leaves, public keys, or signatures.
5. Transaction (proof + note data) submitted on-chain. No separate signatures or public keys needed.

## Detection (Fuzzy Message Detection)

Detection precision `k` is a protocol constant (e.g., k=10). Per note on-chain:

```
(ss_d, ct_d)     = ML-KEM.Encaps(ek_d_j)     — encapsulate under detection key
tag_u16          = LE16(H(ss_d)[0], H(ss_d)[1]) & ((1 << k) - 1)
tag              = LE16(tag_u16)             — 2-byte little-endian field on chain
(ss_v, ct_v)     = ML-KEM.Encaps(ek_v_j)     — encapsulate under viewing key
plaintext        = (v || rseed || memo)
nonce            = H_mnon(H(ss_v) || plaintext)[0..12)
encrypted_data   = ChaCha20-Poly1305(key=H(ss_v), nonce, plaintext)
```

The detection server (with `dk_d_j`) decapsulates `ct_d`, recomputes `tag_u16`, and compares it to the posted little-endian `tag` field. True matches always succeed. Non-matches succeed with probability 2^(-k) (false positives from ML-KEM's implicit rejection).

## Outgoing Viewing

For each output created by a wallet, the sender also posts a fixed-size sender-recovery ciphertext:

```text
outgoing_plaintext = role || v || rseed || d_j || auth_root || pub_seed || nk_tag
outgoing_key       = H_ovk(outgoing_seed, cm)
outgoing_nonce     = H_ovn(outgoing_key, cm)[0..12)
outgoing_ct        = ChaCha20-Poly1305(outgoing_key, outgoing_nonce, outgoing_plaintext)
```

`role` distinguishes recipient, change, shield, unshield-change, and producer-fee outputs. The ciphertext is bound to `cm`, so copying it to another note does not decrypt under the same outgoing key. It intentionally stores the cryptographic note metadata needed for sender recovery, not the full 1024-byte user memo. Payment addresses are unchanged; recipients still use the incoming ML-KEM viewing path above.

## Wallet Note Acceptance

Detection and successful memo decryption are only candidate filters. A wallet MUST accept an incoming note as belonging to one of its addresses only if it can match the note against locally known address metadata and recompute the commitment exactly:

1. Select a local address record containing `(d_j, auth_root_j, pub_seed_j, nk_tag_j)` for the candidate recipient address.
2. Decrypt the note to obtain `(v, rseed, memo)`.
3. Recompute `rcm = H(H(TAG_RCM), rseed)`.
4. Recompute `owner_tag = H_owner(auth_root_j, pub_seed_j, nk_tag_j)`.
5. Iterate the wallet's registered-asset list (tez first, then each compile-time FA2 entry) and recompute `cm_expected = H_commit(d_j, v, asset, rcm, owner_tag)` for each candidate `asset`. The asset that yields `cm_expected == cm` is the asset this note carries.
6. Accept the note only if some candidate asset makes `cm_expected == cm`. Otherwise reject it as malformed, non-local, or unspendable.

**Multiasset note**: the encrypted note payload does NOT carry `asset_id` — that would force a wire-format bump and a Cairo change that re-bound `mh` to `asset`. Instead the wallet re-derives `cm` against each registered asset and picks whichever matches. Cost is O(|registry|) hashes per candidate decrypt; for single-digit registries this is negligible.

## User Memo

Each note carries a 1024-byte user memo field, encrypted alongside `(v, rseed)` inside the AEAD ciphertext. The memo can contain arbitrary data: payment references, return addresses, human-readable messages, or structured metadata.

Memo format conventions (following Zcash ZIP 302):

- If the first byte is <= 0xF4: the memo is a UTF-8 string, zero-padded.
- If the first byte is 0xF6: "no memo" (remainder is zeros).
- If the first byte is >= 0xF5: application-defined binary format.

The memo is end-to-end encrypted — only the recipient (with `dk_v`) can read it. The on-chain ciphertext reveals nothing about the memo content or length (all memos are padded to exactly 1024 bytes before encryption).

## Memo Integrity (Anti-Tampering)

Each circuit includes a `memo_ct_hash` per output note in its public outputs. This is a hash of ALL on-chain note data (`H(ct_d || tag || ct_v || nonce || encrypted_data || outgoing_ct)`), computed **client-side** before proving. The circuit does not compute it — it simply passes it through as a public output. Including the detection ciphertext, tag, and outgoing-recovery ciphertext prevents a relayer from swapping discovery or sender-recovery data.

The on-chain contract verifies `H(posted_calldata) == memo_ct_hash` for each output note. If a malicious relayer or sequencer swaps the encrypted memo data in transit, the hash won't match and the contract rejects the transaction.

## On-Chain Note Data

Each output note in a transaction carries the following on-chain data:

```
cm              —    32 bytes   note commitment
ct_d            — 1,088 bytes   ML-KEM-768 detection ciphertext
tag             —     2 bytes   little-endian `u16`; low k bits are the detection tag, high bits are zero
ct_v            — 1,088 bytes   ML-KEM-768 memo ciphertext
nonce           —    12 bytes   derived AEAD nonce `H_mnon(H(ss_v) || plaintext)[0..12)`
encrypted_data  — 1,080 bytes   ChaCha20-Poly1305(v:8 || rseed:32 || memo:1024) + 16 auth tag
outgoing_ct     —   185 bytes   ChaCha20-Poly1305(role:1 || v:8 || rseed:32 || d_j:32 || auth_root:32 || pub_seed:32 || nk_tag:32) + 16 auth tag
                ---------
                 3,487 bytes per output note (~3.4 KB)
```

## Transaction Format

### Shield

```
proof             — ~295 KB    circuit proof (WOTS+ sig verified inside STARK)
public_outputs    —  320 B     [auth_domain, pubkey_hash, v, fee, producer_fee, cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash, asset_new] (10 x 32 bytes — multiasset)
note_data         —  6.8 KB    2 output notes
                  ----------
                  ~302 KB total (in-circuit WOTS+ signature under the recipient's auth tree binds the entire request payload)
```

### Transfer (N->recipient + up to two change notes + producer fee)

```
proof             — ~295 KB    circuit proof (WOTS+ sig verified inside STARK)
public_outputs    — (N+11)*32 B [auth_domain, root, nf_0..nf_{N-1}, fee, cm_1, cm_2, cm_3, cm_4, mh_1, mh_2, mh_3, mh_4]
note_data         — 13.6 KB    up to 4 output notes (recipient + up to two change + producer fee)
                  ----------
                  ~309 KB + 32N B  (no signatures — WOTS+ verified inside STARK)
```

For a typical N=2 transfer: ~306 KB total.

### Unshield (N->withdrawal + up to two change notes + producer fee)

```
proof             — ~295 KB    circuit proof (WOTS+ sig verified inside STARK)
public_outputs    — (N+12)*32 B [auth_domain, root, nf_0..nf_{N-1}, v_pub, asset_pub, fee, recipient_id, cm_change, mh_change, cm_change_2, mh_change_2, cm_fee, mh_fee]
note_data         — 3.4-10.2 KB up to 3 output notes (producer fee plus up to two change notes)
                  ----------
                  ~299-306 KB + 32N B  (no signatures — WOTS+ verified inside STARK)
```

For a typical N=2 unshield: ~300-306 KB total.

For transfer and unshield public-output parsing, the verifier infers the input count as:
- Transfer: `N = total_public_output_felts - 11` (subtract `auth_domain + root + fee + 4 cms + 4 mhs`).
- Unshield: `N = total_public_output_felts - 12` (subtract `auth_domain + root + v_pub + asset_pub + fee + recipient_id + 2× (cm, mh) for changes + 1× (cm, mh) for fee`).

## Domain Separation

All hashing uses BLAKE2s-256 truncated to 251 bits, with domain separation via BLAKE2s personalization (parameter block P[6..7]):

| Use | Personalization | Function |
|-----|----------------|----------|
| Key derivation | (none) | `hash1`, `hash2_generic` |
| Commitment-tree Merkle nodes | `mrklSP__` | `hash2`, `hash_merkle` |
| Nullifiers | `nulfSP__` | `nullifier` |
| Commitments | `cmmtSP__` | `commit` |
| Per-address nk_spend | `nkspSP__` | `derive_nk_spend` |
| Per-address nk_tag | `nktgSP__` | `derive_nk_tag` |
| Owner tag | `ownrSP__` | `owner_tag` |
| XMSS WOTS+ chain hash | (none) | `H_chain(pub_seed, adrs, x)` |
| XMSS L-tree / auth-tree node hash | (none) | `H_node(pub_seed, adrs, left, right)` |
| Standalone WOTS regression helper | `wotsSP__` | `hash1_wots` |
| Sighash | `sighSP__` | `sighash_fold` (in circuit + client) |
| Memo hash (client-side) | `memoSP__` | -- (not in circuit) |
| Outgoing recovery key | `ovkKSP__` | -- (client-side sender recovery) |
| Outgoing recovery nonce | `ovkNSP__` | -- (client-side sender recovery) |

The commitment tree uses `mrklSP__` for internal nodes. The XMSS address tree does **not** use that personalization; it uses unpersonalized BLAKE2s with ADRS-based domain separation via `H_node`.

## Canonical Encodings

### Felt252 Representation

All hash outputs are BLAKE2s-256 (32 bytes) with the top 5 bits cleared (`output[31] &= 0x07`), producing values in `[0, 2^251)` that fit in a felt252. Values are encoded as 32-byte little-endian arrays.

### Domain Tag Constants

Quoted labels such as `"spend"` or `"mlkem-v"` are shorthand for fixed felt252 constants. They are **not** UTF-8 strings hashed into felts.

The encoding matches the reference Rust implementation's `felt_tag` helper:

1. Interpret `UTF8(label)` as a big-endian unsigned integer `n`.
2. Encode `n` as a 32-byte little-endian felt252, zero-extended.
3. No hashing is applied to the label itself.

Equivalently, for the short ASCII labels used here, the low bytes of the felt contain the label bytes in reverse order.

Examples:

| Constant | Label | Felt252 hex (32-byte little-endian) |
|----------|-------|--------------------------------------|
| `TAG_SPEND` | `"spend"` | `646e657073000000000000000000000000000000000000000000000000000000` |
| `TAG_NK` | `"nk"` | `6b6e000000000000000000000000000000000000000000000000000000000000` |
| `TAG_ASK` | `"ask"` | `6b73610000000000000000000000000000000000000000000000000000000000` |
| `TAG_INCOMING` | `"incoming"` | `676e696d6f636e69000000000000000000000000000000000000000000000000` |
| `TAG_OUTGOING` | `"outgoing"` | `676e696f6774756f000000000000000000000000000000000000000000000000` |
| `TAG_DSK` | `"dsk"` | `6b73640000000000000000000000000000000000000000000000000000000000` |
| `TAG_VIEW` | `"view"` | `7765697600000000000000000000000000000000000000000000000000000000` |
| `TAG_DETECT` | `"detect"` | `7463657465640000000000000000000000000000000000000000000000000000` |
| `TAG_RCM` | `"rcm"` | `6d63720000000000000000000000000000000000000000000000000000000000` |
| `TAG_MLKEM_V2` | `"mlkem-v2"` | `32762d6d656b6c6d000000000000000000000000000000000000000000000000` |
| `TAG_MLKEM_D` | `"mlkem-d"` | `642d6d656b6c6d00000000000000000000000000000000000000000000000000` |
| `TAG_MLKEM_D2` | `"mlkem-d2"` | `32642d6d656b6c6d000000000000000000000000000000000000000000000000` |
| `TAG_XMSS_SK` | `"xmss-sk"` | `6b732d73736d7800000000000000000000000000000000000000000000000000` |
| `TAG_XMSS_PS` | `"xmss-ps"` | `73702d73736d7800000000000000000000000000000000000000000000000000` |
| `TAG_XMSS_CHAIN` | `"xmss-ch"` | `68632d73736d7800000000000000000000000000000000000000000000000000` |
| `TAG_XMSS_LTREE` | `"xmss-lt"` | `746c2d73736d7800000000000000000000000000000000000000000000000000` |
| `TAG_XMSS_TREE` | `"xmss-tr"` | `72742d73736d7800000000000000000000000000000000000000000000000000` |

Examples of use:

- `H("spend", master_sk)` means `H(TAG_SPEND, master_sk)`
- `H("xmss-sk", ask_j, i_felt)` means `H(TAG_XMSS_SK, ask_j, i_felt)`
- `H("rcm")` means `H(TAG_RCM)`

### Canonical Binary Wire Format

For cross-implementation interoperability, the stable protocol objects in this section have a **normative canonical binary encoding** based on **Tezos Data Encoding (TDE)**. The Rust reference implementation uses the `tezos_data_encoding` crate for this binary form, but the specification is the schema below, not the Rust crate itself.

This canonical binary format is the interoperability target for clean-room implementations. The current JSON HTTP API and proof-bundle JSON are convenience transports used by the reference CLI; they are **not** the normative binary compatibility layer.

Unless otherwise stated:

- all records are encoded in the field order listed below
- `felt252` means exactly 32 raw little-endian bytes
- `bytes[N]` means exactly `N` raw bytes
- `bytes` means a TDE dynamic byte string
- `u16le` means exactly 2 raw little-endian bytes interpreted as an unsigned 16-bit integer
- `u64le` means exactly 8 raw little-endian bytes interpreted as an unsigned 64-bit integer

The following stable objects are standardized in v1:

```text
felt252 := bytes[32]

PaymentAddress := record {
  d_j:       felt252,
  auth_root: felt252,
  pub_seed:  felt252,
  nk_tag:    felt252,
  ek_v:      bytes[1184],   // ML-KEM-768 encapsulation key
  ek_d:      bytes[1184]    // ML-KEM-768 encapsulation key
}

EncryptedNote := record {
  ct_d:           bytes[1088],   // ML-KEM-768 ciphertext
  tag:            u16le,         // detection tag, little-endian on the wire
  ct_v:           bytes[1088],   // ML-KEM-768 ciphertext
  nonce:          bytes[12],     // derived AEAD nonce
  encrypted_data: bytes[1080],   // ChaCha20-Poly1305 ciphertext+tag
  outgoing_ct:    bytes[185]     // sender-recovery ciphertext+tag
}

PublishedNote := record {
  cm:  felt252,
  enc: EncryptedNote
}

NoteMemo := record {
  index: u64le,
  cm:    felt252,
  enc:   EncryptedNote
}
```

Notes:

- `PaymentAddress` and `EncryptedNote` are consensus-relevant application objects and MUST decode exactly as above in interoperable implementations.
- `PublishedNote` is the canonical binary form of posted note data (`cm` plus memo/detection ciphertexts).
- `NoteMemo` is the canonical binary form of the reference ledger's notes feed item.
- The STARK proof envelope carries `proof_bytes` and `output_preimage` outside this canonical core schema. Proof-system verifier metadata is not caller-supplied on the consensus path; the verifier derives the canonical verifier parameters from the configured executable and the verified output preimage.
- The repository includes deterministic reference vectors for this schema in `specs/test_vectors/canonical_wire_v1.json`.

### Reference JSON Mapping

The reference CLI currently exposes JSON over HTTP. That JSON must map losslessly to the canonical binary objects above:

- `felt252` fields are serialized as lowercase hex strings of exactly 64 hex characters, no `0x` prefix, representing the 32 raw little-endian bytes
- raw byte fields are serialized as lowercase hex strings, no `0x` prefix
- `index` is serialized as a JSON integer
- canonical binary `index` is `u64le`; the JSON mapping uses the same integer value
- shield requests carry `pubkey_hash` as a `felt252` hex field
- unshield recipients remain JSON strings outside the circuit and are canonicalized before hashing into `recipient_id`

This JSON mapping is a convenience API, not the normative interoperability format.

### Deposit-Pool Identifiers

The bridge receiver for a shield deposit is a namespaced pubkey-hash recipient string:

```text
pubkey_hash         = H_pubkey(auth_domain, auth_root, auth_pub_seed, blind)
deposit_recipient   = "deposit:" || lowercase_hex_32(pubkey_hash)
```

`H_pubkey` is the sequential left-fold using BLAKE2s with the `sighSP__` personalization (the same primitive as `sighash_fold`) over a leading type-tag felt `0x04` followed by the four pubkey-hash fields. The 0x04 tag domain-separates pubkey hashes from transfer sighashes (0x01), unshield sighashes (0x02), and shield sighashes (0x03).

`auth_domain` is the deployment's frozen authentication domain. `auth_root` and `auth_pub_seed` together name a specific WOTS+ key tree that the wallet controls; only the holder of that tree's signing material can later produce a valid shield. `blind` is a per-deposit randomness the wallet derives deterministically from `master_sk` so each pool gets its own unlinkable identifier even when the same auth tree is reused.

The `deposit:` namespace is the canonical L1-bridge recipient string. It prevents a raw 64-character hex pubkey hash from being confused with hex-encoded durable bytes by rollup RPC clients. The bridge MUST reject non-canonical deposit recipients, including missing prefixes, mixed-case hex, and malformed lengths.

#### Aggregated Deposit Pools

The kernel maintains a single per-pool aggregated balance:

- `deposit_balances: HashMap<pubkey_hash, u64>` — open pool balances. A pool with zero balance is removed from storage to bound durable footprint.

Each L1 ticket addressed to `deposit:<hex(pubkey_hash)>` increments `deposit_balances[pubkey_hash]`. Multiple tickets to the same recipient string aggregate; this is how top-ups work.

This scheme is robust against the dust-bricking attack that motivated the original per-slot scheme. Under the slot scheme, an attacker depositing 1 mutez to a victim's `deposit:<hex(intent)>` string created an "orphan slot" because the intent committed to a specific debit and the kernel demanded an exact match. Under aggregated pools, the dust just adds to the victim's pool balance — the victim drains whatever they want at shield time, and any extra mutez in the pool is the user's to drain in a follow-up shield. **Mirror-depositing is therefore a donation to the victim**, not a brick.

#### Shield Authorization (in-circuit XMSS sig)

A shield proof verifies an in-circuit WOTS+ signature under the recipient's auth tree, mirroring the structure used by transfer and unshield. The signature signs `fold(0x03, auth_domain, pubkey_hash, v_pub, fee, producer_fee, cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash)`, so it binds the entire request payload. A delegated prover with the witness still cannot redirect funds, change values, or swap recipients because they don't have access to the wallet's WOTS+ signing material.

This makes the wallet **not stateless**: each shield consumes one WOTS+ key index from the recipient's auth tree (the same index management used for transfer and unshield).

Top-ups, partial drains, and abandoned deposits are all natural under this scheme:

- **Top-up**: send another L1 ticket to the same `deposit:<hex(pubkey_hash)>` recipient. The pool's balance increments. No new pool record is allocated.
- **Partial drain**: the user picks `(v, fee, producer_fee)` at shield time. The kernel debits exactly that, leaves the rest. The same pool can be drained by multiple shields.
- **Abandoned deposits**: a user whose wallet is offline indefinitely can never sign a shield, so the funds remain locked. There is no protocol-level recall mechanism in this version of the design — abandonment is the user's responsibility. (Future versions may add an L1-recall escape hatch.)

#### Privacy of Aggregation

Multiple L1 deposits to the same `deposit:<hex(pubkey_hash)>` recipient are publicly correlatable on L1 (they share the same recipient string). Whether a deposit reuses an existing pool or creates a fresh one is the wallet's choice. The reference wallet's `tzel-wallet deposit --amount <v>` always allocates a fresh pool (a new auth-tree address plus a new `deposit_nonce`-derived blind), so deposits are unlinkable by default. Wallets that want top-up convenience can pin to a previously-used pool, but the reference CLI doesn't expose a flag for that yet.

### L1 Withdrawal Recipient Encoding

The reference clients represent unshield recipients as canonical Tezos L1 account
or contract strings outside the circuit and hash them into felt public outputs:

```text
canonical_recipient = trim(recipient_string)
recipient_id        = H(UTF8(canonical_recipient))
```

using unpersonalized BLAKE2s-256 truncated to 251 bits.

- Unshield proves `recipient_id = H(UTF8(canonical_recipient))`
- The submitted string is trimmed, validated as a canonical `tz1` / `tz2` / `tz3` / `KT1` Base58Check value, then re-hashed and compared to the proved felt

This string serialization is part of the consensus binding. Any deployment that changes accepted recipient types or canonicalization rules MUST version that rule explicitly.

### Merkle Tree Structure

Both the commitment tree and auth key tree use left-right BLAKE2s Merkle trees:

- **Leaf encoding:** leaves are raw felt252 values (32 bytes), not hashed before insertion.
- **Internal nodes:** `H_merkle(left, right)` using the `mrklSP__` personalization.
- **Zero nodes:** derived recursively: `zero[0] = [0u8; 32]`, `zero[d+1] = H_merkle(zero[d], zero[d])`.
- **Append-only:** the commitment tree is append-only. New leaves are added at the next available index. The root is recomputed after each append.
- **Bit ordering:** Merkle path indices use the standard convention: bit 0 of `pos` selects left (0) or right (1) at depth 0 (leaf level), bit 1 at depth 1, etc.

### Position and Index Canonicalization

- **Commitment tree position `pos`:** MUST satisfy `0 <= pos < 2^TREE_DEPTH` (TREE_DEPTH=48). The Cairo circuit enforces this by checking all `path_indices` bits are 0 or 1, and rejecting the path if any bit beyond depth TREE_DEPTH is set (`src/merkle.cairo:77-81`). This prevents alias nullifiers via `pos = real_pos + k*2^TREE_DEPTH`.
- **Auth tree key index `key_idx`:** MUST satisfy `0 <= key_idx < 2^AUTH_DEPTH` (AUTH_DEPTH=16). The circuit rejects out-of-range indices. This prevents aliasing of auth tree leaves.
- **Values `v`:** MUST be u64. Arithmetic uses u128 to prevent overflow. The circuit enforces this via felt-to-u64 conversion.

### Memo-Hash Preimage

The `memo_ct_hash` public output is defined as:

```
memo_ct_hash = H_memo(ct_d || tag_le || ct_v || nonce || encrypted_data || outgoing_ct)
```

where:

- `ct_d` is the ML-KEM-768 detection ciphertext (1088 bytes)
- `tag_le` is the 2-byte little-endian encoding of `tag_u16 = LE16(H(ss_d)[0], H(ss_d)[1]) & ((1 << k) - 1)`
- `ct_v` is the ML-KEM-768 viewing ciphertext (1088 bytes)
- `nonce` is the 12-byte derived AEAD nonce
- `encrypted_data` is the ChaCha20-Poly1305 ciphertext (1080 bytes)
- `outgoing_ct` is the ChaCha20-Poly1305 sender-recovery ciphertext (185 bytes)
- `H_memo` uses the `memoSP__` personalization, truncated to 251 bits

The on-chain contract verifies that hashing the posted note data (exactly these six fields in this order) produces the `memo_ct_hash` from the proof's public outputs. The commitment (`cm`) is NOT included in this hash — it is verified separately via the commitment binding check.
