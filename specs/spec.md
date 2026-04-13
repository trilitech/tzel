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
└── incoming_seed = H(TAG_INCOMING, master_sk)
    ├── dsk         = H(TAG_DSK, incoming_seed)     — diversifier derivation key
    │   └── d_j     = H(dsk, j)                   — diversified address index
    ├── view_root   = H(TAG_VIEW, incoming_seed)    — root for per-address ML-KEM viewing keys
    │   └── seed_v_j = KDF_view(view_root, j)     — exact KDF defined below
    │       └── (ek_v_j, dk_v_j) = ML-KEM-768.KeyGenDet(seed_v_j)
    └── detect_root = H(TAG_DETECT, view_root)      — root for per-address detection keys
        └── seed_d_j = KDF_detect(detect_root, j) — exact KDF defined below
            └── (ek_d_j, dk_d_j) = ML-KEM-768.KeyGenDet(seed_d_j)
```

**Spending branch** holds nullifier material (`nk`) and authorization (`ask`). **Incoming branch** holds address diversification and incoming memo keys. The two branches are independent — address material reveals nothing about spending keys.

The current protocol does NOT include an outgoing viewing key or a sender-recovery ciphertext. Full-view capability means "incoming viewing plus nullifier / spent-state tracking", not "recover sent notes".

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
| **Full view** | `(nk, incoming_seed)` | Above + compute nullifiers + track spent/unspent for notes whose address metadata is known |
| **Spend** | `(nk, ask_base, incoming_seed)` | Above + authorize transactions |

Detection ⊂ incoming view ⊂ full view ⊂ spend. Each level strictly adds capability.

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
rcm         = H(H(TAG_RCM), rseed)                       — commitment randomness
owner_tag   = H_owner(auth_root_j, pub_seed_j, nk_tag_j) — fuses the XMSS public key + nullifier binding
cm          = H_commit(d_j, v, rcm, owner_tag)           — note commitment
nf          = H_nf(nk_spend_j, H_nf(cm, pos))           — position-dependent nullifier
```

The commitment binds to the diversified address, value, and owner tag (which fuses the auth key tree root and nullifier key material). The nullifier uses the per-address `nk_spend_j` and includes the leaf position to prevent faerie gold attacks.

### Position-Dependent Nullifiers

The nullifier includes the Merkle tree leaf index (`pos`):

```
nf = H_nf(nk_spend, H_nf(cm, pos))
```

This prevents an attacker from creating two identical commitments (same d_j, v, rcm, owner_tag) that resolve to a single nullifier. With position in the nullifier, each tree insertion produces a unique nullifier even for duplicate commitments.

## Transaction Types

### Shield (public -> private)

**Public outputs:** `[v_pub, cm_new, sender_id, memo_ct_hash]`

`sender_id` is defined in [Public Account Identifier Encoding](#public-account-identifier-encoding). `auth_root` does NOT appear in the public outputs; it is a private input used only to compute `owner_tag`.

**Circuit constraints:**
1. `rcm = H(H(TAG_RCM), rseed)`
2. `owner_tag = H_owner(auth_root, pub_seed, nk_tag)` where `auth_root`, `pub_seed`, and `nk_tag` are private inputs from the recipient's payment address
3. `cm_new = H_commit(d_j, v_pub, rcm, owner_tag)`

`memo_ct_hash` is computed client-side as `H(ct_d || tag || ct_v || nonce || encrypted_data)` — covering ALL on-chain note data — and passed into the circuit as a public input.

**Contract / ledger checks:** proof valid, sender binding per [Shield sender binding](#shield-sender-binding), `H(posted_memo_calldata) == memo_ct_hash`.

**State changes:** deduct `v_pub` from sender, append `cm_new` to T.

### Transfer (N->2, where 1 <= N <= 7)

Consumes N private notes and creates exactly 2 new private notes. Handles splits (N=1), standard transfers (N=2), and consolidations (N>2) with a single circuit. N is a runtime parameter, not a program parameter — the program hash is the same for all N.

**Public outputs:** `[auth_domain, root, nf_0..nf_{N-1}, cm_1, cm_2, memo_ct_hash_1, memo_ct_hash_2]`

XMSS-style WOTS+ signature verification happens inside the STARK. No auth leaves, public keys, or signatures appear in the public outputs.

**Circuit constraints:**
1. For each input i (0..N):
   - `rcm_i = H(H(TAG_RCM), rseed_i)`
   - `nk_tag_i = H_nktg(nk_spend_i)`
   - `owner_tag_i = H_owner(auth_root_i, pub_seed_i, nk_tag_i)`
   - `cm_i = H_commit(d_j_i, v_i, rcm_i, owner_tag_i)`
   - Merkle membership of `cm_i` at position `pos_i` against `root` (commitment tree)
   - `nf_i = H_nf(nk_spend_i, H_nf(cm_i, pos_i))`
   - XMSS-style WOTS+ verification: the circuit computes the sighash from the public outputs, decomposes it into 128 base-4 digits + 5 checksum digits, then for each of the 133 chains recovers the final public-key endpoint with `H_chain^{w-1-digit}(sig_j, pub_seed_i, ADRS_j)`. The digits are NOT witness data — they are deterministically derived inside the circuit.
   - `auth_leaf_i = LTree(pub_seed_i, key_idx_i, pk_0, ..., pk_132)` from those recovered chain endpoints
   - Merkle membership of that exact `auth_leaf_i` at position `key_idx_i` against `auth_root_i` using the XMSS tree-node hash (auth key tree)
2. All nullifiers pairwise distinct
3. For both outputs:
   - `owner_tag_out = H_owner(auth_root_out, pub_seed_out, nk_tag_out)` where `auth_root_out`, `pub_seed_out`, and `nk_tag_out` are private inputs from the recipient's payment address
   - `cm_out = H_commit(d_j_out, v_out, rcm_out, owner_tag_out)`
4. `sum(v_inputs) = v_1 + v_2` (in u128)
5. All values are u64 (implicit range check)

**Contract checks:** proof valid. No signature verification needed — the STARK proof proves spend authorization.

### Unshield (N->withdrawal + optional change, where 1 <= N <= 7)

Consumes N private notes, releases `v_pub` to a public address, and optionally creates one private change note.

**Public outputs:** `[auth_domain, root, nf_0..nf_{N-1}, v_pub, recipient_id, cm_change, memo_ct_hash_change]`

`recipient_id` is defined in [Public Account Identifier Encoding](#public-account-identifier-encoding).

`cm_change` and `memo_ct_hash_change` are 0 if no change output.

**Circuit constraints:**
1. Same per-input verification as Transfer (including auth tree membership proof and WOTS+ signature verification)
2. All nullifiers pairwise distinct
3. If change:
   - `owner_tag_c = H_owner(auth_root_c, pub_seed_c, nk_tag_c)` where `auth_root_c`, `pub_seed_c`, and `nk_tag_c` are private inputs
   - `cm_change = H_commit(d_j_c, v_change, rcm_c, owner_tag_c)`
4. If no change: all change witness data constrained to zero (`v_change`, `d_j_change`, `rseed_change`, `auth_root_change`, `pub_seed_change`, `nk_tag_change`, `memo_ct_hash_change` = 0) to eliminate prover malleability
5. `sum(v_inputs) = v_pub + v_change`

**Contract / ledger checks:** proof valid. Verify recipient binding per [Public Account Identifier Encoding](#public-account-identifier-encoding), credit `v_pub` to that recipient account, append `cm_change` to T (if nonzero). No signature verification needed — the STARK proof proves spend authorization.

## Contract Consensus Rules

The circuit proves constraints over private inputs. The on-chain contract enforces all remaining consensus rules. These are **not optional** — omitting any of them breaks the security model.

### Root validation (all spending transactions)

The contract maintains an append-only set of historical Merkle roots (anchors). For every transfer or unshield, the contract MUST verify that `root` (from the proof's public outputs) is a member of this set. Rejection of unknown roots prevents an attacker from constructing a fake tree containing self-chosen notes and "spending" them with a valid proof against that fake root.

### Authorization-domain validation (all spending transactions)

The contract or verifier environment MUST verify that `auth_domain` (from the proof's public outputs) equals the deployment's configured spend-authorization domain. Rejection of mismatched domains prevents replay of a valid spend authorization onto a mirrored deployment, fork, or verifier migration that shares the same Merkle root history.

### Executable binding (all proof-verified transactions)

If proofs are produced through a bootloader or recursive verifier wrapper, the verifier environment MUST also authenticate which circuit executable was actually proved. In the reference implementation this means checking the bootloader-reported task program hash against the deployment's expected `run_shield`, `run_transfer`, or `run_unshield` executable hash before interpreting the public outputs. Verifying "some valid Cairo task" is not sufficient.

### Global nullifier uniqueness (all spending transactions)

The circuit enforces pairwise nullifier distinctness within a single transaction (`nf_i != nf_j`). The contract MUST additionally reject any `nf_i` that already exists in the global on-chain nullifier set. This prevents double-spends across transactions. After validation, the contract inserts all `nf_i` into the global set.

### Commitment binding (all transactions with outputs)

For each output note, the contract MUST verify that the `cm` in the posted note data exactly matches the corresponding `cm` in the proof's public outputs. This binds the on-chain note data (encrypted memo, detection ciphertext) to the proven commitment.

### Memo integrity (all transactions with outputs)

For each output note, the contract MUST verify `H(posted_note_calldata) == memo_ct_hash` where `memo_ct_hash` is from the proof's public outputs. This prevents relayers or sequencers from swapping or stripping memo data.

### Shield sender binding

For shield transactions, the verifier environment MUST bind the submitted public sender account to the proved `sender_id` using the exact rule defined in [Public Account Identifier Encoding](#public-account-identifier-encoding).

### Spend authorization (all spending transactions)

WOTS+ signature verification happens entirely inside the STARK circuit. The contract does not verify any signatures — it only verifies the STARK proof. A valid proof guarantees that:
1. Each input note's WOTS+ key is a leaf in the spender's auth tree (bound to the spent commitment)
2. A valid WOTS+ signature over the sighash was provided for each input

No public keys, auth leaves, or signatures appear in the public outputs or on-chain calldata.

### Sighash

The WOTS+ signature inside the STARK binds to the transaction's public outputs. The sighash is computed inside the circuit by folding all public outputs with a circuit-type tag using the `sighSP__` personalization:

```
// Transfer (type_tag = 0x01):
sighash = fold(0x01, auth_domain, root, nf_0, ..., nf_{N-1}, cm_1, cm_2, mh_1, mh_2)

// Unshield (type_tag = 0x02):
sighash = fold(0x02, auth_domain, root, nf_0, ..., nf_{N-1}, v_pub, recipient_id, cm_change, mh_change)
```

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
2. User gives the prover per-input: `(nk_spend_j, auth_root_j, wots_sig_i, auth_tree_path_i, d_j, v, rseed, commitment_tree_path, pos)`, plus output data including `auth_root` and `nk_tag` for output notes.
3. Prover generates the STARK proof. The WOTS+ signature is verified inside the circuit.
4. Prover returns proof to user. Public outputs contain only `[auth_domain, root, nullifiers, commitments, memo hashes]` — no auth leaves, public keys, or signatures.
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

## Wallet Note Acceptance

Detection and successful memo decryption are only candidate filters. A wallet MUST accept an incoming note as belonging to one of its addresses only if it can match the note against locally known address metadata and recompute the commitment exactly:

1. Select a local address record containing `(d_j, auth_root_j, pub_seed_j, nk_tag_j)` for the candidate recipient address.
2. Decrypt the note to obtain `(v, rseed, memo)`.
3. Recompute `rcm = H(H(TAG_RCM), rseed)`.
4. Recompute `owner_tag = H_owner(auth_root_j, pub_seed_j, nk_tag_j)`.
5. Recompute `cm_expected = H_commit(d_j, v, rcm, owner_tag)`.
6. Accept the note only if `cm_expected == cm` from chain data. Otherwise reject it as malformed, non-local, or unspendable.

## User Memo

Each note carries a 1024-byte user memo field, encrypted alongside `(v, rseed)` inside the AEAD ciphertext. The memo can contain arbitrary data: payment references, return addresses, human-readable messages, or structured metadata.

Memo format conventions (following Zcash ZIP 302):

- If the first byte is <= 0xF4: the memo is a UTF-8 string, zero-padded.
- If the first byte is 0xF6: "no memo" (remainder is zeros).
- If the first byte is >= 0xF5: application-defined binary format.

The memo is end-to-end encrypted — only the recipient (with `dk_v`) can read it. The on-chain ciphertext reveals nothing about the memo content or length (all memos are padded to exactly 1024 bytes before encryption).

## Memo Integrity (Anti-Tampering)

Each circuit includes a `memo_ct_hash` per output note in its public outputs. This is a hash of ALL on-chain note data (`H(ct_d || tag || ct_v || nonce || encrypted_data)`), computed **client-side** before proving. The circuit does not compute it — it simply passes it through as a public output. Including the detection ciphertext and tag prevents a relayer from swapping detection data to redirect note discovery.

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
                ---------
                 3,302 bytes per output note (~3.2 KB)
```

## Transaction Format

### Shield

```
proof             — ~295 KB    circuit proof (ZK, two-level recursive STARK)
public_outputs    —  128 B     [v_pub, cm_new, sender_id, memo_ct_hash] (4 x 32 bytes)
note_data         —  3.2 KB    1 output note
                  ----------
                  ~298 KB total (no spend signature — sender bound by external verifier check)
```

### Transfer (N->2)

```
proof             — ~295 KB    circuit proof (WOTS+ sig verified inside STARK)
public_outputs    — (N+6)*32 B  [auth_domain, root, nf_0..nf_{N-1}, cm_1, cm_2, mh_1, mh_2]
note_data         —  6.4 KB    2 output notes
                  ----------
                  ~301 KB + 32N B  (no signatures — WOTS+ verified inside STARK)
```

For a typical N=2 transfer: ~302 KB total.

### Unshield (N->withdrawal + change)

```
proof             — ~295 KB    circuit proof (WOTS+ sig verified inside STARK)
public_outputs    — (N+6)*32 B  [auth_domain, root, nf_0..nf_{N-1}, v_pub, recipient_id, cm_change, mh_change]
note_data         — 0-3.2 KB   0 or 1 change note
                  ----------
                  ~295-299 KB + 32N B  (no signatures — WOTS+ verified inside STARK)
```

For a typical N=2 unshield: ~296-299 KB total.

For transfer and unshield public-output parsing, the verifier infers the input count as `N = total_public_output_felts - 6`. That is, after the leading `auth_domain` and `root`, the final four felts are fixed-format outputs and the remaining middle slice is the nullifier list.

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
| `TAG_DSK` | `"dsk"` | `6b73640000000000000000000000000000000000000000000000000000000000` |
| `TAG_VIEW` | `"view"` | `7765697600000000000000000000000000000000000000000000000000000000` |
| `TAG_DETECT` | `"detect"` | `7463657465640000000000000000000000000000000000000000000000000000` |
| `TAG_RCM` | `"rcm"` | `6d63720000000000000000000000000000000000000000000000000000000000` |
| `TAG_MLKEM_V` | `"mlkem-v"` | `762d6d656b6c6d00000000000000000000000000000000000000000000000000` |
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
  encrypted_data: bytes[1080]    // ChaCha20-Poly1305 ciphertext+tag
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
- The STARK proof envelope (`proof bytes`, `output_preimage`, verifier metadata) is intentionally **not** part of this canonical core schema yet. It is verifier-stack-specific and remains a reference-implementation transport detail in this version of the spec.
- The repository includes deterministic reference vectors for this schema in `specs/test_vectors/canonical_wire_v1.json`.

### Reference JSON Mapping

The reference CLI currently exposes JSON over HTTP. That JSON must map losslessly to the canonical binary objects above:

- `felt252` fields are serialized as lowercase hex strings of exactly 64 hex characters, no `0x` prefix, representing the 32 raw little-endian bytes
- raw byte fields are serialized as lowercase hex strings, no `0x` prefix
- `index` is serialized as a JSON integer
- canonical binary `index` is `u64le`; the JSON mapping uses the same integer value
- public sender / recipient account identifiers remain JSON strings outside the circuit

This JSON mapping is a convenience API, not the normative interoperability format.

### Public Account Identifier Encoding

The current reference ledger represents public sender / recipient accounts as UTF-8 strings outside the circuit and hashes them into felt public outputs:

```text
account_id = H(UTF8(account_string))
```

using unpersonalized BLAKE2s-256 truncated to 251 bits.

- Shield proves `sender_id = account_id(sender_string)`
- Unshield proves `recipient_id = account_id(recipient_string)`
- The submitted string is checked by re-hashing it and comparing to the proved felt

The reference CLI ledger's string-based public accounts are intentionally a demo-only stand-in for verifier-environment identity. They are suitable for local testing and for illustrating what the proof must bind, but not as a secure networked account model. Deployments that replace this with chain-native addresses MUST specify the exact byte serialization and verifier check. "Address" alone is not a sufficient consensus definition.

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
memo_ct_hash = H_memo(ct_d || tag_le || ct_v || nonce || encrypted_data)
```

where:

- `ct_d` is the ML-KEM-768 detection ciphertext (1088 bytes)
- `tag_le` is the 2-byte little-endian encoding of `tag_u16 = LE16(H(ss_d)[0], H(ss_d)[1]) & ((1 << k) - 1)`
- `ct_v` is the ML-KEM-768 viewing ciphertext (1088 bytes)
- `nonce` is the 12-byte derived AEAD nonce
- `encrypted_data` is the ChaCha20-Poly1305 ciphertext (1080 bytes)
- `H_memo` uses the `memoSP__` personalization, truncated to 251 bits

The on-chain contract verifies that hashing the posted note data (exactly these five fields in this order) produces the `memo_ct_hash` from the proof's public outputs. The commitment (`cm`) is NOT included in this hash — it is verified separately via the commitment binding check.
