# StarkPrivacy v2: Post-Quantum Private Transaction Spec

**WARNING: This protocol is under active development. Neither the design nor the implementation should be assumed secure. Do not use for real value.**

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

```text
master_sk
├── spend_seed = H("spend", master_sk)
│   ├── nk         = H("nk",  spend_seed)        — account nullifier root (never leaves user)
│   │   └── nk_spend_j = H_nksp(nk, d_j)         — per-address secret nullifier key
│   │       └── nk_tag_j  = H_nktg(nk_spend_j)   — per-address public binding tag
│   ├── ask_base   = H("ask", spend_seed)         — base authorization secret
│   │   └── ask_j  = H(ask_base, j)               — per-address auth secret
│   │       └── seed_i = H(H("auth-key", ask_j), i) — per-key WOTS+ seed
│   │           └── pk_i = WOTS+.KeyGen(seed_i)   — 133 chain endpoints (w=4)
│   │       └── auth_root_j = MerkleRoot(fold(pk_0), ..., fold(pk_{K-1}))
│   └── ovk        = H("ovk", spend_seed)         — outgoing viewing key
│
└── incoming_seed = H("incoming", master_sk)
    ├── dsk         = H("dsk", incoming_seed)     — diversifier derivation key
    │   └── d_j     = H(dsk, j)                   — diversified address index
    ├── view_seed   = H("view", incoming_seed)    — per-address ML-KEM viewing keys
    │   └── (ek_v_j, dk_v_j) = ML-KEM.KeyGen(H("mlkem-view", view_seed, j))
    └── det_seed    = H("detect", view_seed)      — detection keys (detect ⊂ view)
        └── (ek_d_j, dk_d_j) = ML-KEM.KeyGen(H("mlkem-detect", det_seed, j))
```

**Spending branch** holds nullifier material (nk), authorization (ask), and outgoing view (ovk). **Incoming branch** holds address diversification (dsk), memo encryption (view_seed), and detection (det_seed). The two branches are independent — address material reveals nothing about spending keys.

### Auth Key Tree

Each address `j` has a Merkle tree of K one-time WOTS+ public keys (K = 2^AUTH_DEPTH, default AUTH_DEPTH = 10, giving 1024 keys per address). The scheme is a Winternitz-style one-time signature inspired by WOTS+ (RFC 8391 / XMSS), instantiated with BLAKE2s and w=4 (133 hash chains: 128 message + 5 checksum). It uses project-specific domain-separated hash functions (`wotsSP__` for chain hashing, `pkfdSP__` for public key folding) rather than the exact XMSS WOTS+ parameterization — the security argument is equivalent (one-time unforgeability from second-preimage resistance of the hash function) but the construction is self-contained. The tree is constructed at address generation time:

1. For each index i in 0..K: `seed_i = H(H("auth-key", ask_j), i)`
2. `pk_i = WOTS+.KeyGen(seed_i)` — 133 chain endpoints derived from seed via BLAKE2s hash chains
3. `leaf_i = fold(pk_0, pk_1, ..., pk_132)` — sequential left-fold of the 133 chain endpoints using `H_pkfold`
4. `auth_root_j = MerkleRoot(leaf_0, ..., leaf_{K-1})` — binary Merkle tree using `H_merkle` (see Canonical Encodings for tree structure)

The `auth_root_j` is included in the payment address and bound into commitments via `owner_tag`. Each key is used at most once. When spending, the STARK proves the chosen `pk_i` is a leaf in the tree and verifies the WOTS+ signature inside the circuit. No auth leaf, public key, or signature appears in the public outputs — the STARK proof itself proves spend authorization.

After exhausting all K keys for an address, generate a new address (increment j).

### Per-Address Nullifier Keys

The account-level `nk` never leaves the user's device. Instead, each address derives:

- `nk_spend_j = H_nksp(nk, d_j)` — per-address secret, given to the prover for a specific note
- `nk_tag_j = H_nktg(nk_spend_j)` — per-address public tag, included in the payment address

These are bound into the commitment via an owner tag:

- `owner_tag_j = H_owner(auth_root_j, nk_tag_j)` — fuses auth root + nullifier binding

This ensures the commitment cryptographically binds to the nullifier key material. Given a commitment `cm`, an attacker who wants to spend it with a fake `nk'` would need to find values that produce the same commitment under `H_commit`, which requires a second-preimage. Note that `auth_root_j` is public in the payment address (the sender needs it to create notes) but stays private on-chain (it never appears in proof outputs). The security rests on the collision resistance of `H_owner` and `H_commit`.

## Capability Levels

| Capability | Keys held | Can do |
|------------|-----------|--------|
| **Detection** | `dk_d_j` for address j | Flag candidate transactions (with tunable false positives) |
| **Incoming view** | `(dsk, view_seed)` | Decrypt all memos across all addresses |
| **Full view** | `(nk, dsk, view_seed, ovk)` | Above + compute nullifiers + track spent/unspent + recover sent notes |
| **Spend** | Full view + `ask_base` | Above + authorize transactions |

Detection ⊂ incoming view ⊂ full view ⊂ spend. Each level strictly adds capability.

## Payment Address

What the sender receives:

```
address_j = (d_j, auth_root_j, nk_tag_j, ek_v_j, ek_d_j)
```

- `d_j` — diversifier (32 bytes): identifies the address, appears in the note commitment
- `auth_root_j` — auth key tree root (32 bytes): bound into the commitment; stays private on-chain
- `nk_tag_j` — nullifier binding tag (32 bytes): binds the commitment to the owner's nullifier key
- `ek_v_j` — ML-KEM encapsulation key (~1184 bytes): sender encrypts memos with this
- `ek_d_j` — ML-KEM encapsulation key (~1184 bytes): sender creates detection clues with this

Multiple addresses can be generated from one account (varying j). Each address has unrelated `d_j` values. ML-KEM ciphertexts are randomized per encapsulation, so observers cannot link two transactions to the same recipient.

For circuit purposes, `d_j`, `auth_root_j`, and `nk_tag_j` matter. The ML-KEM keys are application-layer.

## Note Structure

```
rseed       — random per-note seed
rcm         = H(H("rcm"), rseed)                         — commitment randomness
owner_tag   = H_owner(auth_root_j, nk_tag_j)            — fuses auth root + nullifier binding
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

### Why Owner Tags

Without owner tags, the commitment `cm = H(d_j, v, rcm)` would not bind to the nullifier key. An attacker could:

1. Observe `cm` on-chain
2. Choose an arbitrary `nk'`
3. Compute `nf' = H(nk', cm)` — a fresh, unused nullifier
4. Produce a valid proof showing `nf'` has never been spent

This allows unlimited double-spending from a single note. The owner tag fix binds `nk_spend -> nk_tag -> owner_tag -> cm`, creating a unique chain from the nullifier key to the commitment.

## Transaction Types

### Shield (public -> private)

**Public outputs:** `[v_pub, cm_new, sender, memo_ct_hash]`

Note: `auth_root` does NOT appear in the public outputs. It is a private input used only to compute `owner_tag`.

**Circuit constraints:**
1. `rcm = H(H("rcm"), rseed)`
2. `owner_tag = H_owner(auth_root, nk_tag)` where both `auth_root` and `nk_tag` are private inputs from the recipient's payment address
3. `cm_new = H_commit(d_j, v_pub, rcm, owner_tag)`

Note: the circuit cannot verify that `auth_root` or `nk_tag` are correctly derived because the sender does not have the recipient's secrets. Incorrect values create an unspendable note — the deposited tokens are permanently locked. This is a sender-griefing risk: a malicious or buggy sender can burn their deposit by using incorrect recipient address components. The spending circuits (transfer/unshield) enforce the full derivation chain when the note is later spent.

`memo_ct_hash` is computed client-side as `H(ct_d || tag || ct_v || encrypted_data)` — covering ALL on-chain note data — and passed into the circuit as a public input.

**Contract checks:** proof valid, `msg.sender == sender`, `H(posted_memo_calldata) == memo_ct_hash`.

**State changes:** deduct `v_pub` from sender, append `cm_new` to T.

Shield requires no spend authorization — the depositor is authenticated by `msg.sender`.

### Transfer (N->2, where 1 <= N <= 16)

Consumes N private notes and creates exactly 2 new private notes. Handles splits (N=1), standard transfers (N=2), and consolidations (N>2) with a single circuit. N is a runtime parameter, not a program parameter — the program hash is the same for all N.

**N is not private.** The number of published nullifiers reveals the input count. This is inherent to per-input nullifier publication.

**Public outputs:** `[auth_domain, root, nf_0..nf_{N-1}, cm_1, cm_2, memo_ct_hash_1, memo_ct_hash_2]`

WOTS+ signature verification happens inside the STARK. No auth leaves, public keys, or signatures appear in the public outputs.

**Circuit constraints:**
1. For each input i (0..N):
   - `rcm_i = H(H("rcm"), rseed_i)`
   - `nk_tag_i = H_nktg(nk_spend_i)`
   - `owner_tag_i = H_owner(auth_root_i, nk_tag_i)`
   - `cm_i = H_commit(d_j_i, v_i, rcm_i, owner_tag_i)`
   - Merkle membership of `cm_i` at position `pos_i` against `root` (commitment tree)
   - `nf_i = H_nf(nk_spend_i, H_nf(cm_i, pos_i))`
   - Merkle membership of `auth_leaf_i` at position `key_idx_i` against `auth_root_i` (auth key tree)
   - WOTS+ signature verification: the circuit computes the sighash from the public outputs, decomposes it into 128 base-4 digits + 5 checksum digits, then for each of the 133 chains verifies `H_wots^{w-1-digit}(sig_j) == pk_j`. The digits are NOT witness data — they are deterministically derived inside the circuit.
2. All nullifiers pairwise distinct
3. For both outputs:
   - `owner_tag_out = H_owner(auth_root_out, nk_tag_out)` where `auth_root_out` and `nk_tag_out` are private inputs from the recipient's payment address
   - `cm_out = H_commit(d_j_out, v_out, rcm_out, owner_tag_out)`
   - Note: same caveat as shield — incorrect `auth_root_out` or `nk_tag_out` creates an unspendable output (self-griefing by the spender)
4. `sum(v_inputs) = v_1 + v_2` (in u128)
5. All values are u64 (implicit range check)

**Contract checks:** proof valid. No signature verification needed — the STARK proof proves spend authorization.

### Unshield (N->withdrawal + optional change, where 1 <= N <= 16)

Consumes N private notes, releases `v_pub` to a public address, and optionally creates one private change note.

**Public outputs:** `[auth_domain, root, nf_0..nf_{N-1}, v_pub, recipient, cm_change, memo_ct_hash_change]`

`cm_change` and `memo_ct_hash_change` are 0 if no change output.

**Circuit constraints:**
1. Same per-input verification as Transfer (including auth tree membership proof and WOTS+ signature verification)
2. All nullifiers pairwise distinct
3. If change:
   - `owner_tag_c = H_owner(auth_root_c, nk_tag_c)` where `auth_root_c` and `nk_tag_c` are private inputs
   - `cm_change = H_commit(d_j_c, v_change, rcm_c, owner_tag_c)`
4. If no change: all change witness data constrained to zero (`v_change`, `d_j_change`, `rseed_change`, `auth_root_change`, `nk_tag_change`, `memo_ct_hash_change` = 0) to eliminate prover malleability
5. `sum(v_inputs) = v_pub + v_change`

**Contract checks:** proof valid. Credit `v_pub` to `recipient`, append `cm_change` to T (if nonzero). No signature verification needed — the STARK proof proves spend authorization.

### Why N->2 eliminates dummy notes

With N=1 supported natively, there is no second input slot to fill. The only "dummies" are zero-value *outputs* (when change is exactly zero), which are fresh commitments created on the fly — no pre-shielding required.

## Contract Consensus Rules

The circuit proves constraints over private inputs. The on-chain contract enforces all remaining consensus rules. These are **not optional** — omitting any of them breaks the security model.

### Root validation (all spending transactions)

The contract maintains an append-only set of historical Merkle roots (anchors). For every transfer or unshield, the contract MUST verify that `root` (from the proof's public outputs) is a member of this set. Rejection of unknown roots prevents an attacker from constructing a fake tree containing self-chosen notes and "spending" them with a valid proof against that fake root.

### Authorization-domain validation (all spending transactions)

The contract or verifier environment MUST verify that `auth_domain` (from the proof's public outputs) equals the deployment's configured spend-authorization domain. Rejection of mismatched domains prevents replay of a valid spend authorization onto a mirrored deployment, fork, or verifier migration that shares the same Merkle root history.

### Global nullifier uniqueness (all spending transactions)

The circuit enforces pairwise nullifier distinctness within a single transaction (`nf_i != nf_j`). The contract MUST additionally reject any `nf_i` that already exists in the global on-chain nullifier set. This prevents double-spends across transactions. After validation, the contract inserts all `nf_i` into the global set.

### Commitment binding (all transactions with outputs)

For each output note, the contract MUST verify that the `cm` in the posted note data exactly matches the corresponding `cm` in the proof's public outputs. This binds the on-chain note data (encrypted memo, detection ciphertext) to the proven commitment.

### Memo integrity (all transactions with outputs)

For each output note, the contract MUST verify `H(posted_note_calldata) == memo_ct_hash` where `memo_ct_hash` is from the proof's public outputs. This prevents relayers or sequencers from swapping or stripping memo data.

### Shield sender binding

For shield transactions, the contract MUST verify `msg.sender == sender` (from the proof's public outputs) to prevent front-running of shield proofs.

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
sighash = fold(0x02, auth_domain, root, nf_0, ..., nf_{N-1}, v_pub, recipient, cm_change, mh_change)
```

`auth_domain` is a deployment-specific public input/output chosen by the verifier environment and enforced by the contract or ledger. It MUST uniquely identify the deployment context for spend authorizations. A practical derivation is `H(chain_id || contract_addr || verifier_or_program_id || deployment_salt)`, encoded canonically as a felt252.

The circuit-type tag prevents cross-circuit replay (a transfer signature cannot be used for an unshield). `auth_domain` prevents replay across mirrored deployments, forks, or verifier migrations that would otherwise share the same Merkle root history. Nullifier uniqueness still prevents replay of an already-consumed authorization on the same deployment.

**Still out of scope:** `expiry` and per-transaction `nonce` are not currently included in the sighash. They remain higher-level anti-withholding / anti-latency controls, not part of the base spend authorization proof.

### Change output handling (unshield)

If `cm_change == 0` in the proof's public outputs, the contract MUST NOT append any commitment to the tree. If `cm_change != 0`, the contract appends it.

### Tree append ordering

The contract appends commitments to the tree in sequential order (each new commitment gets the next available leaf index) and snapshots the root after each transaction. The new root is added to the historical root set. See Canonical Encodings for Merkle tree structure details.

## Delegated Proving

1. User constructs the transaction, computing the WOTS+ signature over the sighash with `sk_i` for each input.
2. User gives the prover per-input: `(nk_spend_j, auth_root_j, wots_sig_i, auth_tree_path_i, d_j, v, rseed, commitment_tree_path, pos)`, plus output data including `auth_root` and `nk_tag` for output notes.
3. Prover generates the STARK proof (expensive, ~30-50 seconds). The WOTS+ signature is verified inside the circuit.
4. Prover returns proof to user. Public outputs contain only `[auth_domain, root, nullifiers, commitments, memo hashes]` — no auth leaves, public keys, or signatures.
5. Transaction (proof + note data) submitted on-chain. No separate signatures or public keys needed.

The prover sees `nk_spend_j` (per-address nullifier key) and the WOTS+ signature, but NOT `ask_j` or any WOTS+ secret key. The prover:
- **Cannot redirect funds** — the WOTS+ signature is bound to specific output commitments via the sighash. A prover who substitutes different outputs cannot produce a valid proof because the signature verification inside the STARK would fail.
- **Cannot forge a signature** — doesn't have `sk_i`
- **Cannot link spends on-chain** — no auth leaves, public keys, or signatures appear in public outputs, so on-chain observers cannot link spends. However, the delegated prover itself sees `nk_spend_j` and `auth_root_j`, which are per-address values. If the same address is reused for multiple notes and the same proving service handles later spends, the prover can link those spends to the same address context. Unlinkability against the prover depends on address rotation and prover diversity.
- **Cannot spend other notes** — doesn't have witness data for notes not involved in this transaction

Both self-prove and delegated modes produce identical on-chain outputs.

## Why This Eliminates the ak Leak

In the previous design, `ak_j` appeared directly in the proof's public outputs, allowing the original sender (who knows `ak_j` from the payment address) to see when a note was spent. The sender cannot compute the nullifier (they don't know `nk_spend`), so without `ak_j` on-chain, spends are unlinkable.

With the auth key tree and in-STARK WOTS+ verification:
- No auth leaf, public key, or signature appears in the public outputs
- `auth_root_j` stays inside the STARK as a private input
- The sender knows `auth_root_j` but cannot extract any information from the public outputs to link back to it
- Two spends from the same address produce identical-looking on-chain outputs (just nullifiers, commitments, and memo hashes)

This achieves the same unlinkability as Zcash's randomized keys (`rk = ak + alpha*G`) but using only hash-based primitives — no elliptic curves or lattice-based signatures.

## Detection (Fuzzy Message Detection)

Detection precision `k` is a protocol constant (e.g., k=10). Per note on-chain:

```
(ss_d, ct_d)     = ML-KEM.Encaps(ek_d_j)     — encapsulate under detection key
tag              = H(ss_d)[0..k]              — k-bit detection tag
(ss_v, ct_v)     = ML-KEM.Encaps(ek_v_j)     — encapsulate under viewing key
encrypted_data   = ChaCha20-Poly1305(key=H(ss_v), nonce=0, plaintext=(v || rseed || memo))
```

The detection server (with `dk_d_j`) decapsulates `ct_d`, computes `H(ss')[0..k]`, and checks against `tag`. True matches always succeed. Non-matches succeed with probability 2^(-k) (false positives from ML-KEM's implicit rejection).

Detection assumes honest senders. A malicious sender can bypass detection by submitting bogus `ct_d`. The recipient falls back to scanning with `dk_v`.

Precision `k` should NOT be claimed to provide "plausible deniability" without modeling network throughput, user activity, and time aggregation. The false positive rate 2^(-k) is a technical parameter, not a privacy guarantee.

## User Memo

Each note carries a 1024-byte user memo field, encrypted alongside `(v, rseed)` inside the AEAD ciphertext. The memo can contain arbitrary data: payment references, return addresses, human-readable messages, or structured metadata.

Memo format conventions (following Zcash ZIP 302):
- If the first byte is <= 0xF4: the memo is a UTF-8 string, zero-padded.
- If the first byte is 0xF6: "no memo" (remainder is zeros).
- If the first byte is >= 0xF5: application-defined binary format.

The memo is end-to-end encrypted — only the recipient (with `dk_v`) can read it. The on-chain ciphertext reveals nothing about the memo content or length (all memos are padded to exactly 1024 bytes before encryption).

## Memo Integrity (Anti-Tampering)

Each circuit includes a `memo_ct_hash` per output note in its public outputs. This is a hash of ALL on-chain note data (`H(ct_d || tag || ct_v || encrypted_data)`), computed **client-side** before proving. The circuit does not compute it — it simply passes it through as a public output. Including the detection ciphertext and tag prevents a relayer from swapping detection data to redirect note discovery.

The on-chain contract verifies `H(posted_calldata) == memo_ct_hash` for each output note. If a malicious relayer or sequencer swaps the encrypted memo data in transit, the hash won't match and the contract rejects the transaction.

This prevents:
- **Memo spoofing**: a relayer replacing "Payment for invoice #42" with "Send your seed phrase to evil.com"
- **Selective censorship**: a relayer stripping memo data while keeping the proof valid

## On-Chain Note Data

Each output note in a transaction carries the following on-chain data:

```
cm              —    32 bytes   note commitment
ct_d            — 1,088 bytes   ML-KEM-768 detection ciphertext
tag             —     2 bytes   k-bit detection tag
ct_v            — 1,088 bytes   ML-KEM-768 memo ciphertext
encrypted_data  — 1,080 bytes   ChaCha20-Poly1305(v:8 || rseed:32 || memo:1024) + 16 auth tag
                ---------
                 3,290 bytes per output note (~3.2 KB)
```

## Transaction Format

### Shield

```
proof             — ~295 KB    circuit proof (ZK, two-level recursive STARK)
public_outputs    —  128 B     [v_pub, cm_new, sender, memo_ct_hash] (4 x 32 bytes)
note_data         —  3.2 KB    1 output note
                  ----------
                  ~298 KB total (no signature — sender authenticated by msg.sender)
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
public_outputs    — (N+6)*32 B  [auth_domain, root, nf_0..nf_{N-1}, v_pub, recipient, cm_change, mh_change]
note_data         — 0-3.2 KB   0 or 1 change note
                  ----------
                  ~295-299 KB + 32N B  (no signatures — WOTS+ verified inside STARK)
```

For a typical N=2 unshield: ~296-299 KB total.

## Domain Separation

All hashing uses BLAKE2s-256 truncated to 251 bits, with domain separation via BLAKE2s personalization (parameter block P[6..7]):

| Use | Personalization | Function |
|-----|----------------|----------|
| Key derivation | (none) | `hash1`, `hash2_generic` |
| Merkle nodes (commitment tree + auth tree) | `mrklSP__` | `hash2` |
| Nullifiers | `nulfSP__` | `nullifier` |
| Commitments | `cmmtSP__` | `commit` |
| Per-address nk_spend | `nkspSP__` | `derive_nk_spend` |
| Per-address nk_tag | `nktgSP__` | `derive_nk_tag` |
| Owner tag | `ownrSP__` | `owner_tag` |
| WOTS+ chain hash | `wotsSP__` | `hash1_wots` (in circuit) |
| WOTS+ PK fold | `pkfdSP__` | `hash2_pkfold` (in circuit) |
| Sighash | `sighSP__` | `sighash_fold` (in circuit + client) |
| Memo hash (client-side) | `memoSP__` | -- (not in circuit) |

The commitment tree and auth tree both use `mrklSP__` for internal nodes. This is safe because they are verified against different roots in different circuit contexts — there is no cross-tree confusion.

## Canonical Encodings

### Felt252 Representation

All hash outputs are BLAKE2s-256 (32 bytes) with the top 5 bits cleared (`output[31] &= 0x07`), producing values in `[0, 2^251)` that fit in a felt252. Values are encoded as 32-byte little-endian arrays.

### Merkle Tree Structure

Both the commitment tree and auth key tree use left-right BLAKE2s Merkle trees:

- **Leaf encoding:** leaves are raw felt252 values (32 bytes), not hashed before insertion.
- **Internal nodes:** `H_merkle(left, right)` using the `mrklSP__` personalization.
- **Zero nodes:** derived recursively: `zero[0] = [0u8; 32]`, `zero[d+1] = H_merkle(zero[d], zero[d])`.
- **Append-only:** the commitment tree is append-only. New leaves are added at the next available index. The root is recomputed after each append.
- **Bit ordering:** Merkle path indices use the standard convention: bit 0 of `pos` selects left (0) or right (1) at depth 0 (leaf level), bit 1 at depth 1, etc.

### Position and Index Canonicalization

- **Commitment tree position `pos`:** MUST satisfy `0 <= pos < 2^TREE_DEPTH` (TREE_DEPTH=48). The Cairo circuit enforces this by checking all `path_indices` bits are 0 or 1, and rejecting the path if any bit beyond depth TREE_DEPTH is set (`src/merkle.cairo:77-81`). This prevents alias nullifiers via `pos = real_pos + k*2^TREE_DEPTH`.
- **Auth tree key index `key_idx`:** MUST satisfy `0 <= key_idx < 2^AUTH_DEPTH` (AUTH_DEPTH=10). The circuit rejects out-of-range indices (`src/merkle.cairo:108`). This prevents aliasing of auth tree leaves.
- **Values `v`:** MUST be u64. Arithmetic uses u128 to prevent overflow. The circuit enforces this via felt-to-u64 conversion.

### Memo-Hash Preimage

The `memo_ct_hash` public output is defined as:

```
memo_ct_hash = H_memo(ct_d || tag_le || ct_v || encrypted_data)
```

where:
- `ct_d` is the ML-KEM-768 detection ciphertext (1088 bytes)
- `tag_le` is the 2-byte detection tag in little-endian
- `ct_v` is the ML-KEM-768 viewing ciphertext (1088 bytes)
- `encrypted_data` is the ChaCha20-Poly1305 ciphertext (1080 bytes)
- `H_memo` uses the `memoSP__` personalization, truncated to 251 bits

The on-chain contract verifies that hashing the posted note data (exactly these four fields in this order) produces the `memo_ct_hash` from the proof's public outputs. The commitment (`cm`) is NOT included in this hash — it is verified separately via the commitment binding check.

## Security Properties

- **Balance:** u64 values, u128 arithmetic, exact equality. No overflow or wraparound.
- **Double-spend:** Nullifier set on-chain (contract-enforced globally, circuit-enforced per-tx). Position-dependent `nf = H(nk_spend, H(cm, pos))` ensures unique nullifiers even for duplicate commitments.
- **Nullifier binding:** `nk_spend -> nk_tag -> owner_tag -> cm` chain. The commitment cryptographically binds to the nullifier key material via second-preimage resistance of `H_commit`.
- **Spend authority:** The STARK proof proves both knowledge of `nk_spend` and a valid WOTS+ signature over the sighash. The WOTS+ signature is verified inside the circuit. No external signature verification is needed.
- **Spend unlinkability:** WOTS+ signature verification and auth tree membership are entirely inside the STARK. No auth leaves, public keys, or signatures appear in the public outputs. The sender who created the note knows `auth_root` but cannot extract any information from on-chain data to link back to it.
- **Privacy:** Commitments are hiding (randomness `rcm`). Nullifiers unlinkable to commitments (different hash domains, `nk_spend` is private). Per-address diversification prevents cross-address linking.
- **Post-quantum:** BLAKE2s (hash), ML-KEM-768 (memos/detection), WOTS+ w=4 (spend authorization, verified in-STARK), STARKs (proofs). No elliptic curves. No lattice-based signatures.
- **Zero-knowledge:** Two-level recursive proofs. Circuit layer has ZK blinding. Single-level mode is debug-only (not ZK).

## Known Limitations

- **WOTS+ key reuse compromises funds:** Each WOTS+ key MUST be used at most once. Reusing a one-time key across two transactions reveals enough hash chain preimages to allow an attacker to forge signatures and steal funds. This is fundamentally different from ML-DSA (which is many-time secure) — WOTS+ key reuse is a critical security failure, not merely a linkability issue. Users MUST rotate to a new key index for every spend and generate a new address before exhausting all K keys.
- **One-time key exhaustion:** Each address has K = 2^AUTH_DEPTH one-time WOTS+ keys. After exhaustion, the address cannot be used for further spends. Users should rotate addresses before this limit.
- **Auth tree generation cost:** Generating auth_root requires K WOTS+ key derivations at address creation time. With AUTH_DEPTH=10 (K=1024), this is fast (pure BLAKE2s hash chains). Higher depths increase this cost linearly.
- **Detection is honest-sender:** Malicious sender can bypass detection. Recipient falls back to viewing key scanning.
- **Prover learns nk_spend_j:** Can compute the nullifier for the specific note being spent. This is equivalent to public info (NF_set is on-chain). The prover does NOT learn `nk` (the account root) and cannot compute nullifiers for other addresses.
- **ML-KEM key anonymity (ANO-CCA):** We rely on Kyber's key anonymity property, proven separately from IND-CCA2. Should be cited explicitly in production.
- **Detection statistics:** False positive rate 2^(-k) does not automatically provide plausible deniability. Depends on network throughput and user activity.
- **N is not private:** The number of published nullifiers reveals the input count.
- **Malformed viewing ciphertexts (honest-sender):** The circuit proves commitments and memo hashes, but does NOT prove that `ct_v` / `encrypted_data` actually decrypt to the same `(v, rseed, memo)` used for the commitment. A malicious sender can create a valid on-chain note that the recipient cannot decrypt or that decrypts to inconsistent values. This is analogous to the detection bypass — honest-sender behavior is assumed. The memo-hash check binds ciphertext bytes (preventing relay tampering) but not semantic correctness of the encryption.
- **Wallet state is security-critical for WOTS+ safety:** The wallet tracks per-address WOTS+ key indices locally. Unlike multi-use signature schemes, the chain cannot enforce one-time use of hidden auth leaves without revealing metadata. This means wallet state consistency across backups, concurrent devices, and failed submissions is part of the security boundary. A wallet restored from a stale backup may reuse a WOTS+ key that was already consumed, leading to catastrophic key compromise. Implementations MUST serialize wallet state durably before submitting transactions.
- **Delegated prover can link same-address spends:** The prover sees `nk_spend_j` and `auth_root_j`, which are per-address values. If the same proving service handles multiple spends from the same address, it can link them. On-chain unlinkability is preserved regardless. See Delegated Proving section for details.
