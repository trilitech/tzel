# StarkPrivacy v2: Post-Quantum Private Transaction Spec

## Overview

A UTXO-based private transaction system with:
- **Merkle commitment tree** for note storage
- **Nullifiers** for double-spend prevention
- **Two-level recursive STARKs** (Cairo AIR + Stwo circuit reprover) with ZK blinding
- **Post-quantum cryptography** throughout: BLAKE2s hashing, ML-KEM for memos/detection
- **Delegated proving**: untrusted provers generate the STARK proof; the user signs afterward
- **Penumbra-inspired key hierarchy**: spending and address material in separate branches
- **Per-address nullifier binding**: nullifier keys are bound into commitments via owner tags

---

## Key Hierarchy

```text
master_sk
├── spend_seed = H("spend", master_sk)
│   ├── nk        = H("nk",  spend_seed)       — account nullifier root (never leaves user)
│   │   └── nk_spend_j = H_nksp(nk, d_j)       — per-address secret nullifier key
│   │       └── nk_tag_j  = H_nktg(nk_spend_j)  — per-address public binding tag
│   ├── ask_base  = H("ask", spend_seed)        — base authorization secret
│   │   └── ask_j = H(ask_base, j)              — per-address auth signing key
│   │       └── ak_j = H(ask_j)                 — per-address auth verifying key
│   └── ovk       = H("ovk", spend_seed)        — outgoing viewing key
│
└── incoming_seed = H("incoming", master_sk)
    ├── dsk        = H("dsk", incoming_seed)    — diversifier derivation key
    │   └── d_j    = H(dsk, j)                  — diversified address index
    ├── view_seed  = H("view", incoming_seed)   — per-address ML-KEM viewing keys
    │   └── (ek_v_j, dk_v_j) = ML-KEM.KeyGen(H("mlkem-view", view_seed, j))
    └── det_seed   = H("detect", view_seed)     — detection keys (detect ⊂ view)
        └── (ek_d_j, dk_d_j) = ML-KEM.KeyGen(H("mlkem-detect", det_seed, j))
```

**Spending branch** holds nullifier material (nk), authorization (ask), and outgoing view (ovk). **Incoming branch** holds address diversification (dsk), memo encryption (view_seed), and detection (det_seed). The two branches are independent — address material reveals nothing about spending keys.

### Per-Address Nullifier Keys

The account-level `nk` never leaves the user's device. Instead, each address derives:

- `nk_spend_j = H_nksp(nk, d_j)` — per-address secret, given to the prover for a specific note
- `nk_tag_j = H_nktg(nk_spend_j)` — per-address public tag, included in the payment address

These are bound into the commitment via an owner tag:

- `owner_tag_j = H_owner(ak_j, nk_tag_j)` — fuses both keys into a single value

This ensures the commitment cryptographically binds to the nullifier key material. An attacker who invents a fake `nk'` cannot produce a valid commitment without also knowing `ak_j`, and vice versa.

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
address_j = (d_j, ak_j, nk_tag_j, ek_v_j, ek_d_j)
```

- `d_j` — diversifier (32 bytes): identifies the address, appears in the note commitment
- `ak_j` — auth verifying key (32 bytes): the circuit verifies spend authorization
- `nk_tag_j` — nullifier binding tag (32 bytes): binds the commitment to the owner's nullifier key
- `ek_v_j` — ML-KEM encapsulation key (~800 bytes): sender encrypts memos with this
- `ek_d_j` — ML-KEM encapsulation key (~800 bytes): sender creates detection clues with this

Multiple addresses can be generated from one account (varying j). Each address has unrelated `d_j` values. ML-KEM ciphertexts are randomized per encapsulation, so observers cannot link two transactions to the same recipient.

For circuit purposes, `d_j`, `ak_j`, and `nk_tag_j` matter. The ML-KEM keys are application-layer.

## Note Structure

```
rseed       — random per-note seed
rcm         = H("rcm", rseed)                     — commitment randomness
owner_tag   = H_owner(ak_j, nk_tag_j)             — fuses auth + nullifier binding
cm          = H_commit(d_j, v, rcm, owner_tag)     — note commitment
nf          = H_nf(nk_spend_j, H_nf(cm, pos))     — position-dependent nullifier
```

The commitment binds to the diversified address, value, and owner tag (which fuses both the auth key and nullifier key material). The nullifier uses the per-address `nk_spend_j` and includes the leaf position to prevent faerie gold attacks.

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

This allows unlimited double-spending from a single note. The owner tag fix binds `nk_spend → nk_tag → owner_tag → cm`, creating a unique chain from the nullifier key to the commitment.

## Transaction Types

### Shield (public → private)

**Public outputs:** `[v_pub, cm_new, ak_j, sender, memo_ct_hash]`

**Circuit constraints:**
1. `rcm = H("rcm", rseed)`
2. `owner_tag = H_owner(ak, nk_tag)` where `nk_tag` is a private input from the recipient's payment address (the sender does NOT know `nk_spend`)
3. `cm_new = H_commit(d_j, v_pub, rcm, owner_tag)`

Note: the circuit cannot verify `nk_tag = H_nktg(nk_spend)` because the sender does not have the recipient's `nk_spend`. An incorrect `nk_tag` creates an unspendable note (self-griefing only — the sender loses their own deposited tokens). The spending circuits (transfer/unshield) enforce the full derivation chain when the note is later spent.

`memo_ct_hash` is computed client-side as `H(ct_v || encrypted_data)` and passed into the circuit as a public input. The circuit does not compute it — it just includes it in the outputs so the contract can verify the posted memo calldata matches.

**Contract checks:** proof valid, signature under `ak_j`, `msg.sender == sender`, `H(posted_memo_calldata) == memo_ct_hash`.

**State changes:** deduct `v_pub` from sender, append `cm_new` to T.

### Transfer (N→2, where 1 ≤ N ≤ 16)

Consumes N private notes and creates exactly 2 new private notes. Handles splits (N=1), standard transfers (N=2), and consolidations (N>2) with a single circuit. N is a runtime parameter, not a program parameter — the program hash is the same for all N.

**N is not private.** The number of published nullifiers reveals the input count. This is inherent to per-input nullifier publication.

**Public outputs:** `[root, nf_0..nf_{N-1}, cm_1, cm_2, ak_0..ak_{N-1}, memo_ct_hash_1, memo_ct_hash_2]`

**Circuit constraints:**
1. For each input i (0..N):
   - `rcm = H("rcm", rseed_i)`
   - `nk_tag_i = H_nktg(nk_spend_i)`
   - `owner_tag_i = H_owner(ak_i, nk_tag_i)`
   - `cm_i = H_commit(d_j_i, v_i, rcm_i, owner_tag_i)`
   - Merkle membership of `cm_i` at position `pos_i` against `root`
   - `nf_i = H_nf(nk_spend_i, H_nf(cm_i, pos_i))`
2. All nullifiers pairwise distinct
3. For both outputs:
   - `owner_tag_out = H_owner(ak_out, nk_tag_out)` where `nk_tag_out` is a private input from the recipient's payment address
   - `cm_out = H_commit(d_j_out, v_out, rcm_out, owner_tag_out)`
   - Note: same caveat as shield — incorrect `nk_tag` creates an unspendable output (self-griefing by the spender)
4. `sum(v_inputs) = v_1 + v_2` (in u128)
5. All values are u64 (implicit range check)

The contract verifies N signatures (one per `ak_i`). `memo_ct_hash_1` and `memo_ct_hash_2` are hashes of the output notes' encrypted memo ciphertexts (computed client-side, verified by the contract against posted calldata).

### Unshield (N→withdrawal + optional change, where 1 ≤ N ≤ 16)

Consumes N private notes, releases `v_pub` to a public address, and optionally creates one private change note.

**Public outputs:** `[root, nf_0..nf_{N-1}, v_pub, ak_0..ak_{N-1}, recipient, cm_change, memo_ct_hash_change]`

`cm_change` and `memo_ct_hash_change` are 0 if no change output.

**Circuit constraints:**
1. Same per-input verification as Transfer
2. All nullifiers pairwise distinct
3. If change:
   - `owner_tag_c = H_owner(ak_c, nk_tag_c)` where `nk_tag_c` is a private input
   - `cm_change = H_commit(d_j_c, v_change, rcm_c, owner_tag_c)`
4. If no change: all change witness data constrained to zero (`v_change`, `d_j_change`, `rseed_change`, `ak_change`, `nk_tag_change`, `memo_ct_hash_change` = 0) to eliminate prover malleability
5. `sum(v_inputs) = v_pub + v_change`

The contract verifies N signatures, credits `v_pub` to `recipient`, and appends `cm_change` to T (if nonzero).

### Why N→2 eliminates dummy notes

With N=1 supported natively, there is no second input slot to fill. The only "dummies" are zero-value *outputs* (when change is exactly zero), which are fresh commitments created on the fly — no pre-shielding required.

## Delegated Proving

1. User constructs the transaction, deriving all keys from `master_sk`.
2. User gives the prover per-input: `(nk_spend_j, ak_j, d_j, v, rseed, Merkle path, pos)`, plus output data including `nk_tag` for output notes.
3. Prover generates the STARK proof (expensive, ~30-50 seconds).
4. User signs the proof outputs with `ask_j` (trivially cheap).
5. Transaction (proof + signature) submitted in one on-chain call.

The prover sees `nk_spend_j` (per-address nullifier key) for each input note. This lets them compute the nullifier for that specific note — but NF_set is public, so this is equivalent to public information. The prover does NOT learn `nk` (the account-level nullifier root) and cannot compute nullifiers for addresses not involved in the transaction. The prover cannot spend (no `ask`) or decrypt other memos (no `dk_v`).

## Detection (Fuzzy Message Detection)

Detection precision `k` is a protocol constant (e.g., k=10). Per note on-chain:

```
(ss_d, ct_d)     = ML-KEM.Encaps(ek_d_j)     — encapsulate under detection key
tag              = H(ss_d)[0..k]              — k-bit detection tag
(ss_v, ct_v)     = ML-KEM.Encaps(ek_v_j)     — encapsulate under viewing key
encrypted_data   = ChaCha20-Poly1305(key=H(ss_v), nonce=0, plaintext=(v || rseed || user_memo))
```

The detection server (with `dk_d_j`) decapsulates `ct_d`, computes `H(ss')[0..k]`, and checks against `tag`. True matches always succeed. Non-matches succeed with probability 2^(-k) (false positives from ML-KEM's implicit rejection).

Detection assumes honest senders. A malicious sender can bypass detection by submitting bogus `ct_d`. The recipient falls back to scanning with `dk_v`.

Precision `k` should NOT be claimed to provide "plausible deniability" without modeling network throughput, user activity, and time aggregation. The false positive rate 2^(-k) is a technical parameter, not a privacy guarantee.

## User Memo

Each note carries a 1024-byte user memo field, encrypted alongside `(v, rseed)` inside the AEAD ciphertext. The memo can contain arbitrary data: payment references, return addresses, human-readable messages, or structured metadata.

Memo format conventions (following Zcash ZIP 302):
- If the first byte is ≤ 0xF4: the memo is a UTF-8 string, zero-padded.
- If the first byte is 0xF6: "no memo" (remainder is zeros).
- If the first byte is ≥ 0xF5: application-defined binary format.

The memo is end-to-end encrypted — only the recipient (with `dk_v`) can read it. The on-chain ciphertext reveals nothing about the memo content or length (all memos are padded to exactly 1024 bytes before encryption).

## Memo Integrity (Anti-Tampering)

Each circuit includes a `memo_ct_hash` per output note in its public outputs. This is the hash of the encrypted memo ciphertext (`H(ct_v || encrypted_data)`), computed **client-side** before proving. The circuit does not compute it — it simply passes it through as a public output.

The on-chain contract verifies `H(posted_calldata) == memo_ct_hash` for each output note. If a malicious relayer or sequencer swaps the encrypted memo data in transit, the hash won't match and the contract rejects the transaction.

This prevents:
- **Memo spoofing**: a relayer replacing "Payment for invoice #42" with "Send your seed phrase to evil.com"
- **Selective censorship**: a relayer stripping memo data while keeping the proof valid

The memo commitment adds zero computational cost inside the circuit (it's a passthrough public input) and 32 bytes per output note in the public outputs.

Note: the memo data itself is NOT needed for transaction validity. If a node prunes memo calldata after a retention period, the proof remains valid. The `memo_ct_hash` commitment only prevents tampering while the memo data is in transit from user to chain.

## On-Chain Note Data

Each output note in a transaction carries the following on-chain data:

```
cm              —    32 bytes   note commitment
ct_d            — 1,088 bytes   ML-KEM-768 detection ciphertext
tag             —     2 bytes   k-bit detection tag
ct_v            — 1,088 bytes   ML-KEM-768 memo ciphertext
encrypted_data  — 1,080 bytes   ChaCha20-Poly1305(v:8 || rseed:32 || memo:1024) + 16 auth tag
                ─────────────
                 3,290 bytes per output note (~3.2 KB)
```

## Transaction Format

A transaction submitted on-chain contains:

### Shield

```
proof             — ~295 KB    circuit proof (ZK, two-level recursive STARK)
public_outputs    —  160 B     [v_pub, cm_new, ak, sender, memo_ct_hash] (5 × 32 bytes)
note_data         —  3.2 KB    1 output note (cm + detection + encrypted memo)
signature         —   64 B     spend authorization under ak
                  ──────────
                  ~298 KB total
```

### Transfer (N→2)

```
proof             — ~295 KB    circuit proof
public_outputs    — 160+64N B  [root, cm_1, cm_2, mh_1, mh_2] + N×[nf_i] + N×[ak_i]
note_data         —  6.4 KB    2 output notes (each ~3.2 KB)
signatures        —  64N B     N spend authorizations
                  ──────────
                  ~302 KB + 128N bytes
```

### Unshield (N→withdrawal + change)

```
proof             — ~295 KB    circuit proof
public_outputs    — 160+64N B  [root, v_pub, recipient, cm_change, mh_change] + N×[nf_i] + N×[ak_i]
note_data         — 0–3.2 KB   0 or 1 change note
signatures        —  64N B     N spend authorizations
                  ──────────
                  ~295–299 KB + 128N bytes
```

The proof dominates all transaction types at ~295 KB. Note data adds ~3.2 KB per output note. Per-input overhead (nullifier + ak + signature) is ~128 bytes, negligible even at N=16 (~2 KB). Memo hashes (`mh`) add 32 bytes per output note.

## Domain Separation

All hashing uses BLAKE2s-256 truncated to 251 bits, with domain separation via BLAKE2s personalization (parameter block P[6..7]):

| Use | Personalization | Function |
|-----|----------------|----------|
| Key derivation | (none) | `hash1`, `hash2_generic` |
| Merkle nodes | `mrklSP__` | `hash2` |
| Nullifiers | `nulfSP__` | `nullifier` |
| Commitments | `cmmtSP__` | `commit` |
| Per-address nk_spend | `nkspSP__` | `derive_nk_spend` |
| Per-address nk_tag | `nktgSP__` | `derive_nk_tag` |
| Owner tag | `ownrSP__` | `owner_tag` |
| Memo hash (client-side) | `memoSP__` | — (not in circuit) |

Cross-domain collision is impossible regardless of inputs — different IVs produce structurally independent compression states.

## Security Properties

- **Balance:** u64 values, u128 arithmetic, exact equality. No overflow or wraparound.
- **Double-spend:** Nullifier set on-chain. Pairwise `nf_i ≠ nf_j` in circuit. Position-dependent `nf = H(nk_spend, H(cm, pos))` ensures unique nullifiers even for duplicate commitments.
- **Nullifier binding:** `nk_spend → nk_tag → owner_tag → cm` chain. The commitment cryptographically binds to the nullifier key material. An attacker cannot substitute a fake `nk'` without breaking the commitment preimage.
- **Spend authority:** Requires both `nk_spend` (for the proof) and `ask_j` (for the signature).
- **Privacy:** Commitments are hiding (randomness `rcm`). Nullifiers unlinkable to commitments (different hash domains, `nk_spend` is private). Per-address diversification prevents cross-address linking.
- **Post-quantum:** BLAKE2s (hash), ML-KEM (memos/detection), STARKs (proofs). No elliptic curves.
- **Zero-knowledge:** Two-level recursive proofs. Circuit layer has ZK blinding. Single-level mode is debug-only (not ZK).

## Known Limitations

- **`ak_j` sender-timing leak:** The sender knows `ak_j` (it's in the proof output). When the note is spent, `ak_j` appears on-chain. The sender can link "I sent to this address" ↔ "this address just spent." Requires blinded lattice signatures to fix (future work).
- **Detection is honest-sender:** Malicious sender can bypass detection. Recipient falls back to viewing key scanning.
- **Prover learns nk_spend_j:** Can compute the nullifier for the specific note being spent. This is equivalent to public info (NF_set is on-chain). The prover does NOT learn `nk` (the account root) and cannot compute nullifiers for other addresses.
- **ML-KEM key anonymity (ANO-CCA):** We rely on Kyber's key anonymity property, proven separately from IND-CCA2. Should be cited explicitly in production.
- **Detection statistics:** False positive rate 2^(-k) does not automatically provide plausible deniability. Depends on network throughput and user activity.
