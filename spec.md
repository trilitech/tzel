# StarkPrivacy v2: Post-Quantum Private Transaction Spec

## Overview

A UTXO-based private transaction system with:
- **Merkle commitment tree** for note storage
- **Nullifiers** for double-spend prevention
- **Two-level recursive STARKs** (Cairo AIR + Stwo circuit reprover) with ZK blinding
- **Post-quantum cryptography** throughout: BLAKE2s hashing, ML-KEM for memos/detection
- **Delegated proving**: untrusted provers generate the STARK proof; the user signs afterward
- **Penumbra-inspired key hierarchy**: spending and address material in separate branches

---

## Key Hierarchy

```text
master_sk
├── spend_seed = H("spend", master_sk)
│   ├── nk        = H("nk",  spend_seed)       — account nullifier key (ONE per account)
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
address_j = (d_j, ak_j, ek_v_j, ek_d_j)
```

- `d_j` — diversifier (32 bytes): identifies the address, appears in the note commitment
- `ek_v_j` — ML-KEM encapsulation key (~800 bytes): sender encrypts memos with this
- `ek_d_j` — ML-KEM encapsulation key (~800 bytes): sender creates detection clues with this

Multiple addresses can be generated from one account (varying j). Each address has unrelated `d_j` values. ML-KEM ciphertexts are randomized per encapsulation, so observers cannot link two transactions to the same recipient.

For circuit purposes, only `d_j` matters. The ML-KEM keys are application-layer.

## Note Structure

```
rseed  — random per-note seed
rcm    = H("rcm", rseed)           — commitment randomness
cm     = H_commit(d_j, v, rcm, ak)  — note commitment
nf     = H_null(nk, cm)            — nullifier
```

The commitment binds to the diversified address and value. It does NOT contain spending material. The nullifier binds the account-level nullifier key to this specific commitment.

## Transaction Types

### Shield (public → private)

**Public outputs:** `[v_pub, cm_new, ak_j, sender]`

**Circuit constraints:**
1. `rcm = H("rcm", rseed)`
2. `cm_new = H_commit(d_j, v_pub, rcm, ak)`

**Contract checks:** proof valid, signature under `ak_j`, `msg.sender == sender`.

**State changes:** deduct `v_pub` from sender, append `cm_new` to T.

### Transfer (N→2, where 1 ≤ N ≤ 16)

Consumes N private notes and creates exactly 2 new private notes. Handles splits (N=1), standard transfers (N=2), and consolidations (N>2) with a single circuit. N is a runtime parameter, not a program parameter — the program hash is the same for all N.

**N is not private.** The number of published nullifiers reveals the input count. This is inherent to per-input nullifier publication.

**Public outputs:** `[root, nf_0, ..., nf_{N-1}, cm_1, cm_2, ak_0, ..., ak_{N-1}]`

**Circuit constraints:**
1. For each input i (0..N): `rcm = H("rcm", rseed)`, `cm = H_commit(d_j, v, rcm, ak)`, Merkle membership, `nf = H_null(nk, cm)`
2. All nullifiers pairwise distinct
3. For both outputs: `rcm = H("rcm", rseed)`, `cm = H_commit(d_j, v, rcm, ak)`
4. `sum(v_inputs) = v_1 + v_2` (in u128)
5. All values are u64 (implicit range check)

Each input has its own `nk` (supporting cross-account inputs). The contract verifies N signatures (one per `ak_i`).

### Unshield (N→withdrawal + optional change, where 1 ≤ N ≤ 16)

Consumes N private notes, releases `v_pub` to a public address, and optionally creates one private change note.

**Public outputs:** `[root, nf_0, ..., nf_{N-1}, v_pub, ak_0, ..., ak_{N-1}, recipient, cm_change]`

`cm_change` is 0 if no change output.

**Circuit constraints:**
1. Same per-input verification as Transfer
2. All nullifiers pairwise distinct
3. If change: `cm_change = H_commit(d_j_c, v_change, rcm_c, ak_c)`
4. `sum(v_inputs) = v_pub + v_change`

The contract verifies N signatures, credits `v_pub` to `recipient`, and appends `cm_change` to T (if nonzero).

### Why N→2 eliminates dummy notes

With N=1 supported natively, there is no second input slot to fill. The only "dummies" are zero-value *outputs* (when change is exactly zero), which are fresh commitments created on the fly — no pre-shielding required.

## Delegated Proving

1. User constructs the transaction, deriving all keys from `master_sk`.
2. User gives the prover: `(nk, ak, d_j, v, rseed, Merkle path)` per input note, plus output data.
3. Prover generates the STARK proof (expensive, ~30-50 seconds).
4. User signs the proof outputs with `ask_j` (trivially cheap).
5. Transaction (proof + signature) submitted in one on-chain call.

The prover sees `nk` (account-level nullifier key). This lets them compute nullifiers for any of the user's notes — but NF_set is public, so this is equivalent to public information. The prover cannot spend (no `ask`) or decrypt other memos (no `dk_v`).

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
proof             — ~295 KB   circuit proof (ZK, two-level recursive STARK)
public_outputs    —  128 B    [v_pub, cm_new, ak, sender] (4 × 32 bytes)
note_data         —  3.2 KB   1 output note (cm + detection + memo)
signature         —   64 B    spend authorization under ak
                  ─────────
                  ~298 KB total
```

### Transfer (N→2)

```
proof             — ~295 KB   circuit proof
public_outputs    — 96+64N B  [root, cm_1, cm_2] + N × [nf_i] + N × [ak_i]
note_data         —  6.4 KB   2 output notes (each ~3.2 KB)
signatures        —  64N B    N spend authorizations
                  ─────────
                  ~302 KB + 128N bytes  (for N=2: ~302 KB; for N=5: ~303 KB)
```

### Unshield (N→withdrawal + change)

```
proof             — ~295 KB   circuit proof
public_outputs    — 128+64N B [root, v_pub, recipient, cm_change] + N × [nf_i] + N × [ak_i]
note_data         — 0-3.2 KB  0 or 1 change note
signatures        —  64N B    N spend authorizations
                  ─────────
                  ~295-299 KB + 128N bytes
```

The proof dominates all transaction types at ~295 KB. Note data adds ~3.2 KB per output note. Per-input overhead (nullifier + ak + signature) is ~128 bytes, negligible even at N=16 (~2 KB).

## Domain Separation

All hashing uses BLAKE2s-256 truncated to 251 bits, with domain separation via BLAKE2s personalization (parameter block P[6..7]):

| Use | Personalization | h[6] |
|-----|----------------|------|
| Key derivation | (none) | 0x1F83D9AB |
| Merkle nodes | `mrklSP__` | 0x73E8ABC6 |
| Nullifiers | `nulfSP__` | 0x79EFACC5 |
| Commitments | `cmmtSP__` | 0x6BEEB4C8 |

Cross-domain collision is impossible regardless of inputs — different IVs produce structurally independent compression states.

## Security Properties

- **Balance:** u64 values, u128 arithmetic, exact equality. No overflow or wraparound.
- **Double-spend:** Nullifier set on-chain. `nf_a ≠ nf_b` in circuit. `nf = H(nk, cm)` is deterministic per note.
- **Spend authority:** Requires both `nk` (for the proof) and `ask_j` (for the signature).
- **Privacy:** Commitments are hiding (randomness `rcm`). Nullifiers unlinkable to commitments (different hash domains, `nk` is private). Per-address diversification prevents cross-address linking.
- **Post-quantum:** BLAKE2s (hash), ML-KEM (memos/detection), STARKs (proofs). No elliptic curves.
- **Zero-knowledge:** Two-level recursive proofs. Circuit layer has ZK blinding. Single-level mode is debug-only (not ZK).

## Known Limitations

- **`ak_j` sender-timing leak:** The sender knows `ak_j` (it's in the proof output). When the note is spent, `ak_j` appears on-chain. The sender can link "I sent to this address" ↔ "this address just spent." Requires blinded lattice signatures to fix (future work).
- **Detection is honest-sender:** Malicious sender can bypass detection. Recipient falls back to viewing key scanning.
- **Prover learns nk:** Can compute nullifiers for any of the user's notes. Equivalent to public info (NF_set is on-chain).
- **ML-KEM key anonymity (ANO-CCA):** We rely on Kyber's key anonymity property, proven separately from IND-CCA2. Should be cited explicitly in production.
- **Detection statistics:** False positive rate 2^(-k) does not automatically provide plausible deniability. Depends on network throughput and user activity.
