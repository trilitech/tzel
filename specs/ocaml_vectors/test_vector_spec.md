# TzEL v2 — Cross-Implementation Test Vector Specification

**Version:** 1  
**Purpose:** Any independent implementation of the TzEL v2 protocol can generate and consume these vectors to verify byte-exact compatibility with the reference implementation.

## Overview

All test vectors are derived from a single fixed master secret key:

```
master_sk = felt252_le(12345)
          = 0x3930000000000000000000000000000000000000000000000000000000000000
```

(32-byte little-endian encoding of the integer 12345.)

Every operation below is fully deterministic given the inputs specified. There is no randomness. For operations that are normally randomized (ML-KEM encaps), we use the deterministic variant (`encaps_derand`) with fixed coins.

## Conventions

- **felt252**: 32 bytes, little-endian, top 5 bits of byte 31 cleared (`b[31] &= 0x07`).
- **hex**: lowercase, no `0x` prefix, representing raw bytes. A felt is always 64 hex chars.
- **felt_of_int(n)**: 32 bytes LE with `n` in the low bytes, upper bytes zero, then truncate.
- **H(a, b)**: `felt252(BLAKE2s-256(a || b))` where `a`, `b` are 32-byte felts concatenated.
- **Domain tags are fixed felt constants**, not hashed UTF-8 strings. When this document writes `TAG_SPEND`, `TAG_DSK`, `TAG_MLKEM_V`, etc., it refers to the exact felt constants defined in [`specs/spec.md`](../spec.md) under `Domain Tag Constants`.
- All domain-separated hashes use the personalizations from the protocol spec (§ Domain Separation).

## JSON Schema

The output file is a single JSON object. Each section is a key at the top level. All sections are REQUIRED.

```json
{
  "blake2s": [...],
  "key_hierarchy": {...},
  "addresses": [...],
  "mlkem_seeds": [...],
  "mlkem_keygen": [...],
  "mlkem_encaps_derand": [...],
  "chacha20": [...],
  "detection_tags": [...],
  "memo_ct_hash": {...},
  "cross_impl_encrypt": {...},
  "wots": [...],
  "merkle": [...],
  "notes": [...],
  "sighash": [...],
  "account_ids": [...],
  "wire_encoding": {...}
}
```

---

## Section: `blake2s`

Tests raw BLAKE2s-256 with and without personalization.

**Array of objects:**

| Field | Type | Description |
|-------|------|-------------|
| `input` | hex | Raw input bytes |
| `personal` | string | 8-byte ASCII personalization, or `""` for unpersonalized |
| `output` | hex | 32-byte BLAKE2s-256 output (NOT truncated to 251 bits) |

**Required cases (in order):**

| # | input (as string) | personal | Notes |
|---|---|---|---|
| 0 | `""` (empty) | `""` | RFC 7693 test vector |
| 1 | `"abc"` | `""` | RFC 7693 test vector |
| 2 | `"test"` | `"mrklSP__"` | Merkle personalization |
| 3 | `"test"` | `"nulfSP__"` | Nullifier personalization |
| 4 | `"test"` | `"cmmtSP__"` | Commitment personalization |
| 5 | `"test"` | `"nkspSP__"` | nk_spend personalization |
| 6 | `"test"` | `"nktgSP__"` | nk_tag personalization |
| 7 | `"test"` | `"ownrSP__"` | Owner tag personalization |
| 8 | `"test"` | `"wotsSP__"` | WOTS chain personalization |
| 9 | `"test"` | `"sighSP__"` | Sighash personalization |
| 10 | `"test"` | `"memoSP__"` | Memo hash personalization |
| 11 | `"x" * 200` | `""` | Multi-block (>64 bytes) |
| 12 | `"x" * 200` | `"mrklSP__"` | Multi-block with personalization |

The `input` field in the JSON is the hex encoding of the raw bytes (e.g., `"abc"` → `"616263"`).

---

## Section: `key_hierarchy`

Tests the full account key derivation from `master_sk`.

**Single object:**

| Field | Type | Description |
|-------|------|-------------|
| `master_sk` | hex felt | `felt_of_int(12345)` |
| `nk` | hex felt | `H(TAG_NK, H(TAG_SPEND, master_sk))` |
| `ask_base` | hex felt | `H(TAG_ASK, H(TAG_SPEND, master_sk))` |
| `dsk` | hex felt | `H(TAG_DSK, H(TAG_INCOMING, master_sk))` |
| `incoming_seed` | hex felt | `H(TAG_INCOMING, master_sk)` |
| `view_root` | hex felt | `H(TAG_VIEW, incoming_seed)` |
| `detect_root` | hex felt | `H(TAG_DETECT, view_root)` |

---

## Section: `addresses`

Tests per-address derivation for address indices `j = 0, 1, 2`.

**Array of objects:**

| Field | Type | Description |
|-------|------|-------------|
| `j` | int | Address index |
| `d_j` | hex felt | `H(dsk, felt_of_int(j))` |
| `nk_spend` | hex felt | `H_nksp(nk, d_j)` |
| `nk_tag` | hex felt | `H_nktg(nk_spend)` |
| `auth_root` | hex felt | Merkle root of `2^AUTH_DEPTH = 65536` XMSS-style auth leaves |
| `auth_pub_seed` | hex felt | `H(TAG_XMSS_PS, ask_j)` |
| `owner_tag` | hex felt | `H_owner(auth_root, auth_pub_seed, nk_tag)` |

---

## Section: `mlkem_seeds`

Tests ML-KEM 64-byte seed derivation for address indices `j = 0, 1`.

**Array of objects (4 total: view×{0,1} + detect×{0,1}):**

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | `"view"` or `"detect"` |
| `root` | hex felt | `view_root` or `detect_root` from `key_hierarchy` |
| `j` | int | Address index |
| `seed` | hex (128 chars) | 64-byte seed (see spec § ML-KEM derivation steps 2-9) |

**View seed derivation (kind="view"):**
```
h1 = H(TAG_MLKEM_V, root)
h2 = H(h1, felt_of_int(j))
seed = h2 || H(TAG_MLKEM_V2, h2)
```

**Detect seed derivation (kind="detect"):**
```
h1 = H(TAG_MLKEM_D, root)
h2 = H(h1, felt_of_int(j))
seed = h2 || H(TAG_MLKEM_D2, h2)
```

---

## Section: `mlkem_keygen`

Tests ML-KEM-768 deterministic key generation. This is the critical interoperability check — `keygen_det(seed)` must produce byte-identical encapsulation keys across implementations, and the decapsulation key reconstructed from the same seed must successfully decapsulate the deterministic test ciphertexts below.

**Array of objects for j = 0, 1:**

| Field | Type | Description |
|-------|------|-------------|
| `j` | int | Address index |
| `view_seed` | hex (128 chars) | 64-byte view seed from `mlkem_seeds` |
| `ek_v` | hex (2368 chars) | 1184-byte ML-KEM-768 encapsulation key |
| `detect_seed` | hex (128 chars) | 64-byte detect seed from `mlkem_seeds` |
| `ek_d` | hex (2368 chars) | 1184-byte ML-KEM-768 encapsulation key |

The keygen function is FIPS 203 `ML-KEM.KeyGen_internal(d, z)` where `seed[0..32] = d` and `seed[32..64] = z`. In RustCrypto this is `DecapsulationKey::from_seed`. In mlkem-native this is `keypair_derand(pk, sk, coins)` where `coins` is the 64-byte seed.

The vectors intentionally standardize only the 64-byte seed and the 1184-byte encapsulation key. Different libraries may expose the decapsulation key in different serialized forms (for example, seed form vs. deprecated expanded form), but they MUST reconstruct equivalent decapsulation behavior from the same seed.

---

## Section: `mlkem_encaps_derand`

Tests ML-KEM-768 deterministic encapsulation using the j=0 view key.

**Array of 3 objects:**

| Field | Type | Description |
|-------|------|-------------|
| `case` | int | 0, 1, or 2 |
| `ek` | hex (2368 chars) | `ek_v` from `mlkem_keygen[j=0]` |
| `coins` | hex (64 chars) | 32-byte deterministic coins (see below) |
| `ss` | hex (64 chars) | 32-byte shared secret |
| `ct` | hex (2176 chars) | 1088-byte ciphertext |

**Fixed coins per case:**

| Case | coins |
|------|-------|
| 0 | `00` × 32 (all zeros) |
| 1 | `ff` × 32 (all 0xFF) |
| 2 | `BLAKE2s-256("encaps-coins")` (unpersonalized, NOT truncated) |

Implementations MUST verify that `decaps(dk, ct) == ss` for each case, where `dk` is reconstructed from `view_seed` for `j=0`.

---

## Section: `chacha20`

Tests ChaCha20-Poly1305 AEAD encryption with the derived note nonce.

**Array of 2 objects:**

| Field | Type | Description |
|-------|------|-------------|
| `case` | int | 0 or 1 |
| `ss_v` | hex (64 chars) | 32-byte key material: `BLAKE2s-256("key-0")` or `BLAKE2s-256("key-1")` (unpersonalized, NOT truncated) |
| `v` | string | Value as decimal string |
| `rseed` | hex felt | 32-byte rseed |
| `memo` | hex (2048 chars) | 1024-byte memo |
| `nonce` | hex (24 chars) | 12-byte derived nonce `H_mnon(BLAKE2s(ss_v) || plaintext)[0..12)` |
| `encrypted_data` | hex (2160 chars) | 1080-byte ciphertext |

**Encryption spec:**
```
aead_key = BLAKE2s-256(ss_v)          // unpersonalized, NOT truncated, raw 32 bytes
plaintext = v_le64(8 bytes) || rseed(32 bytes) || memo(1024 bytes)    // 1064 bytes
nonce    = BLAKE2s-256(personal="mnonSP__", aead_key || plaintext)[0..12)
encrypted_data = ChaCha20-Poly1305.Encrypt(aead_key, nonce, plaintext)  // 1080 bytes
```

**Case 0:** `ss_v = BLAKE2s("")` of string `"key-0"`, `v = 1000`, `rseed = felt_of_int(42)`, `memo = no_memo()` (0xF6 then zeros).

**Case 1:** `ss_v = BLAKE2s("")` of string `"key-1"`, `v = 0`, `rseed = felt_zero`, `memo = text_memo("hello")` (UTF-8 "hello" then zeros).

---

## Section: `detection_tags`

Tests detection tag computation.

**Array of 4 objects:**

| Field | Type | Description |
|-------|------|-------------|
| `case` | int | 0–3 |
| `ss_d` | hex (64 chars) | 32-byte shared secret |
| `tag` | int | `LE16(BLAKE2s(ss_d)[0], BLAKE2s(ss_d)[1]) & 0x3FF` |

**Shared secrets:** `BLAKE2s-256(s)` (unpersonalized, NOT truncated) for `s` in `["ss-0", "ss-1", "ss-2", "all-zeros"]`.

---

## Section: `memo_ct_hash`

Tests `H_memo(ct_d || tag_le || ct_v || nonce || encrypted_data)`.

**Single object:**

| Field | Type | Description |
|-------|------|-------------|
| `ct_d` | hex | 1088 bytes: `byte[i] = i % 256` |
| `tag` | int | `42` |
| `ct_v` | hex | 1088 bytes: `byte[i] = (i + 100) % 256` |
| `nonce` | hex | 12 bytes: `0x44` repeated |
| `encrypted_data` | hex | 1080 bytes: `byte[i] = (i + 200) % 256` |
| `memo_ct_hash` | hex felt | `H_memo(ct_d || LE16(42) || ct_v || nonce || encrypted_data)` |

---

## Section: `cross_impl_encrypt`

End-to-end test: derives keys from `master_sk`, performs deterministic KEM encapsulation, encrypts a note, and computes the memo hash. Every intermediate value is included for debugging mismatches.

**Single object:**

| Field | Type | Description |
|-------|------|-------------|
| `master_sk` | hex felt | `felt_of_int(12345)` |
| `view_seed` | hex | 64-byte view seed for j=0 |
| `detect_seed` | hex | 64-byte detect seed for j=0 |
| `ek_v` | hex | View encapsulation key |
| `ek_d` | hex | Detect encapsulation key |
| `coins_v` | hex | `BLAKE2s-256("view-encaps-coins")` (NOT truncated) |
| `coins_d` | hex | `BLAKE2s-256("detect-encaps-coins")` (NOT truncated) |
| `ss_v` | hex | `encaps_derand(ek_v, coins_v).ss` |
| `ss_d` | hex | `encaps_derand(ek_d, coins_d).ss` |
| `ct_v` | hex | `encaps_derand(ek_v, coins_v).ct` |
| `ct_d` | hex | `encaps_derand(ek_d, coins_d).ct` |
| `v` | string | `"42000"` |
| `rseed` | hex felt | `felt_of_int(777)` |
| `memo` | hex | `text_memo("cross-impl test")` (1024 bytes) |
| `nonce` | hex | Derived note nonce |
| `encrypted_data` | hex | ChaCha20-Poly1305 output (1080 bytes) |
| `tag` | int | Detection tag from `ss_d` |
| `memo_ct_hash` | hex felt | `H_memo(ct_d \|\| LE16(tag) \|\| ct_v \|\| nonce \|\| encrypted_data)` |

**Verification procedure:** an implementation MUST:
1. Derive `view_seed` and `detect_seed` from `master_sk` and `j=0`
2. Run `keygen_det` on both seeds, compare `ek_v` and `ek_d`
3. Run `encaps_derand(ek_v, coins_v)`, compare `ss_v` and `ct_v`
4. Run `encaps_derand(ek_d, coins_d)`, compare `ss_d` and `ct_d`
5. Encrypt the memo with `ss_v`, compare `nonce` and `encrypted_data`
6. Compute detection tag from `ss_d`, compare `tag`
7. Compute `H_memo(ct_d || LE16(tag) || ct_v || nonce || encrypted_data)`, compare `memo_ct_hash`

If any step fails, the intermediate values pinpoint the first divergence.

---

## Section: `wots`

Tests the XMSS-style WOTS+ spend-auth path for `w=4` (133 chains), including the per-key seed derivation, addressed chain steps, and L-tree leaf compression.

**Array of 3 objects with `ask_j` in `{felt_of_int(42), felt_of_int(100), felt_of_int(999)}` and `key_idx = 0`:**

| Field | Type | Description |
|-------|------|-------------|
| `ask_j` | hex felt | Address auth secret input |
| `auth_pub_seed` | hex felt | `H(TAG_XMSS_PS, ask_j)` |
| `key_idx` | int | XMSS leaf index |
| `seed` | hex felt | `H(TAG_XMSS_SK, ask_j, felt_of_int(key_idx))` |
| `leaf` | hex felt | XMSS L-tree root of the recovered WOTS endpoints |
| `sighash` | hex felt | `H(UTF8("test-sighash"))` — same for all three |
| `signature` | array of 133 hex felts | `sign(seed, sighash)` output |

**XMSS-style WOTS+ keygen:**
```
auth_pub_seed = H(TAG_XMSS_PS, ask_j)
seed          = H(TAG_XMSS_SK, ask_j, felt_of_int(key_idx))

for chain in 0..132:
    sk_chain = H(seed, felt_of_int(chain))
    pk_chain = H_chain^(w-1)(auth_pub_seed, ADRS(chain, step), sk_chain)

leaf = XMSS_LTree(auth_pub_seed, key_idx, pk_0..pk_132)
```

`ADRS(chain, step)` is the packed XMSS address described in [`specs/spec.md`](../spec.md), using the chain role for WOTS chain steps and the L-tree role for the leaf compression.

**XMSS-style WOTS+ sign:**
```
digits = decompose_base4(sighash)   // 128 message + 5 checksum
for chain in 0..132:
    sk_chain = H(seed, felt_of_int(chain))
    sig_chain = H_chain^digits[chain](auth_pub_seed, ADRS(chain, step), sk_chain)
```

---

## Section: `merkle`

Tests binary Merkle tree root computation with `H_merkle` (`mrklSP__`).

**Array of 5 objects:**

| # | depth | leaves (as integers) |
|---|-------|---------------------|
| 0 | 3 | [1, 2, 3, 4] |
| 1 | 4 | [10, 20, 30] |
| 2 | 3 | [1] |
| 3 | 4 | [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] |
| 4 | 3 | [] (empty tree) |

Each integer `n` is encoded as `felt_of_int(n)`. Unfilled leaves are `zero = [0u8; 32]`. Zero nodes: `zero[0] = [0u8; 32]`, `zero[d+1] = H_merkle(zero[d], zero[d])`.

| Field | Type | Description |
|-------|------|-------------|
| `depth` | int | Tree depth |
| `leaves` | array of hex felts | Leaf values |
| `root` | hex felt | Merkle root |

---

## Section: `notes`

Tests note commitment and nullifier computation.

**Array of 3 objects, all using address j=0 derived from `master_sk`:**

| # | v | rseed | pos |
|---|---|-------|-----|
| 0 | 1000 | `felt_of_int(777)` | 0 |
| 1 | 0 | `felt_of_int(1)` | 5 |
| 2 | 999999 | `felt_of_int(42)` | 100 |

| Field | Type | Description |
|-------|------|-------------|
| `d_j` | hex felt | From address j=0 |
| `v` | string | Decimal value |
| `rseed` | hex felt | Random seed |
| `auth_root` | hex felt | From address j=0 |
| `auth_pub_seed` | hex felt | From address j=0 |
| `nk_tag` | hex felt | From address j=0 |
| `rcm` | hex felt | `H(TAG_RCM, rseed)` |
| `owner_tag` | hex felt | `H_owner(auth_root, auth_pub_seed, nk_tag)` |
| `cm` | hex felt | `H_commit(d_j, felt_of_int(v), rcm, owner_tag)` |
| `nk_spend` | hex felt | From address j=0 |
| `pos` | int | Leaf position |
| `nf` | hex felt | `H_nf(nk_spend, H_nf(cm, felt_of_int(pos)))` |

---

## Section: `sighash`

Tests sighash fold with `H_sighash` (`sighSP__`).

**Array of 3 objects:**

| # | Items |
|---|-------|
| 0 | `[felt_of_int(1), felt_of_int(2), felt_of_int(3)]` |
| 1 | `[felt_of_int(0x01), H(UTF8("domain")), H(UTF8("root")), H(UTF8("nf0")), H(UTF8("cm1")), H(UTF8("cm2")), felt_zero, felt_zero]` — simulated transfer sighash |
| 2 | `[felt_of_int(0x02), H(UTF8("domain")), H(UTF8("root")), H(UTF8("nf0")), felt_of_int(5000), account_id("bob"), felt_zero, felt_zero]` — simulated unshield sighash |

| Field | Type | Description |
|-------|------|-------------|
| `items` | array of hex felts | Input felts |
| `result` | hex felt | `fold_left H_sighash items` |

Fold: `result = items[0]`, then for each remaining item `x`: `result = H_sighash(result, x)`.

---

## Section: `account_ids`

Tests public account identifier hashing.

**Array of 4 objects for strings `["alice", "bob", "", "a]very+long/identifier\x00with\nnulls"]`:**

| Field | Type | Description |
|-------|------|-------------|
| `string` | string | UTF-8 account string |
| `id` | hex felt | `felt252(BLAKE2s-256(UTF8(string)))` — unpersonalized, truncated |

---

## Section: `wire_encoding`

Tests canonical binary serialization byte layout.

**Single object:**

| Field | Type | Description |
|-------|------|-------------|
| `payment_address` | hex | 2496-byte PaymentAddress encoding for address j=0 from `master_sk` |
| `encrypted_note` | hex | 3270-byte EncryptedNote with deterministic fill (see below) |
| `published_note` | hex | 3302-byte PublishedNote |
| `note_memo` | hex | 3310-byte NoteMemo with `index=42` |

**Deterministic EncryptedNote fill:**
```
ct_d[i] = i % 256           for i in 0..1088
tag = 42
ct_v[i] = (i + 50) % 256    for i in 0..1088
nonce[i] = 0xAA             for i in 0..12
encrypted_data[i] = (i + 100) % 256  for i in 0..1080
```

**PublishedNote:** `cm = H(UTF8("wire-test-cm"))` (i.e., `felt252(BLAKE2s-256(UTF8("wire-test-cm")))`), followed by the EncryptedNote above.

**NoteMemo:** `index = 42` as u64le, then the same `cm` and EncryptedNote.

**PaymentAddress:** the 6-field record for address j=0 derived from `master_sk`: `(d_j, auth_root, auth_pub_seed, nk_tag, ek_v, ek_d)`, serialized in that order as raw bytes.

---

## How to use

### Generating vectors

Implement a binary that computes every value above and emits the JSON. Use the same code paths as your protocol implementation — do not reimplement the crypto just for vectors.

### Consuming vectors

Load the JSON, recompute every value from the specified inputs, and compare byte-for-byte. On mismatch, the intermediate values in `cross_impl_encrypt` and elsewhere help pinpoint the first divergence.

### What this does NOT cover

| Thing | Why not | How to test instead |
|-------|---------|--------------------|
| Randomized ML-KEM encaps | Non-deterministic by design | Property test: `decaps(dk, encaps(ek).ct) == encaps(ek).ss` |
| STARK proofs | Different provers produce different proofs | Verify-only: `tzel-verify --proof <file>` must accept |
| Proof malleability | Proofs are not unique | Verify the public outputs and program hash, not proof bytes |
| Network transport | Out of scope | Test the canonical wire encoding (covered above) |
