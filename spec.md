# StarkPrivacy: Minimal Private Transaction Spec

## Overview

A UTXO-based private transaction system using a Merkle commitment tree, nullifiers for double-spend prevention, and three transaction types: **Shield**, **Unshield**, and **Transfer**. All proofs will be realized as STARKs over a STARK-friendly hash function.

---

## Primitives

| Symbol | Description |
|--------|-------------|
| `H(...)` | BLAKE2s-256 hash function (truncated to 251 bits for field compatibility) |
| `sk` | Spending key — secret, known only to the note owner |
| `pk` | Paying key — public, derived as `pk = H(sk)` |
| `cm` | Note commitment |
| `nf` | Nullifier — derived as `H(sk, rho)`, revealed when a note is spent |
| `rho` | Note nonce — random field element, unique per note |
| `r` | Blinding factor (random field element) |
| `v` | Amount (field element, non-negative) |
| `T` | Merkle tree of commitments |
| `root` | Merkle root of `T` |
| `path` | Merkle authentication path proving membership in `T` |
| `NF_set` | Global set of revealed nullifiers |

## Keys

A recipient generates a spending key `sk` (random field element) and publishes a paying key:

```
pk = H(sk)
```

`sk` is needed to derive nullifiers and spend notes. `pk` is given to senders so they can create notes payable to the recipient.

## Note Structure

A **note** is the tuple `(pk, v, rho, r)`. Its commitment is:

```
cm = H(pk, v, rho, r)
```

- `pk` is the recipient's paying key — determines who can spend the note.
- `v` is the amount, kept secret.
- `rho` is a random nonce chosen by the note creator, unique per note.
- `r` is a random blinding factor, kept secret.

The commitment `cm` is appended to the Merkle tree `T`. The note is spent by revealing its nullifier:

```
nf = H(sk, rho)
```

Only the owner (who knows `sk`) can compute `nf`. Once `nf` appears in `NF_set`, the note cannot be spent again.

### Encrypted memo

When creating a note for a recipient, the sender encrypts `(v, rho, r)` under the recipient's public key and attaches the ciphertext to the transaction. The recipient scans transactions, decrypts memos with their key, and recovers the note data needed to later spend. This is application-layer — no proof of correct encryption is required.

---

## Transaction Types

### 1. Shield (public -> private)

Deposits `v_pub` tokens from the public domain into a new private note.

**Public inputs:**
- `v_pub` — the deposited amount
- `cm_new` — the new note commitment

**Private inputs (witness):**
- `pk` — recipient's paying key
- `rho`, `r` — nonce and blinding factor for the new note

**Constraints proved by the STARK:**
1. `cm_new = H(pk, v_pub, rho, r)`

**State changes:**
- `v_pub` tokens are consumed from the caller's public balance.
- `cm_new` is appended to `T`.

---

### 2. Unshield (private -> public)

Destroys a private note and releases its value publicly.

**Public inputs:**
- `root` — Merkle root of `T` at proof time
- `nf` — nullifier of the spent note
- `v_pub` — the withdrawn amount

**Private inputs (witness):**
- `sk` — spending key of the note owner
- `rho`, `r` — nonce and blinding factor of the spent note
- `path` — Merkle authentication path for `cm` in `T`

**Constraints proved by the STARK:**
1. `pk = H(sk)`
2. `cm = H(pk, v_pub, rho, r)`
3. `cm` is in `T` under `root` via `path`
4. `nf = H(sk, rho)`

**State changes:**
- `nf` is checked against `NF_set` — reject if present.
- `nf` is added to `NF_set`.
- `v_pub` tokens are credited to the caller's public balance.

---

### 3. Transfer (2-in-2-out JoinSplit)

Consumes up to two private notes and creates up to two new private notes, with total input value equal to total output value. This covers split (1->2), merge (2->1), and simple transfer (1->1) as special cases by setting unused slots to zero-value dummy notes.

**Public inputs:**
- `root` — Merkle root of `T` at proof time
- `nf_a` — nullifier of first spent note
- `nf_b` — nullifier of second spent note
- `cm_1` — first output commitment
- `cm_2` — second output commitment

**Private inputs (witness):**

*Input A:*
- `sk_a` — spending key for input note A
- `v_a`, `rho_a`, `r_a` — amount, nonce, blinding factor for input note A
- `path_a` — Merkle authentication path for input note A

*Input B:*
- `sk_b` — spending key for input note B
- `v_b`, `rho_b`, `r_b` — amount, nonce, blinding factor for input note B
- `path_b` — Merkle authentication path for input note B

*Output 1:*
- `pk_1`, `v_1`, `rho_1`, `r_1` — paying key, amount, nonce, blinding factor

*Output 2:*
- `pk_2`, `v_2`, `rho_2`, `r_2` — paying key, amount, nonce, blinding factor

**Constraints proved by the STARK:**
1. `pk_a = H(sk_a)` and `cm_a = H(pk_a, v_a, rho_a, r_a)` and `cm_a` is in `T` under `root` via `path_a`
2. `nf_a = H(sk_a, rho_a)`
3. `pk_b = H(sk_b)` and `cm_b = H(pk_b, v_b, rho_b, r_b)` and `cm_b` is in `T` under `root` via `path_b`
4. `nf_b = H(sk_b, rho_b)`
5. `nf_a != nf_b` (prevents spending the same note twice in one transaction)
6. `cm_1 = H(pk_1, v_1, rho_1, r_1)`
7. `cm_2 = H(pk_2, v_2, rho_2, r_2)`
8. `v_a + v_b = v_1 + v_2`
9. `v_1 < 2^k` and `v_2 < 2^k` (range checks via `k`-bit binary decomposition — prevents modular arithmetic overflow)

**Dummy notes:** For a 1-in split or 1-out merge, the unused input/output slot uses `v = 0`. A zero-value dummy commitment must still exist in the tree. Rather than relying on system-seeded dummies (whose well-known `sk` would let anyone grief by pre-spending them), users should create their own zero-value notes via Shield with `v_pub = 0`. The nullifier for a zero-value dummy input is still revealed and added to `NF_set`, so each dummy note can only be "spent" once — callers must use distinct dummy notes per transaction.

**State changes:**
- `nf_a` and `nf_b` are each checked against `NF_set` — reject if either is present.
- `nf_a` and `nf_b` are added to `NF_set`.
- `cm_1` and `cm_2` are appended to `T`.

---

## Global State

| Component | Description |
|-----------|-------------|
| `T` | Append-only Merkle tree of all commitments ever created |
| `NF_set` | Set of all revealed nullifiers (enforces single-spend) |

Both are publicly visible. `T` and `NF_set` reveal nothing about amounts or linkage between notes — the commitment hides `(pk, v, rho, r)` and the nullifier `nf = H(sk, rho)` cannot be linked to its commitment without the witness.

**Merkle root validity:** Any root that was ever a valid root of `T` is accepted. Since `T` is append-only, a commitment present under any historical root is still in the current tree. The global nullifier set prevents double-spend regardless of which root a proof references.

---

## Security Properties

- **Balance**: No transaction can create value. Shield/Unshield move exact amounts across the public/private boundary. Transfer enforces `v_a + v_b = v_1 + v_2` with `k`-bit range checks on outputs, preventing modular wraparound. The public layer must enforce `v_pub < 2^k` on Shield/Unshield.
- **Double-spend prevention**: Each note has a unique nullifier `nf = H(sk, rho)`. Spending requires revealing `nf`, and `NF_set` rejects duplicates. Within a single Transfer, `nf_a != nf_b` is enforced in the circuit to prevent spending the same note twice.
- **Spend authority**: Only the holder of `sk` can derive the nullifier for a note paid to `pk = H(sk)`. The sender cannot spend a note they created for someone else.
- **Privacy**: Commitments are hiding (blinding factor `r`). The nullifier is unlinkable to the commitment without knowledge of `sk` and `rho`, so spending does not reveal which commitment was consumed.
- **Soundness**: STARK proofs enforce all constraints — a malicious prover cannot forge a valid proof for any of the three transaction types without a valid witness.

---

## Design Notes

- The hash function `H` is BLAKE2s-256, chosen for its well-established security analysis and native efficiency in the Stwo prover (BLAKE2s is a built-in opcode in the Cairo VM's Stwo backend). Outputs are truncated to 251 bits to fit in the Stark field. Domain separation is achieved via BLAKE2s's byte counter: `H(a)` uses 32 bytes, `H(a,b)` uses 64 bytes, `H(a,b,c,d)` uses 128 bytes (two BLAKE2s blocks).
- The Merkle tree also uses `H` for internal nodes.
- **Amount bit-width `k`:** All amounts must fit in `k` bits (e.g. `k = 64`). Transfer outputs are range-checked inside the circuit. Shield `v_pub` must be range-checked by the public layer before accepting the transaction — failure to do so would let an attacker shield a value near `p`, exploit modular wraparound in a Transfer, and extract inflated value.
- **Dummy notes for flexible arity:** The 2-in-2-out Transfer handles split (1->2), merge (2->1), and 1-to-1 transfer by using zero-value notes in unused slots. Users create their own zero-value notes via Shield with `v_pub = 0` to avoid reliance on shared dummy notes that could be griefed.
- **Viewing keys:** A recipient can derive a separate viewing key from `sk` and share it with auditors to allow decryption of incoming note memos without granting spend authority. This is an application-layer concern and does not affect the circuits.
- **Public outputs:** Each circuit returns its public values as an array of field elements. Shield returns `[v_pub, cm_new]`. Unshield returns `[root, nf, v_pub, recipient]`. Transfer returns `[root, nf_a, nf_b, cm_1, cm_2]`. The on-chain verifier reads these from the proof to update state.
- This spec intentionally omits: fee mechanisms and transaction-level encryption proofs. These can be layered on later.
