# StarkPrivacy: Minimal Private Transaction Spec

## Overview

A UTXO-based private transaction system using a Merkle commitment tree, nullifiers for double-spend prevention, and three transaction types: **Shield**, **Unshield**, and **Transfer**. All proofs are realized as two-level STARKs: a Cairo AIR proof compressed by an Stwo circuit reprover. The circuit proof has zero-knowledge blinding, ensuring that FRI query responses do not leak information about private witness data.

The protocol supports **delegated proving**: users can hand off proof generation to an untrusted third party without risking fund theft. This is achieved by splitting key material into a nullifier key (given to the prover) and an authorization key (kept by the user), following the approach pioneered by Zcash Sapling.

---

## Primitives

| Symbol | Description |
|--------|-------------|
| `H(...)` | BLAKE2s-256 hash function (truncated to 251 bits for field compatibility) |
| `master_sk` | Master spending key — root secret, never shared |
| `nsk` | Nullifier secret key — per-note, derived from `master_sk`, given to prover |
| `pk` | Paying key — public, derived as `pk = H(nsk)` |
| `ask` | Authorization signing key — per-note, derived from `master_sk`, NEVER shared |
| `ak` | Authorization verifying key — public, derived as `ak = H(ask)` |
| `cm` | Note commitment |
| `nf` | Nullifier — derived as `H(nsk, rho)`, revealed when a note is spent |
| `rho` | Note nonce — random field element, unique per note |
| `r` | Blinding factor (random field element) |
| `v` | Amount (field element, non-negative) |
| `T` | Merkle tree of commitments |
| `root` | Merkle root of `T` |
| `path` | Merkle authentication path proving membership in `T` |
| `NF_set` | Global set of revealed nullifiers |

## Key Hierarchy

Each user holds a single `master_sk`. All per-note keys are derived from it:

```
master_sk
├── nsk_i = H(H("nsk", master_sk), i)   — nullifier secret key for note i
│   └── pk_i = H(nsk_i)                 — paying key (public, given to senders)
└── ask_i = H(H("ask", master_sk), i)   — authorization signing key for note i
    └── ak_i = H(ask_i)                 — authorization verifying key (public)
```

**Per-note derivation** ensures that different notes have unrelated keys. A prover who learns `nsk_i` for one note cannot derive keys for any other note (that requires `master_sk`).

**Key separation** enables delegated proving:
- The **prover** receives `(nsk_i, ak_i, v, rho, r, Merkle path)` — enough to generate the STARK proof.
- The **user** keeps `ask_i` and signs the proof's public outputs after the prover returns the proof. The on-chain contract verifies this signature against `ak_i` (which appears in the proof output).
- The prover cannot authorize a spend because they don't have `ask_i`.

## Note Structure

A **note** is the tuple `(pk, ak, v, rho, r)`. Its commitment is:

```
cm = H(H(pk, ak), v, rho, r)
```

The inner `H(pk, ak)` is called the **owner key** — it fuses the nullifier key and authorization key domains. The commitment is bound to both, ensuring a note can only be spent by someone who controls both keys.

- `pk` is derived from `nsk` (the nullifier key) — determines who can compute the nullifier.
- `ak` is derived from `ask` (the authorization key) — determines who can authorize the spend.
- `v` is the amount, kept secret.
- `rho` is a random nonce chosen by the note creator, unique per note.
- `r` is a random blinding factor, kept secret.

The commitment `cm` is appended to the Merkle tree `T`. The note is spent by revealing its nullifier:

```
nf = H(nsk, rho)
```

Only the owner (who knows `nsk`) can compute `nf`. Once `nf` appears in `NF_set`, the note cannot be spent again.

### Encrypted memo

When creating a note for a recipient, the sender encrypts `(v, rho, r)` under the recipient's public encryption key (an X25519 key, separate from the spending keys) and attaches the ciphertext to the transaction. The recipient scans transactions, decrypts memos with their key, and recovers the note data needed to later spend. This is application-layer — no proof of correct encryption is required.

---

## Transaction Types

### 1. Shield (public -> private)

Deposits `v_pub` tokens from the public domain into a new private note.

**Public outputs:**
- `v_pub` — the deposited amount
- `cm_new` — the new note commitment
- `ak` — authorization verifying key (for spend signature verification)
- `sender` — depositor's public address (prevents front-running)

**Private inputs (witness):**
- `pk` — paying key
- `rho`, `r` — nonce and blinding factor for the new note

**Constraints proved by the STARK:**
1. `cm_new = H(H(pk, ak), v_pub, rho, r)`

**Verification:**
- STARK proof is valid
- Signature over outputs is valid under `ak`
- `msg.sender == sender`

**State changes:**
- `v_pub` tokens are consumed from `sender`'s public balance.
- `cm_new` is appended to `T`.

---

### 2. Unshield (private -> public)

Destroys a private note and releases its value publicly.

**Public outputs:**
- `root` — Merkle root of `T` at proof time
- `nf` — nullifier of the spent note
- `v_pub` — the withdrawn amount
- `ak` — authorization verifying key
- `recipient` — destination address (prevents front-running)

**Private inputs (witness):**
- `nsk` — nullifier secret key
- `rho`, `r` — nonce and blinding factor of the spent note
- `path` — Merkle authentication path for `cm` in `T`

**Constraints proved by the STARK:**
1. `pk = H(nsk)`
2. `cm = H(H(pk, ak), v_pub, rho, r)`
3. `cm` is in `T` under `root` via `path`
4. `nf = H(nsk, rho)`

**Verification:**
- STARK proof is valid
- Signature over outputs is valid under `ak`
- `root` is a valid historical root of `T`
- `nf ∉ NF_set`

**State changes:**
- `nf` is added to `NF_set`.
- `v_pub` tokens are credited to `recipient`'s public balance.

---

### 3. Transfer (2-in-2-out JoinSplit)

Consumes up to two private notes and creates up to two new private notes, with total input value equal to total output value. This covers split (1->2), merge (2->1), and simple transfer (1->1) as special cases by setting unused slots to zero-value dummy notes.

**Public outputs:**
- `root` — Merkle root of `T` at proof time
- `nf_a` — nullifier of first spent note
- `nf_b` — nullifier of second spent note
- `cm_1` — first output commitment
- `cm_2` — second output commitment
- `ak_a` — authorization key for input note A
- `ak_b` — authorization key for input note B

**Private inputs (witness):**

*Input A:*
- `nsk_a` — nullifier secret key for input note A
- `ak_a` — authorization verifying key for input note A
- `v_a`, `rho_a`, `r_a` — amount, nonce, blinding factor
- `path_a` — Merkle authentication path

*Input B:* (same structure)

*Output 1:*
- `pk_1`, `ak_1`, `v_1`, `rho_1`, `r_1` — paying key, auth key, amount, nonce, blinding factor

*Output 2:* (same structure)

**Constraints proved by the STARK:**
1. For both inputs: `pk = H(nsk)`, `cm = H(H(pk, ak), v, rho, r)`, Merkle membership
2. `nf_a = H(nsk_a, rho_a)` and `nf_b = H(nsk_b, rho_b)`
3. `nf_a != nf_b`
4. `cm_1 = H(H(pk_1, ak_1), v_1, rho_1, r_1)` and `cm_2 = H(H(pk_2, ak_2), v_2, rho_2, r_2)`
5. `v_a + v_b = v_1 + v_2`
6. `v_1 < 2^64` and `v_2 < 2^64`

**Verification:**
- STARK proof is valid
- Signature over outputs is valid under `ak_a` AND `ak_b` (both inputs must be authorized)
- `root` is a valid historical root of `T`
- `nf_a ∉ NF_set` and `nf_b ∉ NF_set`

**State changes:**
- `nf_a` and `nf_b` are added to `NF_set`.
- `cm_1` and `cm_2` are appended to `T`.

**Dummy notes:** For a 1-in split or 1-out merge, the unused input/output slot uses `v = 0`. A zero-value dummy commitment must still exist in the tree. Users create their own zero-value notes via Shield with `v_pub = 0`.

---

## Delegated Proving

The protocol is designed so that proof generation can be delegated to an untrusted third party:

1. The **user** constructs the transaction, deriving per-note keys from `master_sk`.
2. The user gives the **prover**: `(nsk_i, ak_i, v, rho, r, Merkle path)` per input note, plus all output note data.
3. The **prover** generates the STARK proof (computationally expensive).
4. The **user** signs the proof's public outputs with `ask_i` (a single hash — trivially cheap).
5. The transaction (proof + signature) is submitted in a single on-chain call.

**Security guarantees:**
- The prover cannot steal funds — they don't have `ask_i` and cannot forge the spend authorization signature.
- The prover cannot learn about other transactions — per-note keys (`nsk_i`, `ak_i`) are pseudorandom and unlinkable across notes.
- The prover cannot spend other notes — deriving keys for note `j` requires `master_sk`.
- The prover learns the content of this specific transaction (amounts, recipients by pk). This is the minimum possible — you cannot prove a statement without the prover knowing what is being proved.

---

## Global State

| Component | Description |
|-----------|-------------|
| `T` | Append-only Merkle tree of all commitments ever created |
| `NF_set` | Set of all revealed nullifiers (enforces single-spend) |

Both are publicly visible. `T` and `NF_set` reveal nothing about amounts or linkage between notes — the commitment hides `(pk, ak, v, rho, r)` and the nullifier `nf = H(nsk, rho)` cannot be linked to its commitment without the witness.

**Merkle root validity:** Any root that was ever a valid root of `T` is accepted. Since `T` is append-only, a commitment present under any historical root is still in the current tree. The global nullifier set prevents double-spend regardless of which root a proof references.

---

## Security Properties

- **Balance**: No transaction can create value. Shield/Unshield move exact amounts across the public/private boundary. Transfer enforces `v_a + v_b = v_1 + v_2` with 64-bit range checks on outputs, preventing modular wraparound.
- **Double-spend prevention**: Each note has a unique nullifier `nf = H(nsk, rho)`. Spending requires revealing `nf`, and `NF_set` rejects duplicates. Within a single Transfer, `nf_a != nf_b` is enforced in the circuit.
- **Spend authority**: Only the holder of both `nsk` (for the proof) and `ask` (for the signature) can spend a note. The sender who created the note knows `pk` and `ak` but not `nsk` or `ask`.
- **Delegated proving safety**: The prover sees `nsk` and `ak` but not `ask`. They can generate a valid proof but cannot authorize the spend. Per-note key derivation ensures knowledge of one note's keys reveals nothing about other notes.
- **Privacy**: Commitments are hiding (blinding factor `r`). The nullifier is unlinkable to the commitment without knowledge of `nsk` and `rho`. Per-note keys prevent cross-transaction linkability.
- **Soundness**: STARK proofs enforce all constraints. The two-level recursive proof provides 96-bit security with zero-knowledge blinding on the circuit layer.

---

## Design Notes

- The hash function `H` is BLAKE2s-256, chosen for its well-established security analysis and native efficiency in the Stwo prover. Outputs are truncated to 251 bits for field compatibility. Domain separation is achieved via BLAKE2s's byte counter: `H(a)` uses 32 bytes, `H(a,b)` uses 64 bytes, `H(a,b,c,d)` uses 128 bytes.
- The Merkle tree uses `H(a,b)` for internal nodes.
- **Amount bit-width `k`:** All amounts must fit in 64 bits. Transfer outputs are range-checked inside the circuit. Shield `v_pub` must be range-checked by the public layer.
- **Owner key:** The commitment uses `H(pk, ak)` as its first field, fusing the nullifier and authorization key domains. This ensures the commitment is bound to both keys without changing the hash4 interface.
- **Public outputs:** Shield returns `[v_pub, cm_new, ak, sender]`. Unshield returns `[root, nf, v_pub, ak, recipient]`. Transfer returns `[root, nf_a, nf_b, cm_1, cm_2, ak_a, ak_b]`. The on-chain verifier reads `ak` values to verify spend authorization signatures.
- **No pre-registration:** Unlike systems that require pre-submitted transaction intents, authorization is checked via a signature included in the same transaction as the proof. No additional on-chain interaction is needed before proving.
- This spec intentionally omits: fee mechanisms, transaction-level encryption proofs, and the specific signature scheme for spend authorization (any standard scheme — Ed25519, Schnorr, etc. — works since it's checked by the contract, not inside the circuit).
