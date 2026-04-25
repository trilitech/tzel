# TzEL v2: Security Notes

This document is informative, not normative. The canonical protocol rules and encodings are in `specs/spec.md`.

## Security Properties

- **Balance conservation:** values are u64, arithmetic is carried out in u128, and the circuits enforce exact input/output equality.
- **Double-spend resistance:** nullifiers are unique per spent note position, pairwise distinct within a transaction, and checked against a global on-chain nullifier set.
- **Nullifier binding:** `nk_spend -> nk_tag -> owner_tag -> cm` binds the commitment to the nullifier key material.
- **Spend authority:** the STARK proves both knowledge of `nk_spend` and a valid WOTS+ signature over the sighash. No external signature verification is required.
- **On-chain spend unlinkability:** auth leaves, public keys, and spend signatures do not appear in public outputs.
- **Commitment privacy:** commitments are hiding through `rcm`; nullifiers use separate domains and do not reveal commitments directly.
- **Post-quantum profile:** the design uses BLAKE2s, ML-KEM-768, a hash-based one-time signature, and STARK proofs. It does not rely on elliptic curves or lattice signatures.
- **Zero-knowledge:** the intended deployment profile is the recursive proof path with ZK blinding. Single-level proving is a debug mode, not the privacy target.

## Privacy and Leakage

- **Input count is public:** the number of published nullifiers reveals `N`.
- **Transaction shape and timing are public:** observers still learn transaction type, ordering, and whether there is a change note.
- **Delegated provers get per-address spent-state visibility:** the prover sees per-address values such as `nk_spend_j` and `auth_root_j`. Given public commitments, positions, and the public nullifier set, a prover with `nk_spend_j` can compute candidate nullifiers for one address and learn which public notes for that address have been spent. This is stronger than mere same-address linking.
- **Detection tags are only a filtering aid:** the false-positive rate `2^(-k)` is not, by itself, a meaningful privacy guarantee.
- **Outgoing viewing is sender-scoped:** `outgoing_seed` decrypts sender-recovery ciphertexts for outputs created by the same wallet. It does not detect arbitrary incoming notes, compute nullifiers, or grant spend authority.
- **No expiry in spend authorization:** a delegated prover can withhold a completed authorization until one of its nullifiers is consumed elsewhere. This is a protocol-level anti-withholding gap, not a circuit bug.

## Honest-Sender and Ciphertext Caveats

- **Detection is honest-sender:** a malicious sender can post bogus `ct_d`, causing detection to fail. The recipient then has to rely on viewing-key scanning.
- **Viewing ciphertext correctness is not proven in-circuit:** the proof binds ciphertext bytes, not that `ct_v` / `encrypted_data` decrypt to the same `(v, rseed, memo)` used in the commitment.
- **Recipient address fields are not self-authenticating to the sender:** shield and transfer outputs can be created with malformed `auth_root` / `pub_seed` / `nk_tag`, producing unspendable notes. This is sender self-griefing, not theft.
- **Memo integrity is transport integrity, not semantic correctness:** `memo_ct_hash` prevents relayer mutation of posted note ciphertext fields, but does not prove that the sender encrypted the intended plaintext.
- **Wallets must recompute commitments before showing funds as received:** detection and decryption alone are not enough; note acceptance should be based on exact recomputation of `cm` from local address metadata and decrypted plaintext.

## Wallet and One-Time-Key Safety

- **WOTS+ key reuse is catastrophic:** reusing a one-time key across two transactions can expose enough chain preimages for forgery.
- **Addresses have finite signing capacity:** each address has `2^AUTH_DEPTH` one-time keys. Addresses must be rotated before exhaustion.
- **Wallet state is part of the security boundary:** stale backups, multi-device races, or failed submissions that roll back key allocation can cause one-time-key reuse.
- **Implementations must persist state durably before submission:** this includes per-address WOTS index advancement and any note/account state used to avoid key reuse.
- **Backup restore needs operational discipline:** restoring an older wallet file can silently roll back the next WOTS leaf and re-enable catastrophic one-time-key reuse unless the restored file is known to be fresher than every previously used copy.
- **Reference wallet files are plaintext:** the current wallet format stores `master_sk` and address state unencrypted on disk. File permissions should be restricted tightly; at-rest encryption and memory zeroization remain future hardening work.

## Deployment Notes

- **The reference CLI ledger is demo-only:** `sp-ledger` is a localhost/reference verifier for proof and state-transition checks, not a production bridge or authenticated account system.
- **L1 withdrawal recipients must be specified exactly in deployments:** unshield binds `H(UTF8(canonical_recipient))`, where `canonical_recipient` is the validated tz1/tz2/tz3/KT1 base58 string. Any replacement format must define the exact byte encoding and verifier rule.
- **Shield proofs are intent-bound and domain-bound:** every prover-rewritable field — auth_domain, value, fees, recipient and producer commitments, memo ciphertext hashes — is folded into `deposit_id` via `H_intent`. Cross-deployment replay fails because `auth_domain` is in the intent, and prover-side redirection fails because the kernel recomputes the intent from request fields and rejects a mismatch. Sender-side footguns (over/under-funding the L1 deposit, depositing twice to the same intent) are not addressed by the protocol; deposit balances that do not match the bound debit are unrecoverable. Bridges should refuse top-up credits to non-zero `deposit:<hex>` balances.
- **Shield is safe to delegate to an untrusted prover:** the witness exposes only public-on-the-wire material (recipient address fields, rseed, encrypted-note bytes); none of that grants spend authority because the intent commits to it all. An attacker who steals the witness cannot construct any shield other than the one the L1 deposit already committed to.
- **Proof verification must remain bound to the intended executable and authorization domain:** otherwise a valid proof may be accepted in the wrong verifier context.

## Additional Cryptographic Assumptions and Review Burden

- **ML-KEM failure is primarily a privacy failure:** memo confidentiality, recipient privacy, and detection degrade if ML-KEM breaks; spend authority does not directly derive from ML-KEM.
- **The hash-based spend-authority construction is custom:** it is straightforward and WOTS-like, but it is not the exact standardized XMSS/WOTS+ instantiation, so it carries more direct review burden.
- **ML-KEM key anonymity should be treated as an explicit assumption:** the protocol benefits from recipient-key anonymity properties beyond plain IND-CCA2 confidentiality.
