# TzEL v2: Security Notes

This document is informative, not normative. The canonical protocol rules and encodings are in `specs/spec.md`.

## Security Properties

- **Balance conservation:** values are u64, arithmetic is carried out in u128, and the circuits enforce exact input/output equality. With multiasset, balance is per-asset: the circuit enforces `tez_in = tez_out + fee` AND `primary_in = primary_out` separately (see Multiasset Security below). A pre-fix bug (`unshield.cairo`, commit `2003bf5`) allowed an unconditional `tez_out += v_pub` regardless of `asset_pub`, which an attacker could exploit to mint FA2 tokens on L1 backed by other users' tez deposits. The fix routes `v_pub` to `tez_out` or `primary_out` based on `asset_pub`.
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
- **Shield proofs are signature-bound and domain-bound:** every prover-rewritable field — auth_domain, pubkey_hash, value, fees, recipient and producer commitments, memo ciphertext hashes — is folded into the shield sighash and signed by an in-circuit WOTS+ signature under the recipient's auth tree. Cross-deployment replay fails because `auth_domain` is in both the sighash and the pubkey_hash. Prover-side redirection fails because the kernel checks the proof's public outputs against the request fields and a delegated prover holding the witness still cannot resign the sighash without the wallet's WOTS+ signing key.
- **Bridge deposits aggregate per-pool, not per-slot:** every L1 ticket addressed to `deposit:<hex(pubkey_hash)>` adds to a single per-pool balance keyed by `(asset_id, pubkey_hash)` where `pubkey_hash = H(0x04, auth_domain, auth_root, auth_pub_seed, blind)` and `asset_id` is determined by the ticketer KT1 that emitted the L1 ticket. Multiple L1 tickets from the same ticketer to the same recipient top up the balance; shield draws by `v + fee` (FA2) or `v + fee + producer_fee` (tez) from the asset pool, and FA2 shields ALSO debit `producer_fee` from the user's tez pool at the same `pubkey_hash`. Partial draws are supported. A dust attacker mirroring a victim's pool only donates the underlying L1 token to the victim — the wallet that knows the blind chooses any draw it can afford. The same `pubkey_hash` can host distinct (asset, tez) pools simultaneously; the FA2-shield producer-fee debit explicitly relies on this dual-pool layout.
- **Shield delegation has the same trust profile as transfer / unshield:** the in-circuit WOTS+ verify means the wallet must be online to sign each shield (one WOTS+ key consumed per request). A delegated prover can still see the witness, but cannot construct a different draw because the sighash is signed by a key the prover doesn't hold. The prior "delegate-friendly stateless shield" property is gone, traded for stronger UX (top-ups, partial drains, no fee escalation hazard).
- **Proof verification must remain bound to the intended executable and authorization domain:** otherwise a valid proof may be accepted in the wrong verifier context.

## Multiasset Security

The multiasset upgrade introduced several asset-specific invariants. Three CRITICAL bugs were found and fixed during pre-deployment audit:

- **Per-asset balance is enforced via 2-accumulator constraints:** Cairo cannot iterate over felts, so circuits take a witness-declared "primary non-tez asset" `A` and pin every input/output asset to `{ASSET_TEZ, A}`. The accumulators `tez_in/tez_out` and `primary_in/primary_out` close per-asset. Bug #1 (`v_pub` lane-routing in unshield, commit `2003bf5`) was a CRITICAL violation of this — an unconditional `tez_out += v_pub` regardless of `asset_pub` let a tez-only input set mint FA2 tokens on L1 backed by other users' tez deposits. The fix routes `v_pub` to the right accumulator based on `asset_pub`.

- **Producer fee is permanently tez:** asserted in-circuit (`asset_producer == ASSET_TEZ` in shield; `asset_4 == ASSET_TEZ` in transfer; `asset_fee == ASSET_TEZ` in unshield). The DAL slot publisher receives a tez note regardless of which asset moved in the transaction. Justification: a hostile publisher submitting blocks containing only fee-paid-in-illiquid-NFT transactions would starve the inclusion market.

- **FA2 shields require a tez pool at the same pubkey_hash:** because the producer-fee output is tez, the kernel debits `producer_fee` from a separate `(ASSET_TEZ, pubkey_hash)` pool when shielding an FA2. Bug #2 (commit `aff523a`) was a CRITICAL omission of this split-debit — the kernel was draining `v + fee + producer_fee` from the FA2 pool alone, creating `producer_fee` tez out of nothing (drainable later via the tez ticketer's L1 backing). The fix adds the tez-pool validation and debit in both `prepare_shield` (core) and `prepare_durable_shield_commit` (kernel). FA2 shields now require both pools.

- **Canonical L2 ticket content:** the FA2 bridge ticketer emits L2 tickets with content `(0, None)` regardless of the underlying FA2's `token_id`. Bug #3 (commit `73ad6fb`) was a CRITICAL bricking of FA2 bridges with `token_id != 0` — the previous design stuffed `storage.token_id` into the L2 ticket content, but the kernel uniformly rejects any deposit ticket with `content.token_id != 0`. The fix makes the L2 ticket content canonical and binds the FA2 token_id only via the ticketer's immutable storage. Without this fix, any deposit of a non-zero-token_id FA2 would be permanently locked in the bridge ticketer.

- **Watch wallets iterate the candidate-asset registry:** view-mode and outgoing-mode watch wallets cannot tell which asset a note carries from `cm` alone, so they recompute `cm_expected` under each registered asset and pick the match. Pre-fix watchers hardcoded `ASSET_TEZ` and silently dropped every FA2 note (bugs W1/W2, commit `6973d82`). No fund loss (full wallets still worked), but auditor / outgoing-history visibility was broken for FA2.

- **Operator dal-fee policy inspects cm_4 in transfers:** Phase C added a 4th output slot (`cm_4 = producer fee`). The operator's `enforce_dal_fee_policy` initially looked at `cm_3`, which under Phase C is the `change_2` placeholder. Any transfer with a fee policy configured got rejected before DAL publish. Bug #4 (commit `c9953e0`) fixed the slot, restoring transfer liveness for operators with dal-fee policies.

- **Asset registry skips duplicate tez ticketers:** `compose_asset_registry_with` silently skips any FA2 entry equal to the configured `tez_ticketer` string. This prevents a misconfiguration where the same KT1 appears twice in the registry with two different asset_ids; without the guard, lookups returning first-match would mask the FA2 entry behind the tez entry, making first-match ordering a security property. Defense-in-depth, not exploitable.

- **`MAX_ACCOUNT_ID_BYTES = 128` on wire:** the kernel-decoder caps ticketer address fields at 128 bytes (real Tezos addresses are 36 bytes). Previously 1024; tightened during audit to shrink the untrusted-input allocation footprint.

- **`validate_l1_ticketer_canonical` for boundary inputs:** any caller reading a ticketer string from an untrusted source (CLI, JSON, env var) MUST route through this validator before calling `derive_asset_id`. It trims whitespace, requires KT1 (Originated), and runs b58check parse + re-emit to reject non-canonical encodings. Without canonicalization, a paste with a trailing newline produces a divergent `asset_id` and silently strands user funds.

## Additional Cryptographic Assumptions and Review Burden

- **ML-KEM failure is primarily a privacy failure:** memo confidentiality, recipient privacy, and detection degrade if ML-KEM breaks; spend authority does not directly derive from ML-KEM.
- **The hash-based spend-authority construction is custom:** it is straightforward and WOTS-like, but it is not the exact standardized XMSS/WOTS+ instantiation, so it carries more direct review burden.
- **ML-KEM key anonymity should be treated as an explicit assumption:** the protocol benefits from recipient-key anonymity properties beyond plain IND-CCA2 confidentiality.
