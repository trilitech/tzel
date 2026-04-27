# TzEL post-redesign findings

This file consolidates everything that turned up during the deposit-pool /
pubkey_hash redesign audit, the shield-circuit security review, and the
post-fix reviews. Each finding is tagged with severity and current status.

Severity:
- **CRIT** — exploitable, breaks consensus / custody / soundness.
- **HIGH** — exploitable for theft or DoS at non-trivial cost.
- **MED**  — exploitable for nuisance, privacy leak, or operator harm
  without direct theft.
- **LOW**  — code-quality / defense-in-depth gap; not exploitable on its own.
- **INFO** — design observation, doc gap, or known trade-off.

Status:
- **FIXED** — patched; regression test exists.
- **OPEN**  — not patched.
- **WONTFIX** — explicit design decision.

---

## Kernel — deposit-pool / shield logic

### F-K-1 [HIGH, FIXED] — Drained pools could not be redeposited

`apply_durable_shield_commit` writes empty bytes to the balance path on
full drain (best-effort delete on the WASM PVM, which has no native
delete primitive). A subsequent L1 deposit to that pool hit
`credit_deposit` → `read_store` returned `Some(empty_bytes)`, the
`bytes.len() != 8` check fired, and the deposit errored with
`bad u64 at ...`. After a single full drain the pool was effectively
bricked.

**Fix:** `credit_deposit`, `debit_deposit`, and `deposit_balance` now
treat `Some(empty)` as `None`, matching the convention
`prepare_durable_shield_commit` and the wallet's
`try_read_deposit_balance` already used. The "bad u64" error is now
reserved for genuine durable-store corruption (non-empty, non-8-byte
values).

**Regression:** `pool_can_be_redeposited_after_full_drain` constructs
the post-drain durable state and confirms a fresh L1 ticket succeeds.

**Commit:** `9415a9e`.

### F-K-2 [HIGH, FIXED] — Shield proofs were replayable after pool top-up

The kernel had no replay-protection set for shields. Anyone observing
a victim's valid shield could top up the now-drained pool by exactly
the original debit (mirror deposit / aggregating top-up), resubmit the
same `KernelShieldReq` byte-for-byte, and have the kernel mint a
duplicate of the recipient's note at a fresh tree position. Because
nullifiers are per-position, that duplicate was independently
spendable — the victim's shielded balance silently doubled at the
dust-attacker's expense. The system stayed solvent (the attacker's
mutez funded the duplication) but it allowed:
- silently doubling a victim's shielded balance,
- forging a shield-replay public signal in the tree (privacy leak),
- griefing by inflating the merkle tree at known cost.

**Fix:** added `applied_shield_cms: HashSet<F>` to `tzel_core::Ledger`
and a durable path `/tzel/v1/state/shields/applied_cm/<hex>` in the
kernel. `LedgerState` extended with `has_applied_shield` /
`mark_applied_shield`. `prepare_shield` and
`prepare_durable_shield_commit` reject requests whose `client_cm`
already has a marker; `commit_prepared_shield` and
`apply_durable_shield_commit` write the marker after the balance debit
so subsequent prepare steps observe the post-apply state. OCaml
`Ledger.t` mirrors with `applied_shield_cms : (string, unit)
Hashtbl.t`.

**Why it works:** the WOTS+ signature in the shield circuit signs a
sighash that includes `cm_new`, so a third-party prover with the
witness cannot construct a *different* `cm_new` (would need to forge
the sig) — they can only resubmit the same one, which the kernel set
catches.

**Regressions:**
- `verified_shield_rejects_replay_after_pool_topup` (kernel-level,
  end-to-end against a real STARK proof).
- `test_apply_shield_rejects_replay_of_same_client_cm` (in-memory
  `Ledger`, deterministic).
- `test_apply_shield_two_distinct_shields_can_share_one_pool`
  (positive control: distinct rseeds → distinct cms → both succeed).

**Commit:** `9415a9e`.

---

## Wallet

### F-W-1 [MED, FIXED] — `tzel-wallet deposit` advertised stale flags

The CLI exposed `--to`, `--memo`, `--fee` on the deposit command, but
the post-redesign implementation discarded those user inputs outright
(parameters bound to `_to`, `_memo`, `_fee_arg` and never read). A user
who wrote `tzel-wallet deposit --amount X --to alice` would in fact
fund a fresh self-owned pool keyed by a freshly-allocated auth tree
address, *not* a pool bound to alice. Real L1 mutez gone, intended
binding silently ignored.

**Fix:** dropped the three flags from the CLI definition, the
dispatch, and the `cmd_bridge_deposit` signature. The doc string now
describes the actual semantics (fresh self-owned pool; recipient/fee/
memo decided at shield time). Users physically cannot pass the
misleading flags.

**Commit:** `a7c7c2c`.

### F-W-2 [LOW, FIXED] — Wallet conflated "never credited" with "fully drained"

Pool reporting in `cmd_user_balance`, `cmd_wallet_check`, and
`cmd_rollup_sync` computed `unfunded = pending_deposits.len() -
funded_count` and printed "awaiting on-chain credit". `try_read_
deposit_balance` correctly returns `None` for both states (the kernel
writes empty bytes after a full drain), but the wallet had no local
signal to disambiguate. After a successful shield the user was told
the deposit was still "awaiting on-chain credit." There was also no
pruning path, so drained pools accumulated forever.

**Fix:** added `shielded_cm: Option<F>` to `PendingDeposit`.
`cmd_shield_rollup` records the recipient cm immediately after
submission. `apply_scan_feed` prunes entries when *both* signals align
(kernel reports zero balance AND the cm is observed in the feed);
keeping a funded pool around even with the cm in the feed handles dust
top-ups. Reporting now splits no-balance pools into "awaiting on-chain
credit" (no shield submitted) vs "drained but not yet pruned (run
sync)".

**Regressions:**
- `test_apply_scan_feed_prunes_drained_pool_after_recipient_cm_seen`
  (two-stage observation: keep until cm seen, prune once both signals
  align).
- `test_apply_scan_feed_keeps_funded_pool_even_when_cm_observed`
  (defensive twin: a funded pool stays put even if its cm leaks into
  the feed).

**Commit:** `a7c7c2c`.

### F-W-3 [LOW, OPEN] — Multi-stage drain of the same pool can pin `PendingDeposit` forever

Two compounding mistakes in the F-W-2 fix:

1. **`cmd_shield_rollup` only sets `shielded_cm` when it's currently
   `None`.** The filter at `apps/wallet/src/lib.rs:7214` is
   `p.pubkey_hash == pubkey_hash && p.shielded_cm.is_none()`. So a
   second shield against the same pool (legitimate — core supports
   distinct-cm draws against one pool, see
   `test_apply_shield_two_distinct_shields_can_share_one_pool`) does
   not update `shielded_cm`; the entry stays pinned to the *first*
   shield's `cm1`.

2. **`apply_scan_feed` builds `known_cms` from `feed.notes` only**, the
   incremental feed since the last sync cursor. So `cm1` (observed in
   an earlier sync) is not in the current set even though it is in
   `w.notes`.

Reachable sequence:

   1. Pool funded with X.
   2. Shield 1 drains v1 < X, mints cm1; wallet sets
      `shielded_cm = Some(cm1)`.
   3. Sync 1: cm1 in feed, pool balance > 0 → don't prune (correct).
   4. Shield 2 drains the residue, mints cm2; the `is_none()` filter
      excludes the entry, so `shielded_cm` stays `Some(cm1)`.
   5. Sync 2: cm2 in feed (not cm1), pool balance == 0 → predicate is
      `drained && (cm1 ∈ {cm2})` = `drained && false` → don't prune.

The entry is stuck forever. Reporting permanently shows "drained but
not yet pruned" or, if the user does a fresh sync run with `cm2`
present from the start, an even more confusing state where a fully
consumed pool stays counted.

Impact: stale local deposit metadata and misleading operational
output after legitimate multi-step drains. Not a consensus or custody
break.

**Suggested shape of fix (not applied):** drop the `is_none()` filter
so `cmd_shield_rollup` always overwrites `shielded_cm` with the latest
cm; and have `apply_scan_feed` evaluate `cm_observed` against
`w.notes` (cumulative) plus the new feed leaves, instead of just the
incremental feed. Add a regression test that mirrors the five-step
sequence above.

---

## Shield circuit (`cairo/src/shield.cairo`, `xmss_common.cairo`, `blake_hash.cairo`)

The shield circuit is **sound** under standard WOTS+ + BLAKE2s
assumptions. The findings below are quantitative reductions, code-
quality gaps, and design observations.

### F-C-1 [LOW, OPEN] — Two trailing message digits are always zero

`u32x8_to_felt` masks `h7` to `0x07FFFFFF` (251-bit felt252 ceiling),
but `felt_to_u32x8` doesn't re-mask. So when `sighash_to_wots_digits`
walks the 8 u32 words, the top **4 bits of w7** are guaranteed zero —
that's the last 2 base-4 digits, `digits[126]` and `digits[127]`.
Those chains are always at digit 0, so every shield signature reveals
the WOTS+ secrets for chains 126 and 127.

The checksum (chains 128–132) compensates, so effective security goes
from `4^131` to `4^129`. Still vastly above 128-bit. Not a break, but
the protocol is silently giving up two chains; a future change that
loosened the checksum or shortened the message space could push this
into "actually exploitable" territory.

### F-C-2 [LOW, OPEN] — Dead WOTS+ IV

`blake_hash.cairo` defines `blake2s_iv_wots()` ("wotsSP__") and
`pub fn hash1_wots(a)` that uses it. Neither is called anywhere in
production circuit code; `xmss_chain_step` (the actual chain hash)
uses `hash3_generic` (untyped IV) and relies entirely on the ADRS for
domain separation. There's even a unit test
`test_hash1_wots_uses_distinct_domain` keeping the dead code wired to
test infra.

Two risks: (a) someone sees `hash1_wots` and assumes it's the chain
hash, and (b) refactoring could plausibly switch from one to the other
and silently change the protocol's hash. ADRS-based domain separation
is RFC-8391-style and is sound; the issue is purely that the codebase
advertises an alternative that nothing uses.

### F-C-3 [LOW, OPEN] — Length checks live at the wrong layer

`xmss_recover_pk` does `*wots_sig.at(j)` and `*digits.at(j)` for
`j in 0..WOTS_CHAINS` without internally validating either length.
If a future caller forgets the top-level
`assert(wots_sig_flat.len() == WOTS_CHAINS, ...)` — which `shield.
cairo:58`, `transfer.cairo:72`, and `unshield.cairo` all currently
do — a malformed witness either panics mid-computation (short input)
or silently truncates (extra entries unconsumed). `xmss_verify_auth`
*does* assert siblings length internally; `xmss_recover_pk` is
asymmetric. Defense-in-depth gap.

### F-C-4 [LOW, OPEN] — `auth_idx` overflow path is `try_into().unwrap()`

`shield.cairo:97`:

```cairo
let auth_idx_u32: u32 = auth_idx.try_into().unwrap();
```

`auth_idx` arrives as u64; values > `u32::MAX` panic via the unwrap
rather than producing a typed error. The shield-tree-depth check
(`xmss_verify_auth`'s `assert(idx == 0)` after `AUTH_DEPTH` halvings)
catches `2^16 ≤ auth_idx ≤ u32::MAX`, but the panic path is non-
uniform. Cairo's prover refuses to produce a proof on panic, so this
isn't exploitable — it just means a crafted witness fails with a
less informative error than the `'shield: ...'` asserts above.

### F-C-5 [INFO, WONTFIX] — Recipient must own the pool's auth tree

`pubkey_hash = fold(0x04, auth_domain, auth_root, auth_pub_seed,
blind)` shares `(auth_root, auth_pub_seed)` with the recipient's
`owner_tag`. So a shield from pool P can only mint a recipient note
owned by P's own auth tree. You cannot shield from your pool to a
friend's address — you'd have to shield to yourself, then transfer.

By design (the constraint that closes the dust-bricking attack), but
the doc comment at the top of `shield.cairo` does not make this
explicit; only the wallet code does.

### F-C-6 [LOW, OPEN] — Producer note witness is unconstrained relative to recipient

Nothing in the circuit prevents the prover from passing
`(producer_auth_root, producer_auth_pub_seed, producer_nk_tag,
producer_d_j) == (auth_root, auth_pub_seed, nk_tag, d_j)` and
`producer_rseed == rseed`. With `producer_fee == v_note`, that yields
`cm_producer == cm_new`. The kernel's replay set tracks `cm_new` only,
so two appended leaves with identical cm are not blocked at the
kernel level — both are independently spendable (different positions
→ different nullifiers).

Same failure mode as the wallet routing producer notes back to itself,
which the kernel also doesn't enforce. Worth noting that the *circuit*
makes it trivially possible.

### F-C-7 [LOW, OPEN] — `producer_fee > 0` is the only positivity check in the circuit

`v_note == 0` is allowed (legal "donate everything to fees" shield),
`fee == 0` is allowed (kernel-side `prepare_shield` enforces
`fee >= required_tx_fee`, but the *circuit* doesn't). A circuit-only
deployment without the kernel's fee-floor check would happily prove
`v=0, fee=0, producer_fee=1` shields. Acceptable given the layered
design, but worth pinning down which checks live where.

### F-C-8 [INFO, WONTFIX] — Kernel can't detect WOTS+ key reuse

`auth_idx` is a *private* witness, never a public output. A wallet
that signs two different sighashes with the same `auth_idx` (e.g.,
restored from a stale backup) leaks enough state for an observer of
both signatures to forge under that key. The circuit can't see this —
`auth_idx` is unbound to anything kernel-visible. By design (privacy:
the kernel doesn't learn which key was used) but the consequence is
a wallet-side correctness obligation with no on-chain backstop.

The realistic mitigation is a wallet-side sync-from-chain step that
clamps `bds.next_index` upward by inferring used auth_idx values from
recovered notes. Not implemented; tracked as a future feature.

### F-C-9 [INFO, OPEN] — `pack_adrs` slot widths assume u32 fits

`pack_adrs(tag, key_idx, a, b, c)` packs four 32-bit slots starting at
bits 64, 96, 128, 160. Tag occupies bits 0–63. Currently
`key_idx ≤ 2^16-1`, `chain_idx ≤ WOTS_CHAINS=133`, `step ≤ W-2=2`,
all way within u32. Domain separation depends on these slots not
overlapping in the felt addition. They won't given current values; a
future change that pushed any field above `2^32` would cause silent
collisions in the address scheme.

### F-C-10 [INFO, OPEN] — `xmss_recover_pk` doesn't validate `digits.len()`

The function loops `while j < WOTS_CHAINS` and indexes
`digits.at(j)`. `sighash_to_wots_digits` always produces 133, so this
is fine *now*. If `WOTS_CHAINS` ever decoupled from
`sighash_to_wots_digits`'s output length, this would silently
truncate or panic.

### F-C-11 [INFO, WONTFIX] — felt-encoded BLAKE2s output is 251-bit

`u32x8_to_felt` masks `h7` to 251 bits (top 5 bits dropped). All hash
outputs in the system have 5 fewer effective bits than naive BLAKE2s.
Birthday bound ~2^125.5. Still above 128-bit security but not
128-bit *with margin*. Same observation applies to transfer and
unshield; not shield-specific. Forced by the felt252 representation;
no fix without a different field.

---

## Kernel-level enforcement gaps (out of audit scope, pre-existing)

### F-X-1 [MED, OPEN] — Producer-fee owner_tag not enforced on chain

The kernel's verifier config has `operator_producer_owner_tag` but
the kernel never checks the producer note's owner_tag against it.
The wallet's `cmd_shield_rollup` checks via
`ensure_operator_producer_owner_tag_matches`, but a malicious or
rogue wallet/prover can route the producer note anywhere — including
back to themselves — bypassing the operator's revenue. Symmetric
issue exists on transfer and unshield.

This is a pre-existing kernel-level gap, not introduced by the
redesign. Documented as wallet-side enforcement only in the
`KernelVerifierConfig::operator_producer_owner_tag` doc comment.
Fixing on-chain would require exposing `producer_owner_tag` as a
public output of every spend circuit and adding a kernel check.

---

## Things checked and found OK

These were verified during the audit and stand as positive results:

- WOTS+ chain count and step semantics
  (`step = digit; while step < W-1`) match the standard "extension
  forgery" structure.
- Checksum digits encode `sum(W-1 - digit[i])` correctly; tested.
- Type tags 0x01 / 0x02 / 0x03 / 0x04 are distinct between transfer,
  unshield, shield-sighash, and pubkey-hash.
- Sighash binds every public output: an exhaustive single-field-flip
  test sweep exists in `shield.cairo`'s test module.
- `xmss_ltree` handles odd-length input (`WOTS_CHAINS = 133`).
- ADRS slots `(tag, key_idx, chain_idx, step)` don't overlap given
  current value bounds.
- Hash domain separation by IV: sighash, owner, commit, nullifier,
  merkle, nk_spend, nk_tag are all distinct IVs.
- No integer overflow paths in chain-step or checksum counters
  (checksum maxes at 384, well within u32).
- `auth_root` is the only exit from the WOTS+ verify chain; nothing
  else can satisfy `xmss_verify_auth`.
- Pubkey_hash equation (`fold(0x04, auth_domain, auth_root,
  auth_pub_seed, blind)`) is checked before WOTS+ verify; a wrong
  blind fails fast.
- `producer_fee > 0` is asserted (the only ban-zero in the value
  triple).
- `prepare_shield` cross-checks every public-output entry against
  the request fields (auth_domain, pubkey_hash, v, fee, producer_fee,
  client_cm, producer_cm, mh_recipient, mh_producer).
- `credit_deposit` overflow is `checked_add`-guarded.
- Shield circuit, transfer circuit, and unshield circuit all
  share the same WOTS+ primitive — a break in one would break all.

---

## Open items summary

| ID     | Severity | Status   |
|--------|----------|----------|
| F-K-1  | HIGH     | FIXED    |
| F-K-2  | HIGH     | FIXED    |
| F-W-1  | MED      | FIXED    |
| F-W-2  | LOW      | FIXED    |
| F-W-3  | LOW      | OPEN     |
| F-C-1  | LOW      | OPEN     |
| F-C-2  | LOW      | OPEN     |
| F-C-3  | LOW      | OPEN     |
| F-C-4  | LOW      | OPEN     |
| F-C-5  | INFO     | WONTFIX  |
| F-C-6  | LOW      | OPEN     |
| F-C-7  | LOW      | OPEN     |
| F-C-8  | INFO     | WONTFIX  |
| F-C-9  | INFO     | OPEN     |
| F-C-10 | INFO     | OPEN     |
| F-C-11 | INFO     | WONTFIX  |
| F-X-1  | MED      | OPEN     |
