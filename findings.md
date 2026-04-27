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

### F-W-4 [P1, FIXED] — Pool ownership material recoverable from seed alone

The wallet used to store pool ownership material `(blind,
address_index, auth_domain)` only in local `PendingDeposit` state.
The shield path refuses to proceed unless the pool is still locally
tracked, and on the chain side the wallet can only probe balances
for pools it already knows — the kernel intentionally maintains no
enumerable deposit-balance index. A successful L1 bridge deposit
followed by wallet-file loss therefore stranded real funds in an
opaque pool with no discovery path.

The cryptographic primitive that *enables* recovery was already in
place: `H("tzel-deposit-blind", master_sk, address_index,
deposit_nonce)` makes every blind reproducible from the seed alone.
What was missing was a code path that actually walks the
`(address_index, deposit_nonce)` grid.

**Fix:** new `tzel-wallet recover-deposits` command. Given the seed
already in the wallet file plus user-supplied bounds (default
`max_address_index = 16`, `max_deposit_nonce = 16`), it:

1. Materializes addresses `0..=max_address_index` (full XMSS rebuild
   per address — slow, ~tens of seconds each, but only paid once).
2. For each `(i, j)` pair, derives the candidate blind, computes the
   candidate `pubkey_hash`, probes the rollup for a non-zero balance.
3. Records every funded pool as a fresh `PendingDeposit`.
4. Bumps the local `deposit_nonce` counter past the highest
   recovered value so a subsequent `tzel-wallet deposit` doesn't
   accidentally re-derive a blind that already collides with a
   recovered pool.

Drained pools (kernel balance entry empty after a full debit) are
deliberately *not* recovered — the funds are already in the user's
recipient note, and `tzel-wallet sync` recovers those via the
ML-KEM detection key.

The misleading docs (wallet comment on `derive_deposit_blind` and
the whitepaper paragraph that claimed seed-only recovery already
worked) were corrected in commit `c55ffcb` and now point at the
actual command.

**Regressions:**
- `cmd_recover_deposits_finds_funded_pool_from_seed_alone` plants a
  balance off-diagonal at `(addr=1, nonce=2)` and asserts the
  command finds it from seed alone, sets all `PendingDeposit`
  fields correctly, and bumps `deposit_nonce` past the recovered
  value.
- `cmd_recover_deposits_skips_pools_already_tracked_locally`
  asserts idempotency: re-running recovery on a wallet that already
  has the entry doesn't add a duplicate.

### F-W-5 [P2, FIXED] — Deposit preflight didn't bind `rollup_node_url` to `rollup_address`

`cmd_bridge_deposit` and `cmd_wallet_check` ran their preflight
(verifier configured? bridge ticketer matches? operator owner_tag
matches?) by reading durable state from `profile.rollup_node_url`,
but the actual bridge mint targets `profile.rollup_address`. A stale
or malicious profile that points the two at *different* rollups
could pass preflight and send an irreversible L1 mint to the wrong
rollup. The user's `tzel-wallet check` would also report all green
in that case.

**Fix:** new `RollupRpc::ensure_rollup_address_matches` calls
`/global/smart_rollup_address` on `rollup_node_url` and asserts the
returned `sr1...` equals `profile.rollup_address`. The check runs
*first* in both `cmd_bridge_deposit` (before any state reads) and
`cmd_wallet_check`, so a misconfigured profile fails the gate before
any irreversible action.

**Regression:**
`cmd_wallet_check_fails_when_rollup_node_serves_a_different_rollup`
mocks the rollup node to report a different rollup than the wallet
profile and asserts the check rejects with a clear message.

The spec's "Wallet preflight gates" section now lists the rollup-
address check alongside the verifier-configured / ticketer-matches /
owner_tag-matches gates.

### F-W-6 [P3, FIXED] — Documentation drift: slot-era prose, old config semantics

A handful of docs and comments still described the pre-redesign
behavior:

- `README.md` listed "Allocate per-deposit slots for L1 bridge
  tickets" in the contract description and "per-deposit slots" in
  the durable-state list. Updated to "Credit per-pool aggregated
  balances" and "per-pool deposit balances, applied-shield
  commitments, ..." respectively.
- `specs/spec.md` still described the "auth_domain frozen but other
  verifier-config fields reconfigurable on a pristine ledger" rule
  and the slot-stranding story. Replaced with a one-shot rule that
  matches the current kernel.
- `specs/spec.md`'s ticketer-mismatch warning said the deposit
  burns mutez "to a slot that never appears". Now says "to a pool
  that never appears".
- `specs/spec.md`'s privacy paragraph said reusing or rotating
  `blind` is "user-controlled per-deposit". The current CLI doesn't
  expose a flag for that — the paragraph now describes what the
  reference wallet actually does (always allocate a fresh pool).
- A wallet comment on `fetch_pool_balances_http` still described
  the old slot/intent matching logic. Rewritten.
- The kernel's `validate_bridge_deposit` rejection message said
  "deposit:<32-byte lowercase hex of intent>". Now says "...of
  pubkey_hash".

**Regression:** a workspace-wide grep for `intent`-era language now
returns nothing in the production code paths.

### F-W-7 [P4, FIXED] — Backwards-compat residue in `parse_pubkey_hash_hex`

`parse_pubkey_hash_hex` accepted three input forms — plain hex,
`0x<hex>`, and `deposit:<hex>` — even though the redesign explicitly
opted out of backwards compatibility. The CLI prints plain
lowercase hex, so any user copying the value from `tzel-wallet
check` or `tzel-wallet balance` already sees the canonical form.

**Fix:** parser now accepts exactly one form: 64 lowercase hex
chars, no prefix. The two prefixed forms reject with a clear
message pointing the user at the canonical shape; uppercase hex
rejects too. Old test
`pubkey_hash_hex_round_trips_through_parse_pubkey_hash_hex` is
replaced with `parse_pubkey_hash_hex_accepts_only_canonical_lowercase_hex`,
which asserts the rejection paths.

### F-W-3 [LOW, FIXED] — Multi-stage drain of the same pool pinned `PendingDeposit` forever

Two compounding mistakes in the F-W-2 fix:

1. **`cmd_shield_rollup` only set `shielded_cm` when it was currently
   `None`.** The filter `p.shielded_cm.is_none()` meant a second shield
   against the same pool (legitimate — core supports distinct-cm
   draws, see `test_apply_shield_two_distinct_shields_can_share_one_pool`)
   never updated `shielded_cm`; the entry stayed pinned to the *first*
   shield's `cm1`.

2. **`apply_scan_feed` built `known_cms` from `feed.notes` only**, the
   incremental feed since the last sync cursor. So `cm1` (observed in
   an earlier sync) was not in the current set even though it was in
   `w.notes`.

Reachable sequence (now a regression test):

   1. Pool funded with X.
   2. Shield 1 drains v1 < X, mints cm1; wallet sets
      `shielded_cm = Some(cm1)`.
   3. Sync 1: cm1 in feed, pool balance > 0 → keep (correct).
   4. Shield 2 drains the residue, mints cm2; the old `is_none()`
      filter left `shielded_cm` pinned to `Some(cm1)`.
   5. Sync 2: cm2 in feed (not cm1), pool balance == 0 → predicate
      `drained && (cm1 ∈ {cm2})` = `drained && false` → don't prune.

The entry was stuck forever. Reporting permanently showed "drained
but not yet pruned" — stale local deposit metadata, misleading
operational output. Not a consensus or custody break.

**Fix:**

1. `cmd_shield_rollup` now always overwrites `shielded_cm` with the
   latest shield's recipient cm. Older cms are still observable
   cumulatively via `w.notes`, so the prune predicate accepts an
   observation of any prior cm too.
2. `apply_scan_feed` builds `known_cms` from `w.notes` (after this
   round's recovery, before nullifier pruning) ∪ `feed.notes`
   (defensive coverage for cms the wallet didn't itself recover).
   This is cumulative across syncs and survives both multi-stage
   drains and the "user runs sync twice, only the first contained
   the cm" scenario.

**Regressions:**
- `test_apply_scan_feed_prunes_multi_stage_drain_after_residue_shield`
  walks the exact five-step sequence and asserts pruning fires on
  sync 2.
- `test_apply_scan_feed_prunes_drained_pool_via_cumulative_state`
  is the cumulative twin: cm absorbed in sync 1 (pool still funded,
  no prune), pool drained between syncs, sync 2 has empty feed —
  prune still fires because `w.notes` still contains the cm.

**Commit:** `<this commit>`.

---

## Shield circuit (`cairo/src/shield.cairo`, `xmss_common.cairo`, `blake_hash.cairo`)

The shield circuit is **sound** under standard WOTS+ + BLAKE2s
assumptions. The findings below are quantitative reductions, code-
quality gaps, and design observations.

### F-C-1 [LOW, WONTFIX] — Two trailing message digits are always zero

**Decision:** forced by the felt252 representation. `u32x8_to_felt`
masks `h7` to `0x07FFFFFF` (251-bit ceiling); `felt_to_u32x8`
doesn't re-mask, so `digits[126]` and `digits[127]` are always zero.
Effective WOTS+ security goes from `4^131` to `4^129` — still
vastly above 128-bit. Fixing this would require either changing the
field (impossible) or adding a non-uniform sighash decomposition
(complex). The reduction is acceptable.


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

### F-C-2 [LOW, FIXED] — Dead WOTS+ IV

`blake_hash.cairo` used to define `blake2s_iv_wots()` ("wotsSP__") and
`pub fn hash1_wots(a)` that used it. Neither was called anywhere in
production circuit code; `xmss_chain_step` (the actual chain hash)
uses `hash3_generic` (untyped IV) and relies entirely on the ADRS for
domain separation. A unit test `test_hash1_wots_uses_distinct_domain`
kept the dead code wired into the test infra.

The risk was code-quality only: someone could see `hash1_wots` and
assume it was the chain hash, or a refactor could silently switch
from one to the other. ADRS-based domain separation is
RFC-8391-style and is sound; the issue was just that the codebase
advertised an alternative that nothing used.

**Fix:** deleted `blake2s_iv_wots`, `hash1_wots`, and the dead test.
"The WOTS+ chain hash" is now exactly one thing in the codebase.

### F-C-12 [INFO, FIXED] — `auth_idx` was `u64` but always immediately narrowed to `u32`

Both `shield::verify` (single `auth_idx: u64`) and
`transfer::verify` / `unshield::verify` (`auth_index_list: Span<u64>`)
took `u64` arguments and immediately did
`(*x).try_into().unwrap()` to narrow to `u32` for use in the WOTS+
verify. The double-narrowing (felt252 → u64 → u32) was misleading:
the actual constraint is `auth_idx < 2^AUTH_DEPTH = 65536`, which
fits comfortably in `u32` (or even `u16`).

**Fix:** narrowed every circuit signature to `u32` directly. The
`run_*.cairo` wrappers cast felt252 → u32 once at the boundary;
the inner `try_into().unwrap()` casts and the `auth_idx_u32` rebind
in `shield::verify` are gone. Same number of runtime conversions,
but the type signature now self-documents the bound (an auditor can
read "this is a u32" instead of having to mentally trace the
`try_into` chain).

Affected files: `cairo/src/shield.cairo`,
`cairo/src/run_shield.cairo`, `cairo/src/transfer.cairo`,
`cairo/src/run_transfer.cairo`, `cairo/src/unshield.cairo`,
`cairo/src/run_unshield.cairo`. Test fixtures updated to drop the
`u32 -> u64 -> u32` `.into()` round-trips.

The bytecode change is internal — no public-output layout change,
so the verified-bridge fixture's pinned program_hashes still match
the proofs in the JSON (the proofs are pinned to specific bytecode
they were generated against; the on-disk executables move
independently).

### F-C-3 [LOW, WONTFIX] — Length checks live at the wrong layer

**Decision:** the right home for `assert(wots_sig_flat.len() ==
WOTS_CHAINS)` and `assert(auth_siblings_flat.len() == AUTH_DEPTH)` is
the caller (each of `shield::verify`, `transfer::verify`,
`unshield::verify` already does this). Adding the same asserts inside
`xmss_recover_pk` would duplicate the property in two places without
any new soundness guarantee. If a future caller forgets the assert,
the right fix is to audit that caller, not to bloat every primitive
with belt-and-braces wrappers. (Originally noted below.)


`xmss_recover_pk` does `*wots_sig.at(j)` and `*digits.at(j)` for
`j in 0..WOTS_CHAINS` without internally validating either length.
If a future caller forgets the top-level
`assert(wots_sig_flat.len() == WOTS_CHAINS, ...)` — which `shield.
cairo:58`, `transfer.cairo:72`, and `unshield.cairo` all currently
do — a malformed witness either panics mid-computation (short input)
or silently truncates (extra entries unconsumed). `xmss_verify_auth`
*does* assert siblings length internally; `xmss_recover_pk` is
asymmetric. Defense-in-depth gap.

### F-C-4 [LOW, WONTFIX] — `auth_idx` overflow path is `try_into().unwrap()`

**Decision:** the `try_into().unwrap()` form *is* the bound check —
Cairo's prover refuses to produce a trace that panics, so a malicious
witness with `auth_idx > u32::MAX` fails to produce a proof. Adding
an explicit `assert(...)` would change the error message string but
not the soundness. Since F-C-12 narrowed `auth_idx` to `u32` directly
at the circuit boundary, this is moot anyway — the cast happens once
in the `run_*.cairo` wrapper and the inner `verify` functions take
`u32` natively.


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

### F-C-6 [LOW, INVALID] — Producer note witness is unconstrained relative to recipient

**Decision: invalid.** Originally framed as an exploit where the prover
routes the producer fee back to themselves, "stealing" it from the
operator. There is no rollup operator — the producer fee is paid to
whichever DAL slot publisher includes the transaction, and publishers
gate inclusion off-chain by checking the producer note's `owner_tag`
matches their own. A prover who sets `producer == recipient` is paying
themselves; no publisher will bundle the transaction (no fee for them),
so it never reaches the kernel. Self-defeating, not exploitable.

### F-C-7 [LOW, WONTFIX] — `producer_fee > 0` is the only positivity check in the circuit

**Decision:** circuit proves spending math is consistent (e.g.,
`producer_fee > 0` so the producer note is non-trivial); kernel
enforces deployment policy (`fee >= required_tx_fee`,
`v_note + fee + producer_fee <= pool_balance`). Adding a fee floor
to the circuit would freeze the kernel's policy into every proof,
making it impossible to ever change the floor without regenerating
all circuits. Wrong layer.


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

### F-C-9 [INFO, WONTFIX] — `pack_adrs` slot widths assume u32 fits

**Decision:** the slots are *typed* `u32` in the function signature.
`assert(x < 2^32)` on a `u32` literally cannot fail — it would be
dead defensive code. The forward-looking concern ("a future change
that pushes a field above 2^32 silently overlaps the next slot") is
real but the right defense is comment + structure, not runtime
asserts.


`pack_adrs(tag, key_idx, a, b, c)` packs four 32-bit slots starting at
bits 64, 96, 128, 160. Tag occupies bits 0–63. Currently
`key_idx ≤ 2^16-1`, `chain_idx ≤ WOTS_CHAINS=133`, `step ≤ W-2=2`,
all way within u32. Domain separation depends on these slots not
overlapping in the felt addition. They won't given current values; a
future change that pushed any field above `2^32` would cause silent
collisions in the address scheme.

### F-C-10 [INFO, WONTFIX] — `xmss_recover_pk` doesn't validate `digits.len()`

**Decision:** same reasoning as F-C-3. The pairing
`sighash_to_wots_digits` (always returns 133) ↔ `xmss_recover_pk`
(always indexes 133) is a structural invariant, not a runtime
property worth asserting. If `WOTS_CHAINS` ever decoupled from the
digits function's output length, the right defense is to audit the
decoupling change.


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

### F-X-1 [MED, INVALID] — Producer-fee owner_tag not enforced on chain

**Decision: invalid — wrong mental model.** The original framing assumed
a privileged rollup operator collecting producer fees, and treated the
absence of a kernel cross-check as theft-enabling. There is no such
role: the producer fee is a market price paid to whichever DAL slot
publisher chooses to include the transaction. Publishers (anyone
willing to pay a baker for a slot) enforce their own inclusion policy
off-chain — they only bundle a transaction if the producer note is
payable to them. A wallet that routes the fee to "the wrong receiver"
just won't get included.

The kernel field `operator_producer_owner_tag` and the wallet helper
`ensure_operator_producer_owner_tag_matches` were vestiges of this
wrong model and have since been removed from the kernel verifier
config wire format and the wallet preflight gates respectively.

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
| F-W-3  | LOW      | FIXED    |
| F-W-4  | P1       | FIXED    |
| F-W-5  | P2       | FIXED    |
| F-W-6  | P3       | FIXED    |
| F-W-7  | P4       | FIXED    |
| F-C-1  | LOW      | WONTFIX (251-bit felt forced) |
| F-C-2  | LOW      | FIXED    |
| F-C-3  | LOW      | WONTFIX (caller-layer responsibility) |
| F-C-4  | LOW      | WONTFIX (`try_into().unwrap()` IS the bound check) |
| F-C-5  | INFO     | WONTFIX (by design)  |
| F-C-6  | LOW      | INVALID (no operator role; publisher gates inclusion) |
| F-C-7  | LOW      | WONTFIX (kernel-layer policy) |
| F-C-8  | INFO     | WONTFIX (privacy/recovery trade-off) |
| F-C-9  | INFO     | WONTFIX (type system enforces) |
| F-C-10 | INFO     | WONTFIX (caller-layer responsibility) |
| F-C-11 | INFO     | WONTFIX (251-bit felt forced) |
| F-C-12 | INFO     | FIXED    |
| F-X-1  | MED      | INVALID (no operator role; publisher gates inclusion) |
