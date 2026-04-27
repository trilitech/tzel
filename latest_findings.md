# Deposit / Withdrawal Security Findings — 2026-04-26

> **Update (deposit-pool / pubkey_hash redesign):** A subsequent design
> shift replaced the per-deposit slot scheme with per-pool aggregated
> balances keyed by `H_pubkey(auth_domain, auth_root, auth_pub_seed,
> blind)`. The shield circuit gained an in-circuit WOTS+ signature under
> the recipient's auth tree (matching transfer / unshield). Several
> findings below are resolved or reframed by that redesign:
>
> - **F-HIGH-1 (fee escalation strands deposits)** — RESOLVED. The
>   shield circuit no longer commits `fee` into the pool key; the user
>   picks `fee` at shield time and the kernel enforces `fee >=
>   required_tx_fee` against the pool's current balance. Fee escalation
>   between deposit and shield is now a wallet-side retry, not a
>   protocol-level stranding.
> - **F-MED-1 (by-intent index linear scan DoS)** — RESOLVED. The
>   per-intent index is gone; pools are keyed directly by `pubkey_hash`
>   in a single map. There is no linear scan to abuse.
> - **F-LOW-3 (orphan-slot warning placeholder)** — RESOLVED. Orphan
>   slots no longer exist; mirror-deposits aggregate into the victim's
>   pool, so there is nothing to warn about.
> - **F-LOW-4 (empty by-intent count left at 0)** — RESOLVED with the
>   index removal.
>
> Findings that remain in scope:
> - **F-CRIT-1 (WOTS+ admin key reuse)** — independent of the deposit
>   redesign; still applies to `configure_verifier` /
>   `configure_bridge`.
> - **F-MED-2 (operator owner_tag ZERO)** — wallet-side gate, still
>   applicable.
> - **F-MED-3 (orphan UX in rollup sync)** — partially obsoleted; the
>   sync path now reports per-pool balances rather than orphan counts.
> - **F-LOW-1 (bridge ticketer TOCTOU)** — unchanged.
> - **F-LOW-2 (cm collision settled-flag flip)** — wallet's settled
>   bookkeeping is gone (no orphan detection), so this specific flag
>   isn't the surface anymore. The underlying observation (cm equality
>   alone doesn't bind intent) still merits care anywhere the wallet
>   matches notes against expected receivers.
> - **F-INFO-1 (wire version 16→17 client compat)** — same hygiene
>   concern; the redesign bumped the wire version through 17 along
>   with the kernel-shield-req reshape.


Audit base: `6163eb7` (`shield: subsume orphan-slot drain into a --slot-id flag`)
plus uncommitted/external review.

Findings are aggregated from two sources:

- **[INTERNAL]** my own deep audit (parallel protocol-side + wallet-side reviewers, plus my verification).
- **[EXTERNAL]** a separate review provided by the project author.

Severity legend: `CRITICAL` (fund loss reachable in normal operation),
`HIGH` (fund stranding or strong privilege escalation in plausible scenarios),
`MEDIUM` (degradation, narrow-scope loss, or operationally fragile),
`LOW` (UX or theoretical), `INFO` (deployment hygiene).

---

## CRITICAL

### F-CRIT-1 — WOTS+ admin key reuse on `configure_verifier` / `configure_bridge` [INTERNAL]

**Location.** `core/src/kernel_wire.rs:17-18`, `tezos/rollup-kernel/src/lib.rs:1738-1791`.

**Mechanism.** The kernel verifies admin signatures against a single fixed
WOTS+ leaf per message type:

```rust
pub const KERNEL_VERIFIER_CONFIG_KEY_INDEX: u32 = 0;
pub const KERNEL_BRIDGE_CONFIG_KEY_INDEX: u32 = 1;
```

`compiled_verifier_config_leaf` and `compiled_bridge_config_leaf` are
compile-time constants. There is no key-index rotation: every signed
verifier-config message is checked against the same hardcoded leaf at
index 0, every signed bridge-config message against the same leaf at
index 1.

WOTS+ is a one-time signature scheme. Signing two distinct messages
with the same key index reveals enough chain elements that an observer
can forge a third signature on a chosen message under the standard
WOTS+ assumptions.

**Attack.** Admin signs `configure_verifier(config_A)` (e.g., initial
install). Later admin signs `configure_verifier(config_B)` to update
program hashes or rotate `operator_producer_owner_tag` (the kernel
explicitly permits this while the ledger is pristine — see
`tezos/rollup-kernel/src/lib.rs:1896`). Both signatures appear on L1.
An attacker reads both, forges `sig_C` on attacker-chosen `config_C`,
submits. Kernel accepts.

The attacker can install an arbitrary `operator_producer_owner_tag`
(silently re-routing all producer fees) and arbitrary
`verified_program_hashes` (could install a backdoored verifier).
`auth_domain` is frozen post-first-install so the attacker can't
reconfigure it through this path, but the freeze rule itself relies
on the integrity of the *first* signature, which is single-use-safe.

**Reachable.** Yes, on any deployment that signs more than one verifier
config or more than one bridge config. The spec actively encourages
this ("Other verifier-config fields may still be reconfigured while
the ledger is pristine"). Even an honest sequence of "fix typo, then
sign correct config" leaks if both signatures hit L1.

**Note.** The wallet's spend-authorization path uses an XMSS-style key
tree with per-spend index increments (`wots_key_indices`). The admin
path got the discipline wrong; the wallet path got it right.

---

## HIGH

### F-HIGH-1 — Fee escalation between deposit and shield strands funds [EXTERNAL P1.1]

**Location.** `apps/wallet/src/lib.rs:6608-6609, 6656-6669, 6678-6694`;
`core/src/lib.rs:1803-1808, 2133-2174, 2245`.

**Mechanism.** At deposit time the wallet quotes the *current*
`required_tx_fee` and bakes that exact value into the deposit:

```rust
let required_fee = rollup.current_required_tx_fee_at_block(&head_hash)?;
let fee = resolve_requested_tx_fee(fee_arg, required_fee)?;
// ...
let intent = shield_intent(&auth_domain, amount, fee, profile.dal_fee, ...);
let debit = amount + fee + profile.dal_fee;  // L1 ticket amount
```

The kernel's `required_tx_fee` is dynamic: it doubles per accepted
private tx in a level, capped at `MIN_TX_FEE * 2^MAX_DYNAMIC_FEE_STEP`
= `100_000 * 64` = `6_400_000` mutez. `prepare_shield` rejects when
`req.fee < required_fee` (`core/src/lib.rs:2133-2135`).

The slot is committed:

- `slot.amount = v + fee + producer_fee` is fixed at deposit time
  (the L1 ticket amount).
- `consume_deposit_slot` rejects any non-exact match
  (`core/src/lib.rs:2060-2065`).
- `intent` commits to the exact `fee` value, so changing `req.fee`
  changes `deposit_id`, leaving no slot whose intent matches.

There is no top-up path and no overpay path. Once the kernel's required
fee climbs above the deposited fee, the slot is unrecoverable.

**Attack.** No attacker required — natural congestion suffices. User
deposits at the floor (`100_000`). Six other private txs land in the
same level after the L1 ticket but before the user's shield, pushing
required fee to `6_400_000`. User's shield is permanently rejected;
the L1 mutez remain locked in the bridge against an unreachable slot.

**Bound.** Under the current fee schedule the worst-case required fee
is `6_400_000` mutez, so a wallet that deposits at `MIN_TX_FEE * 64`
would survive. But (a) this charges 64× the floor as insurance on
every deposit, and (b) any future bump to `MAX_DYNAMIC_FEE_STEP` or
`MIN_TX_FEE` invalidates all in-flight deposits made under the old
constants.

**Reachable.** Yes, in normal operation. No malfeasance required.

**Notes on remediation (out of scope for this report).** A wallet-only
fix is partial at best (quote at the cap, accept overpayment). A clean
fix needs a protocol change: relax `consume_deposit_slot` to permit
`slot.amount >= v + req.fee + producer_fee` and burn or refund the
excess, or split the slot's `amount` from the intent's `fee` so the
fee can re-quote at consume time without changing the intent.

---

## MEDIUM

### F-MED-1 — By-intent index linear scan enables L1-funded DoS on shield cost [INTERNAL]

**Location.** `tezos/rollup-kernel/src/lib.rs:1467-1485` (in `prepare_durable_shield_commit`).

**Mechanism.** To prune the by-intent index on slot consumption, the
kernel scans `0..by_intent_count` for the slot id:

```rust
for position in 0..by_intent_count {
    let entry_path = deposits_by_intent_index_path(prepared.deposit_id(), position);
    let entry = ledger.host.read_store(&entry_path, 8)...;
    let id_at_pos = u64::from_le_bytes(entry.try_into().unwrap());
    if id_at_pos == prepared.deposit_slot() { found_position = Some(position); break; }
}
```

Cost is O(N) PVM `read_store` calls per shield, where N = open dust
slots for the intent.

**Attack.** Attacker submits N L1 dust deposits to the victim's
publicly-visible `deposit:<hex(intent)>` recipient. Each adds an entry
to the by-intent index. Every subsequent shield to that intent now
costs N extra reads. With WASM PVM tick budgets, sufficiently large
N can push the legitimate shield over the per-message tick budget,
preventing it from ever being applied.

**Cost asymmetry.** Attacker pays N × (1 mutez minimum L1 ticket + L1
gas). Victim's shield processing cost grows linearly. Unlike the
"balance bucket brick" attack the slot scheme defended against, this
is a soft DoS (cost inflation, not permanent brick), but it can stall
shields under tick budgets.

**Reachable.** Yes for sufficiently motivated attacker against a
specific known intent. Bounded by attacker's L1 budget.

---

### F-MED-2 — `operator_producer_owner_tag == ZERO` silently disables producer-fee enforcement [EXTERNAL P1.2]

**Location.** `apps/wallet/src/lib.rs:2306-2311`, callers at 6654, 7613,
7833.

**Mechanism.** When the kernel-published `operator_producer_owner_tag`
is `ZERO`, the wallet warns and proceeds:

```rust
if rollup_tag == ZERO {
    eprintln!("WARNING: rollup operator has not published an expected producer owner_tag; ...");
    return Ok(());
}
```

The kernel does not enforce producer-fee routing in-circuit; the
wallet's check is the only enforcement of "producer fees go to the
operator." `ZERO` makes that check a no-op. A user (honest or not) with
`profile.dal_fee_address` set to an address they control routes the
producer-fee note to themselves, then later spends it.

**Reachable.** Yes on any deployment whose admin has not yet published
a non-zero `operator_producer_owner_tag` (testnets, fresh deployments,
or operators who never set it). Even non-zero only enforces against
honest wallets — a custom wallet can always skip the gate; this finding
is specifically about the reference wallet's silent passthrough on
`ZERO`.

**Note.** The framing in the original report ("a malicious wallet can
set profile.dal_fee_address to an address it controls") slightly
overstates: the kernel never enforces, even with non-zero tag. The
enforceable surface is the *honest* wallet on a *correctly configured*
deployment, and `ZERO` removes that surface entirely.

---

### F-MED-3 — Orphan-slot recovery not surfaced in real rollup sync UX [EXTERNAL P2.2]

**Location.** `apps/wallet/src/lib.rs:6526-6562` (`cmd_rollup_sync`),
3958-3964 (`cmd_scan` warning text), 6503-6512 (`cmd_wallet_check`),
4015-4080 (`apply_scan_feed` orphan logic).

**Mechanism.** The real production sync command, `cmd_rollup_sync`,
prints:

```
Synced: {} new notes, {} spent removed, {} pending confirmed, {}
deposits settled, {} slots assigned, ...
```

It does NOT surface `summary.orphan_slots` at all. Only the local-test
`cmd_scan` prints an orphan warning, and even that warning is generic:

```
"WARNING: {} orphan deposit slot(s) detected for settled deposits.
 Run `tzel-wallet shield --deposit-id <hex> --slot-id <id> --correlate`
 to recover the L1 mutez ..."
```

The placeholder `<id>` is literal — the warning never tells the user
which slot ids are orphans. `cmd_wallet_check` only shows aggregates.

**Impact.** A user under a mirror-deposit attack:
- receives the shielded note (from whichever slot the kernel consumed
  during the user's shield, possibly the attacker's),
- has no signal that orphan mutez is sitting in a separate slot,
- has no way to discover the orphan slot ids without inspecting wallet
  JSON manually.

**Reachable.** Yes — the recovery mechanism exists (`shield --slot-id N
--correlate`) but the path that surfaces it to users is broken on the
production sync command.

---

## LOW

### F-LOW-1 — Bridge-ticketer reconfiguration TOCTOU during pristine window [EXTERNAL P2.1]

**Location.** `apps/wallet/src/lib.rs:6648` (preflight),
`tezos/rollup-kernel/src/lib.rs:1924-1927` (kernel rule),
`tezos/rollup-kernel/src/lib.rs:220` (`is_pristine`).

**Mechanism.** Wallet's bridge-ticketer preflight is a one-shot read of
durable state. Kernel allows ticketer reconfiguration any time the
ledger is pristine (zero tree size, zero nullifiers, zero deposit slots).
Window: between wallet preflight and L1 ticket inclusion.

**Attack.** Admin (or compromised config signer, see F-CRIT-1)
reconfigures ticketer in the preflight→inclusion window. L1 ticket
arrives at a kernel that no longer trusts the originating bridge; kernel
rejects; mutez locked at bridge with no slot ever allocated.

**Reachable.** Requires admin malfeasance OR racing a legitimate admin
reconfig. Combined with F-CRIT-1, an attacker who has forged an admin
signature can do this without admin involvement.

**Severity.** Low in isolation. Elevated to medium if combined with
F-CRIT-1.

---

### F-LOW-2 — Settled-flag flip on cm collision (theoretical) [INTERNAL]

**Location.** `apps/wallet/src/lib.rs:4042-4049`.

**Mechanism.** `apply_scan_feed` flips `settled = true` on cm equality
alone, with no intent check:

```rust
let live_cms: HashSet<F> = w.notes.iter().map(|n| n.cm).collect();
for d in w.pending_deposits.iter_mut() {
    if !d.settled && live_cms.contains(&d.recipient.cm) {
        d.settled = true;
    }
}
```

If two pending deposits have the same `recipient.cm` but different
intents, both flip when one cm lands.

**Reachable.** Honest wallets randomize `rseed` per deposit; cm
collision is ~2⁻²⁵⁶. Not realistic. Worth noting as fragile (a future
deterministic-rseed import path or fixture could trigger it). The fix
is to key the match on `(cm, intent)` or on the published note's
intent rather than cm alone.

---

### F-LOW-3 — Orphan-slot warning placeholder rather than slot id list [INTERNAL]

**Location.** `apps/wallet/src/lib.rs:3958-3964`.

The warning prints a literal `<id>`; users have to dig in wallet JSON
to find actual orphan slot ids. Same root cause as F-MED-3 but at the
text-template level rather than the surfacing-from-sync level.

---

### F-LOW-4 — Empty by-intent count is written `0` rather than removed [INTERNAL]

**Location.** `tezos/rollup-kernel/src/lib.rs:1595-1598` (in
`apply_durable_shield_commit`).

After the last slot for an intent is consumed, the count key is set
to `0` rather than removed from durable storage. One u64 of permanent
storage per ever-funded intent. Negligible unless the deployment ever
introduces storage rent, but worth flagging.

---

## INFO

### F-INFO-1 — Wire version 15→16 client migration unverified [INTERNAL]

**Location.** `core/src/kernel_wire.rs:16` (`KERNEL_WIRE_VERSION = 16`),
`tezos/rollup-kernel/src/lib.rs:409-413` (strict version check).

`d8b6d54` bumped the wire version. No in-tree audit confirms all
off-chain consumers (provers, indexers, tooling) have migrated. v15
clients silently fail decoding. Worth a deployment-checklist pass.

---

## Verified correct (high-leverage spots, not findings)

These were checked and found sound; including for completeness so the
absence of a finding here is not load-bearing-by-omission.

- `apply_durable_shield_commit` and `apply_durable_unshield_commit` are
  infallible: every line is `Host::write_store` or pure-local
  (`tezos/rollup-kernel/src/lib.rs:1583-1619, 1364-1398`).
- `parse_deposit_recipient_intent` enforces canonical lowercase 64-char
  hex via `hex::encode(&bytes) != hex_id` (`core/src/lib.rs:262`). No
  case/padding/UTF-8 attack surface.
- `KernelVerifierConfig` signing hash binds `auth_domain`, all three
  program hashes, and `operator_producer_owner_tag` via the wire
  encoding (`core/src/kernel_wire.rs:209-214, 486-491, 607-613`). The
  *signature scheme* is the issue (F-CRIT-1), not what it covers.
- auth_domain freeze: `tezos/rollup-kernel/src/lib.rs:1886` rejects
  any change after first install, regardless of pristine state.
- Slot consume binds intent + amount + status atomically
  (`tezos/rollup-kernel/src/lib.rs:1436-1450`); kernel slot counter is
  monotonic with `checked_add`.
- Wallet's settlement-keyed privacy guard correctly catches
  duplicate-leaf events regardless of `slot_id` rotation
  (`apps/wallet/src/lib.rs:7501-7522`, with regression test
  `test_apply_scan_feed_counts_orphan_when_slot_id_rotated_to_remaining_open_slot`).
- Orphan-slot drain produces independent nullifier (folds tree
  position) so funds are recoverable even though deposit-time intent
  linkage leaks (`core/src/lib.rs:325-340`).
- Wallet's WOTS+ key index management for ordinary spend transactions
  correctly increments and persists per-address before submission. (The
  contrast with the kernel admin path makes F-CRIT-1 sharper — the
  wallet path applied the right discipline; the kernel admin path
  didn't.)
- Unshield's L1 outbox emission ordering is safe: `write_output(...)?`
  with the apply step infallible means PVM atomicity guarantees
  outbox-and-state consistency (no half-commit).
- DAL pointer authentication relies on the inner config signature, not
  separately authenticated DAL metadata; not a bypass.
- `cmd_bridge_deposit`'s three preflight checks all use the same pinned
  `head_hash` (`apps/wallet/src/lib.rs:6606`), no cross-snapshot
  inconsistency window.

---

## Suggested triage order

1. **F-CRIT-1 (WOTS+ admin key reuse)** — protocol-level, fund-loss
   class, addresses both initial-deployment risk and combines with
   F-LOW-1 for ticketer hijack.
2. **F-HIGH-1 (fee escalation strands deposits)** — protocol-level
   plus wallet, fund-stranding under normal operation.
3. **F-MED-3 (orphan UX in rollup sync)** — wallet-only, small,
   improves discoverability of an existing recovery mechanism.
4. **F-MED-2 (ZERO operator tag)** — wallet-only, refuse instead of
   warn, with explicit override flag for testnets.
5. **F-MED-1 (by-intent linear scan DoS)** — protocol-level, narrow
   scope, by-design tradeoff that may be acceptable.
6. **F-LOW-1 (ticketer TOCTOU)** — protocol fix (freeze on install),
   low real exposure unless F-CRIT-1 is also live.
7. **F-LOW-2..4, F-INFO-1** — nice-to-have / hygiene.
