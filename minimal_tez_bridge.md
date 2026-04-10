# Minimal Tez Deposit/Withdrawal for a Toy Rollup

This document is informative only. It is implementation guidance for a minimal
Tezos bridge shape, not part of the TzEL normative protocol spec.

A guide for implementing tez-only deposit and withdrawal on a minimal smart rollup
with no sequencer, distilled from the Etherlink kernel implementation.

## Architecture Overview

```
L1 (Tezos)                          L2 (Your Rollup Kernel)
───────────                          ──────────────────────

Ticketer contract (KT1...)           Kernel WASM
  - mint: lock tez, create ticket      - reads inbox
  - burn: destroy ticket, release tez   - credits/debits balances
                                        - writes outbox messages
User sends tez ──► Ticketer.mint()
  ticket ──► Rollup inbox ──────────► Kernel reads Transfer
                                        ──► credits receiver

                                     User requests withdrawal
                                        ──► kernel debits balance
                                        ──► kernel writes outbox msg
L1 executes outbox msg ◄────────────    (ticket burn on ticketer)
  tez released to receiver
```

### What you need on L1

A **ticketer contract** (KT1) that:
1. Has a `mint` entrypoint: accepts tez, creates an FA2.1 ticket, and sends it
   to the rollup via `smart_rollup_deposit`
2. Has a `burn` entrypoint: accepts a ticket back (from an outbox message),
   destroys it, and sends the corresponding tez to the receiver

The ticket content is fixed: `Pair(0, None)` (token_id = 0, no metadata).
The ticket amount equals the number of **mutez** deposited.

### What you need on L2

Your kernel handles two operations:
- **Deposit**: read internal `Transfer` messages from inbox, extract ticket, credit balance
- **Withdrawal**: debit user balance, construct outbox message with ticket burn

---

## Part 1: Deposits (L1 → L2)

### 1.1 How deposits arrive in the inbox

When a user sends tez to the ticketer contract, the ticketer mints a ticket and
sends it to the rollup. The rollup kernel sees this as an **internal Transfer message**
in the inbox.

The inbox message structure (from the Smart Rollup SDK):

```
InboxMessage::Internal(InternalInboxMessage::Transfer(Transfer {
    payload: RollupType,        // Michelson-encoded deposit data
    sender: ContractKt1Hash,    // The L1 contract that sent the transfer
    source: PublicKeyHash,      // The originator of the L1 operation
    destination: SmartRollupAddress, // Must match your rollup address
}))
```

The `payload` for a deposit is a Michelson value of type:

```
(pair
  (bytes %receiver)                    # L2 address of the receiver
  (ticket (pair nat (option bytes))))  # FA2.1 ticket with mutez amount
```

Encoded as `Left(Left(Pair(receiver_bytes, ticket)))` in the Etherlink
`RollupType` (which is `Or(Or(deposit, bytes), bytes)`).

### 1.2 Parsing a deposit in your kernel

Simplified flow (no sequencer, no FA tokens, no chunking):

```rust
use tezos_smart_rollup::prelude::*;
use tezos_smart_rollup_encoding::inbox::{InboxMessage, InternalInboxMessage, Transfer};
use tezos_smart_rollup::michelson::ticket::FA2_1Ticket;
use tezos_smart_rollup::michelson::{MichelsonBytes, MichelsonPair};

// Your rollup's Michelson input type — just the deposit case
// type: (pair bytes (ticket (pair nat (option bytes))))
type DepositPayload = MichelsonPair<MichelsonBytes, FA2_1Ticket>;

fn handle_inbox(host: &mut impl Runtime) {
    while let Ok(Some(message)) = host.read_input() {
        // Parse the raw inbox message
        let parsed = InboxMessage::<DepositPayload>::parse(message.as_ref());

        match parsed {
            Ok((_, InboxMessage::Internal(
                InternalInboxMessage::Transfer(transfer)
            ))) => {
                handle_deposit(host, transfer);
            }
            // StartOfLevel, EndOfLevel, InfoPerLevel — ignore
            Ok((_, InboxMessage::Internal(_))) => {}
            // External messages — ignore for minimal rollup
            Ok((_, InboxMessage::External(_))) => {}
            Err(_) => {} // unparsable, skip
        }
    }
}
```

### 1.3 Processing the deposit

```rust
fn handle_deposit(host: &mut impl Runtime, transfer: Transfer<DepositPayload>) {
    let ticket = transfer.payload.1;  // the FA2_1Ticket
    let receiver_bytes = transfer.payload.0; // MichelsonBytes

    // 1. Verify the ticket creator matches your known ticketer
    //    (prevents crediting from rogue tickets)
    let expected_ticketer = load_ticketer_from_storage(host);
    let ticket_creator = ticket.creator();
    if ticket_creator != &expected_ticketer {
        return; // reject unknown tickets
    }

    // 2. Extract the amount (in mutez)
    let (_, amount_bytes) = ticket.amount().to_bytes_le();
    let amount_mutez: u64 = u64::from_le_bytes(
        amount_bytes.try_into().expect("amount fits in u64")
    );

    // 3. Parse the receiver (for a minimal rollup, this could be
    //    a simple 20-byte address, a tz1 address, or whatever your
    //    L2 addressing scheme is)
    let receiver = parse_receiver(&receiver_bytes);

    // 4. Credit the receiver's balance in your L2 state
    credit_balance(host, &receiver, amount_mutez);
}
```

### 1.4 Key details from Etherlink

- **Ticketer validation is critical**: Etherlink checks that `ticket.creator()` matches
  the configured ticketer contract. Without this, anyone could mint fake tickets.
  (See `etherlink/kernel_latest/kernel/src/parsing.rs:865-872`)

- **Amount conversion**: Etherlink converts mutez → wei (multiply by 10^12) because
  its L2 uses 18-decimal EVM accounting. For a minimal rollup tracking mutez natively,
  you can skip this and just use the raw mutez amount.
  (See `etherlink/kernel_latest/ethereum/src/wei.rs:17-20`)

- **Receiver encoding**: Etherlink supports multiple formats (20-byte EVM address,
  address+chain_id, RLP-encoded). For a minimal rollup, a simple encoding suffices
  (e.g., raw 20-byte address or a tz1 public key hash).
  (See `etherlink/kernel_latest/kernel/src/bridge.rs:244-267`)

- **Deposit hashing**: Etherlink assigns each deposit a pseudo-transaction hash
  (keccak256 of RLP-encoded deposit fields + rollup address as seed) for tracking.
  For a minimal rollup, you may not need this.

---

## Part 2: Withdrawals (L2 → L1)

### 2.1 Overview

A withdrawal sends tez from L2 back to L1 by:
1. Debiting the user's L2 balance
2. Constructing an **outbox message** containing a ticket
3. The L1 protocol eventually executes the outbox message, which calls the
   ticketer's `burn` entrypoint, destroying the ticket and releasing tez

### 2.2 Triggering a withdrawal

In Etherlink, withdrawals are triggered by calling a precompiled Solidity contract.
For a minimal rollup without an EVM, you'd trigger withdrawals via external inbox
messages (the user sends a "withdraw" message to the rollup).

```rust
// Example: parse an external message as a withdrawal request
struct WithdrawalRequest {
    sender: Address,         // L2 account to debit
    receiver: Contract,      // L1 tezos address (tz1/KT1)
    amount_mutez: u64,       // amount to withdraw
}

fn handle_external_message(host: &mut impl Runtime, data: &[u8]) {
    if let Some(withdrawal) = parse_withdrawal_request(data) {
        // 1. Verify the sender has sufficient balance
        let balance = read_balance(host, &withdrawal.sender);
        if balance < withdrawal.amount_mutez {
            return; // insufficient funds
        }

        // 2. Debit the sender's L2 balance
        debit_balance(host, &withdrawal.sender, withdrawal.amount_mutez);

        // 3. Construct and queue the outbox message
        queue_withdrawal_outbox_message(
            host,
            &withdrawal.receiver,
            withdrawal.amount_mutez,
        );
    }
}
```

### 2.3 Constructing the outbox message

The outbox message must be a valid `OutboxMessage` that the L1 protocol can execute.
For a tez withdrawal, it calls the ticketer contract's `burn` entrypoint with:
- A ticket (same type as used for deposits, with the withdrawal amount)
- The L1 receiver address

```rust
use tezos_smart_rollup::outbox::{OutboxMessage, OutboxMessageTransaction, OUTBOX_QUEUE};
use tezos_smart_rollup::michelson::ticket::FA2_1Ticket;
use tezos_smart_rollup::michelson::{MichelsonContract, MichelsonPair, MichelsonOption, MichelsonNat};
use tezos_smart_rollup::types::Entrypoint;
use tezos_protocol::contract::Contract;

// The outbox message parameters type:
//   (pair (contract %receiver) (ticket %ticket (pair nat (option bytes))))
type WithdrawalParams = MichelsonPair<MichelsonContract, FA2_1Ticket>;

fn queue_withdrawal_outbox_message(
    host: &mut impl Runtime,
    receiver: &Contract,       // L1 address (e.g., tz1...)
    amount_mutez: u64,
    ticketer: &Contract,       // your ticketer KT1 address
) {
    // 1. Create the ticket (must match deposit ticket structure exactly)
    let ticket = FA2_1Ticket::new(
        ticketer.clone(),                              // creator = ticketer
        MichelsonPair(
            MichelsonNat::from(0u32),                  // token_id = 0
            MichelsonOption(None),                     // no metadata
        ),
        amount_mutez,                                  // amount in mutez
    ).expect("valid ticket");

    // 2. Build the outbox transaction
    let parameters: WithdrawalParams = MichelsonPair(
        MichelsonContract(receiver.clone()),
        ticket,
    );

    let transaction = OutboxMessageTransaction {
        parameters,
        destination: ticketer.clone(),  // send to the ticketer contract
        entrypoint: Entrypoint::try_from("burn".to_string()).unwrap(),
    };

    // 3. Queue it (the SDK handles flushing to the actual outbox)
    let message = OutboxMessage::AtomicTransactionBatch(vec![transaction].into());
    OUTBOX_QUEUE
        .queue_message(host, message)
        .expect("queue withdrawal");
}
```

After queuing, flush the outbox queue at the end of your kernel run:

```rust
OUTBOX_QUEUE.flush_queue(host);
```

### 2.4 What happens on L1

After the commitment containing this outbox message is cemented (typically ~2 weeks
for the default challenge period), anyone can execute the outbox message on L1 using
the `smart_rollup_execute_outbox_message` operation. This:

1. Calls `ticketer.burn(receiver, ticket)`
2. The ticketer verifies the ticket, destroys it, and sends `amount_mutez` mutez
   to the `receiver` address

This is the "slow withdrawal" path — no trust assumptions beyond the rollup's
fraud proof / validity proof mechanism.

### 2.5 Key details from Etherlink

- **Outbox message format**: The SDK's `OutboxMessage::AtomicTransactionBatch`
  is the standard format. It encodes as: tag byte (0x00) + dynamic-length list
  of transactions. Each transaction has: parameters + destination + entrypoint.
  (See `src/kernel_sdk/encoding/src/outbox.rs:28-36, 174-185`)

- **Ticket must match exactly**: The ticket in the outbox message must have the
  same creator (ticketer), content type (`Pair(nat, option bytes)`), and content
  value (`Pair(0, None)`) as the tickets used for deposits. The L1 ticketer
  contract will reject mismatched tickets.

- **Entrypoint is "burn"**: Etherlink calls the ticketer's `burn` entrypoint.
  Your ticketer contract must implement this.
  (See `etherlink/kernel_latest/revm/src/precompiles/send_outbox_message.rs:270`)

- **Outbox queue**: The SDK provides `OUTBOX_QUEUE` which handles batching and
  the 100-messages-per-level limit. Use `queue_message()` then `flush_queue()`.
  (See `src/kernel_sdk/sdk/src/outbox.rs:99`)

- **Wei/mutez conversion in Etherlink**: Etherlink converts wei back to mutez
  (divide by 10^12) before putting the amount in the ticket. It also rejects
  amounts with non-zero remainder (sub-mutez precision).
  (See `etherlink/kernel_latest/ethereum/src/wei.rs:28-42`)

---

## Part 3: Minimal Kernel Structure

```rust
use tezos_smart_rollup::prelude::*;
use tezos_smart_rollup::entrypoint;
use tezos_smart_rollup::outbox::OUTBOX_QUEUE;

#[entrypoint::main]
pub fn kernel_run(host: &mut impl Runtime) {
    // 1. Read all inbox messages
    while let Ok(Some(message)) = host.read_input() {
        match parse_message(message.as_ref()) {
            Some(Message::Deposit { receiver, amount_mutez }) => {
                credit_balance(host, &receiver, amount_mutez);
            }
            Some(Message::Withdrawal { sender, receiver, amount_mutez }) => {
                if debit_balance(host, &sender, amount_mutez) {
                    queue_withdrawal_outbox_message(
                        host, &receiver, amount_mutez, &load_ticketer(host),
                    );
                }
            }
            None => {} // ignore unparsable / system messages
        }
    }

    // 2. Flush any queued outbox messages
    OUTBOX_QUEUE.flush_queue(host);
}
```

### Storage layout (minimal)

```
/ticketer          — KT1 address of the ticketer contract (set at origination)
/balances/<addr>   — u64 balance in mutez for each L2 address
```

---

## Part 4: L1 Ticketer Contract (Michelson sketch)

The ticketer contract needs two entrypoints:

### `mint` (deposit path)

```
parameter (pair (bytes %receiver) (address %rollup));
# 1. Accept tez (AMOUNT)
# 2. Create ticket: TICKET (Pair 0 None) AMOUNT
# 3. Transfer ticket to rollup: TRANSFER_TOKENS to rollup %deposit
```

### `burn` (withdrawal path)

```
parameter (pair (contract %receiver unit) (ticket %ticket (pair nat (option bytes))));
# 1. READ_TICKET — verify creator is SELF, content is (Pair 0 None)
# 2. DROP ticket (destroys it)
# 3. Send amount mutez to receiver: TRANSFER_TOKENS unit amount receiver
```

The key invariant: **every mutez locked in the ticketer has a corresponding ticket
in circulation** (either on L1 or inside the rollup). Burning a ticket releases
exactly that many mutez.

---

## Part 5: What you can skip (vs Etherlink)

| Etherlink feature | Needed for minimal rollup? |
|---|---|
| EVM execution engine (REVM) | No — handle deposits/withdrawals directly in kernel |
| Sequencer mode / delayed inbox | No — proxy mode only (read inbox directly) |
| FA token bridge | No — tez only |
| Fast withdrawals | No — standard outbox path only |
| Wei/mutez conversion | No — track mutez natively |
| Precompiled Solidity contracts | No — handle withdrawal requests as external messages |
| Blueprint / block production | No — process messages immediately |
| Migration framework | No (initially) |
| Tick budgeting / reboot management | Maybe — depends on expected throughput |
| Chain ID / multi-chain support | No |
| DAL slot processing | No |
| Transaction signing (ECDSA) | Depends on your auth model |

---

## Part 6: Security Considerations

1. **Always validate the ticketer**: Only credit balances for tickets from your
   known ticketer contract. This is the single most important check.

2. **Verify rollup address**: Check that `transfer.destination` matches your
   rollup's address (via `host.reveal_metadata().address()`).

3. **Prevent double-processing**: The inbox is consumed linearly — each message
   is read exactly once. The SDK handles this for you.

4. **Balance underflow**: Always check sufficient balance before debiting
   for withdrawals.

5. **Outbox message limit**: Max 100 outbox messages per Tezos level.
   The `OUTBOX_QUEUE` SDK helper manages this, but excess messages will be
   deferred to subsequent levels (requiring reboots).

6. **Cementation delay**: Outbox messages can only be executed on L1 after the
   commitment is cemented (~2 weeks). Users must wait. This is inherent to the
   optimistic rollup design.
