# Shadownet Shielded Transfer Plan

## Goal

Get from the current state to a live shielded transfer on Shadownet that we can point testers at.

The minimum successful end-to-end flow is:

1. fund an L1 account on Shadownet
2. deposit into the rollup bridge
3. shield into a private note
4. send a shielded transfer to a second wallet
5. sync the recipient wallet and confirm the received note

## Current State

- live Shadownet rollup origination works
- bridge configuration works
- verifier configuration works
- L1 deposit into the rollup works
- the wallet can submit small direct rollup messages
- proof-bearing shield and transfer payloads are too large for direct inbox submission
- the wallet can prove a real shield locally and route it through `tzel-operator`
- `tzel-operator` now publishes oversized payloads to DAL, injects `publish dal commitment`, and tracks submission state on disk
- the kernel now understands DAL pointer messages and can attempt to fetch DAL-backed payloads through the rollup node reveal path
- the current live blocker is DAL availability on Shadownet:
  - commitments publish successfully
  - published slots from this VM became `unattested`
  - the rollup node then reveals `0` bytes for those chunks
- the next live milestone needs a public operator box with a reachable DAL node, not more inbox workarounds

## Definition Of Done

We are done with this phase when all of the following are true:

1. `tzel-wallet shield` succeeds on Shadownet through the operator path
2. `tzel-wallet send` succeeds on Shadownet through the operator path
3. the recipient wallet sees the transferred note after `tzel-wallet sync`
4. we have explorer links for:
   - bridge deposit
   - DAL commitment publish op
   - rollup pointer/control message op
   - the rollup address
5. we have one written smoke-test procedure that another person can run

## Critical Path

### 1. Freeze the DAL submission design

- define the small rollup control message that points at DAL-backed payloads
- keep the existing direct path for tiny admin/config messages
- decide the exact pointer fields:
  - operation kind
  - published level
  - slot index
  - expected payload length
  - expected payload hash
- decide whether the pointer is enough on its own or if we also want a local operator submission id for tracking

Acceptance:

- the wire format is written down in code and tests
- we are not guessing about what the kernel is supposed to fetch

### 2. Implement kernel-side DAL fetch and reassembly

- add DAL pointer handling to the kernel message decoder path
- use the real Octez DAL reveal host API, not a mock-only abstraction
- fetch pages in order
- reassemble the original payload bytes
- verify payload length and hash before decoding the embedded `KernelInboxMessage`
- reject malformed, partial, oversized, or mismatched payloads without mutating ledger state

Acceptance:

- unit tests cover good and bad DAL payload reconstruction
- the kernel only applies the underlying shield/transfer/unshield request after full validation

### 3. Build fast kernel tests for the DAL path

- add host-mocked tests for:
  - valid single-slot payload
  - missing page
  - wrong page order
  - wrong payload hash
  - truncated payload
  - oversized payload
  - wrong operation kind
- reuse checked-in proof fixtures where possible so tests stay fast

Acceptance:

- the DAL path is covered without requiring Octez or live network access
- rollup-kernel tests remain fast enough for normal development

### 4. Turn `tzel-operator` into a real slot publisher

- accept large shield and transfer payloads from the wallet
- publish the payload to the DAL node
- capture the returned commitment metadata
- inject the L1 `publish dal commitment` operation
- wait for inclusion and DAL attestation
- inject the small rollup pointer/control message once the slot is usable
- persist the submission state machine so restarts are safe

Suggested operator states:

- `accepted`
- `slot_published`
- `commitment_included`
- `attested`
- `pointer_sent`
- `completed`
- `failed`

Acceptance:

- a large wallet submission can move from accepted to completed without manual intervention
- the operator survives restart without losing in-flight submissions

Status:

- done for the current design
- oversized submissions now progress in the background without requiring client polling

### 5. Add fast operator tests

- mock the DAL publication step
- mock `octez-client publish dal commitment`
- mock pointer-message injection
- verify state transitions and retry behavior
- verify that oversize payloads no longer fail as direct inbox messages

Acceptance:

- `tzel-operator` behavior is testable without Shadownet
- failure modes are pinned by unit or integration tests

Status:

- in progress
- direct send, DAL publish, attested pointer send, waiting attestation, and terminal `unattested` are now covered

### 6. Finish the wallet/operator integration

- keep proof construction in the wallet
- route large rollup operations through `operator_url`
- make `tzel-wallet status --submission-id ...` useful enough to track live jobs
- ensure wallet output clearly distinguishes:
  - accepted by operator
  - pending DAL publication
  - commitment included
  - pointer sent
  - ready to sync

Acceptance:

- a tester can submit a shield or transfer and understand what stage it is in

### 7. Bring up the Shadownet operator machine

Run a single machine with:

- `octez-node`
- `octez-dal-node`
- `octez-smart-rollup-node --dal-node ...`
- `tzel-operator`

Tasks:

- make sure the rollup node is actually connected to the DAL node
- confirm the rollup node no longer logs that DAL is enabled but unavailable
- verify the operator account can pay for `publish dal commitment`
- verify the operator can inject small direct rollup messages as well

Acceptance:

- the box can both publish slots and feed the rollup node DAL data

Status:

- local VM bring-up proved the process wiring
- the remaining requirement is a public machine with a real `--public-addr` for the DAL node and open firewall rules so other DAL nodes can fetch shards in time to attest

### 8. Run the first live Shadownet shield

Use two wallets:

- Alice
- Bob

Steps:

1. fund Alice on L1
2. deposit into the rollup bridge
3. confirm Alice public rollup balance
4. shield from Alice public balance into Alice private balance through DAL
5. sync Alice and confirm the shielded note exists

Acceptance:

- Alice has a private note on the live rollup after a DAL-backed shield

### 9. Run the first live Shadownet shielded transfer

Steps:

1. derive Bob receive address
2. have Alice send a shielded transfer to Bob through the operator path
3. wait for operator completion and rollup processing
4. sync Bob
5. confirm Bob sees the received note
6. optionally sync Alice and confirm change handling

Acceptance:

- Bob receives the note on Shadownet
- the transfer can be demonstrated with concrete explorer links and wallet outputs

### 10. Capture a repeatable smoke test for others

Write down:

- the required services to run
- the wallet profile settings
- the operator settings
- the exact commands for:
  - deposit
  - shield
  - send
  - sync
- the expected outputs at each stage

Acceptance:

- another engineer can reproduce the live test without rediscovering the flow

## Testing Plan

### Fast local tests

- kernel DAL reconstruction unit tests
- operator state-machine tests
- wallet compile and CLI tests
- existing rollup bridge tests stay green

### Local Octez integration

- update the Octez sandbox path to exercise the pointer-message path if feasible
- if full DAL is too heavy locally, at least verify:
  - direct messages still work
  - pointer messages are decoded correctly
  - kernel state does not mutate on bad DAL payloads

### Live Shadownet tests

- one successful shield
- one successful transfer to a second wallet
- one failure-path test if practical, such as malformed operator submission rejected before L1 injection

## Concrete Order For The Next Few Hours

1. implement the DAL pointer/control message in shared wire types
2. implement kernel DAL fetch/reassembly
3. add kernel DAL tests
4. implement real operator DAL publish flow
5. add operator tests
6. wire wallet status and submission UX as needed
7. bring up the Shadownet DAL-enabled operator machine
8. run live shield
9. run live shielded transfer
10. write the reproducible smoke procedure with explorer links

## Things To Avoid

- do not try to cram proof-bearing payloads back into direct inbox submission
- do not make end-user wallets publish DAL commitments directly
- do not put wallet secret material on the operator machine
- do not let DAL payload decode failures mutate rollup state

## Artifacts To Collect

For the first successful live run, keep:

- rollup address
- bridge ticketer address
- operator account address
- deposit op hash
- DAL commitment publish op hash
- pointer/control message op hash
- recipient wallet address file
- sender and recipient wallet logs
- relevant rollup node and operator logs
