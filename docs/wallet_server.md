# wallet-server

HTTP server exposing a private wallet over a local REST API. Designed to be used by the TzEL web dapp or any HTTP client.

## Building

```bash
cargo build -p tzel-wallet-app --bin wallet-server --release
```

## Running

```bash
wallet-server \
  --wallet=/path/to/wallet.json \
  --ledger=http://<tzel-operator>:8787 \
  --port=8081 \
  --skip-proof            # skip STARK proofs (demo/dev only)
```

With a real proving service:

```bash
wallet-server \
  --wallet=/path/to/wallet.json \
  --ledger=http://<tzel-operator>:8787 \
  --port=8081 \
  --proving-service=http://<proving-service>:9000
```

A fresh wallet is created automatically if the file does not exist.

## API

### `GET /balance`

Returns the available private balance.

```json
{ "private_balance": 1000000 }
```

### `POST /address`

Generates the next payment address and persists the wallet. The address is a JSON blob containing the KEM public keys and diversifier needed for a sender to encrypt a note to this wallet. Each call advances the address counter — share the result with senders and call again to get a fresh address.

### `POST /scan`

Pulls new notes from the ledger and updates the local wallet state.

```bash
curl -X POST http://localhost:8081/scan
```

### `POST /shield`

Shields funds from a public L1 address into the private pool.

```json
{ "sender": "tz1...", "amount": 1000000 }
```

### `POST /transfer`

Transfers private funds to another payment address.

```json
{
  "to": { "d_j": "0x...", "auth_root": "0x...", "auth_pub_seed": "0x...", "nk_tag": "0x...", "ek_v": "0x...", "ek_d": "0x..." },
  "amount": 500000
}
```

### `POST /unshield`

Withdraws private funds to a public L1 address.

```json
{ "recipient": "tz1...", "amount": 500000 }
```

## Testing manually

### Prerequisites

- A running `tzel-operator` connected to an L1 node (or use the `--skip-proof` flag to skip proofs)
- A funded L1 address in the octez-client keychain (for shield)

### Step-by-step

1. **Start the wallet server**

```bash
wallet-server --wallet=/tmp/test-wallet.json --ledger=http://localhost:8787 --port=8081 --skip-proof
```

2. **Check balance** (should be 0 on a fresh wallet)

```bash
curl http://localhost:8081/balance
```

3. **Get a payment address**

```bash
curl -X POST http://localhost:8081/address
```

4. **Shield funds**

```bash
curl -X POST http://localhost:8081/shield \
  -H 'Content-Type: application/json' \
  -d '{"sender":"tz1youraddress","amount":1000000}'
```

5. **Scan to detect incoming notes**

```bash
curl -X POST http://localhost:8081/scan
curl http://localhost:8081/balance   # should now show the shielded amount
```

6. **Transfer to another wallet** (obtain a payment address from another wallet-server instance first)

```bash
curl -X POST http://localhost:8081/transfer \
  -H 'Content-Type: application/json' \
  -d '{"to":{...payment address JSON...},"amount":400000}'
```

7. **Unshield to L1**

```bash
curl -X POST http://localhost:8081/unshield \
  -H 'Content-Type: application/json' \
  -d '{"recipient":"tz1destinationaddress","amount":300000}'
```

## Web dapp

The `web/` directory contains a Vite/React frontend that connects to a running `wallet-server`.

```bash
cd web
npm install
npm run dev    # starts on http://localhost:5173
```

Set the wallet server URL in the UI (defaults to `http://localhost:8081`).
