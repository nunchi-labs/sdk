# nunchi-wallet

Native wallet framework for chains built with the Nunchi SDK.

## Features

| Component | Description |
|---|---|
| **Bech32 addresses** | `nch1…` human-facing addresses via `nunchi-common::Address` |
| **CLI wallet** | Ed25519 key generation, encrypted keystore, sign helper |
| **RPC client** | Submit signed coin transactions to `coins.submit_transaction` |
| **Passkey types** | WebAuthn assertion encoding aligned with Commonware Constantinople |
| **Chain ID binding** | Every signed payload includes `chain_id` to prevent cross-chain replay |

## Quick start

```bash
# Create a wallet (prompts for password via NUNCHI_WALLET_PASSWORD)
export NUNCHI_WALLET_PASSWORD='your-passphrase'
nunchi-wallet create --name default --chain-id 1

# Show Bech32 address
nunchi-wallet address --name default

# Submit a signed transfer to a running node
nunchi-wallet submit-transfer \
  --name default \
  --rpc http://127.0.0.1:8545 \
  --chain-id 1 \
  --coin <coin-id-hex> \
  --to nch1… \
  --amount 1000 \
  --nonce 0
```

## Keystore layout

```
~/.nunchi/wallets/<name>/wallet.json
```

Records are encrypted with Argon2id + ChaCha20-Poly1305 when `NUNCHI_WALLET_PASSWORD` is set.
Use `--insecure-store` only for local development.

## Web passkey wallet

See [`examples/wallet-web`](../examples/wallet-web/) for a browser wallet kit adapted from
Commonware Constantinople's passkey implementation.
