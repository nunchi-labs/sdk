# Nunchi Wallet Specification

This document is the canonical specification for the `nunchi-wallet` crate shipped in the Nunchi SDK.

## 1. Address format (Bech32)

| Field | Value |
|---|---|
| Standard | BIP-173 classic Bech32 |
| HRP | `nch` |
| Payload | 32-byte `Address` digest |
| API | `Address::to_bech32()` / `Address::from_bech32()` |

Addresses are derived identifiers:

```
SHA256("nunchi/account/v1" || kind || material)
```

| Kind | Account type |
|---|---|
| `0` | External wallet (Ed25519 or secp256r1 public key) |
| `1` | Multisig bootstrap policy |
| `2` | Reserved module label |

Only `Address` user-facing fields use Bech32. Public keys, coin IDs, tx hashes, and state roots remain hex.

## 2. Transaction replay protection (`chain_id`)

Every `TransactionPayload` now includes a `chain_id: u64` field encoded before `nonce` and `operation`.

Signing bytes:

```
account_id || authorization_tag || payload.encode()
```

where `payload.encode()` is `chain_id || nonce || operation`.

Wallets must sign with the target chain's id. Changing `chain_id` after signing invalidates the authorization.

## 3. CLI wallet (Ed25519)

| Property | Value |
|---|---|
| Default curve | Ed25519 |
| Keystore root | `~/.nunchi/wallets/<name>/wallet.json` |
| Encryption | Argon2id + ChaCha20-Poly1305 |
| Password source | `NUNCHI_WALLET_PASSWORD` env var |
| Dev escape hatch | `--insecure-store` (plaintext JSON) |

Each record stores: name, `chain_id`, Bech32 address, encoded public key, encrypted private key, created timestamp.

## 4. RPC client

Submits hex-encoded coin transactions to:

```
coins.submit_transaction { "transaction": "<hex>" }
```

The CLI `submit-transfer` command builds a signed `CoinOperation::Transfer` and posts it to a running node.

## 5. Passkey wallet (web)

Browser wallets use WebAuthn P-256 assertions encoded in Constantinople-compatible form:

```
[scheme=1][64-byte sig][u16 len][authenticatorData][u16 len][clientDataJSON]
```

Reference implementation: [`examples/wallet-web`](../examples/wallet-web/).

On-chain verification of passkey signatures requires chain support for bundled WebAuthn assertions (future `nunchi-crypto` extension). The SDK ships encoding types now so web wallets and chains can integrate without another breaking wire change.

## 6. Wallet kit scope for third parties

| Layer | Crate / path | Audience |
|---|---|---|
| Address + tx signing | `nunchi-common`, `nunchi-crypto` | All integrators |
| Encrypted keystore + CLI | `nunchi-wallet` | Operators, devnets |
| Browser passkey kit | `examples/wallet-web` | dApp developers |
| RPC submission | `nunchi-wallet::client` | CLIs, agents, MCP tools |

## 7. Security notes

- Never log private keys or `NUNCHI_WALLET_PASSWORD`.
- Production deployments must not use `--insecure-store`.
- Wallets are chain-scoped via `chain_id`; multi-chain operators should create one wallet record per chain or rotate keys deliberately.
- Cross-chain replay of identical signed payloads is rejected once chains use distinct `chain_id` values.
