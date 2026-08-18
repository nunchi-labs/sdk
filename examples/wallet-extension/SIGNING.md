# Transaction Signing Details

This document explains exactly how transactions are signed in the Nunchi wallet to ensure byte-identical compatibility with the chain.

## Process

The WASM wrapper calls `Transaction::sign(&private_key, nonce, operation)` which performs the following steps:

### 1. Build Signing Bytes

```
signing_bytes = account_id.encode()        // 32 bytes (raw SHA256 digest)
             || authorization_tag          // u8: 0 = Single, 1 = Multisig
             || payload.encode()           // nonce (u64) || operation
```

- `account_id`: The address derived from the public key (32-byte SHA256 digest)
- `authorization_tag`: `0` for single-signature transactions
- `payload`: Contains nonce (u64) and the encoded `CoinOperation`

### 2. Sign with Commonware Signer

```rust
Signer::sign(namespace, signing_bytes)
```

**Important**: The commonware `Signer` does NOT hash the message first. It signs:

```
varint(namespace.len()) || namespace || signing_bytes
```

For the coins namespace `_NUNCHI_COINS` (13 bytes), the varint is `0x0d`:

```
0x0d || "_NUNCHI_COINS" || signing_bytes
```

This means the actual signed message is:
```
0x0d 0x5f 0x4e 0x55 0x4e 0x43 0x48 0x49 0x5f 0x43 0x4f 0x49 0x4e 0x53
|| account_id (32 bytes)
|| 0x00 (Single auth tag)
|| nonce (8 bytes, encoded as u64)
|| operation (variable length)
```

### 3. Transaction Digest

After signing, `Transaction::digest()` returns `SHA256(transaction.encode())`.

This is the transaction hash used by:
- Mempool for deduplication
- RPC `coins.submit_transaction` response
- Block explorers and indexers

**Note**: The digest is NOT the signed message. It's a hash of the complete encoded transaction (account_id + payload + authorization).

## Key Encoding

### Ed25519 (tag 1)
- Public key: 1 byte tag + 32 bytes = 33 bytes total
- Private key: 1 byte tag + 32 bytes = 33 bytes total  
- Signature: 1 byte tag + 64 bytes = 65 bytes total

### Secp256r1 / P-256 (tag 2)
- Public key: 1 byte tag + 33 bytes (compressed) = 34 bytes total
- Private key: 1 byte tag + 32 bytes = 33 bytes total
- Signature: 1 byte tag + 64 bytes = 65 bytes total

## Address Derivation

```rust
Address::external(&public_key) = SHA256(
    b"nunchi/account/v1"  // Domain separator (17 bytes)
    || 0x00               // Kind: external account
    || public_key.encode()  // Curve-tagged public key (33 or 34 bytes)
)
```

The result is encoded as **Bech32** (NOT Bech32m) with HRP `nch`, producing addresses around 62 characters long.

## Single-Signature Verification

The chain verifies a single-signature transaction by:

1. Extracting the `signer` public key from `Authorization::Single`
2. Computing `Address::external(signer)`
3. Checking that it equals `transaction.account_id`
4. Verifying the signature with:
   ```rust
   signer.verify(
       COINS_NAMESPACE,
       &signing_bytes(account_id, AUTH_SINGLE, payload),
       &signature
   )
   ```

If any step fails, the transaction is rejected.

## Example Transfer

```typescript
// Create a transfer
const operation = {
  coin: '0xabcd1234',  // CoinId (hex)
  from: 'nch1...',     // Sender address
  to: 'nch1...',       // Recipient address
  amount: '1000'       // u128 as string
};

// Sign (WASM calls Transaction::sign internally)
const signed = wasm.sign_transfer(
  privateKeyHex,
  nonce,           // Current account nonce (from coins.nonce RPC)
  operation.coin,
  operation.from,
  operation.to,
  operation.amount
);

// Result
signed.transaction_hex  // Hex-encoded nunchi_coins::Transaction
signed.digest_hex       // SHA256 hash for RPC submission

// Submit to RPC
POST http://127.0.0.1:8545
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "coins.submit_transaction",
  "params": {
    "transaction": signed.transaction_hex
  }
}

// Response
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "hash": signed.digest_hex  // Same as digest_hex
  }
}
```

## Correctness Verification

To verify the wallet signs correctly:

1. Generate a transaction in the wallet
2. Submit it to a coins-chain node via `coins.submit_transaction`
3. If accepted and finalized, the encoding is correct

Any encoding mismatch will be rejected by the mempool with an `InvalidSignature` error.

## Why WASM?

The wallet uses a WASM wrapper around the actual Rust crypto types (`nunchi-crypto`, `nunchi-common`, `nunchi-coins`) rather than reimplementing in TypeScript because:

1. **Zero divergence**: Uses the exact same code as the chain
2. **Codec correctness**: commonware-codec handles integer encoding, length prefixes, etc.
3. **Namespace handling**: The varint-prefixed namespace is automatic
4. **Future-proof**: Any chain updates to signing automatically apply to the wallet

This eliminates an entire class of bugs where wallet-signed transactions fail due to encoding differences.
