# Test Fixtures

These fixtures verify that the WASM crypto produces byte-identical encodings and addresses matching the Rust implementation.

## Known Addresses from Genesis

From `examples/coins/chain/tests/fixtures/genesis.json`:

### Issuer
```
Address: nch1jse7wvv4fhj7r7rg307a9nn5fsum4gv23pnudva725w7mhcpu2tsk096jm
```

### Allocation 1
```
Address: nch1g053yaztclz5sngrkhzh4xaucc2wpktf7qzz4yn3vnknat706peq075klx
Amount:  400
```

### Allocation 2
```
Address: nch1e7csjadvt76qxwus96edacptwyfcgput5lrudrt0udp4j86gmwmqnhgh8w
Amount:  600
```

Note: These are about 62 characters (Bech32, not Bech32m, HRP `nch`).

## Verification

Generate Rust fixtures:

```bash
cd examples/coins/chain
cargo test --lib address -- --nocapture | grep nch1
```

Or use coins-chain-tool:

```bash
# Generate key with seed
cargo run --bin coins-chain-tool -- genesis --accounts 1 --seed 1 --out /tmp/test.json
# Address and coin ID printed in output
```

## Testing in Extension

1. Build WASM: `npm run build:wasm`
2. Build extension: `npm run build`
3. Load extension in Chrome
4. Open test-fixtures.html in browser
5. Verify addresses match Rust output

The critical test is that `import_private_key(0x0120a3c1f1e4e3e2ea2787a5e9fb82c85cdb9e59242a8c2ea2fa6a5bb7e14a0e0a)` produces address `nch1qp6lnjh7rn3gaq0gm3v0k5j3v3n9qrkrc7j9zwywvexq9w3u4hkqczp9cc`.

## Transaction Signing

Verify that a signed transfer transaction from the extension can be decoded and verified by a Rust node.

```bash
# Submit a transaction signed by the extension
curl -X POST http://localhost:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"coins.submit_transaction","params":{"transaction":"<hex>"}}'
```

If the transaction is accepted and finalized, the encoding is correct.
