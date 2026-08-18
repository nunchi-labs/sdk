# Nunchi Wallet Extension

A Manifest V3 Chrome extension wallet for Nunchi chains.

## Features

- **Key Management**: Create or import Ed25519 and Secp256r1 (P-256) keys
- **Secure Storage**: Private keys encrypted at rest with password and Argon2-derived keys
- **Address Derivation**: Byte-identical `nch...` Bech32 addresses matching `Address::external`
- **Transaction Signing**: Sign and submit coin transfers with proper namespace and codec
- **In-Page Provider**: `window.nunchi` and `window.nunchi.coins` API for dApps
- **Site Permissions**: Per-origin connection approval
- **Activity Tracking**: View submitted transaction history
- **RPC Configuration**: Configurable network and RPC endpoint

## Architecture

- **WASM Crypto**: Reuses `nunchi-crypto`, `nunchi-common`, `nunchi-coins` for byte-identical encoding
- **Service Worker**: Manifest V3 background service worker manages wallet state and RPC
- **Content Script**: Injects in-page provider into every page
- **Popup UI**: React-based dark finance UI for wallet operations

## Build

### Prerequisites

- Rust 1.88+ (for WASM dependencies) with `wasm-pack` installed: `cargo install wasm-pack`
- Node.js and npm
- `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`

### Build Steps

```bash
cd examples/wallet-extension

# Build WASM crypto wrapper
npm run build:wasm

# Install dependencies
npm install

# Build extension
npm run build
```

The built extension will be in `dist/`.

## Load Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select the `dist/` directory
5. The Nunchi Wallet extension should now appear

## Usage with Coins Chain

### Start Coins Chain

```bash
cd examples/coins/chain
cargo run --bin coins-chain -- --config node0.json
```

### Start Coins Frontend

```bash
cd examples/coins/frontend
npm install
npm run dev
```

Visit http://localhost:5173 and you should see a "Connect Nunchi Wallet" button when the extension is installed.

### Create a Wallet

1. Click the Nunchi Wallet extension icon
2. Choose "Create New Wallet"
3. Select curve (Ed25519 recommended)
4. Set a password (minimum 8 characters)
5. Your wallet is created with a `nch...` address

### Connect to a dApp

1. Visit a Nunchi dApp (like the coins frontend)
2. Click "Connect Nunchi Wallet"
3. Approve the connection in the popup
4. Your address is now connected

### Send a Transaction

1. In the wallet popup, click "Send"
2. Enter recipient `nch...` address
3. Enter coin ID (hex)
4. Enter amount
5. Confirm the transaction
6. Transaction is signed and submitted to the configured RPC

## API

### Provider API

The extension injects `window.nunchi` with the following methods:

```typescript
// Request connection (user approval required)
const accounts = await window.nunchi.request({ 
  method: 'nunchi_requestAccounts' 
});

// Get connected accounts
const accounts = await window.nunchi.request({ 
  method: 'nunchi_accounts' 
});

// Get chain ID
const chainId = await window.nunchi.request({ 
  method: 'nunchi_chainId' 
});

// Sign and send transaction
const { hash } = await window.nunchi.request({
  method: 'nunchi_sendTransaction',
  params: [{
    coin: '0xabcd...',
    from: 'nch1...',
    to: 'nch1...',
    amount: '1000'
  }]
});

// Listen for account changes
window.nunchi.on('accountsChanged', (accounts) => {
  console.log('Accounts changed:', accounts);
});
```

### Coins Provider

A convenience wrapper is available at `window.nunchi.coins` with the same API.

## Test Fixtures

The WASM crypto layer ensures byte-identical encoding with Rust. Test that:

1. Address derivation matches `Address::external` for known keys
2. Signed transactions match `Transaction::sign` output

### Example Test

```typescript
import * as wasm from './wasm/nunchi_wallet_crypto';

// Known private key from Rust tests (seed 1)
const knownKey = '01...'; // Ed25519 private key bytes

// Import and verify
const keyPair = wasm.import_private_key(knownKey);
console.log('Address:', keyPair.address);

// Should match Rust Address::external(&PrivateKey::from_seed(1).public_key())
// Verify with: cargo test --package nunchi-common --lib tests::account
```

## Security Notes

- **Private Keys**: Never shared outside the extension. Encrypted at rest with AES-GCM.
- **Passwords**: Derived with PBKDF2-SHA256 (100k iterations) for encryption keys.
- **Site Isolation**: Each site requires explicit user approval to connect.
- **No Remote Code**: All crypto operations use local WASM, no external dependencies.
- **Audit Needed**: This is demo code. Production use requires a security audit.

## Development

```bash
# Build WASM in watch mode (manual for now)
cd wasm-crypto && wasm-pack build --target web --out-dir ../src/wasm --dev

# Build extension in dev mode
npm run dev
```

After changes, reload the extension in `chrome://extensions/`.

## Troubleshooting

### WASM Build Fails

Ensure `wasm-pack` is installed:
```bash
cargo install wasm-pack
```

### Extension Not Loading

- Check that all files exist in `dist/`
- Ensure `manifest.json` is valid
- Check browser console for errors

### Transactions Fail

- Verify coins-chain RPC is running and accessible
- Check configured RPC URL in settings matches your node
- Ensure account has sufficient balance and correct nonce
- Check that coin ID is valid hex

### Address Mismatch

If the wallet address doesn't match Rust:
- Verify WASM crypto built successfully
- Check that encoding uses the same domain `nunchi/account/v1` and kind `0`
- Compare with Rust fixture tests in `common/src/tests/account.rs`

## Contributing

When modifying crypto operations, always verify against Rust fixtures:

```bash
# Run Rust crypto tests
cargo test --package nunchi-crypto
cargo test --package nunchi-common

# Check address fixtures
cargo test --package nunchi-common address_derivation
```

## License

See repository root LICENSE.MD.
