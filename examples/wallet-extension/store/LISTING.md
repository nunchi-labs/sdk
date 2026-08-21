# Nunchi Wallet - Chrome Web Store Listing

## Name
Nunchi Wallet

## Short Description
Draft Chrome wallet for Nunchi coins. Ed25519 or P-256 keys, nch addresses, window.nunchi. Not an EVM wallet.

## Full Description
MV3 draft SDK example, not audited, not production-ready. Not EVM / not EIP-1193.

**Features:**
- `window.nunchi` provider for dApp integration
- Ed25519 or P-256 (Secp256r1) key generation with CSPRNG
- Bech32 `nch` address format
- Signs via `nunchi-coins Transaction::sign`: transfer, create token, mint, burn, account policy
- Keystore: PBKDF2-SHA256 + AES-GCM encrypted in `chrome.storage.local`

**Security:**
- Pages can only send: `REQUEST_CONNECTION`, `REQUEST_TRANSACTION`, `REQUEST_SIGN`, `GET_CHAIN_ID`
- Approval popup for all privileged operations
- Backup is privileged (extension page only)

**Network:**
- Default RPC: http://localhost:8545
- User can configure remote RPC

**Legal:**
Copyright Nunchi Ltd.

## Category
Productivity (or Developer Tools)

## Language
English
