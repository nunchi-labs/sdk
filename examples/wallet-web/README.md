# wallet-web

Browser passkey wallet kit for Nunchi SDK chains.

Adapted from [Commonware Constantinople](https://github.com/commonwarexyz/constantinople/blob/main/explorer/src/wallet.ts)
with Nunchi's `nch` address story in mind. This example handles WebAuthn registration and signing;
your chain must verify bundled secp256r1 assertions before mainnet use.

## Usage

```ts
import { createPasskeyWallet, signWithPasskey } from './wallet';

const wallet = await createPasskeyWallet('my-wallet');
const signature = await signWithPasskey(wallet, challengeBytes);
```

Integrate with your app's transaction builder by passing the tx hash bytes as the WebAuthn challenge.

## Build

```bash
npm install
npm run build
```
