# Permissions Justification - Nunchi Wallet

## Required Permissions

### `storage`
**Required.**  
Used to persist:
- Encrypted wallet keystore
- User settings (RPC endpoint, curve selection)
- Connected site origins
- Recent transaction history (display only)
- Pending approval prompts
- Unlock attempt counters

### `unlimitedStorage`
**REMOVED** (previously requested, no longer needed).  
Standard `storage` quota is sufficient for wallet use.

## Host Permissions

### `host_permissions: ["http://localhost:*/", "http://127.0.0.1:*/"]`
**Required for default operation.**  
Default RPC endpoint is `http://localhost:8545` (local Nunchi node).  
Allows the extension to query balance, nonce, and submit transactions to a user's local node.

### `optional_host_permissions: ["http://*/*", "https://*/*"]`
**Optional - requested on demand.**  
If the user configures a remote RPC endpoint, the extension will call `chrome.permissions.request()` to ask for permission to access that specific origin.  
The extension does NOT automatically request broad network access.

## Content Scripts

### `matches: ["<all_urls>"]`, `all_frames: true`, `run_at: "document_start"`
**Justified for dApp compatibility.**  
- Injects `window.nunchi` provider into all pages (including iframes)
- Allows dApps to detect wallet and request connection
- Content script allowlists only four message types from pages:
  - `REQUEST_CONNECTION`
  - `REQUEST_TRANSACTION`
  - `REQUEST_SIGN`
  - `GET_CHAIN_ID`
- All privileged operations (CREATE_WALLET, UNLOCK, APPROVE, etc.) require sender origin to be the extension itself

The content script does NOT:
- Read or scrape page content
- Modify the DOM (except injecting the provider script)
- Forward arbitrary messages to the background

## Web Accessible Resources

### `resources: ["inpage.js"]`
**Required for `window.nunchi` injection.**  
The content script injects `inpage.js` as a module script to provide the `window.nunchi` API to pages.  
Only `inpage.js` is exposed; no other extension resources are accessible to pages.

---
No other permissions are requested or required.
