# Privacy Policy - Nunchi Wallet

**Last Updated:** 21 August 2026  
**Contact:** info@nunchi.trade

## Data Collection
Nunchi Ltd collects nothing. This extension:
- Does NOT use analytics
- Does NOT create user accounts
- Does NOT phone home
- Does NOT track usage

## Local Storage
The extension stores data locally in `chrome.storage.local` only:
- Encrypted keystore (AES-GCM, PBKDF2-SHA256 key derivation)
- Settings (RPC endpoint, selected curve)
- Last 50 transactions (display only)
- Connected origins (sites you've approved)
- Pending approval prompts
- Unlock lockout counters

## Key Security
Private keys leave the browser only in two cases:
1. User-approved signed transactions broadcast to configured RPC
2. Explicit backup/export initiated by user from the extension page

## Network
- Default RPC: `http://localhost:8545` (local node)
- Remote RPC: user-configured, extension does not recommend or endorse any service
- All RPC communication is user-initiated or in response to page requests

## Content Script
The content script:
- Injects `window.nunchi` provider for dApp compatibility
- Does NOT scrape or read DOM content
- Only forwards allowlisted messages: `REQUEST_CONNECTION`, `REQUEST_TRANSACTION`, `REQUEST_SIGN`, `GET_CHAIN_ID`

## Children
This extension is not directed at children under 13.

## Changes
Updates to this policy will be posted with a new "Last Updated" date.

---
**Nunchi Ltd**  
info@nunchi.trade
