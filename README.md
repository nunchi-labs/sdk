<p align="center">
  <img src="image.png" alt="Nunchi" width="240" />
</p>

<h3 align="center">Nunchi SDK</h3>

<p align="center">
  modular blockchain framework adding financial primitives to commonware-based chains
</p>

<p align="center">
  <a href="https://docs.nunchi.trade"><strong>Docs</strong></a> &nbsp;&bull;&nbsp;
  <a href="https://discord.gg/nunchi"><strong>Discord</strong></a> &nbsp;&bull;&nbsp;
  <a href="https://x.com/nunchi"><strong>X</strong></a>
</p>

<p align="center">
  <a href="https://app.codecov.io/gh/nunchi-labs/sdk">
    <img src="https://codecov.io/gh/nunchi-labs/sdk/graph/badge.svg" alt="Codecov" />
  </a>
  <a href="./LICENSE-MIT">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" />
  </a>
  <a href="./LICENSE-APACHE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="Apache 2.0 License" />
  </a>
</p>

---


# What this is
The Nunchi SDK is an easy-to-use modular blockchain framework offering financial primitives for commonware-based chains. The core of the framework can be found in the [`nunchi-coins`](coins/) crate

A chain built with the Nunchi SDK adopts our coin and account model, dkg resharing, and bridging setup. The SDK is handcrafted for the requirements of specialized low-latency finance.

## Modules

This repository will contain modules for building public and private blockchains, as well as sequencer systems / rollups. 

### Blockchain Basics

* [`nunchi-coins`](coins/) - defines what a coin and account are
* [`nunchi-common`](common/) - core abstractions for addresses, state db, and runtime
* [`nunchi-crypto`](crypto/) - core primitives/wrappers around commonware cryptographic primitives
* [`nunchi-rpc`](rpc/) - core abstractions for modular RPC
* [`nunchi-dkg`](dkg/) - contains dkg resharing ceremony logic and a consensus engine orchestator
* [`nunchi-bridge`](bridge/) - bridges state roots from other chains, to verify against
* [`nunchi-mempool`](mempool/) - simple p2p mempool
* [`nunchi-oracle`](oracle/) - ingests namespaced, arbitrary data for interpretation by other modules 
* [`nunchi-access-control`](access-control/) - optional scope ownership and role membership for permissioned modules
* `nunchi-chat` - allows humans or agents to publish to permanent on-chain public conversations
* `nunchi-factory` - wrapper of coins for mass issuance 

### Network Infrastructure 

* [`nunchi-authority`](authority/) - provides a proof of authority setup for a chain
* `nunchi-pos` - provides a proof of stake security setup for a chain

* [`nunchi-narae`](narae/) - local devnet runner
* [`nunchi-chain`](chain/) - runtime primitives for generated nunchi chains.

### Financial Primitives

* `nunchi-margin` - user has BTC + nunchi and doesn't want to sell, and deposits BTC+nunchi and gets a stablecoin.  Could be backed by other coins, not just btc and nunchi. 
* `nunchi-securities` - Non-synthetic perps contracts (delivery of tokenized stock)
* `nunchi-vaults` - a module for running vaults composed of many types of capital, traded by an authorised offchain party
* [`nunchi-clob`](clob/) - used on the global chain, provides liquidity between local chain tokens
* `nunchi-derivatives` - ingests a price feed and creates derivatives products
* `nunchi-stablecoin` - a wrapper of coins special for the needs of stablecoins

### Chain Examples

* [`coins-chain`](examples/coins/chain) - default PoA chain
* [`bridge-chain`](examples/bridge-chain) - two chains bridging consensus certificates
* [`custom-module`](examples/custom-module) - starter template for creating a custom nunchi module
* [`wallet-extension`](examples/wallet-extension) - Manifest V3 Chrome browser wallet with WASM crypto

## Commonware compatibility

This workspace pins `commonware-*` crates to **2026.9.0**.

When upgrading nodes:

* Do not run mixed commonware versions in the same peer set (marshal coding / ZODA shards and other wire formats are not interchangeable).
* Mid-sync glue metadata from v2026.7.0 cannot resume after upgrading to v2026.9.0; clear or re-sync any node that crashed mid state-sync before the bump.
* Fresh joining nodes can enable peer QMDB state sync with `state_sync = true`. Nunchi's resolver preserves Commonware's standard wire layout while decoding variable-value operations with the chain-wide 512 KiB value bound.

## Commonware MCP

[`mcp/`](mcp/) is Commonware's MCP server, vendored from [commonwarexyz/monorepo](https://github.com/commonwarexyz/monorepo/tree/5ac6c01c0901d0d48997820f898ceed286c10b73/mcp) at `5ac6c01c0901d0d48997820f898ceed286c10b73`. It replaces `nunchi-mcp`. The package is a TypeScript Cloudflare Worker, so it is not a Cargo workspace member and `cargo build` does not compile it. Node.js 22 is required. Wrangler is installed with the package. A Cloudflare account is required only to deploy.

`nunchi-mcp` was `cargo run -p nunchi-mcp` and spoke MCP over stdio. Build and run this server with:

```bash
just mcp-build
just mcp
```

`just mcp-build` runs `npm ci` and `npm run build` in `mcp/`. `just mcp` applies the local D1 migration and runs `npm run dev`. The server listens on `http://127.0.0.1:8787`.

Cursor ([`.cursor/mcp.json`](.cursor/mcp.json)) and Claude Code ([`.mcp.json`](.mcp.json)) use that URL. Start `just mcp` first. Other clients use the same Streamable HTTP endpoint.

This workspace pins `commonware-*` to **2026.9.0**, indexed as `v2026.9.0`. Pass that `version` on `get_file`, `search_code`, `list_crates`, `get_crate_readme`, and `list_files`. The server defaults to the latest indexed release.

After the server is up, fill the local search index:

```bash
curl "http://127.0.0.1:8787/__scheduled?cron=*"
```

Checks for the package are `npm run ci` in `mcp/` (format, lint, typecheck, unit tests). Tool list, deploy steps, and architecture are in [`mcp/README.md`](mcp/README.md).

Nunchi chain queries and transaction submission stay on the node's JSON-RPC API (narae's default base port is 8545).

## License

This repository is dual-licensed under both the [Apache 2.0](./LICENSE-APACHE) and [MIT](./LICENSE-MIT) licenses. You may choose either license when employing this code.
