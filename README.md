<p align="center">
  <img src="image.png" alt="Nunchi" width="480" />
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

---


# What this is
The Nunchi SDK is an easy-to-use modular blockchain framework offering financial primitives for commonware-based chains. The core of the framework can be found in the [`nunchi-coins`](coins/) crate

A chain built with the Nunchi SDK adopts our coin model, account model, dkg resharing, and bridging setup. The SDK is handcrafted for the requirements of specialized low-latency finance.

## Genesis setup

Genesis is split across two layers:

* [`coins/src/genesis.rs`](coins/src/genesis.rs) defines the coin-module genesis state:
  * `CoinsGenesis` collects `account_policies` and `tokens`
  * `TokenGenesis` defines a token plus its initial `allocations` and optional `max_supply`
  * allocations are validated against the token's `initial_supply`
* [`examples/coins-chain/src/genesis.rs`](examples/coins-chain/src/genesis.rs) defines the chain-level wrapper:
  * `ChainGenesis` composes `authority` genesis with optional `coins` genesis
  * `apply_to_state` applies the full genesis to chain state and fingerprints it to prevent mismatched re-initialization

In other words, token allocations live in the `coins` module, while the top-level genesis entry point lives one layer above it in the chain.

## Modules

This repository will contain modules for building public and private blockchains, as well as sequencer systems / rollups. 

### Blockchain Basics

* [`coins`](coins/) - defines what a coin and account are. Also contains other basic financial functions
* [`crypto`](crypto/) - defines key primitives and wrappers around commonware cryptographic primitives
* [`rpc`](rpc/) - core abstractions for modular RPC
* [`dkg`](dkg/) - contains dkg resharing ceremony logic and a consensus engine orchestator
* `bridge` - moves coins between chains
* `oracle` - takes in price feeds and provides them to other modules
* `chat` - allows humans or agents to publish to permanent on-chain public conversations
* `factory` - wrapper of coins for mass issuance 

### Network Infrastructure 

* [`authority`](authority/) - provides a proof of authority setup for a chain
* `pos` - provides a proof of stake security setup for a chain

### Financial Primitives

* `margin` - user has BTC + nunchi and doesn't want to sell, and deposits BTC+nunchi and gets a stablecoin.  Could be backed by other coins, not just btc and nunchi. 
* `securities` - Non-synthetic perps contracts (delivery of tokenized stock)
* `vaults` - a module for running vaults composed of many types of capital, traded by an authorised offchain party
* `clob` - used on the global chain, provides liquidity between local chain tokens
* `derivatives` - ingests a price feed and creates derivatives products
* `stablecoin` - a wrapper of coins special for the needs of stablecoins
