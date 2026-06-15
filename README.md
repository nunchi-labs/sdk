# sdk
The Nunchi SDK is an easy-to-use modular blockchain framework offering financial primitives for commonware-based chains. The core of the framework can be found in the [`nunchi-coins`](coins/) crate

By adopting the Nunchi SDK for your project, you adopt tbe coin definiton and bridging stule, but arent forced to adopt anything else.  The Nunchi SDK is designed around the specific needs of specalized, localized, high speed finance.  

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

* Authority - provides a proof of authority setup for a chain
* Sequencer - Allows a set of chain logic to behave as a sequencer
* POS - provides a proof of stake security setup for a chain

### Finance

* Portfolio Margin - user has BTC + nunchi and doesn't want to sell, and deposits BTC+nunchi and gets a stablecoin.  Could be backed by other coins, not just btc and nunchi. 
* Securities - Non-synthetic perps contracts (delivery of tokenized stock)
* Vaults - a module for running vaults composed of many types of capital, traded by an authorised offchain party
* Clob - used on the global chain, provides liquidity between local chain tokens
* Derivatives - ingests a price feed and creates derivatives products
* Stablecoin - a wrapper of coins special for the needs of stablecoins

