# sdk
The Nunchi SDK for Commonware blockchains is an easy to use, modular blockchain framework that centers around a singular definition of what a coin is and how bridging should work.  

By adopting the Nunchi SDK for your project, you adopt tbe coin definiton and bridging stule, but arent forced to adopt anything else.  The Nunchi SDK is designed around the specific needs of specalized, localized, high speed finance.  

## Modules

This repository will contain modules for building public and private blockchains, as well as sequencer systems / rollups. 

### Blockchain Basics

* Coins - defines what a coin is, other basic financial functions
* Bridge - moves coins between chains
* Oracle - takes in price feeds and provides them to other modules.  Time series database.
* Chat - allows humans or agents to publish to permanent on-chain public conversations
* Factory - wrapper of coins for mass issuance 

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

