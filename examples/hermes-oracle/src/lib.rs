//! Hermes price-feed adapter for Nunchi oracle updates.
//!
//! # Status
//!
//! This module is an integration harness for measuring how quickly external price observations
//! can become finalized oracle state. It signs normal `nunchi-oracle` update transactions and
//! submits them to a caller-provided transaction sink, so finalized state still goes through the
//! chain's ordinary mempool, consensus, and ledger paths.
//!
//! # Examples
//!
//! A chain node can construct a [`HermesFeed`] for a Pyth price ID and pass its local
//! `MempoolHandle<ChainTransaction>` as the sink, provided `ChainTransaction` implements
//! `From<nunchi_oracle::Transaction>`.

mod actor;
mod hermes;

pub use actor::{
    Actor, ActorConfig, ActorError, FeedObservation, OracleUpdateSink, PriceFeed, SubmittedUpdate,
};
pub use hermes::{
    feed_id_from_hermes_id, parse_hermes_price_update, HermesError, HermesFeed, HermesFeedConfig,
};
