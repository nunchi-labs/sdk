use crate::{FeedId, FeedIdError, FeedPayload, OracleDB, OracleError, OracleLedger};
use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use nunchi_common::Address;
use serde::{Deserialize, Serialize};

/// JSON-facing oracle genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleGenesis {
    /// Feed definitions to register before the first block.
    #[serde(default)]
    pub feeds: Vec<FeedGenesisEntry>,
}

/// One feed definition in the oracle genesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeedGenesisEntry {
    /// Feed identifier string (up to [`crate::MAX_FEED_ID_BYTES`] UTF-8 bytes).
    pub feed_id: String,
    /// Hex-encoded owning [`Address`].
    pub owner: String,
    /// Arbitrary JSON metadata stored alongside the feed definition.
    pub metadata: serde_json::Value,
}

impl<D: OracleDB> OracleLedger<D> {
    /// Seed oracle state from genesis while preserving ledger invariants.
    pub async fn apply_genesis(&mut self, genesis: &OracleGenesis) -> Result<(), OracleError> {
        for entry in &genesis.feeds {
            let feed_id = FeedId::new(entry.feed_id.clone())
                .map_err(|err: FeedIdError| OracleError::Storage(err.to_string()))?;
            let owner = decode_hex_address(&entry.owner)?;
            let metadata = FeedPayload::json(&entry.metadata)
                .map_err(|err| OracleError::Storage(err.to_string()))?;
            self.register_feed(owner, feed_id, metadata).await?;
        }
        Ok(())
    }
}

fn decode_hex_address(value: &str) -> Result<Address, OracleError> {
    let bytes = from_hex(value)
        .ok_or_else(|| OracleError::Storage("invalid hex address".to_string()))?;
    Address::decode(bytes.as_ref()).map_err(|err| OracleError::Storage(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_formatting::hex;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use nunchi_common::QmdbState;
    use nunchi_crypto::PrivateKey;
    use serde_json::json;

    async fn ledger(
        context: deterministic::Context,
        partition: &str,
    ) -> OracleLedger<QmdbState<deterministic::Context>> {
        let db = QmdbState::init(context, partition)
            .await
            .expect("init state db");
        OracleLedger::new(db)
    }

    #[test]
    fn apply_genesis_registers_feeds() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut ledger = ledger(context, "oracle-genesis").await;

            let owner = PrivateKey::ed25519_from_seed(1);
            let owner_address = Address::external(&owner.public_key());
            let owner_hex = hex(owner_address.encode().as_ref());

            let genesis = OracleGenesis {
                feeds: vec![
                    FeedGenesisEntry {
                        feed_id: "btc/usd".to_string(),
                        owner: owner_hex.clone(),
                        metadata: json!({"kind": "price", "base": "BTC", "quote": "USD"}),
                    },
                    FeedGenesisEntry {
                        feed_id: "eth/usd".to_string(),
                        owner: owner_hex.clone(),
                        metadata: json!({"kind": "price", "base": "ETH", "quote": "USD"}),
                    },
                ],
            };

            ledger.apply_genesis(&genesis).await.unwrap();

            let btc = ledger
                .feed(&crate::FeedId::new("btc/usd").unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(btc.owner, owner_address);

            let eth = ledger
                .feed(&crate::FeedId::new("eth/usd").unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(eth.owner, owner_address);
        });
    }

    #[test]
    fn apply_genesis_rejects_duplicate_feeds() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut ledger = ledger(context, "oracle-genesis-dup").await;

            let owner = PrivateKey::ed25519_from_seed(1);
            let owner_hex = hex(Address::external(&owner.public_key()).encode().as_ref());

            let genesis = OracleGenesis {
                feeds: vec![
                    FeedGenesisEntry {
                        feed_id: "dup/feed".to_string(),
                        owner: owner_hex.clone(),
                        metadata: json!({}),
                    },
                    FeedGenesisEntry {
                        feed_id: "dup/feed".to_string(),
                        owner: owner_hex,
                        metadata: json!({}),
                    },
                ],
            };

            let err = ledger.apply_genesis(&genesis).await.unwrap_err();
            assert!(matches!(err, OracleError::DuplicateFeed(_)));
        });
    }

    #[test]
    fn empty_genesis_is_a_no_op() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut ledger = ledger(context, "oracle-genesis-empty").await;
            ledger.apply_genesis(&OracleGenesis::default()).await.unwrap();
        });
    }
}
