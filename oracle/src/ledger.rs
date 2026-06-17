use crate::{
    FeedDefinition, FeedId, FeedPayload, FeedRecord, FeedSubmission, OracleDB, OracleOperation,
    Transaction,
};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, CommitState};
use nunchi_crypto::SignatureError;
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum OracleError {
    #[error("bad oracle transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {account:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        account: Box<Address>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("feed already exists: {0:?}")]
    DuplicateFeed(FeedId),
    #[error("unknown feed {0:?}")]
    UnknownFeed(Box<FeedId>),
    #[error("feed {feed_id:?} belongs to {owner:?}, not {submitter:?}")]
    UnauthorizedPublisher {
        feed_id: Box<FeedId>,
        owner: Box<Address>,
        submitter: Box<Address>,
    },
    #[error("feed observation regressed from {previous} to {next}")]
    StaleObservation { previous: u64, next: u64 },
    #[error("feed sequence overflow")]
    SequenceOverflow,
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Deterministic state machine for oracle feed definitions and submissions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleLedger<D> {
    db: D,
}

impl<D: OracleDB> OracleLedger<D> {
    pub fn new(db: D) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &D {
        &self.db
    }

    pub fn into_inner(self) -> D {
        self.db
    }

    pub async fn nonce(&self, account: &Address) -> Result<u64, OracleError> {
        self.db.nonce(account).await
    }

    pub async fn feed(&self, feed_id: &FeedId) -> Result<Option<FeedDefinition>, OracleError> {
        self.db.feed(feed_id).await
    }

    pub async fn latest_submission(
        &self,
        feed_id: &FeedId,
    ) -> Result<Option<FeedSubmission>, OracleError> {
        self.db.latest_submission(feed_id).await
    }

    pub async fn record(&self, feed_id: &FeedId) -> Result<Option<FeedRecord>, OracleError> {
        let Some(definition) = self.feed(feed_id).await? else {
            return Ok(None);
        };
        Ok(Some(FeedRecord {
            latest: self.latest_submission(feed_id).await?,
            definition,
        }))
    }

    pub async fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), OracleError> {
        tx.verify()?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(OracleError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        match &tx.payload.operation {
            OracleOperation::RegisterFeed { feed_id, metadata } => {
                self.register_feed(tx.account_id.clone(), feed_id.clone(), metadata.clone())
                    .await?
            }
            OracleOperation::Submit {
                feed_id,
                observed_at_ms,
                payload,
            } => {
                self.submit(
                    tx.account_id.clone(),
                    feed_id,
                    *observed_at_ms,
                    payload.clone(),
                )
                .await?
            }
        }

        let next_nonce = expected.checked_add(1).ok_or(OracleError::NonceOverflow)?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        Ok(())
    }

    pub async fn register_feed(
        &mut self,
        owner: Address,
        feed_id: FeedId,
        metadata: FeedPayload,
    ) -> Result<(), OracleError> {
        if self.db.feed(&feed_id).await?.is_some() {
            return Err(OracleError::DuplicateFeed(feed_id));
        }
        self.db.set_feed(&FeedDefinition {
            id: feed_id,
            owner,
            metadata,
        });
        Ok(())
    }

    pub async fn submit(
        &mut self,
        submitter: Address,
        feed_id: &FeedId,
        observed_at_ms: u64,
        payload: FeedPayload,
    ) -> Result<(), OracleError> {
        let definition = self
            .db
            .feed(feed_id)
            .await?
            .ok_or_else(|| OracleError::UnknownFeed(Box::new(feed_id.clone())))?;
        if definition.owner != submitter {
            return Err(OracleError::UnauthorizedPublisher {
                feed_id: Box::new(feed_id.clone()),
                owner: Box::new(definition.owner),
                submitter: Box::new(submitter),
            });
        }

        let sequence = match self.db.latest_submission(feed_id).await? {
            Some(existing) => {
                if observed_at_ms < existing.observed_at_ms {
                    return Err(OracleError::StaleObservation {
                        previous: existing.observed_at_ms,
                        next: observed_at_ms,
                    });
                }
                existing
                    .sequence
                    .checked_add(1)
                    .ok_or(OracleError::SequenceOverflow)?
            }
            None => 0,
        };

        self.db.set_latest_submission(
            feed_id,
            &FeedSubmission {
                observed_at_ms,
                sequence,
                payload,
            },
        );
        Ok(())
    }
}

impl<D: OracleDB + CommitState> OracleLedger<D> {
    /// Flush staged writes, returning the new authenticated state root.
    pub async fn commit(&mut self) -> Result<Digest, OracleError> {
        self.db
            .commit()
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))
    }

    /// The most recently committed authenticated state root.
    pub fn root(&self) -> Digest {
        self.db.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn account(seed: u64) -> PrivateKey {
        PrivateKey::ed25519_from_seed(seed)
    }

    fn feed_id(value: &str) -> FeedId {
        FeedId::new(value).unwrap()
    }

    #[test]
    fn register_and_submit_arbitrary_json_payloads() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut ledger = ledger(context, "oracle-json").await;
            let owner = account(1);
            let owner_address = Address::external(&owner.public_key());
            let feed_id = feed_id("btc/usd");

            let register = Transaction::sign(
                &owner,
                0,
                OracleOperation::RegisterFeed {
                    feed_id: feed_id.clone(),
                    metadata: FeedPayload::json(&json!({
                        "kind": "price",
                        "shape": "spot"
                    }))
                    .unwrap(),
                },
            );
            ledger.apply_transaction(&register).await.unwrap();

            let submit = Transaction::sign(
                &owner,
                1,
                OracleOperation::Submit {
                    feed_id: feed_id.clone(),
                    observed_at_ms: 1_717_171_717_000,
                    payload: FeedPayload::json(&json!({
                        "price": "106500.12",
                        "venue": "nunchi",
                        "confidence": {"ppm": 12},
                        "legs": [{"base": "BTC"}, {"quote": "USD"}]
                    }))
                    .unwrap(),
                },
            );
            ledger.apply_transaction(&submit).await.unwrap();

            let record = ledger.record(&feed_id).await.unwrap().unwrap();
            assert_eq!(record.definition.owner, owner_address);
            assert_eq!(ledger.nonce(&owner_address).await.unwrap(), 2);
            assert_eq!(record.latest.as_ref().unwrap().sequence, 0);

            let decoded: serde_json::Value = record.latest.unwrap().payload.decode_json().unwrap();
            assert_eq!(decoded["price"], "106500.12");
            assert_eq!(decoded["confidence"]["ppm"], 12);
        });
    }

    #[test]
    fn rejects_submission_from_non_owner() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let mut ledger = ledger(context, "oracle-owner").await;
            let owner = account(1);
            let attacker = account(2);
            let feed_id = feed_id("eth/usd");

            ledger
                .apply_transaction(&Transaction::sign(
                    &owner,
                    0,
                    OracleOperation::RegisterFeed {
                        feed_id: feed_id.clone(),
                        metadata: FeedPayload::json(&json!({"kind": "price"})).unwrap(),
                    },
                ))
                .await
                .unwrap();

            let err = ledger
                .apply_transaction(&Transaction::sign(
                    &attacker,
                    0,
                    OracleOperation::Submit {
                        feed_id: feed_id.clone(),
                        observed_at_ms: 10,
                        payload: FeedPayload::json(&json!({"price": "1"})).unwrap(),
                    },
                ))
                .await
                .unwrap_err();

            assert!(matches!(err, OracleError::UnauthorizedPublisher { .. }));
        });
    }

    #[test]
    fn committed_state_survives_reopen() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let owner = account(1);
            let feed_id = feed_id("sol/usd");

            {
                let mut ledger = ledger(context.child("open"), "oracle-reopen").await;
                ledger
                    .apply_transaction(&Transaction::sign(
                        &owner,
                        0,
                        OracleOperation::RegisterFeed {
                            feed_id: feed_id.clone(),
                            metadata: FeedPayload::json(&json!({"kind": "price"})).unwrap(),
                        },
                    ))
                    .await
                    .unwrap();
                ledger
                    .apply_transaction(&Transaction::sign(
                        &owner,
                        1,
                        OracleOperation::Submit {
                            feed_id: feed_id.clone(),
                            observed_at_ms: 42,
                            payload: FeedPayload::json(&json!({
                                "price": "250.01",
                                "source": "oracle"
                            }))
                            .unwrap(),
                        },
                    ))
                    .await
                    .unwrap();
                ledger.commit().await.unwrap();
            }

            let reopened = ledger(context.child("reopen"), "oracle-reopen").await;
            let latest = reopened.latest_submission(&feed_id).await.unwrap().unwrap();
            let decoded: serde_json::Value = latest.payload.decode_json().unwrap();
            assert_eq!(decoded["price"], "250.01");
        });
    }
}
