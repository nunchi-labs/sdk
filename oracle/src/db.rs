use crate::{FeedDefinition, FeedId, FeedSubmission, OracleError, ORACLE_NAMESPACE};
use commonware_codec::{Encode, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{state_db::Namespace, state_db::StateStore, Address};

const NS: Namespace = Namespace::new(ORACLE_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    AccountNonce = 0,
    FeedDefinition = 1,
    LatestSubmission = 2,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, OracleError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| OracleError::Storage(err.to_string()))
}

fn nonce_key(account: &Address) -> Digest {
    NS.key(Table::AccountNonce, account.encode().as_ref())
}

fn feed_definition_key(feed_id: &FeedId) -> Digest {
    NS.key(Table::FeedDefinition, feed_id.encode().as_ref())
}

fn latest_submission_key(feed_id: &FeedId) -> Digest {
    NS.key(Table::LatestSubmission, feed_id.encode().as_ref())
}

pub trait OracleDB {
    fn nonce(
        &self,
        account: &Address,
    ) -> impl std::future::Future<Output = Result<u64, OracleError>> + Send;
    fn set_nonce(&mut self, account: &Address, nonce: u64);

    fn feed(
        &self,
        feed_id: &FeedId,
    ) -> impl std::future::Future<Output = Result<Option<FeedDefinition>, OracleError>> + Send;
    fn set_feed(&mut self, definition: &FeedDefinition);

    fn latest_submission(
        &self,
        feed_id: &FeedId,
    ) -> impl std::future::Future<Output = Result<Option<FeedSubmission>, OracleError>> + Send;
    fn set_latest_submission(&mut self, feed_id: &FeedId, submission: &FeedSubmission);
}

impl<S: StateStore + Sync> OracleDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, OracleError> {
        match StateStore::get(self, &nonce_key(account))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<u64>(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        StateStore::set(self, nonce_key(account), encoded(&nonce));
    }

    async fn feed(&self, feed_id: &FeedId) -> Result<Option<FeedDefinition>, OracleError> {
        match StateStore::get(self, &feed_definition_key(feed_id))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<FeedDefinition>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_feed(&mut self, definition: &FeedDefinition) {
        StateStore::set(
            self,
            feed_definition_key(&definition.id),
            encoded(definition),
        );
    }

    async fn latest_submission(
        &self,
        feed_id: &FeedId,
    ) -> Result<Option<FeedSubmission>, OracleError> {
        match StateStore::get(self, &latest_submission_key(feed_id))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<FeedSubmission>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_latest_submission(&mut self, feed_id: &FeedId, submission: &FeedSubmission) {
        StateStore::set(self, latest_submission_key(feed_id), encoded(submission));
    }
}
