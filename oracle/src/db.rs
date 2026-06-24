//! Persistence layer for the oracle module.

use crate::{
    IntervalKey, NamespaceId, NamespacePolicy, OracleError, OracleRecord, RecordId,
    MAX_RECORDS_PER_BUCKET, ORACLE_NAMESPACE,
};
use async_trait::async_trait;
use commonware_codec::{Encode, RangeCfg, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Namespace, StateStore};

const NS: Namespace = Namespace::new(ORACLE_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Nonce = 0,
    Namespace = 1,
    Writer = 2,
    Record = 3,
    NamespaceInterval = 4,
    WriterInterval = 5,
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

fn writer_key(namespace: &NamespaceId, writer: &Address) -> Digest {
    let mut logical = encoded(namespace);
    logical.extend_from_slice(writer.encode().as_ref());
    NS.key(Table::Writer, &logical)
}

fn namespace_interval_key(namespace: &NamespaceId, interval: &IntervalKey) -> Digest {
    let mut logical = encoded(namespace);
    logical.extend_from_slice(interval.encode().as_ref());
    NS.key(Table::NamespaceInterval, &logical)
}

fn writer_interval_key(writer: &Address, interval: &IntervalKey) -> Digest {
    let mut logical = writer.encode().as_ref().to_vec();
    logical.extend_from_slice(interval.encode().as_ref());
    NS.key(Table::WriterInterval, &logical)
}

#[async_trait]
pub trait OracleDB {
    async fn nonce(&self, account: &Address) -> Result<u64, OracleError>;

    fn set_nonce(&mut self, account: &Address, nonce: u64);

    async fn namespace(
        &self,
        namespace: &NamespaceId,
    ) -> Result<Option<NamespacePolicy>, OracleError>;

    fn set_namespace(&mut self, namespace: &NamespaceId, policy: &NamespacePolicy);

    async fn writer(
        &self,
        namespace: &NamespaceId,
        writer: &Address,
    ) -> Result<Option<bool>, OracleError>;

    fn set_writer(&mut self, namespace: &NamespaceId, writer: &Address, enabled: bool);

    async fn record(&self, id: &RecordId) -> Result<Option<OracleRecord>, OracleError>;

    fn set_record(&mut self, record: &OracleRecord);

    async fn namespace_index(
        &self,
        namespace: &NamespaceId,
        interval: &IntervalKey,
    ) -> Result<Vec<RecordId>, OracleError>;

    fn set_namespace_index(
        &mut self,
        namespace: &NamespaceId,
        interval: &IntervalKey,
        records: &[RecordId],
    );

    async fn writer_index(
        &self,
        writer: &Address,
        interval: &IntervalKey,
    ) -> Result<Vec<RecordId>, OracleError>;

    fn set_writer_index(&mut self, writer: &Address, interval: &IntervalKey, records: &[RecordId]);
}

#[async_trait]
impl<S: StateStore + Send + Sync> OracleDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, OracleError> {
        let key = NS.key(Table::Nonce, account.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        let key = NS.key(Table::Nonce, account.encode().as_ref());
        StateStore::set(self, key, encoded(&nonce));
    }

    async fn namespace(
        &self,
        namespace: &NamespaceId,
    ) -> Result<Option<NamespacePolicy>, OracleError> {
        let key = NS.key(Table::Namespace, namespace.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_namespace(&mut self, namespace: &NamespaceId, policy: &NamespacePolicy) {
        let key = NS.key(Table::Namespace, namespace.encode().as_ref());
        StateStore::set(self, key, encoded(policy));
    }

    async fn writer(
        &self,
        namespace: &NamespaceId,
        writer: &Address,
    ) -> Result<Option<bool>, OracleError> {
        match StateStore::get(self, &writer_key(namespace, writer))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_writer(&mut self, namespace: &NamespaceId, writer: &Address, enabled: bool) {
        StateStore::set(self, writer_key(namespace, writer), encoded(&enabled));
    }

    async fn record(&self, id: &RecordId) -> Result<Option<OracleRecord>, OracleError> {
        let key = NS.key(Table::Record, id.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_record(&mut self, record: &OracleRecord) {
        let key = NS.key(Table::Record, record.id.encode().as_ref());
        StateStore::set(self, key, encoded(record));
    }

    async fn namespace_index(
        &self,
        namespace: &NamespaceId,
        interval: &IntervalKey,
    ) -> Result<Vec<RecordId>, OracleError> {
        match StateStore::get(self, &namespace_interval_key(namespace, interval))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_RECORDS_PER_BUCKET), ()))
                    .map_err(|err| OracleError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_namespace_index(
        &mut self,
        namespace: &NamespaceId,
        interval: &IntervalKey,
        records: &[RecordId],
    ) {
        StateStore::set(
            self,
            namespace_interval_key(namespace, interval),
            encoded(&records.to_vec()),
        );
    }

    async fn writer_index(
        &self,
        writer: &Address,
        interval: &IntervalKey,
    ) -> Result<Vec<RecordId>, OracleError> {
        match StateStore::get(self, &writer_interval_key(writer, interval))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_RECORDS_PER_BUCKET), ()))
                    .map_err(|err| OracleError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_writer_index(&mut self, writer: &Address, interval: &IntervalKey, records: &[RecordId]) {
        StateStore::set(
            self,
            writer_interval_key(writer, interval),
            encoded(&records.to_vec()),
        );
    }
}
