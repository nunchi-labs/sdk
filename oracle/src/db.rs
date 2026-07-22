//! Persistence layer for the oracle module.

use crate::{
    IntervalIndexMeta, IntervalKey, NamespaceId, OracleError, OracleRecord, RecordId,
    INDEX_PAGE_SIZE, ORACLE_NAMESPACE,
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
    Record = 3,
    NamespaceIntervalMeta = 4,
    WriterIntervalMeta = 5,
    NamespaceIntervalPage = 6,
    WriterIntervalPage = 7,
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

fn decode_page(bytes: &[u8]) -> Result<Vec<RecordId>, OracleError> {
    let mut buf = bytes;
    Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=INDEX_PAGE_SIZE), ()))
        .map_err(|err| OracleError::Storage(err.to_string()))
}

fn namespace_meta_key(namespace: &NamespaceId, interval: &IntervalKey) -> Digest {
    let mut logical = encoded(namespace);
    logical.extend_from_slice(interval.encode().as_ref());
    NS.key(Table::NamespaceIntervalMeta, &logical)
}

fn writer_meta_key(writer: &Address, interval: &IntervalKey) -> Digest {
    let mut logical = writer.encode().as_ref().to_vec();
    logical.extend_from_slice(interval.encode().as_ref());
    NS.key(Table::WriterIntervalMeta, &logical)
}

fn namespace_page_key(namespace: &NamespaceId, interval: &IntervalKey, page: u32) -> Digest {
    let mut logical = encoded(namespace);
    logical.extend_from_slice(interval.encode().as_ref());
    logical.extend_from_slice(page.encode().as_ref());
    NS.key(Table::NamespaceIntervalPage, &logical)
}

fn writer_page_key(writer: &Address, interval: &IntervalKey, page: u32) -> Digest {
    let mut logical = writer.encode().as_ref().to_vec();
    logical.extend_from_slice(interval.encode().as_ref());
    logical.extend_from_slice(page.encode().as_ref());
    NS.key(Table::WriterIntervalPage, &logical)
}

fn append_into_pages(
    meta: IntervalIndexMeta,
    last_page: Vec<RecordId>,
    id: RecordId,
) -> Result<(IntervalIndexMeta, u32, Vec<RecordId>), OracleError> {
    if meta.page_count == 0 {
        return Ok((IntervalIndexMeta { page_count: 1 }, 0, vec![id]));
    }

    let page_index = meta.page_count - 1;
    if last_page.len() < INDEX_PAGE_SIZE {
        let mut page = last_page;
        page.push(id);
        return Ok((meta, page_index, page));
    }

    let page_count = meta
        .page_count
        .checked_add(1)
        .ok_or(OracleError::IndexFull)?;
    Ok((IntervalIndexMeta { page_count }, page_count - 1, vec![id]))
}

fn extend_within_limit(
    records: &mut Vec<RecordId>,
    page: Vec<RecordId>,
    max_records: usize,
) -> Result<(), OracleError> {
    if records.len().saturating_add(page.len()) > max_records {
        return Err(OracleError::InvalidQuery(
            "query result exceeds MAX_QUERY_RECORDS",
        ));
    }
    records.extend(page);
    Ok(())
}

#[async_trait]
pub trait OracleDB {
    async fn nonce(&self, account: &Address) -> Result<u64, OracleError>;

    fn set_nonce(&mut self, account: &Address, nonce: u64);

    async fn record(&self, id: &RecordId) -> Result<Option<OracleRecord>, OracleError>;

    fn set_record(&mut self, record: &OracleRecord);

    /// Load record ids indexed under `(namespace, interval)`, across pages.
    ///
    /// Fails if more than `max_records` ids would be returned.
    async fn namespace_index(
        &self,
        namespace: &NamespaceId,
        interval: &IntervalKey,
        max_records: usize,
    ) -> Result<Vec<RecordId>, OracleError>;

    /// Append one record id to the paged `(namespace, interval)` index.
    ///
    /// Always rewrites the last page. Rewrites index meta only when a new page
    /// is allocated (including the first page).
    async fn append_namespace_index(
        &mut self,
        namespace: &NamespaceId,
        interval: &IntervalKey,
        id: RecordId,
    ) -> Result<(), OracleError>;

    /// Load record ids indexed under `(writer, interval)`, across pages.
    ///
    /// Fails if more than `max_records` ids would be returned.
    async fn writer_index(
        &self,
        writer: &Address,
        interval: &IntervalKey,
        max_records: usize,
    ) -> Result<Vec<RecordId>, OracleError>;

    /// Append one record id to the paged `(writer, interval)` index.
    ///
    /// Always rewrites the last page. Rewrites index meta only when a new page
    /// is allocated (including the first page).
    async fn append_writer_index(
        &mut self,
        writer: &Address,
        interval: &IntervalKey,
        id: RecordId,
    ) -> Result<(), OracleError>;
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
        max_records: usize,
    ) -> Result<Vec<RecordId>, OracleError> {
        let meta = match StateStore::get(self, &namespace_meta_key(namespace, interval))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<IntervalIndexMeta>(&bytes)?,
            None => return Ok(Vec::new()),
        };

        let mut records = Vec::new();
        for page in 0..meta.page_count {
            match StateStore::get(self, &namespace_page_key(namespace, interval, page))
                .await
                .map_err(|err| OracleError::Storage(err.to_string()))?
            {
                Some(bytes) => {
                    extend_within_limit(&mut records, decode_page(&bytes)?, max_records)?
                }
                None => return Err(OracleError::MissingRecord),
            }
        }
        Ok(records)
    }

    async fn append_namespace_index(
        &mut self,
        namespace: &NamespaceId,
        interval: &IntervalKey,
        id: RecordId,
    ) -> Result<(), OracleError> {
        let meta = match StateStore::get(self, &namespace_meta_key(namespace, interval))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<IntervalIndexMeta>(&bytes)?,
            None => IntervalIndexMeta::default(),
        };
        let last_page = if meta.page_count == 0 {
            Vec::new()
        } else {
            match StateStore::get(
                self,
                &namespace_page_key(namespace, interval, meta.page_count - 1),
            )
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
            {
                Some(bytes) => decode_page(&bytes)?,
                None => return Err(OracleError::MissingRecord),
            }
        };

        let (next_meta, page_index, page) = append_into_pages(meta, last_page, id)?;
        StateStore::set(
            self,
            namespace_page_key(namespace, interval, page_index),
            encoded(&page),
        );
        if next_meta != meta {
            StateStore::set(
                self,
                namespace_meta_key(namespace, interval),
                encoded(&next_meta),
            );
        }
        Ok(())
    }

    async fn writer_index(
        &self,
        writer: &Address,
        interval: &IntervalKey,
        max_records: usize,
    ) -> Result<Vec<RecordId>, OracleError> {
        let meta = match StateStore::get(self, &writer_meta_key(writer, interval))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<IntervalIndexMeta>(&bytes)?,
            None => return Ok(Vec::new()),
        };

        let mut records = Vec::new();
        for page in 0..meta.page_count {
            match StateStore::get(self, &writer_page_key(writer, interval, page))
                .await
                .map_err(|err| OracleError::Storage(err.to_string()))?
            {
                Some(bytes) => {
                    extend_within_limit(&mut records, decode_page(&bytes)?, max_records)?
                }
                None => return Err(OracleError::MissingRecord),
            }
        }
        Ok(records)
    }

    async fn append_writer_index(
        &mut self,
        writer: &Address,
        interval: &IntervalKey,
        id: RecordId,
    ) -> Result<(), OracleError> {
        let meta = match StateStore::get(self, &writer_meta_key(writer, interval))
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<IntervalIndexMeta>(&bytes)?,
            None => IntervalIndexMeta::default(),
        };
        let last_page = if meta.page_count == 0 {
            Vec::new()
        } else {
            match StateStore::get(
                self,
                &writer_page_key(writer, interval, meta.page_count - 1),
            )
            .await
            .map_err(|err| OracleError::Storage(err.to_string()))?
            {
                Some(bytes) => decode_page(&bytes)?,
                None => return Err(OracleError::MissingRecord),
            }
        };

        let (next_meta, page_index, page) = append_into_pages(meta, last_page, id)?;
        StateStore::set(
            self,
            writer_page_key(writer, interval, page_index),
            encoded(&page),
        );
        if next_meta != meta {
            StateStore::set(self, writer_meta_key(writer, interval), encoded(&next_meta));
        }
        Ok(())
    }
}
