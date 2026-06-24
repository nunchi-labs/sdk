use crate::{
    IntervalKey, NamespaceId, NamespacePolicy, OracleDB, OracleOperation, OracleRecord, RecordId,
    Transaction, MAX_PAYLOAD_SIZE, MAX_PROOF_SIZE, MAX_QUERY_INTERVALS, MAX_RECORDS_PER_BUCKET,
};
use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256};
use nunchi_common::{Address, RuntimeContext};
use nunchi_crypto::SignatureError;
use thiserror::Error;

/// Deterministic oracle state-machine errors.
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
    #[error("oracle namespace is not configured")]
    NamespaceNotConfigured,
    #[error("invalid oracle namespace policy: {0}")]
    InvalidNamespacePolicy(&'static str),
    #[error("invalid oracle genesis: {0}")]
    InvalidGenesis(String),
    #[error("unauthorized oracle operation")]
    Unauthorized,
    #[error("oracle payload is too large")]
    PayloadTooLarge,
    #[error("oracle proof is too large")]
    ProofTooLarge,
    #[error("oracle record index is full")]
    IndexFull,
    #[error("invalid oracle query: {0}")]
    InvalidQuery(&'static str),
    #[error("oracle record index references a missing record")]
    MissingRecord,
    #[error("state storage error: {0}")]
    Storage(String),
}

/// Deterministic oracle ledger over a caller-provided database.
///
/// The ledger validates signed oracle transactions, mutates authenticated state through
/// [`OracleDB`], and stores opaque interval-addressed data. It does not decode payloads,
/// normalize values, derive market state, or decide whether data is fresh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleLedger<D> {
    db: D,
}

impl<D: OracleDB> OracleLedger<D> {
    /// Wrap a database backend as an oracle ledger.
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// Borrow the underlying database.
    pub fn db(&self) -> &D {
        &self.db
    }

    pub(crate) fn db_mut(&mut self) -> &mut D {
        &mut self.db
    }

    /// Consume the ledger, returning the underlying database.
    pub fn into_inner(self) -> D {
        self.db
    }

    /// Validate and apply a signed oracle transaction.
    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
        context: RuntimeContext,
    ) -> Result<(), OracleError> {
        tx.verify()?;

        let expected = self.db.nonce(&tx.account_id).await?;
        if tx.payload.nonce != expected {
            return Err(OracleError::NonceMismatch {
                account: Box::new(tx.account_id.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(
            &tx.account_id,
            tx.payload.nonce,
            &tx.payload.operation,
            context,
        )
        .await?;
        let next_nonce = expected.checked_add(1).ok_or(OracleError::NonceOverflow)?;
        self.db.set_nonce(&tx.account_id, next_nonce);
        Ok(())
    }

    /// Load namespace policy.
    pub async fn namespace(
        &self,
        namespace: &NamespaceId,
    ) -> Result<Option<NamespacePolicy>, OracleError> {
        self.db.namespace(namespace).await
    }

    /// Load writer policy for one namespace.
    pub async fn writer(
        &self,
        namespace: &NamespaceId,
        writer: &Address,
    ) -> Result<Option<bool>, OracleError> {
        self.db.writer(namespace, writer).await
    }

    /// Load an oracle record by id.
    pub async fn record(&self, id: &RecordId) -> Result<Option<OracleRecord>, OracleError> {
        self.db.record(id).await
    }

    /// Query records by namespace over an inclusive interval range.
    pub async fn records_by_namespace(
        &self,
        namespace: &NamespaceId,
        start: IntervalKey,
        end: IntervalKey,
    ) -> Result<Vec<OracleRecord>, OracleError> {
        validate_interval_range(start, end)?;

        let mut records = Vec::new();
        for bucket in start.bucket..=end.bucket {
            let index = self
                .db
                .namespace_index(namespace, &IntervalKey::new(bucket))
                .await?;
            self.load_records(index, &mut records).await?;
        }
        Ok(records)
    }

    /// Query records by writer over an inclusive interval range.
    pub async fn records_by_writer(
        &self,
        writer: &Address,
        start: IntervalKey,
        end: IntervalKey,
    ) -> Result<Vec<OracleRecord>, OracleError> {
        validate_interval_range(start, end)?;

        let mut records = Vec::new();
        for bucket in start.bucket..=end.bucket {
            let index = self
                .db
                .writer_index(writer, &IntervalKey::new(bucket))
                .await?;
            self.load_records(index, &mut records).await?;
        }
        Ok(records)
    }

    async fn apply_operation(
        &mut self,
        signer: &Address,
        nonce: u64,
        operation: &OracleOperation,
        context: RuntimeContext,
    ) -> Result<(), OracleError> {
        match operation {
            OracleOperation::ConfigureNamespace { namespace, policy } => {
                self.configure_namespace(signer, namespace, policy.clone())
                    .await
            }
            OracleOperation::SetWriter {
                namespace,
                writer,
                enabled,
            } => self.set_writer(signer, namespace, writer, *enabled).await,
            OracleOperation::AppendRecord {
                namespace,
                interval,
                payload,
                proof,
            } => {
                self.append_record(
                    signer,
                    nonce,
                    namespace,
                    *interval,
                    payload.clone(),
                    proof.clone(),
                    context,
                )
                .await
            }
        }
    }

    async fn configure_namespace(
        &mut self,
        signer: &Address,
        namespace: &NamespaceId,
        policy: NamespacePolicy,
    ) -> Result<(), OracleError> {
        validate_policy(&policy)?;
        match self.db.namespace(namespace).await? {
            Some(existing) if existing.admin != *signer => return Err(OracleError::Unauthorized),
            None if policy.admin != *signer => return Err(OracleError::Unauthorized),
            _ => {}
        }

        self.db.set_namespace(namespace, &policy);
        Ok(())
    }

    async fn set_writer(
        &mut self,
        signer: &Address,
        namespace: &NamespaceId,
        writer: &Address,
        enabled: bool,
    ) -> Result<(), OracleError> {
        let namespace_policy = self
            .db
            .namespace(namespace)
            .await?
            .ok_or(OracleError::NamespaceNotConfigured)?;
        if namespace_policy.admin != *signer {
            return Err(OracleError::Unauthorized);
        }
        self.db.set_writer(namespace, writer, enabled);
        Ok(())
    }

    async fn append_record(
        &mut self,
        signer: &Address,
        nonce: u64,
        namespace: &NamespaceId,
        interval: IntervalKey,
        payload: Vec<u8>,
        proof: Option<Vec<u8>>,
        context: RuntimeContext,
    ) -> Result<(), OracleError> {
        let policy = self
            .db
            .namespace(namespace)
            .await?
            .ok_or(OracleError::NamespaceNotConfigured)?;
        if !self
            .db
            .writer(namespace, signer)
            .await?
            .is_some_and(|enabled| enabled)
        {
            return Err(OracleError::Unauthorized);
        }
        if payload.len() > policy.max_payload_size as usize || payload.len() > MAX_PAYLOAD_SIZE {
            return Err(OracleError::PayloadTooLarge);
        }
        if proof
            .as_ref()
            .is_some_and(|proof| proof.len() > MAX_PROOF_SIZE)
        {
            return Err(OracleError::ProofTooLarge);
        }

        let mut namespace_records = self.db.namespace_index(namespace, &interval).await?;
        let mut writer_records = self.db.writer_index(signer, &interval).await?;
        if namespace_records.len() == MAX_RECORDS_PER_BUCKET
            || writer_records.len() == MAX_RECORDS_PER_BUCKET
        {
            return Err(OracleError::IndexFull);
        }

        let id = record_id(signer, nonce, namespace, &interval);
        let record = OracleRecord {
            id,
            writer: signer.clone(),
            namespace: *namespace,
            interval,
            payload,
            proof,
            written_at_height: context.height,
            written_at_ms: context.timestamp_ms,
        };
        self.db.set_record(&record);

        namespace_records.push(id);
        self.db
            .set_namespace_index(namespace, &interval, &namespace_records);

        writer_records.push(id);
        self.db.set_writer_index(signer, &interval, &writer_records);
        Ok(())
    }

    async fn load_records(
        &self,
        ids: Vec<RecordId>,
        records: &mut Vec<OracleRecord>,
    ) -> Result<(), OracleError> {
        for id in ids {
            let record = self
                .db
                .record(&id)
                .await?
                .ok_or(OracleError::MissingRecord)?;
            records.push(record);
        }
        Ok(())
    }
}

pub(crate) fn validate_policy(policy: &NamespacePolicy) -> Result<(), OracleError> {
    if policy.max_payload_size == 0 {
        return Err(OracleError::InvalidNamespacePolicy(
            "maximum payload size is zero",
        ));
    }
    if policy.max_payload_size as usize > MAX_PAYLOAD_SIZE {
        return Err(OracleError::InvalidNamespacePolicy(
            "maximum payload size exceeds module limit",
        ));
    }
    Ok(())
}

fn validate_interval_range(start: IntervalKey, end: IntervalKey) -> Result<(), OracleError> {
    if end.bucket < start.bucket {
        return Err(OracleError::InvalidQuery("inverted interval range"));
    }
    let interval_count = end
        .bucket
        .checked_sub(start.bucket)
        .and_then(|count| count.checked_add(1))
        .ok_or(OracleError::InvalidQuery("interval range overflow"))?;
    if interval_count > MAX_QUERY_INTERVALS {
        return Err(OracleError::InvalidQuery("interval range is too large"));
    }
    Ok(())
}

fn record_id(
    writer: &Address,
    nonce: u64,
    namespace: &NamespaceId,
    interval: &IntervalKey,
) -> RecordId {
    let mut bytes = writer.encode().as_ref().to_vec();
    bytes.extend_from_slice(nonce.encode().as_ref());
    bytes.extend_from_slice(namespace.encode().as_ref());
    bytes.extend_from_slice(interval.encode().as_ref());
    RecordId(Sha256::hash(&bytes))
}
