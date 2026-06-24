use commonware_codec::{EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_common::Address;

/// Maximum payload bytes accepted in one oracle record.
pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024;
/// Maximum proof bytes accepted in one oracle record.
pub const MAX_PROOF_SIZE: usize = 16 * 1024;
/// Maximum records stored in one explicit query index bucket.
pub const MAX_RECORDS_PER_BUCKET: usize = 1024;
/// Maximum interval buckets a helper query will read in one call.
pub const MAX_QUERY_INTERVALS: u64 = 1024;

/// Opaque namespace chosen by writers and consuming modules.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NamespaceId(pub Digest);

/// Opaque interval key chosen by writers and consuming modules.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntervalKey {
    /// Consumer-defined interval bucket.
    pub bucket: u64,
}

impl IntervalKey {
    /// Construct an interval key.
    pub const fn new(bucket: u64) -> Self {
        Self { bucket }
    }
}

/// Stable identifier for an appended oracle record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordId(pub Digest);

macro_rules! digest_id_codec {
    ($ty:ty) => {
        impl Write for $ty {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                self.0.write(buf);
            }
        }

        impl Read for $ty {
            type Cfg = ();

            fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
                Ok(Self(Digest::read(buf)?))
            }
        }

        impl FixedSize for $ty {
            const SIZE: usize = Digest::SIZE;
        }
    };
}

digest_id_codec!(NamespaceId);
digest_id_codec!(RecordId);

impl Write for IntervalKey {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.bucket.write(buf);
    }
}

impl Read for IntervalKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            bucket: u64::read(buf)?,
        })
    }
}

impl FixedSize for IntervalKey {
    const SIZE: usize = u64::SIZE;
}

/// Generic namespace-level oracle policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespacePolicy {
    /// Account allowed to configure this namespace and writer set.
    pub admin: Address,
    /// Maximum payload bytes accepted for records in this namespace.
    pub max_payload_size: u32,
}

impl Write for NamespacePolicy {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.admin.write(buf);
        self.max_payload_size.write(buf);
    }
}

impl Read for NamespacePolicy {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            admin: Address::read(buf)?,
            max_payload_size: u32::read(buf)?,
        })
    }
}

impl EncodeSize for NamespacePolicy {
    fn encode_size(&self) -> usize {
        self.admin.encode_size() + self.max_payload_size.encode_size()
    }
}

/// Opaque interval-addressed data stored by the oracle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleRecord {
    /// Record id derived by the oracle from transaction metadata.
    pub id: RecordId,
    /// Account that signed the append transaction.
    pub writer: Address,
    /// Namespace under which the payload was written.
    pub namespace: NamespaceId,
    /// Consumer-defined interval bucket.
    pub interval: IntervalKey,
    /// Opaque payload bytes. The oracle never decodes this field.
    pub payload: Vec<u8>,
    /// Optional opaque proof bytes. The oracle never decodes this field.
    pub proof: Option<Vec<u8>>,
    /// Consensus height at which the record was accepted.
    pub written_at_height: u64,
    /// Consensus timestamp at which the record was accepted.
    pub written_at_ms: u64,
}

impl Write for OracleRecord {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.writer.write(buf);
        self.namespace.write(buf);
        self.interval.write(buf);
        self.payload.write(buf);
        self.proof.write(buf);
        self.written_at_height.write(buf);
        self.written_at_ms.write(buf);
    }
}

impl Read for OracleRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: RecordId::read(buf)?,
            writer: Address::read(buf)?,
            namespace: NamespaceId::read(buf)?,
            interval: IntervalKey::read(buf)?,
            payload: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_PAYLOAD_SIZE), ()))?,
            proof: Option::<Vec<u8>>::read_cfg(buf, &(RangeCfg::new(0..=MAX_PROOF_SIZE), ()))?,
            written_at_height: u64::read(buf)?,
            written_at_ms: u64::read(buf)?,
        })
    }
}

impl EncodeSize for OracleRecord {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.writer.encode_size()
            + self.namespace.encode_size()
            + self.interval.encode_size()
            + self.payload.encode_size()
            + self.proof.encode_size()
            + self.written_at_height.encode_size()
            + self.written_at_ms.encode_size()
    }
}
