use commonware_codec::{EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_common::Address;

/// Maximum payload bytes accepted in one oracle record.
pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024;
/// Maximum proof bytes accepted in one oracle record.
pub const MAX_PROOF_SIZE: usize = 16 * 1024;
/// Maximum record ids stored in one interval-index page.
///
/// Interval indexes are paged: a single `(namespace|writer, interval)` bucket may
/// contain an unbounded number of records across multiple pages of this size.
pub const INDEX_PAGE_SIZE: usize = 1024;
/// Backward-compatible alias for [`INDEX_PAGE_SIZE`].
///
/// Historically this capped total records per interval bucket. Indexes are now
/// paged, so this value is only the per-page capacity.
#[doc(alias = "INDEX_PAGE_SIZE")]
pub const MAX_RECORDS_PER_BUCKET: usize = INDEX_PAGE_SIZE;
/// Maximum interval buckets a helper query will read in one call.
///
/// Sized to allow month-scale day buckets and day-scale minute buckets without
/// forcing consumers to shard interval keys.
pub const MAX_QUERY_INTERVALS: u64 = 100_000;

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

/// Metadata for a paged interval index.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IntervalIndexMeta {
    /// Number of pages currently allocated for this index.
    pub page_count: u32,
}

impl Write for IntervalIndexMeta {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.page_count.write(buf);
    }
}

impl Read for IntervalIndexMeta {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            page_count: u32::read(buf)?,
        })
    }
}

impl FixedSize for IntervalIndexMeta {
    const SIZE: usize = u32::SIZE;
}

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
