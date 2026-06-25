use crate::{IntervalKey, NamespaceId, MAX_PAYLOAD_SIZE, MAX_PROOF_SIZE, ORACLE_NAMESPACE};
use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use nunchi_common::Operation as CommonOperation;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationTag {
    AppendRecord = 0,
}

impl TryFrom<u8> for OperationTag {
    type Error = Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::AppendRecord),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// Oracle state-machine operation carried by a signed Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleOperation {
    /// Append opaque data to one namespace and interval.
    AppendRecord {
        /// Namespace under which the payload is stored.
        namespace: NamespaceId,
        /// Consumer-defined interval bucket.
        interval: IntervalKey,
        /// Opaque payload bytes. The oracle never decodes this field.
        payload: Vec<u8>,
        /// Optional opaque proof bytes. The oracle never decodes this field.
        proof: Option<Vec<u8>>,
    },
}

impl Write for OracleOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::AppendRecord {
                namespace,
                interval,
                payload,
                proof,
            } => {
                (OperationTag::AppendRecord as u8).write(buf);
                namespace.write(buf);
                interval.write(buf);
                payload.write(buf);
                proof.write(buf);
            }
        }
    }
}

impl Read for OracleOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match OperationTag::try_from(u8::read(buf)?)? {
            OperationTag::AppendRecord => Ok(Self::AppendRecord {
                namespace: NamespaceId::read(buf)?,
                interval: IntervalKey::read(buf)?,
                payload: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_PAYLOAD_SIZE), ()))?,
                proof: Option::<Vec<u8>>::read_cfg(buf, &(RangeCfg::new(0..=MAX_PROOF_SIZE), ()))?,
            }),
        }
    }
}

impl EncodeSize for OracleOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::AppendRecord {
                namespace,
                interval,
                payload,
                proof,
            } => {
                namespace.encode_size()
                    + interval.encode_size()
                    + payload.encode_size()
                    + proof.encode_size()
            }
        }
    }
}

impl CommonOperation for OracleOperation {
    const NAMESPACE: &'static [u8] = ORACLE_NAMESPACE;
}

/// Signed oracle transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<OracleOperation>;
/// Signed oracle transaction.
pub type Transaction = nunchi_common::Transaction<OracleOperation>;
