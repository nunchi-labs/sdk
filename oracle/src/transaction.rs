use crate::{FeedId, FeedPayload, ORACLE_NAMESPACE};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::Operation;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleOperationId {
    RegisterFeed = 0,
    Submit = 1,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid oracle operation id: {0}")]
pub struct InvalidOracleOperationId(u8);

impl TryFrom<u8> for OracleOperationId {
    type Error = InvalidOracleOperationId;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::RegisterFeed),
            1 => Ok(Self::Submit),
            _ => Err(InvalidOracleOperationId(value)),
        }
    }
}

impl Write for OracleOperationId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_u8(*self as u8);
    }
}

impl Read for OracleOperationId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Self::try_from(u8::read(buf)?).map_err(|_| Error::Invalid("oracle operation id", "invalid"))
    }
}

/// A ledger operation authorized by a signed oracle transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleOperation {
    RegisterFeed {
        feed_id: FeedId,
        metadata: FeedPayload,
    },
    Submit {
        feed_id: FeedId,
        observed_at_ms: u64,
        payload: FeedPayload,
    },
}

impl Write for OracleOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::RegisterFeed { feed_id, metadata } => {
                OracleOperationId::RegisterFeed.write(buf);
                feed_id.write(buf);
                metadata.write(buf);
            }
            Self::Submit {
                feed_id,
                observed_at_ms,
                payload,
            } => {
                OracleOperationId::Submit.write(buf);
                feed_id.write(buf);
                observed_at_ms.write(buf);
                payload.write(buf);
            }
        }
    }
}

impl Read for OracleOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match OracleOperationId::read(buf)? {
            OracleOperationId::RegisterFeed => Ok(Self::RegisterFeed {
                feed_id: FeedId::read(buf)?,
                metadata: FeedPayload::read(buf)?,
            }),
            OracleOperationId::Submit => Ok(Self::Submit {
                feed_id: FeedId::read(buf)?,
                observed_at_ms: u64::read(buf)?,
                payload: FeedPayload::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for OracleOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::RegisterFeed { feed_id, metadata } => {
                feed_id.encode_size() + metadata.encode_size()
            }
            Self::Submit {
                feed_id,
                observed_at_ms,
                payload,
            } => feed_id.encode_size() + observed_at_ms.encode_size() + payload.encode_size(),
        }
    }
}

impl Operation for OracleOperation {
    const NAMESPACE: &'static [u8] = ORACLE_NAMESPACE;
}

pub type Transaction = nunchi_common::Transaction<OracleOperation>;
pub type TransactionPayload = nunchi_common::TransactionPayload<OracleOperation>;

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use serde_json::json;

    #[test]
    fn roundtrips_register_operation() {
        let operation = OracleOperation::RegisterFeed {
            feed_id: FeedId::new("btc/usd").unwrap(),
            metadata: FeedPayload::json(&json!({"shape": "price"})).unwrap(),
        };
        let decoded = OracleOperation::decode(operation.encode()).unwrap();
        assert_eq!(decoded, operation);
    }
}
