use crate::{
    IntervalKey, NamespaceId, NamespacePolicy, MAX_PAYLOAD_SIZE, MAX_PROOF_SIZE, ORACLE_NAMESPACE,
};
use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use nunchi_common::{Address, Operation as CommonOperation};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationTag {
    ConfigureNamespace = 0,
    SetWriter = 1,
    AppendRecord = 2,
}

impl TryFrom<u8> for OperationTag {
    type Error = Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::ConfigureNamespace),
            1 => Ok(Self::SetWriter),
            2 => Ok(Self::AppendRecord),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// Oracle state-machine operation carried by a signed Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleOperation {
    /// Create or update generic policy for a namespace.
    ConfigureNamespace {
        /// Namespace whose policy is being configured.
        namespace: NamespaceId,
        /// Namespace policy to store.
        policy: NamespacePolicy,
    },
    /// Enable or disable a writer for one namespace.
    SetWriter {
        /// Namespace whose writer policy is changing.
        namespace: NamespaceId,
        /// Account being enabled or disabled.
        writer: Address,
        /// Whether the writer may append records.
        enabled: bool,
    },
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
            Self::ConfigureNamespace { namespace, policy } => {
                (OperationTag::ConfigureNamespace as u8).write(buf);
                namespace.write(buf);
                policy.write(buf);
            }
            Self::SetWriter {
                namespace,
                writer,
                enabled,
            } => {
                (OperationTag::SetWriter as u8).write(buf);
                namespace.write(buf);
                writer.write(buf);
                enabled.write(buf);
            }
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
            OperationTag::ConfigureNamespace => Ok(Self::ConfigureNamespace {
                namespace: NamespaceId::read(buf)?,
                policy: NamespacePolicy::read(buf)?,
            }),
            OperationTag::SetWriter => Ok(Self::SetWriter {
                namespace: NamespaceId::read(buf)?,
                writer: Address::read(buf)?,
                enabled: bool::read(buf)?,
            }),
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
            Self::ConfigureNamespace { namespace, policy } => {
                namespace.encode_size() + policy.encode_size()
            }
            Self::SetWriter {
                namespace,
                writer,
                enabled,
            } => namespace.encode_size() + writer.encode_size() + enabled.encode_size(),
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
