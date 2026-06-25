use crate::CUSTOM_NAMESPACE;
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::Operation;

const OP_SET_VALUE: u8 = 0;
const OP_CLEAR_VALUE: u8 = 1;

/// Custom state-machine operation carried by a signed Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustomOperation {
    /// Set the caller's custom value.
    SetValue { value: u64 },
    /// Clear the caller's custom value.
    ClearValue,
}

impl Write for CustomOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::SetValue { value } => {
                OP_SET_VALUE.write(buf);
                value.write(buf);
            }
            Self::ClearValue => {
                OP_CLEAR_VALUE.write(buf);
            }
        }
    }
}

impl Read for CustomOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            OP_SET_VALUE => Ok(Self::SetValue {
                value: u64::read(buf)?,
            }),
            OP_CLEAR_VALUE => Ok(Self::ClearValue),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for CustomOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::SetValue { value } => value.encode_size(),
            Self::ClearValue => 0,
        }
    }
}

impl Operation for CustomOperation {
    const NAMESPACE: &'static [u8] = CUSTOM_NAMESPACE;
}

/// Signed custom transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<CustomOperation>;
/// Signed custom transaction.
pub type Transaction = nunchi_common::Transaction<CustomOperation>;
