//! Signed counter operations.

use crate::COUNTER_NAMESPACE;
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::Operation;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterOperationId {
    Increment = 0,
    Reset = 1,
}

impl Write for CounterOperationId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_u8(*self as u8);
    }
}

impl Read for CounterOperationId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Increment),
            1 => Ok(Self::Reset),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CounterOperation {
    /// unpermissioned.
    Increment,
    /// requires [`crate::RESETTER_ROLE`].
    Reset { value: u64 },
}

impl Write for CounterOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Increment => CounterOperationId::Increment.write(buf),
            Self::Reset { value } => {
                CounterOperationId::Reset.write(buf);
                value.write(buf);
            }
        }
    }
}

impl Read for CounterOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match CounterOperationId::read(buf)? {
            CounterOperationId::Increment => Ok(Self::Increment),
            CounterOperationId::Reset => Ok(Self::Reset {
                value: u64::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for CounterOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Increment => 0,
            Self::Reset { value } => value.encode_size(),
        }
    }
}

impl Operation for CounterOperation {
    const NAMESPACE: &'static [u8] = COUNTER_NAMESPACE;
}

pub type TransactionPayload = nunchi_common::TransactionPayload<CounterOperation>;
pub type Transaction = nunchi_common::Transaction<CounterOperation>;
