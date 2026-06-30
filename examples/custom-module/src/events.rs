use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::{Address, Event};

pub const VALUE_SET_EVENT: &[u8] = b"custom.value_set.v1";
pub const VALUE_CLEARED_EVENT: &[u8] = b"custom.value_cleared.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueSet {
    pub account_id: Address,
    pub value: u64,
}

impl Write for ValueSet {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.account_id.write(buf);
        self.value.write(buf);
    }
}

impl Read for ValueSet {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            account_id: Address::read(buf)?,
            value: u64::read(buf)?,
        })
    }
}

impl EncodeSize for ValueSet {
    fn encode_size(&self) -> usize {
        self.account_id.encode_size() + self.value.encode_size()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueCleared {
    pub account_id: Address,
}

impl Write for ValueCleared {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.account_id.write(buf);
    }
}

impl Read for ValueCleared {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            account_id: Address::read(buf)?,
        })
    }
}

impl EncodeSize for ValueCleared {
    fn encode_size(&self) -> usize {
        self.account_id.encode_size()
    }
}

pub fn value_set_event(value: ValueSet) -> Event {
    Event::new(bytes::Bytes::from_static(VALUE_SET_EVENT), value.encode())
}

pub fn value_cleared_event(value: ValueCleared) -> Event {
    Event::new(
        bytes::Bytes::from_static(VALUE_CLEARED_EVENT),
        value.encode(),
    )
}
