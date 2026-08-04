use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::{Address, Event};

pub const COUNTER_INCREMENTED_EVENT: &[u8] = b"counter.incremented.v1";
pub const COUNTER_RESET_EVENT: &[u8] = b"counter.reset.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterIncremented {
    pub account: Address,
    pub value: u64,
}

impl Write for CounterIncremented {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.account.write(buf);
        self.value.write(buf);
    }
}

impl Read for CounterIncremented {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            account: Address::read(buf)?,
            value: u64::read(buf)?,
        })
    }
}

impl EncodeSize for CounterIncremented {
    fn encode_size(&self) -> usize {
        self.account.encode_size() + self.value.encode_size()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterReset {
    pub account: Address,
    pub previous: u64,
    pub value: u64,
}

impl Write for CounterReset {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.account.write(buf);
        self.previous.write(buf);
        self.value.write(buf);
    }
}

impl Read for CounterReset {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            account: Address::read(buf)?,
            previous: u64::read(buf)?,
            value: u64::read(buf)?,
        })
    }
}

impl EncodeSize for CounterReset {
    fn encode_size(&self) -> usize {
        self.account.encode_size() + self.previous.encode_size() + self.value.encode_size()
    }
}

pub fn counter_incremented_event(incremented: CounterIncremented) -> Event {
    Event::new(
        bytes::Bytes::from_static(COUNTER_INCREMENTED_EVENT),
        incremented.encode(),
    )
}

pub fn counter_reset_event(reset: CounterReset) -> Event {
    Event::new(bytes::Bytes::from_static(COUNTER_RESET_EVENT), reset.encode())
}
