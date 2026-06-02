use commonware_codec::{EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::ed25519;

// TODO(distractedm1nd): There should be an abstraction over the curves.
pub type AccountId = ed25519::PublicKey;
pub type PrivateKey = ed25519::PrivateKey;
pub type Signature = ed25519::Signature;

/// An account known to the coin ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub id: AccountId,
    pub nonce: u64,
}

impl Account {
    pub fn new(id: AccountId, nonce: u64) -> Self {
        Self { id, nonce }
    }
}

impl Write for Account {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.nonce.write(buf);
    }
}

impl Read for Account {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            id: AccountId::read(buf)?,
            nonce: u64::read(buf)?,
        })
    }
}

impl EncodeSize for Account {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.nonce.encode_size()
    }
}
