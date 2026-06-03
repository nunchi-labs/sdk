use commonware_codec::{EncodeSize, Read, ReadExt, Write};

pub type AccountId = nunchi_crypto::PublicKey;
pub type PrivateKey = nunchi_crypto::PrivateKey;
pub type Signature = nunchi_crypto::Signature;

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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn account_roundtrips_with_ed25519_id() {
        let id = PrivateKey::ed25519_from_seed(1).public_key();
        let account = Account::new(id, 42);

        assert_eq!(Account::decode(account.encode().as_ref()).unwrap(), account);
    }

    #[test]
    fn account_roundtrips_with_secp256r1_id() {
        let id = PrivateKey::secp256r1_from_seed(1).public_key();
        let account = Account::new(id, 42);

        assert_eq!(Account::decode(account.encode().as_ref()).unwrap(), account);
    }
}
