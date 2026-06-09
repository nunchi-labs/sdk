use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_authority::Transaction as AuthorityTransaction;
use nunchi_coins::Transaction as CoinTransaction;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transaction {
    Coin(Box<CoinTransaction>),
    Authority(Box<AuthorityTransaction>),
}

impl Transaction {
    pub fn verify(&self) -> bool {
        match self {
            Self::Coin(tx) => tx.verify().is_ok(),
            Self::Authority(tx) => tx.verify().is_ok(),
        }
    }

    pub fn digest(&self) -> Digest {
        match self {
            Self::Coin(tx) => tx.digest(),
            Self::Authority(tx) => tx.digest(),
        }
    }

    pub fn ordering_key(&self) -> Vec<u8> {
        match self {
            Self::Coin(tx) => tx.account_id.encode().as_ref().to_vec(),
            Self::Authority(tx) => tx.account_id.encode().as_ref().to_vec(),
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Self::Coin(tx) => tx.payload.nonce,
            Self::Authority(tx) => tx.payload.nonce,
        }
    }
}

impl From<CoinTransaction> for Transaction {
    fn from(tx: CoinTransaction) -> Self {
        Self::Coin(Box::new(tx))
    }
}

impl From<AuthorityTransaction> for Transaction {
    fn from(tx: AuthorityTransaction) -> Self {
        Self::Authority(Box::new(tx))
    }
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Coin(tx) => {
                0u8.write(buf);
                tx.write(buf);
            }
            Self::Authority(tx) => {
                1u8.write(buf);
                tx.write(buf);
            }
        }
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Coin(Box::new(CoinTransaction::read(buf)?))),
            1 => Ok(Self::Authority(Box::new(AuthorityTransaction::read(buf)?))),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Coin(tx) => tx.encode_size(),
            Self::Authority(tx) => tx.encode_size(),
        }
    }
}
