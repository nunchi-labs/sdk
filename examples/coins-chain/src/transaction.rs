use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_authority::{AuthorityOperation, Transaction as AuthorityTransaction};
use nunchi_coins::{CoinOperation, Transaction as CoinTransaction};
use nunchi_common::{Address, Operation};
use nunchi_crypto::SignatureError;
use nunchi_mempool::{NonceKey, PoolTransaction};
use nunchi_oracle::{OracleOperation, Transaction as OracleTransaction};

pub(crate) const TX_COIN: u8 = 0;
pub(crate) const TX_AUTHORITY: u8 = 1;
pub(crate) const TX_ORACLE: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transaction {
    Coin(Box<CoinTransaction>),
    Authority(Box<AuthorityTransaction>),
    Oracle(Box<OracleTransaction>),
}

impl Transaction {
    pub fn verify(&self) -> bool {
        match self {
            Self::Coin(tx) => tx.verify().is_ok(),
            Self::Authority(tx) => tx.verify().is_ok(),
            Self::Oracle(tx) => tx.verify().is_ok(),
        }
    }

    pub fn digest(&self) -> Digest {
        match self {
            Self::Coin(tx) => tx.digest(),
            Self::Authority(tx) => tx.digest(),
            Self::Oracle(tx) => tx.digest(),
        }
    }

    pub fn account_id(&self) -> &Address {
        match self {
            Self::Coin(tx) => &tx.account_id,
            Self::Authority(tx) => &tx.account_id,
            Self::Oracle(tx) => &tx.account_id,
        }
    }

    pub fn ordering_key(&self) -> Vec<u8> {
        self.account_id().encode().as_ref().to_vec()
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Self::Coin(tx) => tx.payload.nonce,
            Self::Authority(tx) => tx.payload.nonce,
            Self::Oracle(tx) => tx.payload.nonce,
        }
    }
}

impl PoolTransaction for Transaction {
    type Digest = Digest;
    type NonceKey = NonceKey;
    type VerifyError = SignatureError;

    fn digest(&self) -> Self::Digest {
        Self::digest(self)
    }

    fn nonce_key(&self) -> Self::NonceKey {
        match self {
            Self::Coin(tx) => NonceKey::new(CoinOperation::NAMESPACE, tx.account_id.clone()),
            Self::Authority(tx) => {
                NonceKey::new(AuthorityOperation::NAMESPACE, tx.account_id.clone())
            }
            Self::Oracle(tx) => NonceKey::new(OracleOperation::NAMESPACE, tx.account_id.clone()),
        }
    }

    fn nonce(&self) -> u64 {
        self.nonce()
    }

    fn encoded_size(&self) -> usize {
        EncodeSize::encode_size(self)
    }

    fn verify(&self) -> Result<(), Self::VerifyError> {
        match self {
            Self::Coin(tx) => tx.verify(),
            Self::Authority(tx) => tx.verify(),
            Self::Oracle(tx) => tx.verify(),
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

impl From<OracleTransaction> for Transaction {
    fn from(tx: OracleTransaction) -> Self {
        Self::Oracle(Box::new(tx))
    }
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Coin(tx) => {
                TX_COIN.write(buf);
                tx.write(buf);
            }
            Self::Authority(tx) => {
                TX_AUTHORITY.write(buf);
                tx.write(buf);
            }
            Self::Oracle(tx) => {
                TX_ORACLE.write(buf);
                tx.write(buf);
            }
        }
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            TX_COIN => Ok(Self::Coin(Box::new(CoinTransaction::read(buf)?))),
            TX_AUTHORITY => Ok(Self::Authority(Box::new(AuthorityTransaction::read(buf)?))),
            TX_ORACLE => Ok(Self::Oracle(Box::new(OracleTransaction::read(buf)?))),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Coin(tx) => tx.encode_size(),
            Self::Authority(tx) => tx.encode_size(),
            Self::Oracle(tx) => tx.encode_size(),
        }
    }
}
