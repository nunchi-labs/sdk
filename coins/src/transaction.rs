use super::{Address, CoinId, CoinSpec, MultisigPolicy};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::Operation;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinOperationId {
    CreateToken = 0,
    Mint = 1,
    Burn = 2,
    Transfer = 3,
    RegisterAccountPolicy = 4,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid coin operation id: {0}")]
pub struct InvalidCoinOperationId(u8);

impl TryFrom<u8> for CoinOperationId {
    type Error = InvalidCoinOperationId;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CreateToken),
            1 => Ok(Self::Mint),
            2 => Ok(Self::Burn),
            3 => Ok(Self::Transfer),
            4 => Ok(Self::RegisterAccountPolicy),
            _ => Err(InvalidCoinOperationId(value)),
        }
    }
}

impl Write for CoinOperationId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_u8(*self as u8);
    }
}

impl Read for CoinOperationId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let value = u8::read(buf)?;
        Self::try_from(value).map_err(|_| Error::Invalid("CoinOperationId", "invalid operation id"))
    }
}

/// A ledger operation authorized by a signed transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoinOperation {
    RegisterAccountPolicy {
        account_id: Address,
        policy: MultisigPolicy,
    },
    CreateToken {
        spec: CoinSpec,
    },
    Mint {
        coin: CoinId,
        to: Address,
        amount: u128,
    },
    Burn {
        coin: CoinId,
        from: Address,
        amount: u128,
    },
    Transfer {
        coin: CoinId,
        from: Address,
        to: Address,
        amount: u128,
    },
}

impl Write for CoinOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::RegisterAccountPolicy { account_id, policy } => {
                CoinOperationId::RegisterAccountPolicy.write(buf);
                account_id.write(buf);
                policy.write(buf);
            }
            Self::CreateToken { spec } => {
                CoinOperationId::CreateToken.write(buf);
                spec.write(buf);
            }
            Self::Mint { coin, to, amount } => {
                CoinOperationId::Mint.write(buf);
                coin.write(buf);
                to.write(buf);
                amount.write(buf);
            }
            Self::Burn { coin, from, amount } => {
                CoinOperationId::Burn.write(buf);
                coin.write(buf);
                from.write(buf);
                amount.write(buf);
            }
            Self::Transfer {
                coin,
                from,
                to,
                amount,
            } => {
                CoinOperationId::Transfer.write(buf);
                coin.write(buf);
                from.write(buf);
                to.write(buf);
                amount.write(buf);
            }
        }
    }
}

impl Read for CoinOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match CoinOperationId::read(buf)? {
            CoinOperationId::RegisterAccountPolicy => Ok(Self::RegisterAccountPolicy {
                account_id: Address::read(buf)?,
                policy: MultisigPolicy::read(buf)?,
            }),
            CoinOperationId::CreateToken => Ok(Self::CreateToken {
                spec: CoinSpec::read(buf)?,
            }),
            CoinOperationId::Mint => Ok(Self::Mint {
                coin: CoinId::read(buf)?,
                to: Address::read(buf)?,
                amount: u128::read(buf)?,
            }),
            CoinOperationId::Burn => Ok(Self::Burn {
                coin: CoinId::read(buf)?,
                from: Address::read(buf)?,
                amount: u128::read(buf)?,
            }),
            CoinOperationId::Transfer => Ok(Self::Transfer {
                coin: CoinId::read(buf)?,
                from: Address::read(buf)?,
                to: Address::read(buf)?,
                amount: u128::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for CoinOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::RegisterAccountPolicy { account_id, policy } => {
                account_id.encode_size() + policy.encode_size()
            }
            Self::CreateToken { spec } => spec.encode_size(),
            Self::Mint { coin, to, amount } => {
                coin.encode_size() + to.encode_size() + amount.encode_size()
            }
            Self::Burn { coin, from, amount } => {
                coin.encode_size() + from.encode_size() + amount.encode_size()
            }
            Self::Transfer {
                coin,
                from,
                to,
                amount,
            } => coin.encode_size() + from.encode_size() + to.encode_size() + amount.encode_size(),
        }
    }
}

impl Operation for CoinOperation {
    const NAMESPACE: &'static [u8] = super::COINS_NAMESPACE;
}

pub type Transaction = nunchi_common::Transaction<CoinOperation>;
pub type TransactionPayload = nunchi_common::TransactionPayload<CoinOperation>;
