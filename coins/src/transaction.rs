use super::{AccountId, CoinId, CoinSpec, MultisigPolicy};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::Operation;

const OP_CREATE_TOKEN: u8 = 0;
const OP_MINT: u8 = 1;
const OP_BURN: u8 = 2;
const OP_TRANSFER: u8 = 3;
const OP_REGISTER_ACCOUNT_POLICY: u8 = 4;

/// A ledger operation authorized by a signed transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoinOperation {
    RegisterAccountPolicy {
        account_id: AccountId,
        policy: MultisigPolicy,
    },
    CreateToken {
        spec: CoinSpec,
    },
    Mint {
        coin: CoinId,
        to: AccountId,
        amount: u128,
    },
    Burn {
        coin: CoinId,
        from: AccountId,
        amount: u128,
    },
    Transfer {
        coin: CoinId,
        from: AccountId,
        to: AccountId,
        amount: u128,
    },
}

impl Write for CoinOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::RegisterAccountPolicy { account_id, policy } => {
                OP_REGISTER_ACCOUNT_POLICY.write(buf);
                account_id.write(buf);
                policy.write(buf);
            }
            Self::CreateToken { spec } => {
                OP_CREATE_TOKEN.write(buf);
                spec.write(buf);
            }
            Self::Mint { coin, to, amount } => {
                OP_MINT.write(buf);
                coin.write(buf);
                to.write(buf);
                amount.write(buf);
            }
            Self::Burn { coin, from, amount } => {
                OP_BURN.write(buf);
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
                OP_TRANSFER.write(buf);
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
        match u8::read(buf)? {
            OP_REGISTER_ACCOUNT_POLICY => Ok(Self::RegisterAccountPolicy {
                account_id: AccountId::read(buf)?,
                policy: MultisigPolicy::read(buf)?,
            }),
            OP_CREATE_TOKEN => Ok(Self::CreateToken {
                spec: CoinSpec::read(buf)?,
            }),
            OP_MINT => Ok(Self::Mint {
                coin: CoinId::read(buf)?,
                to: AccountId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OP_BURN => Ok(Self::Burn {
                coin: CoinId::read(buf)?,
                from: AccountId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OP_TRANSFER => Ok(Self::Transfer {
                coin: CoinId::read(buf)?,
                from: AccountId::read(buf)?,
                to: AccountId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
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
