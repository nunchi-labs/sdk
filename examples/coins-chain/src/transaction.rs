use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_authority::AuthorityOperation;
use nunchi_coins::{CoinId, CoinOperation};
use nunchi_common::Transaction as CommonTransaction;
use nunchi_oracle::OracleOperation;

pub(crate) const TX_COIN: u8 = 0;
pub(crate) const TX_AUTHORITY: u8 = 1;
pub(crate) const TX_ORACLE: u8 = 2;

/// V1 transaction fee metadata signed by every coins-chain transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeV1 {
    pub coin: CoinId,
    pub max_amount: u128,
    pub tip: u128,
    pub weight_limit: u64,
}

impl FeeV1 {
    pub fn new(coin: CoinId, max_amount: u128, tip: u128, weight_limit: u64) -> Self {
        Self {
            coin,
            max_amount,
            tip,
            weight_limit,
        }
    }
}

impl Write for FeeV1 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.coin.write(buf);
        self.max_amount.write(buf);
        self.tip.write(buf);
        self.weight_limit.write(buf);
    }
}

impl Read for FeeV1 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            coin: CoinId::read(buf)?,
            max_amount: u128::read(buf)?,
            tip: u128::read(buf)?,
            weight_limit: u64::read(buf)?,
        })
    }
}

impl EncodeSize for FeeV1 {
    fn encode_size(&self) -> usize {
        self.coin.encode_size()
            + self.max_amount.encode_size()
            + self.tip.encode_size()
            + self.weight_limit.encode_size()
    }
}

pub type CoinTransaction = CommonTransaction<CoinOperation, FeeV1>;
pub type AuthorityTransaction = CommonTransaction<AuthorityOperation, FeeV1>;
pub type OracleTransaction = CommonTransaction<OracleOperation, FeeV1>;

nunchi_chain::transaction_wrapper! {
    pub enum Transaction {
        Coin {
            tag: TX_COIN,
            transaction: CoinTransaction,
            operation: CoinOperation,
        },
        Authority {
            tag: TX_AUTHORITY,
            transaction: AuthorityTransaction,
            operation: AuthorityOperation,
        },
        Oracle {
            tag: TX_ORACLE,
            transaction: OracleTransaction,
            operation: OracleOperation,
        },
    }
}
