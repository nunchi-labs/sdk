use nunchi_authority::{AuthorityOperation, Transaction as AuthorityTransaction};
use nunchi_clob::{ClobOperation, Transaction as ClobTransaction};
use nunchi_coins::{CoinOperation, Transaction as CoinTransaction};
use nunchi_oracle::{OracleOperation, Transaction as OracleTransaction};

pub(crate) const TX_COIN: u8 = 0;
pub(crate) const TX_AUTHORITY: u8 = 1;
pub(crate) const TX_ORACLE: u8 = 2;
pub(crate) const TX_CLOB: u8 = 3;

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
        Clob {
            tag: TX_CLOB,
            transaction: ClobTransaction,
            operation: ClobOperation,
        },
    }
}
