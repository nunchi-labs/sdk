use nunchi_authority::{AuthorityOperation, Transaction as AuthorityTransaction};
use nunchi_coins::{CoinOperation, Transaction as CoinTransaction};
use nunchi_oracle::{OracleOperation, Transaction as OracleTransaction};

#[repr(u8)]
#[derive(Clone, Debug, Eq, PartialEq, nunchi_chain::TransactionWrapper)]
pub enum Transaction {
    #[transaction(operation = CoinOperation)]
    Coin(Box<CoinTransaction>) = 0,
    #[transaction(operation = AuthorityOperation)]
    Authority(Box<AuthorityTransaction>) = 1,
    #[transaction(operation = OracleOperation)]
    Oracle(Box<OracleTransaction>) = 2,
}
