use crate::{CustomDB, CustomError, CustomLedger};
use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use nunchi_common::Address;
use serde::{Deserialize, Serialize};

/// JSON-facing custom module genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CustomGenesis {
    #[serde(default)]
    pub accounts: Vec<CustomAccountGenesis>,
}

/// Initial custom value for one account.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CustomAccountGenesis {
    /// Hex-encoded [`Address`].
    pub account: String,
    pub value: u64,
}

impl<D: CustomDB> CustomLedger<D> {
    /// Seed custom state from genesis.
    pub async fn apply_genesis(&mut self, genesis: &CustomGenesis) -> Result<(), CustomError> {
        for account in &genesis.accounts {
            let id = decode_hex::<Address>(&account.account, "account")?;
            self.db.set_value(&id, account.value);
        }
        Ok(())
    }
}

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, CustomError>
where
    T: DecodeExt<()>,
{
    let bytes = from_hex(value).ok_or_else(|| CustomError::Storage(format!("invalid {what}")))?;
    T::decode(bytes.as_ref()).map_err(|err| CustomError::Storage(format!("invalid {what}: {err}")))
}
