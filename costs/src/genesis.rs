use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use nunchi_common::Address;
use serde::{Deserialize, Serialize};

use crate::{CostsDB, CostsError, CostsLedger, WriterRole};

/// JSON-facing bootstrap configuration. Only backend administrator keys enter
/// genesis; client accounts are registered through signed administrative commands.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CostsGenesis {
    #[serde(default)]
    pub administrators: Vec<String>,
}

impl<D: CostsDB> CostsLedger<D> {
    /// Seed the initial administrator allowlist from chain genesis.
    pub async fn apply_genesis(&mut self, genesis: &CostsGenesis) -> Result<(), CostsError> {
        for administrator in &genesis.administrators {
            let address = decode_hex::<Address>(administrator, "administrator")?;
            self.db.set_writer(WriterRole::Admin, &address, true);
        }
        Ok(())
    }
}

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, CostsError>
where
    T: DecodeExt<()>,
{
    let bytes = from_hex(value).ok_or_else(|| CostsError::Storage(format!("invalid {what}")))?;
    T::decode(bytes.as_ref())
        .map_err(|err| CostsError::Storage(format!("invalid {what}: {err}")))
}
