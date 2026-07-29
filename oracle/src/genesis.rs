use crate::{OracleDB, OracleError, OracleLedger};
use serde::{Deserialize, Serialize};

/// JSON-facing oracle module genesis state.
///
/// Currently empty because the oracle is fully permissionless: any account can write to any
/// namespace. See the [crate-level security documentation](crate) for implications.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleGenesis {}

impl<D: OracleDB> OracleLedger<D> {
    /// Apply oracle genesis state.
    pub async fn apply_genesis(&mut self, _genesis: &OracleGenesis) -> Result<(), OracleError> {
        Ok(())
    }
}
