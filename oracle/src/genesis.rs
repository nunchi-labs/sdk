use crate::{
    ledger::validate_policy, NamespaceId, NamespacePolicy, OracleDB, OracleError, OracleLedger,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_formatting::{from_hex, hex};
use nunchi_common::Address;
use serde::{Deserialize, Serialize};

/// JSON-facing oracle module genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleGenesis {
    /// Namespaces to configure at genesis.
    #[serde(default)]
    pub namespaces: Vec<OracleNamespaceGenesis>,
}

/// JSON-facing oracle namespace genesis entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleNamespaceGenesis {
    /// Namespace to configure at genesis.
    #[serde(with = "serde_hex")]
    pub namespace: NamespaceId,
    /// Namespace policy.
    pub policy: NamespacePolicyGenesis,
    /// Writer policies to seed for this namespace.
    #[serde(default)]
    pub writers: Vec<OracleWriterGenesis>,
}

/// JSON-facing [`NamespacePolicy`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamespacePolicyGenesis {
    /// Admin account allowed to configure the namespace after genesis.
    #[serde(with = "serde_hex")]
    pub admin: Address,
    /// Maximum payload bytes accepted for records in this namespace.
    pub max_payload_size: u32,
}

/// JSON-facing writer policy for one namespace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleWriterGenesis {
    /// Writer account.
    #[serde(with = "serde_hex")]
    pub writer: Address,
    /// Whether the writer may append records.
    pub enabled: bool,
}

impl NamespacePolicyGenesis {
    pub fn policy(&self) -> Result<NamespacePolicy, OracleError> {
        let policy = NamespacePolicy {
            admin: self.admin.clone(),
            max_payload_size: self.max_payload_size,
        };
        validate_policy(&policy)?;
        Ok(policy)
    }
}

impl<D: OracleDB> OracleLedger<D> {
    /// Seed oracle state from genesis without transaction authorization.
    pub async fn apply_genesis(&mut self, genesis: &OracleGenesis) -> Result<(), OracleError> {
        for namespace in &genesis.namespaces {
            let policy = namespace.policy.policy()?;
            if self.db().namespace(&namespace.namespace).await?.is_some() {
                return Err(OracleError::InvalidGenesis(format!(
                    "duplicate oracle namespace {:?}",
                    namespace.namespace
                )));
            }

            self.db_mut().set_namespace(&namespace.namespace, &policy);
            for writer in &namespace.writers {
                self.db_mut()
                    .set_writer(&namespace.namespace, &writer.writer, writer.enabled);
            }
        }
        Ok(())
    }
}

mod serde_hex {
    use super::*;
    use serde::{de::Error as _, Deserializer, Serializer};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encode,
        S: Serializer,
    {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: DecodeExt<()>,
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes =
            from_hex(&value).ok_or_else(|| D::Error::custom("expected hex-encoded codec bytes"))?;
        T::decode(bytes.as_ref()).map_err(D::Error::custom)
    }
}
