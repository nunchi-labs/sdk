use crate::{
    AuthorityDB, AuthorityError, AuthorityLedger, EpochNumber, MultisigPolicy, OwnerId, ValidatorId,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_formatting::{from_hex, hex};
use serde::{Deserialize, Serialize};

/// JSON-facing authority module genesis state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityGenesis {
    /// Initial authority policy.
    pub policy: AuthorityPolicyGenesis,
    /// Initial validator set active at `epoch`, encoded as hex in JSON.
    #[serde(with = "serde_hex_vec")]
    pub validators: Vec<ValidatorId>,
    /// First epoch materialized in the authority registry.
    #[serde(default)]
    pub epoch: EpochNumber,
}

/// JSON-facing multisig policy for authority owners.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityPolicyGenesis {
    /// Authority owners, encoded as hex in JSON.
    #[serde(with = "serde_hex_vec")]
    pub owners: Vec<OwnerId>,
    /// Number of owners required for governance actions.
    pub threshold: u16,
}

impl AuthorityGenesis {
    pub fn policy(&self) -> Result<MultisigPolicy, AuthorityError> {
        MultisigPolicy::new(self.policy.threshold, self.policy.owners.clone())
            .ok_or(AuthorityError::InvalidPolicy)
    }

    pub fn validators(&self) -> Result<Vec<ValidatorId>, AuthorityError> {
        Ok(self.validators.clone())
    }
}

impl<D: AuthorityDB> AuthorityLedger<D> {
    /// Seed the authority registry from genesis without transaction authorization.
    ///
    /// This is the trusted bootstrap path. Runtime changes still go through authority
    /// transactions, but genesis must pin the initial policy and validator set before any
    /// first-come-first-served `Configure` transaction can land.
    pub async fn apply_genesis(
        &mut self,
        genesis: &AuthorityGenesis,
    ) -> Result<(), AuthorityError> {
        self.seed_genesis(genesis.policy()?, genesis.validators()?, genesis.epoch)
            .await
    }
}

mod serde_hex_vec {
    use super::*;
    use serde::{de::Error as _, Deserializer, Serializer};

    pub fn serialize<T, S>(value: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encode,
        S: Serializer,
    {
        serializer.collect_seq(value.iter().map(|item| hex(&item.encode())))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: DecodeExt<()>,
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        values
            .into_iter()
            .map(|value| {
                let bytes = from_hex(&value)
                    .ok_or_else(|| D::Error::custom("expected hex-encoded codec bytes"))?;
                T::decode(bytes.as_ref()).map_err(D::Error::custom)
            })
            .collect()
    }
}
