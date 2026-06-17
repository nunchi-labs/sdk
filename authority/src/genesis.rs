use crate::{AuthorityError, AuthorityLedger, EpochNumber, MultisigPolicy, OwnerId, ValidatorId};
use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use serde::{Deserialize, Serialize};

/// JSON-facing authority module genesis state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityGenesis {
    /// Initial authority policy.
    pub policy: AuthorityPolicyGenesis,
    /// Initial validator set active at `epoch`.
    pub validators: Vec<String>,
    /// First epoch materialized in the authority registry.
    #[serde(default)]
    pub epoch: EpochNumber,
}

/// JSON-facing multisig policy for authority owners.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityPolicyGenesis {
    /// Hex-encoded `nunchi_crypto::PublicKey` owners.
    pub owners: Vec<String>,
    /// Number of owners required for governance actions.
    pub threshold: u16,
}

impl AuthorityGenesis {
    pub fn policy(&self) -> Result<MultisigPolicy, AuthorityError> {
        let owners = self
            .policy
            .owners
            .iter()
            .map(|owner| decode_hex::<OwnerId>(owner, "authority owner"))
            .collect::<Result<Vec<_>, _>>()?;
        MultisigPolicy::new(self.policy.threshold, owners).ok_or(AuthorityError::InvalidPolicy)
    }

    pub fn validators(&self) -> Result<Vec<ValidatorId>, AuthorityError> {
        self.validators
            .iter()
            .map(|validator| decode_hex::<ValidatorId>(validator, "authority validator"))
            .collect()
    }
}

impl<D: crate::AuthorityDB> AuthorityLedger<D> {
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

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, AuthorityError>
where
    T: DecodeExt<()>,
{
    let bytes =
        from_hex(value).ok_or_else(|| AuthorityError::Storage(format!("invalid {what}")))?;
    T::decode(bytes.as_ref()).map_err(|err| AuthorityError::Storage(err.to_string()))
}
