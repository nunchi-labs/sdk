//! Persistence layer for the authority module.

use crate::{
    types::{normalize, stored_vec_cfg, OwnerId},
    AuthorityError, EpochNumber, EpochRegistry, MultisigPolicy, Proposal, ProposalId, ValidatorId,
    ValidatorSchedule, AUTHORITY_NAMESPACE,
};
use commonware_codec::{Encode, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_common::state_db::{Namespace, StateStore};

const NS: Namespace = Namespace::new(AUTHORITY_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    OwnerNonce = 0,
    Policy = 1,
    ValidatorIndex = 2,
    ValidatorSchedule = 3,
    Proposal = 4,
    EpochRegistry = 5,
    LatestIndexedEpoch = 6,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, AuthorityError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| AuthorityError::Storage(err.to_string()))
}

fn validator_vec_key() -> Digest {
    NS.key(Table::ValidatorIndex, &[])
}

fn policy_key() -> Digest {
    NS.key(Table::Policy, &[])
}

fn latest_epoch_key() -> Digest {
    NS.key(Table::LatestIndexedEpoch, &[])
}

fn proposal_key(id: &ProposalId) -> Digest {
    NS.key(Table::Proposal, id.encode().as_ref())
}

fn validator_key(id: &ValidatorId) -> Digest {
    NS.key(Table::ValidatorSchedule, id.encode().as_ref())
}

fn epoch_key(epoch: EpochNumber) -> Digest {
    NS.key(Table::EpochRegistry, epoch.encode().as_ref())
}

#[allow(async_fn_in_trait)]
pub trait AuthorityDB {
    async fn nonce(&self, owner: &OwnerId) -> Result<u64, AuthorityError>;
    fn set_nonce(&mut self, owner: &OwnerId, nonce: u64);

    async fn policy(&self) -> Result<Option<MultisigPolicy>, AuthorityError>;
    fn set_policy(&mut self, policy: &MultisigPolicy);

    async fn validator_index(&self) -> Result<Vec<ValidatorId>, AuthorityError>;
    fn set_validator_index(&mut self, validators: &[ValidatorId]);

    async fn validator(
        &self,
        validator: &ValidatorId,
    ) -> Result<Option<ValidatorSchedule>, AuthorityError>;
    fn set_validator(&mut self, schedule: &ValidatorSchedule);

    async fn proposal(&self, id: &ProposalId) -> Result<Option<Proposal>, AuthorityError>;
    fn set_proposal(&mut self, proposal: &Proposal);

    async fn epoch_registry(
        &self,
        epoch: EpochNumber,
    ) -> Result<Option<EpochRegistry>, AuthorityError>;
    fn set_epoch_registry(&mut self, registry: &EpochRegistry);

    async fn latest_indexed_epoch(&self) -> Result<Option<EpochNumber>, AuthorityError>;
    fn set_latest_indexed_epoch(&mut self, epoch: EpochNumber);
}

impl<S: StateStore> AuthorityDB for S {
    async fn nonce(&self, owner: &OwnerId) -> Result<u64, AuthorityError> {
        let key = NS.key(Table::OwnerNonce, owner.encode().as_ref());
        match StateStore::get(self, &key)
            .await
            .map_err(|err| AuthorityError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded::<u64>(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, owner: &OwnerId, nonce: u64) {
        StateStore::set(
            self,
            NS.key(Table::OwnerNonce, owner.encode().as_ref()),
            encoded(&nonce),
        );
    }

    async fn policy(&self) -> Result<Option<MultisigPolicy>, AuthorityError> {
        match StateStore::get(self, &policy_key())
            .await
            .map_err(|err| AuthorityError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<MultisigPolicy>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_policy(&mut self, policy: &MultisigPolicy) {
        StateStore::set(self, policy_key(), encoded(policy));
    }

    async fn validator_index(&self) -> Result<Vec<ValidatorId>, AuthorityError> {
        match StateStore::get(self, &validator_vec_key())
            .await
            .map_err(|err| AuthorityError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_slice();
                Vec::read_cfg(&mut buf, &stored_vec_cfg())
                    .map_err(|err| AuthorityError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_validator_index(&mut self, validators: &[ValidatorId]) {
        let validators = normalize(validators.to_vec());
        StateStore::set(self, validator_vec_key(), encoded(&validators));
    }

    async fn validator(
        &self,
        validator: &ValidatorId,
    ) -> Result<Option<ValidatorSchedule>, AuthorityError> {
        match StateStore::get(self, &validator_key(validator))
            .await
            .map_err(|err| AuthorityError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<ValidatorSchedule>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_validator(&mut self, schedule: &ValidatorSchedule) {
        StateStore::set(self, validator_key(&schedule.validator), encoded(schedule));
    }

    async fn proposal(&self, id: &ProposalId) -> Result<Option<Proposal>, AuthorityError> {
        match StateStore::get(self, &proposal_key(id))
            .await
            .map_err(|err| AuthorityError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<Proposal>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_proposal(&mut self, proposal: &Proposal) {
        StateStore::set(self, proposal_key(&proposal.id), encoded(proposal));
    }

    async fn epoch_registry(
        &self,
        epoch: EpochNumber,
    ) -> Result<Option<EpochRegistry>, AuthorityError> {
        match StateStore::get(self, &epoch_key(epoch))
            .await
            .map_err(|err| AuthorityError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<EpochRegistry>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_epoch_registry(&mut self, registry: &EpochRegistry) {
        StateStore::set(self, epoch_key(registry.epoch), encoded(registry));
    }

    async fn latest_indexed_epoch(&self) -> Result<Option<EpochNumber>, AuthorityError> {
        match StateStore::get(self, &latest_epoch_key())
            .await
            .map_err(|err| AuthorityError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded::<EpochNumber>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_latest_indexed_epoch(&mut self, epoch: EpochNumber) {
        StateStore::set(self, latest_epoch_key(), encoded(&epoch));
    }
}
