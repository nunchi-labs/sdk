use crate::{
    types::{normalize, sorted_unique, OwnerId},
    AuthorityDB, AuthorityOperation, EpochNumber, EpochRegistry, MultisigPolicy, Proposal,
    ProposalId, RegistryChange, Transaction, ValidatorId, ValidatorSchedule,
};
use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256};
use nunchi_common::Authorization;
use nunchi_crypto::SignatureError;
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum AuthorityError {
    #[error("bad authority transaction signature: {0}")]
    BadSignature(#[from] SignatureError),
    #[error("nonce mismatch for {owner:?}: expected {expected}, got {actual}")]
    NonceMismatch {
        owner: Box<OwnerId>,
        expected: u64,
        actual: u64,
    },
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("epoch overflow")]
    EpochOverflow,
    #[error("authority policy is already configured")]
    AlreadyConfigured,
    #[error("authority policy is not configured")]
    NotConfigured,
    #[error("invalid multisig policy")]
    InvalidPolicy,
    #[error("invalid authority epoch")]
    InvalidEpoch,
    #[error("unauthorized authority signer")]
    Unauthorized,
    #[error("proposal already exists")]
    ProposalExists,
    #[error("proposal not found: {0:?}")]
    ProposalNotFound(ProposalId),
    #[error("proposal already executed")]
    ProposalAlreadyExecuted,
    #[error("approval already recorded")]
    ApprovalAlreadyRecorded,
    #[error("proposal has {actual} approvals but requires {required}")]
    InsufficientApprovals { required: u16, actual: usize },
    #[error("validator already active: {0:?}")]
    ValidatorAlreadyActive(Box<ValidatorId>),
    #[error("unknown validator: {0:?}")]
    UnknownValidator(Box<ValidatorId>),
    #[error("state storage error: {0}")]
    Storage(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityLedger<D> {
    db: D,
}

impl<D: AuthorityDB> AuthorityLedger<D> {
    pub fn new(db: D) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &D {
        &self.db
    }

    pub fn into_inner(self) -> D {
        self.db
    }

    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
        current_epoch: EpochNumber,
    ) -> Result<(), AuthorityError> {
        tx.verify()?;

        // Authority approvals are collected on-chain through Propose/Approve/Execute, so each
        // transaction must carry a single owner signature; account-level multisig authorization
        // is not part of this module's model.
        let signer = match &tx.authorization {
            Authorization::Single { signer, .. } => signer.as_ref(),
            Authorization::Multisig { .. } => return Err(AuthorityError::Unauthorized),
        };

        let expected = self.db.nonce(signer).await?;
        if tx.payload.nonce != expected {
            return Err(AuthorityError::NonceMismatch {
                owner: Box::new(signer.clone()),
                expected,
                actual: tx.payload.nonce,
            });
        }

        self.apply_operation(signer, &tx.payload.operation, current_epoch)
            .await?;
        let next_nonce = expected
            .checked_add(1)
            .ok_or(AuthorityError::NonceOverflow)?;
        self.db.set_nonce(signer, next_nonce);
        Ok(())
    }

    pub async fn policy(&self) -> Result<Option<MultisigPolicy>, AuthorityError> {
        self.db.policy().await
    }

    pub async fn proposal(&self, id: &ProposalId) -> Result<Option<Proposal>, AuthorityError> {
        self.db.proposal(id).await
    }

    pub async fn epoch_registry(
        &self,
        epoch: EpochNumber,
    ) -> Result<Option<EpochRegistry>, AuthorityError> {
        self.db.epoch_registry(epoch).await
    }

    pub async fn validator(
        &self,
        validator: &ValidatorId,
    ) -> Result<Option<ValidatorSchedule>, AuthorityError> {
        self.db.validator(validator).await
    }

    async fn apply_operation(
        &mut self,
        signer: &OwnerId,
        operation: &AuthorityOperation,
        current_epoch: EpochNumber,
    ) -> Result<(), AuthorityError> {
        match operation {
            AuthorityOperation::Configure {
                policy,
                initial_validators,
                epoch,
            } => {
                self.configure(signer, policy.clone(), initial_validators.clone(), *epoch)
                    .await
            }
            AuthorityOperation::Propose {
                change,
                effective_epoch,
            } => self
                .propose_change(signer, change.clone(), *effective_epoch, current_epoch)
                .await
                .map(|_| ()),
            AuthorityOperation::Approve { proposal } => self.approve(signer, proposal).await,
            AuthorityOperation::Execute { proposal } => self.execute(signer, proposal).await,
        }
    }

    async fn configure(
        &mut self,
        signer: &OwnerId,
        mut policy: MultisigPolicy,
        initial_validators: Vec<ValidatorId>,
        epoch: EpochNumber,
    ) -> Result<(), AuthorityError> {
        if self.db.policy().await?.is_some() {
            return Err(AuthorityError::AlreadyConfigured);
        }
        policy.owners = sorted_unique(policy.owners).ok_or(AuthorityError::InvalidPolicy)?;
        if policy.threshold == 0 || policy.threshold as usize > policy.owners.len() {
            return Err(AuthorityError::InvalidPolicy);
        }
        if !policy.owners.contains(signer) {
            return Err(AuthorityError::Unauthorized);
        }
        let initial_validators =
            sorted_unique(initial_validators).ok_or(AuthorityError::InvalidPolicy)?;

        self.db.set_policy(&policy);
        self.db.set_validator_index(&initial_validators);
        for validator in initial_validators {
            self.db.set_validator(&ValidatorSchedule {
                validator,
                player_from: epoch,
                dealer_from: epoch,
                removed_from: None,
            });
        }
        self.refresh_epoch(epoch).await
    }

    async fn propose_change(
        &mut self,
        signer: &OwnerId,
        change: RegistryChange,
        effective_epoch: EpochNumber,
        current_epoch: EpochNumber,
    ) -> Result<ProposalId, AuthorityError> {
        self.require_owner(signer).await?;
        if effective_epoch < current_epoch {
            return Err(AuthorityError::InvalidEpoch);
        }
        let id = proposal_id(&change, effective_epoch);
        if self.db.proposal(&id).await?.is_some() {
            return Err(AuthorityError::ProposalExists);
        }
        let proposal = Proposal {
            id,
            change,
            proposed_epoch: effective_epoch,
            approvals: vec![signer.clone()],
            executed: false,
        };
        self.db.set_proposal(&proposal);
        Ok(id)
    }

    async fn approve(
        &mut self,
        signer: &OwnerId,
        proposal: &ProposalId,
    ) -> Result<(), AuthorityError> {
        self.require_owner(signer).await?;
        let mut proposal = self
            .db
            .proposal(proposal)
            .await?
            .ok_or(AuthorityError::ProposalNotFound(*proposal))?;
        if proposal.executed {
            return Err(AuthorityError::ProposalAlreadyExecuted);
        }
        if proposal.approvals.contains(signer) {
            return Err(AuthorityError::ApprovalAlreadyRecorded);
        }
        proposal.approvals.push(signer.clone());
        proposal.approvals = normalize(proposal.approvals);
        self.db.set_proposal(&proposal);
        Ok(())
    }

    async fn execute(
        &mut self,
        signer: &OwnerId,
        proposal: &ProposalId,
    ) -> Result<(), AuthorityError> {
        let policy = self.require_owner(signer).await?;
        let mut proposal = self
            .db
            .proposal(proposal)
            .await?
            .ok_or(AuthorityError::ProposalNotFound(*proposal))?;
        if proposal.executed {
            return Err(AuthorityError::ProposalAlreadyExecuted);
        }
        if proposal.approvals.len() < policy.threshold as usize {
            return Err(AuthorityError::InsufficientApprovals {
                required: policy.threshold,
                actual: proposal.approvals.len(),
            });
        }

        match proposal.change.clone() {
            RegistryChange::AddValidator { validator } => {
                self.add_validator(validator, proposal.proposed_epoch)
                    .await?
            }
            RegistryChange::RemoveValidator { validator } => {
                self.remove_validator(validator, proposal.proposed_epoch)
                    .await?
            }
        }
        proposal.executed = true;
        self.db.set_proposal(&proposal);
        Ok(())
    }

    async fn require_owner(&self, signer: &OwnerId) -> Result<MultisigPolicy, AuthorityError> {
        let policy = self
            .db
            .policy()
            .await?
            .ok_or(AuthorityError::NotConfigured)?;
        if policy.owners.contains(signer) {
            Ok(policy)
        } else {
            Err(AuthorityError::Unauthorized)
        }
    }

    async fn add_validator(
        &mut self,
        validator: ValidatorId,
        proposed_epoch: EpochNumber,
    ) -> Result<(), AuthorityError> {
        let player_from = proposed_epoch
            .checked_add(1)
            .ok_or(AuthorityError::EpochOverflow)?;
        let dealer_from = proposed_epoch
            .checked_add(2)
            .ok_or(AuthorityError::EpochOverflow)?;

        if let Some(schedule) = self.db.validator(&validator).await? {
            let already_active = schedule
                .removed_from
                .is_none_or(|removed| proposed_epoch < removed);
            if already_active {
                return Err(AuthorityError::ValidatorAlreadyActive(Box::new(validator)));
            }
        }

        let mut validators = self.db.validator_index().await?;
        validators.push(validator.clone());
        self.db.set_validator_index(&validators);
        self.db.set_validator(&ValidatorSchedule {
            validator,
            player_from,
            dealer_from,
            removed_from: None,
        });
        self.refresh_epoch(player_from).await?;
        self.refresh_epoch(dealer_from).await
    }

    async fn remove_validator(
        &mut self,
        validator: ValidatorId,
        proposed_epoch: EpochNumber,
    ) -> Result<(), AuthorityError> {
        let removed_from = proposed_epoch
            .checked_add(1)
            .ok_or(AuthorityError::EpochOverflow)?;
        let mut schedule = self
            .db
            .validator(&validator)
            .await?
            .ok_or_else(|| AuthorityError::UnknownValidator(Box::new(validator.clone())))?;
        if !schedule.is_player_at(proposed_epoch) && !schedule.is_dealer_at(proposed_epoch) {
            return Err(AuthorityError::UnknownValidator(Box::new(validator)));
        }
        schedule.removed_from = Some(removed_from);
        self.db.set_validator(&schedule);
        self.refresh_epoch(removed_from).await
    }

    async fn refresh_epoch(&mut self, epoch: EpochNumber) -> Result<(), AuthorityError> {
        let mut players = Vec::new();
        let mut dealers = Vec::new();
        for validator in self.db.validator_index().await? {
            let Some(schedule) = self.db.validator(&validator).await? else {
                continue;
            };
            if schedule.is_player_at(epoch) {
                players.push(validator.clone());
            }
            if schedule.is_dealer_at(epoch) {
                dealers.push(validator);
            }
        }
        self.db.set_epoch_registry(&EpochRegistry {
            epoch,
            players: normalize(players),
            dealers: normalize(dealers),
        });
        if self
            .db
            .latest_indexed_epoch()
            .await?
            .is_none_or(|latest| epoch > latest)
        {
            self.db.set_latest_indexed_epoch(epoch);
        }
        Ok(())
    }
}

pub fn proposal_id(change: &RegistryChange, proposed_epoch: EpochNumber) -> ProposalId {
    let mut bytes = change.encode().as_ref().to_vec();
    bytes.extend_from_slice(proposed_epoch.encode().as_ref());
    Sha256::hash(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{ed25519, sha256::Digest, Signer as _};
    use commonware_runtime::Runner as _;
    use nunchi_common::{state_db::StateStore, StateError};
    use nunchi_crypto::PrivateKey;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemoryState {
        values: BTreeMap<Digest, Vec<u8>>,
    }

    impl StateStore for MemoryState {
        async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.values.get(key).cloned())
        }

        fn set(&mut self, key: Digest, value: Vec<u8>) {
            self.values.insert(key, value);
        }

        fn remove(&mut self, key: Digest) {
            self.values.remove(&key);
        }
    }

    fn owner(seed: u64) -> PrivateKey {
        PrivateKey::from_seed(seed)
    }

    fn validator(seed: u64) -> ValidatorId {
        ed25519::PrivateKey::from_seed(seed).public_key()
    }

    fn policy(owners: &[PrivateKey], threshold: u16) -> MultisigPolicy {
        MultisigPolicy {
            owners: owners.iter().map(PrivateKey::public_key).collect(),
            threshold,
        }
    }

    async fn configured() -> (
        AuthorityLedger<MemoryState>,
        Vec<PrivateKey>,
        Vec<ValidatorId>,
    ) {
        let owners = vec![owner(1), owner(2), owner(3)];
        let validators = vec![validator(10), validator(11)];
        let configure = Transaction::sign(
            &owners[0],
            0,
            AuthorityOperation::Configure {
                policy: policy(&owners, 2),
                initial_validators: validators.clone(),
                epoch: 0,
            },
        );
        let mut ledger = AuthorityLedger::new(MemoryState::default());
        ledger.apply_transaction(&configure, 0).await.unwrap();
        (ledger, owners, validators)
    }

    #[test]
    fn configure_indexes_initial_dealers_and_players() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let (ledger, _, validators) = configured().await;
            let registry = ledger.epoch_registry(0).await.unwrap().unwrap();
            assert_eq!(registry.players, validators);
            assert_eq!(registry.dealers, validators);
        });
    }

    #[test]
    fn add_validator_becomes_player_before_dealer() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let (mut ledger, owners, validators) = configured().await;
            let added = validator(12);
            let change = RegistryChange::AddValidator {
                validator: added.clone(),
            };
            let id = proposal_id(&change, 3);
            ledger
                .apply_transaction(
                    &Transaction::sign(
                        &owners[0],
                        1,
                        AuthorityOperation::Propose {
                            change,
                            effective_epoch: 3,
                        },
                    ),
                    3,
                )
                .await
                .unwrap();
            ledger
                .apply_transaction(
                    &Transaction::sign(&owners[1], 0, AuthorityOperation::Approve { proposal: id }),
                    3,
                )
                .await
                .unwrap();
            ledger
                .apply_transaction(
                    &Transaction::sign(&owners[2], 0, AuthorityOperation::Execute { proposal: id }),
                    3,
                )
                .await
                .unwrap();

            let epoch_4 = ledger.epoch_registry(4).await.unwrap().unwrap();
            let epoch_5 = ledger.epoch_registry(5).await.unwrap().unwrap();
            let mut expected_players = validators.clone();
            expected_players.push(added.clone());
            expected_players = normalize(expected_players);

            assert_eq!(epoch_4.players, expected_players);
            assert_eq!(epoch_4.dealers, validators);
            assert_eq!(epoch_5.players, expected_players);
            assert_eq!(epoch_5.dealers, expected_players);
        });
    }

    #[test]
    fn remove_validator_drops_from_next_epoch() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let (mut ledger, owners, validators) = configured().await;
            let removed = validators[0].clone();
            let change = RegistryChange::RemoveValidator {
                validator: removed.clone(),
            };
            let id = proposal_id(&change, 2);
            ledger
                .apply_transaction(
                    &Transaction::sign(
                        &owners[0],
                        1,
                        AuthorityOperation::Propose {
                            change,
                            effective_epoch: 2,
                        },
                    ),
                    2,
                )
                .await
                .unwrap();
            ledger
                .apply_transaction(
                    &Transaction::sign(&owners[1], 0, AuthorityOperation::Approve { proposal: id }),
                    2,
                )
                .await
                .unwrap();
            ledger
                .apply_transaction(
                    &Transaction::sign(&owners[2], 0, AuthorityOperation::Execute { proposal: id }),
                    2,
                )
                .await
                .unwrap();

            let epoch_3 = ledger.epoch_registry(3).await.unwrap().unwrap();
            assert!(!epoch_3.players.contains(&removed));
            assert!(!epoch_3.dealers.contains(&removed));
        });
    }
}
