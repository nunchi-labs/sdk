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

/// How far past the current epoch a Configure or Propose may schedule a change.
///
/// Every registry change rematerializes the epoch registries from its effective epoch through the
/// latest epoch ever materialized, so this bound keeps that span (and the refresh cost) small.
pub const MAX_EPOCH_LOOKAHEAD: u64 = 100;

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
    #[error("existing authority genesis state does not match configured genesis")]
    GenesisMismatch,
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

    /// Validate and apply a signed authority transaction.
    ///
    /// Does not re-check the transaction signature: callers must only pass
    /// transactions that already passed stateless verification
    /// ([`Transaction::verify`]), which the chain guarantees at mempool
    /// admission and block verification.
    pub async fn apply_transaction(
        &mut self,
        tx: &Transaction,
        current_epoch: EpochNumber,
    ) -> Result<(), AuthorityError> {
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

    pub(crate) async fn seed_genesis(
        &mut self,
        policy: MultisigPolicy,
        initial_validators: Vec<ValidatorId>,
        epoch: EpochNumber,
    ) -> Result<(), AuthorityError> {
        let initial_validators =
            sorted_unique(initial_validators).ok_or(AuthorityError::InvalidPolicy)?;
        if initial_validators.is_empty() {
            return Err(AuthorityError::InvalidPolicy);
        }

        if let Some(existing) = self.db.policy().await? {
            if existing != policy || self.db.validator_index().await? != initial_validators {
                return Err(AuthorityError::GenesisMismatch);
            }
            let registry = self
                .db
                .epoch_registry(epoch)
                .await?
                .ok_or(AuthorityError::GenesisMismatch)?;
            if registry.players != initial_validators || registry.dealers != initial_validators {
                return Err(AuthorityError::GenesisMismatch);
            }
            return Ok(());
        }

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
        self.refresh_epochs(epoch, epoch).await
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
                self.configure(
                    signer,
                    policy.clone(),
                    initial_validators.clone(),
                    *epoch,
                    current_epoch,
                )
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
            AuthorityOperation::Execute { proposal } => {
                self.execute(signer, proposal, current_epoch).await
            }
        }
    }

    // TODO(@erenyegit): configuration is currently first-come-first-served; whoever lands the
    // first Configure transaction owns the authority set. Pin the policy at genesis once genesis
    // configuration is set up.
    async fn configure(
        &mut self,
        signer: &OwnerId,
        mut policy: MultisigPolicy,
        initial_validators: Vec<ValidatorId>,
        epoch: EpochNumber,
        current_epoch: EpochNumber,
    ) -> Result<(), AuthorityError> {
        if self.db.policy().await?.is_some() {
            return Err(AuthorityError::AlreadyConfigured);
        }
        check_epoch_window(epoch, current_epoch)?;
        policy.owners = sorted_unique(policy.owners).ok_or(AuthorityError::InvalidPolicy)?;
        if policy.threshold == 0 || policy.threshold as usize > policy.owners.len() {
            return Err(AuthorityError::InvalidPolicy);
        }
        if !policy.owners.contains(signer) {
            return Err(AuthorityError::Unauthorized);
        }
        let initial_validators =
            sorted_unique(initial_validators).ok_or(AuthorityError::InvalidPolicy)?;
        if initial_validators.is_empty() {
            return Err(AuthorityError::InvalidPolicy);
        }

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
        self.refresh_epochs(epoch, epoch).await
    }

    async fn propose_change(
        &mut self,
        signer: &OwnerId,
        change: RegistryChange,
        effective_epoch: EpochNumber,
        current_epoch: EpochNumber,
    ) -> Result<ProposalId, AuthorityError> {
        self.require_owner(signer).await?;
        check_epoch_window(effective_epoch, current_epoch)?;
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
        current_epoch: EpochNumber,
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
        // Executing past the effective epoch would rewrite registries consensus may already have
        // consumed; a stale proposal must be re-proposed at a future epoch instead.
        if proposal.proposed_epoch < current_epoch {
            return Err(AuthorityError::InvalidEpoch);
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
        self.refresh_epochs(player_from, dealer_from).await
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
        self.refresh_epochs(removed_from, removed_from).await
    }

    /// Rematerialize the epoch registries for `from..=to`.
    ///
    /// The range is extended through the latest epoch already materialized: a schedule change
    /// affects every epoch at or after it takes effect, so previously written registries would
    /// otherwise go stale. The span is bounded because scheduled epochs are capped by
    /// [`MAX_EPOCH_LOOKAHEAD`].
    async fn refresh_epochs(
        &mut self,
        from: EpochNumber,
        to: EpochNumber,
    ) -> Result<(), AuthorityError> {
        let to = self
            .db
            .latest_indexed_epoch()
            .await?
            .map_or(to, |latest| latest.max(to));
        let mut schedules = Vec::new();
        for validator in self.db.validator_index().await? {
            if let Some(schedule) = self.db.validator(&validator).await? {
                schedules.push(schedule);
            }
        }
        for epoch in from..=to {
            let players = schedules
                .iter()
                .filter(|schedule| schedule.is_player_at(epoch))
                .map(|schedule| schedule.validator.clone())
                .collect();
            let dealers = schedules
                .iter()
                .filter(|schedule| schedule.is_dealer_at(epoch))
                .map(|schedule| schedule.validator.clone())
                .collect();
            self.db.set_epoch_registry(&EpochRegistry {
                epoch,
                players: normalize(players),
                dealers: normalize(dealers),
            });
        }
        self.db.set_latest_indexed_epoch(to);
        Ok(())
    }
}

fn check_epoch_window(
    epoch: EpochNumber,
    current_epoch: EpochNumber,
) -> Result<(), AuthorityError> {
    if epoch < current_epoch || epoch > current_epoch.saturating_add(MAX_EPOCH_LOOKAHEAD) {
        return Err(AuthorityError::InvalidEpoch);
    }
    Ok(())
}

pub fn proposal_id(change: &RegistryChange, proposed_epoch: EpochNumber) -> ProposalId {
    let mut bytes = change.encode().as_ref().to_vec();
    bytes.extend_from_slice(proposed_epoch.encode().as_ref());
    Sha256::hash(&bytes)
}
