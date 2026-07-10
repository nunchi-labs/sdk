use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{ed25519, sha256::Digest};
use nunchi_common::MAX_MULTISIG_SIGNERS;
use nunchi_crypto::PublicKey;

/// Maximum number of validators accepted in a wire-decoded list.
pub const MAX_VALIDATORS: usize = 1024;

pub type EpochNumber = u64;
pub type OwnerId = PublicKey;
pub type ValidatorId = ed25519::PublicKey;
pub type ProposalId = Digest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultisigPolicy {
    pub owners: Vec<OwnerId>,
    pub threshold: u16,
}

impl MultisigPolicy {
    pub fn new(threshold: u16, owners: Vec<OwnerId>) -> Option<Self> {
        let owners = sorted_unique(owners)?;
        if threshold == 0 || threshold as usize > owners.len() {
            return None;
        }
        Some(Self { owners, threshold })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryChange {
    AddValidator { validator: ValidatorId },
    RemoveValidator { validator: ValidatorId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: ProposalId,
    pub change: RegistryChange,
    pub proposed_epoch: EpochNumber,
    pub approvals: Vec<OwnerId>,
    pub executed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorSchedule {
    pub validator: ValidatorId,
    pub player_from: EpochNumber,
    pub dealer_from: EpochNumber,
    pub removed_from: Option<EpochNumber>,
}

impl ValidatorSchedule {
    pub fn is_player_at(&self, epoch: EpochNumber) -> bool {
        epoch >= self.player_from && self.removed_from.is_none_or(|removed| epoch < removed)
    }

    pub fn is_dealer_at(&self, epoch: EpochNumber) -> bool {
        epoch >= self.dealer_from && self.removed_from.is_none_or(|removed| epoch < removed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochRegistry {
    pub epoch: EpochNumber,
    pub players: Vec<ValidatorId>,
    pub dealers: Vec<ValidatorId>,
}

pub(crate) fn sorted_unique<T: Ord>(mut values: Vec<T>) -> Option<Vec<T>> {
    values.sort();
    let original = values.len();
    values.dedup();
    (values.len() == original).then_some(values)
}

#[cfg(feature = "state")]
pub(crate) fn normalize<T: Ord>(mut values: Vec<T>) -> Vec<T> {
    values.sort();
    values.dedup();
    values
}

/// Codec config for vectors decoded only from trusted local storage, never the wire.
pub(crate) fn stored_vec_cfg() -> (RangeCfg<usize>, ()) {
    (RangeCfg::from(..), ())
}

impl Write for MultisigPolicy {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.owners.write(buf);
        self.threshold.write(buf);
    }
}

impl Read for MultisigPolicy {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            // Policies arrive on the wire inside Configure, so the owner list is bounded.
            owners: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_MULTISIG_SIGNERS), ()))?,
            threshold: u16::read(buf)?,
        })
    }
}

impl EncodeSize for MultisigPolicy {
    fn encode_size(&self) -> usize {
        self.owners.encode_size() + self.threshold.encode_size()
    }
}

impl Write for RegistryChange {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::AddValidator { validator } => {
                0u8.write(buf);
                validator.write(buf);
            }
            Self::RemoveValidator { validator } => {
                1u8.write(buf);
                validator.write(buf);
            }
        }
    }
}

impl Read for RegistryChange {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::AddValidator {
                validator: ValidatorId::read(buf)?,
            }),
            1 => Ok(Self::RemoveValidator {
                validator: ValidatorId::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for RegistryChange {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::AddValidator { validator } | Self::RemoveValidator { validator } => {
                validator.encode_size()
            }
        }
    }
}

impl Write for Proposal {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.change.write(buf);
        self.proposed_epoch.write(buf);
        self.approvals.write(buf);
        (self.executed as u8).write(buf);
    }
}

impl Read for Proposal {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let id = ProposalId::read(buf)?;
        let change = RegistryChange::read(buf)?;
        let proposed_epoch = EpochNumber::read(buf)?;
        let approvals = Vec::read_cfg(buf, &stored_vec_cfg())?;
        let executed = match u8::read(buf)? {
            0 => false,
            1 => true,
            tag => return Err(Error::InvalidEnum(tag)),
        };
        Ok(Self {
            id,
            change,
            proposed_epoch,
            approvals,
            executed,
        })
    }
}

impl EncodeSize for Proposal {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.change.encode_size()
            + self.proposed_epoch.encode_size()
            + self.approvals.encode_size()
            + 1
    }
}

impl Write for ValidatorSchedule {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.validator.write(buf);
        self.player_from.write(buf);
        self.dealer_from.write(buf);
        match self.removed_from {
            Some(epoch) => {
                1u8.write(buf);
                epoch.write(buf);
            }
            None => 0u8.write(buf),
        }
    }
}

impl Read for ValidatorSchedule {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let validator = ValidatorId::read(buf)?;
        let player_from = EpochNumber::read(buf)?;
        let dealer_from = EpochNumber::read(buf)?;
        let removed_from = match u8::read(buf)? {
            0 => None,
            1 => Some(EpochNumber::read(buf)?),
            tag => return Err(Error::InvalidEnum(tag)),
        };
        Ok(Self {
            validator,
            player_from,
            dealer_from,
            removed_from,
        })
    }
}

impl EncodeSize for ValidatorSchedule {
    fn encode_size(&self) -> usize {
        self.validator.encode_size()
            + self.player_from.encode_size()
            + self.dealer_from.encode_size()
            + 1
            + self.removed_from.map_or(0, |epoch| epoch.encode_size())
    }
}

impl Write for EpochRegistry {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.epoch.write(buf);
        self.players.write(buf);
        self.dealers.write(buf);
    }
}

impl Read for EpochRegistry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            epoch: EpochNumber::read(buf)?,
            players: Vec::read_cfg(buf, &stored_vec_cfg())?,
            dealers: Vec::read_cfg(buf, &stored_vec_cfg())?,
        })
    }
}

impl EncodeSize for EpochRegistry {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.players.encode_size() + self.dealers.encode_size()
    }
}
