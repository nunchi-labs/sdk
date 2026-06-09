use commonware_codec::{varint::UInt, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{ed25519, sha256::Digest};
use nunchi_crypto::PublicKey;

pub type EpochNumber = u64;
pub type OwnerId = PublicKey;
pub type ValidatorId = ed25519::PublicKey;
pub type ProposalId = Digest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultisigPolicy {
    pub owners: Vec<OwnerId>,
    pub threshold: u16,
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

pub(crate) fn normalize<T: Ord>(mut values: Vec<T>) -> Vec<T> {
    values.sort();
    values.dedup();
    values
}

fn write_vec<T: Write>(values: &[T], buf: &mut impl bytes::BufMut) {
    UInt(values.len() as u64).write(buf);
    for value in values {
        value.write(buf);
    }
}

fn read_vec<T: Read<Cfg = ()>>(buf: &mut impl bytes::Buf) -> Result<Vec<T>, Error> {
    let count = UInt::<u64>::read(buf)?.0;
    let mut values = Vec::with_capacity(count as usize);
    for _ in 0..count {
        values.push(T::read(buf)?);
    }
    Ok(values)
}

fn vec_size<T: EncodeSize>(values: &[T]) -> usize {
    UInt(values.len() as u64).encode_size()
        + values.iter().map(EncodeSize::encode_size).sum::<usize>()
}

impl Write for MultisigPolicy {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        write_vec(&self.owners, buf);
        self.threshold.write(buf);
    }
}

impl Read for MultisigPolicy {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            owners: read_vec(buf)?,
            threshold: u16::read(buf)?,
        })
    }
}

impl EncodeSize for MultisigPolicy {
    fn encode_size(&self) -> usize {
        vec_size(&self.owners) + self.threshold.encode_size()
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
        write_vec(&self.approvals, buf);
        (self.executed as u8).write(buf);
    }
}

impl Read for Proposal {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let id = ProposalId::read(buf)?;
        let change = RegistryChange::read(buf)?;
        let proposed_epoch = EpochNumber::read(buf)?;
        let approvals = read_vec(buf)?;
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
            + vec_size(&self.approvals)
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
        write_vec(&self.players, buf);
        write_vec(&self.dealers, buf);
    }
}

impl Read for EpochRegistry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            epoch: EpochNumber::read(buf)?,
            players: read_vec(buf)?,
            dealers: read_vec(buf)?,
        })
    }
}

impl EncodeSize for EpochRegistry {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + vec_size(&self.players) + vec_size(&self.dealers)
    }
}
