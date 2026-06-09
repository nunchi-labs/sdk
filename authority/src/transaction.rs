use crate::{types::RegistryChange, AUTHORITY_NAMESPACE};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_common::Operation as CommonOperation;

const OP_CONFIGURE: u8 = 0;
const OP_PROPOSE: u8 = 1;
const OP_APPROVE: u8 = 2;
const OP_EXECUTE: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityOperation {
    Configure {
        policy: crate::MultisigPolicy,
        initial_validators: Vec<crate::ValidatorId>,
        epoch: crate::EpochNumber,
    },
    Propose {
        change: RegistryChange,
        effective_epoch: crate::EpochNumber,
    },
    Approve {
        proposal: Digest,
    },
    Execute {
        proposal: Digest,
    },
}

impl Write for AuthorityOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Configure {
                policy,
                initial_validators,
                epoch,
            } => {
                OP_CONFIGURE.write(buf);
                policy.write(buf);
                commonware_codec::varint::UInt(initial_validators.len() as u64).write(buf);
                for validator in initial_validators {
                    validator.write(buf);
                }
                epoch.write(buf);
            }
            Self::Propose {
                change,
                effective_epoch,
            } => {
                OP_PROPOSE.write(buf);
                change.write(buf);
                effective_epoch.write(buf);
            }
            Self::Approve { proposal } => {
                OP_APPROVE.write(buf);
                proposal.write(buf);
            }
            Self::Execute { proposal } => {
                OP_EXECUTE.write(buf);
                proposal.write(buf);
            }
        }
    }
}

impl Read for AuthorityOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            OP_CONFIGURE => {
                let policy = crate::MultisigPolicy::read(buf)?;
                let count = commonware_codec::varint::UInt::<u64>::read(buf)?.0;
                let mut initial_validators = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    initial_validators.push(crate::ValidatorId::read(buf)?);
                }
                Ok(Self::Configure {
                    policy,
                    initial_validators,
                    epoch: crate::EpochNumber::read(buf)?,
                })
            }
            OP_PROPOSE => Ok(Self::Propose {
                change: RegistryChange::read(buf)?,
                effective_epoch: crate::EpochNumber::read(buf)?,
            }),
            OP_APPROVE => Ok(Self::Approve {
                proposal: Digest::read(buf)?,
            }),
            OP_EXECUTE => Ok(Self::Execute {
                proposal: Digest::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for AuthorityOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Configure {
                policy,
                initial_validators,
                epoch,
            } => {
                policy.encode_size()
                    + commonware_codec::varint::UInt(initial_validators.len() as u64).encode_size()
                    + initial_validators
                        .iter()
                        .map(EncodeSize::encode_size)
                        .sum::<usize>()
                    + epoch.encode_size()
            }
            Self::Propose {
                change,
                effective_epoch,
            } => change.encode_size() + effective_epoch.encode_size(),
            Self::Approve { proposal } | Self::Execute { proposal } => proposal.encode_size(),
        }
    }
}

impl CommonOperation for AuthorityOperation {
    const NAMESPACE: &'static [u8] = AUTHORITY_NAMESPACE;
}

pub type TransactionPayload = nunchi_common::TransactionPayload<AuthorityOperation>;
pub type Transaction = nunchi_common::Transaction<AuthorityOperation>;
