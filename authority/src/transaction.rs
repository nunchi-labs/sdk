use crate::{types::RegistryChange, AUTHORITY_NAMESPACE, MAX_VALIDATORS};
use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_common::Operation as CommonOperation;

const OP_CONFIGURE: u8 = 0;
const OP_PROPOSE: u8 = 1;
const OP_APPROVE: u8 = 2;
const OP_EXECUTE: u8 = 3;

/// A governance operation applied to the authority validator registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityOperation {
    /// Installs the owner policy and initial validator set for an unconfigured registry.
    ///
    /// This first configuration is first-come-first-served until the chain's genesis is pinned.
    Configure {
        policy: crate::MultisigPolicy,
        initial_validators: Vec<crate::ValidatorId>,
        epoch: crate::EpochNumber,
    },
    /// Proposes adding or removing a validator at a future epoch.
    ///
    /// The submitting owner automatically records an approval for the proposal.
    Propose {
        change: RegistryChange,
        effective_epoch: crate::EpochNumber,
    },
    /// Records an owner approval for an existing proposal.
    Approve {
        proposal: Digest,
    },
    /// Applies an approved proposal at its configured effective epoch.
    ///
    /// The submitting owner must provide the approvals required by the configured policy.
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
                initial_validators.write(buf);
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
                let initial_validators =
                    Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_VALIDATORS), ()))?;
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
            } => policy.encode_size() + initial_validators.encode_size() + epoch.encode_size(),
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

/// An authority-specific transaction payload re-exported from `nunchi_common`.
pub type TransactionPayload = nunchi_common::TransactionPayload<AuthorityOperation>;

/// An authority-specific signed transaction re-exported from `nunchi_common`.
pub type Transaction = nunchi_common::Transaction<AuthorityOperation>;
