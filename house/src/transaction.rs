use crate::{Mode, VaultId, VaultPolicy, HOUSE_NAMESPACE};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::{Address, Operation as CommonOperation};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationTag {
    CreateVault = 0,
    Deposit = 1,
    Withdraw = 2,
    SetVaultPolicy = 3,
    SetAuthorizedSubmitter = 4,
    SetVaultMode = 5,
}

impl TryFrom<u8> for OperationTag {
    type Error = Error;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::CreateVault),
            1 => Ok(Self::Deposit),
            2 => Ok(Self::Withdraw),
            3 => Ok(Self::SetVaultPolicy),
            4 => Ok(Self::SetAuthorizedSubmitter),
            5 => Ok(Self::SetVaultMode),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// House state-machine operation carried by a signed Nunchi transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HouseOperation {
    /// Create a vault owned by the signer.
    CreateVault { policy: VaultPolicy },
    /// Credit quote capital to a vault owned by the signer.
    Deposit { vault: VaultId, amount: u128 },
    /// Debit free quote capital from a vault owned by the signer.
    Withdraw { vault: VaultId, amount: u128 },
    /// Replace the policy of a vault owned by the signer.
    SetVaultPolicy { vault: VaultId, policy: VaultPolicy },
    /// Enable or disable a submitter key for a vault owned by the signer.
    SetAuthorizedSubmitter {
        vault: VaultId,
        submitter: Address,
        enabled: bool,
    },
    /// Change the operating mode of a vault owned by the signer.
    SetVaultMode { vault: VaultId, mode: Mode },
}

impl Write for HouseOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::CreateVault { policy } => {
                (OperationTag::CreateVault as u8).write(buf);
                policy.write(buf);
            }
            Self::Deposit { vault, amount } => {
                (OperationTag::Deposit as u8).write(buf);
                vault.write(buf);
                amount.write(buf);
            }
            Self::Withdraw { vault, amount } => {
                (OperationTag::Withdraw as u8).write(buf);
                vault.write(buf);
                amount.write(buf);
            }
            Self::SetVaultPolicy { vault, policy } => {
                (OperationTag::SetVaultPolicy as u8).write(buf);
                vault.write(buf);
                policy.write(buf);
            }
            Self::SetAuthorizedSubmitter {
                vault,
                submitter,
                enabled,
            } => {
                (OperationTag::SetAuthorizedSubmitter as u8).write(buf);
                vault.write(buf);
                submitter.write(buf);
                enabled.write(buf);
            }
            Self::SetVaultMode { vault, mode } => {
                (OperationTag::SetVaultMode as u8).write(buf);
                vault.write(buf);
                mode.write(buf);
            }
        }
    }
}

impl Read for HouseOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match OperationTag::try_from(u8::read(buf)?)? {
            OperationTag::CreateVault => Ok(Self::CreateVault {
                policy: VaultPolicy::read(buf)?,
            }),
            OperationTag::Deposit => Ok(Self::Deposit {
                vault: VaultId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OperationTag::Withdraw => Ok(Self::Withdraw {
                vault: VaultId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OperationTag::SetVaultPolicy => Ok(Self::SetVaultPolicy {
                vault: VaultId::read(buf)?,
                policy: VaultPolicy::read(buf)?,
            }),
            OperationTag::SetAuthorizedSubmitter => Ok(Self::SetAuthorizedSubmitter {
                vault: VaultId::read(buf)?,
                submitter: Address::read(buf)?,
                enabled: bool::read(buf)?,
            }),
            OperationTag::SetVaultMode => Ok(Self::SetVaultMode {
                vault: VaultId::read(buf)?,
                mode: Mode::read(buf)?,
            }),
        }
    }
}

impl EncodeSize for HouseOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::CreateVault { policy } => policy.encode_size(),
            Self::Deposit { vault, amount } | Self::Withdraw { vault, amount } => {
                vault.encode_size() + amount.encode_size()
            }
            Self::SetVaultPolicy { vault, policy } => vault.encode_size() + policy.encode_size(),
            Self::SetAuthorizedSubmitter {
                vault,
                submitter,
                enabled,
            } => vault.encode_size() + submitter.encode_size() + enabled.encode_size(),
            Self::SetVaultMode { vault, mode } => vault.encode_size() + mode.encode_size(),
        }
    }
}

impl CommonOperation for HouseOperation {
    const NAMESPACE: &'static [u8] = HOUSE_NAMESPACE;
}

/// Signed house transaction payload.
pub type TransactionPayload = nunchi_common::TransactionPayload<HouseOperation>;
/// Signed house transaction.
pub type Transaction = nunchi_common::Transaction<HouseOperation>;
