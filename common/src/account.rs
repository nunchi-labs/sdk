use commonware_codec::{Encode, EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use nunchi_crypto::{Curve, PublicKey};
use thiserror::Error;

const ACCOUNT_TYPE_EXTERNAL: u8 = 0;
const ACCOUNT_TYPE_MULTISIG: u8 = 1;

/// Authorization scheme expected for an account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountType {
    External,
    Multisig,
}

impl Write for AccountType {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::External => ACCOUNT_TYPE_EXTERNAL.write(buf),
            Self::Multisig => ACCOUNT_TYPE_MULTISIG.write(buf),
        }
    }
}

impl Read for AccountType {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            ACCOUNT_TYPE_EXTERNAL => Ok(Self::External),
            ACCOUNT_TYPE_MULTISIG => Ok(Self::Multisig),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for AccountType {
    fn encode_size(&self) -> usize {
        1
    }
}

/// Maximum number of signers a threshold multisig policy can carry.
pub const MAX_MULTISIG_SIGNERS: usize = 256;

/// A threshold multisig policy over Nunchi public keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultisigPolicy {
    threshold: u16,
    signers: Vec<PublicKey>,
}

impl MultisigPolicy {
    pub fn new(threshold: u16, mut signers: Vec<PublicKey>) -> Result<Self, AccountPolicyError> {
        if threshold == 0 {
            return Err(AccountPolicyError::ZeroThreshold);
        }
        if signers.len() > MAX_MULTISIG_SIGNERS {
            return Err(AccountPolicyError::TooManySigners {
                max: MAX_MULTISIG_SIGNERS,
                actual: signers.len(),
            });
        }
        if threshold as usize > signers.len() {
            return Err(AccountPolicyError::ThresholdExceedsSigners {
                threshold,
                signers: signers.len(),
            });
        }
        if signers
            .iter()
            .any(|signer| signer.curve() == Curve::Synthetic)
        {
            return Err(AccountPolicyError::SyntheticSigner);
        }

        let original_signers = signers.len();
        signers.sort_by_cached_key(|signer| signer.encode().as_ref().to_vec());
        signers.dedup();
        if signers.len() != original_signers {
            return Err(AccountPolicyError::DuplicateSigner);
        }

        Ok(Self { threshold, signers })
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn signers(&self) -> &[PublicKey] {
        &self.signers
    }

    pub fn contains(&self, signer: &PublicKey) -> bool {
        self.signers.iter().any(|candidate| candidate == signer)
    }
}

impl Write for MultisigPolicy {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.threshold.write(buf);
        self.signers.write(buf);
    }
}

impl Read for MultisigPolicy {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let threshold = u16::read(buf)?;
        let signers =
            Vec::<PublicKey>::read_cfg(buf, &(RangeCfg::new(0..=MAX_MULTISIG_SIGNERS), ()))?;
        Self::new(threshold, signers).map_err(|_| Error::Invalid("multisig policy", "invalid"))
    }
}

impl EncodeSize for MultisigPolicy {
    fn encode_size(&self) -> usize {
        self.threshold.encode_size() + self.signers.encode_size()
    }
}

/// Invalid account policy configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AccountPolicyError {
    #[error("multisig threshold must be greater than zero")]
    ZeroThreshold,
    #[error("multisig threshold {threshold} exceeds signer count {signers}")]
    ThresholdExceedsSigners { threshold: u16, signers: usize },
    #[error("multisig signers must be unique")]
    DuplicateSigner,
    #[error("synthetic account identifiers cannot be multisig signers")]
    SyntheticSigner,
    #[error("multisig has {actual} signers, but the maximum is {max}")]
    TooManySigners { max: usize, actual: usize },
}
