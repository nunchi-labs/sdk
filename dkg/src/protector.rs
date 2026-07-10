//! Protection for DKG recovery records.
//!
//! # Status
//!
//! This module provides the concrete protector used to seal DKG-owned recovery
//! records before persistence.
//!
//! # Examples
//!
//! ```ignore
//! let protector = StorageProtector::new(dkg_storage_key);
//! let record = protector.seal(plaintext, associated_data, nonce)?;
//! let plaintext = protector.open(&record, associated_data)?;
//! ```

use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_runtime::{Buf, BufMut};

/// DKG storage encryption key.
pub type StorageKey = [u8; 32];

/// Current sealed DKG record format version.
pub const SEALED_RECORD_VERSION: u8 = 0;

/// Nonce size required by the DKG storage protector.
pub const NONCE_SIZE: usize = 12;

/// Errors returned when sealing or opening protected DKG records.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtectionError {
    /// The record was written with an unsupported format version.
    #[error("unsupported sealed record version: {0}")]
    UnsupportedVersion(u8),
    /// AEAD encryption failed.
    #[error("failed to seal dkg record")]
    Seal,
    /// AEAD authentication or decryption failed.
    #[error("failed to open dkg record")]
    Open,
}

/// A sealed DKG record persisted by metadata or journal storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedRecord {
    /// Format version.
    pub version: u8,
    /// AEAD nonce.
    pub nonce: [u8; NONCE_SIZE],
    /// Authenticated ciphertext.
    pub ciphertext: Bytes,
}

impl EncodeSize for SealedRecord {
    fn encode_size(&self) -> usize {
        self.version.encode_size() + self.nonce.encode_size() + self.ciphertext.encode_size()
    }
}

impl Write for SealedRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.nonce.write(buf);
        self.ciphertext.write(buf);
    }
}

impl Read for SealedRecord {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            version: ReadExt::read(buf)?,
            nonce: ReadExt::read(buf)?,
            ciphertext: Bytes::read_cfg(buf, range)?,
        })
    }
}

/// AEAD-backed protector for DKG recovery records.
#[derive(Clone)]
pub struct StorageProtector {
    cipher: ChaCha20Poly1305,
}

impl StorageProtector {
    /// Creates an AEAD protector from a caller-provided DKG storage key.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let protector = StorageProtector::new(dkg_storage_key);
    /// ```
    pub fn new(key: StorageKey) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&key.into()),
        }
    }

    /// Seals plaintext with the supplied associated data and nonce.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let record = protector.seal(plaintext, associated_data, nonce)?;
    /// ```
    pub fn seal(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: [u8; NONCE_SIZE],
    ) -> Result<SealedRecord, ProtectionError> {
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| ProtectionError::Seal)?;

        Ok(SealedRecord {
            version: SEALED_RECORD_VERSION,
            nonce,
            ciphertext: Bytes::from(ciphertext),
        })
    }

    /// Opens a sealed record with the supplied associated data.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let plaintext = protector.open(&record, associated_data)?;
    /// ```
    pub fn open(&self, record: &SealedRecord, ad: &[u8]) -> Result<Bytes, ProtectionError> {
        if record.version != SEALED_RECORD_VERSION {
            return Err(ProtectionError::UnsupportedVersion(record.version));
        }

        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&record.nonce),
                Payload {
                    msg: &record.ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| ProtectionError::Open)?;

        Ok(Bytes::from(plaintext))
    }
}

/// Test-only plaintext protector for storage tests that must inspect records directly.
#[cfg(test)]
pub(crate) struct InsecurePlaintextProtector;

#[cfg(test)]
impl InsecurePlaintextProtector {
    pub(crate) fn seal(
        &self,
        plaintext: &[u8],
        _ad: &[u8],
        nonce: [u8; NONCE_SIZE],
    ) -> SealedRecord {
        SealedRecord {
            version: SEALED_RECORD_VERSION,
            nonce,
            ciphertext: Bytes::copy_from_slice(plaintext),
        }
    }

    pub(crate) fn open(
        &self,
        record: &SealedRecord,
        _ad: &[u8],
    ) -> Result<Bytes, ProtectionError> {
        if record.version != SEALED_RECORD_VERSION {
            return Err(ProtectionError::UnsupportedVersion(record.version));
        }

        Ok(record.ciphertext.clone())
    }
}
