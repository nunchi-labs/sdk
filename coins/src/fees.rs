//! Chain-level transaction fee configuration.
//!
//! # Status
//!
//! Fees are charged by the chain runtime before module dispatch, against the transaction's
//! authorizing account. The fee for a transaction is a deterministic function of its canonical
//! encoded size and the [`FeeConfig`] pinned at genesis, so a signer always knows the exact fee
//! before signing. Chains without a stored [`FeeConfig`] charge nothing.

use super::{Address, CoinId, LedgerError};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};

/// Fee policy stored in the coin module's namespace and applied to every transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeConfig {
    /// Coin fees are paid in.
    pub coin: CoinId,
    /// Account credited with collected fees.
    pub collector: Address,
    /// Flat fee charged per transaction.
    pub base: u128,
    /// Fee charged per canonical encoded transaction byte.
    pub per_byte: u128,
}

impl FeeConfig {
    /// The deterministic fee for a transaction of `encoded_size` canonical bytes.
    pub fn quote(&self, encoded_size: usize) -> Result<u128, LedgerError> {
        let size = u128::try_from(encoded_size).map_err(|_| LedgerError::FeeOverflow)?;
        self.per_byte
            .checked_mul(size)
            .and_then(|scaled| scaled.checked_add(self.base))
            .ok_or(LedgerError::FeeOverflow)
    }
}

impl Write for FeeConfig {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.coin.write(buf);
        self.collector.write(buf);
        self.base.write(buf);
        self.per_byte.write(buf);
    }
}

impl Read for FeeConfig {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            coin: CoinId::read(buf)?,
            collector: Address::read(buf)?,
            base: u128::read(buf)?,
            per_byte: u128::read(buf)?,
        })
    }
}

impl EncodeSize for FeeConfig {
    fn encode_size(&self) -> usize {
        self.coin.encode_size()
            + self.collector.encode_size()
            + self.base.encode_size()
            + self.per_byte.encode_size()
    }
}
