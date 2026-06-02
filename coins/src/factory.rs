use super::{AccountId, CoinId, CoinSpec, LedgerError, TokenDefinition, COINS_NAMESPACE};
use commonware_codec::{Encode, EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::{Hasher, Sha256};

/// Deterministic token factory used by the coin ledger.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenFactory {
    next_nonce: u64,
}

impl TokenFactory {
    pub fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    pub fn derive_coin_id(issuer: &AccountId, nonce: u64, spec: &CoinSpec) -> CoinId {
        let mut hasher = Sha256::new();
        hasher.update(COINS_NAMESPACE);
        hasher.update(&issuer.encode());
        hasher.update(&nonce.encode());
        hasher.update(&spec.encode());
        CoinId(hasher.finalize())
    }

    pub fn create(
        &mut self,
        issuer: AccountId,
        spec: CoinSpec,
    ) -> Result<TokenDefinition, LedgerError> {
        validate_spec(&spec)?;
        let nonce = self.next_nonce;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or(LedgerError::NonceOverflow)?;
        let id = Self::derive_coin_id(&issuer, nonce, &spec);
        Ok(TokenDefinition::from_spec(id, issuer, spec))
    }
}

fn validate_spec(spec: &CoinSpec) -> Result<(), LedgerError> {
    if spec.symbol.is_empty() {
        return Err(LedgerError::InvalidTokenSpec("symbol cannot be empty"));
    }
    if spec.symbol.len() > super::MAX_SYMBOL_BYTES {
        return Err(LedgerError::InvalidTokenSpec("symbol is too long"));
    }
    if spec.name.is_empty() {
        return Err(LedgerError::InvalidTokenSpec("name cannot be empty"));
    }
    if spec.name.len() > super::MAX_NAME_BYTES {
        return Err(LedgerError::InvalidTokenSpec("name is too long"));
    }
    if let Some(max_supply) = spec.max_supply {
        if spec.initial_supply > max_supply {
            return Err(LedgerError::MaxSupplyExceeded {
                max: max_supply,
                attempted: spec.initial_supply,
            });
        }
    }
    Ok(())
}

impl Write for TokenFactory {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.next_nonce.write(buf);
    }
}

impl Read for TokenFactory {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            next_nonce: u64::read(buf)?,
        })
    }
}

impl EncodeSize for TokenFactory {
    fn encode_size(&self) -> usize {
        self.next_nonce.encode_size()
    }
}
