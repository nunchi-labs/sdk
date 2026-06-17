//! Coins-chain runtime transaction enum and execution dispatch.

use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_authority::{AuthorityError, AuthorityLedger};
use nunchi_coins::{Ledger, LedgerError};
use nunchi_common::{Address, PoolTransaction, Runtime, RuntimeContext, StateStore};

const TX_COINS: u8 = 0;
const TX_AUTHORITY: u8 = 1;

#[derive(Clone, Copy, Debug, Default)]
pub struct CoinsRuntime;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeTransaction {
    Coins(nunchi_coins::Transaction),
    Authority(nunchi_authority::Transaction),
}

impl From<nunchi_coins::Transaction> for RuntimeTransaction {
    fn from(transaction: nunchi_coins::Transaction) -> Self {
        Self::Coins(transaction)
    }
}

impl From<nunchi_authority::Transaction> for RuntimeTransaction {
    fn from(transaction: nunchi_authority::Transaction) -> Self {
        Self::Authority(transaction)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("coins module error: {0}")]
    Coins(#[from] LedgerError),
    #[error("authority module error: {0}")]
    Authority(#[from] AuthorityError),
}

impl RuntimeError {
    pub fn is_storage(&self) -> bool {
        matches!(
            self,
            Self::Coins(LedgerError::Storage(_)) | Self::Authority(AuthorityError::Storage(_))
        )
    }
}

impl Runtime for CoinsRuntime {
    type Transaction = RuntimeTransaction;
    type Error = RuntimeError;

    async fn validate<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        apply_transaction(state, context, transaction).await
    }

    async fn apply<S>(
        state: &mut S,
        context: RuntimeContext,
        transaction: &Self::Transaction,
    ) -> Result<(), Self::Error>
    where
        S: StateStore + Send + Sync,
    {
        apply_transaction(state, context, transaction).await
    }

    fn is_storage_error(error: &Self::Error) -> bool {
        error.is_storage()
    }
}

async fn apply_transaction<S>(
    state: &mut S,
    context: RuntimeContext,
    transaction: &RuntimeTransaction,
) -> Result<(), RuntimeError>
where
    S: StateStore + Send + Sync,
{
    match transaction {
        RuntimeTransaction::Coins(transaction) => {
            let mut ledger = Ledger::new(state);
            ledger.apply_transaction(transaction).await?;
        }
        RuntimeTransaction::Authority(transaction) => {
            let mut ledger = AuthorityLedger::new(state);
            ledger.apply_transaction(transaction, context.epoch).await?;
        }
    }
    Ok(())
}

impl PoolTransaction for RuntimeTransaction {
    type VerificationError = nunchi_crypto::SignatureError;

    fn digest(&self) -> Digest {
        match self {
            Self::Coins(transaction) => transaction.digest(),
            Self::Authority(transaction) => transaction.digest(),
        }
    }

    fn verify(&self) -> Result<(), Self::VerificationError> {
        match self {
            Self::Coins(transaction) => transaction.verify(),
            Self::Authority(transaction) => transaction.verify(),
        }
    }

    fn account_id(&self) -> &Address {
        match self {
            Self::Coins(transaction) => &transaction.account_id,
            Self::Authority(transaction) => &transaction.account_id,
        }
    }

    fn nonce(&self) -> u64 {
        match self {
            Self::Coins(transaction) => transaction.payload.nonce,
            Self::Authority(transaction) => transaction.payload.nonce,
        }
    }
}

impl Write for RuntimeTransaction {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Coins(transaction) => {
                TX_COINS.write(buf);
                transaction.write(buf);
            }
            Self::Authority(transaction) => {
                TX_AUTHORITY.write(buf);
                transaction.write(buf);
            }
        }
    }
}

impl Read for RuntimeTransaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            TX_COINS => Ok(Self::Coins(nunchi_coins::Transaction::read(buf)?)),
            TX_AUTHORITY => Ok(Self::Authority(nunchi_authority::Transaction::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for RuntimeTransaction {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Coins(transaction) => transaction.encode_size(),
            Self::Authority(transaction) => transaction.encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{ed25519, Signer as _};
    use nunchi_authority::{AuthorityOperation, MultisigPolicy};
    use nunchi_coins::{CoinOperation, CoinSpec, PrivateKey};

    fn coin_transaction(seed: u64, nonce: u64) -> nunchi_coins::Transaction {
        let signer = PrivateKey::ed25519_from_seed(seed);
        nunchi_coins::Transaction::sign(
            &signer,
            nonce,
            CoinOperation::CreateToken {
                spec: CoinSpec::new("NCH", "Nunchi", 9, 1_000, None),
            },
        )
    }

    fn authority_transaction(seed: u64, nonce: u64) -> nunchi_authority::Transaction {
        let owner = nunchi_crypto::PrivateKey::ed25519_from_seed(seed);
        nunchi_authority::Transaction::sign(
            &owner,
            nonce,
            AuthorityOperation::Configure {
                policy: MultisigPolicy {
                    owners: vec![owner.public_key()],
                    threshold: 1,
                },
                initial_validators: vec![ed25519::PrivateKey::from_seed(seed).public_key()],
                epoch: 0,
            },
        )
    }

    #[test]
    fn runtime_transaction_codec_uses_stable_tags() {
        let coins = RuntimeTransaction::from(coin_transaction(1, 3));
        let authority = RuntimeTransaction::from(authority_transaction(2, 4));

        let coins_encoded = coins.encode();
        let authority_encoded = authority.encode();

        assert_eq!(coins_encoded[0], TX_COINS);
        assert_eq!(authority_encoded[0], TX_AUTHORITY);
        assert_eq!(RuntimeTransaction::decode(coins_encoded).unwrap(), coins);
        assert_eq!(
            RuntimeTransaction::decode(authority_encoded).unwrap(),
            authority
        );
        assert!(RuntimeTransaction::decode([99].as_slice()).is_err());
    }

    #[test]
    fn pool_transaction_forwards_to_inner_transaction() {
        let inner = coin_transaction(3, 7);
        let runtime = RuntimeTransaction::from(inner.clone());

        assert_eq!(runtime.digest(), inner.digest());
        assert_eq!(runtime.account_id(), &inner.account_id);
        assert_eq!(runtime.nonce(), inner.payload.nonce);
        assert!(runtime.verify().is_ok());
    }

    #[test]
    fn runtime_error_classifies_storage_errors() {
        assert!(RuntimeError::Coins(LedgerError::Storage("disk".into())).is_storage());
        assert!(RuntimeError::Authority(AuthorityError::Storage("disk".into())).is_storage());

        assert!(!RuntimeError::Authority(AuthorityError::NotConfigured).is_storage());
        assert!(!RuntimeError::Coins(LedgerError::InvalidTokenSpec("bad")).is_storage());
    }
}
