use crate::{
    multisig_account_id, AccountPolicy, Address, CoinDB, CoinId, CoinSpec, Ledger, LedgerError,
    MultisigPolicy,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_formatting::{from_hex, hex};
use nunchi_crypto::PublicKey;
use serde::{Deserialize, Serialize};

/// JSON-facing coin module genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoinsGenesis {
    /// Multisig account policies to register before token creation.
    #[serde(default)]
    pub account_policies: Vec<AccountPolicyGenesis>,
    /// Tokens to create and optionally distribute at genesis.
    #[serde(default)]
    pub tokens: Vec<TokenGenesis>,
}

/// JSON-facing account policy registration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountPolicyGenesis {
    /// Hex-encoded [`Address`]. Must equal `Address::multisig(policy)`.
    pub account_id: String,
    /// Multisig policy registered at `account_id`.
    pub policy: MultisigPolicyGenesis,
}

/// JSON-facing multisig policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultisigPolicyGenesis {
    /// Number of signers required.
    pub threshold: u16,
    /// Multisig signers, encoded as hex in JSON.
    #[serde(with = "serde_hex_vec")]
    pub signers: Vec<PublicKey>,
}

/// JSON-facing token creation request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenGenesis {
    /// Hex-encoded issuer [`Address`].
    pub issuer: String,
    /// Token creation spec. This is passed through [`crate::TokenFactory`].
    pub spec: CoinSpec,
    /// Optional initial distribution. If present, amounts must sum to `spec.initial_supply`.
    #[serde(default)]
    pub allocations: Vec<AllocationGenesis>,
}

/// JSON-facing balance allocation for a token created in the same genesis entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AllocationGenesis {
    /// Hex-encoded recipient [`Address`].
    pub account: String,
    pub amount: u128,
}

impl MultisigPolicyGenesis {
    pub fn policy(&self) -> Result<MultisigPolicy, LedgerError> {
        MultisigPolicy::new(self.threshold, self.signers.clone())
            .map_err(LedgerError::InvalidAccountPolicy)
    }
}

impl<D: CoinDB> Ledger<D> {
    /// Seed coin state from genesis while preserving ledger invariants.
    pub async fn apply_genesis(&mut self, genesis: &CoinsGenesis) -> Result<(), LedgerError> {
        for account in &genesis.account_policies {
            let account_id = decode_hex::<Address>(&account.account_id, "account id")?;
            let policy = account.policy.policy()?;
            if account_id != multisig_account_id(&policy) {
                return Err(LedgerError::AccountPolicyMismatch(Box::new(account_id)));
            }
            self.register_account_policy(account_id, AccountPolicy::Multisig(policy))
                .await?;
        }

        for token in &genesis.tokens {
            let issuer = decode_hex::<Address>(&token.issuer, "token issuer")?;
            let coin = self
                .create_token(issuer.clone(), token.spec.clone())
                .await?;
            self.apply_allocations(issuer, coin, token.spec.initial_supply, &token.allocations)
                .await?;
        }

        Ok(())
    }

    async fn apply_allocations(
        &mut self,
        issuer: Address,
        coin: CoinId,
        initial_supply: u128,
        allocations: &[AllocationGenesis],
    ) -> Result<(), LedgerError> {
        if allocations.is_empty() {
            return Ok(());
        }

        let mut total = 0u128;
        for allocation in allocations {
            if allocation.amount == 0 {
                return Err(LedgerError::InvalidAmount);
            }
            total = total
                .checked_add(allocation.amount)
                .ok_or(LedgerError::BalanceOverflow)?;
        }
        if total != initial_supply {
            return Err(LedgerError::AllocationSumMismatch {
                expected: initial_supply,
                actual: total,
            });
        }

        if initial_supply > 0 {
            self.debit(&issuer, coin, initial_supply).await?;
        }
        for allocation in allocations {
            let account = decode_hex::<Address>(&allocation.account, "allocation account")?;
            self.credit(&account, coin, allocation.amount).await?;
        }
        Ok(())
    }
}

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, LedgerError>
where
    T: DecodeExt<()>,
{
    let bytes =
        from_hex(value).ok_or_else(|| LedgerError::InvalidGenesis(format!("invalid {what}")))?;
    T::decode(bytes.as_ref())
        .map_err(|err| LedgerError::InvalidGenesis(format!("invalid {what}: {err}")))
}

mod serde_hex_vec {
    use super::*;
    use serde::{de::Error as _, Deserializer, Serializer};

    pub fn serialize<T, S>(value: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encode,
        S: Serializer,
    {
        serializer.collect_seq(value.iter().map(|item| hex(&item.encode())))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: DecodeExt<()>,
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        values
            .into_iter()
            .map(|value| {
                let bytes = from_hex(&value)
                    .ok_or_else(|| D::Error::custom("expected hex-encoded codec bytes"))?;
                T::decode(bytes.as_ref()).map_err(D::Error::custom)
            })
            .collect()
    }
}
