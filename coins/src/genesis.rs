use crate::{
    multisig_account_id, AccountPolicy, Address, CoinDB, CoinId, CoinSpec, FeeConfig, Ledger,
    LedgerError, MultisigPolicy,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_formatting::{from_hex, hex};
use nunchi_crypto::PublicKey;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

/// JSON-facing coin module genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoinsGenesis {
    /// Multisig account policies to register before token creation.
    #[serde(default)]
    pub account_policies: Vec<AccountPolicyGenesis>,
    /// Tokens to create and optionally distribute at genesis.
    #[serde(default)]
    pub tokens: Vec<TokenGenesis>,
    /// Optional transaction fee policy. Chains without one charge no fees.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fees: Option<FeeGenesis>,
}

/// JSON-facing transaction fee policy.
#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeeGenesis {
    /// Index into [`CoinsGenesis::tokens`] selecting the coin fees are paid in.
    pub token: usize,
    /// Bech32-encoded [`Address`] credited with collected fees.
    #[serde_as(as = "DisplayFromStr")]
    pub collector: Address,
    /// Flat fee charged per transaction.
    pub base: u128,
    /// Fee charged per canonical encoded transaction byte.
    pub per_byte: u128,
}

/// JSON-facing account policy registration.
#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountPolicyGenesis {
    /// Bech32-encoded [`Address`]. Must equal `Address::multisig(policy)`.
    #[serde_as(as = "DisplayFromStr")]
    pub account_id: Address,
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
#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenGenesis {
    /// Bech32-encoded issuer [`Address`].
    #[serde_as(as = "DisplayFromStr")]
    pub issuer: Address,
    /// Token creation spec. This is passed through [`crate::TokenFactory`].
    pub spec: CoinSpec,
    /// Optional initial distribution. If present, amounts must sum to `spec.initial_supply`.
    #[serde(default)]
    pub allocations: Vec<AllocationGenesis>,
}

/// JSON-facing balance allocation for a token created in the same genesis entry.
#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AllocationGenesis {
    /// Bech32-encoded recipient [`Address`].
    #[serde_as(as = "DisplayFromStr")]
    pub account: Address,
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
            let policy = account.policy.policy()?;
            if account.account_id != multisig_account_id(&policy) {
                return Err(LedgerError::AccountPolicyMismatch(Box::new(
                    account.account_id.clone(),
                )));
            }
            self.register_account_policy(
                account.account_id.clone(),
                AccountPolicy::Multisig(policy),
            )
            .await?;
        }

        let mut coins = Vec::with_capacity(genesis.tokens.len());
        for token in &genesis.tokens {
            let coin = self
                .create_token(token.issuer.clone(), token.spec.clone())
                .await?;
            self.apply_allocations(
                token.issuer.clone(),
                coin,
                token.spec.initial_supply,
                &token.allocations,
            )
            .await?;
            coins.push(coin);
        }

        if let Some(fees) = &genesis.fees {
            let coin = coins.get(fees.token).ok_or_else(|| {
                LedgerError::InvalidGenesis(format!(
                    "fee token index {} out of range ({} tokens)",
                    fees.token,
                    coins.len()
                ))
            })?;
            self.set_fee_config(&FeeConfig {
                coin: *coin,
                collector: fees.collector.clone(),
                base: fees.base,
                per_byte: fees.per_byte,
            });
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
            self.credit(&allocation.account, coin, allocation.amount)
                .await?;
        }
        Ok(())
    }
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
