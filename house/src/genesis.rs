use crate::{
    ledger::validate_policy, HouseDB, HouseError, HouseLedger, Mode, Vault, VaultId, VaultPolicy,
    HOUSE_NAMESPACE, MAX_SUBMITTERS_PER_VAULT, MAX_VAULTS,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, Sha256};
use commonware_formatting::from_hex;
use nunchi_clob::MarketId;
use nunchi_common::Address;
use serde::{Deserialize, Serialize};

/// JSON-facing house genesis state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct HouseGenesis {
    #[serde(default)]
    pub vaults: Vec<HouseVaultGenesis>,
}

/// Initial vault configured at genesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HouseVaultGenesis {
    /// Bech32 account that owns the vault.
    pub owner: String,
    pub quote_balance: u128,
    pub max_market_allocation: u128,
    pub max_net_inventory: u128,
    pub max_leverage_bps: u32,
    /// Hex-encoded market ids the vault may take exposure in.
    #[serde(default)]
    pub allowed_markets: Vec<String>,
    /// Operating mode: "live", "frozen", or "halt".
    pub mode: String,
    /// Bech32 submitter keys authorized for the vault.
    #[serde(default)]
    pub submitters: Vec<String>,
}

/// Deterministic id for the vault at `index` in the genesis vault list.
pub fn genesis_vault_id(owner: &Address, index: u64) -> VaultId {
    let mut bytes = HOUSE_NAMESPACE.to_vec();
    bytes.extend_from_slice(b"genesis");
    bytes.extend_from_slice(owner.encode().as_ref());
    bytes.extend_from_slice(index.encode().as_ref());
    VaultId(Sha256::hash(&bytes))
}

impl<D: HouseDB> HouseLedger<D> {
    /// Seed house state from genesis.
    pub async fn apply_genesis(&mut self, genesis: &HouseGenesis) -> Result<(), HouseError> {
        let mut vault_index = self.db.vault_index().await?;
        for (index, vault) in genesis.vaults.iter().enumerate() {
            let owner = Address::from_bech32(&vault.owner)
                .map_err(|err| HouseError::Storage(format!("invalid owner: {err}")))?;
            let mut allowed_markets = Vec::with_capacity(vault.allowed_markets.len());
            for market in &vault.allowed_markets {
                allowed_markets.push(decode_hex::<MarketId>(market, "allowed market")?);
            }
            let policy = VaultPolicy {
                max_market_allocation: vault.max_market_allocation,
                max_net_inventory: vault.max_net_inventory,
                max_leverage_bps: vault.max_leverage_bps,
                allowed_markets,
            };
            validate_policy(&policy)?;
            let mode = parse_mode(&vault.mode)?;

            let id = genesis_vault_id(&owner, index as u64);
            if self.db.vault(&id).await?.is_some() {
                return Err(HouseError::VaultAlreadyExists);
            }
            if vault_index.len() == MAX_VAULTS {
                return Err(HouseError::VaultIndexFull);
            }
            if vault.submitters.len() > MAX_SUBMITTERS_PER_VAULT {
                return Err(HouseError::SubmitterIndexFull);
            }
            let mut submitters = Vec::with_capacity(vault.submitters.len());
            for submitter in &vault.submitters {
                submitters.push(
                    Address::from_bech32(submitter)
                        .map_err(|err| HouseError::Storage(format!("invalid submitter: {err}")))?,
                );
            }

            self.db.set_vault(&Vault {
                id,
                owner,
                quote_balance: vault.quote_balance,
                policy,
                mode,
                created_at_height: 0,
                created_at_ms: 0,
            });
            if !submitters.is_empty() {
                self.db.set_submitters(&id, &submitters);
            }
            vault_index.push(id);
        }
        self.db.set_vault_index(&vault_index);
        Ok(())
    }
}

fn parse_mode(value: &str) -> Result<Mode, HouseError> {
    match value {
        "live" => Ok(Mode::Live),
        "frozen" => Ok(Mode::Frozen),
        "halt" => Ok(Mode::Halt),
        _ => Err(HouseError::Storage(format!("invalid mode: {value}"))),
    }
}

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, HouseError>
where
    T: DecodeExt<()>,
{
    let bytes = from_hex(value).ok_or_else(|| HouseError::Storage(format!("invalid {what}")))?;
    T::decode(bytes.as_ref()).map_err(|err| HouseError::Storage(format!("invalid {what}: {err}")))
}
