//! Persistence layer for the house module.

use crate::{
    HouseError, NetInventory, Vault, VaultId, HOUSE_NAMESPACE, MAX_SUBMITTERS_PER_VAULT,
    MAX_VAULTS, MAX_VAULT_MARKETS,
};
use async_trait::async_trait;
use commonware_codec::{Encode, RangeCfg, Read, ReadExt};
use commonware_cryptography::sha256::Digest;
use nunchi_clob::MarketId;
use nunchi_common::{Address, Namespace, StateStore};

const NS: Namespace = Namespace::new(HOUSE_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Nonce = 0,
    Vault = 1,
    VaultIndex = 2,
    Submitters = 3,
    Inventory = 4,
    InventoryIndex = 5,
    Reserved = 6,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, HouseError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| HouseError::Storage(err.to_string()))
}

fn nonce_key(account: &Address) -> Digest {
    NS.key(Table::Nonce, account.encode().as_ref())
}

fn vault_key(vault: &VaultId) -> Digest {
    NS.key(Table::Vault, vault.encode().as_ref())
}

fn vault_index_key() -> Digest {
    NS.key(Table::VaultIndex, b"all")
}

fn submitters_key(vault: &VaultId) -> Digest {
    NS.key(Table::Submitters, vault.encode().as_ref())
}

fn vault_market_logical(vault: &VaultId, market: &MarketId) -> Vec<u8> {
    let mut logical = vault.encode().as_ref().to_vec();
    logical.extend_from_slice(market.encode().as_ref());
    logical
}

fn inventory_key(vault: &VaultId, market: &MarketId) -> Digest {
    NS.key(Table::Inventory, &vault_market_logical(vault, market))
}

fn inventory_index_key(vault: &VaultId) -> Digest {
    NS.key(Table::InventoryIndex, vault.encode().as_ref())
}

fn reserved_key(vault: &VaultId, market: &MarketId) -> Digest {
    NS.key(Table::Reserved, &vault_market_logical(vault, market))
}

/// Typed state access required by [`crate::HouseLedger`].
#[async_trait]
pub trait HouseDB {
    async fn nonce(&self, account: &Address) -> Result<u64, HouseError>;

    fn set_nonce(&mut self, account: &Address, nonce: u64);

    async fn vault(&self, id: &VaultId) -> Result<Option<Vault>, HouseError>;

    fn set_vault(&mut self, vault: &Vault);

    async fn vault_index(&self) -> Result<Vec<VaultId>, HouseError>;

    fn set_vault_index(&mut self, vaults: &[VaultId]);

    async fn submitters(&self, vault: &VaultId) -> Result<Vec<Address>, HouseError>;

    fn set_submitters(&mut self, vault: &VaultId, submitters: &[Address]);

    async fn inventory(
        &self,
        vault: &VaultId,
        market: &MarketId,
    ) -> Result<NetInventory, HouseError>;

    fn set_inventory(&mut self, vault: &VaultId, market: &MarketId, inventory: NetInventory);

    async fn inventory_index(&self, vault: &VaultId) -> Result<Vec<MarketId>, HouseError>;

    fn set_inventory_index(&mut self, vault: &VaultId, markets: &[MarketId]);

    async fn reserved(&self, vault: &VaultId, market: &MarketId) -> Result<u128, HouseError>;

    fn set_reserved(&mut self, vault: &VaultId, market: &MarketId, amount: u128);
}

#[async_trait]
impl<S: StateStore + Send + Sync> HouseDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, HouseError> {
        match StateStore::get(self, &nonce_key(account))
            .await
            .map_err(|err| HouseError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        StateStore::set(self, nonce_key(account), encoded(&nonce));
    }

    async fn vault(&self, id: &VaultId) -> Result<Option<Vault>, HouseError> {
        match StateStore::get(self, &vault_key(id))
            .await
            .map_err(|err| HouseError::Storage(err.to_string()))?
        {
            Some(bytes) => Ok(Some(decoded(&bytes)?)),
            None => Ok(None),
        }
    }

    fn set_vault(&mut self, vault: &Vault) {
        StateStore::set(self, vault_key(&vault.id), encoded(vault));
    }

    async fn vault_index(&self) -> Result<Vec<VaultId>, HouseError> {
        match StateStore::get(self, &vault_index_key())
            .await
            .map_err(|err| HouseError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_VAULTS), ()))
                    .map_err(|err| HouseError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_vault_index(&mut self, vaults: &[VaultId]) {
        StateStore::set(self, vault_index_key(), encoded(&vaults.to_vec()));
    }

    async fn submitters(&self, vault: &VaultId) -> Result<Vec<Address>, HouseError> {
        match StateStore::get(self, &submitters_key(vault))
            .await
            .map_err(|err| HouseError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_SUBMITTERS_PER_VAULT), ()))
                    .map_err(|err| HouseError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_submitters(&mut self, vault: &VaultId, submitters: &[Address]) {
        StateStore::set(self, submitters_key(vault), encoded(&submitters.to_vec()));
    }

    async fn inventory(
        &self,
        vault: &VaultId,
        market: &MarketId,
    ) -> Result<NetInventory, HouseError> {
        match StateStore::get(self, &inventory_key(vault, market))
            .await
            .map_err(|err| HouseError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(NetInventory::flat()),
        }
    }

    fn set_inventory(&mut self, vault: &VaultId, market: &MarketId, inventory: NetInventory) {
        StateStore::set(self, inventory_key(vault, market), encoded(&inventory));
    }

    async fn inventory_index(&self, vault: &VaultId) -> Result<Vec<MarketId>, HouseError> {
        match StateStore::get(self, &inventory_index_key(vault))
            .await
            .map_err(|err| HouseError::Storage(err.to_string()))?
        {
            Some(bytes) => {
                let mut buf = bytes.as_ref();
                Vec::read_cfg(&mut buf, &(RangeCfg::new(0..=MAX_VAULT_MARKETS), ()))
                    .map_err(|err| HouseError::Storage(err.to_string()))
            }
            None => Ok(Vec::new()),
        }
    }

    fn set_inventory_index(&mut self, vault: &VaultId, markets: &[MarketId]) {
        StateStore::set(self, inventory_index_key(vault), encoded(&markets.to_vec()));
    }

    async fn reserved(&self, vault: &VaultId, market: &MarketId) -> Result<u128, HouseError> {
        match StateStore::get(self, &reserved_key(vault, market))
            .await
            .map_err(|err| HouseError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_reserved(&mut self, vault: &VaultId, market: &MarketId, amount: u128) {
        StateStore::set(self, reserved_key(vault, market), encoded(&amount));
    }
}
