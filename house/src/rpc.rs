//! JSON-RPC surface for the house module.

use std::sync::Arc;

use commonware_cryptography::sha256::Digest;
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::{
    core::{async_trait, RegisterMethodError, RpcResult},
    proc_macros::rpc,
};
use nunchi_clob::MarketId;
use nunchi_common::{Address, CommitState};
use nunchi_rpc::{decode_hex, encode_hex, invalid_params, module_error, RpcRouter};
use serde::{Deserialize, Serialize};

use crate::{HouseDB, HouseError, HouseLedger, Mode, NetInventory, Vault, VaultId};

/// Read-only house state required by the house RPC server.
#[async_trait]
pub trait HouseQuery: Clone + Send + Sync + 'static {
    async fn nonce(&self, account: Address) -> Result<u64, HouseError>;

    async fn vault(&self, vault: VaultId) -> Result<Option<Vault>, HouseError>;

    async fn vaults(&self) -> Result<Vec<Vault>, HouseError>;

    async fn submitters(&self, vault: VaultId) -> Result<Vec<Address>, HouseError>;

    async fn inventory(&self, vault: VaultId, market: MarketId)
        -> Result<NetInventory, HouseError>;

    async fn reserved(&self, vault: VaultId, market: MarketId) -> Result<u128, HouseError>;

    async fn state_root(&self) -> Result<Digest, HouseError>;
}

/// Shared committed house ledger handle suitable for RPC query servers.
pub struct SharedLedger<D> {
    ledger: Arc<AsyncMutex<HouseLedger<D>>>,
}

impl<D> SharedLedger<D> {
    pub fn new(ledger: HouseLedger<D>) -> Self {
        Self {
            ledger: Arc::new(AsyncMutex::new(ledger)),
        }
    }

    pub async fn lock(&self) -> futures::lock::MutexGuard<'_, HouseLedger<D>> {
        self.ledger.lock().await
    }
}

impl<D> Clone for SharedLedger<D> {
    fn clone(&self) -> Self {
        Self {
            ledger: self.ledger.clone(),
        }
    }
}

#[async_trait]
impl<D> HouseQuery for SharedLedger<D>
where
    D: HouseDB + CommitState + Send + Sync + 'static,
{
    async fn nonce(&self, account: Address) -> Result<u64, HouseError> {
        self.lock().await.nonce(&account).await
    }

    async fn vault(&self, vault: VaultId) -> Result<Option<Vault>, HouseError> {
        self.lock().await.vault(&vault).await
    }

    async fn vaults(&self) -> Result<Vec<Vault>, HouseError> {
        self.lock().await.vaults().await
    }

    async fn submitters(&self, vault: VaultId) -> Result<Vec<Address>, HouseError> {
        self.lock().await.submitters(&vault).await
    }

    async fn inventory(
        &self,
        vault: VaultId,
        market: MarketId,
    ) -> Result<NetInventory, HouseError> {
        self.lock().await.inventory(&vault, &market).await
    }

    async fn reserved(&self, vault: VaultId, market: MarketId) -> Result<u128, HouseError> {
        self.lock().await.reserved(&vault, &market).await
    }

    async fn state_root(&self) -> Result<Digest, HouseError> {
        Ok(self.lock().await.db().root())
    }
}

/// Concrete house RPC server over a query backend.
#[derive(Clone)]
pub struct HouseRpc<Q> {
    query: Q,
}

impl<Q> HouseRpc<Q> {
    pub fn new(query: Q) -> Self {
        Self { query }
    }
}

#[rpc(server, namespace = "house", namespace_separator = ".")]
pub trait House {
    #[method(name = "nonce", param_kind = map)]
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse>;

    #[method(name = "vault", param_kind = map)]
    async fn vault(&self, vault: String) -> RpcResult<Option<VaultResponse>>;

    #[method(name = "vaults")]
    async fn vaults(&self) -> RpcResult<VaultsResponse>;

    #[method(name = "submitters", param_kind = map)]
    async fn submitters(&self, vault: String) -> RpcResult<SubmittersResponse>;

    #[method(name = "inventory", param_kind = map)]
    async fn inventory(&self, vault: String, market: String) -> RpcResult<InventoryResponse>;

    #[method(name = "reserved", param_kind = map)]
    async fn reserved(&self, vault: String, market: String) -> RpcResult<ReservedResponse>;

    #[method(name = "state_root")]
    async fn state_root(&self) -> RpcResult<RootResponse>;
}

#[async_trait]
impl<Q> HouseServer for HouseRpc<Q>
where
    Q: HouseQuery,
{
    async fn nonce(&self, account: String) -> RpcResult<NonceResponse> {
        let account = decode_account(&account)?;
        let nonce = self.query.nonce(account.clone()).await.map_err(rpc_error)?;
        Ok(NonceResponse {
            account: account.to_bech32(),
            nonce,
        })
    }

    async fn vault(&self, vault: String) -> RpcResult<Option<VaultResponse>> {
        let vault = decode_hex(&vault, "vault")?;
        Ok(self
            .query
            .vault(vault)
            .await
            .map_err(rpc_error)?
            .map(VaultResponse::from))
    }

    async fn vaults(&self) -> RpcResult<VaultsResponse> {
        let vaults = self
            .query
            .vaults()
            .await
            .map_err(rpc_error)?
            .into_iter()
            .map(VaultResponse::from)
            .collect();
        Ok(VaultsResponse { vaults })
    }

    async fn submitters(&self, vault: String) -> RpcResult<SubmittersResponse> {
        let vault = decode_hex(&vault, "vault")?;
        let submitters = self
            .query
            .submitters(vault)
            .await
            .map_err(rpc_error)?
            .into_iter()
            .map(|address| address.to_bech32())
            .collect();
        Ok(SubmittersResponse { submitters })
    }

    async fn inventory(&self, vault: String, market: String) -> RpcResult<InventoryResponse> {
        let vault_id = decode_hex(&vault, "vault")?;
        let market_id = decode_hex(&market, "market")?;
        let inventory = self
            .query
            .inventory(vault_id, market_id)
            .await
            .map_err(rpc_error)?;
        Ok(InventoryResponse {
            vault,
            market,
            negative: inventory.negative,
            base: inventory.base.to_string(),
        })
    }

    async fn reserved(&self, vault: String, market: String) -> RpcResult<ReservedResponse> {
        let vault_id = decode_hex(&vault, "vault")?;
        let market_id = decode_hex(&market, "market")?;
        let reserved = self
            .query
            .reserved(vault_id, market_id)
            .await
            .map_err(rpc_error)?;
        Ok(ReservedResponse {
            vault,
            market,
            reserved: reserved.to_string(),
        })
    }

    async fn state_root(&self) -> RpcResult<RootResponse> {
        let root = self.query.state_root().await.map_err(rpc_error)?;
        Ok(RootResponse {
            root: encode_hex(&root),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NonceResponse {
    pub account: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultResponse {
    pub id: String,
    pub owner: String,
    pub quote_balance: String,
    pub max_market_allocation: String,
    pub max_net_inventory: String,
    pub max_leverage_bps: u32,
    pub allowed_markets: Vec<String>,
    pub mode: String,
    pub created_at_height: u64,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultsResponse {
    pub vaults: Vec<VaultResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmittersResponse {
    pub submitters: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryResponse {
    pub vault: String,
    pub market: String,
    pub negative: bool,
    pub base: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservedResponse {
    pub vault: String,
    pub market: String,
    pub reserved: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootResponse {
    pub root: String,
}

/// Register the house module's query RPC methods into a downstream router.
pub fn register<Context, Q>(
    router: &mut RpcRouter<Context>,
    rpc: HouseRpc<Q>,
) -> Result<(), RegisterMethodError>
where
    Q: HouseQuery,
{
    router.merge(rpc.into_rpc())
}

fn decode_account(value: &str) -> RpcResult<Address> {
    Address::from_bech32(value)
        .map_err(|err| invalid_params(format!("invalid account address: {err}")))
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Live => "live",
        Mode::Frozen => "frozen",
        Mode::Halt => "halt",
    }
}

fn rpc_error(error: HouseError) -> jsonrpsee::types::ErrorObjectOwned {
    module_error(error.to_string())
}

impl From<Vault> for VaultResponse {
    fn from(vault: Vault) -> Self {
        Self {
            id: encode_hex(&vault.id),
            owner: vault.owner.to_bech32(),
            quote_balance: vault.quote_balance.to_string(),
            max_market_allocation: vault.policy.max_market_allocation.to_string(),
            max_net_inventory: vault.policy.max_net_inventory.to_string(),
            max_leverage_bps: vault.policy.max_leverage_bps,
            allowed_markets: vault
                .policy
                .allowed_markets
                .iter()
                .map(encode_hex)
                .collect(),
            mode: mode_name(vault.mode).to_string(),
            created_at_height: vault.created_at_height,
            created_at_ms: vault.created_at_ms,
        }
    }
}
