//! Integration-layer mapping from a bridge [`AssetId`] to a local coins [`CoinId`].
//!
//! A bridged `AssetId` is a chain-scoped hash and cannot be reversed to a coin, so the destination
//! chain configures, at genesis, which local (wrapped) coin each bridgeable asset mints into. This
//! mapping lives in the coins-chain integration layer, not the bridge crate, so the bridge stays
//! decoupled from coins.

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::sha256::Digest;
use nunchi_bridge::AssetId;
use nunchi_coins::CoinId;
use nunchi_common::state_db::{Namespace, StateError, StateStore};

/// Domain separator for the integration-layer bridge asset mapping.
const NS: Namespace = Namespace::new(b"_NUNCHI_BRIDGE_ASSETS");

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    /// `AssetId` -> local `CoinId` the asset is minted into on claim.
    AssetCoin = 0,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn asset_coin_key(asset: &AssetId) -> Digest {
    NS.key(Table::AssetCoin, asset.digest().encode().as_ref())
}

/// The local coin a bridged `asset` mints into on this chain, if configured.
pub async fn asset_coin<S: StateStore>(
    store: &S,
    asset: &AssetId,
) -> Result<Option<CoinId>, StateError> {
    match store.get(&asset_coin_key(asset)).await? {
        Some(bytes) => CoinId::decode(bytes.as_ref())
            .map(Some)
            .map_err(|err| StateError::Backend(err.to_string())),
        None => Ok(None),
    }
}

/// Map a bridged `asset` to the local `coin` it mints into. Configured at genesis.
pub fn set_asset_coin<S: StateStore>(store: &mut S, asset: &AssetId, coin: &CoinId) {
    store.set(asset_coin_key(asset), coin.encode().as_ref().to_vec());
}
