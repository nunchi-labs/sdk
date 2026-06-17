use crate::{
    derive_market_id, LedgerError, Market, MarketId, PerpetualDB, PerpetualLedger, PRICE_SCALE,
};
use commonware_codec::DecodeExt;
use commonware_formatting::from_hex;
use nunchi_coins::CoinId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PerpetualsGenesis {
    #[serde(default)]
    pub markets: Vec<MarketGenesis>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MarketGenesis {
    pub base_asset: String,
    pub quote_asset: String,
    pub collateral_asset: String,
    pub max_leverage_bps: u32,
    pub maintenance_margin_bps: u32,
    pub mark_price: u128,
}

impl MarketGenesis {
    fn base_asset(&self) -> Result<CoinId, LedgerError> {
        decode_hex(&self.base_asset, "base asset")
    }

    fn quote_asset(&self) -> Result<CoinId, LedgerError> {
        decode_hex(&self.quote_asset, "quote asset")
    }

    fn collateral_asset(&self) -> Result<CoinId, LedgerError> {
        decode_hex(&self.collateral_asset, "collateral asset")
    }

    pub fn derived_market_id(&self, nonce: u64) -> Result<MarketId, LedgerError> {
        Ok(derive_market_id(
            self.base_asset()?,
            self.quote_asset()?,
            self.collateral_asset()?,
            nonce,
        ))
    }

    pub fn market(&self, nonce: u64) -> Result<Market, LedgerError> {
        let id = self.derived_market_id(nonce)?;
        if self.mark_price == 0 || self.mark_price > PRICE_SCALE * u64::MAX as u128 {
            return Err(LedgerError::InvalidPrice);
        }
        Ok(Market {
            id,
            base_asset: self.base_asset()?,
            quote_asset: self.quote_asset()?,
            collateral_asset: self.collateral_asset()?,
            max_leverage_bps: self.max_leverage_bps,
            maintenance_margin_bps: self.maintenance_margin_bps,
            mark_price: self.mark_price,
            open_interest: 0,
        })
    }
}

impl<D: PerpetualDB> PerpetualLedger<D> {
    pub async fn apply_genesis(&mut self, genesis: &PerpetualsGenesis) -> Result<(), LedgerError> {
        for market in &genesis.markets {
            self.create_market(
                market.base_asset()?,
                market.quote_asset()?,
                market.collateral_asset()?,
                market.max_leverage_bps,
                market.maintenance_margin_bps,
                market.mark_price,
            )
            .await?;
        }
        Ok(())
    }
}

fn decode_hex<T>(value: &str, what: &'static str) -> Result<T, LedgerError>
where
    T: DecodeExt<()>,
{
    let bytes = from_hex(value).ok_or_else(|| LedgerError::Storage(format!("invalid {what}")))?;
    T::decode(bytes.as_ref()).map_err(|err| LedgerError::Storage(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_formatting::hex;
    use commonware_runtime::{deterministic, Runner as _};
    use nunchi_common::QmdbState;

    fn coin_hex(label: &[u8]) -> String {
        use commonware_cryptography::{Hasher, Sha256};
        hex(&CoinId(Sha256::hash(label)).encode())
    }

    fn sample_genesis() -> PerpetualsGenesis {
        PerpetualsGenesis {
            markets: vec![
                MarketGenesis {
                    base_asset: coin_hex(b"BTC"),
                    quote_asset: coin_hex(b"USD"),
                    collateral_asset: coin_hex(b"USDC"),
                    max_leverage_bps: 50_000,
                    maintenance_margin_bps: 500,
                    mark_price: 50_000,
                },
                MarketGenesis {
                    base_asset: coin_hex(b"ETH"),
                    quote_asset: coin_hex(b"USD"),
                    collateral_asset: coin_hex(b"USDC"),
                    max_leverage_bps: 25_000,
                    maintenance_margin_bps: 1_000,
                    mark_price: 3_000,
                },
            ],
        }
    }

    #[test]
    fn genesis_json_roundtrips() {
        let genesis = sample_genesis();
        let raw = serde_json::to_vec(&genesis).unwrap();
        let decoded: PerpetualsGenesis = serde_json::from_slice(&raw).unwrap();
        assert_eq!(genesis, decoded);
    }

    #[test]
    fn apply_genesis_creates_markets() {
        deterministic::Runner::default().start(|context| async move {
            let db = QmdbState::init(context, "perpetuals-genesis-test")
                .await
                .expect("init state db");
            let mut ledger = PerpetualLedger::new(db);
            let genesis = sample_genesis();
            ledger.apply_genesis(&genesis).await.expect("apply genesis");

            // Both markets were created; market nonce advanced to 2.
            let btc_id = genesis.markets[0].derived_market_id(0).unwrap();
            let eth_id = genesis.markets[1].derived_market_id(1).unwrap();

            let btc = ledger.market(&btc_id).await.unwrap().unwrap();
            assert_eq!(btc.mark_price, 50_000);
            assert_eq!(btc.max_leverage_bps, 50_000);

            let eth = ledger.market(&eth_id).await.unwrap().unwrap();
            assert_eq!(eth.mark_price, 3_000);
            assert_eq!(eth.maintenance_margin_bps, 1_000);
        });
    }

    #[test]
    fn genesis_rejects_zero_mark_price() {
        let bad = MarketGenesis {
            base_asset: coin_hex(b"BTC"),
            quote_asset: coin_hex(b"USD"),
            collateral_asset: coin_hex(b"USDC"),
            max_leverage_bps: 10_000,
            maintenance_margin_bps: 500,
            mark_price: 0,
        };
        assert!(matches!(bad.market(0), Err(LedgerError::InvalidPrice)));
    }

    #[test]
    fn genesis_rejects_invalid_hex_asset() {
        let bad = MarketGenesis {
            base_asset: "not-valid-hex".to_string(),
            quote_asset: coin_hex(b"USD"),
            collateral_asset: coin_hex(b"USDC"),
            max_leverage_bps: 10_000,
            maintenance_margin_bps: 500,
            mark_price: 1_000,
        };
        assert!(matches!(bad.market(0), Err(LedgerError::Storage(_))));
    }
}
