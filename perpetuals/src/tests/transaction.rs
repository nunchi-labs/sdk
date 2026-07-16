use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, Sha256};
use nunchi_oracle::NamespaceId;

use nunchi_crypto::PrivateKey;

use crate::{
    derive_market_id, derive_position_id, Address, CoinId, PerpetualOperation, Side, Transaction,
};

fn coin(seed: &'static [u8]) -> CoinId {
    CoinId(Sha256::hash(seed))
}

fn writer() -> PrivateKey {
    PrivateKey::from_seed(1)
}

fn roundtrip(operation: PerpetualOperation, nonce: u64) {
    let tx = Transaction::sign(&writer(), nonce, operation.clone());
    let decoded = Transaction::decode(tx.encode().as_ref()).expect("decode transaction");
    assert_eq!(decoded.payload.operation, operation);
    assert_eq!(decoded.payload.nonce, nonce);
}

#[test]
fn perpetual_operation_codec_roundtrips() {
    let market = derive_market_id(coin(b"btc"), coin(b"usd"), coin(b"usdc"), 0);
    let position = derive_position_id(&Address::external(&writer().public_key()), &market, 0);
    let writer_addr = Address::external(&writer().public_key());

    roundtrip(
        PerpetualOperation::CreateMarket {
            base_asset: coin(b"btc"),
            quote_asset: coin(b"usd"),
            collateral_asset: coin(b"usdc"),
            oracle_namespace: NamespaceId(Sha256::hash(b"oracle")),
            oracle_writer: writer_addr.clone(),
            clob_market: Some(Sha256::hash(b"clob")),
            oracle_interval_ms: 1_000,
            max_oracle_staleness_ms: 60_000,
            price_decimals: 2,
            max_leverage_bps: 50_000,
            maintenance_margin_bps: 1_000,
            funding_interval_ms: 3_600_000,
            max_funding_rate_bps: 100,
            liquidation_reward_bps: crate::DEFAULT_LIQUIDATION_REWARD_BPS,
        },
        0,
    );
    roundtrip(
        PerpetualOperation::CreateMarket {
            base_asset: coin(b"btc"),
            quote_asset: coin(b"usd"),
            collateral_asset: coin(b"usdc"),
            oracle_namespace: NamespaceId(Sha256::hash(b"oracle")),
            oracle_writer: writer_addr,
            clob_market: None,
            oracle_interval_ms: 1_000,
            max_oracle_staleness_ms: 60_000,
            price_decimals: 0,
            max_leverage_bps: 10_000,
            maintenance_margin_bps: 500,
            funding_interval_ms: 3_600_000,
            max_funding_rate_bps: 100,
            liquidation_reward_bps: crate::DEFAULT_LIQUIDATION_REWARD_BPS,
        },
        1,
    );
    roundtrip(PerpetualOperation::RefreshMarketFromOracle { market }, 2);
    roundtrip(PerpetualOperation::SettleFunding { market }, 3);
    roundtrip(
        PerpetualOperation::OpenPosition {
            market,
            side: Side::Long,
            collateral: 1_000,
            leverage_bps: 50_000,
        },
        4,
    );
    roundtrip(
        PerpetualOperation::AddCollateral {
            position,
            amount: 500,
        },
        5,
    );
    roundtrip(
        PerpetualOperation::ReduceCollateral {
            position,
            amount: 100,
        },
        6,
    );
    roundtrip(PerpetualOperation::ClosePosition { position }, 7);
    roundtrip(PerpetualOperation::Liquidate { position }, 8);
    roundtrip(
        PerpetualOperation::UpdateMarkPrice {
            market,
            mark_price: 101_000,
        },
        9,
    );
}
