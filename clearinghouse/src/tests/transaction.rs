use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, Sha256};
use nunchi_clob::{Fill, FillId, OrderId, Side as ClobSide};
use nunchi_common::Address;
use nunchi_crypto::PrivateKey;

use crate::{ClearinghouseOperation, Transaction};

fn sample_fill() -> Fill {
    Fill {
        id: FillId(Sha256::hash(b"fill")),
        market: nunchi_clob::MarketId(Sha256::hash(b"clob-market")),
        maker_order: OrderId(Sha256::hash(b"maker")),
        taker_order: OrderId(Sha256::hash(b"taker")),
        maker: Address::external(&PrivateKey::from_seed(1).public_key()),
        taker: Address::external(&PrivateKey::from_seed(2).public_key()),
        taker_side: ClobSide::Bid,
        price: 100,
        base_quantity: 4,
        quote_quantity: 400,
        sequence: 0,
        written_at_height: 1,
        written_at_ms: 1_000,
    }
}

#[test]
fn clearinghouse_operation_codec_roundtrips() {
    let settler = PrivateKey::from_seed(3);
    let clob_market = nunchi_clob::MarketId(Sha256::hash(b"clob"));
    let perps_market = Sha256::hash(b"perps");

    for (nonce, operation) in [
        (
            0,
            ClearinghouseOperation::RegisterPerpsMarket {
                clob_market,
                perps_market,
            },
        ),
        (
            1,
            ClearinghouseOperation::SettleFill {
                fill: FillId(Sha256::hash(b"fill-id")),
            },
        ),
        (
            2,
            ClearinghouseOperation::CommitAndSettleFill {
                fill: Box::new(sample_fill()),
            },
        ),
    ] {
        let tx = Transaction::sign(&settler, nonce, operation.clone());
        let decoded = Transaction::decode(tx.encode().as_ref()).expect("decode transaction");
        assert_eq!(decoded.payload.operation, operation);
        assert_eq!(decoded.payload.nonce, nonce);
    }
}
