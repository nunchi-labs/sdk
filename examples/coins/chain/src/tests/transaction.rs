use commonware_codec::Encode;
use nunchi_authority::{AuthorityOperation, Transaction as AuthorityTransaction};
use nunchi_bridge::{BridgeOperation, BridgeTransaction, ChainId};
use nunchi_clob::{AssetId, ClobOperation, Transaction as ClobTransaction};
use nunchi_clearinghouse::{
    ClearinghouseOperation, Transaction as ClearinghouseTransaction,
};
use nunchi_coins::{CoinOperation, Transaction as CoinTransaction};
use nunchi_common::{Address, Operation};
use nunchi_mempool::PoolTransaction;

use commonware_codec::DecodeExt;
use commonware_cryptography::{ed25519, Hasher, Sha256, Signer as _};
use nunchi_authority::MultisigPolicy;
use nunchi_coins::{CoinSpec, PrivateKey, TokenName, TokenSymbol};
use nunchi_oracle::{IntervalKey, NamespaceId, OracleOperation, Transaction as OracleTransaction};
use nunchi_perpetuals::{PerpetualOperation, Side, Transaction as PerpetualTransaction};

use crate::transaction::*;

fn coin_transaction(seed: u64, nonce: u64) -> CoinTransaction {
    let signer = PrivateKey::ed25519_from_seed(seed);
    CoinTransaction::sign(
        &signer,
        nonce,
        CoinOperation::CreateToken {
            spec: CoinSpec::new(
                TokenSymbol::new("NCH").unwrap(),
                TokenName::new("Nunchi").unwrap(),
                9,
                1_000,
                None,
            ),
        },
    )
}

fn authority_transaction(seed: u64, nonce: u64) -> AuthorityTransaction {
    let owner = nunchi_crypto::PrivateKey::ed25519_from_seed(seed);
    AuthorityTransaction::sign(
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

fn oracle_transaction(seed: u64, nonce: u64) -> OracleTransaction {
    let signer = nunchi_crypto::PrivateKey::ed25519_from_seed(seed);
    OracleTransaction::sign(
        &signer,
        nonce,
        OracleOperation::AppendRecord {
            namespace: NamespaceId(Sha256::hash(b"test-namespace")),
            interval: IntervalKey::new(0),
            payload: b"payload".to_vec(),
            proof: None,
        },
    )
}

fn bridge_transaction(seed: u64, nonce: u64) -> BridgeTransaction {
    let signer = nunchi_crypto::PrivateKey::ed25519_from_seed(seed);
    BridgeTransaction::sign(
        &signer,
        nonce,
        BridgeOperation::Lock {
            destination_chain_id: ChainId(Sha256::hash(b"remote-chain")),
            local_asset: Sha256::hash(b"local-asset"),
            amount: 1,
            recipient: Address::external(
                &nunchi_crypto::PrivateKey::ed25519_from_seed(seed + 1).public_key(),
            ),
        },
    )
}

fn clob_transaction(seed: u64, nonce: u64) -> ClobTransaction {
    let signer = nunchi_crypto::PrivateKey::ed25519_from_seed(seed);
    ClobTransaction::sign(
        &signer,
        nonce,
        ClobOperation::CreateMarket {
            base_asset: AssetId(Sha256::hash(b"base")),
            quote_asset: AssetId(Sha256::hash(b"quote")),
            tick_size: 1,
            lot_size: 1,
        },
    )
}

fn perpetual_transaction(seed: u64, nonce: u64) -> PerpetualTransaction {
    let signer = nunchi_crypto::PrivateKey::ed25519_from_seed(seed);
    PerpetualTransaction::sign(
        &signer,
        nonce,
        PerpetualOperation::OpenPosition {
            market: Sha256::hash(b"btc-usd-perp"),
            side: Side::Long,
            collateral: 1_000,
            leverage_bps: 50_000,
        },
    )
}

fn clearinghouse_transaction(seed: u64, nonce: u64) -> ClearinghouseTransaction {
    let signer = nunchi_crypto::PrivateKey::ed25519_from_seed(seed);
    ClearinghouseTransaction::sign(
        &signer,
        nonce,
        ClearinghouseOperation::RegisterPerpsMarket {
            clob_market: nunchi_clob::MarketId(Sha256::hash(b"clob")),
            perps_market: Sha256::hash(b"perps"),
        },
    )
}

#[test]
fn transaction_codec_uses_stable_tags() {
    let coin = Transaction::from(coin_transaction(1, 3));
    let authority = Transaction::from(authority_transaction(2, 4));
    let oracle = Transaction::from(oracle_transaction(3, 5));
    let bridge = Transaction::from(bridge_transaction(4, 6));
    let clob = Transaction::from(clob_transaction(5, 7));
    let perpetual = Transaction::from(perpetual_transaction(6, 8));
    let clearinghouse = Transaction::from(clearinghouse_transaction(7, 9));

    let coin_encoded = coin.encode();
    let authority_encoded = authority.encode();
    let oracle_encoded = oracle.encode();
    let bridge_encoded = bridge.encode();
    let clob_encoded = clob.encode();
    let perpetual_encoded = perpetual.encode();
    let clearinghouse_encoded = clearinghouse.encode();

    assert_eq!(coin_encoded[0], TX_COIN);
    assert_eq!(authority_encoded[0], TX_AUTHORITY);
    assert_eq!(oracle_encoded[0], TX_ORACLE);
    assert_eq!(bridge_encoded[0], TX_BRIDGE);
    assert_eq!(clob_encoded[0], TX_CLOB);
    assert_eq!(perpetual_encoded[0], TX_PERPETUAL);
    assert_eq!(clearinghouse_encoded[0], TX_CLEARINGHOUSE);
    assert_eq!(Transaction::decode(coin_encoded).unwrap(), coin);
    assert_eq!(Transaction::decode(authority_encoded).unwrap(), authority);
    assert_eq!(Transaction::decode(oracle_encoded).unwrap(), oracle);
    assert_eq!(Transaction::decode(bridge_encoded).unwrap(), bridge);
    assert_eq!(Transaction::decode(clob_encoded).unwrap(), clob);
    assert_eq!(Transaction::decode(perpetual_encoded).unwrap(), perpetual);
    assert_eq!(
        Transaction::decode(clearinghouse_encoded).unwrap(),
        clearinghouse
    );
    assert!(Transaction::decode([99].as_slice()).is_err());
}

#[test]
fn pool_transaction_forwards_to_inner_transaction() {
    let inner = coin_transaction(3, 7);
    let transaction = Transaction::from(inner.clone());

    assert_eq!(transaction.digest(), inner.digest());
    assert_eq!(transaction.account_id(), &inner.account_id);
    assert_eq!(transaction.nonce(), inner.payload.nonce);
    assert!(PoolTransaction::verify(&transaction).is_ok());
}

#[test]
fn pool_transaction_nonce_key_uses_operation_namespace() {
    let coin = Transaction::from(coin_transaction(1, 0));
    let authority = Transaction::from(authority_transaction(1, 0));
    let oracle = Transaction::from(oracle_transaction(1, 0));
    let bridge = Transaction::from(bridge_transaction(1, 0));
    let clob = Transaction::from(clob_transaction(1, 0));
    let perpetual = Transaction::from(perpetual_transaction(1, 0));
    let clearinghouse = Transaction::from(clearinghouse_transaction(1, 0));

    assert_eq!(
        PoolTransaction::nonce_key(&coin).namespace(),
        CoinOperation::NAMESPACE
    );
    assert_eq!(
        PoolTransaction::nonce_key(&authority).namespace(),
        AuthorityOperation::NAMESPACE
    );
    assert_eq!(
        PoolTransaction::nonce_key(&oracle).namespace(),
        OracleOperation::NAMESPACE
    );
    assert_eq!(
        PoolTransaction::nonce_key(&bridge).namespace(),
        BridgeOperation::NAMESPACE
    );
    assert_eq!(
        PoolTransaction::nonce_key(&clob).namespace(),
        ClobOperation::NAMESPACE
    );
    assert_eq!(
        PoolTransaction::nonce_key(&perpetual).namespace(),
        PerpetualOperation::NAMESPACE
    );
    assert_eq!(
        PoolTransaction::nonce_key(&clearinghouse).namespace(),
        ClearinghouseOperation::NAMESPACE
    );

    assert_ne!(
        PoolTransaction::nonce_key(&coin),
        PoolTransaction::nonce_key(&authority)
    );
    assert_ne!(
        PoolTransaction::nonce_key(&coin),
        PoolTransaction::nonce_key(&perpetual)
    );
}
