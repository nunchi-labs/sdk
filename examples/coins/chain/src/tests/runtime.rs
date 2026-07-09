use nunchi_authority::AuthorityError;
use nunchi_coins::{
    Address, CoinDB, CoinOperation, CoinSpec, CoinsGenesis, FeeCharged, FeeGenesis, Ledger,
    LedgerError, TokenCreated, TokenFactory, TokenGenesis, TokenName, TokenSymbol,
    FEE_CHARGED_EVENT, TOKEN_CREATED_EVENT, TRANSFERRED_EVENT,
};
use nunchi_common::{QmdbState, Runtime, RuntimeContext, VecEventSink};
use nunchi_crypto::PrivateKey;
use nunchi_oracle::OracleError;

use crate::runtime::*;
use crate::Transaction;
use commonware_codec::{DecodeExt, EncodeSize};
use commonware_runtime::{deterministic, Runner as _};

#[test]
fn runtime_error_classifies_storage_errors() {
    assert!(RuntimeError::Coins(LedgerError::Storage("disk".into())).is_storage());
    assert!(RuntimeError::Authority(AuthorityError::Storage("disk".into())).is_storage());
    assert!(RuntimeError::Oracle(OracleError::Storage("disk".into())).is_storage());

    assert!(!RuntimeError::Authority(AuthorityError::NotConfigured).is_storage());
    assert!(!RuntimeError::Coins(LedgerError::InvalidTokenSpec("bad")).is_storage());
    assert!(!RuntimeError::Oracle(OracleError::PayloadTooLarge).is_storage());
}

#[test]
fn runtime_apply_forwards_coin_events() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "coins-runtime-events")
            .await
            .unwrap();
        let key = PrivateKey::ed25519_from_seed(1);
        let tx = nunchi_coins::Transaction::sign(
            &key,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new(
                    TokenSymbol::new("NCH").unwrap(),
                    TokenName::new("Nunchi").unwrap(),
                    9,
                    1_000,
                    Some(2_000),
                ),
            },
        );
        let tx = Transaction::from(tx);
        let mut events = VecEventSink::new();

        CoinsRuntime::apply(&mut state, RuntimeContext::default(), &tx, &mut events)
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), TOKEN_CREATED_EVENT);
        let payload = TokenCreated::decode(event.value.as_ref()).unwrap();
        assert_eq!(payload.token.total_supply, 1_000);
        assert_eq!(payload.token.max_supply, Some(2_000));
    });
}

#[test]
fn runtime_validate_has_no_event_sink_surface() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "coins-runtime-validate")
            .await
            .unwrap();
        let key = PrivateKey::ed25519_from_seed(1);
        let tx = Transaction::from(nunchi_coins::Transaction::sign(
            &key,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new(
                    TokenSymbol::new("NCH").unwrap(),
                    TokenName::new("Nunchi").unwrap(),
                    9,
                    1_000,
                    None,
                ),
            },
        ));

        CoinsRuntime::validate(&mut state, RuntimeContext::default(), &tx)
            .await
            .unwrap();
    });
}

async fn fee_state(
    context: deterministic::Context,
    partition: &str,
    genesis: &CoinsGenesis,
) -> QmdbState<deterministic::Context> {
    let mut state = QmdbState::init(context, partition).await.unwrap();
    let mut ledger = Ledger::new(&mut state);
    ledger.apply_genesis(genesis).await.expect("apply genesis");
    state
}

fn fee_genesis(issuer: Address, collector: Address, base: u128, per_byte: u128) -> CoinsGenesis {
    CoinsGenesis {
        account_policies: vec![],
        tokens: vec![TokenGenesis {
            issuer,
            spec: CoinSpec::new(
                TokenSymbol::new("NCH").unwrap(),
                TokenName::new("Nunchi").unwrap(),
                9,
                1_000,
                None,
            ),
            allocations: vec![],
        }],
        fees: Some(FeeGenesis {
            token: 0,
            collector,
            base,
            per_byte,
        }),
    }
}

#[test]
fn runtime_charges_fee_before_dispatch() {
    deterministic::Runner::default().start(|context| async move {
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = Address::external(&alice_key.public_key());
        let bob = Address::external(&PrivateKey::ed25519_from_seed(2).public_key());
        let collector = Address::external(&PrivateKey::ed25519_from_seed(9).public_key());

        let genesis = fee_genesis(alice.clone(), collector.clone(), 7, 3);
        let mut state = fee_state(context, "coins-runtime-fees", &genesis).await;
        let spec = &genesis.tokens[0].spec;
        let coin = TokenFactory::derive_coin_id(&alice, 0, spec);

        let tx = Transaction::from(nunchi_coins::Transaction::sign(
            &alice_key,
            0,
            CoinOperation::Transfer {
                coin,
                from: alice.clone(),
                to: bob.clone(),
                amount: 100,
            },
        ));
        let fee = 7 + 3 * tx.encode_size() as u128;

        let mut events = VecEventSink::new();
        CoinsRuntime::apply(&mut state, RuntimeContext::default(), &tx, &mut events)
            .await
            .expect("apply transfer with fee");

        assert_eq!(state.balance(&alice, &coin).await.unwrap(), 900 - fee);
        assert_eq!(state.balance(&bob, &coin).await.unwrap(), 100);
        assert_eq!(state.balance(&collector, &coin).await.unwrap(), fee);

        assert_eq!(events.len(), 2);
        assert_eq!(events.events()[0].name.as_ref(), FEE_CHARGED_EVENT);
        let charged = FeeCharged::decode(events.events()[0].value.as_ref()).unwrap();
        assert_eq!(charged.payer, alice);
        assert_eq!(charged.collector, collector);
        assert_eq!(charged.amount, fee);
        assert_eq!(events.events()[1].name.as_ref(), TRANSFERRED_EVENT);
    });
}

#[test]
fn runtime_rejects_transaction_that_cannot_pay_fee() {
    deterministic::Runner::default().start(|context| async move {
        let alice = Address::external(&PrivateKey::ed25519_from_seed(1).public_key());
        let bob_key = PrivateKey::ed25519_from_seed(2);
        let bob = Address::external(&bob_key.public_key());
        let collector = Address::external(&PrivateKey::ed25519_from_seed(9).public_key());

        let genesis = fee_genesis(alice.clone(), collector, 7, 3);
        let mut state = fee_state(context, "coins-runtime-fees-unpayable", &genesis).await;
        let coin = TokenFactory::derive_coin_id(&alice, 0, &genesis.tokens[0].spec);

        // Bob holds no fee coin, so the ante rejects the transaction before dispatch.
        let tx = Transaction::from(nunchi_coins::Transaction::sign(
            &bob_key,
            0,
            CoinOperation::Transfer {
                coin,
                from: bob.clone(),
                to: alice,
                amount: 1,
            },
        ));
        let err = CoinsRuntime::validate(&mut state, RuntimeContext::default(), &tx)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RuntimeError::Coins(LedgerError::InsufficientBalance { .. })
        ));
    });
}
