use nunchi_authority::AuthorityError;
use nunchi_coins::{
    CoinId, CoinOperation, CoinSpec, LedgerError, TokenCreated, TokenName, TokenSymbol,
    TOKEN_CREATED_EVENT,
};
use nunchi_common::{QmdbState, Runtime, RuntimeContext, VecEventSink};
use nunchi_crypto::PrivateKey;

use crate::runtime::*;
use crate::{CoinTransaction, FeeV1, Transaction};
use commonware_codec::DecodeExt;
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};

fn fee() -> FeeV1 {
    FeeV1::new(CoinId(Sha256::hash(b"native-fee")), 1, 0, 1_000)
}

#[test]
fn runtime_error_classifies_storage_errors() {
    assert!(RuntimeError::Coins(LedgerError::Storage("disk".into())).is_storage());
    assert!(RuntimeError::Authority(AuthorityError::Storage("disk".into())).is_storage());

    assert!(!RuntimeError::Authority(AuthorityError::NotConfigured).is_storage());
    assert!(!RuntimeError::Coins(LedgerError::InvalidTokenSpec("bad")).is_storage());
}

#[test]
fn runtime_apply_forwards_coin_events() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "coins-runtime-events")
            .await
            .unwrap();
        let key = PrivateKey::ed25519_from_seed(1);
        let tx = CoinTransaction::sign_with_fee(
            &key,
            0,
            fee(),
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
        let tx = Transaction::from(CoinTransaction::sign_with_fee(
            &key,
            0,
            fee(),
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
