use crate::{
    account::{multisig_account_id, Address, MultisigPolicy, PrivateKey},
    asset::{TokenError, TokenName, TokenSymbol},
    AccountPolicyRegistered, Burned, CoinOperation, CoinSpec, Ledger, LedgerError, Minted,
    TokenCreated, Transaction, Transferred, ACCOUNT_POLICY_REGISTERED_EVENT, BURNED_EVENT,
    MINTED_EVENT, TOKEN_CREATED_EVENT, TRANSFERRED_EVENT,
};
use commonware_codec::DecodeExt;
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::{QmdbState, VecEventSink};
use nunchi_crypto::SignatureError;

async fn ledger(context: deterministic::Context) -> Ledger<QmdbState<deterministic::Context>> {
    let db = QmdbState::init(context, "coins-events-test")
        .await
        .expect("init state db");
    Ledger::new(db)
}

fn spec(supply: u128, max: Option<u128>) -> Result<CoinSpec, TokenError> {
    Ok(CoinSpec::new(
        TokenSymbol::new("NCH")?,
        TokenName::new("Nunchi")?,
        9,
        supply,
        max,
    ))
}

fn address(key: &PrivateKey) -> Address {
    crate::external_account_id(&key.public_key())
}

fn event_sink() -> VecEventSink {
    VecEventSink::new()
}

#[test]
fn register_account_policy_emits_event() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_a = PrivateKey::ed25519_from_seed(1);
        let alice_b = PrivateKey::secp256r1_from_seed(2);
        let policy =
            MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
        let alice = multisig_account_id(&policy);
        let tx = Transaction::sign_multisig(
            alice.clone(),
            policy.clone(),
            &[&alice_a, &alice_b],
            0,
            CoinOperation::RegisterAccountPolicy {
                account_id: alice.clone(),
                policy: policy.clone(),
            },
        );
        let mut events = event_sink();

        ledger
            .apply_transaction(&tx, Some(&mut events))
            .await
            .expect("register policy");

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), ACCOUNT_POLICY_REGISTERED_EVENT);
        assert_eq!(
            AccountPolicyRegistered::decode(event.value.as_ref()).unwrap(),
            AccountPolicyRegistered {
                account_id: alice,
                policy
            }
        );
    });
}

#[test]
fn create_token_emits_event() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let tx = Transaction::sign(
            &alice_key,
            0,
            CoinOperation::CreateToken {
                spec: spec(1_000, Some(2_000)).expect("valid coin spec"),
            },
        );
        let mut events = event_sink();

        ledger
            .apply_transaction(&tx, Some(&mut events))
            .await
            .expect("create token");

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), TOKEN_CREATED_EVENT);
        let emitted = TokenCreated::decode(event.value.as_ref()).unwrap();
        assert_eq!(emitted.token.issuer, alice);
        assert_eq!(emitted.token.total_supply, 1_000);
        assert_eq!(emitted.token.max_supply, Some(2_000));
        assert_eq!(
            ledger.token(&emitted.token.id).await.unwrap(),
            Some(emitted.token)
        );
    });
}

#[test]
fn mint_emits_event() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));
        let coin = ledger
            .create_token(alice, spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");
        let tx = Transaction::sign(
            &alice_key,
            0,
            CoinOperation::Mint {
                coin,
                to: bob.clone(),
                amount: 250,
            },
        );
        let mut events = event_sink();

        ledger.apply_transaction(&tx, Some(&mut events)).await.unwrap();

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), MINTED_EVENT);
        assert_eq!(
            Minted::decode(event.value.as_ref()).unwrap(),
            Minted {
                coin,
                to: bob,
                amount: 250,
                total_supply: 1_250,
            }
        );
    });
}

#[test]
fn burn_emits_event() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");
        let tx = Transaction::sign(
            &alice_key,
            0,
            CoinOperation::Burn {
                coin,
                from: alice.clone(),
                amount: 250,
            },
        );
        let mut events = event_sink();

        ledger.apply_transaction(&tx, Some(&mut events)).await.unwrap();

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), BURNED_EVENT);
        assert_eq!(
            Burned::decode(event.value.as_ref()).unwrap(),
            Burned {
                coin,
                from: alice,
                amount: 250,
                total_supply: 750,
            }
        );
    });
}

#[test]
fn transfer_emits_event() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));
        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");
        let tx = Transaction::sign(
            &alice_key,
            0,
            CoinOperation::Transfer {
                coin,
                from: alice.clone(),
                to: bob.clone(),
                amount: 250,
            },
        );
        let mut events = event_sink();

        ledger.apply_transaction(&tx, Some(&mut events)).await.unwrap();

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), TRANSFERRED_EVENT);
        assert_eq!(
            Transferred::decode(event.value.as_ref()).unwrap(),
            Transferred {
                coin,
                from: alice,
                to: bob,
                amount: 250,
            }
        );
    });
}

#[test]
fn failed_transactions_emit_no_events() {
    deterministic::Runner::default().start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob_key = PrivateKey::ed25519_from_seed(2);
        let bob = address(&bob_key);
        let carol = address(&PrivateKey::ed25519_from_seed(3));
        let coin = ledger
            .create_token(alice.clone(), spec(100, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let mut bad_signature = Transaction::sign(
            &alice_key,
            0,
            CoinOperation::Transfer {
                coin,
                from: alice.clone(),
                to: bob.clone(),
                amount: 1,
            },
        );
        bad_signature.payload.operation = CoinOperation::Transfer {
            coin,
            from: alice.clone(),
            to: carol.clone(),
            amount: 1,
        };
        assert_no_event(
            &mut ledger,
            &bad_signature,
            LedgerError::BadSignature(SignatureError::InvalidSignature),
        )
        .await;

        let wrong_nonce = Transaction::sign(
            &alice_key,
            5,
            CoinOperation::Transfer {
                coin,
                from: alice.clone(),
                to: bob.clone(),
                amount: 1,
            },
        );
        let mut events = event_sink();
        assert!(matches!(
            ledger.apply_transaction(&wrong_nonce, Some(&mut events)).await,
            Err(LedgerError::NonceMismatch {
                expected: 0,
                actual: 5,
                ..
            })
        ));
        assert!(events.is_empty());

        let zero_amount = Transaction::sign(
            &alice_key,
            0,
            CoinOperation::Transfer {
                coin,
                from: alice.clone(),
                to: bob.clone(),
                amount: 0,
            },
        );
        assert_no_event(&mut ledger, &zero_amount, LedgerError::InvalidAmount).await;

        let unauthorized = Transaction::sign(
            &alice_key,
            0,
            CoinOperation::Transfer {
                coin,
                from: bob.clone(),
                to: carol,
                amount: 1,
            },
        );
        assert_no_event(&mut ledger, &unauthorized, LedgerError::Unauthorized).await;

        let insufficient = Transaction::sign(
            &bob_key,
            0,
            CoinOperation::Transfer {
                coin,
                from: bob.clone(),
                to: alice,
                amount: 1,
            },
        );
        assert_no_event(
            &mut ledger,
            &insufficient,
            LedgerError::InsufficientBalance {
                account: Box::new(bob),
                coin: Box::new(coin),
                available: 0,
                required: 1,
            },
        )
        .await;
    });
}

async fn assert_no_event(
    ledger: &mut Ledger<QmdbState<deterministic::Context>>,
    tx: &Transaction,
    expected: LedgerError,
) {
    let mut events = event_sink();
    assert_eq!(ledger.apply_transaction(tx, Some(&mut events)).await, Err(expected));
    assert!(events.is_empty());
}
