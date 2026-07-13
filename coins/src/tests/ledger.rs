use crate::{
    account::{
        multisig_account_id, AccountPolicy, AccountType, Address, MultisigPolicy, PrivateKey,
    },
    asset::{TokenError, TokenName, TokenSymbol},
    CoinSpec, FeeCharged, FeeConfig, Ledger, LedgerError, Transaction,
};
use commonware_codec::DecodeExt;
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use nunchi_common::{NoopEventSink, QmdbState, VecEventSink};
use nunchi_crypto::SignatureError;

async fn ledger(context: deterministic::Context) -> Ledger<QmdbState<deterministic::Context>> {
    let db = QmdbState::init(context, "coins-test")
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

fn multisig_account(policy: &MultisigPolicy) -> Address {
    multisig_account_id(policy)
}

fn policy_account(policy: &AccountPolicy) -> Address {
    match policy {
        AccountPolicy::Multisig(policy) => multisig_account(policy),
    }
}

#[test]
fn create_token_credits_issuer_and_commits_root() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));

        let empty_root = ledger.root();
        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 1_000);
        assert_eq!(
            ledger.token(&coin).await.unwrap().unwrap().total_supply,
            1_000
        );

        let root = ledger.commit().await.expect("commit");
        assert_ne!(root, empty_root, "committing state must change the root");
    });
}

#[test]
fn mint_respects_max_supply() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        let coin = ledger
            .create_token(
                alice.clone(),
                spec(1_000, Some(1_200)).expect("valid coin spec"),
            )
            .await
            .expect("create token");
        let nonce = ledger.nonce(&alice).await.expect("read nonce");

        let mint = Transaction::sign(
            &alice_key,
            nunchi_common::DEFAULT_CHAIN_ID, nonce,
            crate::CoinOperation::Mint {
                coin,
                to: bob.clone(),
                amount: 200,
            },
        );
        ledger.apply_transaction(&mint, NoopEventSink).await.expect("mint to cap");
        assert_eq!(ledger.balance(&bob, &coin).await.unwrap(), 200);
        assert_eq!(
            ledger.token(&coin).await.unwrap().unwrap().total_supply,
            1_200
        );

        let mint = Transaction::sign(
            &alice_key,
            nunchi_common::DEFAULT_CHAIN_ID,
            nonce.checked_add(1).expect("nonce overflow"),
            crate::CoinOperation::Mint {
                coin,
                to: bob,
                amount: 1,
            },
        );
        let err = ledger.apply_transaction(&mint, NoopEventSink).await.unwrap_err();
        assert_eq!(
            err,
            LedgerError::MaxSupplyExceeded {
                max: 1_200,
                attempted: 1_201,
            }
        );
    });
}

#[test]
fn transfer_via_signed_transaction_moves_balance_and_bumps_nonce() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let tx = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Transfer {
                coin, from: alice.clone(),
                to: bob.clone(),
                amount: 250,
            },
        );
        ledger.apply_transaction(&tx, NoopEventSink).await.expect("apply transfer");

        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 750);
        assert_eq!(ledger.balance(&bob, &coin).await.unwrap(), 250);
        assert_eq!(ledger.nonce(&alice).await.unwrap(), 1);
    });
}

#[test]
fn rejects_transaction_with_wrong_nonce() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let tx = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 5, crate::CoinOperation::Transfer {
                coin, from: alice.clone(),
                to: bob,
                amount: 1,
            },
        );
        let err = ledger.apply_transaction(&tx, NoopEventSink).await.unwrap_err();
        assert!(matches!(
            err,
            LedgerError::NonceMismatch {
                expected: 0,
                actual: 5,
                ..
            }
        ));
    });
}

#[test]
fn rejects_transaction_with_bad_signature() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let mut tx = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Transfer {
                coin, from: alice.clone(),
                to: bob,
                amount: 1,
            },
        );
        tx.payload.operation = crate::CoinOperation::Transfer {
            coin,
            from: alice,
            to: address(&PrivateKey::ed25519_from_seed(3)),
            amount: 1,
        };

        let err = ledger.apply_transaction(&tx, NoopEventSink).await.unwrap_err();
        assert_eq!(
            err,
            LedgerError::BadSignature(SignatureError::InvalidSignature)
        );
    });
}

#[test]
fn committed_state_survives_reopen() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let alice = address(&PrivateKey::ed25519_from_seed(1));

        let coin = {
            let mut ledger = ledger(context.child("open")).await;
            let coin = ledger
                .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
                .await
                .expect("create token");
            ledger.commit().await.expect("commit");
            coin
        };

        let reopened = ledger(context.child("reopen")).await;
        assert_eq!(reopened.balance(&alice, &coin).await.unwrap(), 1_000);
    });
}

#[test]
fn multisig_transaction_moves_balance_and_bumps_account_nonce_once() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_a = PrivateKey::ed25519_from_seed(1);
        let alice_b = PrivateKey::secp256r1_from_seed(2);
        let alice_c = PrivateKey::ed25519_from_seed(3);
        let bob = address(&PrivateKey::ed25519_from_seed(4));
        let policy = MultisigPolicy::new(
            2,
            vec![
                alice_a.public_key(),
                alice_b.public_key(),
                alice_c.public_key(),
            ],
        )
        .unwrap();
        let alice = multisig_account(&policy);
        ledger
            .register_account_policy(alice.clone(), AccountPolicy::Multisig(policy.clone()))
            .await
            .expect("register multisig");

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let tx = Transaction::sign_multisig(
            alice.clone(),
            policy,
            &[&alice_a, &alice_b],
            nunchi_common::DEFAULT_CHAIN_ID, 0,
            crate::CoinOperation::Transfer {
                coin,
                from: alice.clone(),
                to: bob.clone(),
                amount: 250,
            },
        );
        ledger.apply_transaction(&tx, NoopEventSink)
            .await
            .expect("apply multisig transfer");

        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 750);
        assert_eq!(ledger.balance(&bob, &coin).await.unwrap(), 250);
        assert_eq!(ledger.nonce(&alice).await.unwrap(), 1);
    });
}

#[test]
fn rejects_multisig_transaction_below_threshold() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_a = PrivateKey::ed25519_from_seed(1);
        let alice_b = PrivateKey::secp256r1_from_seed(2);
        let policy =
            MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
        let alice = multisig_account(&policy);
        ledger
            .register_account_policy(alice.clone(), AccountPolicy::Multisig(policy.clone()))
            .await
            .expect("register multisig");
        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let tx = Transaction::sign_multisig(
            alice.clone(),
            policy,
            &[&alice_a],
            nunchi_common::DEFAULT_CHAIN_ID, 0,
            crate::CoinOperation::Transfer {
                coin,
                from: alice,
                to: address(&PrivateKey::ed25519_from_seed(3)),
                amount: 1,
            },
        );

        assert_eq!(
            ledger.apply_transaction(&tx, NoopEventSink).await.unwrap_err(),
            LedgerError::BadSignature(SignatureError::InvalidSignature)
        );
    });
}

#[test]
fn rejects_unregistered_multisig_policy() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_a = PrivateKey::ed25519_from_seed(1);
        let alice_b = PrivateKey::secp256r1_from_seed(2);
        let policy =
            MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
        let alice = multisig_account(&policy);

        let tx = Transaction::sign_multisig(
            alice.clone(),
            policy,
            &[&alice_a, &alice_b],
            nunchi_common::DEFAULT_CHAIN_ID, 0,
            crate::CoinOperation::CreateToken {
                spec: spec(1_000, None).expect("valid coin spec"),
            },
        );

        assert_eq!(
            ledger.apply_transaction(&tx, NoopEventSink).await.unwrap_err(),
            LedgerError::UnknownAccountPolicy(Box::new(alice))
        );
    });
}

#[test]
fn registering_same_multisig_policy_twice_is_idempotent() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_a = PrivateKey::ed25519_from_seed(1);
        let alice_b = PrivateKey::secp256r1_from_seed(2);
        let policy =
            AccountPolicy::multisig(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
        let alice = policy_account(&policy);

        let first = ledger
            .register_account_policy(alice.clone(), policy.clone())
            .await
            .expect("first register");
        let second = ledger
            .register_account_policy(alice.clone(), policy)
            .await
            .expect("second register");

        assert_eq!(first, alice);
        assert_eq!(second, alice);
    });
}

#[test]
fn register_account_policy_operation_initializes_multisig_on_chain() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_a = PrivateKey::ed25519_from_seed(2);
        let alice_b = PrivateKey::secp256r1_from_seed(3);
        let policy =
            MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
        let alice = multisig_account(&policy);

        let tx = Transaction::sign_multisig(
            alice.clone(),
            policy.clone(),
            &[&alice_a, &alice_b],
            nunchi_common::DEFAULT_CHAIN_ID, 0,
            crate::CoinOperation::RegisterAccountPolicy {
                account_id: alice.clone(),
                policy: policy.clone(),
            },
        );
        ledger.apply_transaction(&tx, NoopEventSink)
            .await
            .expect("register policy");

        assert_eq!(ledger.nonce(&alice).await.unwrap(), 1);
        assert_eq!(
            ledger.account(&alice).await.unwrap().kind,
            AccountType::Multisig
        );

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");
        let tx = Transaction::sign_multisig(
            alice.clone(),
            policy,
            &[&alice_a, &alice_b],
            nunchi_common::DEFAULT_CHAIN_ID, 1,
            crate::CoinOperation::Transfer {
                coin,
                from: alice.clone(),
                to: address(&alice_a),
                amount: 1,
            },
        );

        ledger.apply_transaction(&tx, NoopEventSink)
            .await
            .expect("apply multisig transfer");
    });
}

#[test]
fn register_account_policy_operation_rejects_external_registration() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let attacker = PrivateKey::ed25519_from_seed(1);
        let alice_a = PrivateKey::ed25519_from_seed(2);
        let alice_b = PrivateKey::secp256r1_from_seed(3);
        let policy =
            MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
        let alice = multisig_account(&policy);

        let tx = Transaction::sign(&attacker, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::RegisterAccountPolicy {
                account_id: alice, policy, });

        assert_eq!(
            ledger.apply_transaction(&tx, NoopEventSink).await,
            Err(LedgerError::Unauthorized)
        );
    });
}

#[test]
fn register_account_policy_operation_cannot_hijack_external_account() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let attacker = PrivateKey::ed25519_from_seed(2);
        let policy = MultisigPolicy::new(1, vec![attacker.public_key()]).unwrap();
        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("fund alice");

        let tx = Transaction::sign_multisig(
            alice.clone(),
            policy.clone(),
            &[&attacker],
            nunchi_common::DEFAULT_CHAIN_ID, 0,
            crate::CoinOperation::RegisterAccountPolicy {
                account_id: alice.clone(),
                policy,
            },
        );

        assert_eq!(
            ledger.apply_transaction(&tx, NoopEventSink).await,
            Err(LedgerError::AccountPolicyMismatch(Box::new(alice.clone())))
        );
        assert_eq!(
            ledger.account(&alice).await.unwrap().kind,
            AccountType::External
        );
        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 1_000);
    });
}

#[test]
fn register_account_policy_operation_rejects_policy_witness_mismatch() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_a = PrivateKey::ed25519_from_seed(1);
        let alice_b = PrivateKey::secp256r1_from_seed(2);
        let authorized =
            MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
        let registered = MultisigPolicy::new(1, vec![alice_a.public_key()]).unwrap();
        let alice = multisig_account(&authorized);

        let tx = Transaction::sign_multisig(
            alice.clone(),
            authorized,
            &[&alice_a, &alice_b],
            nunchi_common::DEFAULT_CHAIN_ID, 0,
            crate::CoinOperation::RegisterAccountPolicy {
                account_id: alice.clone(),
                policy: registered,
            },
        );

        assert_eq!(
            ledger.apply_transaction(&tx, NoopEventSink).await,
            Err(LedgerError::AccountPolicyMismatch(Box::new(alice)))
        );
    });
}

#[test]
fn rejects_cross_account_multisig_replay() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_a = PrivateKey::ed25519_from_seed(1);
        let alice_b = PrivateKey::secp256r1_from_seed(2);
        let policy_a =
            MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
        let policy_b =
            MultisigPolicy::new(1, vec![alice_b.public_key(), alice_a.public_key()]).unwrap();
        let account_a = multisig_account(&policy_a);
        let account_b = multisig_account(&policy_b);
        ledger
            .register_account_policy(account_a.clone(), AccountPolicy::Multisig(policy_a.clone()))
            .await
            .expect("register account a");
        ledger
            .register_account_policy(account_b.clone(), AccountPolicy::Multisig(policy_b.clone()))
            .await
            .expect("register account b");

        let mut tx = Transaction::sign_multisig(
            account_a,
            policy_a,
            &[&alice_a, &alice_b],
            nunchi_common::DEFAULT_CHAIN_ID, 0,
            crate::CoinOperation::CreateToken {
                spec: spec(1_000, None).expect("valid coin spec"),
            },
        );
        tx.account_id = account_b;

        assert_eq!(
            ledger.apply_transaction(&tx, NoopEventSink).await.unwrap_err(),
            LedgerError::BadSignature(SignatureError::InvalidSignature)
        );
    });
}

// ----- Burn -----

#[test]
fn burn_reduces_balance_and_total_supply() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let burn = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Burn {
                coin, from: alice.clone(),
                amount: 400,
            },
        );
        ledger.apply_transaction(&burn, NoopEventSink).await.expect("burn");

        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 600);
        assert_eq!(
            ledger.token(&coin).await.unwrap().unwrap().total_supply,
            600
        );
        assert_eq!(ledger.nonce(&alice).await.unwrap(), 1);
    });
}

#[test]
fn burn_rejects_zero_amount() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let burn = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Burn {
                coin, from: alice, amount: 0, });
        assert_eq!(
            ledger.apply_transaction(&burn, NoopEventSink).await.unwrap_err(),
            LedgerError::InvalidAmount
        );
    });
}

#[test]
fn burn_rejects_unauthorized_signer() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        // alice signs a burn drawn from bob's account.
        let burn = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Burn {
                coin, from: bob, amount: 100, });
        assert_eq!(
            ledger.apply_transaction(&burn, NoopEventSink).await.unwrap_err(),
            LedgerError::Unauthorized
        );
    });
}

#[test]
fn burn_rejects_insufficient_balance() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let burn = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Burn {
                coin, from: alice, amount: 2_000, });
        assert!(matches!(
            ledger.apply_transaction(&burn, NoopEventSink).await.unwrap_err(),
            LedgerError::InsufficientBalance {
                available: 1_000,
                required: 2_000,
                ..
            }
        ));
    });
}

// ----- Mint error paths -----

#[test]
fn mint_rejects_non_issuer() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let bob_key = PrivateKey::ed25519_from_seed(2);
        let bob = address(&bob_key);

        let coin = ledger
            .create_token(alice, spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        // bob is not the issuer, so he cannot mint new supply.
        let mint = Transaction::sign(&bob_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Mint {
                coin, to: bob.clone(),
                amount: 100,
            },
        );
        assert_eq!(
            ledger.apply_transaction(&mint, NoopEventSink).await.unwrap_err(),
            LedgerError::Unauthorized
        );
    });
}

#[test]
fn mint_rejects_zero_amount() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let mint = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Mint {
                coin, to: alice, amount: 0, });
        assert_eq!(
            ledger.apply_transaction(&mint, NoopEventSink).await.unwrap_err(),
            LedgerError::InvalidAmount
        );
    });
}

#[test]
fn mint_rejects_unknown_token() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);

        let unknown =
            crate::TokenFactory::derive_coin_id(&alice, 7, &spec(1, None).expect("valid coin spec"));
        let mint = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Mint {
                coin: unknown, to: alice, amount: 100, });
        assert_eq!(
            ledger.apply_transaction(&mint, NoopEventSink).await.unwrap_err(),
            LedgerError::UnknownToken(unknown)
        );
    });
}

#[test]
fn mint_rejects_supply_overflow() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        // Issue a token whose supply already sits at the u128 ceiling.
        let coin = ledger
            .create_token(alice.clone(), spec(u128::MAX, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let mint = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Mint {
                coin, to: bob, amount: 1, });
        assert_eq!(
            ledger.apply_transaction(&mint, NoopEventSink).await.unwrap_err(),
            LedgerError::SupplyOverflow
        );
    });
}

// ----- Transfer error paths -----

#[test]
fn transfer_rejects_insufficient_balance() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let tx = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Transfer {
                coin, from: alice, to: bob, amount: 2_000, });
        assert!(matches!(
            ledger.apply_transaction(&tx, NoopEventSink).await.unwrap_err(),
            LedgerError::InsufficientBalance {
                available: 1_000,
                required: 2_000,
                ..
            }
        ));
    });
}

#[test]
fn transfer_rejects_zero_amount() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let tx = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Transfer {
                coin, from: alice, to: bob, amount: 0, });
        assert_eq!(
            ledger.apply_transaction(&tx, NoopEventSink).await.unwrap_err(),
            LedgerError::InvalidAmount
        );
    });
}

#[test]
fn transfer_rejects_unauthorized_signer() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        // alice signs a transfer drawn from bob's account.
        let tx = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Transfer {
                coin, from: bob, to: alice, amount: 100, });
        assert_eq!(
            ledger.apply_transaction(&tx, NoopEventSink).await.unwrap_err(),
            LedgerError::Unauthorized
        );
    });
}

#[test]
fn transfer_to_self_preserves_balance() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice_key = PrivateKey::ed25519_from_seed(1);
        let alice = address(&alice_key);

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let tx = Transaction::sign(&alice_key, nunchi_common::DEFAULT_CHAIN_ID, 0, crate::CoinOperation::Transfer {
                coin, from: alice.clone(),
                to: alice.clone(),
                amount: 250,
            },
        );
        ledger
            .apply_transaction(&tx, NoopEventSink)
            .await
            .expect("self transfer");

        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 1_000);
        assert_eq!(ledger.nonce(&alice).await.unwrap(), 1);
    });
}

// ----- create_token / credit / debit edges -----

#[test]
fn create_token_with_zero_supply_mints_no_balance() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));

        let coin = ledger
            .create_token(alice.clone(), spec(0, None).expect("valid coin spec"))
            .await
            .expect("create token");

        let token = ledger.token(&coin).await.unwrap().expect("token exists");
        assert_eq!(token.total_supply, 0);
        assert_eq!(token.issuer, alice);
        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 0);
    });
}

#[test]
fn credit_rejects_balance_overflow() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));

        let coin = ledger
            .create_token(alice.clone(), spec(0, None).expect("valid coin spec"))
            .await
            .expect("create token");

        ledger
            .credit(&alice, coin, u128::MAX)
            .await
            .expect("seed max balance");
        assert_eq!(
            ledger.credit(&alice, coin, 1).await.unwrap_err(),
            LedgerError::BalanceOverflow
        );
    });
}

#[test]
fn credit_and_debit_reject_unknown_token() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let unknown =
            crate::TokenFactory::derive_coin_id(&alice, 1, &spec(1, None).expect("valid coin spec"));

        assert_eq!(
            ledger.credit(&alice, unknown, 1).await.unwrap_err(),
            LedgerError::UnknownToken(unknown)
        );
        assert_eq!(
            ledger.debit(&alice, unknown, 1).await.unwrap_err(),
            LedgerError::UnknownToken(unknown)
        );
    });
}

// ----- fees -----

fn fee_config(coin: crate::CoinId, collector: Address, base: u128, per_byte: u128) -> FeeConfig {
    FeeConfig {
        coin,
        collector,
        base,
        per_byte,
    }
}

#[test]
fn charge_fee_moves_fee_to_collector_and_emits_event() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let collector = address(&PrivateKey::ed25519_from_seed(9));

        let coin = ledger
            .create_token(alice.clone(), spec(1_000, None).expect("valid coin spec"))
            .await
            .expect("create token");
        ledger.set_fee_config(&fee_config(coin, collector.clone(), 10, 2));

        let mut events = VecEventSink::new();
        ledger
            .charge_fee(&alice, 5, &mut events)
            .await
            .expect("charge fee");

        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 980);
        assert_eq!(ledger.balance(&collector, &coin).await.unwrap(), 20);
        // Fees move balances between accounts and never change supply.
        assert_eq!(
            ledger.token(&coin).await.unwrap().unwrap().total_supply,
            1_000
        );

        assert_eq!(events.len(), 1);
        let event = &events.events()[0];
        assert_eq!(event.name.as_ref(), crate::FEE_CHARGED_EVENT);
        let payload = FeeCharged::decode(event.value.as_ref()).expect("decode event");
        assert_eq!(
            payload,
            FeeCharged {
                coin,
                payer: alice,
                collector,
                amount: 20,
            }
        );
    });
}

#[test]
fn charge_fee_without_config_is_a_noop() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));

        let mut events = VecEventSink::new();
        ledger
            .charge_fee(&alice, 100, &mut events)
            .await
            .expect("free chain charges nothing");
        assert!(events.is_empty());
    });
}

#[test]
fn charge_fee_rejects_insufficient_balance() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let collector = address(&PrivateKey::ed25519_from_seed(9));

        let coin = ledger
            .create_token(alice.clone(), spec(100, None).expect("valid coin spec"))
            .await
            .expect("create token");
        ledger.set_fee_config(&fee_config(coin, collector.clone(), 200, 0));

        let err = ledger
            .charge_fee(&alice, 1, NoopEventSink)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LedgerError::InsufficientBalance {
                account: Box::new(alice.clone()),
                coin: Box::new(coin),
                available: 100,
                required: 200,
            }
        );
        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 100);
        assert_eq!(ledger.balance(&collector, &coin).await.unwrap(), 0);
    });
}

#[test]
fn charge_fee_rejects_quote_overflow() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let collector = address(&PrivateKey::ed25519_from_seed(9));

        let coin = ledger
            .create_token(alice.clone(), spec(100, None).expect("valid coin spec"))
            .await
            .expect("create token");

        ledger.set_fee_config(&fee_config(coin, collector.clone(), 0, u128::MAX));
        assert_eq!(
            ledger
                .charge_fee(&alice, 2, NoopEventSink)
                .await
                .unwrap_err(),
            LedgerError::FeeOverflow
        );

        ledger.set_fee_config(&fee_config(coin, collector, 1, u128::MAX));
        assert_eq!(
            ledger
                .charge_fee(&alice, 1, NoopEventSink)
                .await
                .unwrap_err(),
            LedgerError::FeeOverflow
        );
    });
}

#[test]
fn charge_fee_of_zero_stages_no_writes() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let collector = address(&PrivateKey::ed25519_from_seed(9));

        let coin = ledger
            .create_token(alice.clone(), spec(100, None).expect("valid coin spec"))
            .await
            .expect("create token");
        ledger.set_fee_config(&fee_config(coin, collector.clone(), 0, 0));

        let mut events = VecEventSink::new();
        ledger
            .charge_fee(&alice, 100, &mut events)
            .await
            .expect("zero fee");
        assert!(events.is_empty());
        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 100);
    });
}
