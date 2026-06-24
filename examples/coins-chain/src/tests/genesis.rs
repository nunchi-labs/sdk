use crate::StateCommitment;
use nunchi_authority::{AuthorityGenesis, AuthorityLedger};
use nunchi_coins::{CoinsGenesis, Ledger};
use nunchi_common::{CommitState, QmdbState};

use commonware_cryptography::{ed25519, Hasher, Sha256, Signer as _};
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use nunchi_authority::{AuthorityDB, AuthorityOperation, Transaction as AuthorityTransaction};
use nunchi_coins::{Address, CoinDB, CoinSpec, TokenFactory, TokenName, TokenSymbol};
use nunchi_crypto::PrivateKey;
use nunchi_oracle::{
    NamespaceId, NamespacePolicyGenesis, OracleGenesis, OracleLedger, OracleNamespaceGenesis,
    OracleWriterGenesis,
};

use crate::genesis::*;

const GENESIS_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/genesis.json");

fn owner(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn validator(seed: u64) -> ed25519::PrivateKey {
    ed25519::PrivateKey::from_seed(seed)
}

fn external(seed: u64) -> Address {
    Address::external(&owner(seed).public_key())
}

fn oracle_namespace() -> NamespaceId {
    NamespaceId(Sha256::hash(b"coins-chain-oracle-namespace"))
}

fn sample_genesis() -> ChainGenesis {
    let owners = [owner(1), owner(2), owner(3)];
    let validators = [validator(10), validator(11)];
    let issuer = external(100);
    let alice = external(101);
    let bob = external(102);
    let oracle_admin = external(200);
    let oracle_updater = external(201);

    ChainGenesis {
        authority: Some(AuthorityGenesis {
            policy: nunchi_authority::AuthorityPolicyGenesis {
                owners: owners.iter().map(|owner| owner.public_key()).collect(),
                threshold: 2,
            },
            validators: validators
                .iter()
                .map(|validator| validator.public_key())
                .collect(),
            epoch: 0,
        }),
        coins: Some(CoinsGenesis {
            account_policies: Vec::new(),
            tokens: vec![nunchi_coins::TokenGenesis {
                issuer,
                spec: CoinSpec::new(
                    TokenSymbol::new("NCH").unwrap(),
                    TokenName::new("Nunchi").unwrap(),
                    9,
                    1_000,
                    Some(2_000),
                ),
                allocations: vec![
                    nunchi_coins::AllocationGenesis {
                        account: alice,
                        amount: 400,
                    },
                    nunchi_coins::AllocationGenesis {
                        account: bob,
                        amount: 600,
                    },
                ],
            }],
        }),
        oracle: Some(OracleGenesis {
            namespaces: vec![OracleNamespaceGenesis {
                namespace: oracle_namespace(),
                policy: NamespacePolicyGenesis {
                    admin: oracle_admin,
                    max_payload_size: 1024,
                },
                writers: vec![OracleWriterGenesis {
                    writer: oracle_updater,
                    enabled: true,
                }],
            }],
        }),
    }
}

async fn empty_commitment(context: deterministic::Context, partition: &str) -> StateCommitment {
    let state = QmdbState::init(context, partition).await.unwrap();
    state_commitment(state.sync_target().await)
}

#[test]
fn genesis_json_roundtrips() {
    let genesis = sample_genesis();
    let raw = serde_json::to_vec_pretty(&genesis).unwrap();
    let decoded = ChainGenesis::from_slice(&raw).unwrap();
    assert_eq!(decoded, genesis);
}

#[test]
fn genesis_json_loads_from_disk() {
    let genesis = ChainGenesis::from_slice(GENESIS_FIXTURE).unwrap();
    let path = std::env::temp_dir().join(format!("nunchi-genesis-{}.json", std::process::id()));
    std::fs::write(&path, GENESIS_FIXTURE).unwrap();

    assert_eq!(ChainGenesis::read(&path).unwrap(), genesis);

    let _ = std::fs::remove_file(path);
}

#[test]
fn genesis_json_fixture_roundtrips() {
    let genesis = ChainGenesis::from_slice(GENESIS_FIXTURE).unwrap();
    let raw = serde_json::to_vec_pretty(&genesis).unwrap();

    assert_eq!(ChainGenesis::from_slice(&raw).unwrap(), genesis);
}

#[test]
fn same_genesis_produces_same_commitment() {
    deterministic::Runner::default().start(|context| async move {
        let genesis = sample_genesis();
        let empty = empty_commitment(context.child("empty"), "genesis-empty").await;

        let mut first = QmdbState::init(context.child("first"), "genesis-first")
            .await
            .unwrap();
        genesis.apply_to_state(&mut first, &empty).await.unwrap();
        let first = state_commitment(first.sync_target().await);

        let mut second = QmdbState::init(context.child("second"), "genesis-second")
            .await
            .unwrap();
        genesis.apply_to_state(&mut second, &empty).await.unwrap();
        let second = state_commitment(second.sync_target().await);

        assert_eq!(first, second);
    });
}

#[test]
fn invalid_late_section_rolls_back_all_writes() {
    deterministic::Runner::default().start(|context| async move {
        let mut genesis = sample_genesis();
        genesis.coins.as_mut().unwrap().tokens[0].allocations[0].amount = 401;
        let empty = empty_commitment(context.child("empty"), "genesis-rollback-empty").await;
        let mut state = QmdbState::init(context.child("state"), "genesis-rollback")
            .await
            .unwrap();

        assert!(genesis.apply_to_state(&mut state, &empty).await.is_err());

        let authority = AuthorityLedger::new(state);
        assert_eq!(authority.policy().await.unwrap(), None);
    });
}

#[test]
fn applying_same_genesis_twice_is_noop() {
    deterministic::Runner::default().start(|context| async move {
        let genesis = sample_genesis();
        let empty = empty_commitment(context.child("empty"), "genesis-idempotent-empty").await;
        let mut state = QmdbState::init(context.child("state"), "genesis-idempotent")
            .await
            .unwrap();

        genesis.apply_to_state(&mut state, &empty).await.unwrap();
        let first = state_commitment(state.sync_target().await);
        genesis.apply_to_state(&mut state, &empty).await.unwrap();
        let second = state_commitment(state.sync_target().await);

        assert_eq!(first, second);
    });
}

#[test]
fn mismatched_genesis_is_rejected_after_initialization() {
    deterministic::Runner::default().start(|context| async move {
        let first = sample_genesis();
        let mut second = sample_genesis();
        second.authority.as_mut().unwrap().policy.threshold = 1;
        let empty = empty_commitment(context.child("empty"), "genesis-mismatch-empty").await;
        let mut state = QmdbState::init(context.child("state"), "genesis-mismatch")
            .await
            .unwrap();

        first.apply_to_state(&mut state, &empty).await.unwrap();
        assert!(matches!(
            second.apply_to_state(&mut state, &empty).await,
            Err(GenesisError::MismatchedGenesis)
        ));
    });
}

#[test]
fn unmarked_non_empty_state_is_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let genesis = sample_genesis();
        let empty = empty_commitment(context.child("empty"), "genesis-unmarked-empty").await;
        let mut state = QmdbState::init(context.child("state"), "genesis-unmarked")
            .await
            .unwrap();
        let mut ledger = Ledger::new(state);
        let issuer = external(100);
        ledger
            .create_token(
                issuer,
                CoinSpec::new(
                    TokenSymbol::new("OLD").unwrap(),
                    TokenName::new("Old").unwrap(),
                    0,
                    0,
                    None,
                ),
            )
            .await
            .unwrap();
        state = ledger.into_inner();
        state.commit().await.unwrap();

        assert!(matches!(
            genesis.apply_to_state(&mut state, &empty).await,
            Err(GenesisError::UnmarkedState)
        ));
    });
}

#[test]
fn authority_configure_bootstrap_is_closed_by_genesis() {
    deterministic::Runner::default().start(|context| async move {
        let genesis = sample_genesis();
        let empty = empty_commitment(context.child("empty"), "genesis-authority-empty").await;
        let mut state = QmdbState::init(context.child("state"), "genesis-authority")
            .await
            .unwrap();
        genesis.apply_to_state(&mut state, &empty).await.unwrap();

        let mut authority = AuthorityLedger::new(state);
        let attacker = owner(99);
        let attacker_nonce = AuthorityDB::nonce(authority.db(), &attacker.public_key())
            .await
            .unwrap();
        let configure = AuthorityTransaction::sign(
            &attacker,
            attacker_nonce,
            AuthorityOperation::Configure {
                policy: nunchi_authority::MultisigPolicy {
                    owners: vec![attacker.public_key()],
                    threshold: 1,
                },
                initial_validators: vec![validator(99).public_key()],
                epoch: 0,
            },
        );
        let error = authority
            .apply_transaction(&configure, 0)
            .await
            .unwrap_err();
        assert_eq!(error, nunchi_authority::AuthorityError::AlreadyConfigured);
    });
}

#[test]
fn coins_genesis_creates_token_and_initial_balances() {
    deterministic::Runner::default().start(|context| async move {
        let genesis = sample_genesis();
        let empty = empty_commitment(context.child("empty"), "genesis-coins-empty").await;
        let mut state = QmdbState::init(context.child("state"), "genesis-coins")
            .await
            .unwrap();
        genesis.apply_to_state(&mut state, &empty).await.unwrap();

        let issuer = external(100);
        let alice = external(101);
        let bob = external(102);
        let spec = CoinSpec::new(
            TokenSymbol::new("NCH").unwrap(),
            TokenName::new("Nunchi").unwrap(),
            9,
            1_000,
            Some(2_000),
        );
        let ledger = Ledger::new(state);
        let factory_nonce = CoinDB::factory_nonce(ledger.db())
            .await
            .unwrap()
            .checked_sub(1)
            .unwrap();
        let coin = TokenFactory::derive_coin_id(&issuer, factory_nonce, &spec);

        let token = ledger.token(&coin).await.unwrap().unwrap();
        assert_eq!(token.total_supply, 1_000);
        assert_eq!(ledger.balance(&issuer, &coin).await.unwrap(), 0);
        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 400);
        assert_eq!(ledger.balance(&bob, &coin).await.unwrap(), 600);
    });
}

#[test]
fn oracle_genesis_configures_namespace_and_writer() {
    deterministic::Runner::default().start(|context| async move {
        let genesis = sample_genesis();
        let empty = empty_commitment(context.child("empty"), "genesis-oracle-empty").await;
        let mut state = QmdbState::init(context.child("state"), "genesis-oracle")
            .await
            .unwrap();
        genesis.apply_to_state(&mut state, &empty).await.unwrap();

        let oracle = OracleLedger::new(state);
        let policy = oracle.namespace(&oracle_namespace()).await.unwrap().unwrap();
        assert_eq!(policy.max_payload_size, 1024);
    });
}
