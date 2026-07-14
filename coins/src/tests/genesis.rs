use crate::{
    account::{
        external_account_id, multisig_account_id, AccountType, Address, MultisigPolicy, PrivateKey,
    },
    asset::{TokenName, TokenSymbol},
    AccountPolicyGenesis, AllocationGenesis, CoinSpec, CoinsGenesis, FeeConfig, FeeGenesis, Ledger,
    LedgerError, MultisigPolicyGenesis, TokenGenesis,
};
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::QmdbState;

async fn ledger(context: deterministic::Context) -> Ledger<QmdbState<deterministic::Context>> {
    let db = QmdbState::init(context, "coins-genesis-test")
        .await
        .expect("init state db");
    Ledger::new(db)
}

fn spec(supply: u128, max: Option<u128>) -> CoinSpec {
    CoinSpec::new(
        TokenSymbol::new("NCH").expect("symbol"),
        TokenName::new("Nunchi").expect("name"),
        9,
        supply,
        max,
    )
}

fn address(key: &PrivateKey) -> Address {
    external_account_id(&key.public_key())
}

// ----- happy paths -----

#[test]
fn apply_genesis_distributes_token_allocations() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let bob = address(&PrivateKey::ed25519_from_seed(2));
        let carol = address(&PrivateKey::ed25519_from_seed(3));

        let genesis = CoinsGenesis {
            fees: None,
            account_policies: vec![],
            tokens: vec![TokenGenesis {
                issuer: alice.clone(),
                spec: spec(1_000, None),
                allocations: vec![
                    AllocationGenesis {
                        account: bob.clone(),
                        amount: 600,
                    },
                    AllocationGenesis {
                        account: carol.clone(),
                        amount: 400,
                    },
                ],
            }],
        };
        ledger.apply_genesis(&genesis).await.expect("apply genesis");

        // First token: issuer=alice, factory nonce 0, same spec -> deterministic id.
        let coin = crate::TokenFactory::derive_coin_id(&alice, 0, &spec(1_000, None));
        assert_eq!(ledger.balance(&bob, &coin).await.unwrap(), 600);
        assert_eq!(ledger.balance(&carol, &coin).await.unwrap(), 400);
        // The issuer's seed supply is fully distributed.
        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 0);
        assert_eq!(
            ledger.token(&coin).await.unwrap().unwrap().total_supply,
            1_000
        );
    });
}

#[test]
fn apply_genesis_without_allocations_leaves_supply_with_issuer() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));

        let genesis = CoinsGenesis {
            fees: None,
            account_policies: vec![],
            tokens: vec![TokenGenesis {
                issuer: alice.clone(),
                spec: spec(1_000, None),
                allocations: vec![],
            }],
        };
        ledger.apply_genesis(&genesis).await.expect("apply genesis");

        let coin = crate::TokenFactory::derive_coin_id(&alice, 0, &spec(1_000, None));
        assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 1_000);
        assert_eq!(
            ledger.token(&coin).await.unwrap().unwrap().total_supply,
            1_000
        );
    });
}

#[test]
fn apply_genesis_registers_multisig_account_policy() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let a = PrivateKey::ed25519_from_seed(1);
        let b = PrivateKey::ed25519_from_seed(2);
        let policy = MultisigPolicy::new(2, vec![a.public_key(), b.public_key()]).expect("policy");
        let account_id = multisig_account_id(&policy);

        let genesis = CoinsGenesis {
            fees: None,
            account_policies: vec![AccountPolicyGenesis {
                account_id: account_id.clone(),
                policy: MultisigPolicyGenesis {
                    threshold: 2,
                    signers: vec![a.public_key(), b.public_key()],
                },
            }],
            tokens: vec![],
        };
        ledger.apply_genesis(&genesis).await.expect("apply genesis");

        let account = ledger.account(&account_id).await.expect("account");
        assert_eq!(account.kind, AccountType::Multisig);
    });
}

#[test]
fn apply_genesis_creates_multiple_tokens() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));

        let genesis = CoinsGenesis {
            fees: None,
            account_policies: vec![],
            tokens: vec![
                TokenGenesis {
                    issuer: alice.clone(),
                    spec: spec(1_000, None),
                    allocations: vec![],
                },
                TokenGenesis {
                    issuer: alice.clone(),
                    spec: spec(500, None),
                    allocations: vec![],
                },
            ],
        };
        ledger.apply_genesis(&genesis).await.expect("apply genesis");

        // Tokens derive from an incrementing factory nonce, so their ids differ.
        let first = crate::TokenFactory::derive_coin_id(&alice, 0, &spec(1_000, None));
        let second = crate::TokenFactory::derive_coin_id(&alice, 1, &spec(500, None));
        assert_ne!(first, second);
        assert_eq!(ledger.balance(&alice, &first).await.unwrap(), 1_000);
        assert_eq!(ledger.balance(&alice, &second).await.unwrap(), 500);
    });
}

// ----- error paths -----

#[test]
fn apply_genesis_rejects_allocation_sum_mismatch() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let bob = address(&PrivateKey::ed25519_from_seed(2));
        let carol = address(&PrivateKey::ed25519_from_seed(3));

        // Allocations sum to 900, but the token's supply is 1_000.
        let genesis = CoinsGenesis {
            fees: None,
            account_policies: vec![],
            tokens: vec![TokenGenesis {
                issuer: alice,
                spec: spec(1_000, None),
                allocations: vec![
                    AllocationGenesis {
                        account: bob,
                        amount: 500,
                    },
                    AllocationGenesis {
                        account: carol,
                        amount: 400,
                    },
                ],
            }],
        };
        assert_eq!(
            ledger.apply_genesis(&genesis).await.unwrap_err(),
            LedgerError::AllocationSumMismatch {
                expected: 1_000,
                actual: 900,
            }
        );
    });
}

#[test]
fn apply_genesis_rejects_zero_allocation_amount() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let bob = address(&PrivateKey::ed25519_from_seed(2));

        let genesis = CoinsGenesis {
            fees: None,
            account_policies: vec![],
            tokens: vec![TokenGenesis {
                issuer: alice,
                spec: spec(1_000, None),
                allocations: vec![AllocationGenesis {
                    account: bob,
                    amount: 0,
                }],
            }],
        };
        assert_eq!(
            ledger.apply_genesis(&genesis).await.unwrap_err(),
            LedgerError::InvalidAmount
        );
    });
}

#[test]
fn apply_genesis_rejects_allocation_overflow() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let bob = address(&PrivateKey::ed25519_from_seed(2));
        let carol = address(&PrivateKey::ed25519_from_seed(3));

        // The allocation amounts overflow u128 when summed.
        let genesis = CoinsGenesis {
            fees: None,
            account_policies: vec![],
            tokens: vec![TokenGenesis {
                issuer: alice,
                spec: spec(0, None),
                allocations: vec![
                    AllocationGenesis {
                        account: bob,
                        amount: u128::MAX,
                    },
                    AllocationGenesis {
                        account: carol,
                        amount: 1,
                    },
                ],
            }],
        };
        assert_eq!(
            ledger.apply_genesis(&genesis).await.unwrap_err(),
            LedgerError::BalanceOverflow
        );
    });
}

#[test]
fn apply_genesis_rejects_account_policy_mismatch() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let a = PrivateKey::ed25519_from_seed(1);
        let b = PrivateKey::ed25519_from_seed(2);
        // A valid policy, but registered under the wrong account id.
        let wrong = address(&PrivateKey::ed25519_from_seed(9));

        let genesis = CoinsGenesis {
            fees: None,
            account_policies: vec![AccountPolicyGenesis {
                account_id: wrong.clone(),
                policy: MultisigPolicyGenesis {
                    threshold: 2,
                    signers: vec![a.public_key(), b.public_key()],
                },
            }],
            tokens: vec![],
        };
        assert_eq!(
            ledger.apply_genesis(&genesis).await.unwrap_err(),
            LedgerError::AccountPolicyMismatch(Box::new(wrong))
        );
    });
}

#[test]
fn multisig_policy_genesis_rejects_invalid_threshold() {
    // A zero threshold is rejected when reconstructing the on-chain policy;
    // this is a pure check that needs no ledger.
    let signer = PrivateKey::ed25519_from_seed(1).public_key();
    let policy = MultisigPolicyGenesis {
        threshold: 0,
        signers: vec![signer],
    };
    assert!(matches!(
        policy.policy().unwrap_err(),
        LedgerError::InvalidAccountPolicy(_)
    ));
}

#[test]
fn apply_genesis_sets_fee_config() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let collector = address(&PrivateKey::ed25519_from_seed(9));

        let genesis = CoinsGenesis {
            account_policies: vec![],
            tokens: vec![TokenGenesis {
                issuer: alice.clone(),
                spec: spec(1_000, None),
                allocations: vec![],
            }],
            fees: Some(FeeGenesis {
                token: 0,
                collector: collector.clone(),
                base: 10,
                per_byte: 2,
            }),
        };
        ledger.apply_genesis(&genesis).await.expect("apply genesis");

        let coin = crate::TokenFactory::derive_coin_id(&alice, 0, &spec(1_000, None));
        assert_eq!(
            ledger.fee_config().await.unwrap(),
            Some(FeeConfig {
                coin,
                collector,
                base: 10,
                per_byte: 2,
            })
        );
    });
}

#[test]
fn apply_genesis_rejects_fee_token_index_out_of_range() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut ledger = ledger(context).await;
        let alice = address(&PrivateKey::ed25519_from_seed(1));
        let collector = address(&PrivateKey::ed25519_from_seed(9));

        let genesis = CoinsGenesis {
            account_policies: vec![],
            tokens: vec![TokenGenesis {
                issuer: alice,
                spec: spec(1_000, None),
                allocations: vec![],
            }],
            fees: Some(FeeGenesis {
                token: 1,
                collector,
                base: 10,
                per_byte: 2,
            }),
        };
        assert!(matches!(
            ledger.apply_genesis(&genesis).await.unwrap_err(),
            LedgerError::InvalidGenesis(_)
        ));
    });
}
