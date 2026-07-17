mod common;

use common::network::{
    deterministic_state, lossy_link, reliable_link, TestNetworkBuilder, ThresholdFixture,
    ValidatorConfig,
};
use commonware_cryptography::Signer as _;
use commonware_cryptography::{Hasher, Sha256};
use commonware_macros::{select, test_traced};
use commonware_p2p::simulated::Link;
use commonware_runtime::{deterministic, Clock, Runner as _};
use nunchi_authority::{
    proposal_id, AuthorityOperation, MultisigPolicy, RegistryChange,
    Transaction as AuthorityTransaction,
};
use nunchi_coins::{
    Address, CoinId, CoinOperation, CoinSpec, PrivateKey, TokenFactory, TokenName, TokenSymbol,
    Transaction,
};
use nunchi_oracle::{IntervalKey, NamespaceId, OracleOperation, Transaction as OracleTransaction};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Duration;
use tracing::info;

const VALIDATORS: u32 = 5;

// Client account seeds (well clear of the low seeds the consensus fixture uses).
const ALICE: u64 = 100;
const BOB: u64 = 101;
const CAROL: u64 = 102;

const TEST_STACK_SIZE: usize = 16 * 1024 * 1024;

fn with_large_stack(f: impl FnOnce() + Send + 'static) {
    let handle = std::thread::Builder::new()
        .stack_size(TEST_STACK_SIZE)
        .spawn(f)
        .expect("spawn large-stack test thread");
    if let Err(panic) = handle.join() {
        std::panic::resume_unwind(panic);
    }
}

fn key(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn authority_key(seed: u64) -> nunchi_crypto::PrivateKey {
    nunchi_crypto::PrivateKey::from_seed(seed)
}

fn gold_spec() -> CoinSpec {
    CoinSpec::new(
        TokenSymbol::new("GOLD").expect("valid token symbol"),
        TokenName::new("Gold").expect("valid token name"),
        9,
        1_000_000,
        None,
    )
}

/// The id Alice's token will be assigned: it is the first token created on the chain, so the token
/// factory derives it with nonce 0.
fn gold_coin() -> CoinId {
    TokenFactory::derive_coin_id(&Address::from(key(ALICE).public_key()), 0, &gold_spec())
}

fn oracle_namespace() -> NamespaceId {
    NamespaceId(Sha256::hash(b"coins-chain-integration-oracle-namespace"))
}

#[test_traced]
fn reaches_height_with_reliable_links() {
    with_large_stack(|| {
        let link = reliable_link();
        for seed in 0..5 {
            let state = deterministic_state(5, seed, link.clone(), 25);
            assert_eq!(state, deterministic_state(5, seed, link.clone(), 25));
        }
    });
}

#[test_traced]
fn reaches_height_with_lossy_links() {
    with_large_stack(|| {
        let link = lossy_link();
        for seed in 0..2 {
            let state_a = deterministic_state(5, seed, link.clone(), 16);
            let state_b = deterministic_state(5, seed, link.clone(), 16);
            assert_eq!(state_a, state_b);
        }
    });
}

#[test_traced]
fn reaches_height_100() {
    with_large_stack(|| {
        let link = Link {
            latency: Duration::from_millis(80),
            jitter: Duration::from_millis(10),
            success_rate: 0.98,
        };
        deterministic_state(10, 0, link, 100);
    });
}

#[test_traced]
fn backfills_late_validator() {
    with_large_stack(|| {
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let mut network = TestNetworkBuilder::new(5)
                .without_initial_links()
                .build(&mut context)
                .await;

            let link = reliable_link();
            network
                .link_where(link.clone(), |from, to| ![from, to].contains(&0usize))
                .await;

            for index in 1..5 {
                network.start_validator(index).await;
            }
            network.run_until_height(10).await;

            network
                .link_where(link, |from, to| {
                    [from, to].contains(&0usize) && ![from, to].contains(&1usize)
                })
                .await;
            network.start_validator(0).await;
            network.run_until_height(20).await;
        });
    });
}

#[test_traced]
fn recovers_unclean_shutdown() {
    with_large_stack(|| {
        let n = 5;
        let required_container = 60;
        let mut rng = StdRng::seed_from_u64(0);
        let fixture = ThresholdFixture::new(&mut rng, n);

        let mut runs = 0;
        let mut prev_checkpoint = None;
        loop {
            let fixture = fixture.clone();
            let f = |mut context: deterministic::Context| async move {
                // This test restarts validators every 250..1_000ms of simulated time.
                // Keep recovery timeouts below that window so a recovered view can
                // either certify or timeout/nullify before the next forced shutdown.
                let cfg = ValidatorConfig {
                    leader_timeout: Duration::from_millis(250),
                    certification_timeout: Duration::from_millis(500),
                };

                let wait =
                    context.gen_range(Duration::from_millis(250)..Duration::from_millis(1_000));
                let mut network = TestNetworkBuilder::new(n)
                    .with_fixture(fixture)
                    .with_initial_link(reliable_link())
                    .with_validator_config(cfg)
                    .build(&mut context)
                    .await;
                network.start_all().await;

                select! {
                    _ = network.run_until_height_with_interval(
                        required_container,
                        Duration::from_millis(10),
                    ) => {
                        true
                    },
                    _ = network.context().sleep(wait) => {
                        false
                    }
                }
            };

            let (complete, checkpoint) = if let Some(prev_checkpoint) = prev_checkpoint {
                deterministic::Runner::from(prev_checkpoint)
            } else {
                deterministic::Runner::timed(Duration::from_secs(30))
            }
            .start_and_recover(f);

            if complete {
                break;
            }

            prev_checkpoint = Some(checkpoint);
            runs += 1;
        }
        assert!(runs > 1);
        info!(runs, "unclean shutdown recovery worked");
    });
}

/// Submit the demo scenario, returning the accounts involved.
///
/// Alice's operations go to node 0, Bob's to node 1 — demonstrating that each node only proposes
/// the transactions submitted to it, yet the whole network converges on the result.
async fn submit_scenario(
    network: &common::network::TestNetwork<'_>,
) -> (Address, Address, Address) {
    let alice = key(ALICE);
    let bob = key(BOB);
    let alice_id = Address::from(alice.public_key());
    let bob_id = Address::from(bob.public_key());
    let carol_id = Address::from(key(CAROL).public_key());
    let coin = gold_coin();

    let node0 = network.submitter(0);
    let node1 = network.submitter(1);

    // Alice: create GOLD, send some to Bob, mint a bit more, burn a bit.
    node0
        .submit(
            Transaction::sign(&alice, 0, CoinOperation::CreateToken { spec: gold_spec() }).into(),
        )
        .await
        .expect("admit create token");
    node0
        .submit(
            Transaction::sign(
                &alice,
                1,
                CoinOperation::Transfer {
                    coin,
                    from: alice_id.clone(),
                    to: bob_id.clone(),
                    amount: 300_000,
                },
            )
            .into(),
        )
        .await
        .expect("admit transfer");
    node0
        .submit(
            Transaction::sign(
                &alice,
                2,
                CoinOperation::Mint {
                    coin,
                    to: alice_id.clone(),
                    amount: 50_000,
                },
            )
            .into(),
        )
        .await
        .expect("admit mint");
    node0
        .submit(
            Transaction::sign(
                &alice,
                3,
                CoinOperation::Burn {
                    coin,
                    from: alice_id.clone(),
                    amount: 100_000,
                },
            )
            .into(),
        )
        .await
        .expect("admit burn");

    // Bob: forward some of what he received to Carol.
    node1
        .submit(
            Transaction::sign(
                &bob,
                0,
                CoinOperation::Transfer {
                    coin,
                    from: bob_id.clone(),
                    to: carol_id.clone(),
                    amount: 120_000,
                },
            )
            .into(),
        )
        .await
        .expect("admit bob transfer");

    (alice_id, bob_id, carol_id)
}

/// Every validator must commit to the same coin state once the client's transactions settle:
/// consensus on coin state, executed independently by each node from the finalized block stream.
#[test_traced]
fn coin_state_converges_across_validators() {
    with_large_stack(|| {
        let executor = deterministic::Runner::timed(Duration::from_secs(120));
        executor.start(|mut context| async move {
            let mut network = TestNetworkBuilder::new(VALIDATORS)
                .build(&mut context)
                .await;
            network.start_all().await;

            let (alice, bob, _carol) = submit_scenario(&network).await;
            network
                .run_until_nonces(&[(alice.clone(), 4), (bob.clone(), 1)])
                .await;
            let roots = network.run_until_ledger_roots_converge().await;
            assert_eq!(roots.len(), VALIDATORS as usize);

            let reference = roots[0];
            for (index, root) in roots.iter().enumerate() {
                assert_eq!(
                    *root, reference,
                    "validator {index} disagrees on the committed coin state root"
                );
            }
        });
    });
}

/// The committed ledger must match what the submitted transactions prescribe, proving the chain
/// executed the create/transfer/mint/burn operations correctly (no coins lost or minted out of thin
/// air).
#[test_traced]
fn coin_balances_match_submitted_transactions() {
    with_large_stack(|| {
        let executor = deterministic::Runner::timed(Duration::from_secs(120));
        executor.start(|mut context| async move {
            let mut network = TestNetworkBuilder::new(VALIDATORS)
                .build(&mut context)
                .await;
            network.start_all().await;

            let (alice, bob, carol) = submit_scenario(&network).await;
            network
                .run_until_nonces(&[(alice.clone(), 4), (bob.clone(), 1)])
                .await;

            // Inspect any node; convergence (asserted separately) guarantees they all agree.
            let ledgers = network.ledgers().await;
            let ledger = ledgers
                .into_iter()
                .next()
                .expect("at least one validator ledger");
            let coin = gold_coin();

            // Alice: 1_000_000 - 300_000 (to Bob) + 50_000 (mint) - 100_000 (burn) = 650_000.
            assert_eq!(ledger.balance(&alice, &coin).await.unwrap(), 650_000);
            // Bob: received 300_000, forwarded 120_000 to Carol = 180_000.
            assert_eq!(ledger.balance(&bob, &coin).await.unwrap(), 180_000);
            // Carol: received 120_000.
            assert_eq!(ledger.balance(&carol, &coin).await.unwrap(), 120_000);

            // Supply: 1_000_000 initial + 50_000 mint - 100_000 burn = 950_000.
            let token = ledger
                .token(&coin)
                .await
                .unwrap()
                .expect("token must exist");
            assert_eq!(token.total_supply, 950_000);

            // Conservation: all balances sum to the total supply.
            let total = ledger.balance(&alice, &coin).await.unwrap()
                + ledger.balance(&bob, &coin).await.unwrap()
                + ledger.balance(&carol, &coin).await.unwrap();
            assert_eq!(total, token.total_supply, "balances must conserve supply");
        });
    });
}

#[test_traced]
fn authority_registry_updates_onchain() {
    with_large_stack(|| {
        let executor = deterministic::Runner::timed(Duration::from_secs(120));
        executor.start(|mut context| async move {
            let mut network = TestNetworkBuilder::new(VALIDATORS)
                .build(&mut context)
                .await;
            network.start_all().await;

            let owners = [authority_key(500), authority_key(501), authority_key(502)];
            let owner_ids = owners
                .iter()
                .map(nunchi_crypto::PrivateKey::public_key)
                .collect::<Vec<_>>();
            let initial = network.participants().to_vec();
            let added = commonware_cryptography::ed25519::PrivateKey::from_seed(900).public_key();
            let change = RegistryChange::AddValidator {
                validator: added.clone(),
            };
            let proposal = proposal_id(&change, 3);
            let submitter = network.submitter(0);

            submitter
                .submit(
                    AuthorityTransaction::sign(
                        &owners[0],
                        0,
                        AuthorityOperation::Configure {
                            policy: MultisigPolicy {
                                owners: owner_ids,
                                threshold: 2,
                            },
                            initial_validators: initial.clone(),
                            epoch: 0,
                        },
                    )
                    .into(),
                )
                .await
                .expect("admit configure");
            submitter
                .submit(
                    AuthorityTransaction::sign(
                        &owners[0],
                        1,
                        AuthorityOperation::Propose {
                            change,
                            effective_epoch: 3,
                        },
                    )
                    .into(),
                )
                .await
                .expect("admit propose");
            submitter
                .submit(
                    AuthorityTransaction::sign(
                        &owners[1],
                        0,
                        AuthorityOperation::Approve { proposal },
                    )
                    .into(),
                )
                .await
                .expect("admit approve");
            submitter
                .submit(
                    AuthorityTransaction::sign(
                        &owners[2],
                        0,
                        AuthorityOperation::Execute { proposal },
                    )
                    .into(),
                )
                .await
                .expect("admit execute");

            network.run_until_height(12).await;

            let ledgers = network.authority_ledgers().await;
            assert_eq!(ledgers.len(), VALIDATORS as usize);

            for ledger in ledgers {
                let epoch_4 = ledger.epoch_registry(4).await.unwrap().unwrap();
                let epoch_5 = ledger.epoch_registry(5).await.unwrap().unwrap();
                assert!(epoch_4.players.contains(&added));
                assert!(!epoch_4.dealers.contains(&added));
                assert!(epoch_5.players.contains(&added));
                assert!(epoch_5.dealers.contains(&added));
            }
        });
    });
}

#[test_traced]
fn oracle_updates_finalize_across_validators() {
    with_large_stack(|| {
        let executor = deterministic::Runner::timed(Duration::from_secs(120));
        executor.start(|mut context| async move {
            let mut network = TestNetworkBuilder::new(VALIDATORS)
                .build(&mut context)
                .await;
            network.start_all().await;

            let updater = authority_key(701);
            let submitter = network.submitter(0);
            submitter
                .submit(
                    OracleTransaction::sign(
                        &updater,
                        0,
                        OracleOperation::AppendRecord {
                            namespace: oracle_namespace(),
                            interval: IntervalKey::new(3),
                            payload: b"opaque-oracle-payload".to_vec(),
                            proof: None,
                        },
                    )
                    .into(),
                )
                .await
                .expect("admit oracle update");

            loop {
                let ledgers = network.oracle_ledgers().await;
                if ledgers.len() == VALIDATORS as usize {
                    let mut all_updated = true;
                    for ledger in ledgers {
                        let records = ledger
                            .records_by_namespace(
                                &oracle_namespace(),
                                IntervalKey::new(3),
                                IntervalKey::new(3),
                            )
                            .await
                            .unwrap();
                        if records.len() != 1 || records[0].payload != b"opaque-oracle-payload" {
                            all_updated = false;
                            break;
                        }
                    }
                    if all_updated {
                        break;
                    }
                }
                network.context().sleep(Duration::from_secs(1)).await;
            }
        });
    });
}

/// The mempool reports each submission's lifecycle: executable transactions finalize, while a
/// nonce-gapped transaction is admitted but never proposed and stays pending.
#[test_traced]
fn mempool_tracks_status_through_finalization() {
    with_large_stack(|| {
        let executor = deterministic::Runner::timed(Duration::from_secs(120));
        executor.start(|mut context| async move {
            let mut network = TestNetworkBuilder::new(VALIDATORS)
                .build(&mut context)
                .await;
            network.start_all().await;

            let alice = key(ALICE);
            let alice_id = Address::from(alice.public_key());
            let coin = gold_coin();
            let node0 = network.submitter(0);

            let mut digests = Vec::new();
            digests.push(
                node0
                    .submit(
                        Transaction::sign(
                            &alice,
                            0,
                            CoinOperation::CreateToken { spec: gold_spec() },
                        )
                        .into(),
                    )
                    .await
                    .expect("admit create token"),
            );
            for nonce in 1..3 {
                digests.push(
                    node0
                        .submit(
                            Transaction::sign(
                                &alice,
                                nonce,
                                CoinOperation::Mint {
                                    coin,
                                    to: alice_id.clone(),
                                    amount: 1_000,
                                },
                            )
                            .into(),
                        )
                        .await
                        .expect("admit mint"),
                );
            }
            // Nonce 5 leaves a gap at 3 and 4: admitted, but never proposable.
            let gapped = node0
                .submit(
                    Transaction::sign(
                        &alice,
                        5,
                        CoinOperation::Mint {
                            coin,
                            to: alice_id.clone(),
                            amount: 1_000,
                        },
                    )
                    .into(),
                )
                .await
                .expect("admit gapped mint");

            network.run_until_nonces(&[(alice_id, 3)]).await;

            // The pool learns of finalization via a fire-and-forget report, so poll briefly.
            for digest in digests {
                loop {
                    match node0.status(digest).await {
                        Some(nunchi_mempool::TxStatus::Finalized { .. }) => break,
                        Some(nunchi_mempool::TxStatus::Pending) => {
                            network.context().sleep(Duration::from_millis(100)).await;
                        }
                        other => panic!("expected finalization, got {other:?}"),
                    }
                }
            }
            assert_eq!(
                node0.status(gapped).await,
                Some(nunchi_mempool::TxStatus::Pending),
                "gapped transaction must stay pending"
            );
        });
    });
}

/// Resubmitting the same nonce replaces the earlier transaction: only the replacement finalizes.
#[test_traced]
fn mempool_replaces_same_nonce_resubmission() {
    with_large_stack(|| {
        let executor = deterministic::Runner::timed(Duration::from_secs(120));
        executor.start(|mut context| async move {
            let mut network = TestNetworkBuilder::new(VALIDATORS)
                .build(&mut context)
                .await;
            network.start_all().await;

            let alice = key(ALICE);
            let alice_id = Address::from(alice.public_key());
            let node0 = network.submitter(0);

            let original = node0
                .submit(
                    Transaction::sign(&alice, 0, CoinOperation::CreateToken { spec: gold_spec() })
                        .into(),
                )
                .await
                .expect("admit original");
            let replacement = node0
                .submit(
                    Transaction::sign(
                        &alice,
                        0,
                        CoinOperation::CreateToken {
                            spec: CoinSpec::new(
                                TokenSymbol::new("SILV").expect("valid token symbol"),
                                TokenName::new("Silver").expect("valid token name"),
                                9,
                                500_000,
                                None,
                            ),
                        },
                    )
                    .into(),
                )
                .await
                .expect("admit replacement");

            assert_eq!(
                node0.status(original).await,
                Some(nunchi_mempool::TxStatus::Dropped {
                    reason: nunchi_mempool::DropReason::Replaced
                })
            );

            network.run_until_nonces(&[(alice_id.clone(), 1)]).await;
            loop {
                match node0.status(replacement).await {
                    Some(nunchi_mempool::TxStatus::Finalized { .. }) => break,
                    Some(nunchi_mempool::TxStatus::Pending) => {
                        network.context().sleep(Duration::from_millis(100)).await;
                    }
                    other => panic!("expected finalization, got {other:?}"),
                }
            }

            // The chain holds Silver, not Gold: the replacement is what executed.
            let ledger = network.ledgers().await.into_iter().next().expect("ledger");
            let silver = TokenFactory::derive_coin_id(
                &alice_id,
                0,
                &CoinSpec::new(
                    TokenSymbol::new("SILV").expect("valid token symbol"),
                    TokenName::new("Silver").expect("valid token name"),
                    9,
                    500_000,
                    None,
                ),
            );
            assert!(ledger.token(&silver).await.unwrap().is_some());
            assert!(ledger.token(&gold_coin()).await.unwrap().is_none());
        });
    });
}
