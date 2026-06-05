mod common;

use common::network::{
    deterministic_state, lossy_link, reliable_link, TestNetworkBuilder, ThresholdFixture,
    ValidatorConfig,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::simulated::Link;
use commonware_runtime::{deterministic, Clock, Runner as _};
use nunchi_coins::{
    Address, CoinId, CoinOperation, CoinSpec, PrivateKey, TokenFactory, Transaction,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Duration;
use tracing::info;

const VALIDATORS: u32 = 5;

// Client account seeds (well clear of the low seeds the consensus fixture uses).
const ALICE: u64 = 100;
const BOB: u64 = 101;
const CAROL: u64 = 102;

fn key(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn gold_spec() -> CoinSpec {
    CoinSpec::new("GOLD", "Gold", 9, 1_000_000, None)
}

/// The id Alice's token will be assigned: it is the first token created on the chain, so the token
/// factory derives it with nonce 0.
fn gold_coin() -> CoinId {
    TokenFactory::derive_coin_id(&Address::from(key(ALICE).public_key()), 0, &gold_spec())
}

#[test_traced]
fn reaches_height_with_reliable_links() {
    let link = reliable_link();
    for seed in 0..5 {
        let state = deterministic_state(5, seed, link.clone(), 25);
        assert_eq!(state, deterministic_state(5, seed, link.clone(), 25));
    }
}

#[test_traced]
fn reaches_height_with_lossy_links() {
    let link = lossy_link();
    for seed in 0..5 {
        let state = deterministic_state(5, seed, link.clone(), 25);
        assert_eq!(state, deterministic_state(5, seed, link.clone(), 25));
    }
}

#[test_traced]
fn reaches_height_1k() {
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };
    deterministic_state(10, 0, link, 1000);
}

#[test_traced]
fn backfills_late_validator() {
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
}

#[test_traced]
fn recovers_unclean_shutdown() {
    let n = 5;
    let required_container = 100;
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

            let wait = context.gen_range(Duration::from_millis(250)..Duration::from_millis(1_000));
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
    node0.submit(Transaction::sign(
        &alice,
        0,
        CoinOperation::CreateToken { spec: gold_spec() },
    ));
    node0.submit(Transaction::sign(
        &alice,
        1,
        CoinOperation::Transfer {
            coin,
            from: alice_id.clone(),
            to: bob_id.clone(),
            amount: 300_000,
        },
    ));
    node0.submit(Transaction::sign(
        &alice,
        2,
        CoinOperation::Mint {
            coin,
            to: alice_id.clone(),
            amount: 50_000,
        },
    ));
    node0.submit(Transaction::sign(
        &alice,
        3,
        CoinOperation::Burn {
            coin,
            from: alice_id.clone(),
            amount: 100_000,
        },
    ));

    // Bob: forward some of what he received to Carol.
    node1.submit(Transaction::sign(
        &bob,
        0,
        CoinOperation::Transfer {
            coin,
            from: bob_id.clone(),
            to: carol_id.clone(),
            amount: 120_000,
        },
    ));

    (alice_id, bob_id, carol_id)
}

/// Every validator must commit to the same coin state once the client's transactions settle:
/// consensus on coin state, executed independently by each node from the finalized block stream.
#[test_traced]
fn coin_state_converges_across_validators() {
    let executor = deterministic::Runner::timed(Duration::from_secs(120));
    executor.start(|mut context| async move {
        let mut network = TestNetworkBuilder::new(VALIDATORS)
            .build(&mut context)
            .await;
        network.start_all().await;

        let (alice, bob, _carol) = submit_scenario(&network).await;
        network.run_until_nonces(&[(alice, 4), (bob, 1)]).await;

        let handles = network.ledger_handles();
        assert_eq!(handles.len(), VALIDATORS as usize);

        let mut roots = Vec::new();
        for shared in &handles {
            let ledger = shared.lock().await;
            roots.push(ledger.root());
        }

        let reference = roots[0];
        for (index, root) in roots.iter().enumerate() {
            assert_eq!(
                *root, reference,
                "validator {index} disagrees on the committed coin state root"
            );
        }
    });
}

/// The committed ledger must match what the submitted transactions prescribe, proving the chain
/// executed the create/transfer/mint/burn operations correctly (no coins lost or minted out of thin
/// air).
#[test_traced]
fn coin_balances_match_submitted_transactions() {
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
        let shared = network
            .ledger_handles()
            .into_iter()
            .next()
            .expect("at least one validator ledger");
        let ledger = shared.lock().await;
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
}
