mod common;

use common::network::TestNetworkBuilder;
use commonware_cryptography::Signer;
use commonware_macros::test_traced;
use commonware_runtime::deterministic;
use commonware_runtime::Runner as _;
use nunchi_coins::{
    AccountId, CoinId, CoinOperation, CoinSpec, PrivateKey, TokenFactory, Transaction,
};
use std::time::Duration;

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
    TokenFactory::derive_coin_id(&key(ALICE).public_key(), 0, &gold_spec())
}

/// Submit the demo scenario, returning the accounts involved.
///
/// Alice's operations go to node 0, Bob's to node 1 — demonstrating that each node only proposes
/// the transactions submitted to it, yet the whole network converges on the result.
async fn submit_scenario(
    network: &common::network::TestNetwork<'_>,
) -> (AccountId, AccountId, AccountId) {
    let alice = key(ALICE);
    let bob = key(BOB);
    let alice_id = alice.public_key();
    let bob_id = bob.public_key();
    let carol_id = key(CAROL).public_key();
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
            let state = shared.lock().await;
            roots.push(state.ledger.root());
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
        let state = shared.lock().await;
        let ledger = &state.ledger;
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
