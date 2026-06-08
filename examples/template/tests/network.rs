mod common;

use common::network::{
    deterministic_state, lossy_link, reliable_link, TestNetworkBuilder, ThresholdFixture,
    ValidatorConfig,
};
use commonware_macros::{select, test_traced};
use commonware_runtime::{deterministic, Clock, Runner as _};
use nunchi_template::BLOCKS_PER_EPOCH;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Duration;
use tracing::info;

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
fn reaches_next_epoch_after_reshare() {
    deterministic_state(5, 0, reliable_link(), BLOCKS_PER_EPOCH.get() + 25);
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
