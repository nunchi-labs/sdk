mod common;

use common::network::{deterministic_state, lossy_link, reliable_link, TestNetworkBuilder};
use commonware_macros::test_traced;
use commonware_runtime::{deterministic, Runner as _};
use std::time::Duration;

#[test_traced]
fn reaches_height_with_reliable_links() {
    let state = deterministic_state(5, 0, reliable_link(), 25);
    assert_eq!(state, deterministic_state(5, 0, reliable_link(), 25));
}

#[test_traced]
fn reaches_height_with_lossy_links() {
    let state = deterministic_state(5, 0, lossy_link(), 10);
    assert_eq!(state, deterministic_state(5, 0, lossy_link(), 10));
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
