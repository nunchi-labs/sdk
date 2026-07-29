use commonware_consensus::types::Height;
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use futures::lock::Mutex as AsyncMutex;
use jsonrpsee::core::async_trait;
use nunchi_chain::SharedAppliedHeight;
use nunchi_dkg::Finalization;
use nunchi_rpc::encode_hex;
use std::sync::Arc;

use crate::rpc::{BridgeRpc, BridgeServer, LocalFinalizations};
use crate::{BridgeActor, SubmitResult};

use super::{finalization, schemes};

/// Mock implementation of `LocalFinalizations` for testing.
#[derive(Clone)]
struct MockLocal {
    latest_height: Option<u64>,
    finalizations: Vec<(u64, Finalization)>,
    /// When set, `latest_finalization` returns this error.
    error: Option<String>,
}

impl MockLocal {
    fn new() -> Self {
        Self {
            latest_height: None,
            finalizations: Vec::new(),
            error: None,
        }
    }

    fn with_finalization(mut self, height: u64, finalization: Finalization) -> Self {
        if self.latest_height.map_or(true, |h| height > h) {
            self.latest_height = Some(height);
        }
        self.finalizations.push((height, finalization));
        self
    }

    fn with_error(mut self, msg: &str) -> Self {
        self.error = Some(msg.to_string());
        self
    }
}

#[async_trait]
impl LocalFinalizations for MockLocal {
    async fn latest_height(&self) -> Option<u64> {
        self.latest_height
    }

    async fn finalization(&self, height: Height) -> Option<Finalization> {
        self.finalizations
            .iter()
            .find(|(h, _)| *h == height.get())
            .map(|(_, f)| f.clone())
    }

    async fn latest_finalization(&self) -> Result<Option<Finalization>, String> {
        if let Some(ref err) = self.error {
            return Err(err.clone());
        }
        match self.latest_height {
            None => Ok(None),
            Some(h) => Ok(self.finalization(Height::new(h)).await),
        }
    }
}

fn applied_height(h: u64) -> SharedAppliedHeight {
    Arc::new(AsyncMutex::new(Height::new(h)))
}

#[test]
fn status_reports_all_fields() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(10);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let fin = finalization(&schemes, 5, b"foreign");
        assert_eq!(mailbox.submit(fin).await, SubmitResult::Updated);

        let local = MockLocal::new().with_finalization(3, finalization(&schemes, 3, b"local"));
        let rpc = BridgeRpc::new(mailbox, local, applied_height(7));

        let status = rpc.status().await.expect("status should succeed");
        assert_eq!(status.applied_height, 7);
        assert_eq!(status.latest_local_height, Some(3));
        assert_eq!(status.latest_foreign_view, Some(5));
    });
}

#[test]
fn status_with_no_local_or_foreign() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(11);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let local = MockLocal::new();
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let status = rpc.status().await.expect("status should succeed");
        assert_eq!(status.applied_height, 1);
        assert_eq!(status.latest_local_height, None);
        assert_eq!(status.latest_foreign_view, None);
    });
}

#[test]
fn finalization_returns_none_for_missing_height() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(12);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let local = MockLocal::new();
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let result = rpc.finalization(99).await.expect("finalization rpc ok");
        assert_eq!(result, None);
    });
}

#[test]
fn finalization_returns_encoded_value_when_present() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(13);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let fin = finalization(&schemes, 5, b"local-block");
        let expected = encode_hex(&fin);
        let local = MockLocal::new().with_finalization(5, fin);
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let result = rpc.finalization(5).await.expect("finalization rpc ok");
        assert_eq!(result, Some(expected));
    });
}

#[test]
fn latest_finalization_returns_none_when_empty() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(14);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let local = MockLocal::new();
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let result = rpc
            .latest_finalization()
            .await
            .expect("latest_finalization rpc ok");
        assert_eq!(result, None);
    });
}

#[test]
fn latest_finalization_returns_encoded_value() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(15);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let fin = finalization(&schemes, 8, b"latest");
        let expected = encode_hex(&fin);
        let local = MockLocal::new().with_finalization(8, fin);
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let result = rpc
            .latest_finalization()
            .await
            .expect("latest_finalization rpc ok");
        assert_eq!(result, Some(expected));
    });
}

#[test]
fn latest_finalization_propagates_error() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(16);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let local = MockLocal::new().with_error("internal inconsistency");
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let result = rpc.latest_finalization().await;
        assert!(result.is_err(), "expected error from latest_finalization");
    });
}

#[test]
fn submit_finalization_returns_updated() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(17);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let fin = finalization(&schemes, 3, b"foreign");
        let encoded = encode_hex(&fin);
        let local = MockLocal::new();
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let response = rpc
            .submit_finalization(encoded)
            .await
            .expect("submit should succeed");
        assert_eq!(response.result, "updated");
        assert_eq!(response.accepted_view, Some(3));
    });
}

#[test]
fn submit_finalization_returns_stale() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(18);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        // First submit a newer finalization
        let newer = finalization(&schemes, 10, b"newer");
        assert_eq!(mailbox.submit(newer).await, SubmitResult::Updated);

        // Now submit an older one via RPC
        let older = finalization(&schemes, 2, b"older");
        let encoded = encode_hex(&older);
        let local = MockLocal::new();
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let response = rpc
            .submit_finalization(encoded)
            .await
            .expect("submit should succeed");
        assert_eq!(response.result, "stale");
        // accepted_view should still be the newer one
        assert_eq!(response.accepted_view, Some(10));
    });
}

#[test]
fn submit_finalization_returns_rejected_for_wrong_network() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let verifier_schemes = schemes(19);
        let other_schemes = schemes(20);
        let (actor, mailbox) = BridgeActor::new(verifier_schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let fin = finalization(&other_schemes, 3, b"wrong-network");
        let encoded = encode_hex(&fin);
        let local = MockLocal::new();
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let response = rpc
            .submit_finalization(encoded)
            .await
            .expect("submit should succeed");
        assert_eq!(response.result, "rejected");
        assert_eq!(response.accepted_view, None);
    });
}

#[test]
fn latest_accepted_returns_none_initially() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(21);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let local = MockLocal::new();
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let result = rpc.latest_accepted().await.expect("latest_accepted rpc ok");
        assert_eq!(result, None);
    });
}

#[test]
fn latest_accepted_returns_value_after_submit() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(22);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));

        let fin = finalization(&schemes, 7, b"accepted");
        let expected = encode_hex(&fin);
        assert_eq!(mailbox.submit(fin).await, SubmitResult::Updated);

        let local = MockLocal::new();
        let rpc = BridgeRpc::new(mailbox, local, applied_height(1));

        let result = rpc.latest_accepted().await.expect("latest_accepted rpc ok");
        assert_eq!(result, Some(expected));
    });
}
