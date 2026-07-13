use crate::indexer::{IndexerMetrics, LiveUploadArtifact};
use commonware_runtime::{
    deterministic, Clock as _, Metrics as _, Runner as _, Supervisor as _,
};
use std::time::Duration;

#[test]
fn live_upload_metrics_use_expected_labels() {
    deterministic::Runner::default().start(|context| async move {
        let indexer = context.child("indexer");
        let metrics = IndexerMetrics::register(&indexer);
        let artifact = LiveUploadArtifact::NotarizedSeed;

        metrics.live_upload_spawned(artifact);
        {
            let mut guard = metrics.start_live_upload(indexer.child("upload"), artifact);
            context.sleep(Duration::from_millis(1)).await;
            guard.succeed();
        }

        let encoded = context.encode();
        assert!(
            encoded.contains("indexer_live_upload_spawn_total{artifact=\"notarized_seed\"} 1")
        );
        assert!(
            encoded.contains("indexer_live_upload_in_flight{artifact=\"notarized_seed\"} 0")
        );
        assert!(encoded.contains(
            "indexer_live_upload_complete_total{artifact=\"notarized_seed\",status=\"success\"} 1",
        ));
        assert!(encoded.contains("indexer_live_upload_duration_seconds_bucket"));
        assert!(encoded.contains("artifact=\"notarized_seed\""));
        assert!(encoded.contains("status=\"success\""));
    });
}
