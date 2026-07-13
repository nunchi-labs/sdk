use crate::indexer::{HttpArtifact, IndexerMetrics, LiveUploadArtifact};
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
        let marshal_artifact = LiveUploadArtifact::NotarizedBlock;

        metrics.live_upload_spawned(artifact);
        {
            let mut guard = metrics.start_live_upload(indexer.child("upload"), artifact);
            context.sleep(Duration::from_millis(1)).await;
            guard.succeed();
        }
        {
            let wait_context = indexer.child("marshal_wait");
            let mut guard = metrics.start_live_marshal_wait(&wait_context, marshal_artifact);
            context.sleep(Duration::from_millis(1)).await;
            guard.found();
        }
        {
            let wait_context = indexer.child("cancelled_marshal_wait");
            let _guard = metrics.start_live_marshal_wait(&wait_context, marshal_artifact);
            context.sleep(Duration::from_millis(1)).await;
        }
        metrics.http_encoded(HttpArtifact::Finalization, 128, Duration::from_micros(10));
        {
            let mut guard = metrics.start_http_request(HttpArtifact::Finalization, 128);
            guard.succeed();
        }
        {
            let mut guard = metrics.start_http_request(HttpArtifact::Notarization, 64);
            guard.http_status_error();
        }
        {
            let _guard = metrics.start_http_request(HttpArtifact::DkgOutput, 32);
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
        assert!(encoded.contains("indexer_live_marshal_wait_in_flight 0"));
        assert!(encoded.contains(
            "indexer_live_marshal_wait_complete_total{artifact=\"notarized_block\",status=\"found\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_live_marshal_wait_complete_total{artifact=\"notarized_block\",status=\"cancelled\"} 1",
        ));
        assert!(encoded.contains("indexer_live_marshal_wait_duration_seconds_bucket"));
        assert!(encoded.contains(
            "indexer_http_encode_total{artifact=\"finalization\"} 1",
        ));
        assert!(encoded.contains("indexer_http_encode_bytes_bucket"));
        assert!(encoded.contains("indexer_http_encode_duration_seconds_bucket"));
        assert!(encoded.contains(
            "indexer_http_request_body_in_flight_bytes{artifact=\"finalization\"} 0",
        ));
        assert!(
            encoded.contains("indexer_http_request_in_flight{artifact=\"finalization\"} 0")
        );
        assert!(encoded.contains(
            "indexer_http_request_complete_total{artifact=\"finalization\",status=\"success\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_http_request_complete_total{artifact=\"notarization\",status=\"http_status_error\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_http_request_complete_total{artifact=\"dkg_output\",status=\"transport_error\"} 1",
        ));
        assert!(encoded.contains("indexer_http_request_duration_seconds_bucket"));
        assert!(encoded.contains("artifact=\"notarized_seed\""));
        assert!(encoded.contains("artifact=\"notarized_block\""));
        assert!(encoded.contains("artifact=\"dkg_output\""));
        assert!(encoded.contains("artifact=\"notarization\""));
        assert!(encoded.contains("artifact=\"finalization\""));
        assert!(encoded.contains("status=\"success\""));
        assert!(encoded.contains("status=\"found\""));
        assert!(encoded.contains("status=\"cancelled\""));
        assert!(encoded.contains("status=\"http_status_error\""));
        assert!(encoded.contains("status=\"transport_error\""));
    });
}
