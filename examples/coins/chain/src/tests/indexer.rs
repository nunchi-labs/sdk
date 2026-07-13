use crate::{
    indexer::{
        BlockMetricSource, HttpArtifact, IndexerMetrics, LiveUploadArtifact, SharedCacheSource,
        SharedRetentionReason,
    },
    Block, StateCommitment, Transaction, EPOCH,
};
use commonware_consensus::types::{Height, Round, View};
use commonware_cryptography::{ed25519, Hasher, Sha256, Signer};
use commonware_runtime::{
    deterministic, Clock as _, Metrics as _, Runner as _, Supervisor as _,
};
use commonware_storage::mmr::Location;
use commonware_utils::range::NonEmptyRange;
use std::time::Duration;

fn state(height: u64) -> StateCommitment {
    StateCommitment {
        root: Sha256::hash(&height.to_be_bytes()),
        range: NonEmptyRange::new(Location::new(height)..Location::new(height + 1))
            .expect("non-empty range"),
    }
}

fn block(view: u64, height: u64, label: &[u8]) -> Block {
    Block::new(
        crate::Context {
            round: Round::new(EPOCH, View::new(view)),
            leader: ed25519::PrivateKey::from_seed(view).public_key(),
            parent: (
                View::new(view.saturating_sub(1)),
                Sha256::hash(format!("parent-{view}").as_bytes()),
            ),
        },
        Sha256::hash(label),
        Height::new(height),
        height,
        Vec::<Transaction>::new(),
        None,
        (),
        state(height),
    )
}

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

#[test]
fn shared_state_metrics_use_expected_labels() {
    deterministic::Runner::default().start(|context| async move {
        let indexer = context.child("indexer");
        let metrics = IndexerMetrics::register(&indexer);

        metrics.shared_state(1, 256, 2, 3, 4, 5, 6);
        metrics.shared_cache_inserted(SharedCacheSource::ProducerRecord);
        metrics.shared_cache_inserted(SharedCacheSource::LiveCertificate);
        metrics.shared_cache_inserted(SharedCacheSource::ConsumerMarshal);
        metrics.shared_cache_removed(SharedRetentionReason::Uploaded);
        metrics.shared_cache_removed(SharedRetentionReason::CertificateFinished);
        metrics.shared_cache_removed(SharedRetentionReason::Pruned);
        metrics.shared_pruned(SharedRetentionReason::Uploaded, 1);
        metrics.shared_pruned(SharedRetentionReason::CertificateFinished, 1);
        metrics.shared_pruned(SharedRetentionReason::Pruned, 1);

        let encoded = context.encode();
        assert!(encoded.contains("indexer_shared_cached_blocks 1"));
        assert!(encoded.contains("indexer_shared_cached_block_estimated_bytes 256"));
        assert!(encoded.contains("indexer_shared_certificate_upload_digests 2"));
        assert!(encoded.contains("indexer_shared_certificate_upload_refs 3"));
        assert!(encoded.contains("indexer_shared_uploaded_digests 4"));
        assert!(encoded.contains("indexer_shared_latest_finalized_height 5"));
        assert!(encoded.contains("indexer_shared_acked_through_height 6"));
        assert!(encoded.contains(
            "indexer_shared_cache_insert_total{source=\"producer_record\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_shared_cache_insert_total{source=\"live_certificate\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_shared_cache_insert_total{source=\"consumer_marshal\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_shared_cache_remove_total{reason=\"uploaded\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_shared_cache_remove_total{reason=\"certificate_finished\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_shared_cache_remove_total{reason=\"pruned\"} 1",
        ));
        assert!(encoded.contains("indexer_shared_prune_total{reason=\"uploaded\"} 1"));
        assert!(encoded
            .contains("indexer_shared_prune_total{reason=\"certificate_finished\"} 1"));
        assert!(encoded.contains("indexer_shared_prune_total{reason=\"pruned\"} 1"));
    });
}

#[test]
fn block_metrics_use_expected_sources() {
    deterministic::Runner::default().start(|context| async move {
        let indexer = context.child("indexer");
        let metrics = IndexerMetrics::register(&indexer);
        let block = block(3, 3, b"block");

        metrics.observe_block(BlockMetricSource::ProducerRecord, &block);
        metrics.observe_block(BlockMetricSource::LiveCertificate, &block);
        metrics.observe_block(BlockMetricSource::ConsumerCached, &block);
        metrics.observe_block(BlockMetricSource::ConsumerMarshal, &block);

        let encoded = context.encode();
        assert!(encoded.contains("indexer_block_estimated_bytes_bucket"));
        assert!(encoded.contains("indexer_block_transaction_count_bucket"));
        assert!(encoded.contains("source=\"producer_record\""));
        assert!(encoded.contains("source=\"live_certificate\""));
        assert!(encoded.contains("source=\"consumer_cached\""));
        assert!(encoded.contains("source=\"consumer_marshal\""));
    });
}
