use crate::{
    indexer::{
        BackfillDecision, BackfillPhase, BackfillResetReason, BackfillWaitReason,
        BlockMetricSource, DkgUploadStatus, HttpArtifact, IndexerMetrics, LiveUploadArtifact,
        ProducerActivity, ProducerStatus, QueueReadSource, QueueStatus, SharedCacheSource,
        SharedRetentionReason,
        SharedStateSnapshot,
    },
    Block, StateCommitment, Transaction, EPOCH,
};
use commonware_consensus::types::{Height, Round, View};
use commonware_cryptography::{ed25519, Hasher, Sha256, Signer};
use commonware_runtime::{
    deterministic, Clock as _, Metrics as _, Runner as _, Spawner as _, Supervisor as _,
};
use futures::channel::oneshot;
use commonware_storage::mmr::Location;
use commonware_utils::range::NonEmptyRange;
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

type MockRelease = oneshot::Receiver<Result<(), MockUploadError>>;
type SharedMockRelease = Arc<Mutex<Option<MockRelease>>>;

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

fn assert_metric(encoded: &str, line: &str) {
    assert!(
        encoded.lines().any(|candidate| candidate == line),
        "missing metric line `{line}` in:\n{encoded}",
    );
}

#[derive(Debug)]
enum MockUploadError {
    HttpStatus,
}

impl fmt::Display for MockUploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mock upload failed")
    }
}

impl std::error::Error for MockUploadError {}

#[derive(Clone)]
struct MockClient {
    metrics: IndexerMetrics,
    artifact: HttpArtifact,
    body_bytes: usize,
    started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    release: SharedMockRelease,
}

impl MockClient {
    fn new(
        metrics: IndexerMetrics,
        artifact: HttpArtifact,
        body_bytes: usize,
    ) -> (
        Self,
        oneshot::Receiver<()>,
        oneshot::Sender<Result<(), MockUploadError>>,
    ) {
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        (
            Self {
                metrics,
                artifact,
                body_bytes,
                started: Arc::new(Mutex::new(Some(started_tx))),
                release: Arc::new(Mutex::new(Some(release_rx))),
            },
            started_rx,
            release_tx,
        )
    }

    async fn upload(&self) -> Result<(), MockUploadError> {
        let mut request = self
            .metrics
            .start_http_request(self.artifact, self.body_bytes);
        let started = self.started.lock().expect("started lock").take();
        if let Some(started) = started {
            started.send(()).expect("notify upload started");
        }
        let release = self
            .release
            .lock()
            .expect("release lock")
            .take()
            .expect("release receiver should be present");
        match release.await.unwrap_or(Err(MockUploadError::HttpStatus)) {
            Ok(()) => {
                request.succeed();
                Ok(())
            }
            Err(error) => {
                request.http_status_error();
                Err(error)
            }
        }
    }
}

#[test]
fn live_upload_in_flight_gauge_tracks_blocked_upload() {
    deterministic::Runner::default().start(|context| async move {
        let metrics = IndexerMetrics::register(&context.child("indexer"));
        let artifact = LiveUploadArtifact::FinalizedBlock;
        let (client, started, release) =
            MockClient::new(metrics.clone(), HttpArtifact::Finalization, 0);

        metrics.live_upload_spawned(artifact);
        let handle = context.child("upload").spawn({
            let metrics = metrics.clone();
            move |context| async move {
                let mut upload = metrics.start_live_upload(context, artifact);
                client.upload().await.expect("mock upload succeeds");
                upload.succeed();
            }
        });

        started.await.expect("live upload started");
        let encoded = context.encode();
        assert_metric(
            &encoded,
            "indexer_live_upload_spawn_total{artifact=\"finalized_block\"} 1",
        );
        assert_metric(
            &encoded,
            "indexer_live_upload_in_flight{artifact=\"finalized_block\"} 1",
        );

        release.send(Ok(())).expect("release upload");
        handle.await.expect("upload task should complete");

        let encoded = context.encode();
        assert_metric(
            &encoded,
            "indexer_live_upload_in_flight{artifact=\"finalized_block\"} 0",
        );
        assert_metric(
            &encoded,
            "indexer_live_upload_complete_total{artifact=\"finalized_block\",status=\"success\"} 1",
        );
    });
}

#[test]
fn http_body_bytes_are_held_only_while_request_is_in_flight() {
    deterministic::Runner::default().start(|context| async move {
        let metrics = IndexerMetrics::register(&context.child("indexer"));
        let artifact = HttpArtifact::Finalization;
        let (client, started, release) = MockClient::new(metrics.clone(), artifact, 512);

        let handle = context.child("http_success").spawn({
            move |_| async move {
                client.upload().await.expect("mock upload succeeds");
            }
        });

        started.await.expect("http request started");
        let encoded = context.encode();
        assert_metric(
            &encoded,
            "indexer_http_request_body_in_flight_bytes{artifact=\"finalization\"} 512",
        );
        assert_metric(
            &encoded,
            "indexer_http_request_in_flight{artifact=\"finalization\"} 1",
        );

        release.send(Ok(())).expect("release http success");
        handle.await.expect("http success task should complete");

        let encoded = context.encode();
        assert_metric(
            &encoded,
            "indexer_http_request_body_in_flight_bytes{artifact=\"finalization\"} 0",
        );
        assert_metric(
            &encoded,
            "indexer_http_request_in_flight{artifact=\"finalization\"} 0",
        );
        assert_metric(
            &encoded,
            "indexer_http_request_complete_total{artifact=\"finalization\",status=\"success\"} 1",
        );

        let (client, started, release) = MockClient::new(metrics.clone(), artifact, 128);
        let handle = context.child("http_failure").spawn(move |_| async move {
            client.upload().await.expect_err("mock upload fails");
        });
        started.await.expect("http failure started");
        release
            .send(Err(MockUploadError::HttpStatus))
            .expect("release http failure");
        handle.await.expect("http failure task should complete");

        let encoded = context.encode();
        assert_metric(
            &encoded,
            "indexer_http_request_body_in_flight_bytes{artifact=\"finalization\"} 0",
        );
        assert_metric(
            &encoded,
            "indexer_http_request_complete_total{artifact=\"finalization\",status=\"http_status_error\"} 1",
        );
    });
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

        metrics.shared_state(SharedStateSnapshot {
            cached_blocks: 1,
            cached_block_estimated_bytes: 256,
            certificate_upload_digests: 2,
            certificate_upload_refs: 3,
            uploaded_digests: 4,
            latest_finalized_height: 8,
            acked_through_height: 6,
        });
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
        assert!(encoded.contains("indexer_shared_latest_finalized_height 8"));
        assert!(encoded.contains("indexer_shared_acked_through_height 6"));
        assert!(encoded.contains("indexer_queue_ack_floor_height 6"));
        assert!(encoded.contains("indexer_queue_lag_height 2"));
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

#[test]
fn backfill_metrics_use_expected_labels() {
    deterministic::Runner::default().start(|context| async move {
        let indexer = context.child("indexer");
        let metrics = IndexerMetrics::register(&indexer);
        let block = block(4, 4, b"block");

        metrics.backfill_configured(16);
        {
            let mut upload = metrics.start_backfill_upload();
            upload.hold_block(&block);
            let _body = metrics.start_backfill_body(512);
            upload.uploaded();
        }
        {
            let mut upload = metrics.start_backfill_upload();
            upload.skipped();
        }
        metrics.backfill_decision(BackfillDecision::Skip, BackfillPhase::Start);
        metrics.backfill_decision(BackfillDecision::Wait, BackfillPhase::BeforeBlock);
        metrics.backfill_decision(BackfillDecision::Proceed, BackfillPhase::BeforeAttempt);
        metrics.backfill_retry(BackfillWaitReason::CertificateUpload);
        metrics.backfill_retry(BackfillWaitReason::MissingBlock);
        metrics.backfill_retry(BackfillWaitReason::MissingFinalization);
        metrics.backfill_retry(BackfillWaitReason::MismatchedFinalization);
        metrics.backfill_retry(BackfillWaitReason::HttpError);
        metrics.backfill_waited(BackfillWaitReason::CertificateUpload, Duration::from_millis(1));
        metrics.backfill_waited(BackfillWaitReason::MissingBlock, Duration::from_millis(1));
        metrics.backfill_waited(BackfillWaitReason::MissingFinalization, Duration::from_millis(1));
        metrics.backfill_waited(BackfillWaitReason::MismatchedFinalization, Duration::from_millis(1));
        metrics.backfill_waited(BackfillWaitReason::HttpError, Duration::from_millis(1));
        metrics.backfill_queue_reset(BackfillResetReason::MissingFinalization, 32, 31);
        metrics.backfill_queue_reset(BackfillResetReason::MismatchedFinalization, 2, 1);
        metrics.queue_enqueued(QueueStatus::Success);
        metrics.queue_enqueued(QueueStatus::Failure);
        metrics.queue_acked(QueueStatus::Success);
        metrics.queue_acked(QueueStatus::Failure);
        metrics.queue_synced(QueueStatus::Success, Duration::from_millis(1));
        metrics.queue_synced(QueueStatus::Failure, Duration::from_millis(1));
        metrics.queue_read(QueueReadSource::TryRecv, QueueStatus::Success);
        metrics.queue_read(QueueReadSource::TryRecv, QueueStatus::Empty);
        metrics.queue_read(QueueReadSource::TryRecv, QueueStatus::Failure);
        metrics.queue_read(QueueReadSource::Recv, QueueStatus::Success);
        metrics.queue_read(QueueReadSource::Recv, QueueStatus::Closed);
        metrics.queue_read(QueueReadSource::Recv, QueueStatus::Failure);
        metrics.queue_ack_floor(7);
        metrics.queue_entry(9);
        metrics.producer_reported(ProducerActivity::Block, ProducerStatus::Enqueued);
        metrics.producer_reported(ProducerActivity::Block, ProducerStatus::Dropped);
        metrics.producer_reported(ProducerActivity::Tip, ProducerStatus::Ignored);
        metrics.producer_recorded(ProducerStatus::Recorded, Duration::from_millis(1));
        metrics.producer_recorded(ProducerStatus::AlreadyUploaded, Duration::from_millis(1));
        metrics.producer_mailbox_overflowed(256);
        metrics.producer_mailbox_overflow_drained(256);
        metrics.dkg_upload_completed(DkgUploadStatus::NoEpoch, Duration::from_millis(1));
        metrics.dkg_upload_completed(DkgUploadStatus::NoOutput, Duration::from_millis(1));
        metrics.dkg_upload_completed(DkgUploadStatus::Success, Duration::from_millis(1));
        metrics.dkg_upload_completed(DkgUploadStatus::Failure, Duration::from_millis(1));
        metrics.dkg_upload_output_bytes(1024);
        metrics.dkg_upload_last_attempt_epoch(8);
        metrics.dkg_upload_last_success_epoch(7);

        let encoded = context.encode();
        assert!(encoded.contains("indexer_backfill_active_uploads 0"));
        assert!(encoded.contains("indexer_backfill_max_active 16"));
        assert!(encoded.contains("indexer_backfill_start_total 2"));
        assert!(encoded.contains("indexer_backfill_complete_total{status=\"uploaded\"} 1"));
        assert!(encoded.contains("indexer_backfill_complete_total{status=\"skipped\"} 1"));
        assert!(encoded.contains("indexer_backfill_upload_duration_seconds_bucket"));
        assert!(encoded.contains(
            "indexer_backfill_decision_total{decision=\"skip\",phase=\"start\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_backfill_decision_total{decision=\"wait\",phase=\"before_block\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_backfill_decision_total{decision=\"proceed\",phase=\"before_attempt\"} 1",
        ));
        assert!(encoded.contains("indexer_backfill_wait_duration_seconds_bucket"));
        assert!(encoded.contains(
            "indexer_backfill_retry_total{reason=\"certificate_upload\"} 1",
        ));
        assert!(encoded.contains("indexer_backfill_retry_total{reason=\"missing_block\"} 1"));
        assert!(encoded
            .contains("indexer_backfill_retry_total{reason=\"missing_finalization\"} 1"));
        assert!(encoded
            .contains("indexer_backfill_retry_total{reason=\"mismatched_finalization\"} 1"));
        assert!(encoded.contains("indexer_backfill_retry_total{reason=\"http_error\"} 1"));
        assert!(encoded.contains(
            "indexer_backfill_queue_reset_total{reason=\"missing_finalization\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_backfill_queue_reset_total{reason=\"mismatched_finalization\"} 1",
        ));
        assert!(encoded.contains("indexer_backfill_queue_reset_abandoned_entries_bucket"));
        assert!(encoded.contains("indexer_backfill_queue_reset_abandoned_height_span_bucket"));
        assert!(encoded.contains("indexer_backfill_active_block_estimated_bytes 0"));
        assert!(encoded.contains("indexer_backfill_active_body_estimated_bytes 0"));
        assert!(encoded.contains("indexer_queue_enqueue_total{status=\"success\"} 1"));
        assert!(encoded.contains("indexer_queue_enqueue_total{status=\"failure\"} 1"));
        assert!(encoded.contains("indexer_queue_ack_total{status=\"success\"} 1"));
        assert!(encoded.contains("indexer_queue_ack_total{status=\"failure\"} 1"));
        assert!(encoded.contains("indexer_queue_sync_duration_seconds_bucket"));
        assert!(encoded.contains(
            "indexer_queue_read_total{source=\"try_recv\",status=\"success\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_queue_read_total{source=\"try_recv\",status=\"empty\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_queue_read_total{source=\"try_recv\",status=\"failure\"} 1",
        ));
        assert!(
            encoded.contains("indexer_queue_read_total{source=\"recv\",status=\"success\"} 1")
        );
        assert!(
            encoded.contains("indexer_queue_read_total{source=\"recv\",status=\"closed\"} 1")
        );
        assert!(
            encoded.contains("indexer_queue_read_total{source=\"recv\",status=\"failure\"} 1")
        );
        assert!(encoded.contains("indexer_queue_ack_floor_height 7"));
        assert!(encoded.contains("indexer_queue_entry_height 9"));
        assert!(encoded.contains(
            "indexer_producer_report_total{activity=\"block\",status=\"enqueued\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_producer_report_total{activity=\"block\",status=\"dropped\"} 1",
        ));
        assert!(
            encoded.contains("indexer_producer_report_total{activity=\"tip\",status=\"ignored\"} 1")
        );
        assert!(encoded.contains(
            "indexer_producer_report_total{activity=\"block\",status=\"recorded\"} 1",
        ));
        assert!(encoded.contains(
            "indexer_producer_report_total{activity=\"block\",status=\"already_uploaded\"} 1",
        ));
        assert!(encoded.contains("indexer_producer_mailbox_overflow_total 1"));
        assert!(encoded.contains("indexer_producer_mailbox_overflow_entries 0"));
        assert!(encoded.contains("indexer_producer_mailbox_overflow_block_estimated_bytes 0"));
        assert!(encoded.contains("indexer_producer_record_duration_seconds_bucket"));
        assert!(encoded.contains("indexer_dkg_upload_loop_total{status=\"no_epoch\"} 1"));
        assert!(encoded.contains("indexer_dkg_upload_loop_total{status=\"no_output\"} 1"));
        assert!(encoded.contains("indexer_dkg_upload_loop_total{status=\"success\"} 1"));
        assert!(encoded.contains("indexer_dkg_upload_loop_total{status=\"failure\"} 1"));
        assert!(encoded.contains("indexer_dkg_upload_output_bytes_bucket"));
        assert!(encoded.contains("indexer_dkg_upload_duration_seconds_bucket"));
        assert!(encoded.contains("indexer_dkg_upload_last_attempt_epoch 8"));
        assert!(encoded.contains("indexer_dkg_upload_last_success_epoch 7"));
    });
}

#[test]
fn backfill_active_gauges_track_block_and_body_guards() {
    deterministic::Runner::default().start(|context| async move {
        let metrics = IndexerMetrics::register(&context.child("indexer"));
        let first = block(10, 10, b"first");
        let second = block(11, 11, b"second");

        metrics.backfill_configured(2);
        let mut first_upload = metrics.start_backfill_upload();
        first_upload.hold_block(&first);
        let mut second_upload = metrics.start_backfill_upload();
        second_upload.hold_block(&second);
        let body = metrics.start_backfill_body(1_024);

        let encoded = context.encode();
        assert_metric(&encoded, "indexer_backfill_max_active 2");
        assert_metric(&encoded, "indexer_backfill_active_uploads 2");
        assert!(encoded.contains("indexer_backfill_active_block_estimated_bytes "));
        assert_metric(
            &encoded,
            "indexer_backfill_active_body_estimated_bytes 1024",
        );

        first_upload.uploaded();
        second_upload.skipped();
        drop(body);
        drop(first_upload);
        drop(second_upload);

        let encoded = context.encode();
        assert_metric(&encoded, "indexer_backfill_active_uploads 0");
        assert_metric(&encoded, "indexer_backfill_active_block_estimated_bytes 0");
        assert_metric(&encoded, "indexer_backfill_active_body_estimated_bytes 0");
        assert_metric(&encoded, "indexer_backfill_start_total 2");
        assert_metric(
            &encoded,
            "indexer_backfill_complete_total{status=\"uploaded\"} 1",
        );
        assert_metric(
            &encoded,
            "indexer_backfill_complete_total{status=\"skipped\"} 1",
        );
    });
}
