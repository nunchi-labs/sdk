use crate::{
    indexer::{
        metrics::{estimated_block_bytes, SharedCacheSource, SharedRetentionReason},
        IndexerMetrics,
    },
    Block,
};
use bytes::{Buf, BufMut};
use commonware_codec::{self, FixedSize, Read, Write};
use commonware_cryptography::{sha256::Digest, Digestible};
use commonware_utils::{sync::Mutex, PrioritySet};
use std::{collections::BTreeMap, sync::Arc};

pub enum Decision {
    Skip,
    Wait,
    Proceed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub height: u64,
    pub digest: Digest,
}

impl FixedSize for Entry {
    const SIZE: usize = u64::SIZE + Digest::SIZE;
}

impl Write for Entry {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.digest.write(buf);
    }
}

impl Read for Entry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let height = u64::read_cfg(buf, &())?;
        let digest = Digest::read_cfg(buf, &())?;
        Ok(Self { height, digest })
    }
}

pub struct State {
    uploaded: PrioritySet<Digest, u64>,
    acked_through: u64,
    latest_finalized: u64,
    cached_blocks: BTreeMap<Digest, CachedBlock>,
    cached_block_estimated_bytes: u64,
    certificate_uploads: BTreeMap<Digest, usize>,
    certificate_upload_refs: usize,
    metrics: Option<IndexerMetrics>,
}

struct CachedBlock {
    block: Block,
    estimated_bytes: u64,
}

impl State {
    pub fn new() -> Self {
        Self {
            uploaded: PrioritySet::new(),
            acked_through: 0,
            latest_finalized: 0,
            cached_blocks: BTreeMap::new(),
            cached_block_estimated_bytes: 0,
            certificate_uploads: BTreeMap::new(),
            certificate_upload_refs: 0,
            metrics: None,
        }
    }

    pub fn with_metrics(metrics: IndexerMetrics) -> Self {
        let mut state = Self::new();
        state.metrics = Some(metrics);
        state.sync_metrics();
        state
    }

    fn is_uploaded(&self, digest: &Digest) -> bool {
        self.uploaded.contains(digest)
    }

    pub fn record(&mut self, block: &Block) -> Option<Entry> {
        let entry = Entry {
            height: block.height.get(),
            digest: block.digest(),
        };
        self.observe_finalization(entry.height);
        if self.is_uploaded(&entry.digest) {
            self.sync_metrics();
            return None;
        }
        self.cache_block_inner(block.clone(), SharedCacheSource::ProducerRecord);
        self.sync_metrics();
        Some(entry)
    }

    pub fn advance_queue_floor(&mut self, height: u64) {
        self.acked_through = self.acked_through.max(height);
        self.prune();
        self.sync_metrics();
    }

    pub fn mark_uploaded(&mut self, digest: Digest, height: u64) {
        self.remove_cached_block(&digest, SharedRetentionReason::Uploaded);
        if !self.uploaded.contains(&digest) {
            self.shared_pruned(SharedRetentionReason::Uploaded, 1);
        }
        self.uploaded.put(digest, height);
        self.prune();
        self.sync_metrics();
    }

    pub fn cache_block(&mut self, block: Block, source: SharedCacheSource) {
        self.cache_block_inner(block, source);
        self.sync_metrics();
    }

    pub fn cached_block(&self, digest: &Digest) -> Option<Block> {
        self.cached_blocks
            .get(digest)
            .map(|cached| cached.block.clone())
    }

    pub fn should_upload(&self, digest: &Digest) -> Decision {
        if self.is_uploaded(digest) {
            Decision::Skip
        } else if self.certificate_uploads.contains_key(digest) {
            Decision::Wait
        } else {
            Decision::Proceed
        }
    }

    pub fn start_certificate_upload(&mut self, digest: Digest) {
        *self.certificate_uploads.entry(digest).or_default() += 1;
        self.certificate_upload_refs += 1;
        self.sync_metrics();
    }

    pub fn finish_certificate_upload(&mut self, digest: &Digest, uploaded_height: Option<u64>) {
        let count = self
            .certificate_uploads
            .get_mut(digest)
            .expect("missing in-flight certificate upload");
        *count -= 1;
        self.certificate_upload_refs -= 1;
        if *count == 0 {
            self.certificate_uploads.remove(digest);
        }
        if let Some(height) = uploaded_height {
            self.remove_cached_block(digest, SharedRetentionReason::CertificateFinished);
            if !self.uploaded.contains(digest) {
                self.shared_pruned(SharedRetentionReason::CertificateFinished, 1);
            }
            self.uploaded.put(*digest, height);
        }
        self.prune();
        self.sync_metrics();
    }

    fn observe_finalization(&mut self, height: u64) {
        self.latest_finalized = self.latest_finalized.max(height);
        self.prune();
    }

    fn cache_block_inner(&mut self, block: Block, source: SharedCacheSource) {
        let digest = block.digest();
        if self.cached_blocks.contains_key(&digest) {
            return;
        }

        let estimated_bytes = estimated_block_bytes(&block);
        self.cached_blocks.insert(
            digest,
            CachedBlock {
                block,
                estimated_bytes,
            },
        );
        self.cached_block_estimated_bytes = self
            .cached_block_estimated_bytes
            .saturating_add(estimated_bytes);
        if let Some(metrics) = &self.metrics {
            metrics.shared_cache_inserted(source);
        }
    }

    fn remove_cached_block(&mut self, digest: &Digest, reason: SharedRetentionReason) -> bool {
        let Some(cached) = self.cached_blocks.remove(digest) else {
            return false;
        };
        self.cached_block_estimated_bytes = self
            .cached_block_estimated_bytes
            .saturating_sub(cached.estimated_bytes);
        if let Some(metrics) = &self.metrics {
            metrics.shared_cache_removed(reason);
        }
        true
    }

    fn prune(&mut self) {
        let mut pruned = 0;
        while let Some((_, &height)) = self.uploaded.peek() {
            if height >= self.acked_through {
                break;
            }
            self.uploaded.pop();
            pruned += 1;
        }
        self.shared_pruned(SharedRetentionReason::Pruned, pruned);

        let mut cached_prune_before = self.latest_finalized;
        for digest in self.certificate_uploads.keys() {
            let Some(cached) = self.cached_blocks.get(digest) else {
                continue;
            };
            cached_prune_before = cached_prune_before.min(cached.block.height.get());
        }

        let pruned = self
            .cached_blocks
            .iter()
            .filter_map(|(digest, cached)| {
                (cached.block.height.get() < cached_prune_before).then_some(*digest)
            })
            .collect::<Vec<_>>();
        for digest in &pruned {
            self.remove_cached_block(digest, SharedRetentionReason::Pruned);
        }
        self.shared_pruned(SharedRetentionReason::Pruned, pruned.len() as u64);
    }

    fn shared_pruned(&self, reason: SharedRetentionReason, count: u64) {
        if count == 0 {
            return;
        }
        if let Some(metrics) = &self.metrics {
            metrics.shared_pruned(reason, count);
        }
    }

    fn sync_metrics(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.shared_state(
                self.cached_blocks.len(),
                self.cached_block_estimated_bytes,
                self.certificate_uploads.len(),
                self.certificate_upload_refs,
                self.uploaded.len(),
                self.latest_finalized,
                self.acked_through,
            );
        }
    }
}

pub type SharedState = Arc<Mutex<State>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StateCommitment, Transaction, EPOCH};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_consensus::types::{Height, Round, View};
    use commonware_cryptography::{ed25519, Hasher, Sha256, Signer};
    use commonware_runtime::{deterministic, Metrics as _, Runner as _, Supervisor as _};
    use commonware_storage::mmr::Location;
    use commonware_utils::range::NonEmptyRange;

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
    fn entry_codec_roundtrips() {
        let entry = Entry {
            height: 7,
            digest: Sha256::hash(b"block"),
        };

        let encoded = entry.encode();
        let decoded = Entry::decode(encoded).expect("decode entry");

        assert_eq!(decoded.height, entry.height);
        assert_eq!(decoded.digest, entry.digest);
    }

    #[test]
    fn record_caches_block_until_uploaded() {
        let mut state = State::new();
        let block = block(1, 1, b"one");
        let digest = block.digest();

        let entry = state.record(&block).expect("entry should be queued");

        assert_eq!(entry.height, 1);
        assert_eq!(entry.digest, digest);
        assert_eq!(state.cached_block(&digest).as_ref(), Some(&block));

        state.mark_uploaded(digest, 1);

        assert!(state.record(&block).is_none());
        assert!(state.cached_block(&digest).is_none());
        assert!(matches!(state.should_upload(&digest), Decision::Skip));
    }

    #[test]
    fn duplicate_pending_finalizations_are_allowed_until_upload_succeeds() {
        let mut state = State::new();
        let block = block(5, 5, b"five");
        let digest = block.digest();

        assert!(state.record(&block).is_some());
        assert!(state.record(&block).is_some());

        state.mark_uploaded(digest, 5);

        assert!(state.record(&block).is_none());
    }

    #[test]
    fn certificate_upload_blocks_backfill_then_marks_uploaded() {
        let mut state = State::new();
        let block = block(9, 9, b"nine");
        let digest = block.digest();

        state.cache_block(block.clone(), SharedCacheSource::LiveCertificate);
        state.start_certificate_upload(digest);

        assert!(matches!(state.should_upload(&digest), Decision::Wait));
        assert_eq!(state.cached_block(&digest).as_ref(), Some(&block));

        state.finish_certificate_upload(&digest, Some(block.height.get()));

        assert!(matches!(state.should_upload(&digest), Decision::Skip));
        assert!(state.cached_block(&digest).is_none());
    }

    #[test]
    fn notarization_upload_does_not_satisfy_finalization_backfill() {
        let mut state = State::new();
        let block = block(9, 9, b"nine");
        let digest = block.digest();

        state.cache_block(block.clone(), SharedCacheSource::LiveCertificate);
        state.start_certificate_upload(digest);
        state.finish_certificate_upload(&digest, None);

        assert!(matches!(state.should_upload(&digest), Decision::Proceed));
        assert_eq!(state.cached_block(&digest).as_ref(), Some(&block));
    }

    #[test]
    fn failed_certificate_upload_eventually_prunes_old_cache() {
        let mut state = State::new();
        let old = block(2, 2, b"old");
        let old_digest = old.digest();
        let newer = block(3, 3, b"newer");

        state.start_certificate_upload(old_digest);
        state.cache_block(old, SharedCacheSource::LiveCertificate);
        state.finish_certificate_upload(&old_digest, None);

        assert!(state.cached_block(&old_digest).is_some());

        state.record(&newer);

        assert!(state.cached_block(&old_digest).is_none());
    }

    #[test]
    fn uploaded_dedupe_prunes_behind_queue_floor() {
        let mut state = State::new();
        let digest_10 = Sha256::hash(b"10");
        let digest_11 = Sha256::hash(b"11");

        state.mark_uploaded(digest_10, 10);
        state.mark_uploaded(digest_11, 11);
        state.advance_queue_floor(11);

        assert!(!state.is_uploaded(&digest_10));
        assert!(state.is_uploaded(&digest_11));
    }

    #[test]
    fn metrics_track_cache_bytes_refs_and_pruning() {
        deterministic::Runner::default().start(|context| async move {
            let metrics = IndexerMetrics::register(&context.child("indexer"));
            let mut state = State::with_metrics(metrics);
            let block = block(7, 7, b"seven");
            let digest = block.digest();

            assert!(state.record(&block).is_some());
            assert!(state.record(&block).is_some());
            state.start_certificate_upload(digest);
            state.start_certificate_upload(digest);
            state.finish_certificate_upload(&digest, None);
            state.finish_certificate_upload(&digest, Some(block.height.get()));
            state.advance_queue_floor(block.height.get() + 1);

            let encoded = context.encode();
            assert!(encoded.contains("indexer_shared_cached_blocks 0"));
            assert!(encoded.contains("indexer_shared_cached_block_estimated_bytes 0"));
            assert!(encoded.contains("indexer_shared_certificate_upload_digests 0"));
            assert!(encoded.contains("indexer_shared_certificate_upload_refs 0"));
            assert!(encoded.contains("indexer_shared_uploaded_digests 0"));
            assert!(encoded.contains("indexer_shared_latest_finalized_height 7"));
            assert!(encoded.contains("indexer_shared_acked_through_height 8"));
            assert!(encoded.contains(
                "indexer_shared_cache_insert_total{source=\"producer_record\"} 1",
            ));
            assert!(encoded.contains(
                "indexer_shared_cache_remove_total{reason=\"certificate_finished\"} 1",
            ));
            assert!(encoded
                .contains("indexer_shared_prune_total{reason=\"certificate_finished\"} 1"));
            assert!(encoded.contains("indexer_shared_prune_total{reason=\"pruned\"} 1"));
        });
    }
}
