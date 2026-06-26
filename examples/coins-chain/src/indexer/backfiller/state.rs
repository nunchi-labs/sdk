use crate::Block;
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
    cached_blocks: BTreeMap<Digest, Block>,
    certificate_uploads: BTreeMap<Digest, usize>,
}

impl State {
    pub fn new() -> Self {
        Self {
            uploaded: PrioritySet::new(),
            acked_through: 0,
            latest_finalized: 0,
            cached_blocks: BTreeMap::new(),
            certificate_uploads: BTreeMap::new(),
        }
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
            return None;
        }
        self.cache_block(block.clone());
        Some(entry)
    }

    pub fn advance_queue_floor(&mut self, height: u64) {
        self.acked_through = self.acked_through.max(height);
        self.prune();
    }

    pub fn mark_uploaded(&mut self, digest: Digest, height: u64) {
        self.cached_blocks.remove(&digest);
        self.uploaded.put(digest, height);
        self.prune();
    }

    pub fn cache_block(&mut self, block: Block) {
        self.cached_blocks.entry(block.digest()).or_insert(block);
    }

    pub fn cached_block(&self, digest: &Digest) -> Option<Block> {
        self.cached_blocks.get(digest).cloned()
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
    }

    pub fn finish_certificate_upload(&mut self, digest: &Digest, uploaded_height: Option<u64>) {
        let count = self
            .certificate_uploads
            .get_mut(digest)
            .expect("missing in-flight certificate upload");
        *count -= 1;
        if *count == 0 {
            self.certificate_uploads.remove(digest);
        }
        if let Some(height) = uploaded_height {
            self.cached_blocks.remove(digest);
            self.uploaded.put(*digest, height);
        }
        self.prune();
    }

    fn observe_finalization(&mut self, height: u64) {
        self.latest_finalized = self.latest_finalized.max(height);
        self.prune();
    }

    fn prune(&mut self) {
        while let Some((_, &height)) = self.uploaded.peek() {
            if height >= self.acked_through {
                break;
            }
            self.uploaded.pop();
        }

        let mut cached_prune_before = self.latest_finalized;
        for digest in self.certificate_uploads.keys() {
            let Some(block) = self.cached_blocks.get(digest) else {
                continue;
            };
            cached_prune_before = cached_prune_before.min(block.height.get());
        }
        self.cached_blocks
            .retain(|_, block| block.height.get() >= cached_prune_before);
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

        state.cache_block(block.clone());
        state.start_certificate_upload(digest);

        assert!(matches!(state.should_upload(&digest), Decision::Wait));
        assert_eq!(state.cached_block(&digest).as_ref(), Some(&block));

        state.finish_certificate_upload(&digest, Some(block.height.get()));

        assert!(matches!(state.should_upload(&digest), Decision::Skip));
        assert!(state.cached_block(&digest).is_none());
    }

    #[test]
    fn failed_certificate_upload_eventually_prunes_old_cache() {
        let mut state = State::new();
        let old = block(2, 2, b"old");
        let old_digest = old.digest();
        let newer = block(3, 3, b"newer");

        state.start_certificate_upload(old_digest);
        state.cache_block(old);
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
}
