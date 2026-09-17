//! Exact binding between an attached QMDB and a certified startup block.

use commonware_actor::Feedback;
use commonware_consensus::{
    marshal::Update,
    types::Height,
    Block, Heightable, Reporter,
};
use commonware_cryptography::{sha256::Digest, Digestible};
use commonware_storage::{
    mmr::Family,
    qmdb::sync::Target,
};
use commonware_utils::Acknowledgement as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

/// A bounded startup candidate recorded from canonical local history or a
/// certificate-verified peer-sync floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupCandidate {
    pub height: Height,
    pub digest: Digest,
    pub state_target: Target<Family, Digest>,
    pub certificate_payload: Option<Digest>,
    pub genesis: bool,
}

/// The single certified block whose complete target equals attached QMDB.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupArtifact {
    pub anchor_height: Height,
    pub anchor_digest: Digest,
    pub anchor_state_target: Target<Family, Digest>,
}

/// Bounded candidate collector used only during startup.
pub struct StartupCoordinator {
    capacity: NonZeroUsize,
    candidates: BTreeMap<(Height, Digest), StartupCandidate>,
    failure: Option<Error>,
}

impl StartupCoordinator {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            candidates: BTreeMap::new(),
            failure: None,
        }
    }

    /// Record a candidate, deduplicating the same height and digest.
    pub fn record(&mut self, candidate: StartupCandidate) -> Result<(), Error> {
        let key = (candidate.height, candidate.digest);
        if let Some(existing) = self.candidates.get(&key) {
            return (existing == &candidate)
                .then_some(())
                .ok_or(Error::ConflictingCandidate);
        }
        if self.candidates.len() == self.capacity.get() {
            return Err(Error::CapacityExceeded);
        }
        self.candidates.insert(key, candidate);
        Ok(())
    }

    /// Match the complete root and operation range and require exactly one
    /// certificate-bound candidate.
    pub fn resolve(
        &mut self,
        attached: &Target<Family, Digest>,
    ) -> Result<StartupArtifact, Error> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        let mut matches = self
            .candidates
            .values()
            .filter(|candidate| &candidate.state_target == attached);
        let candidate = matches.next().ok_or(Error::NoExactMatch)?;
        if matches.next().is_some() {
            return Err(Error::MultipleExactMatches);
        }
        if candidate.genesis {
            if candidate.height != Height::zero()
                || candidate.certificate_payload.is_some()
            {
                return Err(Error::InvalidGenesisCandidate);
            }
        } else if candidate.certificate_payload != Some(candidate.digest) {
            return Err(Error::CertificatePayloadMismatch);
        }
        let artifact = StartupArtifact {
            anchor_height: candidate.height,
            anchor_digest: candidate.digest,
            anchor_state_target: candidate.state_target.clone(),
        };
        self.candidates.clear();
        Ok(artifact)
    }

    fn fail(&mut self, error: Error) {
        self.failure.get_or_insert(error);
    }
}

/// Reporter that records selected certified startup blocks and immediately
/// acknowledges its `Exact` clone.
#[derive(Clone)]
pub struct StartupReporter<B: Block> {
    coordinator: Arc<Mutex<StartupCoordinator>>,
    certified_payloads: BTreeSet<Digest>,
    target: fn(&B) -> Target<Family, Digest>,
}

impl<B: Block<Digest = Digest>> StartupReporter<B> {
    pub fn new(
        coordinator: Arc<Mutex<StartupCoordinator>>,
        certified_payloads: impl IntoIterator<Item = Digest>,
        target: fn(&B) -> Target<Family, Digest>,
    ) -> Self {
        Self {
            coordinator,
            certified_payloads: certified_payloads.into_iter().collect(),
            target,
        }
    }
}

impl<B> Reporter for StartupReporter<B>
where
    B: Block<Digest = Digest>
        + Heightable
        + Digestible<Digest = Digest>
        + Send
        + Sync
        + 'static,
{
    type Activity = Update<B>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let Update::Block(block, acknowledgement) = update {
            let digest = block.digest();
            if self.certified_payloads.contains(&digest) {
                let result = self
                    .coordinator
                    .lock()
                    .expect("startup coordinator lock poisoned")
                    .record(StartupCandidate {
                        height: block.height(),
                        digest,
                        state_target: (self.target)(&block),
                        certificate_payload: Some(digest),
                        genesis: false,
                    });
                if let Err(error) = result {
                    self.coordinator
                        .lock()
                        .expect("startup coordinator lock poisoned")
                        .fail(error);
                }
            }
            acknowledgement.acknowledge();
        }
        Feedback::Ok
    }
}

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum Error {
    #[error("startup candidate capacity exceeded")]
    CapacityExceeded,
    #[error("same startup height and digest were recorded with conflicting data")]
    ConflictingCandidate,
    #[error("attached QMDB has no exact certified startup candidate")]
    NoExactMatch,
    #[error("attached QMDB matches multiple startup candidates")]
    MultipleExactMatches,
    #[error("startup certificate payload does not equal its block digest")]
    CertificatePayloadMismatch,
    #[error("genesis startup candidate is malformed")]
    InvalidGenesisCandidate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_storage::mmr::Location;
    use commonware_utils::{non_empty_range, NZUsize};

    fn target(root: u8, start: u64, end: u64) -> Target<Family, Digest> {
        Target::new(
            Digest([root; 32]),
            non_empty_range!(Location::new(start), Location::new(end)),
        )
    }

    fn candidate(
        height: u64,
        digest: u8,
        state_target: Target<Family, Digest>,
    ) -> StartupCandidate {
        let digest = Digest([digest; 32]);
        StartupCandidate {
            height: Height::new(height),
            digest,
            state_target,
            certificate_payload: Some(digest),
            genesis: false,
        }
    }

    #[test]
    fn exact_target_and_certificate_payload_are_required() {
        let exact = target(1, 4, 9);
        let mut coordinator = StartupCoordinator::new(NZUsize!(4));
        coordinator
            .record(candidate(7, 2, exact.clone()))
            .unwrap();
        assert_eq!(
            coordinator.resolve(&target(1, 4, 8)),
            Err(Error::NoExactMatch)
        );
        assert_eq!(
            coordinator.resolve(&target(1, 5, 9)),
            Err(Error::NoExactMatch)
        );
        let artifact = coordinator.resolve(&exact).unwrap();
        assert_eq!(artifact.anchor_height, Height::new(7));
        assert_eq!(artifact.anchor_state_target, exact);
    }

    #[test]
    fn root_only_range_only_and_conflicting_matches_are_rejected() {
        let exact = target(3, 10, 20);
        let mut coordinator = StartupCoordinator::new(NZUsize!(4));
        coordinator
            .record(candidate(1, 1, target(3, 1, 2)))
            .unwrap();
        coordinator
            .record(candidate(2, 2, target(4, 10, 20)))
            .unwrap();
        assert_eq!(coordinator.resolve(&exact), Err(Error::NoExactMatch));

        coordinator
            .record(candidate(3, 3, exact.clone()))
            .unwrap();
        coordinator
            .record(candidate(4, 4, exact.clone()))
            .unwrap();
        assert_eq!(
            coordinator.resolve(&exact),
            Err(Error::MultipleExactMatches)
        );
    }
}
