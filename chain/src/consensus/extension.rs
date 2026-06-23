use std::{fmt::Debug, future::Future};

use commonware_codec::{EncodeSize, Read, Write};

/// Consensus-side payload carried by blocks but driven outside ordinary runtime transactions.
pub trait BlockExtension: 'static {
    /// Extension payload embedded in a proposed block.
    type Payload: Clone
        + Debug
        + EncodeSize
        + Read<Cfg = Self::ReadCfg>
        + Write
        + Send
        + Sync
        + 'static;

    /// Codec config used to decode the extension payload.
    type ReadCfg: Clone + Send + Sync + 'static;

    /// Payload to use for genesis blocks.
    fn genesis_payload() -> Self::Payload;
}

/// Proposal-side driver for a block extension.
///
/// Finalization/reporting is intentionally not part of this trait. Extensions that need finalized
/// block notifications should wire that through the consensus/marshal reporter path that owns
/// acknowledgements for those notifications.
pub trait ConsensusExtension: BlockExtension + Clone + Send + 'static {
    /// Produce the extension payload for the next proposal.
    fn propose(&mut self) -> impl Future<Output = Self::Payload> + Send;
}

/// Pair of extra consensus extensions carried in one block extension slot.
#[derive(Clone, Copy, Debug, Default)]
pub struct Composite<A, B>(pub A, pub B);

impl<A, B> Composite<A, B> {
    pub const fn new(left: A, right: B) -> Self {
        Self(left, right)
    }
}

impl<A, B> BlockExtension for Composite<A, B>
where
    A: BlockExtension,
    B: BlockExtension,
{
    type Payload = (A::Payload, B::Payload);
    type ReadCfg = (A::ReadCfg, B::ReadCfg);

    fn genesis_payload() -> Self::Payload {
        (A::genesis_payload(), B::genesis_payload())
    }
}

impl<A, B> ConsensusExtension for Composite<A, B>
where
    A: ConsensusExtension,
    B: ConsensusExtension,
{
    async fn propose(&mut self) -> Self::Payload {
        let left = self.0.propose().await;
        let right = self.1.propose().await;
        (left, right)
    }
}

/// Empty extra consensus extension for chains without additional non-DKG payloads.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoConsensusExtension;

impl BlockExtension for NoConsensusExtension {
    type Payload = ();
    type ReadCfg = ();

    fn genesis_payload() -> Self::Payload {}
}

impl ConsensusExtension for NoConsensusExtension {
    fn propose(&mut self) -> impl Future<Output = Self::Payload> + Send {
        std::future::ready(())
    }
}
