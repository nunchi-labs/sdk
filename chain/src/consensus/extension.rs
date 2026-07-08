use std::{fmt::Debug, future::Future};

use commonware_codec::{EncodeSize, Read, Write};
use nunchi_common::{RuntimeContext, StateStore};

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

    /// Verify an extension payload included in a proposed block.
    fn verify_payload(&mut self, _payload: &Self::Payload) -> impl Future<Output = bool> + Send {
        std::future::ready(true)
    }

    /// Apply the extension payload to the same authenticated state as runtime transactions.
    fn apply_payload<S>(
        &mut self,
        _state: &mut S,
        _context: RuntimeContext,
        _payload: &Self::Payload,
    ) -> impl Future<Output = bool> + Send
    where
        S: StateStore + Send + Sync,
    {
        std::future::ready(true)
    }
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

    async fn verify_payload(&mut self, payload: &Self::Payload) -> bool {
        self.0.verify_payload(&payload.0).await && self.1.verify_payload(&payload.1).await
    }

    async fn apply_payload<S>(
        &mut self,
        state: &mut S,
        context: RuntimeContext,
        payload: &Self::Payload,
    ) -> bool
    where
        S: StateStore + Send + Sync,
    {
        self.0.apply_payload(state, context, &payload.0).await
            && self.1.apply_payload(state, context, &payload.1).await
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
