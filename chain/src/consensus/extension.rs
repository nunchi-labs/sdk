use std::{fmt::Debug, future::Future};

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
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
pub trait ConsensusExtension: BlockExtension + Clone + Send + Sync + 'static {
    /// Load extension state that proposals must match before [`Self::propose`].
    ///
    /// The default is a no-op. Extensions whose proposal state is rebuilt from
    /// the parent chain state should override this so a restarted process does
    /// not propose from an empty cache.
    fn prepare<S>(&mut self, _state: &mut S) -> impl Future<Output = ()> + Send
    where
        S: StateStore + Send + Sync,
    {
        std::future::ready(())
    }

    /// Read state staged for the block being proposed.
    ///
    /// Called after in-block transactions are applied and before [`Self::propose`].
    /// `prepare` has already loaded the parent state. The default is a no-op.
    /// Overrides must not publish this view on any path that outlives the attempt.
    fn preview<S>(&mut self, _state: &mut S) -> impl Future<Output = ()> + Send
    where
        S: StateStore + Send + Sync,
    {
        std::future::ready(())
    }

    /// Produce the extension payload for the next proposal.
    ///
    /// `context` is the block being proposed. Payloads that record height or
    /// time must use it so verification replays the same values.
    fn propose(
        &mut self,
        context: RuntimeContext,
    ) -> impl Future<Output = Self::Payload> + Send;

    /// Produce the extension payload after runtime transactions are applied to `state`.
    fn propose_from_state<S>(
        &mut self,
        _state: &mut S,
        context: RuntimeContext,
    ) -> impl Future<Output = Self::Payload> + Send
    where
        S: StateStore + Send + Sync,
    {
        self.propose(context)
    }

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

    /// Run extension side effects that should happen only for a certified block.
    fn commit_payload<S>(
        &mut self,
        _state: &mut S,
        _context: RuntimeContext,
        _payload: &Self::Payload,
    ) -> impl Future<Output = ()> + Send
    where
        S: StateStore + Send + Sync,
    {
        std::future::ready(())
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
    async fn prepare<S>(&mut self, state: &mut S)
    where
        S: StateStore + Send + Sync,
    {
        self.0.prepare(state).await;
        self.1.prepare(state).await;
    }

    async fn preview<S>(&mut self, state: &mut S)
    where
        S: StateStore + Send + Sync,
    {
        self.0.preview(state).await;
        self.1.preview(state).await;
    }

    async fn propose(&mut self, context: RuntimeContext) -> Self::Payload {
        let left = self.0.propose(context).await;
        let right = self.1.propose(context).await;
        (left, right)
    }

    async fn propose_from_state<S>(
        &mut self,
        state: &mut S,
        context: RuntimeContext,
    ) -> Self::Payload
    where
        S: StateStore + Send + Sync,
    {
        let left = self.0.propose_from_state(&mut *state, context).await;
        let right = self.1.propose_from_state(state, context).await;
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

    async fn commit_payload<S>(
        &mut self,
        state: &mut S,
        context: RuntimeContext,
        payload: &Self::Payload,
    ) where
        S: StateStore + Send + Sync,
    {
        self.0.commit_payload(state, context, &payload.0).await;
        self.1.commit_payload(state, context, &payload.1).await;
    }
}

/// Empty extra consensus extension for chains without additional non-DKG payloads.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoConsensusExtension;

/// Zero-byte payload used when a block has no extra consensus extension.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EmptyPayload;

impl Write for EmptyPayload {
    fn write(&self, _buf: &mut impl BufMut) {}
}

impl EncodeSize for EmptyPayload {
    fn encode_size(&self) -> usize {
        0
    }
}

impl Read for EmptyPayload {
    type Cfg = ();

    fn read_cfg(_buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self)
    }
}

impl BlockExtension for NoConsensusExtension {
    type Payload = EmptyPayload;
    type ReadCfg = ();

    fn genesis_payload() -> Self::Payload {
        EmptyPayload
    }
}

impl ConsensusExtension for NoConsensusExtension {
    fn propose(&mut self, _context: RuntimeContext) -> impl Future<Output = Self::Payload> + Send {
        std::future::ready(EmptyPayload)
    }
}
