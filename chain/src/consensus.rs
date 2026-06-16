use std::{fmt::Debug, future::Future, num::NonZeroU32};

use commonware_codec::{EncodeSize, Read, Write};
use nunchi_dkg::{self as dkg, DealerLog, ReshareBlock};

use crate::Block;

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

/// Optional consensus-side extension driven outside ordinary runtime transactions.
pub trait ConsensusExtension<Block>: BlockExtension + Clone + Send + 'static {
    /// Produce a payload for the next proposal.
    fn propose(&mut self) -> impl Future<Output = Self::Payload> + Send;

    /// Verify the extension payload on a candidate block.
    fn verify(&mut self, block: &Block) -> impl Future<Output = bool> + Send;

    /// Observe a finalized block after it is applied.
    fn finalized(&mut self, block: &Block) -> impl Future<Output = ()> + Send;
}

/// Empty consensus extension for chains without DKG/authority payloads.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoConsensusExtension;

impl BlockExtension for NoConsensusExtension {
    type Payload = ();
    type ReadCfg = ();

    fn genesis_payload() -> Self::Payload {}
}

impl<Block> ConsensusExtension<Block> for NoConsensusExtension
where
    Block: Sync,
{
    fn propose(&mut self) -> impl Future<Output = Self::Payload> + Send {
        std::future::ready(())
    }

    fn verify(&mut self, _block: &Block) -> impl Future<Output = bool> + Send {
        std::future::ready(true)
    }

    fn finalized(&mut self, _block: &Block) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }
}

/// DKG resharing extension payload and proposer hook.
pub struct DkgExtension<Tx>
where
    Block<Tx, DkgExtension<Tx>>: ReshareBlock,
{
    mailbox: dkg::Mailbox<Block<Tx, DkgExtension<Tx>>>,
}

impl<Tx> DkgExtension<Tx>
where
    Block<Tx, DkgExtension<Tx>>: ReshareBlock,
{
    pub const fn new(mailbox: dkg::Mailbox<Block<Tx, DkgExtension<Tx>>>) -> Self {
        Self { mailbox }
    }

    pub fn mailbox(&self) -> dkg::Mailbox<Block<Tx, DkgExtension<Tx>>> {
        self.mailbox.clone()
    }
}

impl<Tx> Clone for DkgExtension<Tx>
where
    Block<Tx, DkgExtension<Tx>>: ReshareBlock,
{
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
        }
    }
}

impl<Tx> BlockExtension for DkgExtension<Tx>
where
    Block<Tx, DkgExtension<Tx>>: ReshareBlock,
{
    type Payload = Option<DealerLog>;
    type ReadCfg = NonZeroU32;

    fn genesis_payload() -> Self::Payload {
        None
    }
}

impl<Tx> ConsensusExtension<Block<Tx, DkgExtension<Tx>>> for DkgExtension<Tx>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    fn propose(&mut self) -> impl Future<Output = Self::Payload> + Send {
        self.mailbox.act()
    }

    fn verify(
        &mut self,
        _block: &Block<Tx, DkgExtension<Tx>>,
    ) -> impl Future<Output = bool> + Send {
        std::future::ready(true)
    }

    fn finalized(
        &mut self,
        _block: &Block<Tx, DkgExtension<Tx>>,
    ) -> impl Future<Output = ()> + Send {
        // DKG finalization is still driven by the marshal reporter so that acknowledgement
        // behavior remains unchanged while the engine extraction is unfinished.
        std::future::ready(())
    }
}

impl<Tx> ReshareBlock for Block<Tx, DkgExtension<Tx>>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    fn reshare_log(&self) -> Option<&DealerLog> {
        self.extension.as_ref()
    }
}
