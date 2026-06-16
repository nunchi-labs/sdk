use std::{future::Future, num::NonZeroU32};

use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::{marshal::Update, Reporters};
use nunchi_dkg::{self as dkg, DealerLog, ReshareBlock};

use crate::{Block, Finalized, Notarized};

use super::{BlockExtension, ConsensusExtension};

/// Block type for chains that carry DKG resharing payloads.
pub type DkgBlock<Tx> = Block<Tx, DkgExtension<Tx>>;

/// Notarized block type for chains that carry DKG resharing payloads.
pub type DkgNotarized<Tx> = Notarized<Tx, DkgExtension<Tx>>;

/// Finalized block type for chains that carry DKG resharing payloads.
pub type DkgFinalized<Tx> = Finalized<Tx, DkgExtension<Tx>>;

/// DKG actor specialized to blocks with DKG resharing payloads.
pub type DkgActor<E, P, Tx> = dkg::Actor<E, P, DkgBlock<Tx>>;

/// DKG mailbox specialized to blocks with DKG resharing payloads.
pub type DkgMailbox<Tx> = dkg::Mailbox<DkgBlock<Tx>>;

/// Marshal reporters for a stateful application plus the DKG actor mailbox.
pub type DkgReporters<Tx, R> = Reporters<Update<DkgBlock<Tx>>, R, DkgMailbox<Tx>>;

/// Build the marshal reporter fan-out required by DKG resharing chains.
///
/// The stateful application and DKG actor both need finalized-block notifications. Keeping this
/// helper here prevents each DKG-backed chain from spelling the `Reporters<Update<DkgBlock<_>>, ...>`
/// type itself.
pub fn dkg_reporters<Tx, R>(stateful: R, dkg: DkgMailbox<Tx>) -> DkgReporters<Tx, R>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    Reporters::from((stateful, dkg))
}

/// DKG resharing extension payload and proposer hook.
pub struct DkgExtension<Tx>
where
    DkgBlock<Tx>: ReshareBlock,
{
    mailbox: DkgMailbox<Tx>,
}

impl<Tx> DkgExtension<Tx>
where
    DkgBlock<Tx>: ReshareBlock,
{
    pub const fn new(mailbox: DkgMailbox<Tx>) -> Self {
        Self { mailbox }
    }

    pub fn mailbox(&self) -> DkgMailbox<Tx> {
        self.mailbox.clone()
    }
}

impl<Tx> Clone for DkgExtension<Tx>
where
    DkgBlock<Tx>: ReshareBlock,
{
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
        }
    }
}

impl<Tx> BlockExtension for DkgExtension<Tx>
where
    DkgBlock<Tx>: ReshareBlock,
{
    type Payload = Option<DealerLog>;
    type ReadCfg = NonZeroU32;

    fn genesis_payload() -> Self::Payload {
        None
    }
}

impl<Tx> ConsensusExtension for DkgExtension<Tx>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    fn propose(&mut self) -> impl Future<Output = Self::Payload> + Send {
        self.mailbox.act()
    }
}

impl<Tx> ReshareBlock for DkgBlock<Tx>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
{
    fn reshare_log(&self) -> Option<&DealerLog> {
        self.extension.as_ref()
    }
}
