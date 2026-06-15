use std::{future::Future, num::NonZeroU32};

use commonware_codec::{EncodeSize, Read, Write};
use nunchi_common::{BlockExtension, ConsensusExtension};
use nunchi_dkg::{self as dkg, DealerLog, ReshareBlock};

use crate::Block;

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
