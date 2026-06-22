use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::{marshal::Update, Reporters};
use nunchi_dkg as dkg;

use crate::{Block, BlockExtension, NoConsensusExtension};

/// DKG actor specialized to SDK blocks.
pub type DkgActor<E, P, Tx, Ext = NoConsensusExtension> = dkg::Actor<E, P, Block<Tx, Ext>>;

/// DKG mailbox specialized to SDK blocks.
pub type DkgMailbox<Tx, Ext = NoConsensusExtension> = dkg::Mailbox<Block<Tx, Ext>>;

/// Marshal reporters for a stateful application plus the DKG actor mailbox.
pub type DkgReporters<Tx, R, Ext = NoConsensusExtension> =
    Reporters<Update<Block<Tx, Ext>>, R, DkgMailbox<Tx, Ext>>;

/// Build the marshal reporter fan-out required by DKG resharing chains.
///
/// The stateful application and DKG actor both need finalized-block notifications. Keeping this
/// helper here prevents each DKG-backed chain from spelling the `Reporters<Update<Block<_>>, ...>`
/// type itself.
pub fn dkg_reporters<Tx, R, Ext>(stateful: R, dkg: DkgMailbox<Tx, Ext>) -> DkgReporters<Tx, R, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension,
{
    Reporters::from((stateful, dkg))
}
