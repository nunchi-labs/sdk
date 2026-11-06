use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::{marshal::Update, Reporters};
use nunchi_dkg as dkg;

use crate::{BlockExtension, CodingBlock, NoConsensusExtension};

/// DKG actor specialized to SDK coding blocks.
pub type DkgActor<E, P, Tx, Ext = NoConsensusExtension> = dkg::Actor<E, P, CodingBlock<Tx, Ext>>;

/// DKG mailbox specialized to SDK coding blocks.
pub type DkgMailbox<Tx, Ext = NoConsensusExtension> = dkg::Mailbox<CodingBlock<Tx, Ext>>;

/// Marshal reporters for a stateful application plus the DKG actor mailbox.
pub type DkgReporters<Tx, R, Ext = NoConsensusExtension> =
    Reporters<Update<CodingBlock<Tx, Ext>>, R, DkgMailbox<Tx, Ext>>;

/// Build the marshal reporter fan-out required by DKG resharing chains.
///
/// The stateful application and DKG actor both need finalized-block notifications. Keeping this
/// helper here prevents each DKG-backed chain from spelling the `Reporters<Update<CodingBlock<_>>, ...>`
/// type itself.
pub fn dkg_reporters<Tx, R, Ext>(stateful: R, dkg: DkgMailbox<Tx, Ext>) -> DkgReporters<Tx, R, Ext>
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    Reporters::from((stateful, dkg))
}
