//! Payload bounds for the authenticated discovery network.

use crate::{consensus::BlockExtension, BlockCommitment, CodingBlock, EngineVariant};
use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::marshal;
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    ed25519,
    sha256::Digest,
};
use commonware_glue::{
    dkg::{self, orchestrator},
    stateful::{db::p2p as state_sync, probe},
};
use commonware_p2p::max_message_size;
use commonware_storage::mmr;
use nunchi_dkg::Scheme;
use std::num::{NonZeroU32, NonZeroU64};

/// `max_message_size` that admits every payload a DKG-backed engine sends.
///
/// Commonware 2026.10 sizes each authenticated channel from this value.
/// [`commonware_p2p::Sender::send`] panics when a payload is larger, and a peer
/// that sends one is disconnected. The bound is the maximum of:
///
/// - simplex votes and certificates, prefixed for the orchestrator's epoch muxer
/// - marshal backfill and erasure-coded shard broadcasts
/// - the stateful floor probe
/// - DKG dealings and acknowledgements, prefixed for the epoch muxer
/// - a QMDB state-sync response of `max_serve_ops` operations
/// - one mempool or module gossip transaction
pub fn discovery_max_message_size<Tx, Ext>(
    participants: NonZeroU32,
    block_codec_config: &<CodingBlock<Tx, Ext> as Read>::Cfg,
    max_serve_ops: NonZeroU64,
    max_operation_bytes: usize,
    max_tx_bytes: usize,
) -> u32
where
    Tx: Clone + EncodeSize + Read<Cfg = ()> + Send + Sync + Write + 'static,
    Ext: BlockExtension + Clone + Send + Sync,
{
    let committee = participants.get();
    max_message_size(&[
        orchestrator::max_payload_size::<Scheme, BlockCommitment<Tx, Ext>>(committee),
        marshal::max_payload_size::<EngineVariant<Tx, Ext>, Scheme>(committee, block_codec_config),
        probe::max_payload_size::<EngineVariant<Tx, Ext>, Scheme>(committee),
        dkg::max_payload_size::<MinSig, ed25519::PublicKey>(participants),
        state_sync::max_payload_size::<mmr::Family, Digest>(max_serve_ops, max_operation_bytes),
        max_tx_bytes,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consensus::BlockExtension, EmptyPayload};
    use bytes::BufMut;
    use commonware_codec::{EncodeSize, Error, Read, Write};
    use commonware_utils::{NZU32, NZU64};

    #[derive(Clone)]
    struct EmptyTx;

    impl Write for EmptyTx {
        fn write(&self, _buf: &mut impl BufMut) {}
    }

    impl Read for EmptyTx {
        type Cfg = ();

        fn read_cfg(_buf: &mut impl commonware_codec::Buf, _: &()) -> Result<Self, Error> {
            Ok(Self)
        }
    }

    impl EncodeSize for EmptyTx {
        fn encode_size(&self) -> usize {
            0
        }
    }

    #[derive(Clone)]
    struct TestExtension;

    impl BlockExtension for TestExtension {
        type Payload = EmptyPayload;
        type ReadCfg = ();

        fn genesis_payload() -> Self::Payload {
            EmptyPayload
        }
    }

    #[test]
    fn discovery_limit_admits_every_engine_payload() {
        let participants = NZU32!(4);
        let block_codec_config = (participants, ());
        let max_serve_ops = NZU64!(1_024);
        let operation_bytes = nunchi_common::max_qmdb_operation_bytes();
        let tx_bytes = 64 * 1024;
        let limit = discovery_max_message_size::<EmptyTx, TestExtension>(
            participants,
            &block_codec_config,
            max_serve_ops,
            operation_bytes,
            tx_bytes,
        );
        let limit = usize::try_from(limit).unwrap();
        let committee = participants.get();
        let marshal = marshal::max_payload_size::<EngineVariant<EmptyTx, TestExtension>, Scheme>(
            committee,
            &block_codec_config,
        );
        let simplex =
            orchestrator::max_payload_size::<Scheme, BlockCommitment<EmptyTx, TestExtension>>(
                committee,
            );
        let floor = probe::max_payload_size::<EngineVariant<EmptyTx, TestExtension>, Scheme>(
            committee,
        );
        let dealing = dkg::max_payload_size::<MinSig, ed25519::PublicKey>(participants);
        let sync =
            state_sync::max_payload_size::<mmr::Family, Digest>(max_serve_ops, operation_bytes);
        assert!(limit >= marshal);
        assert!(limit >= simplex);
        assert!(limit >= floor);
        assert!(limit >= dealing);
        assert!(limit >= sync);
        assert!(limit >= tx_bytes);
        // The previous hardcoded discovery cap cannot carry marshal backfill for the
        // block bound, nor a full state-sync batch.
        assert!(marshal > 1024 * 1024 || sync > 1024 * 1024);
        assert!(limit > 1024 * 1024);
    }
}
