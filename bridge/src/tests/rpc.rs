use commonware_consensus::{
    marshal::{
        coding::types::{coding_config_for_participants, CodedBlock},
        core::Actor as MarshalActor,
        Config as MarshalConfig, Identifier, Start,
    },
    simplex::scheme::bls12381_threshold::vrf,
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::ConstantProvider, ed25519, sha256,
    Digest as _, Signer,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Runner as _, Supervisor as _,
};
use commonware_storage::{archive::immutable, mmr::Location};
use commonware_utils::{non_empty_range, test_rng, NZU32, NZU64, NZUsize};
use nunchi_chain::{
    dummy_genesis_parent, engine, CodingBlock, CodingContext, EmptyPayload, EngineVariant,
    StateCommitment,
};
use nunchi_dkg::Scheme;

use crate::rpc::LocalFinalizations;

const NAMESPACE: &[u8] = b"_NUNCHI_BRIDGE_MARSHAL_RPC_TEST";

fn state() -> StateCommitment {
    StateCommitment {
        root: sha256::Digest::EMPTY,
        range: non_empty_range!(Location::new(0), Location::new(1)),
    }
}

fn genesis_block() -> CodingBlock<u8> {
    CodingBlock::new(
        CodingContext {
            round: Round::new(Epoch::zero(), View::zero()),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::zero(), dummy_genesis_parent()),
        },
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        Vec::new(),
        None,
        EmptyPayload,
        state(),
    )
}

fn archive_config<C>(
    name: &str,
    page_cache: CacheRef,
    codec_config: C,
    replay_buffer: std::num::NonZeroUsize,
    write_buffer: std::num::NonZeroUsize,
) -> immutable::Config<C> {
    let prefix = format!("bridge-rpc-marshal-{name}");
    immutable::Config {
        metadata_partition: format!("{prefix}-metadata"),
        freezer_table_partition: format!("{prefix}-freezer-table"),
        freezer_table_initial_size: 64,
        freezer_table_resize_frequency: 10,
        freezer_table_resize_chunk_size: 10,
        freezer_key_partition: format!("{prefix}-freezer-key"),
        freezer_key_page_cache: page_cache,
        freezer_value_partition: format!("{prefix}-freezer-value"),
        freezer_value_target_size: 1_024,
        freezer_value_compression: None,
        ordinal_partition: format!("{prefix}-ordinal"),
        items_per_section: NZU64!(10),
        codec_config,
        replay_buffer,
        freezer_key_write_buffer: write_buffer,
        freezer_value_write_buffer: write_buffer,
        ordinal_write_buffer: write_buffer,
    }
}

#[test]
fn marshal_mailbox_local_finalizations_are_empty_before_start() {
    deterministic::Runner::default().start(|context| async move {
        let mut rng = test_rng();
        let scheme = vrf::fixture::<MinSig, _>(&mut rng, NAMESPACE, 4).schemes[0].clone();
        let provider = ConstantProvider::<Scheme, Epoch>::new(scheme);
        let page_cache =
            CacheRef::from_pooler(&context, engine::PAGE_CACHE_PAGE_SIZE, NZUsize!(1_024));
        let coded_genesis = CodedBlock::new(
            genesis_block(),
            coding_config_for_participants(4),
            &Sequential,
        );
        let block_codec_config = (NZU32!(4), ());
        let replay_buffer = NZUsize!(1_024);
        let write_buffer = NZUsize!(1_024);

        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(
                "finalizations",
                page_cache.clone(),
                (),
                replay_buffer,
                write_buffer,
            ),
        )
        .await
        .expect("finalizations archive");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(
                "blocks",
                page_cache.clone(),
                block_codec_config,
                replay_buffer,
                write_buffer,
            ),
        )
        .await
        .expect("finalized blocks archive");

        let (actor, mailbox, _) = MarshalActor::<_, EngineVariant<u8>, _, _, _, _, _>::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            MarshalConfig {
                provider,
                epocher: FixedEpocher::new(NZU64!(200)),
                start: Start::Genesis(coded_genesis),
                partition_prefix: "bridge-rpc-marshal".to_string(),
                mailbox_size: NZUsize!(16),
                view_retention: ViewDelta::new(10),
                prunable_items_per_section: NZU64!(10),
                page_cache,
                replay_buffer,
                key_write_buffer: write_buffer,
                value_write_buffer: write_buffer,
                block_codec_config,
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(1),
                strategy: Sequential,
            },
        )
        .await;
        drop(actor);

        assert!(mailbox.latest_height().await.is_none());
        assert!(mailbox.finalization(Height::new(1)).await.is_none());
        assert_eq!(mailbox.latest_finalization().await, Ok(None));
        assert!(mailbox.get_info(Identifier::Latest).await.is_none());
    });
}
