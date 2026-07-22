//! Bounded finalized-history storage for coins-chain validators.

use crate::{Block, Finalization};
use commonware_codec::Read;
use commonware_cryptography::sha256::Digest;
use commonware_runtime::{buffer::paged::CacheRef, BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_storage::{
    archive::{prunable, Archive as _},
    metadata::{self, Metadata},
    translator::EightCap,
};
use commonware_utils::{sequence::U64, NZU64};
use nunchi_chain::engine::{
    MAX_PENDING_ACKS, PRUNE_MAINTENANCE_INTERVAL, PRUNE_RETAINED_MARSHAL_BLOCKS, REPLAY_BUFFER,
    WRITE_BUFFER,
};
use std::num::NonZeroU64;

pub(crate) const FORMAT_VERSION: u64 = 1;
pub(crate) const PRUNABLE_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(4_096);
pub(crate) const LOGICAL_RETENTION: u64 =
    PRUNE_RETAINED_MARSHAL_BLOCKS as u64 + MAX_PENDING_ACKS.get() as u64 + 1;
pub(crate) const MAX_RETAINED_HEIGHTS: u64 = LOGICAL_RETENTION
    + PRUNABLE_ITEMS_PER_SECTION.get()
    - 1
    + PRUNE_MAINTENANCE_INTERVAL.get() as u64
    - 1;

const MARKER_KEY: U64 = U64::new(0);

pub(crate) type FinalizationsArchive<E> =
    prunable::Archive<EightCap, E, Digest, Finalization>;
pub(crate) type BlocksArchive<E> = prunable::Archive<EightCap, E, Digest, Block>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MarkerStatus {
    Created,
    RecoveredPartialInitialization,
    Present,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HistoryError {
    #[error("legacy finalized-history partition exists: {partition}; stop the devnet and clear the complete validator storage directory before relaunch")]
    LegacyPartition { partition: String },
    #[error("history format marker exists but required partition is missing: {partition}; clear the complete devnet validator storage directory before relaunch")]
    MarkedPartitionMissing { partition: String },
    #[error("history format marker is missing but {partition} contains finalized data at height {height}; refusing to modify unmarked storage")]
    NonEmptyUnmarked { partition: String, height: u64 },
    #[error("invalid history format marker in {partition}: expected version {expected}, found {found:?}")]
    InvalidMarker {
        partition: String,
        expected: u64,
        found: Option<u64>,
    },
    #[error("failed to inspect history partition {partition}: {source}")]
    Inspect {
        partition: String,
        #[source]
        source: commonware_runtime::Error,
    },
    #[error("failed to open history archive partition {partition}: {source}")]
    Archive {
        partition: String,
        #[source]
        source: commonware_storage::archive::Error,
    },
    #[error("failed to access history marker partition {partition}: {source}")]
    Marker {
        partition: String,
        #[source]
        source: commonware_storage::metadata::Error,
    },
    #[error("invalid history retention configuration: {0}")]
    Retention(&'static str),
}

#[derive(Clone, Debug)]
pub(crate) struct Partitions {
    pub(crate) finalizations_key: String,
    pub(crate) finalizations_value: String,
    pub(crate) blocks_key: String,
    pub(crate) blocks_value: String,
    pub(crate) metadata: String,
}

impl Partitions {
    pub(crate) fn new(prefix: &str) -> Self {
        Self {
            finalizations_key: format!(
                "{prefix}-finalizations-by-height-prunable-v1-key"
            ),
            finalizations_value: format!(
                "{prefix}-finalizations-by-height-prunable-v1-value"
            ),
            blocks_key: format!("{prefix}-finalized-blocks-prunable-v1-key"),
            blocks_value: format!("{prefix}-finalized-blocks-prunable-v1-value"),
            metadata: format!("{prefix}-history-prunable-v1-metadata"),
        }
    }

    fn archives(&self) -> [&str; 4] {
        [
            &self.finalizations_key,
            &self.finalizations_value,
            &self.blocks_key,
            &self.blocks_value,
        ]
    }
}

pub(crate) struct Opened<E>
where
    E: BufferPooler + Clock + Storage + Metrics,
{
    pub(crate) finalizations: FinalizationsArchive<E>,
    pub(crate) blocks: BlocksArchive<E>,
    pub(crate) partitions: Partitions,
    pub(crate) marker_status: MarkerStatus,
}

pub(crate) const fn policy_floor(tip: u64, retained: u64) -> u64 {
    tip.saturating_add(1).saturating_sub(retained)
}

pub(crate) fn validate_production_retention() -> Result<(), HistoryError> {
    if MAX_PENDING_ACKS.get() != 16 {
        return Err(HistoryError::Retention(
            "MAX_PENDING_ACKS changed; update the mandatory rewind assertion",
        ));
    }
    if LOGICAL_RETENTION != 217 {
        return Err(HistoryError::Retention(
            "logical finalized-history retention must be 217",
        ));
    }
    if MAX_RETAINED_HEIGHTS != 4_343 {
        return Err(HistoryError::Retention(
            "section-granular finalized-history bound must be 4,343",
        ));
    }
    Ok(())
}

pub(crate) async fn open<E>(
    context: &E,
    prefix: &str,
    page_cache: CacheRef,
    block_codec_config: <Block as Read>::Cfg,
) -> Result<Opened<E>, HistoryError>
where
    E: BufferPooler + Clock + Spawner + Storage + Metrics,
{
    validate_production_retention()?;
    reject_legacy(context, prefix).await?;

    let partitions = Partitions::new(prefix);
    let marker_existed = partition_exists(context, &partitions.metadata).await?;
    let mut archive_existed = [false; 4];
    for (exists, partition) in archive_existed
        .iter_mut()
        .zip(partitions.archives().into_iter())
    {
        *exists = partition_exists(context, partition).await?;
    }
    let mut finalizations =
        init_finalizations(context, &partitions, page_cache.clone()).await?;
    let mut blocks = init_blocks(
        context,
        &partitions,
        page_cache.clone(),
        block_codec_config,
    )
    .await?;

    let marker_status = if marker_existed {
        validate_marker(context, &partitions.metadata).await?;
        let archives_empty = finalizations.first_index().is_none() && blocks.first_index().is_none();
        let all_lazy = archive_existed.iter().all(|exists| !exists);
        if !(archive_existed.iter().all(|exists| *exists) || archives_empty && all_lazy) {
            let partition = partitions
                .archives()
                .into_iter()
                .zip(archive_existed)
                .find_map(|(partition, exists)| (!exists).then_some(partition))
                .expect("at least one marked archive partition is missing");
            return Err(HistoryError::MarkedPartitionMissing {
                partition: partition.to_string(),
            });
        }
        MarkerStatus::Present
    } else {
        if let Some(height) = finalizations.first_index() {
            return Err(HistoryError::NonEmptyUnmarked {
                partition: partitions.finalizations_key.clone(),
                height,
            });
        }
        if let Some(height) = blocks.first_index() {
            return Err(HistoryError::NonEmptyUnmarked {
                partition: partitions.blocks_key.clone(),
                height,
            });
        }

        // Ensure all newly-created archive blobs are durable and structurally reopenable before
        // committing the format marker.
        finalizations.sync().await.map_err(|source| HistoryError::Archive {
            partition: partitions.finalizations_key.clone(),
            source,
        })?;
        blocks.sync().await.map_err(|source| HistoryError::Archive {
            partition: partitions.blocks_key.clone(),
            source,
        })?;
        drop(finalizations);
        drop(blocks);
        finalizations = init_finalizations(context, &partitions, page_cache.clone()).await?;
        blocks = init_blocks(context, &partitions, page_cache, block_codec_config).await?;
        write_marker(context, &partitions.metadata).await?;

        if archive_existed.into_iter().any(|exists| exists) {
            MarkerStatus::RecoveredPartialInitialization
        } else {
            MarkerStatus::Created
        }
    };

    Ok(Opened {
        finalizations,
        blocks,
        partitions,
        marker_status,
    })
}

async fn init_finalizations<E>(
    context: &E,
    partitions: &Partitions,
    page_cache: CacheRef,
) -> Result<FinalizationsArchive<E>, HistoryError>
where
    E: BufferPooler + Clock + Spawner + Storage + Metrics,
{
    prunable::Archive::init(
        context.child("finalizations_by_height"),
        prunable::Config {
            translator: EightCap,
            key_partition: partitions.finalizations_key.clone(),
            key_page_cache: page_cache,
            value_partition: partitions.finalizations_value.clone(),
            compression: Some(3),
            codec_config: (),
            items_per_section: PRUNABLE_ITEMS_PER_SECTION,
            key_write_buffer: WRITE_BUFFER,
            value_write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        },
    )
    .await
    .map_err(|source| HistoryError::Archive {
        partition: partitions.finalizations_key.clone(),
        source,
    })
}

async fn init_blocks<E>(
    context: &E,
    partitions: &Partitions,
    page_cache: CacheRef,
    codec_config: <Block as Read>::Cfg,
) -> Result<BlocksArchive<E>, HistoryError>
where
    E: BufferPooler + Clock + Spawner + Storage + Metrics,
{
    prunable::Archive::init(
        context.child("finalized_blocks"),
        prunable::Config {
            translator: EightCap,
            key_partition: partitions.blocks_key.clone(),
            key_page_cache: page_cache,
            value_partition: partitions.blocks_value.clone(),
            compression: Some(3),
            codec_config,
            items_per_section: PRUNABLE_ITEMS_PER_SECTION,
            key_write_buffer: WRITE_BUFFER,
            value_write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        },
    )
    .await
    .map_err(|source| HistoryError::Archive {
        partition: partitions.blocks_key.clone(),
        source,
    })
}

async fn partition_exists<E: Storage>(context: &E, partition: &str) -> Result<bool, HistoryError> {
    match context.scan(partition).await {
        Ok(_) => Ok(true),
        Err(commonware_runtime::Error::PartitionMissing(_)) => Ok(false),
        Err(source) => Err(HistoryError::Inspect {
            partition: partition.to_string(),
            source,
        }),
    }
}

async fn validate_marker<E>(context: &E, partition: &str) -> Result<(), HistoryError>
where
    E: BufferPooler + Clock + Storage + Metrics + Spawner,
{
    let marker = Metadata::<E, U64, u64>::init(
        context.child("history_marker"),
        metadata::Config {
            partition: partition.to_string(),
            codec_config: (),
        },
    )
    .await
    .map_err(|source| HistoryError::Marker {
        partition: partition.to_string(),
        source,
    })?;
    let found = marker.get(&MARKER_KEY).copied();
    if found != Some(FORMAT_VERSION) {
        return Err(HistoryError::InvalidMarker {
            partition: partition.to_string(),
            expected: FORMAT_VERSION,
            found,
        });
    }
    Ok(())
}

async fn write_marker<E>(context: &E, partition: &str) -> Result<(), HistoryError>
where
    E: BufferPooler + Clock + Storage + Metrics + Spawner,
{
    let mut marker = Metadata::<E, U64, u64>::init(
        context.child("history_marker"),
        metadata::Config {
            partition: partition.to_string(),
            codec_config: (),
        },
    )
    .await
    .map_err(|source| HistoryError::Marker {
        partition: partition.to_string(),
        source,
    })?;
    marker
        .put_sync(MARKER_KEY, FORMAT_VERSION)
        .await
        .map_err(|source| HistoryError::Marker {
            partition: partition.to_string(),
            source,
        })
}

async fn reject_legacy<E: Storage>(context: &E, prefix: &str) -> Result<(), HistoryError> {
    const FINALIZATION_SUFFIXES: [&str; 5] = [
        "finalizations-by-height-metadata",
        "finalizations-by-height-freezer-table",
        "finalizations-by-height-freezer-key",
        "finalizations-by-height-freezer-value",
        "finalizations-by-height-ordinal",
    ];
    const BLOCK_SUFFIXES: [&str; 5] = [
        "finalized_blocks-metadata",
        "finalized_blocks-freezer-table",
        "finalized_blocks-freezer-key",
        "finalized_blocks-freezer-value",
        "finalized_blocks-ordinal",
    ];

    for suffix in FINALIZATION_SUFFIXES.into_iter().chain(BLOCK_SUFFIXES) {
        let partition = format!("{prefix}-{suffix}");
        if partition_exists(context, &partition).await? {
            return Err(HistoryError::LegacyPartition { partition });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _};
    use commonware_utils::{NZU16, NZU32, NZUsize};

    #[test]
    fn production_retention_arithmetic() {
        validate_production_retention().unwrap();
        assert_eq!(policy_floor(216, LOGICAL_RETENTION), 0);
        assert_eq!(policy_floor(217, LOGICAL_RETENTION), 1);
        assert_eq!(LOGICAL_RETENTION, 217);
        assert_eq!(MAX_RETAINED_HEIGHTS, 4_343);
    }

    #[test]
    fn fresh_format_marker_is_durable_and_legacy_is_not_created() {
        deterministic::Runner::default().start(|context| async move {
            let page_cache = CacheRef::from_pooler(&context, NZU16!(4_096), NZUsize!(32));
            let first = open(
                &context,
                "validator",
                page_cache.clone(),
                (NZU32!(1), ()),
            )
            .await
            .expect("initialize fresh history");
            assert_eq!(first.marker_status, MarkerStatus::Created);
            assert_eq!(first.finalizations.first_index(), None);
            assert_eq!(first.blocks.first_index(), None);
            drop(first);

            let reopened = open(
                &context,
                "validator",
                page_cache,
                (NZU32!(1), ()),
            )
            .await
            .expect("reopen marked history");
            assert_eq!(reopened.marker_status, MarkerStatus::Present);

            for suffix in [
                "finalizations-by-height-metadata",
                "finalizations-by-height-freezer-table",
                "finalizations-by-height-freezer-key",
                "finalizations-by-height-freezer-value",
                "finalizations-by-height-ordinal",
                "finalized_blocks-metadata",
                "finalized_blocks-freezer-table",
                "finalized_blocks-freezer-key",
                "finalized_blocks-freezer-value",
                "finalized_blocks-ordinal",
            ] {
                assert!(matches!(
                    context.scan(&format!("validator-{suffix}")).await,
                    Err(commonware_runtime::Error::PartitionMissing(_))
                ));
            }
        });
    }

    #[test]
    fn refuses_known_legacy_partition() {
        deterministic::Runner::default().start(|context| async move {
            context
                .open("validator-finalized_blocks-ordinal", b"legacy")
                .await
                .expect("create legacy partition");
            let page_cache = CacheRef::from_pooler(&context, NZU16!(4_096), NZUsize!(32));
            let result = open(
                &context,
                "validator",
                page_cache,
                (NZU32!(1), ()),
            )
            .await;
            assert!(matches!(result, Err(HistoryError::LegacyPartition { .. })));
        });
    }
}
