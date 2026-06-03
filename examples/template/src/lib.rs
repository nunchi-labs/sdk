use commonware_consensus::types::Epoch;
use commonware_formatting::hex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
};

mod block;
mod consensus;
mod namespace;

pub mod dkg;
pub mod orchestrator;
pub mod setup;

pub mod application;
pub mod engine;

pub use block::{genesis, Block, Finalized, Notarized};
pub use consensus::{
    Activity, Context, EdScheme, EpochProvider, Finalization, Identity, Notarization, Provider,
    PublicKey, Scheme, Seed, Seedable, Signature, ThresholdScheme,
};
pub use namespace::APPLICATION as NAMESPACE;
pub use setup::PeerConfig;

/// The number of blocks in an epoch.
///
/// Production systems should use a much larger value, as DKG/reshare safety depends on
/// synchrony during the epoch window.
pub const BLOCKS_PER_EPOCH: NonZeroU64 = commonware_utils::NZU64!(200);

/// The bootstrap epoch number used in [commonware_consensus::simplex].
pub const EPOCH: Epoch = Epoch::zero();

#[repr(u8)]
pub enum Kind {
    Seed = 0,
    Notarization = 1,
    Finalization = 2,
}

impl Kind {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Seed),
            1 => Some(Self::Notarization),
            2 => Some(Self::Finalization),
            _ => None,
        }
    }

    pub fn to_hex(&self) -> String {
        match self {
            Self::Seed => hex(&[0]),
            Self::Notarization => hex(&[1]),
            Self::Finalization => hex(&[2]),
        }
    }
}

pub const DEFAULT_BLOCKING_THREADS: usize = 512;
pub const DEFAULT_STORAGE_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = commonware_utils::NZU32!(16_384);
pub const DEFAULT_NETWORK_BUFFER_POOL_MAX_PER_CLASS: NonZeroU32 = commonware_utils::NZU32!(4_096);

fn default_blocking_threads() -> usize {
    DEFAULT_BLOCKING_THREADS
}

fn default_storage_buffer_pool_max_per_class() -> Option<NonZeroU32> {
    Some(DEFAULT_STORAGE_BUFFER_POOL_MAX_PER_CLASS)
}

fn default_network_buffer_pool_max_per_class() -> Option<NonZeroU32> {
    Some(DEFAULT_NETWORK_BUFFER_POOL_MAX_PER_CLASS)
}

/// Configuration for the [engine::Engine].
#[derive(Deserialize, Serialize)]
pub struct Config {
    pub private_key: String,
    pub share: String,
    pub polynomial: String,

    pub port: u16,
    pub metrics_port: u16,
    pub directory: String,
    pub worker_threads: usize,
    #[serde(default = "default_blocking_threads")]
    pub blocking_threads: usize,
    #[serde(default = "default_storage_buffer_pool_max_per_class")]
    pub storage_buffer_pool_max_per_class: Option<NonZeroU32>,
    #[serde(default = "default_network_buffer_pool_max_per_class")]
    pub network_buffer_pool_max_per_class: Option<NonZeroU32>,
    #[serde(default)]
    pub storage_buffer_pool_parallelism: Option<NonZeroUsize>,
    #[serde(default)]
    pub network_buffer_pool_parallelism: Option<NonZeroUsize>,
    pub log_level: String,

    pub local: bool,
    pub allowed_peers: Vec<String>,
    pub bootstrappers: Vec<String>,

    pub message_backlog: usize,
    pub mailbox_size: usize,
    pub deque_size: usize,

    pub signature_threads: usize,
}

/// A list of peers provided when a validator is run locally.
///
/// When run remotely, [`commonware_deployer::aws::Hosts`](https://docs.rs/commonware-deployer/latest/commonware_deployer/aws/struct.Hosts.html) is used instead.
#[derive(Deserialize, Serialize)]
pub struct Peers {
    pub addresses: HashMap<String, SocketAddr>,
}

#[cfg(test)]
mod type_tests {
    use super::*;
    use commonware_codec::{Decode, Encode};
    use commonware_consensus::{
        simplex::{
            scheme::bls12381_threshold::vrf as bls12381_threshold,
            types::{Finalization, Finalize, Notarization, Notarize, Proposal},
        },
        types::{Height, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig, certificate::mocks::Fixture, ed25519, sha256,
        Digest, Digestible, Hasher, Sha256, Signer,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::NZU32;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_notarized() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 4;
        let Fixture { schemes, .. } =
            bls12381_threshold::fixture::<MinSig, _>(&mut rng, NAMESPACE, n);

        let context = Context {
            round: Round::new(EPOCH, View::new(9)),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::new(8), sha256::Digest::EMPTY),
        };
        let digest = Sha256::hash(b"hello world");
        let block = Block::new(context, digest, Height::new(10), None);
        let proposal = Proposal::new(
            Round::new(EPOCH, View::new(9)),
            View::new(8),
            block.digest(),
        );

        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap();
        let notarized = Notarized::new(notarization, block.clone());

        let encoded = notarized.encode();
        let decoded =
            Notarized::decode_cfg(encoded, &NZU32!(n)).expect("failed to decode notarized");
        assert_eq!(notarized, decoded);
        assert!(notarized.verify(&schemes[0], &Sequential));
    }

    #[test]
    fn test_finalized() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 4;
        let Fixture { schemes, .. } =
            bls12381_threshold::fixture::<MinSig, _>(&mut rng, NAMESPACE, n);

        let context = Context {
            round: Round::new(EPOCH, View::new(9)),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::new(8), sha256::Digest::EMPTY),
        };
        let digest = Sha256::hash(b"hello world");
        let block = Block::new(context, digest, Height::new(10), None);
        let proposal = Proposal::new(
            Round::new(EPOCH, View::new(9)),
            View::new(8),
            block.digest(),
        );

        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap();
        let finalized = Finalized::new(finalization, block.clone());

        let encoded = finalized.encode();
        let decoded =
            Finalized::decode_cfg(encoded, &NZU32!(n)).expect("failed to decode finalized");
        assert_eq!(finalized, decoded);
        assert!(finalized.verify(&schemes[0], &Sequential));
    }
}
