commonware_macros::stability_scope!(ALPHA {
use commonware_consensus::{Block, Heightable};
use commonware_cryptography::{
    bls12381::{dkg::feldman_desmedt::SignedDealerLog, primitives::variant::MinSig},
    ed25519,
};

mod actor;
mod consensus;
mod egress;
mod ingress;
pub mod orchestrator;
mod setup;
mod state;
#[cfg(test)]
mod tests;

pub use actor::{Actor, Config, Execution};
pub use consensus::{
    Activity, Context, EdScheme, EpochProvider, Finalization, Identity, Notarization, Provider,
    PublicKey, Scheme, Seed, Seedable, Signature, ThresholdScheme,
};
pub use egress::{ContinueOnUpdate, PostUpdate, Update, UpdateCallBack};
pub use ingress::{Mailbox, Message};
pub use setup::PeerConfig;

pub type DealerLog = SignedDealerLog<MinSig, ed25519::PrivateKey>;

pub const MAX_SUPPORTED_MODE: commonware_cryptography::bls12381::primitives::sharing::ModeVersion =
    commonware_cryptography::bls12381::primitives::sharing::ModeVersion::v0();

pub trait ReshareBlock: Block + Heightable + Clone + Send + 'static {
    fn reshare_log(&self) -> Option<&DealerLog>;
}
});
