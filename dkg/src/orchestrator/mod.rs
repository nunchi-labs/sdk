//! Consensus engine orchestrator for epoch transitions.

mod actor;
pub use actor::{Actor, Config, NoopReporter, StartupFloor};

mod ingress;
#[cfg(test)]
pub use ingress::Message;
pub use ingress::{EpochTransition, Mailbox};
