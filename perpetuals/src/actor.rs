//! Perpetuals actor that drains mailbox messages into ledger state.
//!
//! Chain runtimes can spawn this beside the CLOB actor and wire the CLOB
//! mailbox as a producer of [`crate::ingress::Message::UpdateMarkPrice`].

use crate::{
    ingress::{apply_message, Mailbox},
    PerpetualDB, PerpetualLedger,
};
use commonware_actor::mailbox::{self, Receiver as ActorReceiver};
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner};
use nunchi_common::StateStore;
use std::num::NonZeroUsize;
use tracing::{debug, warn};

/// Perpetuals actor configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub mailbox_size: NonZeroUsize,
}

/// Perpetuals actor over a shared database backend.
pub struct Actor<D, C: Clock> {
    context: ContextCell<C>,
    mailbox: ActorReceiver<crate::ingress::Message>,
    ledger: PerpetualLedger<D>,
}

impl<D, C> Actor<D, C>
where
    C: Metrics + Spawner + Clock,
    D: PerpetualDB + nunchi_coins::CoinDB + StateStore + Send + Sync + 'static,
{
    /// Create a new actor and its paired mailbox.
    pub fn new(context: C, cfg: Config, ledger: PerpetualLedger<D>) -> (Self, Mailbox) {
        let (sender, mailbox) = mailbox::new(context.child("perpetuals-mailbox"), cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                ledger,
            },
            Mailbox::new(sender),
        )
    }

    /// Borrow the ledger for queries while the actor is idle.
    pub fn ledger(&self) -> &PerpetualLedger<D> {
        &self.ledger
    }

    /// Borrow the ledger mutably for deterministic tests.
    pub fn ledger_mut(&mut self) -> &mut PerpetualLedger<D> {
        &mut self.ledger
    }

    /// Start processing mailbox messages until the context is stopped.
    pub fn start(mut self) -> Handle<()>
    where
        C: Spawner + Send + 'static,
    {
        commonware_runtime::spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        loop {
            select_loop! {
                self.context,
                on_stopped => {
                    debug!("perpetuals actor stopped");
                    break;
                },
                message = self.mailbox.recv() => {
                    let Some(message) = message else {
                        continue;
                    };
                    if let Err(err) = apply_message(&mut self.ledger, message).await {
                        warn!(?err, "failed to apply perpetuals mailbox message");
                    }
                },
            }
        }
    }
}
