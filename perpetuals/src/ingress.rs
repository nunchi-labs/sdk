//! Perpetuals [Actor] ingress for cross-module mark-price updates.
//!
//! The spot/perps CLOB actor publishes executable mark prices here so the
//! perpetuals ledger can keep `mark_price` distinct from oracle `index_price`.
//!
//! [Actor]: super::actor::Actor

use crate::{MarketId, PerpetualError, PerpetualLedger};
use commonware_actor::mailbox::{Policy, Sender};
use commonware_utils::Acknowledgement;
use nunchi_common::{RuntimeContext, StateStore};
use std::collections::VecDeque;
use tracing::error;

/// Message delivered to the perpetuals actor mailbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message<A = commonware_utils::acknowledgement::Exact>
where
    A: Acknowledgement,
{
    /// Apply a CLOB-derived mark price to a perpetuals market.
    UpdateMarkPrice {
        market: MarketId,
        mark_price: u128,
        context: RuntimeContext,
        response: A,
    },
}

impl<A> Policy for Message<A>
where
    A: Acknowledgement,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
    }
}

/// Outbox for sending mark-price updates to the perpetuals actor.
#[derive(Clone)]
pub struct Mailbox<A = commonware_utils::acknowledgement::Exact>
where
    A: Acknowledgement,
{
    sender: Sender<Message<A>>,
}

impl<A> Mailbox<A>
where
    A: Acknowledgement,
{
    /// Create a mailbox from an actor ingress sender.
    pub const fn new(sender: Sender<Message<A>>) -> Self {
        Self { sender }
    }

    /// Publish a CLOB mid/last price as the market mark.
    pub fn update_mark_price(
        &mut self,
        market: MarketId,
        mark_price: u128,
        context: RuntimeContext,
        response: A,
    ) -> commonware_actor::Feedback {
        self.sender.enqueue(Message::UpdateMarkPrice {
            market,
            mark_price,
            context,
            response,
        })
    }
}

/// Apply a mailbox message to a perpetuals ledger.
pub async fn apply_message<D, A>(
    ledger: &mut PerpetualLedger<D>,
    message: Message<A>,
) -> Result<(), PerpetualError>
where
    D: crate::PerpetualDB + nunchi_coins::CoinDB + StateStore + Send + Sync,
    A: Acknowledgement,
{
    match message {
        Message::UpdateMarkPrice {
            market,
            mark_price,
            context,
            response,
        } => {
            let result = ledger.update_mark_price(market, mark_price, context).await;
            if result.is_err() {
                error!(?result, "mark price update failed");
            }
            response.acknowledge();
            result
        }
    }
}
