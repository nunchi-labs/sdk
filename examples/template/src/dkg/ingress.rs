//! DKG [Actor] ingress (mailbox and messages)
//!
//! [Actor]: super::Actor

use crate::{block::DealerLog, Block};
use commonware_actor::{
    mailbox::{Policy, Sender},
    Feedback,
};
use commonware_consensus::{marshal::Update, Reporter};
use commonware_utils::{acknowledgement::Exact, channel::oneshot, Acknowledgement};
use std::collections::VecDeque;
use tracing::error;

/// A message that can be sent to the [Actor].
///
/// [Actor]: super::Actor
#[allow(clippy::large_enum_variant)]
pub enum Message<A = Exact>
where
    A: Acknowledgement,
{
    /// A request for the [Actor]'s next [DealerLog] for inclusion within a block.
    Act {
        response: oneshot::Sender<Option<DealerLog>>,
    },

    /// A new block has been finalized.
    Finalized { block: Block, response: A },
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

/// Inbox for sending messages to the DKG [Actor].
///
/// [Actor]: super::Actor
#[derive(Clone)]
pub struct Mailbox<A = Exact>
where
    A: Acknowledgement,
{
    sender: Sender<Message<A>>,
}

impl<A> Mailbox<A>
where
    A: Acknowledgement,
{
    /// Create a new mailbox.
    pub const fn new(sender: Sender<Message<A>>) -> Self {
        Self { sender }
    }

    /// Request the [Actor]'s next payload for inclusion within a block.
    ///
    /// [Actor]: super::Actor
    pub async fn act(&mut self) -> Option<DealerLog> {
        let (response_tx, response_rx) = oneshot::channel();
        if !self
            .sender
            .enqueue(Message::Act {
                response: response_tx,
            })
            .accepted()
        {
            error!("failed to send act message");
            return None;
        }

        match response_rx.await {
            Ok(outcome) => outcome,
            Err(err) => {
                error!(?err, "failed to receive act response");
                None
            }
        }
    }
}

impl<A> Reporter for Mailbox<A>
where
    A: Acknowledgement,
{
    type Activity = Update<Block, A>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        // Report the finalized block to the DKG actor on a best-effort basis.
        let Update::Block(block, ack_tx) = update else {
            // We ignore any other updates sent by marshal.
            return Feedback::Ok;
        };
        self.sender.enqueue(Message::Finalized {
            block,
            response: ack_tx,
        })
    }
}
