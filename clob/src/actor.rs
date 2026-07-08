use std::collections::{BTreeMap, BTreeSet};

use crate::{
    engine::validate_order, ClobError, ClobOperation, MatchBatch, MatchEngine, Market, MarketId,
    Order, OrderId, Transaction, MAX_MATCH_BATCH_FILLS, MAX_MATCH_BATCH_ORDERS,
};
use commonware_runtime::{Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use nunchi_common::{Address, RuntimeContext};
use tracing::warn;

/// Runtime settings for the validator-local CLOB actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClobConfig {
    pub mailbox_size: usize,
}

impl Default for ClobConfig {
    fn default() -> Self {
        Self { mailbox_size: 1024 }
    }
}

enum Message {
    SubmitOrder {
        tx: Transaction,
        responder: oneshot::Sender<Result<(), ClobError>>,
    },
    UpsertMarket {
        market: Market,
        sequence: u64,
    },
    SyncAccepted {
        market: Market,
        sequence: u64,
        accepted_orders: Vec<OrderId>,
        order_updates: Vec<(OrderId, Option<Order>)>,
        nonce_updates: Vec<(Address, u64)>,
        responder: oneshot::Sender<Result<(), ClobError>>,
    },
    SyncNonce {
        account: Address,
        nonce: u64,
        responder: oneshot::Sender<Result<(), ClobError>>,
    },
    Propose {
        responder: oneshot::Sender<MatchBatch>,
    },
}

/// Cloneable ingress handle for a running validator-local CLOB actor.
#[derive(Clone, Debug)]
pub struct ClobMailbox {
    sender: mpsc::Sender<Message>,
}

impl ClobMailbox {
    /// Submit a signed owner order intent to the local off-chain book.
    pub async fn submit_order(&self, tx: Transaction) -> Result<(), ClobError> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender.send(Message::SubmitOrder { tx, responder }).await.is_err() {
            return Err(ClobError::ActorStopped);
        }
        receiver.await.unwrap_or(Err(ClobError::ActorStopped))
    }

    /// Make market metadata available to local proposer matching.
    pub fn upsert_market(&self, market: Market) {
        self.upsert_market_state(market, 0);
    }

    /// Make market metadata and the current committed sequence available locally.
    pub fn upsert_market_state(&self, market: Market, sequence: u64) {
        let mut sender = self.sender.clone();
        if sender
            .try_send(Message::UpsertMarket { market, sequence })
            .is_err()
        {
            warn!("clob mailbox unavailable; dropping market update");
        }
    }

    /// Apply order/sequence updates for an accepted match batch.
    pub async fn sync_accepted(
        &self,
        market: Market,
        sequence: u64,
        accepted_orders: Vec<OrderId>,
        order_updates: Vec<(OrderId, Option<Order>)>,
        nonce_updates: Vec<(Address, u64)>,
    ) -> Result<(), ClobError> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::SyncAccepted {
                market,
                sequence,
                accepted_orders,
                order_updates,
                nonce_updates,
                responder,
            })
            .await
            .is_err()
        {
            return Err(ClobError::ActorStopped);
        }
        receiver.await.unwrap_or(Err(ClobError::ActorStopped))
    }

    /// Apply the committed nonce for an account after payload rejection or external sync.
    pub async fn sync_nonce(&self, account: Address, nonce: u64) -> Result<(), ClobError> {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender
            .send(Message::SyncNonce {
                account,
                nonce,
                responder,
            })
            .await
            .is_err()
        {
            return Err(ClobError::ActorStopped);
        }
        receiver.await.unwrap_or(Err(ClobError::ActorStopped))
    }

    /// Drain currently matchable signed orders into one proposed batch.
    pub async fn propose(&self) -> MatchBatch {
        let (responder, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        if sender.send(Message::Propose { responder }).await.is_err() {
            return MatchBatch::default();
        }
        receiver.await.unwrap_or_default()
    }
}

/// Validator-local off-chain CLOB actor.
pub struct ClobActor {
    receiver: mpsc::Receiver<Message>,
    pending_orders: Vec<Transaction>,
    active_orders: BTreeMap<OrderId, Order>,
    markets: BTreeMap<MarketId, Market>,
    sequences: BTreeMap<MarketId, u64>,
    nonces: BTreeMap<Address, u64>,
}

impl ClobActor {
    pub fn new(config: ClobConfig) -> (Self, ClobMailbox) {
        let (sender, receiver) = mpsc::channel(config.mailbox_size);
        (
            Self {
                receiver,
                pending_orders: Vec::new(),
                active_orders: BTreeMap::new(),
                markets: BTreeMap::new(),
                sequences: BTreeMap::new(),
                nonces: BTreeMap::new(),
            },
            ClobMailbox { sender },
        )
    }

    pub fn start<E>(self, context: E) -> Handle<()>
    where
        E: Spawner + Send + 'static,
    {
        context.spawn(|_| self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.receiver.next().await {
            match message {
                Message::SubmitOrder { tx, responder } => {
                    let result = self.accept_order(tx);
                    let _ = responder.send(result);
                }
                Message::UpsertMarket { market, sequence } => {
                    self.sequences.insert(market.id, sequence);
                    self.markets.insert(market.id, market);
                }
                Message::SyncAccepted {
                    market,
                    sequence,
                    accepted_orders,
                    order_updates,
                    nonce_updates,
                    responder,
                } => {
                    self.sync_accepted_batch(
                        market,
                        sequence,
                        accepted_orders,
                        order_updates,
                        nonce_updates,
                    );
                    let _ = responder.send(Ok(()));
                }
                Message::SyncNonce {
                    account,
                    nonce,
                    responder,
                } => {
                    self.sync_nonce_state(account, nonce);
                    let _ = responder.send(Ok(()));
                }
                Message::Propose { responder } => {
                    let _ = responder.send(self.propose_batch());
                }
            }
        }
    }

    fn propose_batch(&mut self) -> MatchBatch {
        if self.pending_orders.is_empty() {
            return MatchBatch::default();
        }
        let orders = self.proposal_orders();
        if orders.is_empty() {
            return MatchBatch::default();
        }
        if orders.len() > MAX_MATCH_BATCH_ORDERS {
            warn!(
                orders = orders.len(),
                "local clob proposal exceeds match batch order limits"
            );
            return MatchBatch::default();
        }
        let resting_snapshots = self
            .active_orders
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let replay = MatchEngine::replay_with_resting(
            &resting_snapshots,
            &orders,
            &self.markets,
            self.sequences.clone(),
            RuntimeContext::default(),
        );
        match replay {
            Ok(result) if result.fills.is_empty() => {
                self.drop_closed_pending_orders(&result.orders);
                MatchBatch::default()
            }
            Ok(result) => {
                if result.fills.len() > MAX_MATCH_BATCH_FILLS {
                    warn!(
                        fills = result.fills.len(),
                        "local clob proposal exceeds match batch fill limits"
                    );
                    return MatchBatch::default();
                }
                MatchBatch {
                    resting_orders: Vec::new(),
                    orders,
                    fills: result.fills,
                }
            }
            Err(error) => {
                warn!(?error, "dropping invalid local clob proposal batch");
                MatchBatch::default()
            }
        }
    }

    fn sync_accepted_batch(
        &mut self,
        market: Market,
        sequence: u64,
        accepted_orders: Vec<OrderId>,
        order_updates: Vec<(OrderId, Option<Order>)>,
        nonce_updates: Vec<(Address, u64)>,
    ) {
        self.sequences.insert(market.id, sequence);
        self.markets.insert(market.id, market);

        let accepted = accepted_orders.into_iter().collect::<BTreeSet<_>>();
        self.pending_orders
            .retain(|tx| !accepted.contains(&OrderId(tx.digest())));

        for (order_id, update) in order_updates {
            match update {
                Some(order) if order.status.is_open() && order.remaining_base > 0 => {
                    self.active_orders.insert(order_id, order);
                }
                _ => {
                    self.active_orders.remove(&order_id);
                }
            }
        }
        for (account, nonce) in nonce_updates {
            self.nonces.insert(account, nonce);
        }
        self.drop_stale_pending_orders();
    }

    fn drop_closed_pending_orders(&mut self, order_updates: &BTreeMap<OrderId, Order>) {
        let closed = order_updates
            .iter()
            .filter_map(|(order_id, order)| {
                if order.status.is_open() && order.remaining_base > 0 {
                    None
                } else {
                    Some(*order_id)
                }
            })
            .collect::<BTreeSet<_>>();
        self.pending_orders
            .retain(|tx| !closed.contains(&OrderId(tx.digest())));
    }

    fn accept_order(&mut self, tx: Transaction) -> Result<(), ClobError> {
        tx.verify()?;
        let ClobOperation::PlaceOrder {
            market,
            price,
            base_quantity,
            ..
        } = &tx.payload.operation
        else {
            return Err(ClobError::InvalidOrder(
                "clob actor only accepts place-order intents",
            ));
        };
        if let Some(market_info) = self.markets.get(market) {
            validate_order(market_info, *price, *base_quantity)?;
        }
        let expected = self.expected_nonce_for_account(&tx.account_id);
        if tx.payload.nonce != expected {
            return Err(ClobError::NonceMismatch {
                account: Box::new(tx.account_id),
                expected,
                actual: tx.payload.nonce,
            });
        }
        let order_id = OrderId(tx.digest());
        if self
            .pending_orders
            .iter()
            .any(|pending| OrderId(pending.digest()) == order_id)
        {
            return Err(ClobError::InvalidOrder("duplicate pending order id"));
        }
        self.pending_orders.push(tx);
        Ok(())
    }

    fn proposal_orders(&mut self) -> Vec<Transaction> {
        let mut expected_nonces = self.nonces.clone();
        let mut stale = BTreeSet::new();
        let mut orders = Vec::new();
        for tx in &self.pending_orders {
            let order_id = OrderId(tx.digest());
            let expected = expected_nonces.entry(tx.account_id.clone()).or_default();
            match tx.payload.nonce.cmp(expected) {
                std::cmp::Ordering::Less => {
                    stale.insert(order_id);
                }
                std::cmp::Ordering::Equal if self.can_locally_replay(tx) => {
                    orders.push(tx.clone());
                    if let Some(next) = expected.checked_add(1) {
                        *expected = next;
                    }
                }
                std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {}
            }
        }
        self.pending_orders
            .retain(|tx| !stale.contains(&OrderId(tx.digest())));
        orders
    }

    fn expected_nonce_for_account(&self, account: &Address) -> u64 {
        let mut expected = *self.nonces.get(account).unwrap_or(&0);
        for tx in &self.pending_orders {
            if &tx.account_id == account && tx.payload.nonce == expected {
                let Some(next) = expected.checked_add(1) else {
                    break;
                };
                expected = next;
            }
        }
        expected
    }

    fn can_locally_replay(&self, tx: &Transaction) -> bool {
        match &tx.payload.operation {
            ClobOperation::PlaceOrder { market, .. } => self.markets.contains_key(market),
            _ => false,
        }
    }

    fn sync_nonce_state(&mut self, account: Address, nonce: u64) {
        self.nonces.insert(account, nonce);
        self.drop_stale_pending_orders();
    }

    fn drop_stale_pending_orders(&mut self) {
        self.pending_orders.retain(|tx| {
            self.nonces
                .get(&tx.account_id)
                .is_none_or(|expected| tx.payload.nonce >= *expected)
        });
    }
}
