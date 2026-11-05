use std::collections::{BTreeMap, BTreeSet};

use crate::{
    engine::{validate_order, MatchCursor},
    ClobActorSnapshot, ClobError, ClobOperation, MatchBatch, MatchEngine, Market, MarketId, Order,
    OrderId, Transaction, MAX_MATCH_BATCH_FILLS, MAX_MATCH_BATCH_ORDERS,
};
use commonware_codec::{Encode, Read};
use commonware_cryptography::PublicKey;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    FutureExt, SinkExt, StreamExt,
};
use nunchi_common::{Address, RuntimeContext};
use tracing::{debug, warn};

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

    /// Reload committed markets, resting orders, and nonces after process start.
    pub fn restore_snapshot(&mut self, snapshot: ClobActorSnapshot) {
        for (market, sequence) in snapshot.markets {
            self.sequences.insert(market.id, sequence);
            self.markets.insert(market.id, market);
        }
        for order in snapshot.orders {
            if order.status.is_open() && order.remaining_base > 0 {
                self.active_orders.insert(order.id, order);
            }
        }
        for (account, nonce) in snapshot.nonces {
            self.nonces.insert(account, nonce);
        }
    }

    pub fn start<E>(self, context: E) -> Handle<()>
    where
        E: Spawner + Send + 'static,
    {
        context.spawn(|_| self.run())
    }

    /// Spawn the actor with P2P propagation for signed order intents.
    ///
    /// Gossiped intents only enter the validator-local pending book. They do
    /// not produce fills by themselves; the selected proposer remains the sole
    /// source of match batches carried through the consensus extension.
    pub fn start_p2p<E, S, R>(self, context: E, p2p: (S, R)) -> Handle<()>
    where
        E: Spawner + Send + 'static,
        S: Sender + 'static,
        R: Receiver<PublicKey = S::PublicKey> + 'static,
    {
        context.spawn(|_| self.run_p2p(p2p))
    }

    async fn run(mut self) {
        while let Some(message) = self.receiver.next().await {
            self.handle(message);
        }
    }

    async fn run_p2p<S, R>(mut self, (mut sender, mut receiver): (S, R))
    where
        S: Sender,
        R: Receiver<PublicKey = S::PublicKey>,
    {
        loop {
            futures::select! {
                message = self.receiver.next().fuse() => {
                    let Some(message) = message else {
                        warn!("clob mailbox closed, stopping p2p actor");
                        return;
                    };
                    self.handle_with_gossip(message, &mut sender);
                },
                message = receiver.recv().fuse() => {
                    match message {
                        Ok((peer, bytes)) => self.handle_network(peer, bytes),
                        Err(error) => {
                            warn!(?error, "clob p2p receiver closed; continuing node-local");
                            self.run().await;
                            return;
                        }
                    }
                },
            }
        }
    }

    fn handle(&mut self, message: Message) {
        match message {
            Message::SubmitOrder { tx, responder } => {
                let result = self.accept_order(tx);
                let _ = responder.send(result);
            }
            Message::UpsertMarket { market, sequence } => {
                // Genesis seeding queues sequence 0 before recovery runs. Do not
                // roll a restored sequence backwards.
                let current = self.sequences.get(&market.id).copied().unwrap_or(0);
                if sequence >= current || !self.markets.contains_key(&market.id) {
                    self.sequences.insert(market.id, sequence.max(current));
                }
                self.markets.entry(market.id).or_insert(market);
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

    fn handle_with_gossip<S>(&mut self, message: Message, sender: &mut S)
    where
        S: Sender,
    {
        match message {
            Message::SubmitOrder { tx, responder } => {
                let gossip = tx.clone();
                let result = self.accept_order(tx);
                if result.is_ok() {
                    let sent = sender.send(Recipients::All, gossip.encode(), false);
                    if sent.is_empty() {
                        debug!("clob p2p broadcast accepted by no peers");
                    }
                }
                let _ = responder.send(result);
            }
            message => self.handle(message),
        }
    }

    fn handle_network<P>(&mut self, peer: P, mut bytes: commonware_runtime::IoBuf)
    where
        P: PublicKey,
    {
        match Transaction::read_cfg(&mut bytes, &()) {
            Ok(tx) => match self.accept_order(tx) {
                Ok(()) => debug!(?peer, "admitted gossiped clob order intent"),
                Err(error) => debug!(?peer, ?error, "rejected gossiped clob order intent"),
            },
            Err(error) => warn!(?peer, ?error, "invalid gossiped clob order intent"),
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
        let resting_snapshots = self.active_orders.values().cloned().collect::<Vec<_>>();
        let markets = self.markets.clone();
        let sequences = self.sequences.clone();
        let mut replay = match ProposalFillCount::new(
            &resting_snapshots,
            &markets,
            sequences.clone(),
            RuntimeContext::default(),
        ) {
            Ok(replay) => replay,
            Err(error) => {
                warn!(?error, "dropping invalid local clob proposal batch");
                return MatchBatch::default();
            }
        };
        let selected = select_bounded_orders(
            &orders,
            |batch| replay.fill_count(batch),
            MAX_MATCH_BATCH_ORDERS,
            MAX_MATCH_BATCH_FILLS,
        );
        if selected.is_empty() {
            if orders.len() <= MAX_MATCH_BATCH_ORDERS {
                if let Ok(result) = MatchEngine::replay_with_resting(
                    &resting_snapshots,
                    &orders,
                    &self.markets,
                    self.sequences.clone(),
                    RuntimeContext::default(),
                ) {
                    self.drop_closed_pending_orders(&result.orders);
                }
            }
            return MatchBatch::default();
        }
        match MatchEngine::replay_with_resting(
            &resting_snapshots,
            &selected,
            &self.markets,
            self.sequences.clone(),
            RuntimeContext::default(),
        ) {
            Ok(result) if !result.fills.is_empty() => MatchBatch {
                orders: selected,
                fills: result.fills,
            },
            Ok(result) => {
                self.drop_closed_pending_orders(&result.orders);
                MatchBatch::default()
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

/// Fill counts for proposal selection.
///
/// Each call is the accepted prefix plus one candidate, or the accepted prefix again at the end.
/// The cursor commits an order once a later call keeps it, so a candidate verifies and matches once.
pub(crate) struct ProposalFillCount {
    resting: MatchCursor,
    committed: MatchCursor,
    committed_orders: Vec<Transaction>,
    speculative: Option<(Transaction, MatchCursor, usize)>,
}

impl ProposalFillCount {
    pub(crate) fn new(
        resting_orders: &[Order],
        markets: &BTreeMap<MarketId, Market>,
        sequences: BTreeMap<MarketId, u64>,
        context: RuntimeContext,
    ) -> Result<Self, ClobError> {
        let resting = MatchCursor::from_resting(resting_orders, markets, sequences, context)?;
        let committed = resting.clone();
        Ok(Self {
            resting,
            committed,
            committed_orders: Vec::new(),
            speculative: None,
        })
    }

    pub(crate) fn fill_count(&mut self, batch: &[Transaction]) -> Result<usize, ClobError> {
        if batch.is_empty() {
            return Ok(0);
        }

        if let Some((tx, cursor, fills)) = self.speculative.take() {
            let commit_at = self.committed_orders.len();
            let extends = batch.len() > commit_at
                && batch[..commit_at] == self.committed_orders[..]
                && batch[commit_at] == tx;
            if extends {
                self.committed = cursor;
                self.committed_orders.push(tx);
                if batch.len() == self.committed_orders.len() {
                    return Ok(fills);
                }
            }
        }

        if self.committed_orders.len() > batch.len()
            || batch[..self.committed_orders.len()] != self.committed_orders[..]
        {
            self.committed = self.resting.clone();
            self.committed_orders.clear();
        }

        let mut trial = self.committed.clone();
        for tx in &batch[self.committed_orders.len()..] {
            trial.push(tx)?;
        }
        let fills = trial.fill_len();
        if batch.len() == self.committed_orders.len() + 1 {
            self.speculative = Some((batch[batch.len() - 1].clone(), trial, fills));
        }
        Ok(fills)
    }
}

/// Pick a nonce-valid subset that matches and fits in one batch.
///
/// A full pending set above the order cap used to make every proposal empty. Non-filling
/// orders do not consume the last free slot while later orders remain, so a crossing order
/// from another account can still be included.
pub(crate) fn select_bounded_orders(
    orders: &[Transaction],
    mut fill_count: impl FnMut(&[Transaction]) -> Result<usize, ClobError>,
    max_orders: usize,
    max_fills: usize,
) -> Vec<Transaction> {
    if max_orders == 0 || orders.is_empty() {
        return Vec::new();
    }
    let mut chosen = Vec::new();
    // Fill count of `chosen`. The trial callback already produced it when that prefix was accepted.
    let mut chosen_fills = 0;
    let mut blocked = BTreeSet::new();
    let mut next_nonce = BTreeMap::new();
    for (index, tx) in orders.iter().enumerate() {
        if blocked.contains(&tx.account_id) {
            continue;
        }
        if next_nonce
            .get(&tx.account_id)
            .is_some_and(|expected| tx.payload.nonce != *expected)
        {
            blocked.insert(tx.account_id.clone());
            continue;
        }
        if chosen.len() == max_orders {
            blocked.insert(tx.account_id.clone());
            continue;
        }
        let mut trial = chosen.clone();
        trial.push(tx.clone());
        let fills = match fill_count(&trial) {
            Ok(fills) if fills <= max_fills => fills,
            Ok(_) | Err(_) => {
                blocked.insert(tx.account_id.clone());
                continue;
            }
        };
        let later_orders = index + 1 < orders.len();
        if fills == chosen_fills && chosen.len() + 1 == max_orders && later_orders {
            blocked.insert(tx.account_id.clone());
            continue;
        }
        chosen = trial;
        chosen_fills = fills;
        match tx.payload.nonce.checked_add(1) {
            Some(next) => {
                next_nonce.insert(tx.account_id.clone(), next);
            }
            None => {
                blocked.insert(tx.account_id.clone());
            }
        }
    }
    match fill_count(&chosen) {
        Ok(fills) if fills > 0 && fills <= max_fills && chosen.len() <= max_orders => chosen,
        _ => Vec::new(),
    }
}
