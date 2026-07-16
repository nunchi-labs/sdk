//! Config-aware P2P resolver for Nunchi's variable-value QMDB.
//!
//! Commonware's QMDB sync engine supports variable operations, but the 2026.7.0 glue P2P
//! resolver decodes only operations whose codec configuration is exactly `()`. Nunchi values
//! are `Vec<u8>`, so their operation codec requires a length bound. This module keeps the
//! Commonware request/response wire layout and resolver engine while supplying that bound when
//! decoding peer responses.

use bytes::{Buf, BufMut, Bytes};
use commonware_actor::mailbox::{
    self as actor_mailbox, Overflow, Policy, Sender as ActorSender,
};
use commonware_codec::{
    Decode, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{sha256::Digest, PublicKey};
use commonware_glue::stateful::db::{AttachableResolver, Shared};
use commonware_macros::{select, select_loop};
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{p2p, Delivery, Resolver as _};
use commonware_runtime::{
    spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_storage::{
    merkle::{Proof, MAX_PINNED_NODES, MAX_PROOF_DIGESTS_PER_ELEMENT},
    mmr::{self, Location},
    qmdb::sync::resolver::{FetchResult, Resolver as SyncResolver},
    Context as StorageContext,
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    Span,
};
use futures::{future, FutureExt as _};
use nunchi_common::{
    QmdbBackend, QmdbDatabaseSet, QmdbOperation, QmdbOperationCfg,
};
use rand::Rng;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, VecDeque},
    fmt,
    future::Future,
    hash::{Hash, Hasher},
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, info};

type ResolverResult =
    Result<FetchResult<mmr::Family, QmdbOperation, Digest>, ResponseDropped>;
type PendingSubscriber = oneshot::Sender<ResolverResult>;

/// Probe-only certificate provider for nodes that have not started their DKG actor yet.
///
/// The epoch-independent scheme authenticates recovered certificates from any resharing epoch.
/// The sizing scheme supplies the configured participant count used only to derive the `f + 1`
/// response threshold. Keeping this separate from the consensus provider avoids treating an old
/// epoch's signing scheme as valid for a future epoch.
#[derive(Clone)]
pub struct FloorProvider<S> {
    verifier: std::sync::Arc<S>,
    sizing_scheme: std::sync::Arc<S>,
}

impl<S> FloorProvider<S> {
    /// Create a provider from an all-epoch verifier and a committee-sizing scheme.
    pub fn new(verifier: S, sizing_scheme: S) -> Self {
        Self {
            verifier: std::sync::Arc::new(verifier),
            sizing_scheme: std::sync::Arc::new(sizing_scheme),
        }
    }
}

impl<S> commonware_cryptography::certificate::Provider for FloorProvider<S>
where
    S: commonware_cryptography::certificate::Scheme,
{
    type Scope = commonware_consensus::types::Epoch;
    type Scheme = S;

    fn scoped(
        &self,
        _epoch: Self::Scope,
    ) -> Option<commonware_cryptography::certificate::Scoped<Self::Scheme>> {
        Some(commonware_cryptography::certificate::Scoped::verifier(
            self.verifier.clone(),
        ))
    }

    fn scheme(&self, _epoch: Self::Scope) -> Option<std::sync::Arc<Self::Scheme>> {
        Some(self.sizing_scheme.clone())
    }
}

/// Configuration for [`Actor`].
pub struct Config<E, P, D, B>
where
    E: StorageContext,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    /// Provider for the current peer set.
    pub peer_provider: D,
    /// Blocker used when peers send invalid data.
    pub blocker: B,
    /// Local database used to serve incoming requests when available.
    pub database: Option<QmdbDatabaseSet<E>>,
    /// Codec configuration used to bound operation values received from peers.
    pub operation_codec_config: QmdbOperationCfg,
    /// Maximum size of resolver mailbox backlogs.
    pub mailbox_size: NonZeroUsize,
    /// Local node identity if available.
    pub me: Option<P>,
    /// Initial expected performance for new peers.
    pub initial: Duration,
    /// Request timeout.
    pub timeout: Duration,
    /// Retry cadence for pending fetches.
    pub fetch_retry_timeout: Duration,
    /// Maximum number of operations to serve in a single response.
    pub max_serve_ops: NonZeroU64,
    /// Send fetch requests with network priority.
    pub priority_requests: bool,
    /// Send responses with network priority.
    pub priority_responses: bool,
}

#[derive(Clone, Debug)]
struct Request {
    op_count: Location,
    start_loc: Location,
    max_ops: NonZeroU64,
    include_pinned_nodes: bool,
}

impl PartialEq for Request {
    fn eq(&self, other: &Self) -> bool {
        self.op_count == other.op_count
            && self.start_loc == other.start_loc
            && self.max_ops == other.max_ops
            && self.include_pinned_nodes == other.include_pinned_nodes
    }
}

impl Eq for Request {}

impl PartialOrd for Request {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Request {
    fn cmp(&self, other: &Self) -> Ordering {
        self.op_count
            .cmp(&other.op_count)
            .then_with(|| self.start_loc.cmp(&other.start_loc))
            .then_with(|| self.max_ops.cmp(&other.max_ops))
            .then_with(|| self.include_pinned_nodes.cmp(&other.include_pinned_nodes))
    }
}

impl Hash for Request {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.op_count.hash(state);
        self.start_loc.hash(state);
        self.max_ops.hash(state);
        self.include_pinned_nodes.hash(state);
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Request(count={}, start={}, max={}, pinned={})",
            self.op_count, self.start_loc, self.max_ops, self.include_pinned_nodes,
        )
    }
}

impl Write for Request {
    fn write(&self, buf: &mut impl BufMut) {
        self.op_count.write(buf);
        self.start_loc.write(buf);
        self.max_ops.write(buf);
        self.include_pinned_nodes.write(buf);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        self.op_count.encode_size()
            + self.start_loc.encode_size()
            + self.max_ops.encode_size()
            + self.include_pinned_nodes.encode_size()
    }
}

impl Read for Request {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            op_count: Location::read(buf)?,
            start_loc: Location::read(buf)?,
            max_ops: NonZeroU64::read(buf)?,
            include_pinned_nodes: bool::read(buf)?,
        })
    }
}

impl Span for Request {}

struct Response {
    proof: Proof<mmr::Family, Digest>,
    operations: Vec<QmdbOperation>,
    pinned_nodes: Option<Vec<Digest>>,
}

impl Write for Response {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.operations.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl EncodeSize for Response {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.operations.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl Read for Response {
    /// `(max_operations, operation_codec_config)`.
    type Cfg = (usize, QmdbOperationCfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let (max_ops, operation_cfg) = cfg;
        let max_proof_digests = max_ops.saturating_mul(MAX_PROOF_DIGESTS_PER_ELEMENT);
        let proof = Proof::<mmr::Family, Digest>::read_cfg(buf, &max_proof_digests)?;
        let operations = Vec::<QmdbOperation>::read_cfg(
            buf,
            &(RangeCfg::from(..=*max_ops), *operation_cfg),
        )?;
        let pinned_nodes = Option::<Vec<Digest>>::read_range(buf, ..=MAX_PINNED_NODES)?;
        Ok(Self {
            proof,
            operations,
            pinned_nodes,
        })
    }
}

enum EngineMessage {
    Deliver {
        key: Request,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        key: Request,
        response: oneshot::Sender<Bytes>,
    },
}

impl EngineMessage {
    fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

#[derive(Default)]
struct EnginePending(VecDeque<EngineMessage>);

impl Overflow<EngineMessage> for EnginePending {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(EngineMessage) -> Option<EngineMessage>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }
            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl Policy for EngineMessage {
    type Overflow = EnginePending;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if !message.response_closed() {
            overflow.0.push_back(message);
        }
    }
}

#[derive(Clone)]
struct Handler {
    sender: ActorSender<EngineMessage>,
}

impl Handler {
    const fn new(sender: ActorSender<EngineMessage>) -> Self {
        Self { sender }
    }
}

impl commonware_resolver::Consumer for Handler {
    type Key = Request;
    type Value = Bytes;
    type Subscriber = ();

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(EngineMessage::Deliver {
            key: delivery.key,
            value,
            response,
        });
        receiver
    }
}

impl p2p::Producer for Handler {
    type Key = Request;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(EngineMessage::Produce { key, response });
        receiver
    }
}

/// The resolver actor dropped a response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

enum Message<E: StorageContext> {
    AttachDatabase(QmdbDatabaseSet<E>),
    GetOperations {
        request: Request,
        response: oneshot::Sender<ResolverResult>,
    },
    CancelOperations {
        request: Request,
    },
}

impl<E: StorageContext> Message<E> {
    fn response_closed(&self) -> bool {
        match self {
            Self::AttachDatabase(_) | Self::CancelOperations { .. } => false,
            Self::GetOperations { response, .. } => response.is_closed(),
        }
    }
}

struct Pending<E: StorageContext> {
    database: Option<QmdbDatabaseSet<E>>,
    messages: VecDeque<Message<E>>,
}

impl<E: StorageContext> Default for Pending<E> {
    fn default() -> Self {
        Self {
            database: None,
            messages: VecDeque::new(),
        }
    }
}

impl<E: StorageContext> Overflow<Message<E>> for Pending<E> {
    fn is_empty(&self) -> bool {
        self.database.is_none() && self.messages.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(Message<E>) -> Option<Message<E>>,
    {
        if let Some(database) = self.database.take() {
            if let Some(Message::AttachDatabase(database)) = push(Message::AttachDatabase(database))
            {
                self.database = Some(database);
                return;
            }
        }
        while let Some(message) = self.messages.pop_front() {
            if message.response_closed() {
                continue;
            }
            if let Some(message) = push(message) {
                self.messages.push_front(message);
                break;
            }
        }
    }
}

impl<E: StorageContext> Policy for Message<E> {
    type Overflow = Pending<E>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }
        match message {
            Message::AttachDatabase(database) => overflow.database = Some(database),
            message => overflow.messages.push_back(message),
        }
    }
}

/// Client-facing resolver handle used by the QMDB sync engine.
pub struct Mailbox<E: StorageContext> {
    sender: ActorSender<Message<E>>,
}

impl<E: StorageContext> Clone for Mailbox<E> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<E: StorageContext> Mailbox<E> {
    const fn new(sender: ActorSender<Message<E>>) -> Self {
        Self { sender }
    }

    /// Attach a database so the actor can serve incoming peer requests.
    pub fn attach_database(&self, database: QmdbDatabaseSet<E>) {
        let _ = self.sender.enqueue(Message::AttachDatabase(database));
    }
}

impl<E: StorageContext> SyncResolver for Mailbox<E> {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = QmdbOperation;
    type Error = ResponseDropped;

    async fn get_operations(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        cancel_rx: oneshot::Receiver<()>,
    ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        let request = Request {
            op_count,
            start_loc,
            max_ops,
            include_pinned_nodes,
        };
        futures::pin_mut!(cancel_rx);
        let (response_tx, response_rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetOperations {
            request: request.clone(),
            response: response_tx,
        });
        futures::pin_mut!(response_rx);

        select! {
            response = response_rx.as_mut() => response.map_err(|_| ResponseDropped)?,
            _ = cancel_rx.as_mut() => {
                if let Some(response) = response_rx.as_mut().now_or_never() {
                    return response.map_err(|_| ResponseDropped)?;
                }
                let _ = self.sender.enqueue(Message::CancelOperations { request });
                Err(ResponseDropped)
            },
        }
    }
}

impl<E: StorageContext> AttachableResolver<QmdbBackend<E>> for Mailbox<E> {
    fn attach_database(&self, db: Shared<QmdbBackend<E>>) -> impl Future<Output = ()> + Send {
        Self::attach_database(self, db);
        std::future::ready(())
    }
}

enum State<E: StorageContext> {
    NoDb,
    HasDb(QmdbDatabaseSet<E>),
}

enum MailboxAction {
    None,
    Fetch(Request),
    Cancel(Request),
}

/// P2P QMDB resolver that decodes variable-value operations with explicit bounds.
pub struct Actor<E, P, D, B>
where
    E: StorageContext + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    context: ContextCell<E>,
    config: Config<E, P, D, B>,
    mailbox_rx: actor_mailbox::Receiver<Message<E>>,
    state: State<E>,
    pending: BTreeMap<Request, Vec<PendingSubscriber>>,
}

impl<E, P, D, B> Actor<E, P, D, B>
where
    E: StorageContext + BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    /// Create a resolver actor and mailbox.
    pub fn new(context: E, mut config: Config<E, P, D, B>) -> (Self, Mailbox<E>) {
        let state = config.database.take().map_or(State::NoDb, State::HasDb);
        let (mailbox_tx, mailbox_rx) =
            actor_mailbox::new(context.child("mailbox"), config.mailbox_size);
        let mailbox = Mailbox::new(mailbox_tx);
        (
            Self {
                context: ContextCell::new(context),
                config,
                mailbox_rx,
                state,
                pending: BTreeMap::new(),
            },
            mailbox,
        )
    }

    /// Start the resolver service.
    pub fn start(
        mut self,
        net: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(net))
    }

    async fn run(
        mut self,
        (sender, receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let (handler_tx, mut handler_rx) =
            actor_mailbox::new(self.context.child("handler"), self.config.mailbox_size);
        let handler = Handler::new(handler_tx);
        let (engine, mut resolver_mailbox) = p2p::Engine::new(
            self.context.as_present().child("resolver"),
            p2p::Config {
                peer_provider: self.config.peer_provider.clone(),
                blocker: self.config.blocker.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.config.mailbox_size,
                me: self.config.me.clone(),
                initial: self.config.initial,
                timeout: self.config.timeout,
                fetch_retry_timeout: self.config.fetch_retry_timeout,
                priority_requests: self.config.priority_requests,
                priority_responses: self.config.priority_responses,
            },
        );
        let mut resolver_task = engine.start((sender, receiver));

        select_loop! {
            self.context,
            on_start => {
                self.pending.retain(|_, subscribers| {
                    subscribers.retain(|subscriber| !subscriber.is_closed());
                    !subscribers.is_empty()
                });
                let mailbox_message = async {
                    match self.mailbox_rx.recv().await {
                        Some(message) => Some(message),
                        None => future::pending().await,
                    }
                };
            },
            on_stopped => return,
            _ = &mut resolver_task => return,
            Some(message) = mailbox_message else continue => {
                match self.handle_mailbox_message(message) {
                    MailboxAction::None => {}
                    MailboxAction::Fetch(request) => {
                        resolver_mailbox.fetch(request);
                    }
                    MailboxAction::Cancel(request) => {
                        resolver_mailbox.retain(move |key, _| key != &request);
                    }
                }
            },
            Some(message) = handler_rx.recv() else return => match message {
                EngineMessage::Deliver { key, value, response } => {
                    self.handle_deliver(key, value, response).await;
                }
                EngineMessage::Produce { key, response } => {
                    self.handle_produce(key, response).await;
                }
            },
        }
    }

    fn handle_mailbox_message(&mut self, message: Message<E>) -> MailboxAction {
        match message {
            Message::AttachDatabase(database) => {
                let replacing_existing = matches!(self.state, State::HasDb(_));
                info!(replacing_existing, "attached state-sync resolver database");
                self.state = State::HasDb(database);
                MailboxAction::None
            }
            Message::GetOperations { request, response } => {
                if let Some(subscribers) = self.pending.get_mut(&request) {
                    subscribers.retain(|subscriber| !subscriber.is_closed());
                    if !subscribers.is_empty() {
                        subscribers.push(response);
                        return MailboxAction::None;
                    }
                }
                self.pending.insert(request.clone(), vec![response]);
                MailboxAction::Fetch(request)
            }
            Message::CancelOperations { request } => {
                if self.should_cancel_request(&request) {
                    MailboxAction::Cancel(request)
                } else {
                    MailboxAction::None
                }
            }
        }
    }

    fn should_cancel_request(&mut self, request: &Request) -> bool {
        let Some(subscribers) = self.pending.get_mut(request) else {
            return false;
        };
        subscribers.retain(|subscriber| !subscriber.is_closed());
        if !subscribers.is_empty() {
            return false;
        }
        self.pending.remove(request);
        true
    }

    async fn handle_deliver(
        &mut self,
        key: Request,
        value: Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let Some(subscribers) = self.pending.remove(&key) else {
            response.send_lossy(true);
            return;
        };
        let decode_cfg = (
            key.max_ops.get() as usize,
            self.config.operation_codec_config,
        );
        let decoded = match Response::decode_cfg(value, &decode_cfg) {
            Ok(decoded) => decoded,
            Err(error) => {
                debug!(?key, ?error, "invalid state-sync response");
                self.pending.insert(key, subscribers);
                response.send_lossy(false);
                return;
            }
        };

        let mut approvals = Vec::new();
        for subscriber in subscribers {
            let (success_tx, success_rx) = oneshot::channel();
            if subscriber
                .send(Ok(FetchResult::with_callback(
                    decoded.proof.clone(),
                    decoded.operations.clone(),
                    decoded.pinned_nodes.clone(),
                    success_tx,
                )))
                .is_ok()
            {
                approvals.push(success_rx);
            }
        }
        if approvals.is_empty() {
            response.send_lossy(true);
            return;
        }
        let mut peer_valid = true;
        for approval in approvals {
            if let Ok(approved) = approval.await {
                peer_valid &= approved;
            }
        }
        response.send_lossy(peer_valid);
    }

    async fn handle_produce(&mut self, key: Request, response: oneshot::Sender<Bytes>) {
        let State::HasDb(database) = &self.state else {
            return;
        };
        if key.max_ops > self.config.max_serve_ops {
            return;
        }
        let (_cancel_tx, cancel_rx) = oneshot::channel();
        let result = database
            .get_operations(
                key.op_count,
                key.start_loc,
                key.max_ops,
                key.include_pinned_nodes,
                cancel_rx,
            )
            .await;
        let Ok(fetch) = result else {
            return;
        };
        response.send_lossy(
            Response {
                proof: fetch.proof,
                operations: fetch.operations,
                pinned_nodes: fetch.pinned_nodes,
            }
            .encode(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;
    use commonware_runtime::{deterministic, Runner as _};

    fn response(value: Vec<u8>) -> Response {
        Response {
            proof: Proof {
                leaves: Location::new(0),
                inactive_peaks: 0,
                digests: Vec::new(),
            },
            operations: vec![QmdbOperation::CommitFloor(
                Some(value),
                Location::new(0),
            )],
            pinned_nodes: None,
        }
    }

    #[test]
    fn response_codec_uses_explicit_value_bound() {
        let encoded = response(vec![9; 32]).encode();
        let cfg = (1, ((), (RangeCfg::from(..=32), ())));
        let decoded = Response::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(decoded.operations.len(), 1);
    }

    #[test]
    fn response_codec_rejects_oversized_value() {
        let encoded = response(vec![9; 33]).encode();
        let cfg = (1, ((), (RangeCfg::from(..=32), ())));
        assert!(Response::decode_cfg(encoded, &cfg).is_err());
    }

    #[test]
    fn request_codec_round_trips() {
        let request = Request {
            op_count: Location::new(128),
            start_loc: Location::new(64),
            max_ops: NonZeroU64::new(16).unwrap(),
            include_pinned_nodes: true,
        };
        let decoded = Request::decode(request.encode()).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn mailbox_cancellation_is_forwarded() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context, NonZeroUsize::new(4).unwrap());
            let mailbox = Mailbox::<deterministic::Context>::new(sender);
            let (cancel_tx, cancel_rx) = oneshot::channel();
            let get =
                mailbox.get_operations(Location::new(10), Location::new(3), NonZeroU64::MIN, false, cancel_rx);
            let observe = async move {
                let response = match receiver.recv().await.unwrap() {
                    Message::GetOperations { response, .. } => response,
                    _ => panic!("expected get operations"),
                };
                drop(cancel_tx);
                assert!(matches!(
                    receiver.recv().await.unwrap(),
                    Message::CancelOperations { .. }
                ));
                drop(response);
            };
            let (result, _) = futures::join!(get, observe);
            assert!(matches!(result, Err(ResponseDropped)));
        });
    }
}
