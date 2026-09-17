//! Config-aware P2P resolver for Nunchi's variable-value QMDB.
//!
//! Commonware's QMDB sync engine supports variable operations, but the 2026.9.0 glue P2P
//! resolver decodes only operations whose codec configuration is exactly `()`. Nunchi values
//! are `Vec<u8>`, so their operation codec requires a length bound. This module keeps the
//! Commonware request/response wire layout and resolver engine while supplying that bound when
//! decoding peer responses.

use bytes::Bytes;
use commonware_actor::mailbox::{
    self as actor_mailbox, Overflow, Policy, Sender as ActorSender,
};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{sha256::Digest, PublicKey};
use commonware_glue::stateful::db::{AttachableResolver, Shared};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{p2p, Delivery, Resolver as _};
use commonware_runtime::{
    spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_storage::{
    mmr,
    qmdb::sync::{FeedbackTx, Request, Response, Source},
    Context as StorageContext,
};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use futures::future;
use nunchi_common::{
    QmdbBackend, QmdbDatabaseSet, QmdbOperation, QmdbOperationCfg,
};
use rand::Rng;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::info;

type SyncRequest = Request<mmr::Family>;
type SyncResponse = Response<mmr::Family, QmdbOperation, Digest>;
type PendingSubscriber = oneshot::Sender<(SyncResponse, FeedbackTx)>;

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

enum EngineMessage {
    Deliver {
        key: SyncRequest,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        key: SyncRequest,
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
    type Key = SyncRequest;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = bool;

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
    type Key = SyncRequest;

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
        request: SyncRequest,
        response: PendingSubscriber,
    },
    CancelOperations {
        request: SyncRequest,
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

struct CancelGuard<E: StorageContext> {
    sender: ActorSender<Message<E>>,
    cancel: Option<Message<E>>,
}

impl<E: StorageContext> CancelGuard<E> {
    const fn new(sender: ActorSender<Message<E>>, cancel: Message<E>) -> Self {
        Self {
            sender,
            cancel: Some(cancel),
        }
    }

    fn disarm(&mut self) {
        self.cancel = None;
    }
}

impl<E: StorageContext> Drop for CancelGuard<E> {
    fn drop(&mut self) {
        let Some(cancel) = self.cancel.take() else {
            return;
        };
        let _ = self.sender.enqueue(cancel);
    }
}

impl<E: StorageContext> Source for Mailbox<E> {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = QmdbOperation;
    type Error = ResponseDropped;

    async fn serve(
        &self,
        request: SyncRequest,
    ) -> Result<(SyncResponse, FeedbackTx), Self::Error> {
        let (response_tx, response_rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetOperations {
            request,
            response: response_tx,
        });
        let mut guard = CancelGuard::new(
            self.sender.clone(),
            Message::CancelOperations { request },
        );
        let result = response_rx.await;
        guard.disarm();
        result.map_err(|_| ResponseDropped)
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
    Fetch(SyncRequest),
    Cancel(SyncRequest),
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
    pending: BTreeMap<SyncRequest, Vec<PendingSubscriber>>,
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
                self.pending.insert(request, vec![response]);
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

    fn should_cancel_request(&mut self, request: &SyncRequest) -> bool {
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
        key: SyncRequest,
        value: Bytes,
        feedback_tx: oneshot::Sender<bool>,
    ) {
        let Some(subscribers) = self.pending.remove(&key) else {
            feedback_tx.send_lossy(true);
            return;
        };
        let decode_cfg = (
            key.max_ops().get() as usize,
            self.config.operation_codec_config,
        );
        let decoded = match SyncResponse::decode_cfg(value, &decode_cfg) {
            Ok(decoded)
                if matches!(
                    (&key, &decoded),
                    (Request::Operations { .. }, Response::Operations { .. })
                        | (Request::Boundary { .. }, Response::Boundary { .. })
                ) =>
            {
                decoded
            }
            Ok(_) | Err(_) => {
                self.pending.insert(key, subscribers);
                feedback_tx.send_lossy(false);
                return;
            }
        };

        let mut approvals = Vec::new();
        for subscriber in subscribers {
            let (success_tx, success_rx) = oneshot::channel();
            if subscriber.send((decoded.clone(), Some(success_tx))).is_ok() {
                approvals.push(success_rx);
            }
        }
        if approvals.is_empty() {
            feedback_tx.send_lossy(true);
            return;
        }
        let mut peer_valid = true;
        for approval in approvals {
            if let Ok(approved) = approval.await {
                peer_valid &= approved;
            }
        }
        feedback_tx.send_lossy(peer_valid);
    }

    async fn handle_produce(&mut self, key: SyncRequest, response: oneshot::Sender<Bytes>) {
        let State::HasDb(database) = &self.state else {
            return;
        };
        if let Request::Operations { max_ops, .. } = key {
            if max_ops > self.config.max_serve_ops {
                return;
            }
        }
        let Ok((payload, _feedback_tx)) = database.serve(key).await else {
            return;
        };
        response.send_lossy(payload.encode());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_actor::Feedback;
    use commonware_codec::{DecodeExt, Error as CodecError, RangeCfg};
    use commonware_cryptography::ed25519;
    use commonware_p2p::{Provider, TrackedPeers};
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use commonware_storage::merkle::Proof;
    use commonware_storage::mmr::Location;
    use commonware_utils::{channel::oneshot, vec::NonEmptyVec, NZUsize};
    use nunchi_common::{
        qmdb_operation_codec_config, shared_database, QmdbBackend, QmdbState,
    };
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::Duration;

    #[derive(Clone, Debug)]
    struct DummyProvider;

    impl Provider for DummyProvider {
        type PublicKey = ed25519::PublicKey;

        async fn peer_set(&mut self, _id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
            None
        }

        async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<Self::PublicKey> {
            let (_tx, rx) = commonware_utils::channel::mpsc::unbounded_channel();
            rx
        }
    }

    #[derive(Clone)]
    struct DummyBlocker;

    impl commonware_p2p::Blocker for DummyBlocker {
        type PublicKey = ed25519::PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> Feedback {
            Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) = commonware_utils::channel::ring::channel(NZUsize!(1));
            receiver
        }
    }

    type TestActor =
        Actor<deterministic::Context, ed25519::PublicKey, DummyProvider, DummyBlocker>;
    type TestPending = PendingSubscriber;
    type TestPendingResult = oneshot::Receiver<(SyncResponse, FeedbackTx)>;

    fn test_config(
        database: Option<QmdbDatabaseSet<deterministic::Context>>,
    ) -> Config<deterministic::Context, ed25519::PublicKey, DummyProvider, DummyBlocker> {
        Config {
            peer_provider: DummyProvider,
            blocker: DummyBlocker,
            database,
            operation_codec_config: qmdb_operation_codec_config(),
            mailbox_size: NZUsize!(16),
            me: None,
            timeout: Duration::from_millis(10),
            fetch_retry_timeout: Duration::from_millis(10),
            max_serve_ops: NonZeroU64::new(16).unwrap(),
            priority_requests: false,
            priority_responses: false,
        }
    }

    fn test_request_at(size: Location) -> SyncRequest {
        Request::Operations {
            size,
            start: Location::new(0),
            max_ops: NonZeroU64::new(1).unwrap(),
        }
    }

    fn test_subscriber() -> (TestPending, TestPendingResult) {
        oneshot::channel()
    }

    async fn init_db(
        context: deterministic::Context,
        partition: &str,
    ) -> QmdbDatabaseSet<deterministic::Context> {
        let cfg = QmdbState::config(&context, partition);
        let db = QmdbBackend::init(context, cfg)
            .await
            .expect("db init should succeed");
        shared_database(db)
    }

    fn empty_proof() -> Proof<mmr::Family, Digest> {
        Proof {
            leaves: Location::new(0),
            inactive_peaks: 0,
            digests: Vec::new(),
        }
    }

    fn response(value: Vec<u8>) -> SyncResponse {
        Response::Operations {
            proof: empty_proof(),
            operations: vec![QmdbOperation::CommitFloor(
                Some(value),
                Location::new(0),
            )],
        }
    }

    fn encoded_fetch_payload() -> Bytes {
        Response::Operations {
            proof: empty_proof(),
            operations: Vec::<QmdbOperation>::new(),
        }
        .encode()
    }

    fn operations_len(response: &SyncResponse) -> usize {
        match response {
            Response::Operations { operations, .. } => operations.len(),
            Response::Boundary { .. } => 1,
        }
    }

    #[test]
    fn response_codec_uses_explicit_value_bound() {
        let encoded = response(vec![9; 32]).encode();
        let cfg = (1, ((), (RangeCfg::from(..=32), ())));
        let decoded = SyncResponse::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(operations_len(&decoded), 1);
    }

    #[test]
    fn response_codec_rejects_oversized_value() {
        let encoded = response(vec![9; 33]).encode();
        let cfg = (1, ((), (RangeCfg::from(..=32), ())));
        assert!(SyncResponse::decode_cfg(encoded, &cfg).is_err());
    }

    #[test]
    fn response_codec_roundtrips_with_pinned_nodes() {
        let response = Response::Boundary {
            proof: Proof {
                leaves: Location::new(10),
                inactive_peaks: 0,
                digests: vec![Digest::from([7; 32])],
            },
            op: QmdbOperation::CommitFloor(None, Location::new(0)),
            pinned_nodes: vec![Digest::from([9; 32])],
        };
        let encoded = response.encode();
        let decoded = SyncResponse::decode_cfg(encoded, &(1, qmdb_operation_codec_config())).unwrap();
        match decoded {
            Response::Boundary {
                op: _,
                pinned_nodes,
                proof,
            } => {
                assert_eq!(pinned_nodes.len(), 1);
                assert_eq!(proof.leaves, Location::new(10));
            }
            Response::Operations { .. } => panic!("expected boundary response"),
        }
    }

    #[test]
    fn request_codec_round_trips() {
        let request = Request::Operations {
            size: Location::new(128),
            start: Location::new(64),
            max_ops: NonZeroU64::new(16).unwrap(),
        };
        let decoded = Request::<mmr::Family>::decode(request.encode()).unwrap();
        assert_eq!(request, decoded);
        assert!(request < test_request_at(Location::new(200)));
        assert!(format!("{request}").contains("max=16"));

        let mut hasher = DefaultHasher::new();
        request.hash(&mut hasher);
        let mut hasher2 = DefaultHasher::new();
        decoded.hash(&mut hasher2);
        assert_eq!(hasher.finish(), hasher2.finish());
    }

    #[test]
    fn request_decode_rejects_invalid_variant() {
        let mut encoded = Request::Operations {
            size: Location::new(128),
            start: Location::new(64),
            max_ops: NonZeroU64::new(16).unwrap(),
        }
        .encode()
        .to_vec();
        encoded[0] = 2;
        assert!(matches!(
            Request::<mmr::Family>::decode(Bytes::from(encoded)),
            Err(CodecError::InvalidEnum(2))
        ));
    }

    #[test]
    fn mailbox_cancellation_is_forwarded() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<deterministic::Context>::new(sender);
            {
                let get = mailbox.serve(test_request_at(Location::new(10)));
                futures::pin_mut!(get);
                assert!(futures::poll!(get.as_mut()).is_pending());
            }
            match receiver.recv().await.expect("request should be queued") {
                Message::GetOperations { .. } => {}
                _ => panic!("expected get operations"),
            }
            match receiver.recv().await.expect("cancel should be queued") {
                Message::CancelOperations { .. } => {}
                _ => panic!("expected cancel operations"),
            }
        });
    }

    #[test]
    fn mailbox_returns_completed_response_before_cancel() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<deterministic::Context>::new(sender);
            let get = mailbox.serve(test_request_at(Location::new(1)));
            let observe = async move {
                let Message::GetOperations { response, .. } =
                    receiver.recv().await.expect("request queued")
                else {
                    panic!("expected get operations");
                };
                response
                    .send((
                        Response::Operations {
                            proof: empty_proof(),
                            operations: Vec::<QmdbOperation>::new(),
                        },
                        None,
                    ))
                    .unwrap();
            };
            let (result, _) = futures::join!(get, observe);
            assert!(result.is_ok());
        });
    }

    #[test]
    fn attach_database_message_is_retained_in_overflow() {
        deterministic::Runner::default().start(|context| async move {
            let db = init_db(context.child("db"), "overflow-attach").await;
            let mut overflow = Pending::<deterministic::Context>::default();
            assert!(overflow.is_empty());

            Policy::handle(
                &mut overflow,
                Message::AttachDatabase(db.clone()),
            );
            assert!(!overflow.is_empty());

            let mut seen = false;
            overflow.drain(|message| {
                seen = matches!(message, Message::AttachDatabase(_));
                None
            });
            assert!(seen);
            assert!(overflow.is_empty());
        });
    }

    #[test]
    fn engine_pending_skips_closed_responses() {
        let mut overflow = EnginePending::default();
        let (tx, rx) = oneshot::channel();
        drop(rx);
        Policy::handle(
            &mut overflow,
            EngineMessage::Produce {
                key: test_request_at(Location::new(1)),
                response: tx,
            },
        );
        assert!(overflow.is_empty());

        let (tx, _rx) = oneshot::channel();
        Policy::handle(
            &mut overflow,
            EngineMessage::Deliver {
                key: test_request_at(Location::new(2)),
                value: Bytes::new(),
                response: tx,
            },
        );
        assert!(!overflow.is_empty());
        overflow.drain(|_| None);
        assert!(overflow.is_empty());
    }

    #[test]
    fn handler_enqueues_deliver_and_produce() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context, NZUsize!(4));
            let mut handler = Handler::new(sender);
            let request = test_request_at(Location::new(3));

            let deliver_rx = commonware_resolver::Consumer::deliver(
                &mut handler,
                Delivery {
                    key: request,
                    subscribers: NonEmptyVec::new(((), tracing::Span::none())),
                },
                Bytes::from_static(b"payload"),
            );
            let EngineMessage::Deliver { key, value, response } =
                receiver.recv().await.expect("deliver queued")
            else {
                panic!("expected deliver");
            };
            assert_eq!(key, request);
            assert_eq!(value.as_ref(), b"payload");
            response.send_lossy(true);
            assert!(deliver_rx.await.unwrap());

            let produce_rx = p2p::Producer::produce(&mut handler, request);
            let EngineMessage::Produce { key, response } =
                receiver.recv().await.expect("produce queued")
            else {
                panic!("expected produce");
            };
            assert_eq!(key, request);
            response.send_lossy(Bytes::from_static(b"ops"));
            assert_eq!(produce_rx.await.unwrap().as_ref(), b"ops");
        });
    }

    #[test]
    fn produce_denied_before_attach() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let (response_tx, response_rx) = oneshot::channel();
            actor
                .handle_produce(test_request_at(Location::new(1)), response_tx)
                .await;
            assert!(response_rx.await.is_err());
        });
    }

    #[test]
    fn same_request_served_after_attach() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context.child("actor"), test_config(None));
            let db = init_db(context.child("resolver_db"), "resolver_after_attach").await;
            let op_count = db.read().await.bounds().end;
            let action = actor.handle_mailbox_message(Message::AttachDatabase(db));
            assert!(matches!(action, MailboxAction::None));

            let (response_tx, response_rx) = oneshot::channel();
            actor
                .handle_produce(test_request_at(op_count), response_tx)
                .await;

            let payload = response_rx
                .await
                .expect("response should be available after attach");
            assert!(!payload.is_empty());
        });
    }

    #[test]
    fn produce_rejects_request_above_max_serve_ops() {
        deterministic::Runner::default().start(|context| async move {
            let db = init_db(context.child("resolver_db"), "resolver-unbounded-max-ops").await;
            let op_count = db.read().await.bounds().end;
            let (mut actor, _mailbox) =
                TestActor::new(context.child("actor"), test_config(Some(db)));

            let request = Request::Operations {
                size: op_count.max(Location::new(1)),
                start: Location::new(0),
                max_ops: NonZeroU64::new(1_000).unwrap(),
            };
            let (response_tx, response_rx) = oneshot::channel();
            actor.handle_produce(request, response_tx).await;
            assert!(response_rx.await.is_err());
        });
    }

    #[test]
    fn deliver_with_dropped_response_receiver_is_treated_as_valid() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (subscriber_tx, subscriber_rx) = test_subscriber();
            drop(subscriber_rx);
            actor.pending.insert(request, vec![subscriber_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            actor
                .handle_deliver(request, encoded_fetch_payload(), ack_tx)
                .await;
            assert!(ack_rx.await.unwrap());
        });
    }

    #[test]
    fn deliver_rejects_invalid_payload_and_keeps_pending() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (subscriber_tx, _subscriber_rx) = test_subscriber();
            actor.pending.insert(request, vec![subscriber_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            actor
                .handle_deliver(request, Bytes::from_static(b"not-a-response"), ack_tx)
                .await;
            assert!(!ack_rx.await.unwrap());
            assert!(actor.pending.contains_key(&request));
        });
    }

    #[test]
    fn deliver_with_rejected_subscriber_blocks_peer() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (sub1_tx, sub1_rx) = test_subscriber();
            let (sub2_tx, sub2_rx) = test_subscriber();
            actor
                .pending
                .insert(request, vec![sub1_tx, sub2_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            futures::join!(
                actor.handle_deliver(request, encoded_fetch_payload(), ack_tx),
                async {
                    let (_response, feedback_tx) = sub1_rx.await.unwrap();
                    feedback_tx
                        .expect("deliveries should include feedback")
                        .send(true)
                        .unwrap();
                },
                async {
                    let (_response, feedback_tx) = sub2_rx.await.unwrap();
                    feedback_tx
                        .expect("deliveries should include feedback")
                        .send(false)
                        .unwrap();
                }
            );

            assert!(!ack_rx.await.unwrap());
        });
    }

    #[test]
    fn deliver_ignores_dropped_subscriber_approval() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (sub1_tx, sub1_rx) = test_subscriber();
            let (sub2_tx, sub2_rx) = test_subscriber();
            actor
                .pending
                .insert(request, vec![sub1_tx, sub2_tx]);

            let (ack_tx, ack_rx) = oneshot::channel();
            futures::join!(
                actor.handle_deliver(request, encoded_fetch_payload(), ack_tx),
                async {
                    let fetch = sub1_rx.await.unwrap();
                    drop(fetch);
                },
                async {
                    let (_response, feedback_tx) = sub2_rx.await.unwrap();
                    feedback_tx
                        .expect("deliveries should include feedback")
                        .send(true)
                        .unwrap();
                }
            );

            assert!(ack_rx.await.unwrap());
        });
    }

    #[test]
    fn deliver_without_pending_subscribers_is_treated_as_valid() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let (ack_tx, ack_rx) = oneshot::channel();
            actor
                .handle_deliver(
                    test_request_at(Location::new(1)),
                    Bytes::from_static(b"late-response"),
                    ack_tx,
                )
                .await;
            assert!(ack_rx.await.unwrap());
        });
    }

    #[test]
    fn get_operations_coalesces_active_subscribers() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (first_tx, _first_rx) = test_subscriber();
            let action = actor.handle_mailbox_message(Message::GetOperations {
                request,
                response: first_tx,
            });
            assert!(matches!(action, MailboxAction::Fetch(ref key) if key == &request));

            let (second_tx, _second_rx) = test_subscriber();
            let action = actor.handle_mailbox_message(Message::GetOperations {
                request,
                response: second_tx,
            });
            assert!(matches!(action, MailboxAction::None));
            assert_eq!(actor.pending.get(&request).unwrap().len(), 2);
        });
    }

    #[test]
    fn get_operations_refetches_when_pending_subscribers_are_closed() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (stale_tx, stale_rx) = test_subscriber();
            drop(stale_rx);
            actor.pending.insert(request, vec![stale_tx]);

            let (fresh_tx, _fresh_rx) = test_subscriber();
            let action = actor.handle_mailbox_message(Message::GetOperations {
                request,
                response: fresh_tx,
            });

            assert!(matches!(action, MailboxAction::Fetch(ref key) if key == &request));
            let pending = actor.pending.get(&request).unwrap();
            assert_eq!(pending.len(), 1);
            assert!(!pending[0].is_closed());
        });
    }

    #[test]
    fn cancel_operations_removes_idle_requests() {
        deterministic::Runner::default().start(|context| async move {
            let (mut actor, _mailbox) = TestActor::new(context, test_config(None));
            let request = test_request_at(Location::new(1));

            let (stale_tx, stale_rx) = test_subscriber();
            drop(stale_rx);
            actor.pending.insert(request, vec![stale_tx]);

            let action = actor.handle_mailbox_message(Message::CancelOperations {
                request,
            });
            assert!(matches!(action, MailboxAction::Cancel(ref key) if key == &request));
            assert!(!actor.pending.contains_key(&request));

            let (live_tx, _live_rx) = test_subscriber();
            actor.pending.insert(request, vec![live_tx]);
            let action = actor.handle_mailbox_message(Message::CancelOperations { request });
            assert!(matches!(action, MailboxAction::None));
        });
    }

    #[test]
    fn attachable_resolver_forwards_database() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mb"), NZUsize!(4));
            let mailbox = Mailbox::<deterministic::Context>::new(sender);
            let db = init_db(context.child("db"), "attachable-resolver").await;
            AttachableResolver::attach_database(&mailbox, db).await;
            assert!(matches!(
                receiver.recv().await.unwrap(),
                Message::AttachDatabase(_)
            ));
        });
    }
}
