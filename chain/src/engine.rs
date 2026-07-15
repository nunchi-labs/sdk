//! Reusable engine tuning and support types.

use commonware_actor::Feedback;
use commonware_consensus::{
    marshal::ancestry::Ancestry, Automaton, CertifiableAutomaton, Relay, Reporter, types::ViewDelta,
};
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{AttachableResolver, SyncEngineConfig};
use commonware_macros::select;
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
    Clock, Metrics, Spawner,
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::AsyncRwLock,
    NZU16, NZU64, NZUsize,
};
use futures::channel::oneshot as futures_oneshot;
use nunchi_common::{QmdbBackend, QmdbOperation};
use rand::Rng;
use std::{
    collections::VecDeque,
    future::Future,
    num::{NonZero, NonZeroU16, NonZeroUsize},
    sync::{Arc, Mutex},
};

pub const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
pub const DEQUE_SIZE: usize = 10;
pub const ACTIVITY_TIMEOUT: ViewDelta = ViewDelta::new(256);
pub const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
pub const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
pub const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
pub const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
pub const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
pub const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
pub const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);
pub const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024); // 8MB
pub const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024); // 1MB
pub const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(4_096); // 4KB
pub const PAGE_CACHE_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
pub const MAX_REPAIR: NonZero<usize> = NZUsize!(50);
pub const MAX_PENDING_ACKS: NonZero<usize> = NZUsize!(16);
pub const STATE_SYNC_FETCH_BATCH_SIZE: NonZero<u64> = NZU64!(1_024);
pub const STATE_SYNC_APPLY_BATCH_SIZE: usize = 4_096;
pub const STATE_SYNC_MAX_OUTSTANDING_REQUESTS: usize = 8;
pub const STATE_SYNC_UPDATE_CHANNEL_SIZE: NonZero<usize> = NZUsize!(256);
pub const STATE_SYNC_MAX_RETAINED_ROOTS: usize = 32;
pub const APPLICATION_VERIFY_CONCURRENCY: NonZeroUsize = NZUsize!(16);
pub const CONSENSUS_VERIFY_CONCURRENCY: NonZeroUsize = NZUsize!(16);
pub const CONSENSUS_VERIFY_WAITING: usize = 64;

#[derive(Clone)]
pub struct VerifyLimiter<A> {
    application: A,
    limiter: Arc<Limiter>,
    metrics: VerifyLimiterMetrics,
}

#[derive(Clone)]
struct VerifyLimiterMetrics {
    in_flight: Gauge,
    waiting: Gauge,
    spawn_total: Counter,
    complete_total: Counter,
}

struct Limiter {
    state: Mutex<LimiterState>,
}

struct LimiterState {
    available: usize,
    in_flight: usize,
    waiting: usize,
    waiters: VecDeque<futures_oneshot::Sender<()>>,
}

struct Permit {
    limiter: Arc<Limiter>,
    metrics: VerifyLimiterMetrics,
}

impl<A> VerifyLimiter<A> {
    pub fn new<E>(context: &E, application: A, max_in_flight: NonZeroUsize) -> Self
    where
        E: Metrics,
    {
        Self {
            application,
            limiter: Arc::new(Limiter {
                state: Mutex::new(LimiterState {
                    available: max_in_flight.get(),
                    in_flight: 0,
                    waiting: 0,
                    waiters: VecDeque::new(),
                }),
            }),
            metrics: VerifyLimiterMetrics {
                in_flight: context.gauge(
                    "application_verify_in_flight",
                    "application verification tasks currently holding execution capacity",
                ),
                waiting: context.gauge(
                    "application_verify_waiting",
                    "application verification tasks waiting for execution capacity",
                ),
                spawn_total: context.counter(
                    "application_verify_spawn_total",
                    "application verification tasks admitted by consensus",
                ),
                complete_total: context.counter(
                    "application_verify_complete_total",
                    "application verification tasks completed",
                ),
            },
        }
    }
}

impl Limiter {
    async fn acquire(self: &Arc<Self>, metrics: &VerifyLimiterMetrics) -> Permit {
        loop {
            let receiver = {
                let mut state = self.state.lock().expect("verify limiter mutex poisoned");
                if state.available > 0 {
                    state.available -= 1;
                    state.in_flight += 1;
                    metrics.in_flight.try_set(state.in_flight).ok();
                    metrics.spawn_total.inc();
                    return Permit {
                        limiter: self.clone(),
                        metrics: metrics.clone(),
                    };
                }

                let (sender, receiver) = futures_oneshot::channel();
                state.waiting += 1;
                state.waiters.push_back(sender);
                metrics.waiting.try_set(state.waiting).ok();
                receiver
            };

            if receiver.await.is_ok() {
                metrics.spawn_total.inc();
                return Permit {
                    limiter: self.clone(),
                    metrics: metrics.clone(),
                };
            }
        }
    }

    fn release(&self, metrics: &VerifyLimiterMetrics) {
        let mut state = self.state.lock().expect("verify limiter mutex poisoned");
        state.in_flight = state.in_flight.saturating_sub(1);
        metrics.in_flight.try_set(state.in_flight).ok();
        metrics.complete_total.inc();

        while let Some(sender) = state.waiters.pop_front() {
            state.waiting = state.waiting.saturating_sub(1);
            metrics.waiting.try_set(state.waiting).ok();
            if sender.send(()).is_ok() {
                state.in_flight += 1;
                metrics.in_flight.try_set(state.in_flight).ok();
                return;
            }
        }

        state.available += 1;
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.limiter.release(&self.metrics);
    }
}

impl<E, A> commonware_consensus::Application<E> for VerifyLimiter<A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: commonware_consensus::Application<E>,
    A::Context: Send,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;

    fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> impl Future<Output = Option<Self::Block>> + Send {
        self.application.propose(context, ancestry)
    }

    fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> impl Future<Output = bool> + Send {
        let mut application = self.application.clone();
        let limiter = self.limiter.clone();
        let metrics = self.metrics.clone();
        async move {
            let _permit = limiter.acquire(&metrics).await;
            application.verify(context, ancestry).await
        }
    }
}

pub struct VerificationScheduler<E, A> {
    automaton: A,
    scheduler: Arc<Scheduler>,
    metrics: SchedulerMetrics,
    context: Arc<AsyncRwLock<E>>,
}

impl<E, A> Clone for VerificationScheduler<E, A>
where
    A: Clone,
{
    fn clone(&self) -> Self {
        Self {
            automaton: self.automaton.clone(),
            scheduler: self.scheduler.clone(),
            metrics: self.metrics.clone(),
            context: self.context.clone(),
        }
    }
}

#[derive(Clone)]
struct SchedulerMetrics {
    in_flight: Gauge,
    waiting: Gauge,
    admitted_total: Counter,
    completed_total: Counter,
    verify_overflow_total: Counter,
    certify_overflow_total: Counter,
    canceled_waiters_total: Counter,
}

struct Scheduler {
    max_waiting: usize,
    state: Mutex<SchedulerState>,
}

struct SchedulerState {
    available: usize,
    in_flight: usize,
    waiting: usize,
    waiters: VecDeque<futures_oneshot::Sender<()>>,
}

enum Admission {
    Permit(SchedulerPermit),
    Overflow,
}

struct SchedulerPermit {
    scheduler: Arc<Scheduler>,
    metrics: SchedulerMetrics,
}

impl<E, A> VerificationScheduler<E, A> {
    pub fn new(
        context: E,
        automaton: A,
        max_in_flight: NonZeroUsize,
        max_waiting: usize,
    ) -> Self
    where
        E: Metrics,
    {
        Self {
            automaton,
            scheduler: Arc::new(Scheduler {
                max_waiting,
                state: Mutex::new(SchedulerState {
                    available: max_in_flight.get(),
                    in_flight: 0,
                    waiting: 0,
                    waiters: VecDeque::new(),
                }),
            }),
            metrics: SchedulerMetrics {
                in_flight: context.gauge(
                    "consensus_verify_in_flight",
                    "consensus verification tasks currently admitted before deferred verification",
                ),
                waiting: context.gauge(
                    "consensus_verify_waiting",
                    "consensus verification requests waiting before deferred verification",
                ),
                admitted_total: context.counter(
                    "consensus_verify_admitted_total",
                    "consensus verification requests admitted before deferred verification",
                ),
                completed_total: context.counter(
                    "consensus_verify_completed_total",
                    "consensus verification requests completed after admission",
                ),
                verify_overflow_total: context.counter(
                    "consensus_verify_verify_overflow_total",
                    "verify requests left pending because the consensus verification scheduler was full",
                ),
                certify_overflow_total: context.counter(
                    "consensus_verify_certify_overflow_total",
                    "certify requests left pending because the consensus verification scheduler was full",
                ),
                canceled_waiters_total: context.counter(
                    "consensus_verify_canceled_waiters_total",
                    "consensus verification waiters canceled before admission",
                ),
            },
            context: Arc::new(AsyncRwLock::new(context)),
        }
    }
}

impl Scheduler {
    async fn acquire(self: &Arc<Self>, metrics: &SchedulerMetrics) -> Admission {
        loop {
            let receiver = {
                let mut state = self.state.lock().expect("verification scheduler mutex poisoned");
                if state.available > 0 {
                    state.available -= 1;
                    state.in_flight += 1;
                    metrics.in_flight.try_set(state.in_flight).ok();
                    metrics.admitted_total.inc();
                    return Admission::Permit(SchedulerPermit {
                        scheduler: self.clone(),
                        metrics: metrics.clone(),
                    });
                }

                if state.waiting >= self.max_waiting {
                    return Admission::Overflow;
                }

                let (sender, receiver) = futures_oneshot::channel();
                state.waiting += 1;
                state.waiters.push_back(sender);
                metrics.waiting.try_set(state.waiting).ok();
                receiver
            };

            if receiver.await.is_ok() {
                metrics.admitted_total.inc();
                return Admission::Permit(SchedulerPermit {
                    scheduler: self.clone(),
                    metrics: metrics.clone(),
                });
            }
        }
    }

    fn release(&self, metrics: &SchedulerMetrics) {
        let mut state = self.state.lock().expect("verification scheduler mutex poisoned");
        state.in_flight = state.in_flight.saturating_sub(1);
        metrics.in_flight.try_set(state.in_flight).ok();
        metrics.completed_total.inc();

        while let Some(sender) = state.waiters.pop_front() {
            state.waiting = state.waiting.saturating_sub(1);
            metrics.waiting.try_set(state.waiting).ok();
            if sender.send(()).is_ok() {
                state.in_flight += 1;
                metrics.in_flight.try_set(state.in_flight).ok();
                return;
            }
            metrics.canceled_waiters_total.inc();
        }

        state.available += 1;
    }
}

impl Drop for SchedulerPermit {
    fn drop(&mut self) {
        self.scheduler.release(&self.metrics);
    }
}

impl<E, A> VerificationScheduler<E, A>
where
    E: Spawner,
{
    async fn pending_receiver(
        context: Arc<AsyncRwLock<E>>,
        name: &'static str,
    ) -> oneshot::Receiver<bool> {
        let (mut sender, receiver) = oneshot::channel();
        let runtime_context = context.write().await.child(name);
        runtime_context.spawn(move |_| async move {
            sender.closed().await;
        });
        receiver
    }
}

impl<E, A> Automaton for VerificationScheduler<E, A>
where
    E: Spawner + Metrics + Send + Sync + 'static,
    A: Automaton,
    A::Context: Send,
{
    type Context = A::Context;
    type Digest = A::Digest;

    fn propose(
        &mut self,
        context: Self::Context,
    ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send {
        self.automaton.propose(context)
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let admission = self.scheduler.acquire(&self.metrics).await;
        let Admission::Permit(permit) = admission else {
            self.metrics.verify_overflow_total.inc();
            return Self::pending_receiver(self.context.clone(), "verify_overflow").await;
        };

        let mut automaton = self.automaton.clone();
        let (mut sender, receiver) = oneshot::channel();
        let runtime_context = self.context.write().await.child("verify");
        runtime_context.spawn(move |_| async move {
            let inner = select! {
                _ = sender.closed() => {
                    return;
                },
                inner = automaton.verify(context, payload) => inner,
            };
            let result = select! {
                _ = sender.closed() => {
                    return;
                },
                result = inner => result,
            };
            if let Ok(valid) = result {
                sender.send_lossy(valid);
            }
            drop(permit);
        });
        receiver
    }
}

impl<E, A> CertifiableAutomaton for VerificationScheduler<E, A>
where
    E: Spawner + Metrics + Send + Sync + 'static,
    A: CertifiableAutomaton,
    A::Context: Send,
{
    async fn certify(
        &mut self,
        round: commonware_consensus::types::Round,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let admission = self.scheduler.acquire(&self.metrics).await;
        let Admission::Permit(permit) = admission else {
            self.metrics.certify_overflow_total.inc();
            return Self::pending_receiver(self.context.clone(), "certify_overflow").await;
        };

        let mut automaton = self.automaton.clone();
        let (mut sender, receiver) = oneshot::channel();
        let runtime_context = self.context.write().await.child("certify");
        runtime_context.spawn(move |_| async move {
            let inner = select! {
                _ = sender.closed() => {
                    return;
                },
                inner = automaton.certify(round, payload) => inner,
            };
            let result = select! {
                _ = sender.closed() => {
                    return;
                },
                result = inner => result,
            };
            if let Ok(valid) = result {
                sender.send_lossy(valid);
            }
            drop(permit);
        });
        receiver
    }
}

impl<E, A> Relay for VerificationScheduler<E, A>
where
    E: Send + Sync + 'static,
    A: Relay,
{
    type Digest = A::Digest;
    type PublicKey = A::PublicKey;
    type Plan = A::Plan;

    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback {
        self.automaton.broadcast(payload, plan)
    }
}

impl<E, A> Reporter for VerificationScheduler<E, A>
where
    E: Send + Sync + 'static,
    A: Reporter,
{
    type Activity = A::Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.automaton.report(activity)
    }
}

pub fn state_sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: STATE_SYNC_FETCH_BATCH_SIZE,
        apply_batch_size: STATE_SYNC_APPLY_BATCH_SIZE,
        max_outstanding_requests: STATE_SYNC_MAX_OUTSTANDING_REQUESTS,
        update_channel_size: STATE_SYNC_UPDATE_CHANNEL_SIZE,
        max_retained_roots: STATE_SYNC_MAX_RETAINED_ROOTS,
    }
}

/// Placeholder for a peer state-sync resolver.
///
/// `commonware_glue::stateful::db::p2p::standard::Actor` would slot in here, but as of
/// commonware 2026.5.0 it requires `Op: Codec<Cfg = ()>`, which only fixed-encoding QMDB
/// operations satisfy; the shared state database is variable-value (`Vec<u8>`), whose
/// operation codec config is `((), (RangeCfg, ()))`. Until upstream threads the codec config
/// through its resolver (or a chain moves to fixed-size values), peer state sync stays disabled:
/// no startup path attaches a state-sync floor, so nodes recover via marshal backfill and this
/// resolver is never asked to fetch.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoStateSyncResolver;

#[derive(Debug, thiserror::Error)]
#[error("peer state sync resolver is not configured")]
pub struct NoStateSyncError;

impl<E> AttachableResolver<QmdbBackend<E>> for NoStateSyncResolver
where
    E: commonware_storage::Context + Send + Sync + 'static,
{
    fn attach_database(
        &self,
        _db: Arc<AsyncRwLock<QmdbBackend<E>>>,
    ) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }
}

impl commonware_storage::qmdb::sync::resolver::Resolver for NoStateSyncResolver {
    type Family = commonware_storage::mmr::Family;
    type Digest = Digest;
    type Op = QmdbOperation;
    type Error = NoStateSyncError;

    fn get_operations<'a>(
        &'a self,
        _op_count: commonware_storage::mmr::Location,
        _start_loc: commonware_storage::mmr::Location,
        _max_ops: NonZero<u64>,
        _include_pinned_nodes: bool,
        _cancel_rx: oneshot::Receiver<()>,
    ) -> impl Future<
        Output = Result<
            commonware_storage::qmdb::sync::resolver::FetchResult<
                Self::Family,
                Self::Op,
                Self::Digest,
            >,
            Self::Error,
        >,
    > + Send
           + 'a {
        std::future::ready(Err(NoStateSyncError))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::telemetry::metrics::{raw, Registered, Registration};
    use futures::{pin_mut, task::noop_waker};
    use std::task::{Context, Poll};

    fn metrics() -> VerifyLimiterMetrics {
        VerifyLimiterMetrics {
            in_flight: Registered::with_registration(raw::Gauge::default(), Registration::from(())),
            waiting: Registered::with_registration(raw::Gauge::default(), Registration::from(())),
            spawn_total: Registered::with_registration(
                raw::Counter::default(),
                Registration::from(()),
            ),
            complete_total: Registered::with_registration(
                raw::Counter::default(),
                Registration::from(()),
            ),
        }
    }

    fn scheduler_metrics() -> SchedulerMetrics {
        SchedulerMetrics {
            in_flight: Registered::with_registration(raw::Gauge::default(), Registration::from(())),
            waiting: Registered::with_registration(raw::Gauge::default(), Registration::from(())),
            admitted_total: Registered::with_registration(
                raw::Counter::default(),
                Registration::from(()),
            ),
            completed_total: Registered::with_registration(
                raw::Counter::default(),
                Registration::from(()),
            ),
            verify_overflow_total: Registered::with_registration(
                raw::Counter::default(),
                Registration::from(()),
            ),
            certify_overflow_total: Registered::with_registration(
                raw::Counter::default(),
                Registration::from(()),
            ),
            canceled_waiters_total: Registered::with_registration(
                raw::Counter::default(),
                Registration::from(()),
            ),
        }
    }

    fn scheduler(max_in_flight: usize, max_waiting: usize) -> Arc<Scheduler> {
        Arc::new(Scheduler {
            max_waiting,
            state: Mutex::new(SchedulerState {
                available: max_in_flight,
                in_flight: 0,
                waiting: 0,
                waiters: VecDeque::new(),
            }),
        })
    }

    #[test]
    fn verify_limiter_holds_second_acquire_until_release() {
        let limiter = Arc::new(Limiter {
            state: Mutex::new(LimiterState {
                available: 1,
                in_flight: 0,
                waiting: 0,
                waiters: VecDeque::new(),
            }),
        });
        let metrics = metrics();

        let first = futures::executor::block_on(limiter.acquire(&metrics));
        let second = limiter.acquire(&metrics);
        pin_mut!(second);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(matches!(second.as_mut().poll(&mut context), Poll::Pending));

        drop(first);
        assert!(matches!(second.as_mut().poll(&mut context), Poll::Ready(_)));
    }

    #[test]
    fn scheduler_holds_second_acquire_until_release() {
        let scheduler = scheduler(1, 1);
        let metrics = scheduler_metrics();

        let first = match futures::executor::block_on(scheduler.acquire(&metrics)) {
            Admission::Permit(permit) => permit,
            Admission::Overflow => panic!("first acquire should be admitted"),
        };
        let second = scheduler.acquire(&metrics);
        pin_mut!(second);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(matches!(second.as_mut().poll(&mut context), Poll::Pending));

        drop(first);
        assert!(matches!(
            second.as_mut().poll(&mut context),
            Poll::Ready(Admission::Permit(_))
        ));
    }

    #[test]
    fn scheduler_rejects_waiter_when_queue_full() {
        let scheduler = scheduler(1, 1);
        let metrics = scheduler_metrics();

        let _first = match futures::executor::block_on(scheduler.acquire(&metrics)) {
            Admission::Permit(permit) => permit,
            Admission::Overflow => panic!("first acquire should be admitted"),
        };
        let second = scheduler.acquire(&metrics);
        pin_mut!(second);

        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(matches!(second.as_mut().poll(&mut context), Poll::Pending));
        assert!(matches!(
            futures::executor::block_on(scheduler.acquire(&metrics)),
            Admission::Overflow
        ));
    }

    #[test]
    fn scheduler_releases_canceled_waiter() {
        let scheduler = scheduler(1, 1);
        let metrics = scheduler_metrics();

        let first = match futures::executor::block_on(scheduler.acquire(&metrics)) {
            Admission::Permit(permit) => permit,
            Admission::Overflow => panic!("first acquire should be admitted"),
        };
        {
            let second = scheduler.acquire(&metrics);
            pin_mut!(second);

            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            assert!(matches!(second.as_mut().poll(&mut context), Poll::Pending));
        }
        drop(first);

        let state = scheduler
            .state
            .lock()
            .expect("verification scheduler mutex poisoned");
        assert_eq!(state.waiting, 0);
        assert_eq!(state.in_flight, 0);
        assert_eq!(state.available, 1);
    }
}
