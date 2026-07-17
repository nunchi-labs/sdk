//! Reusable engine tuning and support types.

use commonware_actor::Feedback;
use commonware_consensus::{
    marshal::ancestry::Ancestry, Automaton, CertifiableAutomaton, Relay, Reporter, types::ViewDelta,
};
use commonware_glue::stateful::{db::SyncEngineConfig, PruneConfig};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
    Clock, Metrics, Spawner,
};
use commonware_utils::{channel::oneshot, NZU16, NZU64, NZUsize};
use futures::channel::oneshot as futures_oneshot;
use rand::Rng;
use std::{
    collections::VecDeque,
    future::Future,
    num::{NonZero, NonZeroU16, NonZeroUsize},
    sync::{Arc, Mutex},
    time::Duration,
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
pub const STATE_SYNC_RESOLVER_INITIAL: Duration = Duration::from_secs(1);
pub const STATE_SYNC_RESOLVER_TIMEOUT: Duration = Duration::from_secs(2);
pub const STATE_SYNC_RESOLVER_RETRY: Duration = Duration::from_millis(100);
/// Prune cadence in finalized heights (retention floors are independent of this).
pub const PRUNE_MAINTENANCE_INTERVAL: NonZero<usize> = NZUsize!(32);
/// Finalized blocks retained in marshal beyond `max_pending_acks + 1` (~1 epoch buffer).
pub const PRUNE_RETAINED_MARSHAL_BLOCKS: usize = 200;
/// Extra QMDB history beyond the ack window for serving lagging state-sync peers.
pub const PRUNE_RETAINED_QMDB_BLOCKS: usize = 200;

/// Heap-boxes an automaton so large consensus application state does not inflate task futures.
pub struct BoxedAutomaton<A> {
    automaton: Box<A>,
}

impl<A> BoxedAutomaton<A> {
    /// Creates a boxed automaton wrapper.
    pub fn new(automaton: A) -> Self {
        Self {
            automaton: Box::new(automaton),
        }
    }
}

impl<A> Clone for BoxedAutomaton<A>
where
    A: Clone,
{
    fn clone(&self) -> Self {
        Self {
            automaton: Box::new((*self.automaton).clone()),
        }
    }
}

impl<A> Automaton for BoxedAutomaton<A>
where
    A: Automaton,
{
    type Context = A::Context;
    type Digest = A::Digest;

    fn propose(
        &mut self,
        context: Self::Context,
    ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send {
        self.automaton.propose(context)
    }

    fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
        self.automaton.verify(context, payload)
    }
}

impl<A> CertifiableAutomaton for BoxedAutomaton<A>
where
    A: CertifiableAutomaton,
{
    fn certify(
        &mut self,
        round: commonware_consensus::types::Round,
        payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
        self.automaton.certify(round, payload)
    }
}

impl<A> Relay for BoxedAutomaton<A>
where
    A: Relay,
{
    type Digest = A::Digest;
    type PublicKey = A::PublicKey;
    type Plan = A::Plan;

    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback {
        self.automaton.broadcast(payload, plan)
    }
}

impl<A> Reporter for BoxedAutomaton<A>
where
    A: Reporter,
{
    type Activity = A::Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.automaton.report(activity)
    }
}

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

pub fn state_sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: STATE_SYNC_FETCH_BATCH_SIZE,
        apply_batch_size: STATE_SYNC_APPLY_BATCH_SIZE,
        max_outstanding_requests: STATE_SYNC_MAX_OUTSTANDING_REQUESTS,
        update_channel_size: STATE_SYNC_UPDATE_CHANNEL_SIZE,
        max_retained_roots: STATE_SYNC_MAX_RETAINED_ROOTS,
    }
}

/// Periodic marshal + QMDB pruning; `max_pending_acks` must match marshal's config.
pub fn state_prune_config() -> PruneConfig {
    PruneConfig {
        max_pending_acks: MAX_PENDING_ACKS,
        maintenance_interval: PRUNE_MAINTENANCE_INTERVAL,
        retained_marshal_blocks: PRUNE_RETAINED_MARSHAL_BLOCKS,
        retained_qmdb_blocks: PRUNE_RETAINED_QMDB_BLOCKS,
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
}
