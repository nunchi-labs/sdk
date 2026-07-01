//! Persistent storage for DKG protocol state.
//!
//! Stores epoch state using key-value metadata storage and per-epoch messages
//! (dealer broadcasts, player acks, logs) using append-only journals for crash recovery.
//! In-memory BTreeMaps provide fast lookups while storage ensures durability.
//!
use crate::protector::{SealedRecord, StorageProtector, NONCE_SIZE};
use commonware_codec::{Encode, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::Epoch as EpochNum;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{
            Dealer as CryptoDealer, DealerLog, DealerPrivMsg, DealerPubMsg, Info, Logs, Output,
            Player as CryptoPlayer, PlayerAck, SignedDealerLog,
        },
        primitives::{group::Share, sharing::ModeVersion, variant::Variant},
    },
    transcript::{Summary, Transcript},
    BatchVerifier, PublicKey, Signer,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef, Buf, BufMut, BufferPooler, Clock, Metrics, Storage as RuntimeStorage,
};
use commonware_storage::{
    journal::segmented::variable::{Config as SVConfig, Journal as SVJournal},
    metadata::{Config as MetadataConfig, Metadata},
};
use commonware_utils::{Faults, NZUsize, NZU16};
use futures::StreamExt;
use rand_core::CryptoRngCore;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
};
use tracing::{debug, warn};

// Configure 32MB page cache
const PAGE_SIZE: NonZeroU16 = NZU16!(1 << 12);
const PAGE_CACHE_CAPACITY: NonZeroUsize = NZUsize!(1 << 13);

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1 << 12);
const READ_BUFFER: NonZeroUsize = NZUsize!(1 << 20);

const RECORD_AD_DOMAIN: &[u8] = b"nunchi-dkg-storage";
const RECORD_KIND_EPOCH: u8 = 0;
const RECORD_KIND_EVENT: u8 = 1;

/// Epoch-level DKG state persisted across restarts.
#[derive(Clone)]
pub struct Epoch<V: Variant, P: PublicKey> {
    pub round: u64,
    pub rng_seed: Summary,
    pub output: Option<Output<V, P>>,
    pub share: Option<Share>,
}

impl<V: Variant, P: PublicKey> EncodeSize for Epoch<V, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.rng_seed.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for Epoch<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.rng_seed.write(buf);
        self.output.write(buf);
        self.share.write(buf);
    }
}

impl<V, P> Read for Epoch<V, P>
where
    V: Variant,
    P: PublicKey,
{
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            round: ReadExt::read(buf)?,
            rng_seed: ReadExt::read(buf)?,
            output: Read::read_cfg(buf, cfg)?,
            share: ReadExt::read(buf)?,
        })
    }
}

/// An event we want to record to replay later, if we crash.
enum Event<V: Variant, P: PublicKey> {
    /// A dealer message we received and committed to ack (as a player).
    /// Once persisted, we will always generate the same ack for this dealer.
    Dealing(P, DealerPubMsg<V>, DealerPrivMsg),
    /// A player ack we received (as a dealer).
    Ack(P, PlayerAck<P>),
    /// A finalized dealer log.
    Log(P, DealerLog<V, P>),
}

impl<V: Variant, P: PublicKey> EncodeSize for Event<V, P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealing(x0, x1, x2) => x0.encode_size() + x1.encode_size() + x2.encode_size(),
            Self::Ack(x0, x1) => x0.encode_size() + x1.encode_size(),
            Self::Log(x0, x1) => x0.encode_size() + x1.encode_size(),
        }
    }
}

impl<V: Variant, P: PublicKey> Write for Event<V, P> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Dealing(x0, x1, x2) => {
                0u8.write(buf);
                x0.write(buf);
                x1.write(buf);
                x2.write(buf);
            }
            Self::Ack(x0, x1) => {
                1u8.write(buf);
                x0.write(buf);
                x1.write(buf);
            }
            Self::Log(x0, x1) => {
                2u8.write(buf);
                x0.write(buf);
                x1.write(buf);
            }
        }
    }
}

impl<V: Variant, P: PublicKey> Read for Event<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Dealing(
                ReadExt::read(buf)?,
                Read::read_cfg(buf, cfg)?,
                ReadExt::read(buf)?,
            )),
            1 => Ok(Self::Ack(ReadExt::read(buf)?, ReadExt::read(buf)?)),
            2 => Ok(Self::Log(ReadExt::read(buf)?, Read::read_cfg(buf, cfg)?)),
            other => Err(commonware_codec::Error::InvalidEnum(other)),
        }
    }
}

/// In-memory cache for a single epoch's DKG messages.
struct EpochCache<V: Variant, P: PublicKey> {
    dealings: BTreeMap<P, (DealerPubMsg<V>, DealerPrivMsg)>,
    acks: BTreeMap<P, PlayerAck<P>>,
    logs: BTreeMap<P, DealerLog<V, P>>,
}

impl<V: Variant, P: PublicKey> Default for EpochCache<V, P> {
    fn default() -> Self {
        Self {
            dealings: BTreeMap::new(),
            acks: BTreeMap::new(),
            logs: BTreeMap::new(),
        }
    }
}

/// DKG persistent storage.
///
/// Wraps metadata storage for epoch state and journaled storage for protocol messages,
/// with in-memory BTreeMaps for fast lookups. Using metadata with epoch keys eliminates
/// the position/epoch confusion that can occur with position-based journals.
pub struct Storage<E, V, P>
where
    E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRngCore,
    V: Variant,
    P: PublicKey,
{
    context: E,
    protector: StorageProtector,
    partition_prefix: String,
    namespace: Vec<u8>,
    public_key: P,

    states: Metadata<E, u64, SealedRecord>,
    msgs: SVJournal<E, SealedRecord>,

    // In-memory state
    current: Option<(EpochNum, Epoch<V, P>)>,
    epochs: BTreeMap<EpochNum, EpochCache<V, P>>,
}

impl<E, V, P> Storage<E, V, P>
where
    E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRngCore,
    V: Variant,
    P: PublicKey,
{
    /// Initialize storage, creating partitions if needed.
    /// Replays metadata and journals to populate in-memory caches.
    pub async fn init(
        context: E,
        partition_prefix: &str,
        protector: StorageProtector,
        namespace: Vec<u8>,
        public_key: P,
        max_read_size: NonZeroU32,
        max_supported_mode: ModeVersion,
    ) -> Self {
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_CAPACITY);

        let states: Metadata<E, u64, SealedRecord> = Metadata::init(
            context.child("states"),
            MetadataConfig {
                partition: format!("{partition_prefix}_states"),
                codec_config: RangeCfg::from(..),
            },
        )
        .await
        .expect("should be able to init dkg_states metadata");

        let msgs = SVJournal::init(
            context.child("msgs"),
            SVConfig {
                partition: format!("{partition_prefix}_msgs"),
                compression: None,
                codec_config: RangeCfg::from(..),
                page_cache,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("should be able to init dkg_msgs journal");

        // Find the current epoch by looking for the highest key in metadata
        let partition_prefix = partition_prefix.to_owned();
        let current = states.keys().max().map(|&epoch_num| {
            let record = states.get(&epoch_num).expect("key must exist");
            let state = Self::open_epoch_record(
                &protector,
                &partition_prefix,
                &namespace,
                &public_key,
                (max_read_size, max_supported_mode),
                EpochNum::new(epoch_num),
                record,
            )
            .expect("should be able to open dkg epoch state");
            (EpochNum::new(epoch_num), state)
        });

        // Replay msgs to populate epoch caches
        let mut epochs = BTreeMap::<EpochNum, EpochCache<V, P>>::new();
        {
            let replay = msgs
                .replay(0, 0, READ_BUFFER)
                .await
                .expect("should be able to replay msgs");
            futures::pin_mut!(replay);

            while let Some(result) = replay.next().await {
                let (section, _, _, record) = result.expect("should be able to read msg");
                let epoch = EpochNum::new(section);
                let event = Self::open_event_record(
                    &protector,
                    &partition_prefix,
                    &namespace,
                    &public_key,
                    max_read_size,
                    epoch,
                    &record,
                )
                .expect("should be able to open dkg msg");
                let cache = epochs.entry(epoch).or_default();
                match event {
                    Event::Dealing(dealer, pub_msg, priv_msg) => {
                        cache.dealings.insert(dealer, (pub_msg, priv_msg));
                    }
                    Event::Ack(player, ack) => {
                        cache.acks.insert(player, ack);
                    }
                    Event::Log(dealer, log) => {
                        cache.logs.insert(dealer, log);
                    }
                }
            }
        }

        Self {
            context,
            protector,
            partition_prefix,
            namespace,
            public_key,
            states,
            msgs,
            current,
            epochs,
        }
    }

    fn associated_data(
        partition_prefix: &str,
        namespace: &[u8],
        public_key: &P,
        kind: u8,
        epoch: EpochNum,
    ) -> Vec<u8> {
        fn append_bytes(out: &mut Vec<u8>, value: &[u8]) {
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value);
        }

        let public_key = public_key.encode();
        let mut ad = Vec::with_capacity(
            RECORD_AD_DOMAIN.len() + 1 + 8 + partition_prefix.len() + namespace.len() + public_key.len(),
        );
        append_bytes(&mut ad, RECORD_AD_DOMAIN);
        ad.push(kind);
        append_bytes(&mut ad, partition_prefix.as_bytes());
        append_bytes(&mut ad, namespace);
        append_bytes(&mut ad, &public_key);
        ad.extend_from_slice(&epoch.get().to_be_bytes());
        ad
    }

    fn open_epoch_record(
        protector: &StorageProtector,
        partition_prefix: &str,
        namespace: &[u8],
        public_key: &P,
        cfg: (NonZeroU32, ModeVersion),
        epoch: EpochNum,
        record: &SealedRecord,
    ) -> Result<Epoch<V, P>, String> {
        let ad = Self::associated_data(
            partition_prefix,
            namespace,
            public_key,
            RECORD_KIND_EPOCH,
            epoch,
        );
        let plaintext = protector
            .open(record, &ad)
            .map_err(|err| format!("open failed: {err}"))?;
        let mut buf = plaintext.as_ref();
        let state = Epoch::read_cfg(&mut buf, &cfg)
            .map_err(|err| format!("decode failed: {err}"))?;
        if buf.has_remaining() {
            return Err("decode failed: trailing bytes".to_string());
        }
        Ok(state)
    }

    fn open_event_record(
        protector: &StorageProtector,
        partition_prefix: &str,
        namespace: &[u8],
        public_key: &P,
        max_read_size: NonZeroU32,
        epoch: EpochNum,
        record: &SealedRecord,
    ) -> Result<Event<V, P>, String> {
        let ad = Self::associated_data(
            partition_prefix,
            namespace,
            public_key,
            RECORD_KIND_EVENT,
            epoch,
        );
        let plaintext = protector
            .open(record, &ad)
            .map_err(|err| format!("open failed: {err}"))?;
        let mut buf = plaintext.as_ref();
        let event = Event::read_cfg(&mut buf, &max_read_size)
            .map_err(|err| format!("decode failed: {err}"))?;
        if buf.has_remaining() {
            return Err("decode failed: trailing bytes".to_string());
        }
        Ok(event)
    }

    fn seal_record(&mut self, kind: u8, epoch: EpochNum, plaintext: &[u8]) -> SealedRecord {
        let mut nonce = [0u8; NONCE_SIZE];
        self.context.fill_bytes(&mut nonce);
        let ad = Self::associated_data(
            &self.partition_prefix,
            &self.namespace,
            &self.public_key,
            kind,
            epoch,
        );
        self.protector
            .seal(plaintext, &ad, nonce)
            .expect("should be able to seal dkg record")
    }

    /// Returns all dealer messages received during the given epoch.
    pub fn dealings(&self, epoch: EpochNum) -> Vec<(P, DealerPubMsg<V>, DealerPrivMsg)> {
        self.epochs
            .get(&epoch)
            .map(|cache| {
                cache
                    .dealings
                    .iter()
                    .map(|(k, (v1, v2))| (k.clone(), v1.clone(), v2.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all player acknowledgments received during the given epoch.
    pub fn acks(&self, epoch: EpochNum) -> Vec<(P, PlayerAck<P>)> {
        self.epochs
            .get(&epoch)
            .map(|cache| {
                cache
                    .acks
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all finalized dealer logs for the given epoch.
    pub fn logs(&self, epoch: EpochNum) -> BTreeMap<P, DealerLog<V, P>> {
        self.epochs
            .get(&epoch)
            .map(|cache| cache.logs.clone())
            .unwrap_or_default()
    }

    /// Checks if a dealer has already submitted a log this epoch.
    pub fn has_log(&self, epoch: EpochNum, dealer: &P) -> bool {
        self.epochs
            .get(&epoch)
            .map(|cache| cache.logs.contains_key(dealer))
            .unwrap_or(false)
    }

    /// Returns the current epoch state, if initialized.
    pub fn epoch(&self) -> Option<(EpochNum, Epoch<V, P>)> {
        self.current.as_ref().map(|(e, s)| (*e, s.clone()))
    }

    fn get_or_create_epoch(&mut self, epoch: EpochNum) -> &mut EpochCache<V, P> {
        self.epochs.entry(epoch).or_default()
    }

    /// Checks if a key exists in an epoch's cache using the provided accessor.
    fn has_cached<K: Ord, T>(
        &self,
        epoch: EpochNum,
        get_map: impl Fn(&EpochCache<V, P>) -> &BTreeMap<K, T>,
        key: &K,
    ) -> bool {
        self.epochs
            .get(&epoch)
            .is_some_and(|cache| get_map(cache).contains_key(key))
    }

    /// Persists a dealer message for crash recovery.
    /// Returns false if the dealing was already stored.
    pub async fn append_dealing(
        &mut self,
        epoch: EpochNum,
        dealer: P,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) -> bool {
        // Check if already stored
        if self.has_cached(epoch, |c| &c.dealings, &dealer) {
            return false;
        }

        // Persist to journal
        let section = epoch.get();
        let event = Event::Dealing(dealer.clone(), pub_msg.clone(), priv_msg.clone());
        let record = self.seal_record(RECORD_KIND_EVENT, epoch, &event.encode());
        self.msgs
            .append(section, &record)
            .await
            .expect("should be able to write to msgs");
        self.msgs
            .sync(section)
            .await
            .expect("should be able to sync msgs");

        // Update in-memory cache
        self.get_or_create_epoch(epoch)
            .dealings
            .insert(dealer, (pub_msg, priv_msg));
        true
    }

    /// Persists a player acknowledgment we received (as a dealer) for crash recovery.
    /// Returns false if the ack was already stored.
    pub async fn append_ack(&mut self, epoch: EpochNum, player: P, ack: PlayerAck<P>) -> bool {
        // Check if already stored
        if self.has_cached(epoch, |c| &c.acks, &player) {
            return false;
        }

        // Persist to journal
        let section = epoch.get();
        let event: Event<V, P> = Event::Ack(player.clone(), ack.clone());
        let record = self.seal_record(RECORD_KIND_EVENT, epoch, &event.encode());
        self.msgs
            .append(section, &record)
            .await
            .expect("should be able to write to msgs");
        self.msgs
            .sync(section)
            .await
            .expect("should be able to sync msgs");

        // Update in-memory cache
        self.get_or_create_epoch(epoch).acks.insert(player, ack);
        true
    }

    /// Persists a finalized dealer log.
    /// Returns false if the log was already stored.
    pub async fn append_log(&mut self, epoch: EpochNum, dealer: P, log: DealerLog<V, P>) -> bool {
        // Check if already stored
        if self.has_cached(epoch, |c| &c.logs, &dealer) {
            return false;
        }

        // Persist to journal
        let section = epoch.get();
        let event = Event::Log(dealer.clone(), log.clone());
        let record = self.seal_record(RECORD_KIND_EVENT, epoch, &event.encode());
        self.msgs
            .append(section, &record)
            .await
            .expect("should be able to write to msgs");
        self.msgs
            .sync(section)
            .await
            .expect("should be able to sync msgs");

        // Update in-memory cache
        self.get_or_create_epoch(epoch).logs.insert(dealer, log);
        true
    }

    /// Persists epoch state.
    pub async fn set_epoch(&mut self, epoch: EpochNum, state: Epoch<V, P>) {
        // Persist to metadata using epoch number as key
        let epoch_key = epoch.get();
        let record = self.seal_record(RECORD_KIND_EPOCH, epoch, &state.encode());
        if self.states.put(epoch_key, record).is_some() {
            warn!(%epoch, "overwriting existing epoch state");
        }
        self.states
            .sync()
            .await
            .expect("should be able to sync state");

        // Update in-memory state
        self.current = Some((epoch, state));
    }

    /// Removes all data from epochs older than `min`.
    pub async fn prune(&mut self, min: EpochNum) {
        let min_epoch = min.get();

        // Prune msgs journal
        self.msgs
            .prune(min_epoch)
            .await
            .expect("should be able to prune msgs");

        // Prune states metadata - remove all epochs < min
        self.states.retain(|&epoch_key, _| epoch_key >= min_epoch);
        self.states
            .sync()
            .await
            .expect("should be able to sync states after prune");

        // Remove old epoch caches
        self.epochs.retain(|&epoch, _| epoch >= min);
    }

    /// Create a Dealer for the given epoch, replaying any stored acks.
    /// Returns None if we've already submitted a log this epoch.
    pub fn create_dealer<C: Signer<PublicKey = P>, M: Faults>(
        &self,
        epoch: EpochNum,
        signer: C,
        round_info: Info<V, P>,
        share: Option<Share>,
        rng_seed: Summary,
    ) -> Option<Dealer<V, C>> {
        // If we've already observed our log in a finalized block, there is nothing more to do!
        if self.has_log(epoch, &signer.public_key()) {
            return None;
        }

        // Start a new dealer
        let (mut crypto_dealer, pub_msg, priv_msgs) = CryptoDealer::start::<M>(
            Transcript::resume(rng_seed).noise(b"dealer-rng"),
            round_info,
            signer,
            share,
        )
        .expect("should be able to create dealer");

        // Replay stored acks
        let mut unsent: BTreeMap<P, DealerPrivMsg> = priv_msgs.into_iter().collect();
        for (player, ack) in self.acks(epoch) {
            if unsent.contains_key(&player)
                && crypto_dealer
                    .receive_player_ack(player.clone(), ack)
                    .is_ok()
            {
                unsent.remove(&player);
                debug!(?epoch, ?player, "replayed player ack");
            }
        }

        Some(Dealer::new(Some(crypto_dealer), pub_msg, unsent))
    }

    /// Create a Player for the given epoch by resuming from persisted state.
    pub fn create_player<C: Signer<PublicKey = P>, M: Faults>(
        &self,
        epoch: EpochNum,
        signer: C,
        round_info: Info<V, P>,
    ) -> Option<Player<V, C>> {
        let logs = self.logs(epoch);
        let dealings = self.dealings(epoch);
        let (crypto_player, acks) = CryptoPlayer::resume::<M>(round_info, signer, &logs, dealings)
            .expect("should be able to resume player");
        for dealer in acks.keys() {
            debug!(?epoch, ?dealer, "restored committed dealer message");
        }

        Some(Player {
            player: crypto_player,
            acks,
        })
    }
}

/// Internal state for a dealer in the current round.
pub struct Dealer<V: Variant, C: Signer> {
    dealer: Option<CryptoDealer<V, C>>,
    pub_msg: DealerPubMsg<V>,
    unsent: BTreeMap<C::PublicKey, DealerPrivMsg>,
    finalized: Option<SignedDealerLog<V, C>>,
}

impl<V: Variant, C: Signer> Dealer<V, C> {
    pub const fn new(
        dealer: Option<CryptoDealer<V, C>>,
        pub_msg: DealerPubMsg<V>,
        unsent: BTreeMap<C::PublicKey, DealerPrivMsg>,
    ) -> Self {
        Self {
            dealer,
            pub_msg,
            unsent,
            finalized: None,
        }
    }

    /// Handle an incoming ack from a player.
    ///
    /// If the ack is valid and new, persists it to storage.
    /// Returns true if the ack was successfully processed.
    pub async fn handle<E>(
        &mut self,
        storage: &mut Storage<E, V, C::PublicKey>,
        epoch: EpochNum,
        player: C::PublicKey,
        ack: PlayerAck<C::PublicKey>,
    ) -> bool
    where
        E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRngCore,
    {
        if !self.unsent.contains_key(&player) {
            return false;
        }
        if let Some(ref mut dealer) = self.dealer {
            if dealer
                .receive_player_ack(player.clone(), ack.clone())
                .is_ok()
            {
                self.unsent.remove(&player);
                storage.append_ack(epoch, player, ack).await;
                return true;
            }
        }
        false
    }

    /// Finalize the dealer and produce a signed log for inclusion in a block.
    pub fn finalize<M: Faults>(&mut self) {
        if self.finalized.is_some() {
            return;
        }

        // Even after the finalized_log is taken, we won't attempt to finalize again
        // because the dealer will be None.
        if let Some(dealer) = self.dealer.take() {
            let log = dealer.finalize::<M>();
            self.finalized = Some(log);
        }
    }

    /// Returns a clone of the finalized log if it exists.
    pub fn finalized(&self) -> Option<SignedDealerLog<V, C>> {
        self.finalized.clone()
    }

    /// Takes and returns the finalized log, leaving None in its place.
    pub const fn take_finalized(&mut self) -> Option<SignedDealerLog<V, C>> {
        self.finalized.take()
    }

    /// Returns shares to distribute to players.
    ///
    /// Returns an iterator of (player, pub_msg, priv_msg) tuples for each player
    /// that hasn't yet acknowledged their share.
    pub fn shares_to_distribute(
        &self,
    ) -> impl Iterator<Item = (C::PublicKey, DealerPubMsg<V>, DealerPrivMsg)> + '_ {
        self.unsent
            .iter()
            .map(|(player, priv_msg)| (player.clone(), self.pub_msg.clone(), priv_msg.clone()))
    }
}

/// Internal state for a player in the current round.
pub struct Player<V: Variant, C: Signer> {
    player: CryptoPlayer<V, C>,
    /// Acks we've generated, keyed by dealer. Once we generate an ack for a dealer,
    /// we will not generate a different one (to avoid conflicting votes).
    acks: BTreeMap<C::PublicKey, PlayerAck<C::PublicKey>>,
}

impl<V: Variant, C: Signer> Player<V, C> {
    /// Handle an incoming dealer message.
    ///
    /// If this is a new valid dealer message, persists it to storage before returning.
    pub async fn handle<E, M>(
        &mut self,
        storage: &mut Storage<E, V, C::PublicKey>,
        epoch: EpochNum,
        dealer: C::PublicKey,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) -> Option<PlayerAck<C::PublicKey>>
    where
        E: BufferPooler + Clock + RuntimeStorage + Metrics + CryptoRngCore,
        M: Faults,
    {
        // If we've already generated an ack, return the cached version
        if let Some(ack) = self.acks.get(&dealer) {
            return Some(ack.clone());
        }

        // Otherwise generate a new ack
        if let Some(ack) =
            self.player
                .dealer_message::<M>(dealer.clone(), pub_msg.clone(), priv_msg.clone())
        {
            storage
                .append_dealing(epoch, dealer.clone(), pub_msg, priv_msg)
                .await;
            self.acks.insert(dealer, ack.clone());
            return Some(ack);
        }
        None
    }

    /// Finalize the player's participation in the DKG round.
    pub fn finalize<M: Faults, B: BatchVerifier<PublicKey = C::PublicKey>>(
        self,
        rng: &mut impl CryptoRngCore,
        logs: Logs<V, C::PublicKey, M>,
        strategy: &impl Strategy,
    ) -> Result<
        (Output<V, C::PublicKey>, Share),
        commonware_cryptography::bls12381::dkg::feldman_desmedt::Error,
    > {
        self.player.finalize::<M, B>(rng, logs, strategy)
    }
}
