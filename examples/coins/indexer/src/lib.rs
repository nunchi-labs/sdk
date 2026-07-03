//! In-memory indexer for coins-chain consensus artifacts.
//!
//! The API mirrors Alto's binary indexer shape so validators can upload
//! encoded consensus artifacts and browsers or tooling can fetch the same
//! encoded bytes for local verification.

use axum::{
    body::Bytes,
    extract::{ws::WebSocketUpgrade, Path, State as AxumState},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize, FixedSize, Write};
use commonware_consensus::{
    types::{Epoch, EpochInfo, Epocher, FixedEpocher, View},
    Viewable,
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{observe, Info, Logs, Output},
        primitives::{
            sharing::{Mode, ModeVersion},
            variant::MinSig,
        },
    },
    ed25519::Batch,
    sha256::Digest,
    Digestible,
};
use commonware_formatting::{from_hex, hex};
use commonware_parallel::Sequential;
use commonware_utils::union;
use commonware_utils::N3f1;
use futures::{SinkExt, StreamExt};
use nunchi_coins_chain::{
    Block, Finalized, Identity, Notarized, PublicKey, Scheme, Seed, BLOCKS_PER_EPOCH,
    MAX_SUPPORTED_MODE, NAMESPACE,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    num::NonZeroU32,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast::{self, error::RecvError};
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
};
use tracing::warn;

pub const LATEST: &str = "latest";
const DKG_OUTPUT_STATE_FILE: &str = "dkg-output.latest";

type BlockCfg = (NonZeroU32, ());
type DkgOutputCfg = (NonZeroU32, ModeVersion);
pub type DkgOutput = Output<MinSig, PublicKey>;
type DkgLogs = Logs<MinSig, PublicKey, N3f1>;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct ArtifactKey {
    epoch: Epoch,
    view: View,
}

#[repr(u8)]
pub enum Kind {
    Seed = 0,
    Notarization = 1,
    Finalization = 2,
}

pub struct Store {
    seeds: BTreeMap<View, Seed>,
    notarizations: BTreeMap<ArtifactKey, Notarized>,
    finalizations: BTreeMap<ArtifactKey, Finalized>,
    seed_uploads: BTreeSet<View>,
    notarization_uploads: BTreeSet<ArtifactKey>,
    finalization_uploads: BTreeSet<ArtifactKey>,
    finalized_height_to_key: BTreeMap<u64, ArtifactKey>,
    blocks_by_digest: BTreeMap<Digest, Block>,
    verifier: VerifierState,
}

impl Store {
    fn new(
        initial_epoch: Epoch,
        initial_scheme: Scheme,
        initial_output: Option<DkgOutput>,
    ) -> Self {
        Self {
            seeds: BTreeMap::new(),
            notarizations: BTreeMap::new(),
            finalizations: BTreeMap::new(),
            seed_uploads: BTreeSet::new(),
            notarization_uploads: BTreeSet::new(),
            finalization_uploads: BTreeSet::new(),
            finalized_height_to_key: BTreeMap::new(),
            blocks_by_digest: BTreeMap::new(),
            verifier: VerifierState::new(initial_epoch, initial_scheme, initial_output),
        }
    }
}

struct VerifierState {
    schemes: BTreeMap<Epoch, Scheme>,
    latest_epoch: Epoch,
    output: Option<DkgOutput>,
    logs: BTreeMap<Epoch, DkgLogs>,
    pending_boundaries: BTreeSet<Epoch>,
}

impl VerifierState {
    fn new(initial_epoch: Epoch, initial_scheme: Scheme, output: Option<DkgOutput>) -> Self {
        Self {
            schemes: BTreeMap::from([(initial_epoch, initial_scheme)]),
            latest_epoch: initial_epoch,
            output,
            logs: BTreeMap::new(),
            pending_boundaries: BTreeSet::new(),
        }
    }

    fn latest_scheme(&self) -> Option<Scheme> {
        self.schemes.get(&self.latest_epoch).cloned()
    }

    fn scheme(&self, epoch: Epoch) -> Option<Scheme> {
        self.schemes.get(&epoch).cloned().or_else(|| {
            (self.output.is_none())
                .then(|| self.latest_scheme())
                .flatten()
        })
    }

    fn observe_block(&mut self, namespace: &[u8], block: &Block) {
        let Some(bounds) = block_epoch_info(block) else {
            return;
        };
        let epoch = bounds.epoch();
        if self.schemes.contains_key(&epoch.next()) {
            return;
        }

        let Some(info) = self.round_info(namespace, epoch) else {
            return;
        };

        if let Some(signed) = block.reshare_log.clone() {
            if let Some((dealer, log)) = signed.check(&info) {
                self.logs
                    .entry(epoch)
                    .or_insert_with(|| DkgLogs::new(info.clone()))
                    .record(dealer, log);
            }
        }

        if block.height >= bounds.last() {
            self.pending_boundaries.insert(epoch);
        }

        if self.pending_boundaries.contains(&epoch) {
            self.try_observe_epoch(namespace, epoch, info);
        }
    }

    fn round_info(&self, namespace: &[u8], epoch: Epoch) -> Option<Info<MinSig, PublicKey>> {
        let output = self.output.clone()?;
        let dealers = output.players().clone();
        let players = output.players().clone();
        Info::new::<N3f1>(
            namespace,
            epoch.get(),
            Some(output),
            Mode::NonZeroCounter,
            dealers,
            players,
        )
        .ok()
    }

    fn try_observe_epoch(&mut self, namespace: &[u8], epoch: Epoch, info: Info<MinSig, PublicKey>) {
        let logs = self
            .logs
            .remove(&epoch)
            .unwrap_or_else(|| DkgLogs::new(info));
        let Ok(next_output) =
            observe::<_, _, N3f1, Batch>(&mut rand::rngs::OsRng, logs.clone(), &Sequential)
        else {
            self.logs.insert(epoch, logs);
            warn!(%epoch, "could not derive next indexer verifier yet");
            return;
        };
        let next_epoch = epoch.next();
        let scheme = Scheme::certificate_verifier(namespace, *next_output.public().public());
        self.output = Some(next_output);
        self.schemes.insert(next_epoch, scheme);
        self.latest_epoch = next_epoch;
        self.pending_boundaries.remove(&epoch);
    }

    fn install_output(&mut self, namespace: &[u8], epoch: Epoch, output: DkgOutput) {
        let scheme = Scheme::certificate_verifier(namespace, *output.public().public());
        self.schemes.insert(epoch, scheme);
        if epoch >= self.latest_epoch {
            self.output = Some(output);
            self.latest_epoch = epoch;
            self.logs.retain(|logged_epoch, _| *logged_epoch >= epoch);
            self.pending_boundaries.retain(|pending| *pending >= epoch);
        }
    }
}

#[derive(Clone)]
pub struct Indexer {
    namespace: Vec<u8>,
    participants: NonZeroU32,
    dkg_output_state_dir: Option<PathBuf>,
    store: Arc<RwLock<Store>>,
    consensus_tx: broadcast::Sender<Vec<u8>>,
    summary_tx: broadcast::Sender<SummaryEvent>,
}

impl Indexer {
    pub fn new(identity: Identity, participants: NonZeroU32) -> Self {
        let namespace = union(NAMESPACE, b"_CONSENSUS");
        let scheme = Scheme::certificate_verifier(&namespace, identity);
        Self::from_scheme(namespace, participants, Epoch::zero(), scheme, None)
    }

    pub fn new_from_output(output: DkgOutput, participants: NonZeroU32) -> Self {
        Self::new_from_output_at(Epoch::zero(), output, participants)
    }

    pub fn new_from_output_at(epoch: Epoch, output: DkgOutput, participants: NonZeroU32) -> Self {
        let namespace = union(NAMESPACE, b"_CONSENSUS");
        let scheme = Scheme::certificate_verifier(&namespace, *output.public().public());
        Self::from_scheme(namespace, participants, epoch, scheme, Some(output))
    }

    fn from_scheme(
        namespace: Vec<u8>,
        participants: NonZeroU32,
        initial_epoch: Epoch,
        scheme: Scheme,
        output: Option<DkgOutput>,
    ) -> Self {
        let (consensus_tx, _) = broadcast::channel(1024);
        let (summary_tx, _) = broadcast::channel(1024);
        Self {
            namespace,
            participants,
            dkg_output_state_dir: None,
            store: Arc::new(RwLock::new(Store::new(initial_epoch, scheme, output))),
            consensus_tx,
            summary_tx,
        }
    }

    pub fn with_dkg_output_state_dir(mut self, path: PathBuf) -> Self {
        self.dkg_output_state_dir = Some(path);
        self
    }

    fn block_cfg(&self) -> BlockCfg {
        (self.participants, ())
    }

    fn dkg_output_cfg(&self) -> DkgOutputCfg {
        (self.participants, MAX_SUPPORTED_MODE)
    }

    pub fn submit_dkg_output(&self, epoch: Epoch, output: DkgOutput) {
        {
            let mut store = self.store.write().unwrap();
            store
                .verifier
                .install_output(&self.namespace, epoch, output.clone());
        }
        if let Some(path) = &self.dkg_output_state_dir {
            if let Err(error) = persist_dkg_output(path, epoch, &output) {
                warn!(%epoch, %error, "failed to persist DKG output");
            }
        }
    }

    pub fn submit_seed(&self, seed: Seed) -> Result<(), &'static str> {
        let view = seed.view();
        let scheme = {
            let mut store = self.store.write().unwrap();
            if store.seeds.contains_key(&view) || !store.seed_uploads.insert(view) {
                return Ok(());
            }
            store.verifier.latest_scheme()
        };
        let Some(scheme) = scheme else {
            self.store.write().unwrap().seed_uploads.remove(&view);
            return Err("missing verifier");
        };
        if !seed.verify(&scheme) {
            self.store.write().unwrap().seed_uploads.remove(&view);
            return Err("invalid seed signature");
        }

        let mut store = self.store.write().unwrap();
        store.seed_uploads.remove(&view);
        if store.seeds.insert(view, seed.clone()).is_some() {
            return Ok(());
        }

        let mut data = vec![0u8; u8::SIZE + seed.encode_size()];
        data[0] = Kind::Seed as u8;
        seed.write(&mut data[1..].as_mut());
        let _ = self.consensus_tx.send(data);
        let _ = self.summary_tx.send(SummaryEvent {
            kind: "seed",
            view: Some(view.get()),
            height: None,
            digest: None,
            transaction_count: None,
            block_timestamp: None,
            observed_at: now_ms(),
        });
        Ok(())
    }

    pub fn get_seed(&self, query: &str) -> Option<Seed> {
        let store = self.store.read().unwrap();
        if query == LATEST {
            store.seeds.last_key_value().map(|(_, seed)| seed.clone())
        } else {
            let view = parse_index(query)?;
            store.seeds.get(&View::new(view)).cloned()
        }
    }

    pub fn submit_notarization(&self, notarized: Notarized) -> Result<(), &'static str> {
        let view = notarized.proof.view();
        let Some(epoch) = block_epoch(&notarized.block) else {
            return Err("unsupported block height");
        };
        let key = ArtifactKey { epoch, view };
        let scheme = {
            let mut store = self.store.write().unwrap();
            if store.notarizations.contains_key(&key) || !store.notarization_uploads.insert(key) {
                return Ok(());
            }
            store.verifier.scheme(epoch)
        };
        let Some(scheme) = scheme else {
            self.store
                .write()
                .unwrap()
                .notarization_uploads
                .remove(&key);
            return Err("missing verifier");
        };
        if !notarized.verify(&scheme, &Sequential) {
            self.store
                .write()
                .unwrap()
                .notarization_uploads
                .remove(&key);
            return Err("invalid notarization signature");
        }

        let mut store = self.store.write().unwrap();
        store.notarization_uploads.remove(&key);
        store
            .blocks_by_digest
            .insert(notarized.block.digest(), notarized.block.clone());

        if store.notarizations.insert(key, notarized.clone()).is_some() {
            return Ok(());
        }

        let mut data = vec![0u8; u8::SIZE + notarized.encode_size()];
        data[0] = Kind::Notarization as u8;
        notarized.write(&mut data[1..].as_mut());
        let _ = self.consensus_tx.send(data);
        let _ = self
            .summary_tx
            .send(SummaryEvent::from_notarized("notarization", &notarized));
        Ok(())
    }

    pub fn get_notarization(&self, query: &str) -> Option<Notarized> {
        let store = self.store.read().unwrap();
        if query == LATEST {
            store
                .notarizations
                .last_key_value()
                .map(|(_, notarized)| notarized.clone())
        } else {
            let view = parse_index(query)?;
            store
                .notarizations
                .iter()
                .rev()
                .find(|(key, _)| key.view == View::new(view))
                .map(|(_, notarized)| notarized.clone())
        }
    }

    pub fn submit_finalization(&self, finalized: Finalized) -> Result<(), &'static str> {
        let view = finalized.proof.view();
        let Some(epoch) = block_epoch(&finalized.block) else {
            return Err("unsupported block height");
        };
        let key = ArtifactKey { epoch, view };
        let scheme = {
            let mut store = self.store.write().unwrap();
            if store.finalizations.contains_key(&key) || !store.finalization_uploads.insert(key) {
                return Ok(());
            }
            store.verifier.scheme(epoch)
        };
        let Some(scheme) = scheme else {
            self.store
                .write()
                .unwrap()
                .finalization_uploads
                .remove(&key);
            return Err("missing verifier");
        };
        if !finalized.verify(&scheme, &Sequential) {
            self.store
                .write()
                .unwrap()
                .finalization_uploads
                .remove(&key);
            return Err("invalid finalization signature");
        }

        let mut store = self.store.write().unwrap();
        store.finalization_uploads.remove(&key);
        store
            .blocks_by_digest
            .insert(finalized.block.digest(), finalized.block.clone());

        if store.finalizations.insert(key, finalized.clone()).is_some() {
            return Ok(());
        }
        store
            .finalized_height_to_key
            .insert(finalized.block.height.get(), key);
        store
            .verifier
            .observe_block(&self.namespace, &finalized.block);

        let mut data = vec![0u8; u8::SIZE + finalized.encode_size()];
        data[0] = Kind::Finalization as u8;
        finalized.write(&mut data[1..].as_mut());
        let _ = self.consensus_tx.send(data);
        let _ = self
            .summary_tx
            .send(SummaryEvent::from_finalized("finalization", &finalized));
        Ok(())
    }

    pub fn get_finalization(&self, query: &str) -> Option<Finalized> {
        let store = self.store.read().unwrap();
        if query == LATEST {
            store
                .finalizations
                .last_key_value()
                .map(|(_, finalized)| finalized.clone())
        } else {
            let view = parse_index(query)?;
            store
                .finalizations
                .iter()
                .rev()
                .find(|(key, _)| key.view == View::new(view))
                .map(|(_, finalized)| finalized.clone())
        }
    }

    pub fn submit_block(&self, block: Block) {
        let mut store = self.store.write().unwrap();
        store.verifier.observe_block(&self.namespace, &block);
        store.blocks_by_digest.insert(block.digest(), block);
    }

    pub fn get_block(&self, query: &str) -> Option<BlockResult> {
        let store = self.store.read().unwrap();
        if query == LATEST {
            return store
                .finalizations
                .last_key_value()
                .map(|(_, finalized)| BlockResult::Finalized(finalized.clone()));
        }

        let raw = from_hex(query)?;
        if raw.len() == u64::SIZE {
            let height = u64::decode(raw.as_slice()).ok()?;
            store.finalized_height_to_key.get(&height).and_then(|key| {
                store
                    .finalizations
                    .get(key)
                    .map(|finalized| BlockResult::Finalized(finalized.clone()))
            })
        } else if raw.len() == Digest::SIZE {
            let digest = Digest::decode(raw.as_slice()).ok()?;
            store
                .blocks_by_digest
                .get(&digest)
                .map(|block| BlockResult::Block(block.clone()))
        } else {
            None
        }
    }

    pub fn consensus_subscriber(&self) -> broadcast::Receiver<Vec<u8>> {
        self.consensus_tx.subscribe()
    }

    pub fn summary_subscriber(&self) -> broadcast::Receiver<SummaryEvent> {
        self.summary_tx.subscribe()
    }

    pub fn latest_summary(&self) -> Option<SummaryEvent> {
        let store = self.store.read().unwrap();
        store
            .finalizations
            .last_key_value()
            .map(|(_, finalized)| SummaryEvent::from_finalized("finalization", finalized))
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryEvent {
    kind: &'static str,
    view: Option<u64>,
    height: Option<u64>,
    digest: Option<String>,
    transaction_count: Option<usize>,
    block_timestamp: Option<u64>,
    observed_at: u64,
}

impl SummaryEvent {
    fn from_notarized(kind: &'static str, notarized: &Notarized) -> Self {
        Self {
            kind,
            view: Some(notarized.proof.view().get()),
            height: Some(notarized.block.height.get()),
            digest: Some(hex(notarized.block.digest().as_ref())),
            transaction_count: Some(notarized.block.transactions.len()),
            block_timestamp: Some(notarized.block.timestamp),
            observed_at: now_ms(),
        }
    }

    fn from_finalized(kind: &'static str, finalized: &Finalized) -> Self {
        Self {
            kind,
            view: Some(finalized.proof.view().get()),
            height: Some(finalized.block.height.get()),
            digest: Some(hex(finalized.block.digest().as_ref())),
            transaction_count: Some(finalized.block.transactions.len()),
            block_timestamp: Some(finalized.block.timestamp),
            observed_at: now_ms(),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum BlockResult {
    Block(Block),
    Finalized(Finalized),
}

pub struct Api {
    indexer: Arc<Indexer>,
}

impl Api {
    pub fn new(indexer: Arc<Indexer>) -> Self {
        Self { indexer }
    }

    pub fn router(self) -> Router {
        self.api_router()
    }

    pub fn router_with_frontend(self, frontend_dir: Option<PathBuf>) -> Router {
        let router = self.api_router();
        let Some(frontend_dir) = frontend_dir else {
            return router;
        };
        let index = frontend_dir.join("index.html");
        router.fallback_service(ServeDir::new(frontend_dir).fallback(ServeFile::new(index)))
    }

    fn api_router(self) -> Router {
        Router::new()
            .route("/health", get(health_check))
            .route("/seed", post(seed_upload))
            .route("/seed/{query}", get(seed_get))
            .route("/notarization", post(notarization_upload))
            .route("/notarization/{query}", get(notarization_get))
            .route("/finalization", post(finalization_upload))
            .route("/finalization/{query}", get(finalization_get))
            .route("/block", post(block_upload))
            .route("/block/{query}", get(block_get))
            .route("/dkg-output/{epoch}", post(dkg_output_upload))
            .route("/consensus/ws", get(consensus_ws))
            .route("/consensus/summary/latest", get(consensus_summary_latest))
            .route("/consensus/summary/ws", get(consensus_summary_ws))
            .layer(CorsLayer::permissive())
            .with_state(self.indexer)
    }
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn seed_upload(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    body: Bytes,
) -> impl IntoResponse {
    match Seed::decode(body.as_ref()) {
        Ok(seed) => match indexer.submit_seed(seed) {
            Ok(()) => StatusCode::OK,
            Err(_) => StatusCode::UNAUTHORIZED,
        },
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

async fn seed_get(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    Path(query): Path<String>,
) -> impl IntoResponse {
    match indexer.get_seed(&query) {
        Some(seed) => (StatusCode::OK, seed.encode().to_vec()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn notarization_upload(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    body: Bytes,
) -> impl IntoResponse {
    match Notarized::decode_cfg(body.as_ref(), &indexer.block_cfg()) {
        Ok(notarized) => match indexer.submit_notarization(notarized) {
            Ok(()) => StatusCode::OK,
            Err(_) => StatusCode::UNAUTHORIZED,
        },
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

async fn notarization_get(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    Path(query): Path<String>,
) -> impl IntoResponse {
    match indexer.get_notarization(&query) {
        Some(notarized) => (StatusCode::OK, notarized.encode().to_vec()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn finalization_upload(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    body: Bytes,
) -> impl IntoResponse {
    match Finalized::decode_cfg(body.as_ref(), &indexer.block_cfg()) {
        Ok(finalized) => match indexer.submit_finalization(finalized) {
            Ok(()) => StatusCode::OK,
            Err(_) => StatusCode::UNAUTHORIZED,
        },
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

async fn finalization_get(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    Path(query): Path<String>,
) -> impl IntoResponse {
    match indexer.get_finalization(&query) {
        Some(finalized) => (StatusCode::OK, finalized.encode().to_vec()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn block_upload(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    body: Bytes,
) -> impl IntoResponse {
    match Block::decode_cfg(body.as_ref(), &indexer.block_cfg()) {
        Ok(block) => {
            indexer.submit_block(block);
            StatusCode::OK
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

async fn block_get(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    Path(query): Path<String>,
) -> impl IntoResponse {
    match indexer.get_block(&query) {
        Some(BlockResult::Block(block)) => {
            (StatusCode::OK, block.encode().to_vec()).into_response()
        }
        Some(BlockResult::Finalized(finalized)) => {
            (StatusCode::OK, finalized.encode().to_vec()).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn dkg_output_upload(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    Path(epoch): Path<u64>,
    body: Bytes,
) -> impl IntoResponse {
    match DkgOutput::decode_cfg(body.as_ref(), &indexer.dkg_output_cfg()) {
        Ok(output) => {
            indexer.submit_dkg_output(Epoch::new(epoch), output);
            StatusCode::OK
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

async fn consensus_ws(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_consensus_ws(socket, indexer))
}

async fn consensus_summary_ws(
    AxumState(indexer): AxumState<Arc<Indexer>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_consensus_summary_ws(socket, indexer))
}

async fn consensus_summary_latest(
    AxumState(indexer): AxumState<Arc<Indexer>>,
) -> impl IntoResponse {
    match indexer.latest_summary() {
        Some(event) => Json(event).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn handle_consensus_ws(socket: axum::extract::ws::WebSocket, indexer: Arc<Indexer>) {
    let (mut sender, _receiver) = socket.split();
    let mut consensus = indexer.consensus_subscriber();

    loop {
        match consensus.recv().await {
            Ok(data) => {
                if sender
                    .send(axum::extract::ws::Message::Binary(data.into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => break,
        }
    }
}

async fn handle_consensus_summary_ws(socket: axum::extract::ws::WebSocket, indexer: Arc<Indexer>) {
    let (mut sender, _receiver) = socket.split();
    let mut consensus = indexer.summary_subscriber();

    loop {
        match consensus.recv().await {
            Ok(event) => {
                let Ok(data) = serde_json::to_string(&event) else {
                    continue;
                };
                if sender
                    .send(axum::extract::ws::Message::Text(data.into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => break,
        }
    }
}

fn parse_index(query: &str) -> Option<u64> {
    let raw = from_hex(query)?;
    if raw.len() != u64::SIZE {
        return None;
    }
    u64::decode(raw.as_slice()).ok()
}

fn block_epoch(block: &Block) -> Option<Epoch> {
    block_epoch_info(block).map(|info| info.epoch())
}

fn block_epoch_info(block: &Block) -> Option<EpochInfo> {
    FixedEpocher::new(BLOCKS_PER_EPOCH).containing(block.height)
}

pub fn load_dkg_output(
    path: &FsPath,
    participants: NonZeroU32,
) -> Result<Option<(Epoch, DkgOutput)>, Box<dyn std::error::Error>> {
    let path = path.join(DKG_OUTPUT_STATE_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if bytes.len() < u64::SIZE {
        return Err("invalid DKG output state".into());
    }
    let mut epoch = [0u8; u64::SIZE];
    epoch.copy_from_slice(&bytes[..u64::SIZE]);
    let output = DkgOutput::decode_cfg(&bytes[u64::SIZE..], &(participants, MAX_SUPPORTED_MODE))
        .map_err(|_| "invalid DKG output state")?;
    Ok(Some((Epoch::new(u64::from_be_bytes(epoch)), output)))
}

fn persist_dkg_output(path: &FsPath, epoch: Epoch, output: &DkgOutput) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let file = path.join(DKG_OUTPUT_STATE_FILE);
    let tmp = path.join(format!("{DKG_OUTPUT_STATE_FILE}.tmp"));
    let mut bytes = epoch.get().to_be_bytes().to_vec();
    bytes.extend_from_slice(output.encode().as_ref());
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, file)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
