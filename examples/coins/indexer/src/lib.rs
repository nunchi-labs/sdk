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
use commonware_consensus::{types::View, Viewable};
use commonware_cryptography::{sha256::Digest, Digestible};
use commonware_formatting::{from_hex, hex};
use commonware_parallel::Sequential;
use commonware_utils::union;
use futures::{SinkExt, StreamExt};
use nunchi_coins_chain::{Block, Finalized, Identity, Notarized, Scheme, Seed, NAMESPACE};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast::{self, error::RecvError};
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
};

pub const LATEST: &str = "latest";

type BlockCfg = (NonZeroU32, ());

#[repr(u8)]
pub enum Kind {
    Seed = 0,
    Notarization = 1,
    Finalization = 2,
}

#[derive(Default)]
pub struct Store {
    seeds: BTreeMap<View, Seed>,
    notarizations: BTreeMap<View, Notarized>,
    finalizations: BTreeMap<View, Finalized>,
    seed_uploads: BTreeSet<View>,
    notarization_uploads: BTreeSet<View>,
    finalization_uploads: BTreeSet<View>,
    finalized_height_to_view: BTreeMap<u64, View>,
    blocks_by_digest: BTreeMap<Digest, Block>,
}

#[derive(Clone)]
pub struct Indexer {
    scheme: Scheme,
    participants: NonZeroU32,
    store: Arc<RwLock<Store>>,
    consensus_tx: broadcast::Sender<Vec<u8>>,
    summary_tx: broadcast::Sender<SummaryEvent>,
}

impl Indexer {
    pub fn new(identity: Identity, participants: NonZeroU32) -> Self {
        let namespace = union(NAMESPACE, b"_CONSENSUS");
        let scheme = Scheme::certificate_verifier(&namespace, identity);
        let (consensus_tx, _) = broadcast::channel(1024);
        let (summary_tx, _) = broadcast::channel(1024);
        Self {
            scheme,
            participants,
            store: Arc::new(RwLock::new(Store::default())),
            consensus_tx,
            summary_tx,
        }
    }

    fn block_cfg(&self) -> BlockCfg {
        (self.participants, ())
    }

    pub fn submit_seed(&self, seed: Seed) -> Result<(), &'static str> {
        let view = seed.view();
        {
            let mut store = self.store.write().unwrap();
            if store.seeds.contains_key(&view) || !store.seed_uploads.insert(view) {
                return Ok(());
            }
        }
        if !seed.verify(&self.scheme) {
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
        {
            let mut store = self.store.write().unwrap();
            if store.notarizations.contains_key(&view) || !store.notarization_uploads.insert(view) {
                return Ok(());
            }
        }
        if !notarized.verify(&self.scheme, &Sequential) {
            self.store
                .write()
                .unwrap()
                .notarization_uploads
                .remove(&view);
            return Err("invalid notarization signature");
        }

        let mut store = self.store.write().unwrap();
        store.notarization_uploads.remove(&view);
        store
            .blocks_by_digest
            .insert(notarized.block.digest(), notarized.block.clone());

        if store
            .notarizations
            .insert(view, notarized.clone())
            .is_some()
        {
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
            store.notarizations.get(&View::new(view)).cloned()
        }
    }

    pub fn submit_finalization(&self, finalized: Finalized) -> Result<(), &'static str> {
        let view = finalized.proof.view();
        {
            let mut store = self.store.write().unwrap();
            if store.finalizations.contains_key(&view) || !store.finalization_uploads.insert(view) {
                return Ok(());
            }
        }
        if !finalized.verify(&self.scheme, &Sequential) {
            self.store
                .write()
                .unwrap()
                .finalization_uploads
                .remove(&view);
            return Err("invalid finalization signature");
        }

        let mut store = self.store.write().unwrap();
        store.finalization_uploads.remove(&view);
        store
            .blocks_by_digest
            .insert(finalized.block.digest(), finalized.block.clone());

        if store
            .finalizations
            .insert(view, finalized.clone())
            .is_some()
        {
            return Ok(());
        }
        store
            .finalized_height_to_view
            .insert(finalized.block.height.get(), view);

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
            store.finalizations.get(&View::new(view)).cloned()
        }
    }

    pub fn submit_block(&self, block: Block) {
        let mut store = self.store.write().unwrap();
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
            store
                .finalized_height_to_view
                .get(&height)
                .and_then(|view| {
                    store
                        .finalizations
                        .get(view)
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
