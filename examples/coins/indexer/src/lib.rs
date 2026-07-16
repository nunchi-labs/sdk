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
    types::{Epoch, EpochInfo, Epocher, FixedEpocher, Round, View},
    Epochable, Viewable,
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{sharing::ModeVersion, variant::MinSig},
    },
    sha256::Digest,
    Digestible,
};
use commonware_formatting::{from_hex, hex};
use commonware_parallel::Sequential;
use commonware_utils::union;
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
    seeds: BTreeMap<Round, Seed>,
    notarizations: BTreeMap<ArtifactKey, Notarized>,
    finalizations: BTreeMap<ArtifactKey, Finalized>,
    seed_uploads: BTreeSet<Round>,
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
    scheme: Scheme,
    latest_epoch: Epoch,
    output: Option<DkgOutput>,
}

impl VerifierState {
    fn new(initial_epoch: Epoch, initial_scheme: Scheme, output: Option<DkgOutput>) -> Self {
        Self {
            scheme: initial_scheme,
            latest_epoch: initial_epoch,
            output,
        }
    }

    fn scheme(&self, _: Epoch) -> Scheme {
        self.scheme.clone()
    }

    fn install_output(&mut self, epoch: Epoch, output: DkgOutput) -> Result<bool, &'static str> {
        if output.public().public() != self.scheme.identity() {
            return Err("DKG output changed the threshold identity");
        }
        if epoch < self.latest_epoch {
            return Ok(false);
        }
        if epoch == self.latest_epoch && self.output.as_ref() == Some(&output) {
            return Ok(false);
        }
        if epoch == self.latest_epoch && self.output.is_some() {
            return Err("conflicting DKG output for current epoch");
        }

        self.output = Some(output);
        self.latest_epoch = epoch;
        Ok(true)
    }
}

#[derive(Clone)]
pub struct Indexer {
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
        Self::from_scheme(participants, Epoch::zero(), scheme, None)
    }

    pub fn new_from_output(output: DkgOutput, participants: NonZeroU32) -> Self {
        Self::new_from_output_at(Epoch::zero(), output, participants)
    }

    pub fn new_from_output_at(epoch: Epoch, output: DkgOutput, participants: NonZeroU32) -> Self {
        let namespace = union(NAMESPACE, b"_CONSENSUS");
        let scheme = Scheme::certificate_verifier(&namespace, *output.public().public());
        Self::from_scheme(participants, epoch, scheme, Some(output))
    }

    fn from_scheme(
        participants: NonZeroU32,
        initial_epoch: Epoch,
        scheme: Scheme,
        output: Option<DkgOutput>,
    ) -> Self {
        let (consensus_tx, _) = broadcast::channel(1024);
        let (summary_tx, _) = broadcast::channel(1024);
        Self {
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

    pub fn submit_dkg_output(&self, epoch: Epoch, output: DkgOutput) -> Result<(), &'static str> {
        let installed = {
            let mut store = self.store.write().unwrap();
            store.verifier.install_output(epoch, output.clone())?
        };
        if installed {
            if let Some(path) = &self.dkg_output_state_dir {
                if let Err(error) = persist_dkg_output(path, epoch, &output) {
                    warn!(%epoch, %error, "failed to persist DKG output");
                }
            }
        }
        Ok(())
    }

    pub fn submit_seed(&self, seed: Seed) -> Result<(), &'static str> {
        let round = seed.round();
        let view = seed.view();
        let scheme = {
            let mut store = self.store.write().unwrap();
            if store.seeds.contains_key(&round) || !store.seed_uploads.insert(round) {
                return Ok(());
            }
            store.verifier.scheme(seed.epoch())
        };
        if !seed.verify(&scheme) {
            self.store.write().unwrap().seed_uploads.remove(&round);
            return Err("invalid seed signature");
        }

        let mut store = self.store.write().unwrap();
        store.seed_uploads.remove(&round);
        if store.seeds.insert(round, seed.clone()).is_some() {
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
            store
                .seeds
                .iter()
                .rev()
                .find(|(round, _)| round.view() == View::new(view))
                .map(|(_, seed)| seed.clone())
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
        Ok(output) => match indexer.submit_dkg_output(Epoch::new(epoch), output) {
            Ok(()) => StatusCode::OK,
            Err(_) => StatusCode::UNAUTHORIZED,
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::simplex::{
        scheme::bls12381_threshold::vrf as bls12381_threshold,
        types::{
            Finalization as ConsensusFinalization, Finalize, Notarization as ConsensusNotarization,
            Notarize, Proposal,
        },
    };
    use commonware_consensus::types::Height;
    use commonware_cryptography::{
        bls12381::dkg::feldman_desmedt::deal, certificate::mocks::Fixture, ed25519, sha256::Sha256,
        Digest as _, Hasher, Signer,
    };
    use commonware_storage::mmr::Location;
    use commonware_utils::{
        ordered::Set, range::NonEmptyRange, test_rng, test_rng_seeded, N3f1, NZU32,
    };
    use nunchi_coins_chain::{Context, Seedable, StateCommitment};

    fn schemes() -> Vec<Scheme> {
        let mut rng = test_rng();
        let namespace = union(NAMESPACE, b"_CONSENSUS");
        let Fixture { schemes, .. } =
            bls12381_threshold::fixture::<MinSig, _>(&mut rng, &namespace, 4);
        schemes
    }

    fn seed(schemes: &[Scheme], epoch: u64, view: u64) -> Seed {
        let round = Round::new(Epoch::new(epoch), View::new(view));
        let proposal = Proposal::new(round, View::zero(), Sha256::hash(&round.encode()));
        let notarizes = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("sign notarize"))
            .collect::<Vec<_>>();
        ConsensusNotarization::from_notarizes(&schemes[0], &notarizes, &Sequential)
            .expect("build notarization")
            .seed()
    }

    fn output(seed: u64) -> DkgOutput {
        let players = Set::from_iter_dedup(
            (0..4).map(|offset| ed25519::PrivateKey::from_seed(seed + offset).public_key()),
        );
        let mut rng = test_rng_seeded(seed);
        deal::<MinSig, _, N3f1>(&mut rng, Default::default(), players)
            .expect("deal")
            .0
    }

    fn finalized(schemes: &[Scheme], epoch: u64, view: u64, height: u64) -> Finalized {
        let round = Round::new(Epoch::new(epoch), View::new(view));
        let block = Block::new(
            Context {
                round,
                leader: ed25519::PrivateKey::from_seed(100).public_key(),
                parent: (View::zero(), Digest::EMPTY),
            },
            Sha256::hash(b"parent"),
            Height::new(height),
            1_000,
            Vec::new(),
            None,
            (),
            StateCommitment {
                root: Sha256::hash(b"state"),
                range: NonEmptyRange::new(Location::new(1)..Location::new(2)).unwrap(),
            },
        );
        let proposal = Proposal::new(round, View::zero(), block.digest());
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
            .collect::<Vec<_>>();
        Finalized::new(
            ConsensusFinalization::from_finalizes(&schemes[0], &finalizes, &Sequential)
                .expect("build finalization"),
            block,
        )
    }

    #[test]
    fn seeds_with_reused_views_are_indexed_by_round() {
        let schemes = schemes();
        let indexer = Indexer::new(*schemes[0].identity(), NZU32!(4));

        indexer.submit_seed(seed(&schemes, 0, 1)).unwrap();
        indexer.submit_seed(seed(&schemes, 1, 1)).unwrap();

        let store = indexer.store.read().unwrap();
        assert_eq!(store.seeds.len(), 2);
        assert!(store
            .seeds
            .contains_key(&Round::new(Epoch::zero(), View::new(1))));
        assert!(store
            .seeds
            .contains_key(&Round::new(Epoch::new(1), View::new(1))));
    }

    #[test]
    fn finalization_after_transition_does_not_wait_for_dkg_upload() {
        let schemes = schemes();
        let indexer = Indexer::new(*schemes[0].identity(), NZU32!(4));
        let finalized = finalized(&schemes, 1, 1, BLOCKS_PER_EPOCH.get() + 1);

        indexer.submit_finalization(finalized).unwrap();

        assert!(indexer.get_finalization(LATEST).is_some());
    }

    #[test]
    fn dkg_checkpoint_cannot_change_threshold_identity() {
        let initial = output(10);
        let replacement = output(20);
        assert_ne!(initial.public().public(), replacement.public().public());
        let indexer = Indexer::new_from_output(initial, NZU32!(4));

        let result = indexer.submit_dkg_output(Epoch::new(1), replacement);

        assert_eq!(result, Err("DKG output changed the threshold identity"));
        assert_eq!(
            indexer.store.read().unwrap().verifier.latest_epoch,
            Epoch::zero()
        );
    }

    #[test]
    fn stale_dkg_checkpoint_does_not_replace_persisted_latest() {
        let path = std::env::temp_dir().join(format!(
            "coins-indexer-dkg-checkpoint-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        let output = output(30);
        let indexer = Indexer::new_from_output(output.clone(), NZU32!(4))
            .with_dkg_output_state_dir(path.clone());

        indexer
            .submit_dkg_output(Epoch::new(2), output.clone())
            .unwrap();
        indexer
            .submit_dkg_output(Epoch::new(1), output.clone())
            .unwrap();

        let (epoch, persisted) = load_dkg_output(&path, NZU32!(4))
            .unwrap()
            .expect("persisted checkpoint");
        assert_eq!(epoch, Epoch::new(2));
        assert_eq!(persisted, output);
        let _ = fs::remove_dir_all(path);
    }
}
