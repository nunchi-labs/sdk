//! Locked atomic local-file DKG recovery publication.

use bytes::{Buf, Bytes};
use commonware_codec::{Encode, ReadExt};
use commonware_cryptography::ed25519;
use commonware_formatting::hex;
use commonware_utils::sys_rng;
use fs2::FileExt;
use nunchi_dkg::{
    DurableReceipt, EncryptedRecoveryBundle, EncryptedRecoveryManifest, ManifestProtector,
    PublicationStage, RecoveryAssociatedData, RecoveryError, RecoveryManifest,
    RecoveryCandidate, RecoveryManifestEntry, RecoveryMetadata, RecoveryPublication, RecoverySink,
    MAX_RETAINED_BUNDLES,
};
use rand::Rng;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    thread::JoinHandle,
};
use tokio::sync::{mpsc, oneshot};

const LOCK_FILE: &str = ".nunchi-dkg-recovery.lock";
const MANIFEST_FILE: &str = "manifest.bundle";
const BUNDLES_DIR: &str = "bundles";
const ORPHANS_DIR: &str = "recovery-orphans";
const QUEUE_CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerPublication { First, Publish, NormalReplay }

#[derive(Clone, Debug, thiserror::Error)]
pub enum FileRecoveryError {
    #[error("recovery worker failed at {stage:?}")]
    Stage { stage: PublicationStage },
    #[error("recovery directory is not in the required state")]
    InvalidState,
    #[error("recovery directory lock is already held")]
    LockConflict,
    #[error("recovery worker stopped")]
    Stopped,
}

impl FileRecoveryError {
    const fn stage(stage: PublicationStage) -> Self {
        Self::Stage { stage }
    }

    const fn publication_stage(&self) -> PublicationStage {
        match self {
            Self::Stage { stage } => *stage,
            Self::LockConflict => PublicationStage::Lock,
            Self::InvalidState => PublicationStage::ReceiptCheck,
            Self::Stopped => PublicationStage::WorkerShutdown,
        }
    }
}

enum Command {
    Publish {
        operation: WorkerPublication,
        bundle: EncryptedRecoveryBundle,
        metadata: RecoveryMetadata,
        response: oneshot::Sender<Result<DurableReceipt, FileRecoveryError>>,
    },
    Load {
        response: oneshot::Sender<Result<Vec<(EncryptedRecoveryBundle, RecoveryMetadata)>, FileRecoveryError>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<(), FileRecoveryError>>,
    },
}

/// Clone-cheap async client. Accepted FIFO commands are owned by the worker and
/// are not canceled when a response future is dropped.
#[derive(Clone)]
pub struct FileRecoverySink {
    sender: mpsc::Sender<Command>,
}

#[async_trait::async_trait]
impl RecoverySink for FileRecoverySink {
    async fn load_candidates(&mut self) -> Result<Vec<RecoveryCandidate>, RecoveryError> {
        FileRecoverySink::load_candidates(self)
            .await
            .map(|candidates| {
                candidates
                    .into_iter()
                    .map(|(bundle, metadata)| RecoveryCandidate { bundle, metadata })
                    .collect()
            })
            .map_err(|error| RecoveryError::Publication(error.publication_stage()))
    }

    async fn publish(
        &mut self,
        operation: RecoveryPublication,
        bundle: EncryptedRecoveryBundle,
        metadata: RecoveryMetadata,
    ) -> Result<DurableReceipt, RecoveryError> {
        let operation = match operation {
            RecoveryPublication::GenesisFirst => WorkerPublication::First,
            RecoveryPublication::NormalReplay => WorkerPublication::NormalReplay,
            RecoveryPublication::DisasterRestore | RecoveryPublication::Runtime => WorkerPublication::Publish,
        };
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::Publish {
                operation,
                bundle,
                metadata,
                response,
            })
            .await
            .map_err(|_| RecoveryError::Publication(PublicationStage::Queue))?;
        receiver
            .await
            .map_err(|_| RecoveryError::Publication(PublicationStage::WorkerShutdown))?
            .map_err(|error| RecoveryError::Publication(error.publication_stage()))
    }
}

impl FileRecoverySink {
    pub async fn load_candidates(
        &self,
    ) -> Result<Vec<(EncryptedRecoveryBundle, RecoveryMetadata)>, FileRecoveryError> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Command::Load { response })
            .await
            .map_err(|_| FileRecoveryError::Stopped)?;
        receiver.await.map_err(|_| FileRecoveryError::Stopped)?
    }
}

pub struct FileRecoveryWorker {
    sender: mpsc::Sender<Command>,
    completion: oneshot::Receiver<Result<(), FileRecoveryError>>,
    completion_result: Option<Result<(), FileRecoveryError>>,
    thread: Option<JoinHandle<()>>,
}

impl FileRecoveryWorker {
    pub async fn start(
        directory: PathBuf,
        storage_directory: PathBuf,
        protector: ManifestProtector,
        associated_data: RecoveryAssociatedData<ed25519::PublicKey>,
    ) -> Result<(Self, FileRecoverySink), FileRecoveryError> {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let (startup_tx, startup_rx) = oneshot::channel();
        let (completion_tx, completion) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("nunchi-dkg-recovery".to_owned())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match Worker::open(directory, storage_directory, protector, associated_data) {
                        Ok(worker) => {
                            let _ = startup_tx.send(Ok(()));
                            worker.run(receiver)
                        }
                        Err(error) => {
                            let _ = startup_tx.send(Err(error.clone()));
                            Err(error)
                        }
                    }
                }))
                .unwrap_or(Err(FileRecoveryError::Stopped));
                let _ = completion_tx.send(result);
            })
            .map_err(|_| FileRecoveryError::stage(PublicationStage::WorkerShutdown))?;
        match startup_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = thread.join();
                return Err(error);
            }
            Err(_) => {
                let _ = thread.join();
                return Err(FileRecoveryError::Stopped);
            }
        }
        let sink = FileRecoverySink {
            sender: sender.clone(),
        };
        Ok((
            Self {
                sender,
                completion,
                completion_result: None,
                thread: Some(thread),
            },
            sink,
        ))
    }

    pub async fn completed(&mut self) -> Result<(), FileRecoveryError> {
        if let Some(result) = self.completion_result.clone() {
            return result;
        }
        let result = (&mut self.completion)
            .await
            .map_err(|_| FileRecoveryError::Stopped)?;
        self.completion_result = Some(result.clone());
        result
    }

    pub async fn shutdown(mut self) -> Result<(), FileRecoveryError> {
        if self.completion_result.is_none() {
            let (response, receiver) = oneshot::channel();
            self.sender
                .send(Command::Shutdown { response })
                .await
                .map_err(|_| FileRecoveryError::Stopped)?;
            receiver.await.map_err(|_| FileRecoveryError::Stopped)??;
            let result = (&mut self.completion)
                .await
                .map_err(|_| FileRecoveryError::Stopped)?;
            self.completion_result = Some(result);
        }
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| FileRecoveryError::Stopped)?;
        }
        self.completion_result
            .expect("worker completion recorded before join")
    }
}

enum DirectoryState {
    Empty,
    Ready(RecoveryManifest),
    InvalidWithArtifacts,
}

struct Worker {
    directory: PathBuf,
    protector: ManifestProtector,
    associated_data: RecoveryAssociatedData<ed25519::PublicKey>,
    _lock: File,
}

impl Worker {
    fn open(
        directory: PathBuf,
        storage_directory: PathBuf,
        protector: ManifestProtector,
        associated_data: RecoveryAssociatedData<ed25519::PublicKey>,
    ) -> Result<Self, FileRecoveryError> {
        let directory = directory
            .canonicalize()
            .map_err(|_| FileRecoveryError::stage(PublicationStage::Lock))?;
        let storage_directory = storage_directory
            .canonicalize()
            .map_err(|_| FileRecoveryError::stage(PublicationStage::Lock))?;
        if !directory.is_dir()
            || directory.starts_with(&storage_directory)
            || storage_directory.starts_with(&directory)
        {
            return Err(FileRecoveryError::InvalidState);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if fs::metadata(&directory)
                .map_err(|_| FileRecoveryError::InvalidState)?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err(FileRecoveryError::InvalidState);
            }
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join(LOCK_FILE))
            .map_err(|_| FileRecoveryError::stage(PublicationStage::Lock))?;
        lock.try_lock_exclusive()
            .map_err(|_| FileRecoveryError::LockConflict)?;
        Ok(Self {
            directory,
            protector,
            associated_data,
            _lock: lock,
        })
    }

    fn run(mut self, mut receiver: mpsc::Receiver<Command>) -> Result<(), FileRecoveryError> {
        while let Some(command) = receiver.blocking_recv() {
            match command {
                Command::Publish {
                    operation,
                    bundle,
                    metadata,
                    response,
                } => {
                    let _ = response.send(self.publish(operation, bundle, metadata));
                }
                Command::Load { response } => {
                    let _ = response.send(self.load_candidates());
                }
                Command::Shutdown { response } => {
                    receiver.close();
                    while let Some(command) = receiver.blocking_recv() {
                        match command {
                            Command::Publish { operation, bundle, metadata, response } => {
                                let _ = response.send(self.publish(operation, bundle, metadata));
                            }
                            Command::Load { response } => {
                                let _ = response.send(self.load_candidates());
                            }
                            Command::Shutdown { response } => {
                                let _ = response.send(Ok(()));
                            }
                        }
                    }
                    let _ = response.send(Ok(()));
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn classify(&self) -> Result<DirectoryState, FileRecoveryError> {
        let manifest_path = self.directory.join(MANIFEST_FILE);
        match self.load_manifest() {
            Ok(manifest) => return Ok(DirectoryState::Ready(manifest)),
            Err(_) if manifest_path.exists() => return Ok(DirectoryState::InvalidWithArtifacts),
            Err(_) => {}
        }
        let mut artifacts = false;
        for entry in fs::read_dir(&self.directory)
            .map_err(|_| FileRecoveryError::stage(PublicationStage::Lock))?
        {
            let entry = entry.map_err(|_| FileRecoveryError::stage(PublicationStage::Lock))?;
            let name = entry.file_name();
            if name == LOCK_FILE || name == ORPHANS_DIR {
                continue;
            }
            if name == BUNDLES_DIR || name == MANIFEST_FILE || name.to_string_lossy().starts_with(".tmp-") {
                artifacts = true;
                continue;
            }
            return Err(FileRecoveryError::InvalidState);
        }
        Ok(if artifacts {
            DirectoryState::InvalidWithArtifacts
        } else {
            DirectoryState::Empty
        })
    }

    fn publish(
        &mut self,
        operation: WorkerPublication,
        bundle: EncryptedRecoveryBundle,
        metadata: RecoveryMetadata,
    ) -> Result<DurableReceipt, FileRecoveryError> {
        let state = self.classify()?;
        let manifest = match (operation, state) {
            (WorkerPublication::First, DirectoryState::Empty) => None,
            (WorkerPublication::Publish, DirectoryState::Ready(manifest)) => Some(manifest),
            (WorkerPublication::NormalReplay, DirectoryState::Ready(manifest)) => Some(manifest),
            (WorkerPublication::NormalReplay, DirectoryState::Empty) => None,
            (WorkerPublication::NormalReplay, DirectoryState::InvalidWithArtifacts) => {
                self.quarantine()?;
                None
            }
            _ => return Err(FileRecoveryError::InvalidState),
        };
        self.install(bundle, metadata, manifest)
    }

    fn install(
        &mut self,
        bundle: EncryptedRecoveryBundle,
        metadata: RecoveryMetadata,
        prior: Option<RecoveryManifest>,
    ) -> Result<DurableReceipt, FileRecoveryError> {
        let encoded = bundle.encode();
        let bundle_digest = bundle.digest();
        if let Some(manifest) = prior.as_ref() {
            if let Some(newest) = manifest.entries.first() {
                if newest.bundle_digest == bundle_digest
                    && newest.created_at_ms == metadata.created_at_ms
                    && newest.checkpoint_epoch == metadata.checkpoint_epoch
                    && newest.checkpoint_digest == metadata.checkpoint_digest
                {
                    self.verify_bundle(newest)?;
                    return Ok(receipt(manifest.generation, newest));
                }
            }
        }

        let bundles = self.directory.join(BUNDLES_DIR);
        if !bundles.exists() {
            create_secure_directory(&bundles)?;
            sync_dir(&self.directory)?;
        }
        ensure_directory(&bundles)?;
        let target = bundles.join(format!("{}.bundle", hex(&bundle_digest)));
        if target.exists() {
            let existing = read_regular(&target)?;
            if existing != encoded {
                return Err(FileRecoveryError::InvalidState);
            }
        } else {
            let temp = self.directory.join(temp_name());
            write_new(&temp, &encoded)?;
            fs::rename(&temp, &target)
                .map_err(|_| FileRecoveryError::stage(PublicationStage::Rename))?;
            sync_dir(&bundles)?;
        }

        let entry = RecoveryManifestEntry {
            bundle_digest,
            created_at_ms: metadata.created_at_ms,
            checkpoint_epoch: metadata.checkpoint_epoch,
            checkpoint_digest: metadata.checkpoint_digest,
        };
        let generation = prior
            .as_ref()
            .map_or(Ok(1), |manifest| manifest.generation.checked_add(1).ok_or(FileRecoveryError::InvalidState))?;
        let mut entries = vec![entry];
        if let Some(prior) = prior {
            entries.extend(prior.entries.into_iter().filter(|old| old.bundle_digest != bundle_digest));
        }
        entries.truncate(MAX_RETAINED_BUNDLES);
        let manifest = RecoveryManifest {
            format_version: nunchi_dkg::recovery::RECOVERY_FORMAT_VERSION,
            generation,
            entries,
        };
        let sealed = self
            .protector
            .encrypt(&manifest, &self.associated_data, &mut sys_rng())
            .map_err(|_| FileRecoveryError::stage(PublicationStage::Encrypt))?;
        let manifest_temp = self.directory.join(temp_name());
        write_new(&manifest_temp, &sealed.encode())?;
        fs::rename(&manifest_temp, self.directory.join(MANIFEST_FILE))
            .map_err(|_| FileRecoveryError::stage(PublicationStage::ManifestReplace))?;
        sync_dir(&self.directory)?;
        self.cleanup(&manifest)?;
        Ok(receipt(generation, &entry))
    }

    fn load_manifest(&self) -> Result<RecoveryManifest, FileRecoveryError> {
        let bytes = read_regular(&self.directory.join(MANIFEST_FILE))?;
        let mut input = bytes.as_slice();
        let envelope = EncryptedRecoveryManifest::read(&mut input)
            .map_err(|_| FileRecoveryError::InvalidState)?;
        if !input.is_empty() {
            return Err(FileRecoveryError::InvalidState);
        }
        let manifest = self
            .protector
            .decrypt(&envelope, &self.associated_data)
            .map_err(|_| FileRecoveryError::InvalidState)?;
        for entry in &manifest.entries {
            self.verify_bundle(entry)?;
        }
        Ok(manifest)
    }

    fn verify_bundle(&self, entry: &RecoveryManifestEntry) -> Result<Bytes, FileRecoveryError> {
        let path = self
            .directory
            .join(BUNDLES_DIR)
            .join(format!("{}.bundle", hex(&entry.bundle_digest)));
        let bytes = Bytes::from(read_regular(&path)?);
        let mut input = bytes.clone();
        let envelope = EncryptedRecoveryBundle::read(&mut input)
            .map_err(|_| FileRecoveryError::InvalidState)?;
        if input.has_remaining() || envelope.digest() != entry.bundle_digest {
            return Err(FileRecoveryError::InvalidState);
        }
        Ok(bytes)
    }

    fn load_candidates(
        &self,
    ) -> Result<Vec<(EncryptedRecoveryBundle, RecoveryMetadata)>, FileRecoveryError> {
        let DirectoryState::Ready(manifest) = self.classify()? else {
            return Err(FileRecoveryError::InvalidState);
        };
        manifest
            .entries
            .iter()
            .map(|entry| {
                let bytes = self.verify_bundle(entry)?;
                let mut input = bytes.clone();
                let bundle = EncryptedRecoveryBundle::read(&mut input)
                    .map_err(|_| FileRecoveryError::InvalidState)?;
                Ok((
                    bundle,
                    RecoveryMetadata {
                        checkpoint_epoch: entry.checkpoint_epoch,
                        created_at_ms: entry.created_at_ms,
                        checkpoint_digest: entry.checkpoint_digest,
                    },
                ))
            })
            .collect()
    }

    fn cleanup(&self, manifest: &RecoveryManifest) -> Result<(), FileRecoveryError> {
        let bundles = self.directory.join(BUNDLES_DIR);
        let mut obsolete = Vec::new();
        for entry in fs::read_dir(&bundles)
            .map_err(|_| FileRecoveryError::stage(PublicationStage::Cleanup))?
        {
            let entry = entry.map_err(|_| FileRecoveryError::stage(PublicationStage::Cleanup))?;
            let ty = entry.file_type().map_err(|_| FileRecoveryError::InvalidState)?;
            if !ty.is_file() {
                return Err(FileRecoveryError::InvalidState);
            }
            let name = entry.file_name();
            let name_text = name.to_string_lossy();
            let digest_name = name_text
                .strip_suffix(".bundle")
                .is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                });
            if !digest_name {
                return Err(FileRecoveryError::InvalidState);
            }
            let retained = manifest.entries.iter().any(|item| {
                name_text == format!("{}.bundle", hex(&item.bundle_digest))
            });
            if !retained {
                obsolete.push(entry.path());
            }
        }
        for path in obsolete {
            fs::remove_file(path)
                .map_err(|_| FileRecoveryError::stage(PublicationStage::Cleanup))?;
        }
        sync_dir(&bundles)
    }

    fn quarantine(&self) -> Result<(), FileRecoveryError> {
        let root = self.directory.join(ORPHANS_DIR);
        if !root.exists() {
            create_secure_directory(&root)?;
            sync_dir(&self.directory)?;
        }
        ensure_directory(&root)?;
        let mut rng = sys_rng();
        let id = (rng.next_u64() as u128) << 64 | rng.next_u64() as u128;
        let destination = root.join(format!("{id:032x}"));
        create_secure_directory(&destination)?;
        sync_dir(&root)?;
        let mut artifacts = Vec::new();
        for entry in fs::read_dir(&self.directory)
            .map_err(|_| FileRecoveryError::stage(PublicationStage::Rename))?
        {
            let entry = entry.map_err(|_| FileRecoveryError::stage(PublicationStage::Rename))?;
            let name = entry.file_name();
            if name == LOCK_FILE || name == ORPHANS_DIR {
                continue;
            }
            if name == MANIFEST_FILE
                || name == BUNDLES_DIR
                || name.to_string_lossy().starts_with(".tmp-")
            {
                let file_type = entry
                    .file_type()
                    .map_err(|_| FileRecoveryError::InvalidState)?;
                let safe_type = if name == BUNDLES_DIR {
                    file_type.is_dir()
                } else {
                    file_type.is_file()
                };
                if !safe_type {
                    return Err(FileRecoveryError::InvalidState);
                }
                artifacts.push((entry.path(), destination.join(name)));
            } else {
                return Err(FileRecoveryError::InvalidState);
            }
        }
        for (source, target) in artifacts {
            fs::rename(source, target)
                .map_err(|_| FileRecoveryError::stage(PublicationStage::Rename))?;
            sync_dir(&self.directory)?;
            sync_dir(&destination)?;
        }
        Ok(())
    }
}

fn receipt(generation: u64, entry: &RecoveryManifestEntry) -> DurableReceipt {
    DurableReceipt {
        manifest_generation: generation,
        checkpoint_epoch: entry.checkpoint_epoch,
        created_at_ms: entry.created_at_ms,
        checkpoint_digest: entry.checkpoint_digest,
        bundle_digest: entry.bundle_digest,
    }
}

fn temp_name() -> String {
    format!(".tmp-{:016x}", sys_rng().next_u64())
}

fn ensure_directory(path: &Path) -> Result<(), FileRecoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| FileRecoveryError::InvalidState)?;
    if !metadata.file_type().is_dir() {
        return Err(FileRecoveryError::InvalidState);
    }
    Ok(())
}

fn create_secure_directory(path: &Path) -> Result<(), FileRecoveryError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| FileRecoveryError::stage(PublicationStage::Create))
}

fn read_regular(path: &Path) -> Result<Vec<u8>, FileRecoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| FileRecoveryError::InvalidState)?;
    if !metadata.file_type().is_file() {
        return Err(FileRecoveryError::InvalidState);
    }
    let mut file = File::open(path).map_err(|_| FileRecoveryError::InvalidState)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| FileRecoveryError::stage(PublicationStage::Write))?;
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), FileRecoveryError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| FileRecoveryError::stage(PublicationStage::Create))?;
    file.write_all(bytes)
        .map_err(|_| FileRecoveryError::stage(PublicationStage::Write))?;
    file.sync_all()
        .map_err(|_| FileRecoveryError::stage(PublicationStage::FileSync))
}

fn sync_dir(path: &Path) -> Result<(), FileRecoveryError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| FileRecoveryError::stage(PublicationStage::DirectorySync))
}
