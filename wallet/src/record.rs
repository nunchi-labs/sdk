use commonware_codec::{DecodeExt, Encode};
use nunchi_common::{Address, Bech32Error, ADDRESS_HRP};
use nunchi_crypto::{Curve, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const WALLET_SCHEMA_VERSION: u32 = 1;

/// Errors surfaced by wallet persistence and validation.
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("wallet not found: {name}")]
    NotFound { name: String },
    #[error("wallet already exists: {name}")]
    AlreadyExists { name: String },
    #[error("invalid wallet name: {reason}")]
    InvalidName { reason: String },
    #[error("invalid bech32 address: {0}")]
    InvalidAddress(#[from] Bech32Error),
    #[error("invalid wallet record: {reason}")]
    InvalidRecord { reason: String },
    #[error("keystore error: {0}")]
    Keystore(#[from] crate::keystore::KeystoreError),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("json error at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Cleartext wallet metadata persisted after decryption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletRecord {
    pub schema_version: u32,
    pub name: String,
    pub chain_id: u64,
    pub curve: String,
    pub address: String,
    pub public_key_hex: String,
    pub private_key_hex: String,
    pub created_at_ms: u128,
}

/// Public wallet summary safe to print in CLI output.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WalletSummary {
    pub name: String,
    pub chain_id: u64,
    pub curve: String,
    pub address: String,
    pub public_key_hex: String,
    pub created_at_ms: u128,
    pub record_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedWallet {
    pub summary: WalletSummary,
}

#[derive(Debug, Clone)]
pub struct CreateWalletOptions {
    pub wallet_root: PathBuf,
    pub name: String,
    pub chain_id: u64,
    pub password: Option<String>,
    pub insecure_store: bool,
}

impl CreateWalletOptions {
    pub fn new(wallet_root: impl Into<PathBuf>, name: impl Into<String>, chain_id: u64) -> Self {
        Self {
            wallet_root: wallet_root.into(),
            name: name.into(),
            chain_id,
            password: std::env::var("NUNCHI_WALLET_PASSWORD").ok(),
            insecure_store: false,
        }
    }

    pub fn password(mut self, password: Option<String>) -> Self {
        self.password = password;
        self
    }

    pub fn insecure_store(mut self, insecure_store: bool) -> Self {
        self.insecure_store = insecure_store;
        self
    }
}

#[derive(Debug, Clone)]
pub struct WalletLookupOptions {
    pub wallet_root: PathBuf,
    pub name: String,
    pub password: Option<String>,
}

impl WalletLookupOptions {
    pub fn new(wallet_root: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        Self {
            wallet_root: wallet_root.into(),
            name: name.into(),
            password: std::env::var("NUNCHI_WALLET_PASSWORD").ok(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListWalletsOptions {
    pub wallet_root: PathBuf,
    pub password: Option<String>,
}

impl ListWalletsOptions {
    pub fn new(wallet_root: impl Into<PathBuf>) -> Self {
        Self {
            wallet_root: wallet_root.into(),
            password: std::env::var("NUNCHI_WALLET_PASSWORD").ok(),
        }
    }
}

pub fn address_hrp() -> &'static str {
    ADDRESS_HRP
}

pub fn parse_address(value: &str) -> Result<Address, WalletError> {
    Address::from_bech32(value).map_err(WalletError::from)
}

pub fn address_from_public_key(public_key: &PublicKey) -> Address {
    Address::external(public_key)
}

pub fn create_wallet(options: &CreateWalletOptions) -> Result<CreatedWallet, WalletError> {
    let name = normalize_wallet_name(&options.name)?;
    let record_path = wallet_record_path(&options.wallet_root, &name);
    if record_path.is_file() {
        return Err(WalletError::AlreadyExists { name });
    }

    let private_key = generate_ed25519_key()?;
    let public_key = private_key.public_key();
    let address = address_from_public_key(&public_key).to_bech32();
    let record = WalletRecord {
        schema_version: WALLET_SCHEMA_VERSION,
        name: name.clone(),
        chain_id: options.chain_id,
        curve: "ed25519".to_string(),
        address,
        public_key_hex: encode_hex(&public_key.encode()),
        private_key_hex: encode_hex(&private_key.encode()),
        created_at_ms: unix_now_ms(),
    };
    validate_wallet_record(&record)?;
    crate::keystore::write_wallet(&record_path, &record, options.password.as_deref(), options.insecure_store)?;
    Ok(CreatedWallet {
        summary: wallet_summary_from_record(&record, record_path),
    })
}

pub fn list_wallets(options: &ListWalletsOptions) -> Result<Vec<WalletSummary>, WalletError> {
    let wallets_root = wallets_root(&options.wallet_root);
    if !wallets_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut summaries = Vec::new();
    for entry in fs::read_dir(&wallets_root).map_err(|source| WalletError::Io {
        path: wallets_root.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| WalletError::Io {
            path: wallets_root.clone(),
            source,
        })?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let record_file = path.join("wallet.json");
        if !record_file.is_file() {
            continue;
        }
        let record = crate::keystore::read_wallet(&record_file, options.password.as_deref())?;
        summaries.push(wallet_summary_from_record(&record, record_file));
    }
    summaries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(summaries)
}

pub fn show_wallet(options: &WalletLookupOptions) -> Result<WalletSummary, WalletError> {
    let name = normalize_wallet_name(&options.name)?;
    let record_path = wallet_record_path(&options.wallet_root, &name);
    if !record_path.is_file() {
        return Err(WalletError::NotFound { name });
    }
    let record = crate::keystore::read_wallet(&record_path, options.password.as_deref())?;
    Ok(wallet_summary_from_record(&record, record_path))
}

pub fn load_private_key(options: &WalletLookupOptions) -> Result<PrivateKey, WalletError> {
    let name = normalize_wallet_name(&options.name)?;
    let record_path = wallet_record_path(&options.wallet_root, &name);
    if !record_path.is_file() {
        return Err(WalletError::NotFound { name });
    }
    let record = crate::keystore::read_wallet(&record_path, options.password.as_deref())?;
    decode_private_key(&record.private_key_hex)
}

pub fn sign_message(
    options: &WalletLookupOptions,
    namespace: &[u8],
    message: &[u8],
) -> Result<String, WalletError> {
    let private_key = load_private_key(options)?;
    let signature = private_key.sign(namespace, message);
    Ok(encode_hex(&signature.encode()))
}

fn wallet_summary_from_record(record: &WalletRecord, record_path: PathBuf) -> WalletSummary {
    WalletSummary {
        name: record.name.clone(),
        chain_id: record.chain_id,
        curve: record.curve.clone(),
        address: record.address.clone(),
        public_key_hex: record.public_key_hex.clone(),
        created_at_ms: record.created_at_ms,
        record_path: record_path.display().to_string(),
    }
}

pub(crate) fn wallets_root(wallet_root: &Path) -> PathBuf {
    wallet_root.join("wallets")
}

pub(crate) fn wallet_record_path(wallet_root: &Path, name: &str) -> PathBuf {
    wallets_root(wallet_root).join(name).join("wallet.json")
}

fn normalize_wallet_name(name: &str) -> Result<String, WalletError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(WalletError::InvalidName {
            reason: "name must not be empty".to_string(),
        });
    }
    if trimmed.len() > 64 {
        return Err(WalletError::InvalidName {
            reason: "name must be at most 64 characters".to_string(),
        });
    }
    let valid = trimmed
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_'));
    if !valid {
        return Err(WalletError::InvalidName {
            reason: "name must use lowercase letters, digits, '-' or '_'".to_string(),
        });
    }
    Ok(trimmed.to_string())
}

pub(crate) fn validate_wallet_record(record: &WalletRecord) -> Result<(), WalletError> {
    if record.schema_version != WALLET_SCHEMA_VERSION {
        return Err(WalletError::InvalidRecord {
            reason: format!("unsupported schema version {}", record.schema_version),
        });
    }
    if record.curve != "ed25519" {
        return Err(WalletError::InvalidRecord {
            reason: format!("unsupported curve {}", record.curve),
        });
    }
    let address = parse_address(&record.address)?;
    let private_key = decode_private_key(&record.private_key_hex)?;
    let public_key = private_key.public_key();
    if address_from_public_key(&public_key) != address {
        return Err(WalletError::InvalidRecord {
            reason: "address does not match derived public key".to_string(),
        });
    }
    if encode_hex(&public_key.encode()) != record.public_key_hex {
        return Err(WalletError::InvalidRecord {
            reason: "public_key_hex does not match private key".to_string(),
        });
    }
    if private_key.curve() != Curve::Ed25519 {
        return Err(WalletError::InvalidRecord {
            reason: "private key must be ed25519".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn decode_private_key(hex_value: &str) -> Result<PrivateKey, WalletError> {
    let bytes = decode_hex(hex_value).map_err(|reason| WalletError::InvalidRecord { reason })?;
    PrivateKey::decode(bytes.as_ref()).map_err(|reason| WalletError::InvalidRecord {
        reason: format!("private key decode failed: {reason}"),
    })
}

#[cfg(feature = "cli")]
fn generate_ed25519_key() -> Result<PrivateKey, WalletError> {
    use commonware_cryptography::ed25519;
    use commonware_math::algebra::Random;
    use rand::rngs::OsRng;
    Ok(PrivateKey::Ed25519(ed25519::PrivateKey::random(OsRng)))
}

#[cfg(not(feature = "cli"))]
fn generate_ed25519_key() -> Result<PrivateKey, WalletError> {
    Ok(PrivateKey::ed25519_from_seed(rand_core::RngCore::next_u64(
        &mut rand_core::OsRng,
    )))
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("hex value must not be empty".to_string());
    }
    if !trimmed.len().is_multiple_of(2) {
        return Err("hex value must have even length".to_string());
    }
    if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("hex value contains invalid characters".to_string());
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&trimmed[index..index + 2], 16)
                .map_err(|_| "hex value contains invalid characters".to_string())
        })
        .collect()
}

fn unix_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_wallet_writes_bech32_address() {
        let temp = tempfile::tempdir().expect("tempdir");
        let created = create_wallet(
            &CreateWalletOptions::new(temp.path(), "default", 1).insecure_store(true),
        )
        .expect("create wallet");
        assert!(created.summary.address.starts_with("nch1"));
        assert_eq!(created.summary.chain_id, 1);
    }
}
