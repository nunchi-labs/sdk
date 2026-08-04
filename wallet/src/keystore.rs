use crate::record::{validate_wallet_record, WalletRecord};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use thiserror::Error;

const ENVELOPE_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("wallet password is required; set NUNCHI_WALLET_PASSWORD or pass --insecure-store for dev only")]
    PasswordRequired,
    #[error("failed to decrypt wallet; wrong password or corrupted file")]
    DecryptFailed,
    #[error("invalid keystore envelope: {reason}")]
    InvalidEnvelope { reason: String },
    #[error("system random failed: {reason}")]
    Random { reason: String },
    #[error("io error at {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("json error at {path}: {source}")]
    Json {
        path: std::path::PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedEnvelope {
    version: u32,
    kdf: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InsecureEnvelope {
    version: u32,
    insecure: bool,
    record: WalletRecord,
}

pub struct WalletKeystore;

impl WalletKeystore {
    pub fn default_root() -> std::path::PathBuf {
        std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".nunchi")
    }
}

pub(crate) fn write_wallet(
    path: &Path,
    record: &WalletRecord,
    password: Option<&str>,
    insecure_store: bool,
) -> Result<(), crate::record::WalletError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| crate::record::WalletError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let json = if insecure_store {
        serde_json::to_string_pretty(&InsecureEnvelope {
            version: ENVELOPE_VERSION,
            insecure: true,
            record: record.clone(),
        })
    } else {
        let password = password.ok_or(KeystoreError::PasswordRequired)?;
        let envelope = encrypt_record(record, password)?;
        serde_json::to_string_pretty(&envelope)
    }
    .map_err(|source| crate::record::WalletError::Json {
        path: path.to_path_buf(),
        source,
    })?;

    fs::write(path, json).map_err(|source| crate::record::WalletError::Io {
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) fn read_wallet(
    path: &Path,
    password: Option<&str>,
) -> Result<WalletRecord, crate::record::WalletError> {
    let raw = fs::read_to_string(path).map_err(|source| crate::record::WalletError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    if let Ok(insecure) = serde_json::from_str::<InsecureEnvelope>(&raw) {
        if insecure.insecure {
            validate_wallet_record(&insecure.record)?;
            return Ok(insecure.record);
        }
    }

    let envelope: EncryptedEnvelope =
        serde_json::from_str(&raw).map_err(|source| crate::record::WalletError::Json {
            path: path.to_path_buf(),
            source,
        })?;
    let password = password.ok_or(KeystoreError::PasswordRequired)?;
    let record = decrypt_record(&envelope, password)?;
    validate_wallet_record(&record)?;
    Ok(record)
}

fn encrypt_record(
    record: &WalletRecord,
    password: &str,
) -> Result<EncryptedEnvelope, KeystoreError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|source| KeystoreError::Random {
        reason: source.to_string(),
    })?;
    getrandom::fill(&mut nonce_bytes).map_err(|source| KeystoreError::Random {
        reason: source.to_string(),
    })?;

    let key = derive_key(password, &salt)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).map_err(|_| KeystoreError::InvalidEnvelope {
            reason: "invalid derived key length".to_string(),
        })?;
    let plaintext = serde_json::to_vec(record).map_err(|_| KeystoreError::InvalidEnvelope {
        reason: "failed to serialize wallet record".to_string(),
    })?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext =
        cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| KeystoreError::InvalidEnvelope {
                reason: "encryption failed".to_string(),
            })?;

    Ok(EncryptedEnvelope {
        version: ENVELOPE_VERSION,
        kdf: "argon2id".to_string(),
        salt: hex_encode(&salt),
        nonce: hex_encode(&nonce_bytes),
        ciphertext: hex_encode(&ciphertext),
    })
}

fn decrypt_record(
    envelope: &EncryptedEnvelope,
    password: &str,
) -> Result<WalletRecord, KeystoreError> {
    if envelope.version != ENVELOPE_VERSION || envelope.kdf != "argon2id" {
        return Err(KeystoreError::InvalidEnvelope {
            reason: "unsupported keystore version".to_string(),
        });
    }
    let salt = hex_decode(&envelope.salt).map_err(|_| KeystoreError::InvalidEnvelope {
        reason: "invalid salt".to_string(),
    })?;
    let nonce_bytes = hex_decode(&envelope.nonce).map_err(|_| KeystoreError::InvalidEnvelope {
        reason: "invalid nonce".to_string(),
    })?;
    let ciphertext =
        hex_decode(&envelope.ciphertext).map_err(|_| KeystoreError::InvalidEnvelope {
            reason: "invalid ciphertext".to_string(),
        })?;
    if salt.len() != SALT_LEN || nonce_bytes.len() != NONCE_LEN {
        return Err(KeystoreError::InvalidEnvelope {
            reason: "invalid salt or nonce length".to_string(),
        });
    }

    let key = derive_key(password, &salt)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).map_err(|_| KeystoreError::InvalidEnvelope {
            reason: "invalid derived key length".to_string(),
        })?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| KeystoreError::DecryptFailed)?;
    serde_json::from_slice(&plaintext).map_err(|_| KeystoreError::InvalidEnvelope {
        reason: "invalid wallet record payload".to_string(),
    })
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], KeystoreError> {
    let params =
        Params::new(19 * 1024, 2, 1, Some(32)).map_err(|_| KeystoreError::InvalidEnvelope {
            reason: "invalid argon2 params".to_string(),
        })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| KeystoreError::InvalidEnvelope {
            reason: "key derivation failed".to_string(),
        })?;
    Ok(key)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use commonware_codec::Encode;
    use nunchi_crypto::PrivateKey;

    use super::*;
    use crate::record::{address_from_public_key, encode_hex, WalletError};

    fn sample_record(name: &str) -> WalletRecord {
        let private_key = PrivateKey::from_seed(17);
        let public_key = private_key.public_key();
        WalletRecord {
            schema_version: 1,
            name: name.to_string(),
            chain_id: 42,
            curve: "ed25519".to_string(),
            address: address_from_public_key(&public_key).to_bech32(),
            public_key_hex: encode_hex(&public_key.encode()),
            private_key_hex: encode_hex(&private_key.encode()),
            created_at_ms: 123,
        }
    }

    fn assert_invalid_envelope(error: WalletError, expected: &str) {
        match error {
            WalletError::Keystore(KeystoreError::InvalidEnvelope { reason }) => {
                assert_eq!(reason, expected);
            }
            other => panic!("expected invalid envelope, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_wallet_round_trips_and_rejects_wrong_password() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("wallets/default/wallet.json");
        let record = sample_record("default");

        write_wallet(&path, &record, Some("correct horse"), false).expect("write encrypted wallet");
        let raw = fs::read_to_string(&path).expect("read envelope");
        assert!(raw.contains("\"kdf\": \"argon2id\""));
        assert!(!raw.contains(&record.private_key_hex));

        let loaded = read_wallet(&path, Some("correct horse")).expect("read encrypted wallet");
        assert_eq!(loaded, record);

        let error = read_wallet(&path, Some("wrong horse")).expect_err("wrong password fails");
        assert!(matches!(
            error,
            WalletError::Keystore(KeystoreError::DecryptFailed)
        ));
    }

    #[test]
    fn encrypted_wallet_requires_password_on_write_and_read() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("wallets/default/wallet.json");
        let record = sample_record("default");

        let error = write_wallet(&path, &record, None, false).expect_err("password required");
        assert!(matches!(
            error,
            WalletError::Keystore(KeystoreError::PasswordRequired)
        ));

        write_wallet(&path, &record, Some("secret"), false).expect("write encrypted wallet");
        let error = read_wallet(&path, None).expect_err("password required");
        assert!(matches!(
            error,
            WalletError::Keystore(KeystoreError::PasswordRequired)
        ));
    }

    #[test]
    fn insecure_wallet_round_trips_without_password() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("wallets/dev/wallet.json");
        let record = sample_record("dev");

        write_wallet(&path, &record, None, true).expect("write insecure wallet");
        let raw = fs::read_to_string(&path).expect("read envelope");
        assert!(raw.contains("\"insecure\": true"));
        assert!(raw.contains(&record.private_key_hex));

        let loaded = read_wallet(&path, None).expect("read insecure wallet");
        assert_eq!(loaded, record);
    }

    #[test]
    fn invalid_envelopes_are_rejected_before_decryption() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("wallet.json");

        fs::write(&path, "not json").expect("write invalid json");
        let error = read_wallet(&path, Some("secret")).expect_err("invalid json");
        assert!(matches!(error, WalletError::Json { .. }));

        fs::write(
            &path,
            serde_json::json!({
                "version": 2,
                "kdf": "argon2id",
                "salt": "00",
                "nonce": "00",
                "ciphertext": "00"
            })
            .to_string(),
        )
        .expect("write unsupported envelope");
        let error = read_wallet(&path, Some("secret")).expect_err("unsupported version");
        assert_invalid_envelope(error, "unsupported keystore version");

        fs::write(
            &path,
            serde_json::json!({
                "version": 1,
                "kdf": "argon2id",
                "salt": "zz",
                "nonce": "00",
                "ciphertext": "00"
            })
            .to_string(),
        )
        .expect("write invalid salt");
        let error = read_wallet(&path, Some("secret")).expect_err("invalid salt");
        assert_invalid_envelope(error, "invalid salt");

        fs::write(
            &path,
            serde_json::json!({
                "version": 1,
                "kdf": "argon2id",
                "salt": "00",
                "nonce": "00",
                "ciphertext": "00"
            })
            .to_string(),
        )
        .expect("write invalid lengths");
        let error = read_wallet(&path, Some("secret")).expect_err("invalid length");
        assert_invalid_envelope(error, "invalid salt or nonce length");
    }

    #[test]
    fn decrypt_record_rejects_tampered_ciphertext() {
        let record = sample_record("tampered");
        let mut envelope = encrypt_record(&record, "secret").expect("encrypt");
        envelope.ciphertext = "00".repeat(envelope.ciphertext.len() / 2);

        let error = decrypt_record(&envelope, "secret").expect_err("tampered ciphertext");
        assert!(matches!(error, KeystoreError::DecryptFailed));
    }

    #[test]
    fn hex_decode_rejects_malformed_values() {
        assert_eq!(hex_decode("00ff").expect("hex"), vec![0, 255]);
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("zz").is_err());
    }
}
