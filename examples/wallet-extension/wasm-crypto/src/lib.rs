use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::Hasher;
use nunchi_coins::{Address, CoinId, CoinOperation, PrivateKey, Transaction};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    pub curve: String,
    pub private_key_hex: String,
    pub public_key_hex: String,
    pub address: String,
}

#[wasm_bindgen]
pub fn generate_ed25519_keypair() -> Result<JsValue, JsValue> {
    let mut rng = rand::thread_rng();
    let private_key = nunchi_crypto::PrivateKey::Ed25519(
        commonware_cryptography::ed25519::PrivateKey::random(&mut rng),
    );
    let public_key = private_key.public_key();
    let address = Address::external(&public_key);

    let result = KeyPair {
        curve: "Ed25519".to_string(),
        private_key_hex: hex::encode(private_key.encode()),
        public_key_hex: hex::encode(public_key.encode()),
        address: address.to_bech32(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn generate_secp256r1_keypair() -> Result<JsValue, JsValue> {
    let mut rng = rand::thread_rng();
    let private_key = nunchi_crypto::PrivateKey::Secp256r1(
        commonware_cryptography::secp256r1::standard::PrivateKey::random(&mut rng),
    );
    let public_key = private_key.public_key();
    let address = Address::external(&public_key);

    let result = KeyPair {
        curve: "Secp256r1".to_string(),
        private_key_hex: hex::encode(private_key.encode()),
        public_key_hex: hex::encode(public_key.encode()),
        address: address.to_bech32(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn import_private_key(private_key_hex: &str) -> Result<JsValue, JsValue> {
    let bytes = hex::decode(private_key_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid hex: {}", e)))?;
    let private_key = PrivateKey::decode(bytes.as_ref())
        .map_err(|e| JsValue::from_str(&format!("invalid private key: {}", e)))?;
    let public_key = private_key.public_key();
    let address = Address::external(&public_key);

    let curve = match private_key {
        PrivateKey::Ed25519(_) => "Ed25519",
        PrivateKey::Secp256r1(_) => "Secp256r1",
    };

    let result = KeyPair {
        curve: curve.to_string(),
        private_key_hex: private_key_hex.to_string(),
        public_key_hex: hex::encode(public_key.encode()),
        address: address.to_bech32(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn derive_address(public_key_hex: &str) -> Result<String, JsValue> {
    let bytes = hex::decode(public_key_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid hex: {}", e)))?;
    let public_key = nunchi_crypto::PublicKey::decode(bytes.as_ref())
        .map_err(|e| JsValue::from_str(&format!("invalid public key: {}", e)))?;
    let address = Address::external(&public_key);
    Ok(address.to_bech32())
}

#[wasm_bindgen]
pub fn validate_address(address: &str) -> bool {
    Address::from_bech32(address).is_ok()
}

#[derive(Serialize, Deserialize)]
pub struct SignedTransaction {
    pub transaction_hex: String,
    pub digest_hex: String,
}

#[wasm_bindgen]
pub fn sign_transfer(
    private_key_hex: &str,
    nonce: u64,
    coin_hex: &str,
    from_address: &str,
    to_address: &str,
    amount_str: &str,
) -> Result<JsValue, JsValue> {
    let private_bytes = hex::decode(private_key_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid private key hex: {}", e)))?;
    let private_key = PrivateKey::decode(private_bytes.as_ref())
        .map_err(|e| JsValue::from_str(&format!("invalid private key: {}", e)))?;

    let coin_bytes = hex::decode(coin_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid coin hex: {}", e)))?;
    let coin = CoinId::decode(coin_bytes.as_ref())
        .map_err(|e| JsValue::from_str(&format!("invalid coin id: {}", e)))?;

    let from = Address::from_bech32(from_address)
        .map_err(|e| JsValue::from_str(&format!("invalid from address: {}", e)))?;
    let to = Address::from_bech32(to_address)
        .map_err(|e| JsValue::from_str(&format!("invalid to address: {}", e)))?;

    let amount: u128 = amount_str
        .parse()
        .map_err(|e| JsValue::from_str(&format!("invalid amount: {}", e)))?;

    let operation = CoinOperation::Transfer {
        coin,
        from,
        to,
        amount,
    };

    let transaction = Transaction::sign(&private_key, nonce, operation);
    let digest = transaction.digest();

    let result = SignedTransaction {
        transaction_hex: hex::encode(transaction.encode()),
        digest_hex: hex::encode(digest.as_ref()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

use rand::RngCore;

struct OsRngWrapper;

impl rand::CryptoRng for OsRngWrapper {}

impl rand::RngCore for OsRngWrapper {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        getrandom::getrandom(dest).map_err(|e| {
            rand::Error::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("getrandom failed: {}", e),
            ))
        })
    }
}

mod rand {
    pub use ::rand::*;
    pub fn thread_rng() -> super::OsRngWrapper {
        super::OsRngWrapper
    }
}
