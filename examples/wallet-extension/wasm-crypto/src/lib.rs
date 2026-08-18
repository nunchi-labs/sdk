use commonware_codec::{DecodeExt, Encode, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_crypto::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

const ADDRESS_DOMAIN: &[u8] = b"nunchi/account/v1";
const ADDRESS_EXTERNAL: u8 = 0;
pub const ADDRESS_HRP: &str = "nch";
const COINS_NAMESPACE: &[u8] = b"_NUNCHI_COINS";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address(Digest);

impl Address {
    pub fn external(public_key: &PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ADDRESS_DOMAIN);
        hasher.update(&[ADDRESS_EXTERNAL]);
        hasher.update(&public_key.encode());
        Self(hasher.finalize())
    }

    pub fn to_bech32(&self) -> String {
        let hrp = bech32::Hrp::parse(ADDRESS_HRP).expect("static HRP valid");
        bech32::encode::<bech32::Bech32>(hrp, self.encode().as_ref()).expect("address encodes")
    }

    pub fn from_bech32(value: &str) -> Result<Self, String> {
        let (hrp, bytes) = bech32::decode(value).map_err(|e| e.to_string())?;
        if hrp.as_str() != ADDRESS_HRP {
            return Err(format!("wrong HRP: expected {}, got {}", ADDRESS_HRP, hrp));
        }
        if bytes.len() != 32 {
            return Err(format!("wrong length: expected 32, got {}", bytes.len()));
        }
        let mut digest_bytes = [0u8; 32];
        digest_bytes.copy_from_slice(&bytes);
        Ok(Self(Digest::from(digest_bytes)))
    }
}

impl Write for Address {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for Address {
    type Cfg = ();
    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl FixedSize for Address {
    const SIZE: usize = 32;
}

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
    let mut seed_bytes = [0u8; 8];
    getrandom::getrandom(&mut seed_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed = u64::from_le_bytes(seed_bytes);
    
    let private_key = PrivateKey::ed25519_from_seed(seed);
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
    let mut seed_bytes = [0u8; 8];
    getrandom::getrandom(&mut seed_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let seed = u64::from_le_bytes(seed_bytes);
    
    let private_key = PrivateKey::secp256r1_from_seed(seed);
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
    let public_key = PublicKey::decode(bytes.as_ref())
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
    
    let from = Address::from_bech32(from_address)
        .map_err(|e| JsValue::from_str(&format!("invalid from address: {}", e)))?;
    let to = Address::from_bech32(to_address)
        .map_err(|e| JsValue::from_str(&format!("invalid to address: {}", e)))?;

    let amount: u128 = amount_str
        .parse()
        .map_err(|e| JsValue::from_str(&format!("invalid amount: {}", e)))?;

    let signer_public = private_key.public_key();
    let account_id = Address::external(&signer_public);
    
    let mut payload_bytes = Vec::new();
    payload_bytes.extend_from_slice(&nonce.encode());
    payload_bytes.push(3);
    payload_bytes.extend_from_slice(&coin_bytes);
    payload_bytes.extend_from_slice(from.encode().as_ref());
    payload_bytes.extend_from_slice(to.encode().as_ref());
    payload_bytes.extend_from_slice(&amount.encode());
    
    let mut signing_bytes = Vec::new();
    signing_bytes.extend_from_slice(account_id.encode().as_ref());
    signing_bytes.push(0);
    signing_bytes.extend_from_slice(&payload_bytes);
    
    let signature = private_key.sign(COINS_NAMESPACE, &signing_bytes);
    
    let mut transaction_bytes = Vec::new();
    transaction_bytes.extend_from_slice(account_id.encode().as_ref());
    transaction_bytes.extend_from_slice(&payload_bytes);
    transaction_bytes.push(0);
    transaction_bytes.extend_from_slice(&signer_public.encode());
    transaction_bytes.extend_from_slice(&signature.encode());
    
    let digest = Sha256::hash(&transaction_bytes);

    let result = SignedTransaction {
        transaction_hex: hex::encode(&transaction_bytes),
        digest_hex: hex::encode(digest.as_ref()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

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
