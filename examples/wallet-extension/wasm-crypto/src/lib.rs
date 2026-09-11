use commonware_codec::{DecodeExt, Encode, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_coins::{
    multisig_account_id, CoinId, CoinOperation, CoinSpec, MultisigPolicy, TokenFactory, TokenName,
    TokenSymbol, Transaction,
};
use nunchi_crypto::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[cfg(test)]
mod tests;

const ADDRESS_DOMAIN: &[u8] = b"nunchi/account/v1";
const ADDRESS_EXTERNAL: u8 = 0;
pub const ADDRESS_HRP: &str = "nch";
pub const COINS_NAMESPACE: &[u8] = b"_NUNCHI_COINS";

pub fn encode_varint(mut n: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if n == 0 {
            break;
        }
    }
    buf
}

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
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let mut encoded = Vec::with_capacity(33);
    encoded.push(1);
    encoded.extend_from_slice(&entropy);
    
    let private_key = PrivateKey::decode(encoded.as_ref())
        .map_err(|e| JsValue::from_str(&format!("failed to decode key: {}", e)))?;
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
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let mut encoded = Vec::with_capacity(33);
    encoded.push(2);
    encoded.extend_from_slice(&entropy);
    
    let private_key = PrivateKey::decode(encoded.as_ref())
        .map_err(|e| JsValue::from_str(&format!("failed to decode key: {}", e)))?;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

fn encode_signed(transaction: Transaction) -> SignedTransaction {
    SignedTransaction {
        transaction_hex: hex::encode(transaction.encode()),
        digest_hex: hex::encode(transaction.digest().as_ref()),
        account: None,
    }
}

fn parse_private_key(private_key_hex: &str) -> Result<PrivateKey, String> {
    let private_bytes = hex::decode(private_key_hex).map_err(|e| format!("invalid private key hex: {e}"))?;
    PrivateKey::decode(private_bytes.as_ref()).map_err(|e| format!("invalid private key: {e}"))
}

fn parse_address(value: &str, label: &str) -> Result<nunchi_coins::Address, String> {
    nunchi_coins::Address::from_bech32(value).map_err(|e| format!("invalid {label}: {e}"))
}

fn parse_coin(coin_hex: &str) -> Result<CoinId, String> {
    let coin_bytes = hex::decode(coin_hex).map_err(|e| format!("invalid coin hex: {e}"))?;
    if coin_bytes.len() != 32 {
        return Err(format!("CoinId must be exactly 32 bytes, got {}", coin_bytes.len()));
    }
    let coin_id: [u8; 32] = coin_bytes.try_into().expect("length checked");
    Ok(CoinId::from(Digest::from(coin_id)))
}

fn parse_amount(amount_str: &str) -> Result<u128, String> {
    amount_str.parse().map_err(|e| format!("invalid amount: {e}"))
}

fn parse_spec(
    symbol: &str,
    name: &str,
    decimals: u8,
    initial_supply: &str,
    max_supply: &str,
) -> Result<CoinSpec, String> {
    let max_supply = if max_supply.is_empty() {
        None
    } else {
        Some(parse_amount(max_supply)?)
    };
    Ok(CoinSpec::new(
        TokenSymbol::new(symbol).map_err(|e| e.to_string())?,
        TokenName::new(name).map_err(|e| e.to_string())?,
        decimals,
        parse_amount(initial_supply)?,
        max_supply,
    ))
}

fn parse_signers(signer_pub_keys: &str) -> Result<Vec<PublicKey>, String> {
    let mut keys = Vec::new();
    for key in signer_pub_keys
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let bytes = hex::decode(key).map_err(|e| format!("invalid signer public key hex: {e}"))?;
        keys.push(
            PublicKey::decode(bytes.as_ref()).map_err(|e| format!("invalid signer public key: {e}"))?,
        );
    }
    Ok(keys)
}

fn parse_policy(
    threshold: u16,
    signer_pub_keys: &str,
    fallback: Option<&PublicKey>,
) -> Result<MultisigPolicy, String> {
    let mut keys = parse_signers(signer_pub_keys)?;
    if keys.is_empty() {
        match fallback {
            Some(key) => keys.push(key.clone()),
            None => return Err("signer public keys are required".to_string()),
        }
    }
    MultisigPolicy::new(threshold, keys).map_err(|e| e.to_string())
}

pub fn sign_transfer_internal(
    private_key: &PrivateKey,
    nonce: u64,
    coin_id: &[u8; 32],
    from_addr: &Address,
    to_addr: &Address,
    amount: u128,
) -> Result<(Vec<u8>, Digest), String> {
    let derived_from = Address::external(&private_key.public_key());
    if &derived_from != from_addr {
        return Err("from_address does not match private key".to_string());
    }

    let transaction = Transaction::sign(
        private_key,
        nonce,
        CoinOperation::Transfer {
            coin: CoinId::from(Digest::from(*coin_id)),
            from: parse_address(&from_addr.to_bech32(), "from")?,
            to: parse_address(&to_addr.to_bech32(), "to")?,
            amount,
        },
    );
    Ok((transaction.encode().to_vec(), transaction.digest()))
}

fn to_js(result: SignedTransaction) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
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
    let private_key = parse_private_key(private_key_hex).map_err(|e| JsValue::from_str(&e))?;
    let coin = parse_coin(coin_hex).map_err(|e| JsValue::from_str(&e))?;
    let from = parse_address(from_address, "from address").map_err(|e| JsValue::from_str(&e))?;
    let to = parse_address(to_address, "to address").map_err(|e| JsValue::from_str(&e))?;
    let amount = parse_amount(amount_str).map_err(|e| JsValue::from_str(&e))?;
    if from != nunchi_coins::Address::external(&private_key.public_key()) {
        return Err(JsValue::from_str("from_address does not match private key"));
    }
    to_js(encode_signed(Transaction::sign(
        &private_key,
        nonce,
        CoinOperation::Transfer { coin, from, to, amount },
    )))
}

#[wasm_bindgen]
pub fn sign_create_token(
    private_key_hex: &str,
    nonce: u64,
    symbol: &str,
    name: &str,
    decimals: u8,
    initial_supply: &str,
    max_supply: &str,
) -> Result<JsValue, JsValue> {
    let private_key = parse_private_key(private_key_hex).map_err(|e| JsValue::from_str(&e))?;
    let spec = parse_spec(symbol, name, decimals, initial_supply, max_supply).map_err(|e| JsValue::from_str(&e))?;
    to_js(encode_signed(Transaction::sign(
        &private_key,
        nonce,
        CoinOperation::CreateToken { spec },
    )))
}

#[wasm_bindgen]
pub fn sign_mint(
    private_key_hex: &str,
    nonce: u64,
    coin_hex: &str,
    to_address: &str,
    amount_str: &str,
) -> Result<JsValue, JsValue> {
    let private_key = parse_private_key(private_key_hex).map_err(|e| JsValue::from_str(&e))?;
    let coin = parse_coin(coin_hex).map_err(|e| JsValue::from_str(&e))?;
    let to = parse_address(to_address, "to address").map_err(|e| JsValue::from_str(&e))?;
    let amount = parse_amount(amount_str).map_err(|e| JsValue::from_str(&e))?;
    to_js(encode_signed(Transaction::sign(
        &private_key,
        nonce,
        CoinOperation::Mint { coin, to, amount },
    )))
}

#[wasm_bindgen]
pub fn sign_burn(
    private_key_hex: &str,
    nonce: u64,
    coin_hex: &str,
    from_address: &str,
    amount_str: &str,
) -> Result<JsValue, JsValue> {
    let private_key = parse_private_key(private_key_hex).map_err(|e| JsValue::from_str(&e))?;
    let coin = parse_coin(coin_hex).map_err(|e| JsValue::from_str(&e))?;
    let from = parse_address(from_address, "from address").map_err(|e| JsValue::from_str(&e))?;
    let amount = parse_amount(amount_str).map_err(|e| JsValue::from_str(&e))?;
    if from != nunchi_coins::Address::external(&private_key.public_key()) {
        return Err(JsValue::from_str("from_address does not match private key"));
    }
    to_js(encode_signed(Transaction::sign(
        &private_key,
        nonce,
        CoinOperation::Burn { coin, from, amount },
    )))
}

#[wasm_bindgen]
pub fn derive_multisig_account(threshold: u16, signer_pub_keys: &str) -> Result<String, JsValue> {
    let policy =
        parse_policy(threshold, signer_pub_keys, None).map_err(|e| JsValue::from_str(&e))?;
    Ok(multisig_account_id(&policy).to_bech32())
}

#[wasm_bindgen]
pub fn sign_register_account_policy(
    private_key_hex: &str,
    nonce: u64,
    threshold: u16,
    signer_pub_keys: &str,
) -> Result<JsValue, JsValue> {
    let private_key = parse_private_key(private_key_hex).map_err(|e| JsValue::from_str(&e))?;
    let policy = parse_policy(threshold, signer_pub_keys, Some(&private_key.public_key()))
        .map_err(|e| JsValue::from_str(&e))?;
    let account_id = multisig_account_id(&policy);
    let transaction = Transaction::sign_multisig(
        account_id.clone(),
        policy.clone(),
        &[&private_key],
        nonce,
        CoinOperation::RegisterAccountPolicy {
            account_id: account_id.clone(),
            policy,
        },
    );
    to_js(SignedTransaction {
        transaction_hex: hex::encode(transaction.encode()),
        digest_hex: hex::encode(transaction.digest().as_ref()),
        account: Some(account_id.to_bech32()),
    })
}

#[wasm_bindgen]
pub fn derive_coin_id(
    issuer: &str,
    nonce: u64,
    symbol: &str,
    name: &str,
    decimals: u8,
    initial_supply: &str,
    max_supply: &str,
) -> Result<String, JsValue> {
    let issuer = parse_address(issuer, "issuer").map_err(|e| JsValue::from_str(&e))?;
    let spec = parse_spec(symbol, name, decimals, initial_supply, max_supply).map_err(|e| JsValue::from_str(&e))?;
    Ok(hex::encode(TokenFactory::derive_coin_id(&issuer, nonce, &spec).encode()))
}

