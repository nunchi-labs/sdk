#[cfg(test)]
mod tests {
    use crate::{Address, SignedTransaction, KeyPair, sign_transfer, generate_ed25519_keypair, import_private_key, COINS_NAMESPACE};
    use commonware_codec::Encode;
    use commonware_cryptography::Hasher;
    use nunchi_common::{Address as NunchiAddress, Authorization, Transaction, TransactionPayload};
    use nunchi_crypto::PrivateKey as NunchiPrivateKey;

    #[test]
    fn test_keygen_produces_unique_keys() {
        let key1 = generate_ed25519_keypair().unwrap();
        let key2 = generate_ed25519_keypair().unwrap();
        
        let k1: KeyPair = serde_wasm_bindgen::from_value(key1).unwrap();
        let k2: KeyPair = serde_wasm_bindgen::from_value(key2).unwrap();
        
        assert_ne!(k1.private_key_hex, k2.private_key_hex, "Keys must be unique");
        assert_ne!(k1.address, k2.address, "Addresses must be unique");
    }

    #[test]
    fn test_keygen_produces_33_byte_ed25519_key() {
        let key = generate_ed25519_keypair().unwrap();
        let k: KeyPair = serde_wasm_bindgen::from_value(key).unwrap();
        
        let bytes = hex::decode(&k.private_key_hex).unwrap();
        assert_eq!(bytes.len(), 33, "Ed25519 private key must be 33 bytes (tag + 32)");
        assert_eq!(bytes[0], 1, "Ed25519 tag must be 1");
    }

    #[test]
    fn test_keygen_not_from_seed_of_first_8_bytes() {
        let key = generate_ed25519_keypair().unwrap();
        let k: KeyPair = serde_wasm_bindgen::from_value(key).unwrap();
        
        let bytes = hex::decode(&k.private_key_hex).unwrap();
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&bytes[1..9]);
        let seed = u64::from_le_bytes(seed_bytes);
        
        let seed_key = NunchiPrivateKey::ed25519_from_seed(seed);
        let seed_addr = NunchiAddress::external(&seed_key.public_key());
        
        assert_ne!(k.address, seed_addr.to_bech32(), "Real key must not equal from_seed of first 8 bytes");
    }

    #[test]
    fn test_address_matches_nunchi_common_from_seed() {
        let seed = 1u64;
        let nunchi_key = NunchiPrivateKey::ed25519_from_seed(seed);
        let nunchi_pub = nunchi_key.public_key();
        let nunchi_addr = NunchiAddress::external(&nunchi_pub);
        
        let wasm_result = import_private_key(&hex::encode(nunchi_key.encode())).unwrap();
        let wasm: KeyPair = serde_wasm_bindgen::from_value(wasm_result).unwrap();
        
        assert_eq!(wasm.address, nunchi_addr.to_bech32(), "WASM address must match nunchi_common");
    }

    #[test]
    fn test_sign_transfer_matches_official_transaction_sign() {
        let seed = 42u64;
        let nunchi_key = NunchiPrivateKey::ed25519_from_seed(seed);
        let from_addr = NunchiAddress::external(&nunchi_key.public_key());
        
        let to_key = NunchiPrivateKey::ed25519_from_seed(99);
        let to_addr = NunchiAddress::external(&to_key.public_key());
        
        let coin_id = [0u8; 32];
        let nonce = 5u64;
        let amount = 1000u128;
        
        let operation = {
            let mut buf = Vec::new();
            buf.push(3);
            buf.extend_from_slice(&coin_id);
            buf.extend_from_slice(from_addr.encode().as_ref());
            buf.extend_from_slice(to_addr.encode().as_ref());
            buf.extend_from_slice(&amount.encode());
            buf
        };
        
        let payload = TransactionPayload::new(nonce, operation);
        let signature = nunchi_key.sign(COINS_NAMESPACE, &{
            let mut bytes = Vec::new();
            bytes.extend_from_slice(from_addr.encode().as_ref());
            bytes.push(0);
            bytes.extend_from_slice(&payload.nonce.encode());
            bytes.extend_from_slice(payload.operation.as_ref());
            bytes
        });
        
        let authorization = Authorization::Single {
            signer: Box::new(nunchi_key.public_key()),
            signature,
        };
        
        let official_tx = Transaction {
            account_id: from_addr.clone(),
            payload,
            authorization,
        };
        
        let official_bytes = official_tx.encode();
        let official_digest = commonware_cryptography::Sha256::hash(&official_bytes);
        
        let wasm_result = sign_transfer(
            &hex::encode(nunchi_key.encode()),
            nonce,
            &hex::encode(coin_id),
            &from_addr.to_bech32(),
            &to_addr.to_bech32(),
            &amount.to_string(),
        ).unwrap();
        
        let wasm: SignedTransaction = serde_wasm_bindgen::from_value(wasm_result).unwrap();
        let wasm_bytes = hex::decode(&wasm.transaction_hex).unwrap();
        let wasm_digest = hex::decode(&wasm.digest_hex).unwrap();
        
        assert_eq!(wasm_bytes, official_bytes, "WASM transaction bytes must match official Transaction::sign");
        assert_eq!(wasm_digest.as_slice(), official_digest.as_ref(), "WASM digest must match official digest");
    }

    #[test]
    fn test_sign_transfer_rejects_wrong_from_address() {
        let key1 = NunchiPrivateKey::ed25519_from_seed(1);
        let key2 = NunchiPrivateKey::ed25519_from_seed(2);
        
        let _addr1 = NunchiAddress::external(&key1.public_key());
        let addr2 = NunchiAddress::external(&key2.public_key());
        
        let result = sign_transfer(
            &hex::encode(key1.encode()),
            0,
            &hex::encode([0u8; 32]),
            &addr2.to_bech32(),
            &addr2.to_bech32(),
            "100",
        );
        
        assert!(result.is_err(), "Must reject when from_address != signer address");
    }

    #[test]
    fn test_coin_id_must_be_32_bytes() {
        let key = NunchiPrivateKey::ed25519_from_seed(1);
        let addr = NunchiAddress::external(&key.public_key());
        
        let result = sign_transfer(
            &hex::encode(key.encode()),
            0,
            &hex::encode([0u8; 31]),
            &addr.to_bech32(),
            &addr.to_bech32(),
            "100",
        );
        
        assert!(result.is_err(), "Must reject CoinId that is not 32 bytes");
    }

    #[test]
    fn test_bech32_not_bech32m() {
        let key = NunchiPrivateKey::ed25519_from_seed(1);
        let addr = NunchiAddress::external(&key.public_key());
        let bech32_str = addr.to_bech32();
        
        let (hrp, bytes) = bech32::decode(&bech32_str).unwrap();
        assert_eq!(hrp.as_str(), "nch");
        
        let encoded = bech32::encode::<bech32::Bech32>(hrp, &bytes).unwrap();
        assert_eq!(encoded, bech32_str, "Must be Bech32, not Bech32m");
    }

    #[test]
    fn test_reject_wrong_hrp() {
        let valid = Address::from_bech32("nch1h2l9l85pj8u49qfgnnxc0smcccv28n8q7utwfz5zjxg8zr8xzls4gqyjq");
        assert!(valid.is_ok());
        
        let wrong_hrp = Address::from_bech32("eth1h2l9l85pj8u49qfgnnxc0smcccv28n8q7utwfz5zjxg8zr8xzls4gqyjq");
        assert!(wrong_hrp.is_err());
    }
}
