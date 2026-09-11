#[cfg(test)]
mod tests {
    use crate::{sign_transfer_internal, Address};
    use commonware_codec::Encode;
    use commonware_cryptography::{sha256::Digest, Hasher};
    use nunchi_coins::{CoinId, CoinOperation, Transaction};
    use nunchi_common::Address as NunchiAddress;
    use nunchi_crypto::PrivateKey as NunchiPrivateKey;


    #[test]
    fn test_address_matches_nunchi_common_from_seed() {
        let seed = 1u64;
        let nunchi_key = NunchiPrivateKey::ed25519_from_seed(seed);
        let nunchi_pub = nunchi_key.public_key();
        let nunchi_addr = NunchiAddress::external(&nunchi_pub);
        
        let wasm_addr = Address::external(&nunchi_pub);
        
        assert_eq!(wasm_addr.to_bech32(), nunchi_addr.to_bech32(), "WASM address must match nunchi_common");
    }

    #[test]
    fn test_sign_transfer_matches_official_ed25519() {
        let seed = 42u64;
        let nunchi_key = NunchiPrivateKey::ed25519_from_seed(seed);
        let from_addr = NunchiAddress::external(&nunchi_key.public_key());
        
        let to_key = NunchiPrivateKey::ed25519_from_seed(99);
        let to_addr = NunchiAddress::external(&to_key.public_key());
        
        let coin_id = [0u8; 32];
        let nonce = 5u64;
        let amount = 1000u128;
        
        let operation = CoinOperation::Transfer {
            coin: CoinId::from(Digest::from(coin_id)),
            from: from_addr.clone(),
            to: to_addr.clone(),
            amount,
        };
        
        let official_tx = Transaction::sign(
            &nunchi_key,
            nonce,
            operation,
        );
        
        let official_bytes = official_tx.encode();
        let official_digest = commonware_cryptography::Sha256::hash(&official_bytes);
        
        let from_wasm_addr = Address::external(&nunchi_key.public_key());
        let to_wasm_addr = Address::external(&to_key.public_key());
        
        let (wasm_bytes, wasm_digest) = sign_transfer_internal(
            &nunchi_key,
            nonce,
            &coin_id,
            &from_wasm_addr,
            &to_wasm_addr,
            amount,
        ).unwrap();
        
        assert_eq!(wasm_bytes, official_bytes, "WASM transaction bytes must match official Transaction::sign");
        assert_eq!(wasm_digest.as_ref(), official_digest.as_ref(), "WASM digest must match official digest");
    }

    #[test]
    fn test_sign_transfer_matches_official_secp256r1() {
        let seed = 42u64;
        let nunchi_key = NunchiPrivateKey::secp256r1_from_seed(seed);
        let from_addr = NunchiAddress::external(&nunchi_key.public_key());
        
        let to_key = NunchiPrivateKey::secp256r1_from_seed(99);
        let to_addr = NunchiAddress::external(&to_key.public_key());
        
        let coin_id = [1u8; 32];
        let nonce = 7u64;
        let amount = 2000u128;
        
        let operation = CoinOperation::Transfer {
            coin: CoinId::from(Digest::from(coin_id)),
            from: from_addr.clone(),
            to: to_addr.clone(),
            amount,
        };
        
        let official_tx = Transaction::sign(
            &nunchi_key,
            nonce,
            operation,
        );
        
        let official_bytes = official_tx.encode();
        let official_digest = commonware_cryptography::Sha256::hash(&official_bytes);
        
        let from_wasm_addr = Address::external(&nunchi_key.public_key());
        let to_wasm_addr = Address::external(&to_key.public_key());
        
        let (wasm_bytes, wasm_digest) = sign_transfer_internal(
            &nunchi_key,
            nonce,
            &coin_id,
            &from_wasm_addr,
            &to_wasm_addr,
            amount,
        ).unwrap();
        
        assert_eq!(wasm_bytes, official_bytes, "WASM Secp256r1 transaction bytes must match official");
        assert_eq!(wasm_digest.as_ref(), official_digest.as_ref(), "WASM Secp256r1 digest must match official");
    }

    #[test]
    fn test_sign_transfer_rejects_wrong_from_address() {
        let key1 = NunchiPrivateKey::ed25519_from_seed(1);
        let key2 = NunchiPrivateKey::ed25519_from_seed(2);
        
        let _addr1 = Address::external(&key1.public_key());
        let addr2 = Address::external(&key2.public_key());
        
        let result = sign_transfer_internal(
            &key1,
            0,
            &[0u8; 32],
            &addr2,
            &addr2,
            100,
        );
        
        assert!(result.is_err(), "Must reject when from_address != signer address");
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
        let key = NunchiPrivateKey::ed25519_from_seed(1);
        let addr = NunchiAddress::external(&key.public_key());
        let valid_bech32 = addr.to_bech32();
        
        let valid = Address::from_bech32(&valid_bech32);
        assert!(valid.is_ok(), "Valid address should parse");
        
        let wrong_hrp_str = valid_bech32.replacen("nch", "eth", 1);
        let wrong_hrp = Address::from_bech32(&wrong_hrp_str);
        assert!(wrong_hrp.is_err(), "Wrong HRP should be rejected");
    }
}
