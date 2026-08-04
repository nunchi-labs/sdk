use commonware_codec::Encode;
use commonware_cryptography::sha256::Digest;
use jsonrpsee::{
    core::{client::ClientT, params::ObjectParams},
    http_client::HttpClient,
};
use nunchi_coins::{CoinOperation, Transaction};
use nunchi_common::Address;
use nunchi_crypto::PrivateKey;
use nunchi_rpc::encode_hex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct WalletRpcClient {
    http: HttpClient,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitTransactionResponse {
    pub hash: String,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("rpc client error: {0}")]
    Rpc(String),
    #[error("invalid address: {0}")]
    Address(String),
    #[error("invalid coin id: {0}")]
    CoinId(String),
    #[error("amount is not a valid u128")]
    InvalidAmount,
}

impl WalletRpcClient {
    pub fn new(rpc_url: impl AsRef<str>) -> Result<Self, ClientError> {
        let http = HttpClient::builder()
            .build(rpc_url.as_ref())
            .map_err(|err| ClientError::Rpc(err.to_string()))?;
        Ok(Self { http })
    }

    pub async fn submit_coins_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<SubmitTransactionResponse, ClientError> {
        submit_coins_transaction(&self.http, transaction).await
    }

    pub fn build_transfer(
        signer: &PrivateKey,
        chain_id: u64,
        nonce: u64,
        coin: nunchi_coins::CoinId,
        from: Address,
        to: Address,
        amount: u128,
    ) -> Transaction {
        Transaction::sign(
            signer,
            chain_id,
            nonce,
            CoinOperation::Transfer {
                coin,
                from,
                to,
                amount,
            },
        )
    }
}

pub async fn submit_coins_transaction(
    client: &HttpClient,
    transaction: &Transaction,
) -> Result<SubmitTransactionResponse, ClientError> {
    let encoded = encode_hex(&transaction.encode());
    let params = submit_transaction_params(encoded)?;
    let response: SubmitTransactionResponse = client
        .request("coins.submit_transaction", params)
        .await
        .map_err(|err| ClientError::Rpc(err.to_string()))?;
    Ok(response)
}

fn submit_transaction_params(transaction: String) -> Result<ObjectParams, ClientError> {
    let mut params = ObjectParams::new();
    params
        .insert("transaction", transaction)
        .map_err(|err| ClientError::Rpc(err.to_string()))?;
    Ok(params)
}

pub fn parse_coin_id_hex(value: &str) -> Result<nunchi_coins::CoinId, ClientError> {
    nunchi_rpc::decode_hex(value, "coin id").map_err(|err| ClientError::CoinId(err.to_string()))
}

pub fn transaction_digest_hex(transaction: &Transaction) -> String {
    let digest: Digest = transaction.digest();
    encode_hex(&digest)
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::sha256::Digest;
    use jsonrpsee::core::traits::ToRpcParams;
    use nunchi_coins::{CoinId, CoinOperation};
    use nunchi_common::Address;
    use nunchi_crypto::PrivateKey;

    use super::{
        parse_coin_id_hex, submit_transaction_params, transaction_digest_hex, ClientError,
        WalletRpcClient,
    };

    #[test]
    fn submit_transaction_uses_named_rpc_parameters() {
        let params = submit_transaction_params("deadbeef".to_string()).expect("build params");
        let raw = params
            .to_rpc_params()
            .expect("serialize params")
            .expect("non-empty params");

        assert_eq!(raw.get(), r#"{"transaction":"deadbeef"}"#);
    }

    #[test]
    fn parses_coin_id_and_builds_chain_bound_transfer() {
        let signer = PrivateKey::from_seed(41);
        let from = Address::external(&signer.public_key());
        let to = Address::external(&PrivateKey::from_seed(42).public_key());
        let coin_hex = "11".repeat(32);
        let coin = parse_coin_id_hex(&coin_hex).expect("coin id");
        assert_eq!(coin, CoinId(Digest([0x11; 32])));

        let tx =
            WalletRpcClient::build_transfer(&signer, 17, 3, coin, from.clone(), to.clone(), 250);
        assert_eq!(tx.account_id, from);
        assert_eq!(tx.payload.chain_id, 17);
        assert_eq!(tx.payload.nonce, 3);
        match &tx.payload.operation {
            CoinOperation::Transfer {
                coin: actual_coin,
                from: actual_from,
                to: actual_to,
                amount,
            } => {
                assert_eq!(*actual_coin, coin);
                assert_eq!(*actual_from, from);
                assert_eq!(*actual_to, to);
                assert_eq!(*amount, 250);
            }
            other => panic!("expected transfer, got {other:?}"),
        }
        tx.verify().expect("transaction verifies");

        let digest = transaction_digest_hex(&tx);
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn client_helpers_report_invalid_inputs() {
        let error = WalletRpcClient::new("not a url").expect_err("invalid URL");
        assert!(matches!(error, ClientError::Rpc(_)));

        let error = parse_coin_id_hex("not hex").expect_err("invalid coin id");
        assert!(matches!(error, ClientError::CoinId(_)));
    }
}
