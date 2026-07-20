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
    use jsonrpsee::core::traits::ToRpcParams;

    use super::submit_transaction_params;

    #[test]
    fn submit_transaction_uses_named_rpc_parameters() {
        let params = submit_transaction_params("deadbeef".to_string()).expect("build params");
        let raw = params
            .to_rpc_params()
            .expect("serialize params")
            .expect("non-empty params");

        assert_eq!(raw.get(), r#"{"transaction":"deadbeef"}"#);
    }
}
