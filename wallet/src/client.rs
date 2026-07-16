use commonware_codec::Encode;
use commonware_cryptography::sha256::Digest;
use jsonrpsee::{core::client::ClientT, http_client::HttpClient, rpc_params};
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
            .build(rpc_url.as_ref().to_string())
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
    let response: SubmitTransactionResponse = client
        .request("coins.submit_transaction", rpc_params![("transaction", encoded)])
        .await
        .map_err(|err| ClientError::Rpc(err.to_string()))?;
    Ok(response)
}

pub fn parse_coin_id_hex(value: &str) -> Result<nunchi_coins::CoinId, ClientError> {
    nunchi_rpc::decode_hex(value, "coin id").map_err(|err| ClientError::CoinId(err.to_string()))
}

pub fn transaction_digest_hex(transaction: &Transaction) -> String {
    let digest: Digest = transaction.digest();
    encode_hex(&digest)
}
