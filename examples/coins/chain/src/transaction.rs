use commonware_codec::EncodeSize;
use commonware_cryptography::{Hasher as _, Sha256};
use nunchi_authority::{AuthorityOperation, Transaction as AuthorityTransaction};
use nunchi_bridge::{BridgeOperation, BridgeTransaction};
use nunchi_clob::{ClobOperation, Transaction as ClobTransaction};
use nunchi_coins::{CoinOperation, Transaction as CoinTransaction};
use nunchi_common::{Address, MultisigPolicy, MAX_MULTISIG_SIGNERS};
use nunchi_crypto::PrivateKey;
use nunchi_mempool::PoolConfig;
use nunchi_oracle::{
    IntervalKey, NamespaceId, OracleOperation, Transaction as OracleTransaction, MAX_PAYLOAD_SIZE,
    MAX_PROOF_SIZE,
};

pub(crate) const TX_COIN: u8 = 0;
pub(crate) const TX_AUTHORITY: u8 = 1;
pub(crate) const TX_ORACLE: u8 = 2;
pub(crate) const TX_BRIDGE: u8 = 3;
pub(crate) const TX_CLOB: u8 = 4;

nunchi_chain::transaction_wrapper! {
    pub enum Transaction {
        Coin {
            tag: TX_COIN,
            transaction: CoinTransaction,
            operation: CoinOperation,
        },
        Authority {
            tag: TX_AUTHORITY,
            transaction: AuthorityTransaction,
            operation: AuthorityOperation,
        },
        Oracle {
            tag: TX_ORACLE,
            transaction: OracleTransaction,
            operation: OracleOperation,
        },
        Bridge {
            tag: TX_BRIDGE,
            transaction: BridgeTransaction,
            operation: BridgeOperation,
        },
        Clob {
            tag: TX_CLOB,
            transaction: ClobTransaction,
            operation: ClobOperation,
        },
    }
}

/// Mempool bounds that admit every coins-chain transaction the codec decodes.
///
/// The generic pool default is 64 KiB. A maximum oracle append (64 KiB payload
/// and 16 KiB proof) authorized by every allowed multisig signer is larger, so
/// the default pool would drop a transaction consensus can still execute.
pub fn pool_config() -> PoolConfig {
    let mut config = PoolConfig::default();
    config.max_tx_bytes = config.max_tx_bytes.max(widest_transaction_bytes());
    config
}

pub(crate) fn widest_transaction_bytes() -> usize {
    let signers: Vec<PrivateKey> = (0..u64::try_from(MAX_MULTISIG_SIGNERS).expect("signer count"))
        .map(PrivateKey::secp256r1_from_seed)
        .collect();
    let policy = MultisigPolicy::new(
        1,
        signers.iter().map(PrivateKey::public_key).collect(),
    )
    .expect("maximum signer set is a valid policy");
    let account = Address::multisig(&policy);
    let signers = signers.iter().collect::<Vec<_>>();
    let oracle = OracleTransaction::sign_multisig(
        account,
        policy,
        &signers,
        u64::MAX,
        OracleOperation::AppendRecord {
            namespace: NamespaceId(Sha256::hash(&[b"oracle-bound"])),
            interval: IntervalKey::new(u64::MAX),
            payload: vec![0; MAX_PAYLOAD_SIZE],
            proof: Some(vec![0; MAX_PROOF_SIZE]),
        },
    );
    Transaction::from(oracle).encode_size()
}
