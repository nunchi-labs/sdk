use std::{collections::BTreeMap, future::Future};

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::{Address, NoFee, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;

use crate::{
    IntervalKey, NamespaceId, OracleError, OracleGenesis, OracleLedger, OracleOperation,
    Transaction, MAX_PAYLOAD_SIZE, MAX_PROOF_SIZE,
};

#[derive(Default)]
struct MemoryStore {
    values: BTreeMap<Digest, Option<Vec<u8>>>,
}

fn run_test<F, Fut>(test: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    deterministic::Runner::default().start(|_| test());
}

impl StateStore for MemoryStore {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.values.get(key).cloned().flatten())
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        self.values.insert(key, Some(value));
    }

    fn remove(&mut self, key: Digest) {
        self.values.insert(key, None);
    }
}

fn id(seed: &'static [u8]) -> Digest {
    Sha256::hash(seed)
}

fn namespace() -> NamespaceId {
    NamespaceId(id(b"namespace"))
}

fn other_namespace() -> NamespaceId {
    NamespaceId(id(b"other-namespace"))
}

fn context(timestamp_ms: u64) -> RuntimeContext {
    RuntimeContext {
        epoch: 0,
        height: 7,
        timestamp_ms,
        block_digest: None,
    }
}

fn sign(signer: &PrivateKey, nonce: u64, operation: OracleOperation) -> Transaction {
    Transaction::sign(signer, nonce, NoFee, operation)
}

fn append_tx(
    writer: &PrivateKey,
    nonce: u64,
    namespace: NamespaceId,
    interval: u64,
    payload: Vec<u8>,
) -> Transaction {
    append_tx_with_proof(writer, nonce, namespace, interval, payload, None)
}

fn append_tx_with_proof(
    writer: &PrivateKey,
    nonce: u64,
    namespace: NamespaceId,
    interval: u64,
    payload: Vec<u8>,
    proof: Option<Vec<u8>>,
) -> Transaction {
    sign(
        writer,
        nonce,
        OracleOperation::AppendRecord {
            namespace,
            interval: IntervalKey::new(interval),
            payload,
            proof,
        },
    )
}

#[test]
fn writer_appends_to_unconfigured_namespace() {
    run_test(|| async {
        let writer = PrivateKey::from_seed(2);
        let mut ledger = OracleLedger::new(MemoryStore::default());

        let tx = append_tx(&writer, 0, namespace(), 3, b"\xffprice? no idea".to_vec());
        ledger.apply_transaction(&tx, context(1_000)).await.unwrap();

        let records = ledger
            .records_by_namespace(&namespace(), IntervalKey::new(3), IntervalKey::new(3))
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].writer, Address::external(&writer.public_key()));
        assert_eq!(records[0].namespace, namespace());
        assert_eq!(records[0].interval, IntervalKey::new(3));
        assert_eq!(records[0].payload, b"\xffprice? no idea");
        assert_eq!(records[0].written_at_height, 7);
        assert_eq!(records[0].written_at_ms, 1_000);
    });
}

#[test]
fn multiple_writers_append_to_same_namespace() {
    run_test(|| async {
        let first = PrivateKey::from_seed(2);
        let second = PrivateKey::from_seed(3);
        let mut ledger = OracleLedger::new(MemoryStore::default());

        ledger
            .apply_transaction(
                &append_tx(&first, 0, namespace(), 3, b"first".to_vec()),
                context(1_000),
            )
            .await
            .unwrap();
        ledger
            .apply_transaction(
                &append_tx(&second, 0, namespace(), 3, b"second".to_vec()),
                context(1_100),
            )
            .await
            .unwrap();

        let records = ledger
            .records_by_namespace(&namespace(), IntervalKey::new(3), IntervalKey::new(3))
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].payload, b"first");
        assert_eq!(records[1].payload, b"second");
    });
}

#[test]
fn multiple_payload_formats_coexist_without_decoding() {
    run_test(|| async {
        let writer = PrivateKey::from_seed(2);
        let mut ledger = OracleLedger::new(MemoryStore::default());

        let signed_price_like = (-123_i128).encode().as_ref().to_vec();
        let text_like = br#"{"kind":"research","score":42}"#.to_vec();
        ledger
            .apply_transaction(
                &append_tx(&writer, 0, namespace(), 10, signed_price_like.clone()),
                context(1_000),
            )
            .await
            .unwrap();
        ledger
            .apply_transaction(
                &append_tx(&writer, 1, namespace(), 10, text_like.clone()),
                context(1_100),
            )
            .await
            .unwrap();

        let records = ledger
            .records_by_namespace(&namespace(), IntervalKey::new(10), IntervalKey::new(10))
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].payload, signed_price_like);
        assert_eq!(records[1].payload, text_like);
    });
}

#[test]
fn query_by_writer_spans_intervals() {
    run_test(|| async {
        let writer = PrivateKey::from_seed(2);
        let mut ledger = OracleLedger::new(MemoryStore::default());
        ledger
            .apply_transaction(
                &append_tx(&writer, 0, namespace(), 1, b"one".to_vec()),
                context(1_000),
            )
            .await
            .unwrap();
        ledger
            .apply_transaction(
                &append_tx(&writer, 1, other_namespace(), 3, b"three".to_vec()),
                context(3_000),
            )
            .await
            .unwrap();

        let records = ledger
            .records_by_writer(
                &Address::external(&writer.public_key()),
                IntervalKey::new(1),
                IntervalKey::new(3),
            )
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].payload, b"one");
        assert_eq!(records[1].payload, b"three");
    });
}

#[test]
fn payload_and_proof_limits_are_global() {
    run_test(|| async {
        let writer = PrivateKey::from_seed(2);
        let mut ledger = OracleLedger::new(MemoryStore::default());

        let payload = vec![0; MAX_PAYLOAD_SIZE + 1];
        let err = ledger
            .apply_transaction(
                &append_tx(&writer, 0, namespace(), 1, payload),
                context(1_000),
            )
            .await
            .unwrap_err();
        assert_eq!(err, OracleError::PayloadTooLarge);

        let proof = Some(vec![0; MAX_PROOF_SIZE + 1]);
        let err = ledger
            .apply_transaction(
                &append_tx_with_proof(&writer, 0, namespace(), 1, Vec::new(), proof),
                context(1_000),
            )
            .await
            .unwrap_err();
        assert_eq!(err, OracleError::ProofTooLarge);
    });
}

#[test]
fn transaction_codec_round_trips() {
    let writer = PrivateKey::from_seed(1);
    let tx = append_tx(&writer, 0, namespace(), 3, b"payload".to_vec());
    let encoded = tx.encode();

    assert_eq!(Transaction::decode(encoded).unwrap(), tx);
}

#[test]
fn genesis_is_noop_for_permissionless_oracle() {
    run_test(|| async {
        let writer = PrivateKey::from_seed(2);
        let mut ledger = OracleLedger::new(MemoryStore::default());

        ledger.apply_genesis(&OracleGenesis {}).await.unwrap();
        ledger
            .apply_transaction(
                &append_tx(&writer, 0, namespace(), 1, b"from-genesis".to_vec()),
                context(1_000),
            )
            .await
            .unwrap();

        let records = ledger
            .records_by_namespace(&namespace(), IntervalKey::new(1), IntervalKey::new(1))
            .await
            .unwrap();
        assert_eq!(records[0].payload, b"from-genesis");
    });
}
