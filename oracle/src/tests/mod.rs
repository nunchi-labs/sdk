use std::collections::BTreeMap;

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use futures::executor::block_on;
use nunchi_common::{Address, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;

use crate::{
    IntervalKey, NamespaceId, NamespacePolicy, NamespacePolicyGenesis, OracleError, OracleGenesis,
    OracleLedger, OracleNamespaceGenesis, OracleOperation, OracleWriterGenesis, Transaction,
};

#[derive(Default)]
struct MemoryStore {
    values: BTreeMap<Digest, Option<Vec<u8>>>,
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
    }
}

fn policy(admin: &Address) -> NamespacePolicy {
    NamespacePolicy {
        admin: admin.clone(),
        max_payload_size: 1024,
    }
}

fn genesis(admin: &PrivateKey, writer: &PrivateKey) -> OracleGenesis {
    OracleGenesis {
        namespaces: vec![OracleNamespaceGenesis {
            namespace: namespace(),
            policy: NamespacePolicyGenesis {
                admin: Address::external(&admin.public_key()),
                max_payload_size: 1024,
            },
            writers: vec![OracleWriterGenesis {
                writer: Address::external(&writer.public_key()),
                enabled: true,
            }],
        }],
    }
}

fn sign(signer: &PrivateKey, nonce: u64, operation: OracleOperation) -> Transaction {
    Transaction::sign(signer, nonce, operation)
}

fn configure_tx(admin: &PrivateKey, nonce: u64) -> Transaction {
    sign(
        admin,
        nonce,
        OracleOperation::ConfigureNamespace {
            namespace: namespace(),
            policy: policy(&Address::external(&admin.public_key())),
        },
    )
}

fn set_writer_tx(admin: &PrivateKey, writer: &PrivateKey, nonce: u64) -> Transaction {
    sign(
        admin,
        nonce,
        OracleOperation::SetWriter {
            namespace: namespace(),
            writer: Address::external(&writer.public_key()),
            enabled: true,
        },
    )
}

fn unset_writer_tx(admin: &PrivateKey, writer: &PrivateKey, nonce: u64) -> Transaction {
    sign(
        admin,
        nonce,
        OracleOperation::SetWriter {
            namespace: namespace(),
            writer: Address::external(&writer.public_key()),
            enabled: false,
        },
    )
}

fn append_tx(
    writer: &PrivateKey,
    nonce: u64,
    namespace: NamespaceId,
    interval: u64,
    payload: Vec<u8>,
) -> Transaction {
    sign(
        writer,
        nonce,
        OracleOperation::AppendRecord {
            namespace,
            interval: IntervalKey::new(interval),
            payload,
            proof: None,
        },
    )
}

fn initialized() -> (OracleLedger<MemoryStore>, PrivateKey, PrivateKey) {
    let admin = PrivateKey::from_seed(1);
    let writer = PrivateKey::from_seed(2);
    let mut ledger = OracleLedger::new(MemoryStore::default());
    block_on(ledger.apply_transaction(&configure_tx(&admin, 0), context(100))).unwrap();
    block_on(ledger.apply_transaction(&set_writer_tx(&admin, &writer, 1), context(100))).unwrap();
    (ledger, admin, writer)
}

#[test]
fn authorized_writer_appends_opaque_payload() {
    let (mut ledger, _, writer) = initialized();

    let tx = append_tx(&writer, 0, namespace(), 3, b"\xffprice? no idea".to_vec());
    block_on(ledger.apply_transaction(&tx, context(1_000))).unwrap();

    let records = block_on(ledger.records_by_namespace(
        &namespace(),
        IntervalKey::new(3),
        IntervalKey::new(3),
    ))
    .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].writer, Address::external(&writer.public_key()));
    assert_eq!(records[0].namespace, namespace());
    assert_eq!(records[0].interval, IntervalKey::new(3));
    assert_eq!(records[0].payload, b"\xffprice? no idea");
    assert_eq!(records[0].written_at_height, 7);
    assert_eq!(records[0].written_at_ms, 1_000);
}

#[test]
fn unauthorized_writer_is_rejected() {
    let (mut ledger, _, _) = initialized();
    let attacker = PrivateKey::from_seed(3);

    let tx = append_tx(&attacker, 0, namespace(), 3, b"payload".to_vec());
    let err = block_on(ledger.apply_transaction(&tx, context(1_000))).unwrap_err();

    assert_eq!(err, OracleError::Unauthorized);
}

#[test]
fn disabled_writer_cannot_append() {
    let (mut ledger, admin, writer) = initialized();

    let first = append_tx(&writer, 0, namespace(), 3, b"first".to_vec());
    block_on(ledger.apply_transaction(&first, context(1_000))).unwrap();
    block_on(ledger.apply_transaction(&unset_writer_tx(&admin, &writer, 2), context(1_100)))
        .unwrap();

    let second = append_tx(&writer, 1, namespace(), 3, b"second".to_vec());
    let err = block_on(ledger.apply_transaction(&second, context(1_200))).unwrap_err();

    assert_eq!(err, OracleError::Unauthorized);
    let records = block_on(ledger.records_by_namespace(
        &namespace(),
        IntervalKey::new(3),
        IntervalKey::new(3),
    ))
    .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payload, b"first");
}

#[test]
fn multiple_payload_formats_coexist_without_decoding() {
    let (mut ledger, _, writer) = initialized();

    let signed_price_like = (-123_i128).encode().as_ref().to_vec();
    let text_like = br#"{"kind":"research","score":42}"#.to_vec();
    block_on(ledger.apply_transaction(
        &append_tx(&writer, 0, namespace(), 10, signed_price_like.clone()),
        context(1_000),
    ))
    .unwrap();
    block_on(ledger.apply_transaction(
        &append_tx(&writer, 1, namespace(), 10, text_like.clone()),
        context(1_100),
    ))
    .unwrap();

    let records = block_on(ledger.records_by_namespace(
        &namespace(),
        IntervalKey::new(10),
        IntervalKey::new(10),
    ))
    .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].payload, signed_price_like);
    assert_eq!(records[1].payload, text_like);
}

#[test]
fn query_by_writer_spans_intervals() {
    let (mut ledger, _, writer) = initialized();
    block_on(ledger.apply_transaction(
        &append_tx(&writer, 0, namespace(), 1, b"one".to_vec()),
        context(1_000),
    ))
    .unwrap();
    block_on(ledger.apply_transaction(
        &append_tx(&writer, 1, namespace(), 3, b"three".to_vec()),
        context(3_000),
    ))
    .unwrap();

    let records = block_on(ledger.records_by_writer(
        &Address::external(&writer.public_key()),
        IntervalKey::new(1),
        IntervalKey::new(3),
    ))
    .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].payload, b"one");
    assert_eq!(records[1].payload, b"three");
}

#[test]
fn namespace_policy_is_independent_per_namespace() {
    let (mut ledger, admin, writer) = initialized();
    let other_admin = PrivateKey::from_seed(4);
    block_on(ledger.apply_transaction(
        &sign(
            &other_admin,
            0,
            OracleOperation::ConfigureNamespace {
                namespace: other_namespace(),
                policy: policy(&Address::external(&other_admin.public_key())),
            },
        ),
        context(100),
    ))
    .unwrap();

    let err = block_on(ledger.apply_transaction(
        &sign(
            &admin,
            2,
            OracleOperation::SetWriter {
                namespace: other_namespace(),
                writer: Address::external(&writer.public_key()),
                enabled: true,
            },
        ),
        context(100),
    ))
    .unwrap_err();
    assert_eq!(err, OracleError::Unauthorized);
}

#[test]
fn transaction_codec_round_trips() {
    let admin = PrivateKey::from_seed(1);
    let tx = configure_tx(&admin, 0);
    let encoded = tx.encode();

    assert_eq!(Transaction::decode(encoded).unwrap(), tx);
}

#[test]
fn genesis_seeds_namespace_and_writer_policy() {
    let admin = PrivateKey::from_seed(1);
    let writer = PrivateKey::from_seed(2);
    let mut ledger = OracleLedger::new(MemoryStore::default());

    block_on(ledger.apply_genesis(&genesis(&admin, &writer))).unwrap();
    let tx = append_tx(&writer, 0, namespace(), 1, b"from-genesis".to_vec());
    block_on(ledger.apply_transaction(&tx, context(1_000))).unwrap();

    let records = block_on(ledger.records_by_namespace(
        &namespace(),
        IntervalKey::new(1),
        IntervalKey::new(1),
    ))
    .unwrap();
    assert_eq!(records[0].payload, b"from-genesis");
}

#[test]
fn genesis_rejects_duplicate_namespace() {
    let admin = PrivateKey::from_seed(1);
    let writer = PrivateKey::from_seed(2);
    let mut genesis = genesis(&admin, &writer);
    genesis.namespaces.push(genesis.namespaces[0].clone());
    let mut ledger = OracleLedger::new(MemoryStore::default());

    assert!(matches!(
        block_on(ledger.apply_genesis(&genesis)).unwrap_err(),
        OracleError::InvalidGenesis(_)
    ));
}
