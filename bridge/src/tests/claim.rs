use std::num::NonZeroU64;

use commonware_codec::{DecodeExt, Encode, EncodeSize};
use commonware_cryptography::{sha256, Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use nunchi_common::{
    state_db::{verify_state_update, StateError, StateProof},
    Address, CommitState, Namespace, NoopEventSink, QmdbState, StateStore, VecEventSink,
};
use nunchi_crypto::PrivateKey;

use crate::events::{TransferClaimed, TRANSFER_CLAIMED_EVENT};
use crate::genesis::BridgeGenesis;
use crate::ledger::{BridgeError, BridgeLedger, BridgeReceipt};
use crate::record::{
    consumed_record_key, foreign_chain_id, foreign_root, foreign_root_key, is_consumed,
    put_transfer_record, set_bridge_nonce, store_certified_root, transfer_record_key, AssetId,
    BridgeTransferRecord, CertifiedRootStatus, ChainId, BRIDGE_NAMESPACE,
};
use crate::transaction::{BridgeOperation, BridgeOperationId, Transaction};

fn signer(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn addr(key: &PrivateKey) -> Address {
    Address::external(&key.public_key())
}

fn source_chain() -> ChainId {
    ChainId(Sha256::hash(&[b"source-chain"]))
}

fn dest_chain() -> ChainId {
    ChainId(Sha256::hash(&[b"dest-chain"]))
}

fn sample_record(recipient: Address) -> BridgeTransferRecord {
    let source = source_chain();
    BridgeTransferRecord {
        source_chain_id: source,
        destination_chain_id: dest_chain(),
        source_asset: AssetId::derive(&source, &Sha256::hash(&[b"coin"])),
        amount: 1_000,
        sender: addr(&signer(9)),
        recipient,
        nonce: 0,
    }
}

/// Write `record` into a fresh source-chain state, commit, and produce an inclusion proof of it
/// against the committed root. Returns `(committed_root, proof)`.
async fn source_root_and_proof(
    context: &deterministic::Context,
    record: &BridgeTransferRecord,
) -> (sha256::Digest, StateProof) {
    let mut source = QmdbState::init(context.child("src"), "bridge-claim-source")
        .await
        .expect("init source");
    put_transfer_record(&mut source, record);
    let root = source.commit().await.expect("commit source");
    let bounds = source.operation_bounds();
    let proof = source
        .proof(bounds.start, NonZeroU64::new(1024).unwrap())
        .await
        .expect("proof");
    (root, proof)
}

async fn dest_state(
    context: &deterministic::Context,
    partition: &str,
) -> QmdbState<deterministic::Context> {
    let mut dest = QmdbState::init(context.child("dst"), partition)
        .await
        .expect("init dest");
    BridgeGenesis::new(dest_chain())
        .with_foreign_chain(source_chain())
        .apply(&mut dest);
    dest
}

async fn dest_ledger(
    context: &deterministic::Context,
) -> BridgeLedger<QmdbState<deterministic::Context>> {
    BridgeLedger::new(dest_state(context, "bridge-claim-dest").await)
}

async fn certify(state: &mut QmdbState<deterministic::Context>, view: u64, root: sha256::Digest) {
    assert_eq!(
        store_certified_root(state, view, root).await.expect("store root"),
        CertifiedRootStatus::Stored
    );
}

fn claim_tx(
    claimer: &PrivateKey,
    nonce: u64,
    source: ChainId,
    source_view: u64,
    record: BridgeTransferRecord,
    proof: StateProof,
) -> Transaction {
    Transaction::sign(
        claimer,
        nonce,
        BridgeOperation::Claim {
            source_chain_id: source,
            source_view,
            record,
            proof,
        },
    )
}

#[test]
fn lock_produces_a_claimable_record_proof() {
    // The record a real `BridgeOperation::Lock` writes must be provable end to end: commit the
    // source state, generate an inclusion proof, and verify it exactly as a destination claim does.
    deterministic::Runner::default().start(|context| async move {
        let mut source = QmdbState::init(context.child("src"), "lock-proof")
            .await
            .expect("init source");
        // The source chain's own id is `source_chain()`; the lock stamps it onto the record.
        BridgeGenesis::new(source_chain()).apply(&mut source);

        let alice = signer(1);
        let recipient = addr(&signer(2));
        let local_asset = Sha256::hash(&[b"coin"]);
        let mut ledger = BridgeLedger::new(source);
        let lock = Transaction::sign(
            &alice,
            0,
            BridgeOperation::Lock {
                destination_chain_id: dest_chain(),
                local_asset,
                amount: 1_000,
                recipient: recipient.clone(),
            },
        );
        let receipt = ledger
            .apply_transaction(&lock, NoopEventSink)
            .await
            .expect("lock");
        let BridgeReceipt::Locked(record_id) = receipt else {
            panic!("expected Locked receipt");
        };

        let mut source = ledger.into_inner();
        let root = source.commit().await.expect("commit source");
        let bounds = source.operation_bounds();
        let proof = source
            .proof(bounds.start, NonZeroU64::new(1024).unwrap())
            .await
            .expect("proof");

        // The record the lock wrote, reconstructed, must be authenticated by the proof.
        let record = BridgeTransferRecord {
            source_chain_id: source_chain(),
            destination_chain_id: dest_chain(),
            source_asset: AssetId::derive(&source_chain(), &local_asset),
            amount: 1_000,
            sender: addr(&alice),
            recipient,
            nonce: 0,
        };
        assert_eq!(record.record_id(), record_id);
        assert!(
            verify_state_update(
                &proof,
                &root,
                &transfer_record_key(&record_id),
                record.encode().as_ref()
            ),
            "a lock-written record must be provable to a destination claim"
        );
    });
}

#[test]
fn claim_succeeds_and_marks_consumed() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        let record = sample_record(recipient.clone());
        let (root, proof) = source_root_and_proof(&context, &record).await;
        let record_id = record.record_id();

        let mut state = dest_state(&context, "bridge-claim-dest").await;
        certify(&mut state, 7, root).await;
        let mut ledger = BridgeLedger::new(state);

        // Claim against the certified root.
        let claimer = signer(3);
        let mut claim_sink = VecEventSink::new();
        let receipt = ledger
            .apply_transaction(
                &claim_tx(&claimer, 0, source_chain(), 7, record.clone(), proof),
                &mut claim_sink,
            )
            .await
            .expect("claim");
        assert_eq!(
            receipt,
            BridgeReceipt::Claimed {
                source_asset: record.source_asset,
                recipient,
                amount: record.amount,
            }
        );

        // The claim emitted a TransferClaimed event with the settlement details.
        assert_eq!(claim_sink.len(), 1);
        let event = &claim_sink.events()[0];
        assert_eq!(event.name.as_ref(), TRANSFER_CLAIMED_EVENT);
        let decoded = TransferClaimed::decode(commonware_codec::Viewing::new(&event.value))
            .expect("decode event");
        assert_eq!(decoded.record_id, record_id);
        assert_eq!(decoded.amount, record.amount);

        // The record is now consumed.
        let mut state = ledger.into_inner();
        state.commit().await.expect("commit dest");
        assert!(is_consumed(&state, &source_chain(), &record_id)
            .await
            .expect("consumed"));
    });
}

#[test]
fn claim_rejects_double_claim() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        let record = sample_record(recipient);
        let (root, proof) = source_root_and_proof(&context, &record).await;

        let mut state = dest_state(&context, "double-claim").await;
        certify(&mut state, 7, root).await;
        let mut ledger = BridgeLedger::new(state);

        let claimer = signer(3);
        ledger
            .apply_transaction(
                &claim_tx(&claimer, 0, source_chain(), 7, record.clone(), proof.clone()),
                NoopEventSink,
            )
            .await
            .expect("first claim");

        // A second claim (correct next nonce) is rejected as already consumed.
        let err = ledger
            .apply_transaction(
                &claim_tx(&claimer, 1, source_chain(), 7, record, proof),
                NoopEventSink,
            )
            .await
            .expect_err("double claim");
        assert_eq!(err, BridgeError::AlreadyClaimed);
    });
}

#[test]
fn claim_rejects_missing_anchor() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        let record = sample_record(recipient);
        let (_root, proof) = source_root_and_proof(&context, &record).await;

        let mut ledger = dest_ledger(&context).await;
        // No certified root for view 7.
        let claimer = signer(3);
        let err = ledger
            .apply_transaction(
                &claim_tx(&claimer, 0, source_chain(), 7, record, proof),
                NoopEventSink,
            )
            .await
            .expect_err("missing anchor");
        assert_eq!(err, BridgeError::MissingAnchor);
    });
}

#[test]
fn claim_rejects_wrong_destination() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        // Record destined for a different chain than this ledger's local chain.
        let mut record = sample_record(recipient);
        record.destination_chain_id = ChainId(Sha256::hash(&[b"other-dest"]));
        let (root, proof) = source_root_and_proof(&context, &record).await;

        let mut state = dest_state(&context, "wrong-dest").await;
        certify(&mut state, 7, root).await;
        let mut ledger = BridgeLedger::new(state);

        let claimer = signer(3);
        let err = ledger
            .apply_transaction(
                &claim_tx(&claimer, 0, source_chain(), 7, record, proof),
                NoopEventSink,
            )
            .await
            .expect_err("wrong destination");
        assert_eq!(err, BridgeError::WrongDestination);
    });
}

#[test]
fn claim_rejects_tampered_record() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        let record = sample_record(recipient);
        let (root, proof) = source_root_and_proof(&context, &record).await;

        let mut state = dest_state(&context, "tampered").await;
        certify(&mut state, 7, root).await;
        let mut ledger = BridgeLedger::new(state);

        // Tamper the amount: the proof was generated for the original record, so it no longer
        // authenticates the (content-addressed) tampered record.
        let mut tampered = record;
        tampered.amount += 1;
        let claimer = signer(3);
        let err = ledger
            .apply_transaction(
                &claim_tx(&claimer, 0, source_chain(), 7, tampered, proof),
                NoopEventSink,
            )
            .await
            .expect_err("tampered record");
        assert_eq!(err, BridgeError::InvalidProof);
    });
}


#[test]
fn certified_root_advances_by_view_and_rejects_conflicts() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = dest_state(&context, "root-order").await;
        let first = Sha256::hash(&[b"root-5"]);
        let second = Sha256::hash(&[b"root-8"]);
        certify(&mut state, 5, first).await;
        assert_eq!(
            store_certified_root(&mut state, 5, first).await.expect("replay"),
            CertifiedRootStatus::Unchanged
        );
        assert_eq!(
            store_certified_root(&mut state, 5, second)
                .await
                .expect("conflict"),
            CertifiedRootStatus::Conflict
        );
        assert_eq!(
            store_certified_root(&mut state, 4, Sha256::hash(&[b"root-4"]))
                .await
                .expect("stale"),
            CertifiedRootStatus::Stale
        );
        certify(&mut state, 8, second).await;
        assert_eq!(
            foreign_root(&state, &source_chain(), 8)
                .await
                .expect("read")
                .expect("stored")
                .state_root,
            second
        );
        // The earlier view remains available to in-flight claims.
        assert_eq!(
            foreign_root(&state, &source_chain(), 5)
                .await
                .expect("read")
                .expect("kept")
                .state_root,
            first
        );
    });
}

#[test]
fn certified_root_requires_one_configured_foreign_chain() {
    deterministic::Runner::default().start(|context| async move {
        let mut dest = QmdbState::init(context.child("dst"), "no-foreign")
            .await
            .expect("init dest");
        BridgeGenesis::new(dest_chain()).apply(&mut dest);
        assert_eq!(
            store_certified_root(&mut dest, 7, Sha256::hash(&[b"root"]))
                .await
                .expect("unconfigured"),
            CertifiedRootStatus::Unconfigured
        );
        assert_eq!(foreign_chain_id(&dest).await.expect("read"), None);
    });
}

#[test]
fn claim_rejects_source_chain_mismatch() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        let record = sample_record(recipient);
        let (root, proof) = source_root_and_proof(&context, &record).await;

        let mut state = dest_state(&context, "source-mismatch").await;
        certify(&mut state, 7, root).await;
        let mut ledger = BridgeLedger::new(state);

        // The claim declares a different source chain than the record carries.
        let other_source = ChainId(Sha256::hash(&[b"other-source"]));
        let claimer = signer(3);
        let err = ledger
            .apply_transaction(
                &claim_tx(&claimer, 0, other_source, 7, record, proof),
                NoopEventSink,
            )
            .await
            .expect_err("source mismatch");
        assert_eq!(err, BridgeError::ClaimSourceMismatch);
    });
}

#[test]
fn claim_rejects_chain_other_than_the_configured_foreign_chain() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        let other = ChainId(Sha256::hash(&[b"other-source"]));
        let mut record = sample_record(recipient);
        record.source_chain_id = other;
        let (_root, proof) = source_root_and_proof(&context, &record).await;

        let mut ledger = dest_ledger(&context).await;
        let err = ledger
            .apply_transaction(
                &claim_tx(&signer(3), 0, other, 7, record, proof),
                NoopEventSink,
            )
            .await
            .expect_err("other foreign chain");
        assert_eq!(err, BridgeError::UnexpectedForeignChain);
    });
}

#[test]
fn claim_codec_round_trip() {
    deterministic::Runner::default().start(|context| async move {
        let record = sample_record(addr(&signer(2)));
        let (_root, proof) = source_root_and_proof(&context, &record).await;
        let tx = claim_tx(&signer(3), 0, source_chain(), 7, record, proof);
        assert_eq!(
            Transaction::decode(tx.encode()).expect("decode claim tx"),
            tx
        );
        let encoded = tx.encode();
        assert_eq!(encoded.len(), tx.encode_size());
        assert!(Transaction::decode(commonware_codec::Copying(&encoded[..encoded.len() - 1])).is_err());
    });
}

#[test]
fn operation_ids_round_trip_and_reject_unknown() {
    assert_eq!(
        BridgeOperationId::try_from(0).expect("lock"),
        BridgeOperationId::Lock
    );
    assert_eq!(
        BridgeOperationId::try_from(2).expect("claim"),
        BridgeOperationId::Claim
    );
    // Operation id 1 is unused. It must not decode as a claim.
    assert!(BridgeOperationId::try_from(1).is_err());
    assert!(BridgeOperation::decode(commonware_codec::Copying(&[1u8][..])).is_err());
    assert!(BridgeOperationId::try_from(3).is_err());
    assert!(BridgeOperation::decode(commonware_codec::Copying(&[3u8][..])).is_err());
    assert!(BridgeOperation::decode(commonware_codec::Copying(&[][..])).is_err());
}

#[test]
fn claim_rejects_when_chain_not_configured() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        let record = sample_record(recipient);
        let (_root, proof) = source_root_and_proof(&context, &record).await;

        let dest = QmdbState::init(context.child("dst"), "unconfigured-claim")
            .await
            .expect("init dest");
        let mut ledger = BridgeLedger::new(dest);
        let err = ledger
            .apply_transaction(
                &claim_tx(&signer(3), 0, source_chain(), 7, record, proof),
                NoopEventSink,
            )
            .await
            .expect_err("unconfigured");
        assert_eq!(err, BridgeError::ChainNotConfigured);
    });
}

#[test]
fn claim_rejects_when_foreign_chain_not_configured() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        let record = sample_record(recipient);
        let (_root, proof) = source_root_and_proof(&context, &record).await;

        let mut dest = QmdbState::init(context.child("dst"), "no-foreign-claim")
            .await
            .expect("init dest");
        BridgeGenesis::new(dest_chain()).apply(&mut dest);
        let mut ledger = BridgeLedger::new(dest);
        let err = ledger
            .apply_transaction(
                &claim_tx(&signer(3), 0, source_chain(), 7, record, proof),
                NoopEventSink,
            )
            .await
            .expect_err("no foreign chain");
        assert_eq!(err, BridgeError::ForeignChainNotConfigured);
    });
}

#[test]
fn storage_error_wraps_state_backend_failure() {
    let err = BridgeError::from(StateError::Backend("disk".into()));
    assert_eq!(err, BridgeError::Storage("state backend error: disk".into()));
    assert_eq!(
        BridgeError::from(StateError::ValueTooLarge { size: 8, max: 4 }),
        BridgeError::Storage("state value is too large: size 8, maximum 4".into())
    );
}

#[test]
fn claim_operation_rejects_every_truncated_prefix() {
    deterministic::Runner::default().start(|context| async move {
        let record = sample_record(addr(&signer(2)));
        let (_root, proof) = source_root_and_proof(&context, &record).await;
        let op = BridgeOperation::Claim {
            source_chain_id: source_chain(),
            source_view: 7,
            record,
            proof,
        };
        let encoded = op.encode();
        assert_eq!(encoded.len(), op.encode_size());
        for i in 0..encoded.len() {
            assert!(
                BridgeOperation::decode(commonware_codec::Copying(&encoded[..i])).is_err(),
                "claim prefix {i} must fail"
            );
        }
        assert_eq!(
            BridgeOperation::decode(encoded).expect("full claim"),
            op
        );
    });
}

#[test]
fn apply_rejects_nonce_overflow() {
    deterministic::Runner::default().start(|context| async move {
        let sender = signer(1);
        let mut dest = dest_state(&context, "nonce-overflow").await;
        set_bridge_nonce(&mut dest, &addr(&sender), u64::MAX);

        let mut ledger = BridgeLedger::new(dest);
        let err = ledger
            .apply_transaction(
                &Transaction::sign(
                    &sender,
                    u64::MAX,
                    BridgeOperation::Lock {
                        destination_chain_id: ChainId(Sha256::hash(&[b"other"])),
                        local_asset: Sha256::hash(&[b"coin"]),
                        amount: 1,
                        recipient: addr(&signer(2)),
                    },
                ),
                NoopEventSink,
            )
            .await
            .expect_err("overflow");
        assert_eq!(err, BridgeError::NonceOverflow);
    });
}

struct FailGet<S> {
    inner: S,
    fail: sha256::Digest,
}

impl<S: StateStore + Send + Sync> StateStore for FailGet<S> {
    async fn get(&self, key: &sha256::Digest) -> Result<Option<Vec<u8>>, StateError> {
        if *key == self.fail {
            Err(StateError::Backend("injected".into()))
        } else {
            self.inner.get(key).await
        }
    }

    fn set(&mut self, key: sha256::Digest, value: Vec<u8>) {
        self.inner.set(key, value);
    }

    fn remove(&mut self, key: sha256::Digest) {
        self.inner.remove(key);
    }
}

fn local_chain_id_key() -> sha256::Digest {
    Namespace::new(BRIDGE_NAMESPACE).key(3u8, b"local_chain_id")
}

fn foreign_chain_key() -> sha256::Digest {
    Namespace::new(BRIDGE_NAMESPACE).key(3u8, b"foreign_chain_id")
}

fn latest_view_key(source: &ChainId) -> sha256::Digest {
    Namespace::new(BRIDGE_NAMESPACE).key(5u8, source.encode().as_ref())
}

#[test]
fn apply_surfaces_injected_storage_errors() {
    deterministic::Runner::default().start(|context| async move {
        let record = sample_record(addr(&signer(2)));
        let (root, proof) = source_root_and_proof(&context, &record).await;
        let record_id = record.record_id();

        let mut ledger = BridgeLedger::new(FailGet {
            inner: dest_state(&context, "fail-chain").await,
            fail: local_chain_id_key(),
        });
        let err = ledger
            .apply_transaction(
                &claim_tx(
                    &signer(3),
                    0,
                    source_chain(),
                    7,
                    record.clone(),
                    proof.clone(),
                ),
                NoopEventSink,
            )
            .await
            .expect_err("local chain get");
        assert!(matches!(err, BridgeError::Storage(_)));

        let mut ledger = BridgeLedger::new(FailGet {
            inner: dest_state(&context, "fail-foreign").await,
            fail: foreign_chain_key(),
        });
        let err = ledger
            .apply_transaction(
                &claim_tx(
                    &signer(3),
                    0,
                    source_chain(),
                    7,
                    record.clone(),
                    proof.clone(),
                ),
                NoopEventSink,
            )
            .await
            .expect_err("foreign chain get");
        assert!(matches!(err, BridgeError::Storage(_)));

        let err = store_certified_root(
            &mut FailGet {
                inner: dest_state(&context, "fail-latest").await,
                fail: latest_view_key(&source_chain()),
            },
            7,
            root,
        )
        .await
        .expect_err("latest view get");
        assert!(matches!(err, StateError::Backend(_)));

        let mut inner = dest_state(&context, "fail-root").await;
        certify(&mut inner, 7, root).await;
        let mut ledger = BridgeLedger::new(FailGet {
            inner,
            fail: foreign_root_key(&source_chain(), 7),
        });
        let err = ledger
            .apply_transaction(
                &claim_tx(
                    &signer(3),
                    0,
                    source_chain(),
                    7,
                    record.clone(),
                    proof.clone(),
                ),
                NoopEventSink,
            )
            .await
            .expect_err("foreign root get");
        assert!(matches!(err, BridgeError::Storage(_)));

        let mut inner = dest_state(&context, "fail-consumed").await;
        certify(&mut inner, 7, root).await;
        let mut ledger = BridgeLedger::new(FailGet {
            inner,
            fail: consumed_record_key(&source_chain(), &record_id),
        });
        let err = ledger
            .apply_transaction(
                &claim_tx(&signer(3), 0, source_chain(), 7, record, proof),
                NoopEventSink,
            )
            .await
            .expect_err("consumed get");
        assert!(matches!(err, BridgeError::Storage(_)));
    });
}
