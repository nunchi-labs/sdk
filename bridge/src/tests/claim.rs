use std::num::NonZeroU64;

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256, Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use nunchi_common::{
    state_db::{verify_state_update, CommitState, StateProof},
    Address, NoopEventSink, QmdbState, VecEventSink,
};
use nunchi_crypto::PrivateKey;

use crate::events::{
    ForeignRootAnchored, TransferClaimed, FOREIGN_ROOT_ANCHORED_EVENT, TRANSFER_CLAIMED_EVENT,
};
use crate::genesis::BridgeGenesis;
use crate::ledger::{BridgeError, BridgeLedger, BridgeReceipt};
use crate::record::{
    is_consumed, put_transfer_record, transfer_record_key, AssetId, BridgeTransferRecord, ChainId,
};
use crate::transaction::{BridgeOperation, Transaction};

fn signer(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn addr(key: &PrivateKey) -> Address {
    Address::external(&key.public_key())
}

fn source_chain() -> ChainId {
    ChainId(Sha256::hash(b"source-chain"))
}

fn dest_chain() -> ChainId {
    ChainId(Sha256::hash(b"dest-chain"))
}

fn sample_record(recipient: Address) -> BridgeTransferRecord {
    let source = source_chain();
    BridgeTransferRecord {
        source_chain_id: source,
        destination_chain_id: dest_chain(),
        source_asset: AssetId::derive(&source, &Sha256::hash(b"coin")),
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
    let bounds = source.operation_bounds().await;
    let proof = source
        .proof(bounds.start, NonZeroU64::new(1024).unwrap())
        .await
        .expect("proof");
    (root, proof)
}

async fn dest_ledger(
    context: &deterministic::Context,
    attestor: &Address,
) -> BridgeLedger<QmdbState<deterministic::Context>> {
    let mut dest = QmdbState::init(context.child("dst"), "bridge-claim-dest")
        .await
        .expect("init dest");
    BridgeGenesis::new(dest_chain())
        .with_attestor(attestor.clone())
        .apply(&mut dest);
    BridgeLedger::new(dest)
}

fn anchor_tx(
    attestor: &PrivateKey,
    nonce: u64,
    source: ChainId,
    view: u64,
    state_root: sha256::Digest,
) -> Transaction {
    Transaction::sign(
        attestor,
        nonce,
        BridgeOperation::AnchorForeignRoot {
            source_chain_id: source,
            view,
            state_root,
        },
    )
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
        let local_asset = Sha256::hash(b"coin");
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
        let bounds = source.operation_bounds().await;
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

        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;

        // Anchor the source root at view 7.
        let mut sink = VecEventSink::new();
        let anchored = ledger
            .apply_transaction(&anchor_tx(&attestor, 0, source_chain(), 7, root), &mut sink)
            .await
            .expect("anchor");
        assert_eq!(
            anchored,
            BridgeReceipt::Anchored {
                source_chain_id: source_chain(),
                view: 7,
            }
        );

        // Claim against the anchored root.
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
        let decoded = TransferClaimed::decode(event.value.as_ref()).expect("decode event");
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

        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;
        ledger
            .apply_transaction(&anchor_tx(&attestor, 0, source_chain(), 7, root), NoopEventSink)
            .await
            .expect("anchor");

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

        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;
        // No anchor for (source_chain, 7).
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
        record.destination_chain_id = ChainId(Sha256::hash(b"other-dest"));
        let (root, proof) = source_root_and_proof(&context, &record).await;

        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;
        ledger
            .apply_transaction(&anchor_tx(&attestor, 0, source_chain(), 7, root), NoopEventSink)
            .await
            .expect("anchor");

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

        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;
        ledger
            .apply_transaction(&anchor_tx(&attestor, 0, source_chain(), 7, root), NoopEventSink)
            .await
            .expect("anchor");

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
fn anchor_rejects_non_attestor() {
    deterministic::Runner::default().start(|context| async move {
        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;

        // A different signer tries to anchor.
        let impostor = signer(4);
        let err = ledger
            .apply_transaction(
                &anchor_tx(&impostor, 0, source_chain(), 7, Sha256::hash(b"root")),
                NoopEventSink,
            )
            .await
            .expect_err("non-attestor");
        assert_eq!(err, BridgeError::NotAttestor);
    });
}

#[test]
fn anchor_rejects_stale_view() {
    deterministic::Runner::default().start(|context| async move {
        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;

        ledger
            .apply_transaction(
                &anchor_tx(&attestor, 0, source_chain(), 7, Sha256::hash(b"root-7")),
                NoopEventSink,
            )
            .await
            .expect("anchor view 7");

        // Re-anchoring the same view is stale.
        let err = ledger
            .apply_transaction(
                &anchor_tx(&attestor, 1, source_chain(), 7, Sha256::hash(b"root-7b")),
                NoopEventSink,
            )
            .await
            .expect_err("stale view");
        assert_eq!(
            err,
            BridgeError::StaleAnchor {
                latest: 7,
                submitted: 7
            }
        );
    });
}

#[test]
fn anchor_is_monotonic_per_source_chain() {
    deterministic::Runner::default().start(|context| async move {
        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;
        let other_source = ChainId(Sha256::hash(b"other-source"));

        // Anchor chain A at a high view.
        ledger
            .apply_transaction(
                &anchor_tx(&attestor, 0, source_chain(), 100, Sha256::hash(b"a-100")),
                NoopEventSink,
            )
            .await
            .expect("anchor A@100");

        // A different source chain is unaffected: it can anchor at a low view.
        let anchored = ledger
            .apply_transaction(
                &anchor_tx(&attestor, 1, other_source, 1, Sha256::hash(b"b-1")),
                NoopEventSink,
            )
            .await
            .expect("anchor B@1");
        assert_eq!(
            anchored,
            BridgeReceipt::Anchored {
                source_chain_id: other_source,
                view: 1,
            }
        );
    });
}

#[test]
fn anchor_rejects_when_attestor_not_configured() {
    deterministic::Runner::default().start(|context| async move {
        // Destination has a chain id but no configured attestor.
        let mut dest = QmdbState::init(context.child("dst"), "no-attestor")
            .await
            .expect("init dest");
        BridgeGenesis::new(dest_chain()).apply(&mut dest);
        let mut ledger = BridgeLedger::new(dest);

        let attestor = signer(1);
        let err = ledger
            .apply_transaction(
                &anchor_tx(&attestor, 0, source_chain(), 7, Sha256::hash(b"root")),
                NoopEventSink,
            )
            .await
            .expect_err("attestor not configured");
        assert_eq!(err, BridgeError::AttestorNotConfigured);
    });
}

#[test]
fn claim_rejects_source_chain_mismatch() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(&signer(2));
        let record = sample_record(recipient);
        let (root, proof) = source_root_and_proof(&context, &record).await;

        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;
        ledger
            .apply_transaction(&anchor_tx(&attestor, 0, source_chain(), 7, root), NoopEventSink)
            .await
            .expect("anchor");

        // The claim declares a different source chain than the record carries.
        let other_source = ChainId(Sha256::hash(b"other-source"));
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
fn anchor_emits_foreign_root_anchored_event() {
    deterministic::Runner::default().start(|context| async move {
        let attestor = signer(1);
        let mut ledger = dest_ledger(&context, &addr(&attestor)).await;

        let root = Sha256::hash(b"anchored-root");
        let mut sink = VecEventSink::new();
        ledger
            .apply_transaction(&anchor_tx(&attestor, 0, source_chain(), 9, root), &mut sink)
            .await
            .expect("anchor");

        assert_eq!(sink.len(), 1);
        let event = &sink.events()[0];
        assert_eq!(event.name.as_ref(), FOREIGN_ROOT_ANCHORED_EVENT);
        let decoded = ForeignRootAnchored::decode(event.value.as_ref()).expect("decode event");
        assert_eq!(decoded.source_chain_id, source_chain());
        assert_eq!(decoded.view, 9);
        assert_eq!(decoded.state_root, root);
    });
}

#[test]
fn anchor_and_claim_codec_round_trip() {
    let anchor = BridgeOperation::AnchorForeignRoot {
        source_chain_id: source_chain(),
        view: 42,
        state_root: Sha256::hash(b"root"),
    };
    assert_eq!(
        BridgeOperation::decode(anchor.encode().as_ref()).expect("decode anchor"),
        anchor
    );

    // A claim carries an embedded proof; a signed transaction wrapping it must round-trip.
    deterministic::Runner::default().start(|context| async move {
        let record = sample_record(addr(&signer(2)));
        let (_root, proof) = source_root_and_proof(&context, &record).await;
        let tx = claim_tx(&signer(3), 0, source_chain(), 7, record, proof);
        assert_eq!(
            Transaction::decode(tx.encode().as_ref()).expect("decode claim tx"),
            tx
        );
    });
}
