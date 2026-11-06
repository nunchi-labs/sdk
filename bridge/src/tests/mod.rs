mod claim;
mod events;
mod genesis;
mod ledger;
mod record;
mod rpc;

use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf,
        types::{Finalization as CFinalization, Finalize, Proposal},
    },
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, ed25519, sha256, Digest as _, Digestible as _, Hasher,
    Sha256, Signer,
};
use commonware_parallel::Sequential;
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use commonware_storage::mmr::Location;
use commonware_utils::{non_empty, non_empty_range, TestRng};
use nunchi_chain::{ConsensusExtension, StateCommitment};
use nunchi_common::{Address, CommitState, NoopEventSink, QmdbState, RuntimeContext};
use nunchi_dkg::{Context, Finalization, Scheme};
use std::num::NonZeroU64;

use crate::genesis::BridgeGenesis;
use crate::ledger::BridgeLedger;
use crate::record::{foreign_root, AssetId, BridgeTransferRecord, ChainId};
use crate::transaction::{BridgeOperation, Transaction};
use crate::{BridgeActor, BridgeBlock, BridgeExtension, BridgePayload, SubmitResult};
use nunchi_crypto::PrivateKey;

const NAMESPACE: &[u8] = b"_NUNCHI_BRIDGE_TEST";

fn schemes(seed: u64) -> Vec<Scheme> {
    let mut rng = TestRng::new(seed);
    vrf::fixture::<MinSig, _>(&mut rng, NAMESPACE, 4).schemes
}

fn finalization_over(schemes: &[Scheme], view: u64, payload: sha256::Digest) -> Finalization {
    let proposal = Proposal::new(
        Round::new(Epoch::zero(), View::new(view)),
        View::new(view.saturating_sub(1)),
        payload,
    );
    let finalizes: Vec<_> = schemes
        .iter()
        .take(3)
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
        .collect();
    CFinalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential).unwrap()
}

fn finalization(schemes: &[Scheme], view: u64, payload: &[u8]) -> Finalization {
    finalization_over(schemes, view, Sha256::hash(&[payload]))
}

fn context() -> Context {
    Context {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), sha256::Digest::EMPTY),
    }
}

fn state() -> StateCommitment {
    StateCommitment {
        root: sha256::Digest::EMPTY,
        range: non_empty_range!(Location::new(0), Location::new(1)),
    }
}

#[test]
fn payload_codec_round_trips() {
    let finalization = finalization(&schemes(1), 3, b"foreign");
    let payload = Some(finalization);

    let encoded = payload.encode();
    let decoded = BridgePayload::decode(encoded.as_ref()).unwrap();

    assert_eq!(payload, decoded);
    assert_eq!(
        BridgePayload::decode(None::<Finalization>.encode().as_ref()).unwrap(),
        None
    );
}

#[test]
fn submit_accepts_valid_foreign_finalization() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(2);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));
        let finalization = finalization(&schemes, 3, b"foreign");

        assert_eq!(
            mailbox.submit(finalization.clone()).await,
            SubmitResult::Updated
        );
        assert_eq!(mailbox.latest().await, Some(finalization.clone()));
        assert!(mailbox.verify_payload(Some(finalization)).await);
    });
}

#[test]
fn submit_rejects_wrong_network_finalization() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let verifier = schemes(3);
        let other = schemes(4);
        let (actor, mailbox) = BridgeActor::new(verifier[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));
        let finalization = finalization(&other, 3, b"foreign");

        assert_eq!(mailbox.submit(finalization).await, SubmitResult::Rejected);
        assert_eq!(mailbox.latest().await, None);
    });
}

#[test]
fn submit_keeps_latest_view() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let schemes = schemes(5);
        let (actor, mailbox) = BridgeActor::new(schemes[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));
        let older = finalization(&schemes, 2, b"older");
        let newer = finalization(&schemes, 4, b"newer");

        assert_eq!(mailbox.submit(newer.clone()).await, SubmitResult::Updated);
        assert_eq!(mailbox.submit(older).await, SubmitResult::Stale);

        assert_eq!(mailbox.latest().await, Some(newer));
    });
}

#[test]
fn bridge_payload_is_committed_in_block_digest() {
    let schemes = schemes(6);
    let finalization = finalization(&schemes, 3, b"foreign");
    let left = BridgeBlock::<u8>::new(
        context(),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![7],
        None,
        None,
        state(),
    );
    let right = BridgeBlock::<u8>::new(
        context(),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![7],
        None,
        Some(finalization),
        state(),
    );

    assert_ne!(left.encode(), right.encode());
    assert_ne!(left.digest(), right.digest());
}

#[test]
fn verified_finalization_stores_certified_root_for_claims() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let source = ChainId(Sha256::hash(&[b"source-chain"]));
        let dest = ChainId(Sha256::hash(&[b"dest-chain"]));
        let sender = PrivateKey::from_seed(1);
        let recipient = Address::external(&PrivateKey::from_seed(2).public_key());
        let local_asset = Sha256::hash(&[b"coin"]);

        let mut source_state = QmdbState::init(context.child("src"), "cert-claim-src")
            .await
            .expect("init source");
        BridgeGenesis::new(source).apply(&mut source_state);
        let mut source_ledger = BridgeLedger::new(source_state);
        source_ledger
            .apply_transaction(
                &Transaction::sign(
                    &sender,
                    0,
                    BridgeOperation::Lock {
                        destination_chain_id: dest,
                        local_asset,
                        amount: 1_000,
                        recipient: recipient.clone(),
                    },
                ),
                NoopEventSink,
            )
            .await
            .expect("lock");
        let mut source_state = source_ledger.into_inner();
        let root = source_state.commit().await.expect("commit source");
        let bounds = source_state.operation_bounds();
        let proof = source_state
            .proof(bounds.start, NonZeroU64::new(1024).unwrap())
            .await
            .expect("proof");
        let record = BridgeTransferRecord {
            source_chain_id: source,
            destination_chain_id: dest,
            source_asset: AssetId::derive(&source, &local_asset),
            amount: 1_000,
            sender: Address::external(&sender.public_key()),
            recipient: recipient.clone(),
            nonce: 0,
        };

        let foreign = schemes(7);
        let (actor, mailbox) = BridgeActor::new(foreign[0].clone(), 16);
        let _actor = actor.start(context.child("bridge"));
        let mut extension = BridgeExtension::new(mailbox.clone());
        let certificate = finalization_over(&foreign, 7, root);
        assert_eq!(
            mailbox.submit(certificate.clone()).await,
            SubmitResult::Updated
        );

        let mut dest_state = QmdbState::init(context.child("dst"), "cert-claim-dst")
            .await
            .expect("init dest");
        BridgeGenesis::new(dest)
            .with_foreign_chain(source)
            .apply(&mut dest_state);

        let runtime = RuntimeContext::default();
        let payload = extension.propose(runtime).await;
        assert_eq!(payload, Some(certificate.clone()));
        assert!(
            extension
                .apply_payload(&mut dest_state, runtime, &payload)
                .await
        );
        // Including the same certificate again does not roll the root back.
        assert!(
            extension
                .apply_payload(&mut dest_state, runtime, &payload)
                .await
        );
        assert_eq!(
            foreign_root(&dest_state, &source, 7)
                .await
                .expect("read")
                .expect("stored")
                .state_root,
            root
        );

        let older = finalization_over(&foreign, 3, Sha256::hash(&[b"older-root"]));
        assert!(
            !extension
                .apply_payload(&mut dest_state, runtime, &Some(older))
                .await
        );
        let wrong_schemes = schemes(8);
        let wrong = finalization_over(&wrong_schemes, 9, Sha256::hash(&[b"wrong-root"]));
        assert!(
            !extension
                .apply_payload(&mut dest_state, runtime, &Some(wrong))
                .await
        );
        assert!(foreign_root(&dest_state, &source, 9)
            .await
            .expect("read")
            .is_none());

        let mut dest_ledger = BridgeLedger::new(dest_state);
        let claimed = dest_ledger
            .apply_transaction(
                &Transaction::sign(
                    &PrivateKey::from_seed(3),
                    0,
                    BridgeOperation::Claim {
                        source_chain_id: source,
                        source_view: 7,
                        record,
                        proof,
                    },
                ),
                NoopEventSink,
            )
            .await
            .expect("claim");
        assert!(matches!(
            claimed,
            crate::ledger::BridgeReceipt::Claimed { amount: 1_000, .. }
        ));

        // A chain with no foreign chain configured still accepts the certificate in the
        // extension, and does not invent a claim root.
        let mut bare = QmdbState::init(context.child("bare"), "cert-unconfigured")
            .await
            .expect("init bare");
        assert!(
            extension
                .apply_payload(&mut bare, runtime, &payload)
                .await
        );
    });
}
