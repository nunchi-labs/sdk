mod genesis;
mod ledger;
mod record;

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
use commonware_utils::{non_empty_range, test_rng_seeded};
use nunchi_chain::StateCommitment;
use nunchi_dkg::{Context, Finalization, Scheme};

use crate::{BridgeActor, BridgeBlock, BridgePayload, SubmitResult};

const NAMESPACE: &[u8] = b"_NUNCHI_BRIDGE_TEST";

fn schemes(seed: u64) -> Vec<Scheme> {
    let mut rng = test_rng_seeded(seed);
    vrf::fixture::<MinSig, _>(&mut rng, NAMESPACE, 4).schemes
}

fn finalization(schemes: &[Scheme], view: u64, payload: &[u8]) -> Finalization {
    let proposal = Proposal::new(
        Round::new(Epoch::zero(), View::new(view)),
        View::new(view.saturating_sub(1)),
        Sha256::hash(payload),
    );
    let finalizes: Vec<_> = schemes
        .iter()
        .take(3)
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
        .collect();
    CFinalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
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
