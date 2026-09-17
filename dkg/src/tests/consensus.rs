use crate::{orchestrator::EpochTransition, EpochProvider, Provider, ThresholdScheme};
use commonware_consensus::{
    simplex::types::{Proposal, Subject},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::variant::MinSig,
    },
    certificate::{Scheme as _, Verifier as _},
    ed25519::PrivateKey,
    sha256::{Digest, Sha256},
    Hasher, Signer,
};
use commonware_parallel::Sequential;
use commonware_utils::{ordered::Set, test_rng, N3f1};

#[test]
fn shareless_epoch_scheme_verifies_but_cannot_vote() {
    let namespace = b"shareless-consensus";
    let signers = (0..4).map(PrivateKey::from_seed).collect::<Vec<_>>();
    let participants = Set::from_iter_dedup(signers.iter().map(Signer::public_key));
    let mut rng = test_rng();
    let (output, shares) = deal::<MinSig, _, N3f1>(
        &mut rng,
        Default::default(),
        participants.clone(),
    )
    .unwrap();
    let observer = PrivateKey::from_seed(99);
    let provider: Provider<ThresholdScheme<MinSig>, PrivateKey> =
        Provider::new(namespace.to_vec(), observer, None);
    let transition = EpochTransition {
        epoch: Epoch::new(3),
        poly: Some(output.public().clone()),
        share: None,
        dealers: participants.clone(),
    };
    let verifier = provider.scheme_for_epoch(&transition);
    let proposal = Proposal::new(
        Round::new(Epoch::new(3), View::new(2)),
        View::new(1),
        Sha256::hash(b"proposal"),
    );
    let subject = Subject::Notarize { proposal: &proposal };

    assert!(verifier.me().is_none());
    assert!(verifier.sign(subject).is_none());

    let votes = signers
        .iter()
        .map(|signer| {
            let share = shares.get_value(&signer.public_key()).unwrap().clone();
            ThresholdScheme::<MinSig>::signer(
                namespace,
                participants.clone(),
                output.public().clone(),
                share,
            )
            .unwrap()
            .sign(subject)
            .unwrap()
        })
        .collect::<Vec<_>>();
    let certificate = verifier
        .assemble::<_, N3f1>(votes, &Sequential)
        .expect("quorum votes should assemble");
    assert!(verifier.verify_certificate::<_, Digest, N3f1>(
        &mut rng,
        subject,
        &certificate,
        &Sequential,
    ));
}
