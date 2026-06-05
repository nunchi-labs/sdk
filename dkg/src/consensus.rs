use crate::orchestrator::EpochTransition;
use commonware_consensus::simplex::types::{
    Activity as CActivity, Context as CContext, Finalization as CFinalization,
    Notarization as CNotarization,
};
use commonware_consensus::{simplex, types::Epoch};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt as dkg,
        primitives::variant::{MinSig, Variant},
    },
    certificate::{self, Scheme as CertificateScheme},
    ed25519,
    sha256::Digest,
    PublicKey as CryptoPublicKey, Signer,
};
use commonware_utils::sync::Mutex;
use std::{collections::HashMap, sync::Arc};

pub type Context = CContext<Digest, PublicKey>;

pub type ThresholdScheme<V> =
    simplex::scheme::bls12381_threshold::vrf::Scheme<ed25519::PublicKey, V>;
pub type EdScheme = simplex::scheme::ed25519::Scheme;
pub type Scheme = ThresholdScheme<MinSig>;
pub type Seed = simplex::scheme::bls12381_threshold::vrf::Seed<MinSig>;
pub use simplex::scheme::bls12381_threshold::vrf::Seedable;
pub type Notarization = CNotarization<Scheme, Digest>;
pub type Finalization = CFinalization<Scheme, Digest>;
pub type Activity = CActivity<Scheme, Digest>;

pub type PublicKey = ed25519::PublicKey;
pub type Identity = <MinSig as Variant>::Public;
pub type Signature = <MinSig as Variant>::Signature;

/// Provides signing schemes for different epochs.
#[derive(Clone)]
pub struct Provider<S: CertificateScheme, C: Signer> {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
    namespace: Vec<u8>,
    certificate_verifier: Option<Arc<S>>,
    signer: C,
}

impl<S: CertificateScheme, C: Signer> Provider<S, C> {
    pub fn new(namespace: Vec<u8>, signer: C, certificate_verifier: Option<S>) -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
            namespace,
            certificate_verifier: certificate_verifier.map(Arc::new),
            signer,
        }
    }

    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: S) -> bool {
        let mut schemes = self.schemes.lock();
        schemes.insert(epoch, Arc::new(scheme)).is_none()
    }

    /// Unregisters the signing scheme for the given epoch.
    ///
    /// Returns `false` if no scheme was registered for the epoch.
    pub fn unregister(&self, epoch: &Epoch) -> bool {
        let mut schemes = self.schemes.lock();
        schemes.remove(epoch).is_some()
    }
}

impl<S: CertificateScheme, C: Signer> certificate::Provider for Provider<S, C> {
    type Scope = Epoch;
    type Scheme = S;

    fn scoped(&self, epoch: Epoch) -> Option<Arc<S>> {
        let schemes = self.schemes.lock();
        schemes.get(&epoch).cloned()
    }

    fn all(&self) -> Option<Arc<S>> {
        self.certificate_verifier.clone()
    }
}

pub trait EpochProvider {
    type Variant: Variant;
    type PublicKey: CryptoPublicKey;
    type Scheme: CertificateScheme;

    /// Returns a [CertificateScheme] for the given [EpochTransition].
    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme;

    /// Creates an epoch-independent certificate verifier from the DKG output.
    ///
    /// Returns `None` for schemes that don't support epoch-independent verification
    /// (Ed25519 during the initial DKG requires the full participant list to verify certificates).
    fn certificate_verifier(
        namespace: &[u8],
        output: &dkg::Output<Self::Variant, Self::PublicKey>,
    ) -> Option<Self::Scheme>;
}

impl<V: Variant> EpochProvider for Provider<ThresholdScheme<V>, ed25519::PrivateKey> {
    type Variant = V;
    type PublicKey = ed25519::PublicKey;
    type Scheme = ThresholdScheme<V>;

    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme {
        transition.share.as_ref().map_or_else(
            || {
                ThresholdScheme::verifier(
                    &self.namespace,
                    transition.dealers.clone(),
                    transition
                        .poly
                        .clone()
                        .expect("group polynomial must exist"),
                )
            },
            |share| {
                ThresholdScheme::signer(
                    &self.namespace,
                    transition.dealers.clone(),
                    transition
                        .poly
                        .clone()
                        .expect("group polynomial must exist"),
                    share.clone(),
                )
                .expect("share must be in dealers")
            },
        )
    }

    fn certificate_verifier(
        namespace: &[u8],
        output: &dkg::Output<Self::Variant, Self::PublicKey>,
    ) -> Option<Self::Scheme> {
        Some(ThresholdScheme::certificate_verifier(
            namespace,
            *output.public().public(),
        ))
    }
}

impl EpochProvider for Provider<EdScheme, ed25519::PrivateKey> {
    type Variant = MinSig;
    type PublicKey = ed25519::PublicKey;
    type Scheme = EdScheme;

    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme {
        EdScheme::signer(
            &self.namespace,
            transition.dealers.clone(),
            self.signer.clone(),
        )
        .unwrap_or_else(|| EdScheme::verifier(&self.namespace, transition.dealers.clone()))
    }

    fn certificate_verifier(
        _namespace: &[u8],
        _output: &dkg::Output<Self::Variant, Self::PublicKey>,
    ) -> Option<Self::Scheme> {
        // Ed25519 doesn't support epoch-independent certificate verification
        // since certificates require the full participant list which changes per epoch.
        None
    }
}
