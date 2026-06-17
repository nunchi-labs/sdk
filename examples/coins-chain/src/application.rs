//! Coins-chain application alias over the reusable `nunchi-chain` application.

use commonware_cryptography::{sha256, Hasher, Sha256};

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"nunchi coins chain";

pub type Application = nunchi_chain::Application<
    crate::CoinsRuntime,
    nunchi_chain::DkgExtension<crate::RuntimeTransaction>,
>;
pub type BasicApplication<R = crate::CoinsRuntime> = nunchi_chain::Application<R>;

pub fn genesis_payload() -> sha256::Digest {
    Sha256::hash(GENESIS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StateCommitment, TxPool};
    use commonware_consensus::types::Height;
    use commonware_glue::stateful::db::DatabaseSet as _;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::sync::AsyncRwLock;
    use futures::lock::Mutex as AsyncMutex;
    use nunchi_coins::{
        multisig_account_id, AccountPolicy, CoinOperation, CoinSpec, Ledger, MultisigPolicy,
        PrivateKey, TokenName, TokenSymbol, Transaction as CoinTransaction,
    };
    use nunchi_common::{QmdbBackend, QmdbBatch, QmdbDatabaseSet, QmdbState, RuntimeContext};
    use std::sync::Arc;

    fn spec() -> CoinSpec {
        CoinSpec::new(
            TokenSymbol::new("NCH").expect("valid token symbol"),
            TokenName::new("Nunchi").expect("valid token name"),
            9,
            1_000,
            None,
        )
    }

    #[test]
    fn proposal_skips_unregistered_multisig() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (_, submitter) = TxPool::new();
            let config = QmdbState::<deterministic::Context>::config(&context, "application-test");
            let db = QmdbBackend::init(context, config)
                .await
                .expect("init state db");
            let databases: QmdbDatabaseSet<deterministic::Context> = Arc::new(AsyncRwLock::new(db));
            let genesis_target = databases.committed_targets().await;
            let genesis_state = StateCommitment {
                root: genesis_target.root,
                range: genesis_target.range,
            };
            let applied_height = Arc::new(AsyncMutex::new(Height::zero()));
            let app: BasicApplication = BasicApplication::new(
                submitter,
                16,
                applied_height,
                genesis_state,
                genesis_payload(),
            );

            let alice_a = PrivateKey::ed25519_from_seed(1);
            let alice_b = PrivateKey::secp256r1_from_seed(2);
            let policy =
                MultisigPolicy::new(2, vec![alice_a.public_key(), alice_b.public_key()]).unwrap();
            let account_id = multisig_account_id(&policy);
            let tx = CoinTransaction::sign_multisig(
                account_id.clone(),
                policy.clone(),
                &[&alice_a, &alice_b],
                0,
                CoinOperation::CreateToken { spec: spec() },
            );

            let batches = databases.new_batches().await;
            let (included, _) = app
                .build_valid_transactions(
                    batches,
                    RuntimeContext::default(),
                    vec![tx.clone().into()],
                )
                .await;
            assert!(included.is_empty());

            let batches = databases.new_batches().await;
            let mut ledger = Ledger::new(QmdbBatch::new(batches));
            ledger
                .register_account_policy(account_id, AccountPolicy::Multisig(policy))
                .await
                .expect("register policy");
            let merkleized = ledger
                .into_inner()
                .merkleize()
                .await
                .expect("merkleize policy registration");
            databases.finalize(merkleized).await;

            let batches = databases.new_batches().await;
            let (included, _) = app
                .build_valid_transactions(
                    batches,
                    RuntimeContext::default(),
                    vec![tx.clone().into()],
                )
                .await;
            assert_eq!(included, vec![tx.into()]);
        });
    }
}
