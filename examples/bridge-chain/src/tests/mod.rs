use commonware_codec::Encode;
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
use commonware_glue::stateful::{db::DatabaseSet, Application as StatefulApplication};
use commonware_parallel::Sequential;
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use commonware_utils::{sync::AsyncRwLock, test_rng_seeded};
use nunchi_bridge::{BridgeExtension, BridgePayload, SubmitResult};
use nunchi_chain::StateCommitment;
use nunchi_common::{QmdbBackend, QmdbDatabaseSet, QmdbMerkleized, QmdbState};
use nunchi_dkg::{Context, Finalization, Scheme};
use nunchi_mempool::PoolConfig;
use std::sync::Arc;

use crate::{application, Application, Block, TxPool};

const FOREIGN_NAMESPACE: &[u8] = b"_NUNCHI_BRIDGE_CHAIN_FOREIGN";
const WRONG_NAMESPACE: &[u8] = b"_NUNCHI_BRIDGE_CHAIN_WRONG";

fn schemes(namespace: &[u8], seed: u64) -> Vec<Scheme> {
    let mut rng = test_rng_seeded(seed);
    vrf::fixture::<MinSig, _>(&mut rng, namespace, 4).schemes
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
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalization"))
        .collect();
    CFinalization::from_finalizes(&schemes[0], &finalizes, &Sequential)
        .expect("assemble finalization")
}

fn consensus_context(view: u64) -> Context {
    Context {
        round: Round::new(Epoch::zero(), View::new(view)),
        leader: ed25519::PrivateKey::from_seed(view).public_key(),
        parent: (View::new(view.saturating_sub(1)), sha256::Digest::EMPTY),
    }
}

#[test]
fn chain_application_proposes_and_verifies_bridge_payload() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let foreign = schemes(FOREIGN_NAMESPACE, 1);
        let wrong = schemes(WRONG_NAMESPACE, 2);
        let bridge = BridgeExtension::new(foreign[0].clone());
        let handle = bridge.handle();

        let foreign_finalization = finalization(&foreign, 7, b"foreign block digest");
        let wrong_finalization = finalization(&wrong, 8, b"wrong block digest");

        assert_eq!(handle.submit(wrong_finalization), SubmitResult::Rejected);
        assert_eq!(handle.latest(), None);

        assert_eq!(
            handle.submit(foreign_finalization.clone()),
            SubmitResult::Updated
        );
        assert_eq!(handle.latest(), Some(foreign_finalization.clone()));

        let (txpool, submitter) = TxPool::new(PoolConfig::default());
        let _txpool = txpool.start(context.child("txpool"));
        let mut input = submitter.clone();

        let db_context = context.child("state");
        let config = QmdbState::<deterministic::Context>::config(&db_context, "bridge-chain-e2e");
        let db: QmdbBackend<deterministic::Context> = QmdbBackend::init(db_context, config)
            .await
            .expect("init state db");
        let databases: QmdbDatabaseSet<deterministic::Context> = Arc::new(AsyncRwLock::new(db));
        let genesis_target = databases.committed_targets().await;
        let genesis_state = StateCommitment {
            root: genesis_target.root,
            range: genesis_target.range,
        };
        let applied_height = Arc::new(futures::lock::Mutex::new(Height::zero()));
        let mut app = application(
            submitter,
            bridge,
            applied_height,
            genesis_state,
            Sha256::hash(b"bridge-chain genesis"),
        );

        let genesis =
            <Application as StatefulApplication<deterministic::Context>>::genesis(&mut app).await;
        let proposed = <Application as StatefulApplication<deterministic::Context>>::propose(
            &mut app,
            (context.child("propose"), consensus_context(1)),
            futures::stream::iter([genesis.clone()]),
            databases.new_batches().await,
            &mut input,
        )
        .await
        .expect("propose bridge block");

        let bridge_payload: BridgePayload = proposed.block.extension.clone();
        assert_eq!(bridge_payload, Some(foreign_finalization.clone()));

        let verified: Option<QmdbMerkleized<deterministic::Context>> =
            <Application as StatefulApplication<deterministic::Context>>::verify(
                &mut app,
                (context.child("verify"), proposed.block.context.clone()),
                futures::stream::iter([proposed.block.clone(), genesis.clone()]),
                databases.new_batches().await,
            )
            .await;
        assert!(verified.is_some());

        let block_state = StateCommitment {
            root: proposed.block.state_root,
            range: proposed.block.state_range.clone(),
        };
        let empty = Block::new(
            proposed.block.context.clone(),
            genesis.digest(),
            proposed.block.height,
            proposed.block.timestamp,
            Vec::new(),
            None,
            None,
            block_state,
        );
        assert_ne!(proposed.block.encode(), empty.encode());
        assert_ne!(proposed.block.digest(), empty.digest());

        let wrong_finalization = finalization(&wrong, 8, b"wrong block digest");
        let rejected = Block::new(
            proposed.block.context.clone(),
            genesis.digest(),
            proposed.block.height,
            proposed.block.timestamp,
            Vec::new(),
            None,
            Some(wrong_finalization),
            StateCommitment {
                root: proposed.block.state_root,
                range: proposed.block.state_range.clone(),
            },
        );
        let verified: Option<QmdbMerkleized<deterministic::Context>> =
            <Application as StatefulApplication<deterministic::Context>>::verify(
                &mut app,
                (context.child("verify_reject"), rejected.context.clone()),
                futures::stream::iter([rejected, genesis]),
                databases.new_batches().await,
            )
            .await;
        assert!(verified.is_none());

        handle.clear();
        let proposed = <Application as StatefulApplication<deterministic::Context>>::propose(
            &mut app,
            (context.child("propose_empty"), consensus_context(2)),
            futures::stream::iter([proposed.block]),
            databases.new_batches().await,
            &mut input,
        )
        .await
        .expect("propose empty bridge block");
        assert_eq!(proposed.block.extension, None);
    });
}
