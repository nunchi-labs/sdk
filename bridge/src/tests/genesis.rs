use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::{CommitState, QmdbState};

use crate::genesis::BridgeGenesis;
use crate::record::{foreign_chain_id, local_chain_id, ChainId};

#[test]
fn genesis_pins_local_chain_id() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-genesis-test")
            .await
            .expect("init state");

        // Unset before genesis.
        assert_eq!(local_chain_id(&state).await.expect("read"), None);

        let chain_id = ChainId(Sha256::hash(&[b"local-chain"]));
        BridgeGenesis::new(chain_id).apply(&mut state);
        state.commit().await.expect("commit");

        assert_eq!(local_chain_id(&state).await.expect("read"), Some(chain_id));
        assert_eq!(foreign_chain_id(&state).await.expect("read"), None);

        let foreign = ChainId(Sha256::hash(&[b"foreign-chain"]));
        BridgeGenesis::new(chain_id)
            .with_foreign_chain(foreign)
            .apply(&mut state);
        state.commit().await.expect("commit foreign");
        assert_eq!(
            foreign_chain_id(&state).await.expect("read"),
            Some(foreign)
        );
    });
}
