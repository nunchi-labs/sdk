use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::{state_db::CommitState, QmdbState};

use crate::genesis::BridgeGenesis;
use crate::record::{local_chain_id, ChainId};

#[test]
fn genesis_pins_local_chain_id() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-genesis-test")
            .await
            .expect("init state");

        // Unset before genesis.
        assert_eq!(local_chain_id(&state).await.expect("read"), None);

        let chain_id = ChainId(Sha256::hash(b"local-chain"));
        BridgeGenesis::new(chain_id).apply(&mut state);
        state.commit().await.expect("commit");

        assert_eq!(local_chain_id(&state).await.expect("read"), Some(chain_id));
    });
}
