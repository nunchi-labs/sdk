use std::num::NonZeroU64;

use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};

use crate::state_db::{verify_state_proof, CommitState, Namespace, QmdbState, StateStore};

#[test]
fn state_proof_roundtrips_and_rejects_wrong_root() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "state-proof-test")
            .await
            .expect("init state");

        // Write a namespaced key, then commit to obtain the authenticated root.
        let ns = Namespace::new(b"test-ns");
        state.set(ns.key(0u8, b"account-1"), b"balance".to_vec());
        let root = state.commit().await.expect("commit");

        // Prove the committed operations and verify against the root.
        let bounds = state.operation_bounds().await;
        let proof = state
            .proof(bounds.start, NonZeroU64::new(1024).unwrap())
            .await
            .expect("generate proof");

        // Positive: the proof verifies against the committed root, over a non-empty
        // authenticated operation set.
        assert!(verify_state_proof(&proof, &root));
        assert!(!proof.operations().is_empty());

        // Negative: an unrelated root must not verify.
        assert!(!verify_state_proof(&proof, &Sha256::hash(b"not-the-root")));

        // Negative: once the state advances, the stale proof no longer verifies against the
        // new committed root; the proof is bound to the exact committed state.
        state.set(ns.key(0u8, b"account-2"), b"other".to_vec());
        let new_root = state.commit().await.expect("second commit");
        assert_ne!(root, new_root);
        assert!(!verify_state_proof(&proof, &new_root));
    });
}
