use std::num::NonZeroU64;

use commonware_codec::{Decode, Encode, RangeCfg};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};

use crate::state_db::{
    verify_state_proof, verify_state_update, CommitState, Namespace, QmdbState, StateProof,
    StateProofCfg, StateStore,
};

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
        let bounds = state.operation_bounds();
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

#[test]
fn historical_proof_verifies_against_past_root() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "historical-proof-test")
            .await
            .expect("init state");
        let ns = Namespace::new(b"test-ns");
        let key1 = ns.key(0u8, b"account-1");

        // Commit R1, then capture its root and operation count (the historical size that
        // produced that root).
        state.set(key1, b"balance".to_vec());
        let root1 = state.commit().await.expect("first commit");
        let bounds1 = state.operation_bounds();
        let size1 = bounds1.end;

        // Advance the state to a distinct root R2.
        state.set(ns.key(0u8, b"account-2"), b"other".to_vec());
        let root2 = state.commit().await.expect("second commit");
        assert_ne!(root1, root2);

        // A proof generated as-of R1's size verifies against the historical root R1, even though
        // the state has since advanced to R2.
        let proof = state
            .historical_proof(size1, bounds1.start, NonZeroU64::new(1024).unwrap())
            .await
            .expect("historical proof");

        // The proof reports the operation range it starts at, so a caller can line it up against a
        // block's state range.
        assert_eq!(proof.start(), bounds1.start);
        assert!(verify_state_proof(&proof, &root1));

        // It authenticates the account-1 update that existed as of R1...
        assert!(verify_state_update(&proof, &root1, &key1, b"balance"));

        // ...but does not verify against the newer root R2: the proof is bound to the historical
        // state it was generated against.
        assert!(!verify_state_proof(&proof, &root2));
    });
}

#[test]
fn verify_state_update_checks_operation_membership() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "state-update-membership-test")
            .await
            .expect("init state");
        let ns = Namespace::new(b"test-ns");
        let key = ns.key(0u8, b"account-1");

        state.set(key, b"balance".to_vec());
        let root = state.commit().await.expect("commit");

        let bounds = state.operation_bounds();
        let proof = state
            .proof(bounds.start, NonZeroU64::new(1024).unwrap())
            .await
            .expect("generate proof");

        // The proof itself is valid against the committed root; verify_state_update layers an
        // operation-membership check on top of that.
        assert!(verify_state_proof(&proof, &root));

        // Positive: the exact committed key/value is authenticated by the proof.
        assert!(verify_state_update(&proof, &root, &key, b"balance"));

        // Negative: the proof verifies against the root, but it contains no operation writing a
        // different value to the key, so membership fails.
        assert!(!verify_state_update(&proof, &root, &key, b"wrong-value"));

        // Negative: likewise for a key that was never written.
        let absent = ns.key(0u8, b"account-absent");
        assert!(!verify_state_update(&proof, &root, &absent, b"balance"));

        // Negative: a wrong root fails outright, regardless of membership.
        assert!(!verify_state_update(
            &proof,
            &Sha256::hash(b"not-the-root"),
            &key,
            b"balance"
        ));
    });
}

#[test]
fn state_proof_codec_roundtrips() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "state-proof-codec-test")
            .await
            .expect("init state");
        let ns = Namespace::new(b"test-ns");
        let key = ns.key(0u8, b"account-1");

        state.set(key, b"balance".to_vec());
        let root = state.commit().await.expect("commit");

        let bounds = state.operation_bounds();
        let proof = state
            .proof(bounds.start, NonZeroU64::new(1024).unwrap())
            .await
            .expect("generate proof");

        // Encode, then decode with generous bounds, and confirm the decoded proof is fully
        // equivalent: it verifies against the root and authenticates the same update.
        let encoded = proof.encode();
        let cfg = StateProofCfg {
            max_proof_digests: 1024,
            operations: RangeCfg::new(0..=1024usize),
            value_len: RangeCfg::new(0..=4096usize),
        };
        let decoded = StateProof::decode_cfg(encoded, &cfg).expect("decode state proof");

        assert!(verify_state_proof(&decoded, &root));
        assert!(verify_state_update(&decoded, &root, &key, b"balance"));
        assert_eq!(decoded.operations().len(), proof.operations().len());
    });
}
