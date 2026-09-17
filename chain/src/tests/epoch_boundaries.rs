//! Tests for epoch boundaries, resharing logs, and DKG integration with coding blocks.

use commonware_codec::{Decode, Encode};
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_cryptography::{ed25519, sha256, Digest as _, Digestible, Signer};
use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::mmr::Location;
use commonware_utils::non_empty_range;

use crate::{dummy_genesis_parent, CodingBlock, CodingContext, NoConsensusExtension, StateCommitment};

fn state() -> StateCommitment {
    StateCommitment {
        root: sha256::Digest::EMPTY,
        range: non_empty_range!(Location::new(0), Location::new(1)),
    }
}

fn coding_context_at_epoch(epoch: u64) -> CodingContext<u8> {
    CodingContext {
        round: Round::new(Epoch::new(epoch), View::zero()),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), dummy_genesis_parent::<u8, NoConsensusExtension>()),
    }
}

fn coding_block_at_epoch(epoch: u64, transactions: Vec<u8>) -> CodingBlock<u8> {
    use crate::EmptyPayload;
    CodingBlock::new(
        coding_context_at_epoch(epoch),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        transactions,
        None,
        EmptyPayload,
        state(),
    )
}

#[test]
fn epoch_boundary_blocks_at_different_epochs() {
    let epoch0 = coding_block_at_epoch(0, vec![]);
    let epoch1 = coding_block_at_epoch(1, vec![]);
    
    assert_eq!(epoch0.header.context.round.epoch(), Epoch::zero());
    assert_eq!(epoch1.header.context.round.epoch(), Epoch::new(1));
    assert_ne!(epoch0.digest(), epoch1.digest());
}

#[test]
fn coding_context_epoch_is_preserved_in_block() {
    let epoch = 5;
    let block = coding_block_at_epoch(epoch, vec![1, 2, 3]);
    
    assert_eq!(block.header.context.round.epoch().get(), epoch);
}

#[test]
fn coding_block_epoch_transition_changes_round() {
    let block_epoch0 = coding_block_at_epoch(0, vec![]);
    let block_epoch1 = coding_block_at_epoch(1, vec![]);
    
    assert_ne!(
        block_epoch0.header.context.round,
        block_epoch1.header.context.round
    );
}

#[test]
fn coding_block_codec_preserves_no_reshare_log() {
    use crate::EmptyPayload;
    use commonware_utils::NZU32;
    
    let without_reshare = CodingBlock::new(
        coding_context_at_epoch(0),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![7],
        None,
        EmptyPayload,
        state(),
    );
    
    let encoded = without_reshare.encode();
    let decoded = CodingBlock::<u8>::decode_cfg(encoded.as_ref(), &(NZU32!(4), ()))
        .expect("decode should succeed");
    
    assert!(decoded.header.reshare_log.is_none());
}

#[test]
fn different_epochs_at_same_height_produce_different_blocks() {
    use crate::EmptyPayload;
    let epoch0_height5 = CodingBlock::new(
        coding_context_at_epoch(0),
        sha256::Digest::EMPTY,
        Height::new(5),
        1,
        vec![],
        None,
        EmptyPayload,
        state(),
    );
    
    let epoch1_height5 = CodingBlock::new(
        coding_context_at_epoch(1),
        sha256::Digest::EMPTY,
        Height::new(5),
        1,
        vec![],
        None,
        EmptyPayload,
        state(),
    );
    
    assert_ne!(epoch0_height5.digest(), epoch1_height5.digest());
}

#[test]
fn coding_block_round_view_affects_digest() {
    use crate::EmptyPayload;
    let view0 = CodingContext {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), dummy_genesis_parent::<u8, NoConsensusExtension>()),
    };
    
    let view5 = CodingContext {
        round: Round::new(Epoch::zero(), View::new(5)),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), dummy_genesis_parent::<u8, NoConsensusExtension>()),
    };
    
    let block_view0 = CodingBlock::new(
        view0,
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![],
        None,
        EmptyPayload,
        state(),
    );
    
    let block_view5 = CodingBlock::new(
        view5,
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![],
        None,
        EmptyPayload,
        state(),
    );
    
    assert_ne!(block_view0.digest(), block_view5.digest());
}

#[test]
fn coding_block_leader_affects_digest() {
    use crate::EmptyPayload;
    let leader0 = CodingContext {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), dummy_genesis_parent::<u8, NoConsensusExtension>()),
    };
    
    let leader1 = CodingContext {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: ed25519::PrivateKey::from_seed(1).public_key(),
        parent: (View::zero(), dummy_genesis_parent::<u8, NoConsensusExtension>()),
    };
    
    let block_leader0 = CodingBlock::new(
        leader0,
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![],
        None,
        EmptyPayload,
        state(),
    );
    
    let block_leader1 = CodingBlock::new(
        leader1,
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        vec![],
        None,
        EmptyPayload,
        state(),
    );
    
    assert_ne!(block_leader0.digest(), block_leader1.digest());
}

#[test]
fn deterministic_epoch_boundary_behavior() {
    deterministic::Runner::default().start(|_context| async move {
        let block1 = coding_block_at_epoch(0, vec![1]);
        let block2 = coding_block_at_epoch(1, vec![1]);
        
        assert_ne!(block1.digest(), block2.digest());
        
        let block1_again = coding_block_at_epoch(0, vec![1]);
        assert_eq!(block1.digest(), block1_again.digest());
    });
}
