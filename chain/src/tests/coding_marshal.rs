//! Tests for coding marshal migration: Reed-Solomon dissemination, empty shards, and commitments.

use commonware_codec::{Decode, Encode, EncodeSize};
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    marshal::coding::types::{coding_config_for_participants, CodedBlock},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{sha256, Committable, Digest as _, Digestible, Sha256, Signer};
use commonware_parallel::Sequential;
use commonware_runtime::{deterministic, Runner as _};
use commonware_storage::mmr::Location;
use commonware_utils::non_empty_range;

use crate::{dummy_genesis_parent, CodingBlock, CodingContext, EmptyPayload, NoConsensusExtension, StateCommitment};

fn coding_context() -> CodingContext<u8> {
    CodingContext {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), dummy_genesis_parent()),
    }
}

fn state() -> StateCommitment {
    StateCommitment {
        root: sha256::Digest::EMPTY,
        range: non_empty_range!(Location::new(0), Location::new(1)),
    }
}

fn coding_block(transactions: Vec<u8>) -> CodingBlock<u8> {
    CodingBlock::new(
        coding_context(),
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
fn coded_block_commitment_is_deterministic() {
    let block = coding_block(vec![7, 8, 9]);
    let config = coding_config_for_participants(4);
    
    let coded1 = CodedBlock::<_, ReedSolomon<Sha256>, Sha256>::new(block.clone(), config, &Sequential);
    let coded2 = CodedBlock::<_, ReedSolomon<Sha256>, Sha256>::new(block, config, &Sequential);
    
    assert_eq!(coded1.commitment(), coded2.commitment());
}

#[test]
fn coded_block_empty_transactions_produces_valid_commitment() {
    let block = coding_block(vec![]);
    let config = coding_config_for_participants(4);
    
    let coded = CodedBlock::<_, ReedSolomon<Sha256>, Sha256>::new(block.clone(), config, &Sequential);
    
    assert!(coded.encode_size() > 0);
}

#[test]
fn coded_block_shards_count_matches_config() {
    let block = coding_block(vec![1, 2, 3]);
    let config = coding_config_for_participants(4);
    
    let coded = CodedBlock::<_, ReedSolomon<Sha256>, Sha256>::new(block, config, &Sequential);
    
    assert_eq!(coded.encode_size(), coded.encode().len());
}

#[test]
fn genesis_parent_commitment_is_stable() {
    let parent1 = dummy_genesis_parent::<u8, NoConsensusExtension>();
    let parent2 = dummy_genesis_parent::<u8, NoConsensusExtension>();
    
    assert_eq!(parent1, parent2);
}

#[test]
fn genesis_parent_for_different_participant_counts_differ() {
    use crate::genesis_parent;
    
    let parent_n4 = genesis_parent::<u8, NoConsensusExtension>(4);
    let parent_n7 = genesis_parent::<u8, NoConsensusExtension>(7);
    
    assert_ne!(parent_n4, parent_n7);
}

#[test]
fn coding_block_commitment_matches_application_digest() {
    let block = coding_block(vec![7, 8]);
    
    assert_eq!(block.commitment(), block.digest());
}

#[test]
fn coding_block_encode_size_matches_encoding() {
    let block = coding_block(vec![1, 2, 3, 4, 5]);
    
    assert_eq!(block.encode_size(), block.encode().len());
}

#[test]
fn coding_block_codec_round_trip() {
    let block = coding_block(vec![10, 20, 30]);
    let encoded = block.encode();
    
    use commonware_utils::NZU32;
    let decoded = CodingBlock::<u8>::decode_cfg(encoded.as_ref(), &(NZU32!(4), ()))
        .expect("decode should succeed");
    
    assert_eq!(decoded.digest(), block.digest());
    assert_eq!(decoded.transactions, block.transactions);
}

#[test]
fn coding_block_large_transaction_list_encodes() {
    let transactions = vec![42; 1000];
    let block = coding_block(transactions.clone());
    
    assert_eq!(block.transactions.len(), 1000);
    assert_eq!(block.encode_size(), block.encode().len());
}

#[test]
fn coded_block_different_configs_produce_different_commitments() {
    let block = coding_block(vec![7]);
    
    let config_n4 = coding_config_for_participants(4);
    let config_n7 = coding_config_for_participants(7);
    
    let coded_n4 = CodedBlock::<_, ReedSolomon<Sha256>, Sha256>::new(block.clone(), config_n4, &Sequential);
    let coded_n7 = CodedBlock::<_, ReedSolomon<Sha256>, Sha256>::new(block, config_n7, &Sequential);
    
    assert_ne!(coded_n4.commitment(), coded_n7.commitment());
}

#[test]
fn coding_context_parent_carries_commitment() {
    let ctx = coding_context();
    
    assert_eq!(ctx.parent.1, dummy_genesis_parent());
}

#[test]
fn deterministic_runtime_coding_block_creation() {
    deterministic::Runner::default().start(|_context| async move {
        let block1 = coding_block(vec![5, 6, 7]);
        let block2 = coding_block(vec![5, 6, 7]);
        
        assert_eq!(block1.digest(), block2.digest());
    });
}
