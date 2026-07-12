//! Tests for the compact, digest-authenticated [`BlockHeader`] and the transaction-root
//! commitment the block digest is now committed over (see `Block::header` / `BlockHeader::digest`).

use commonware_codec::{Decode, Encode};
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_cryptography::{ed25519, sha256, Digest as _, Digestible as _, Signer};
use commonware_storage::mmr::Location;
use commonware_utils::{non_empty_range, NZU32};
use nunchi_chain::{Block, BlockHeader, NoConsensusExtension, StateCommitment};
use nunchi_dkg::Context;

fn context() -> Context {
    Context {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), sha256::Digest::EMPTY),
    }
}

fn state() -> StateCommitment {
    StateCommitment {
        root: sha256::Digest::EMPTY,
        range: non_empty_range!(Location::new(0), Location::new(1)),
    }
}

/// Read config for `BlockHeader<NoConsensusExtension>`: a bound for the reshare log plus the unit
/// extension config.
fn header_cfg() -> (std::num::NonZeroU32, ()) {
    (NZU32!(1), ())
}

fn block(transactions: Vec<u8>) -> Block<u8> {
    Block::new(
        context(),
        sha256::Digest::EMPTY,
        Height::zero(),
        1,
        transactions,
        None,
        (),
        state(),
    )
}

#[test]
fn header_digest_matches_block_digest() {
    let block = block(vec![7, 8, 9]);

    // The compact header reproduces the full block's digest without carrying the transactions.
    assert_eq!(block.header().digest(), block.digest());
}

#[test]
fn changing_a_transaction_changes_root_and_digest() {
    let base = block(vec![7, 8]);
    let changed = block(vec![7, 9]);

    assert_ne!(
        base.header().transaction_root,
        changed.header().transaction_root
    );
    assert_ne!(base.digest(), changed.digest());

    // Each header still authenticates its own block.
    assert_eq!(base.header().digest(), base.digest());
    assert_eq!(changed.header().digest(), changed.digest());
}

#[test]
fn reordering_transactions_changes_root_and_digest() {
    let ordered = block(vec![7, 8]);
    let reordered = block(vec![8, 7]);

    // The transaction root commits to order, not just the multiset of transactions.
    assert_ne!(
        ordered.header().transaction_root,
        reordered.header().transaction_root
    );
    assert_ne!(ordered.digest(), reordered.digest());
}

#[test]
fn empty_and_nonempty_transaction_lists_differ() {
    let empty = block(vec![]);
    let nonempty = block(vec![7]);

    // The count is committed, so an empty list is not the same commitment as any non-empty one.
    assert_ne!(
        empty.header().transaction_root,
        nonempty.header().transaction_root
    );
    // The header still authenticates a block with no transactions.
    assert_eq!(empty.header().digest(), empty.digest());
}

#[test]
fn changing_state_commitment_changes_header_digest() {
    let base = block(vec![7]).header();

    // A different state root changes the authenticated digest.
    let mut changed_root = base.clone();
    changed_root.state_root = block(vec![9, 9]).digest();
    assert_ne!(changed_root.state_root, base.state_root);
    assert_ne!(changed_root.digest(), base.digest());

    // A different state range changes the authenticated digest.
    let mut changed_range = base.clone();
    changed_range.state_range = non_empty_range!(Location::new(0), Location::new(2));
    assert_ne!(changed_range.digest(), base.digest());
}

#[test]
fn header_codec_round_trips() {
    let block = block(vec![7, 8]);
    let header = block.header();

    let decoded =
        BlockHeader::<NoConsensusExtension>::decode_cfg(header.encode().as_ref(), &header_cfg())
            .unwrap();

    assert_eq!(decoded, header);
    // A header recovered from the wire still authenticates the block.
    assert_eq!(decoded.digest(), block.digest());
}
