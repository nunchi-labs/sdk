//! Tests for [`BlockHeader`] and the transaction-root commitment the block digest is built on.

use commonware_codec::{Decode, Encode, EncodeSize, Error};
use commonware_consensus::{
    marshal::coding::types::{coding_config_for_participants, CodedBlock},
    simplex::{
        scheme::bls12381_threshold::vrf,
        types::{Finalize, Notarize, Proposal},
    },
    types::{Epoch, Height, Round, View},
    Block as ConsensusBlock, CertifiableBlock, Heightable,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, ed25519, sha256, Committable, Digest as _,
    Digestible as _, Signer,
};
use commonware_parallel::Sequential;
use commonware_storage::mmr::Location;
use commonware_utils::{non_empty, non_empty_range, test_rng, NZU32};
use nunchi_chain::{
    dummy_genesis_parent, Block, BlockHeader, CodingBlock, CodingContext, EmptyPayload, Finalized,
    NoConsensusExtension, Notarized, StateCommitment,
};
use nunchi_dkg::{Context, Scheme};

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
        EmptyPayload,
        state(),
    )
}

fn coding_context() -> CodingContext<u8> {
    CodingContext {
        round: Round::new(Epoch::zero(), View::zero()),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), dummy_genesis_parent()),
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

fn schemes() -> Vec<Scheme> {
    let mut rng = test_rng();
    vrf::fixture::<MinSig, _>(&mut rng, b"nunchi-chain-block-test", 4).schemes
}

fn notarization_for(
    block: &CodingBlock<u8>,
) -> nunchi_dkg::Notarization<nunchi_chain::BlockCommitment<u8>> {
    let commitment = CodedBlock::new(
        block.clone(),
        coding_config_for_participants(4),
        &Sequential,
    )
    .commitment();
    let proposal = Proposal::new(block.header.context.round, View::zero(), commitment);
    let schemes = schemes();
    let notarizes = schemes
        .iter()
        .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("sign notarize"))
        .collect::<Vec<_>>();
    nunchi_dkg::Notarization::from_notarizes(
        &schemes[0],
        non_empty![@notarizes.iter()],
        &Sequential,
    )
    .expect("build notarization")
}

fn finalization_for(
    block: &CodingBlock<u8>,
) -> nunchi_dkg::Finalization<nunchi_chain::BlockCommitment<u8>> {
    let commitment = CodedBlock::new(
        block.clone(),
        coding_config_for_participants(4),
        &Sequential,
    )
    .commitment();
    let proposal = Proposal::new(block.header.context.round, View::zero(), commitment);
    let schemes = schemes();
    let finalizes = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
        .collect::<Vec<_>>();
    nunchi_dkg::Finalization::from_finalizes(
        &schemes[0],
        non_empty![@finalizes.iter()],
        &Sequential,
    )
    .expect("build finalization")
}

#[test]
fn header_digest_matches_block_digest() {
    let block = block(vec![7, 8, 9]);

    assert_eq!(block.header.digest(), block.digest());
}

#[test]
fn changing_a_transaction_changes_root_and_digest() {
    let base = block(vec![7, 8]);
    let changed = block(vec![7, 9]);

    assert_ne!(
        base.header.transaction_root,
        changed.header.transaction_root
    );
    assert_ne!(base.digest(), changed.digest());
    assert_eq!(base.header.digest(), base.digest());
    assert_eq!(changed.header.digest(), changed.digest());
}

#[test]
fn reordering_transactions_changes_root_and_digest() {
    let ordered = block(vec![7, 8]);
    let reordered = block(vec![8, 7]);

    assert_ne!(
        ordered.header.transaction_root,
        reordered.header.transaction_root
    );
    assert_ne!(ordered.digest(), reordered.digest());
}

#[test]
fn empty_and_nonempty_transaction_lists_differ() {
    let empty = block(vec![]);
    let nonempty = block(vec![7]);

    assert_ne!(
        empty.header.transaction_root,
        nonempty.header.transaction_root
    );
    assert_eq!(empty.header.digest(), empty.digest());
}

#[test]
fn changing_state_commitment_changes_header_digest() {
    let base = block(vec![7]).header;

    let mut changed_root = base.clone();
    changed_root.state_root = block(vec![9, 9]).digest();
    assert_ne!(changed_root.state_root, base.state_root);
    assert_ne!(changed_root.digest(), base.digest());

    let mut changed_range = base.clone();
    changed_range.state_range = non_empty_range!(Location::new(0), Location::new(2));
    assert_ne!(changed_range.digest(), base.digest());
}

#[test]
fn header_codec_round_trips() {
    let block = block(vec![7, 8]);
    let header = block.header.clone();

    let decoded =
        BlockHeader::<NoConsensusExtension>::decode_cfg(header.encode().as_ref(), &header_cfg())
            .unwrap();

    assert_eq!(decoded, header);
    assert_eq!(decoded.digest(), block.digest());
}

#[test]
fn decode_rejects_mismatched_transaction_root() {
    let block = block(vec![7, 8]);
    let mut bytes = block.encode().as_ref().to_vec();

    // Tamper with the first transaction byte after the header and count varint, so the
    // transaction list no longer matches the header's transaction root.
    let first_transaction = block.header.encode_size() + 1;
    bytes[first_transaction] = 9;

    let result = Block::<u8>::decode_cfg(bytes.as_slice(), &header_cfg());
    assert!(matches!(
        result,
        Err(Error::Invalid(
            _,
            "transaction root does not match transactions"
        ))
    ));
}

#[test]
fn inner_block_exposes_consensus_header_fields() {
    let block = block(vec![7]);

    assert_eq!(ConsensusBlock::parent(&block), block.header.parent);
    assert_eq!(block.height(), block.header.height);
    assert_eq!(block.context(), block.header.context);
}

#[test]
fn coding_block_traits_and_deref_mut_reach_inner_header() {
    let mut block = coding_block(vec![7, 8]);

    assert_eq!(ConsensusBlock::parent(&*block), block.header.parent);
    assert_eq!(block.height(), block.header.height);
    assert_eq!(block.context().parent.1, dummy_genesis_parent());
    assert_eq!(block.commitment(), block.digest());

    block.header.timestamp = 99;
    assert_eq!(block.header.timestamp, 99);
}

#[test]
fn header_and_block_decode_reject_truncated_buffers() {
    assert!(BlockHeader::<NoConsensusExtension>::decode_cfg(&[] as &[u8], &header_cfg()).is_err());
    assert!(Block::<u8>::decode_cfg(&[] as &[u8], &header_cfg()).is_err());
}

#[test]
fn notarized_and_finalized_round_trip_and_reject_digest_mismatch() {
    let block = coding_block(vec![7]);
    let other = coding_block(vec![8]);
    let notarized = Notarized::new(notarization_for(&block), block.clone());
    let finalized = Finalized::new(finalization_for(&block), block.clone());

    let decoded_notarized = Notarized::<u8>::decode_cfg(notarized.encode().as_ref(), &header_cfg())
        .expect("notarized round-trip");
    assert_eq!(decoded_notarized.block.digest(), block.digest());

    let decoded_finalized = Finalized::<u8>::decode_cfg(finalized.encode().as_ref(), &header_cfg())
        .expect("finalized round-trip");
    assert_eq!(decoded_finalized.block.digest(), block.digest());

    let mut mismatched_notarized = notarized.encode().to_vec();
    let proof_len = notarized.proof.encode_size();
    mismatched_notarized.truncate(proof_len);
    mismatched_notarized.extend_from_slice(other.encode().as_ref());
    assert!(matches!(
        Notarized::<u8>::decode_cfg(mismatched_notarized.as_slice(), &header_cfg()),
        Err(Error::Invalid(
            _,
            "proof payload does not match block digest"
        ))
    ));

    let mut mismatched_finalized = finalized.encode().to_vec();
    let proof_len = finalized.proof.encode_size();
    mismatched_finalized.truncate(proof_len);
    mismatched_finalized.extend_from_slice(other.encode().as_ref());
    assert!(matches!(
        Finalized::<u8>::decode_cfg(mismatched_finalized.as_slice(), &header_cfg()),
        Err(Error::Invalid(
            _,
            "proof payload does not match block digest"
        ))
    ));
}
