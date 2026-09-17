use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, Sha256};
use nunchi_common::Address;
use nunchi_crypto::PrivateKey;

use crate::events::{
    foreign_root_anchored_event, transfer_claimed_event, transfer_locked_event, ForeignRootAnchored,
    TransferClaimed, TransferLocked, FOREIGN_ROOT_ANCHORED_EVENT, TRANSFER_CLAIMED_EVENT,
    TRANSFER_LOCKED_EVENT,
};
use crate::record::{AssetId, ChainId, TransferRecordId};

fn addr(seed: u64) -> Address {
    Address::external(&PrivateKey::from_seed(seed).public_key())
}

fn chain(label: &[u8]) -> ChainId {
    ChainId(Sha256::hash(label))
}

fn locked() -> TransferLocked {
    let source = chain(b"src");
    TransferLocked {
        record_id: TransferRecordId(Sha256::hash(b"record")),
        source_chain_id: source,
        destination_chain_id: chain(b"dst"),
        source_asset: AssetId::derive(&source, &Sha256::hash(b"coin")),
        amount: 99,
        sender: addr(1),
        recipient: addr(2),
        nonce: 3,
    }
}

fn anchored() -> ForeignRootAnchored {
    ForeignRootAnchored {
        source_chain_id: chain(b"src"),
        view: 11,
        state_root: Sha256::hash(b"root"),
    }
}

fn claimed() -> TransferClaimed {
    let source = chain(b"src");
    TransferClaimed {
        record_id: TransferRecordId(Sha256::hash(b"record")),
        source_chain_id: source,
        source_view: 7,
        source_asset: AssetId::derive(&source, &Sha256::hash(b"coin")),
        recipient: addr(2),
        amount: 400,
    }
}

fn assert_truncated_fails<T>(value: &T)
where
    T: Encode + DecodeExt<()> + Eq + std::fmt::Debug,
{
    let encoded = value.encode();
    assert!(
        encoded.len() > 1,
        "encoded payload must be large enough to truncate"
    );
    assert!(T::decode(&encoded[..encoded.len() - 1]).is_err());
    assert!(T::decode(&[][..]).is_err());
}

#[test]
fn transfer_locked_event_round_trips() {
    let value = locked();
    let decoded = TransferLocked::decode(value.encode().as_ref()).expect("decode");
    assert_eq!(decoded, value);
    assert_truncated_fails(&value);

    let event = transfer_locked_event(value);
    assert_eq!(event.name.as_ref(), TRANSFER_LOCKED_EVENT);
}

#[test]
fn foreign_root_anchored_event_round_trips() {
    let value = anchored();
    let decoded = ForeignRootAnchored::decode(value.encode().as_ref()).expect("decode");
    assert_eq!(decoded, value);
    assert_truncated_fails(&value);

    let event = foreign_root_anchored_event(value);
    assert_eq!(event.name.as_ref(), FOREIGN_ROOT_ANCHORED_EVENT);
}

#[test]
fn transfer_claimed_event_round_trips() {
    let value = claimed();
    let decoded = TransferClaimed::decode(value.encode().as_ref()).expect("decode");
    assert_eq!(decoded, value);
    assert_truncated_fails(&value);

    let event = transfer_claimed_event(value);
    assert_eq!(event.name.as_ref(), TRANSFER_CLAIMED_EVENT);
}
