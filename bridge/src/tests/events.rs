use commonware_codec::DecodeExt;
use commonware_cryptography::{Hasher, Sha256};
use nunchi_common::Address;
use nunchi_crypto::PrivateKey;

use crate::{
    events::transfer_locked_event, AssetId, ChainId, TransferLocked, TransferRecordId,
    TRANSFER_LOCKED_EVENT,
};

#[test]
fn transfer_locked_event_round_trips_all_fields() {
    let source_chain_id = ChainId(Sha256::hash(b"source-chain"));
    let value = TransferLocked {
        record_id: TransferRecordId(Sha256::hash(b"record")),
        source_chain_id,
        destination_chain_id: ChainId(Sha256::hash(b"destination-chain")),
        source_asset: AssetId::derive(&source_chain_id, &Sha256::hash(b"asset")),
        amount: u128::MAX,
        sender: Address::external(&PrivateKey::from_seed(1).public_key()),
        recipient: Address::external(&PrivateKey::from_seed(2).public_key()),
        nonce: u64::MAX,
    };

    let event = transfer_locked_event(value.clone());

    assert_eq!(event.name.as_ref(), TRANSFER_LOCKED_EVENT);
    assert_eq!(
        TransferLocked::decode(event.value.as_ref()).expect("decode event"),
        value
    );
}
