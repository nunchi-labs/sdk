use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};
use nunchi_common::{state_db::CommitState, Address, QmdbState};
use nunchi_crypto::PrivateKey;

use crate::record::{
    consumed_record_key, is_consumed, mark_consumed, put_transfer_record, transfer_record,
    transfer_record_key, AssetId, BridgeTransferRecord, ChainId, TransferRecordId,
};

fn addr(seed: u64) -> Address {
    Address::external(&PrivateKey::from_seed(seed).public_key())
}

fn record() -> BridgeTransferRecord {
    let source_chain_id = ChainId(Sha256::hash(b"chain-a"));
    BridgeTransferRecord {
        source_chain_id,
        destination_chain_id: ChainId(Sha256::hash(b"chain-b")),
        source_asset: AssetId::derive(&source_chain_id, &Sha256::hash(b"coin")),
        amount: 1_000,
        sender: addr(1),
        recipient: addr(2),
        nonce: 7,
    }
}

#[test]
fn transfer_record_codec_round_trips() {
    let record = record();
    let decoded = BridgeTransferRecord::decode(record.encode().as_ref()).unwrap();
    assert_eq!(record, decoded);
}

#[test]
fn digest_newtypes_round_trip_through_codec() {
    let chain = ChainId(Sha256::hash(b"chain-a"));
    let asset = AssetId::derive(&chain, &Sha256::hash(b"coin"));
    let record_id = TransferRecordId(Sha256::hash(b"record"));

    assert_eq!(ChainId::decode(chain.encode().as_ref()).unwrap(), chain);
    let decoded_asset = AssetId::decode(asset.encode().as_ref()).unwrap();
    assert_eq!(decoded_asset, asset);
    assert_eq!(
        TransferRecordId::decode(record_id.encode().as_ref()).unwrap(),
        record_id
    );

    // The digest accessor is stable across encode/decode.
    assert_eq!(decoded_asset.digest(), asset.digest());
}

#[test]
fn record_id_is_deterministic() {
    // Same fields -> same id.
    assert_eq!(record().record_id(), record().record_id());
}

#[test]
fn record_id_changes_with_every_field() {
    let base = record();
    let id = base.record_id();

    let mutations: Vec<BridgeTransferRecord> = vec![
        BridgeTransferRecord {
            source_chain_id: ChainId(Sha256::hash(b"other")),
            ..base.clone()
        },
        BridgeTransferRecord {
            destination_chain_id: ChainId(Sha256::hash(b"other")),
            ..base.clone()
        },
        BridgeTransferRecord {
            source_asset: AssetId::derive(&base.source_chain_id, &Sha256::hash(b"other")),
            ..base.clone()
        },
        BridgeTransferRecord {
            amount: base.amount + 1,
            ..base.clone()
        },
        BridgeTransferRecord {
            sender: addr(9),
            ..base.clone()
        },
        BridgeTransferRecord {
            recipient: addr(9),
            ..base.clone()
        },
        BridgeTransferRecord {
            nonce: base.nonce + 1,
            ..base.clone()
        },
    ];

    for mutated in mutations {
        assert_ne!(mutated.record_id(), id, "changing a field must change the id");
    }
}

#[test]
fn asset_id_is_chain_scoped() {
    let coin = Sha256::hash(b"coin");
    let chain_a = ChainId(Sha256::hash(b"chain-a"));
    let chain_b = ChainId(Sha256::hash(b"chain-b"));

    // Deterministic for a given (chain, local asset).
    assert_eq!(
        AssetId::derive(&chain_a, &coin),
        AssetId::derive(&chain_a, &coin)
    );
    // The same local asset on two different chains yields distinct ids.
    assert_ne!(
        AssetId::derive(&chain_a, &coin),
        AssetId::derive(&chain_b, &coin)
    );
}

#[test]
fn keys_are_deterministic_and_scoped() {
    let id = TransferRecordId(Sha256::hash(b"record"));
    let other_id = TransferRecordId(Sha256::hash(b"other-record"));
    let chain = ChainId(Sha256::hash(b"chain-a"));
    let other_chain = ChainId(Sha256::hash(b"chain-b"));

    // Deterministic.
    assert_eq!(transfer_record_key(&id), transfer_record_key(&id));
    assert_eq!(
        consumed_record_key(&chain, &id),
        consumed_record_key(&chain, &id)
    );

    // A transfer-record key and a consumed key for the same id never collide (different tables).
    assert_ne!(transfer_record_key(&id), consumed_record_key(&chain, &id));

    // Consumed keys are scoped by both source chain and record id.
    assert_ne!(
        consumed_record_key(&chain, &id),
        consumed_record_key(&other_chain, &id)
    );
    assert_ne!(
        consumed_record_key(&chain, &id),
        consumed_record_key(&chain, &other_id)
    );
}

#[test]
fn record_persists_and_reads_back() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-record-test")
            .await
            .expect("init state");

        let record = record();
        let id = record.record_id();
        put_transfer_record(&mut state, &record);
        state.commit().await.expect("commit");

        assert_eq!(
            transfer_record(&state, &id).await.expect("read"),
            Some(record)
        );
        // An unknown id reads back as absent.
        let unknown = TransferRecordId(Sha256::hash(b"unknown"));
        assert_eq!(transfer_record(&state, &unknown).await.expect("read"), None);
    });
}

#[test]
fn consumed_marker_is_set_and_checked() {
    deterministic::Runner::default().start(|context| async move {
        let mut state = QmdbState::init(context, "bridge-consumed-test")
            .await
            .expect("init state");

        let chain = ChainId(Sha256::hash(b"chain-a"));
        let id = TransferRecordId(Sha256::hash(b"record"));

        assert!(!is_consumed(&state, &chain, &id).await.expect("read"));

        mark_consumed(&mut state, &chain, &id);
        state.commit().await.expect("commit");

        assert!(is_consumed(&state, &chain, &id).await.expect("read"));
        // A different record id from the same chain is independent.
        let other = TransferRecordId(Sha256::hash(b"other-record"));
        assert!(!is_consumed(&state, &chain, &other).await.expect("read"));
    });
}
