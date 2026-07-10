use std::num::NonZeroU64;

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use nunchi_bridge::{
    record::put_transfer_record, AssetId, BridgeGenesis, BridgeOperation, BridgeTransaction,
    BridgeTransferRecord, ChainId,
};
use nunchi_coins::{CoinOperation, CoinSpec, Ledger, TokenCreated, TokenName, TokenSymbol};
use nunchi_common::{
    state_db::CommitState, Address, QmdbState, Runtime, RuntimeContext, VecEventSink,
};
use nunchi_crypto::PrivateKey;

use crate::bridge_assets::set_asset_coin;
use crate::runtime::{CoinsRuntime, RuntimeError};
use crate::Transaction;

fn key(seed: u64) -> PrivateKey {
    PrivateKey::ed25519_from_seed(seed)
}

fn addr(seed: u64) -> Address {
    Address::external(&key(seed).public_key())
}

fn source_chain() -> ChainId {
    ChainId(Sha256::hash(b"source-chain"))
}

fn dest_chain() -> ChainId {
    ChainId(Sha256::hash(b"dest-chain"))
}

fn spec(symbol: &str, name: &str, supply: u128) -> CoinSpec {
    CoinSpec::new(
        TokenSymbol::new(symbol).unwrap(),
        TokenName::new(name).unwrap(),
        9,
        supply,
        None,
    )
}

#[test]
fn bridge_claim_verifies_proof_and_mints_mapped_asset() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(2);

        // ----- Source chain: write the transfer record and prove it. -----
        let mut source = QmdbState::init(context.child("src"), "claim-src")
            .await
            .unwrap();
        let src_local_asset = Sha256::hash(b"src-coin");
        let record = BridgeTransferRecord {
            source_chain_id: source_chain(),
            destination_chain_id: dest_chain(),
            source_asset: AssetId::derive(&source_chain(), &src_local_asset),
            amount: 400,
            sender: addr(1),
            recipient: recipient.clone(),
            nonce: 0,
        };
        put_transfer_record(&mut source, &record);
        let source_root = source.commit().await.unwrap();
        let bounds = source.operation_bounds().await;
        let proof = source
            .proof(bounds.start, NonZeroU64::new(1024).unwrap())
            .await
            .unwrap();

        // Local sanity: the proof authenticates the record against the source root.
        assert!(
            nunchi_common::state_db::verify_state_update(
                &proof,
                &source_root,
                &nunchi_bridge::transfer_record_key(&record.record_id()),
                record.encode().as_ref(),
            ),
            "proof should authenticate the record locally"
        );

        // ----- Destination chain: wrapped token, mapping, attestor; anchor then claim. -----
        let mut dest = QmdbState::init(context.child("dst"), "claim-dst")
            .await
            .unwrap();
        let issuer = key(5);
        let mut ev = VecEventSink::new();
        // The wrapped destination coin starts at 0 supply; bridge_mint grows it.
        let create_wrapped = Transaction::from(nunchi_coins::Transaction::sign(
            &issuer,
            0,
            CoinOperation::CreateToken {
                spec: spec("WSC", "Wrapped Source", 0),
            },
        ));
        CoinsRuntime::apply(&mut dest, RuntimeContext::default(), &create_wrapped, &mut ev)
            .await
            .unwrap();
        let wrapped = TokenCreated::decode(ev.events()[0].value.as_ref())
            .unwrap()
            .token
            .id;

        let attestor = key(3);
        BridgeGenesis::new(dest_chain())
            .with_attestor(Address::external(&attestor.public_key()))
            .apply(&mut dest);
        set_asset_coin(&mut dest, &record.source_asset, &wrapped);

        let anchor = Transaction::from(BridgeTransaction::sign(
            &attestor,
            0,
            BridgeOperation::AnchorForeignRoot {
                source_chain_id: source_chain(),
                view: 7,
                state_root: source_root,
            },
        ));
        CoinsRuntime::apply(
            &mut dest,
            RuntimeContext::default(),
            &anchor,
            &mut VecEventSink::new(),
        )
        .await
        .unwrap();

        let claimer = key(4);
        let claim = Transaction::from(BridgeTransaction::sign(
            &claimer,
            0,
            BridgeOperation::Claim {
                source_chain_id: source_chain(),
                source_view: 7,
                record,
                proof,
            },
        ));
        CoinsRuntime::apply(
            &mut dest,
            RuntimeContext::default(),
            &claim,
            &mut VecEventSink::new(),
        )
        .await
        .unwrap();

        // The recipient was minted 400 of the wrapped coin on the destination chain, and the
        // wrapped token's supply grew to match (backed 1:1 by the source escrow, on the source
        // chain, which the destination claim never touches).
        let recipient_bal = {
            let ledger = Ledger::new(&mut dest);
            ledger.balance(&recipient, &wrapped).await.unwrap()
        };
        assert_eq!(recipient_bal, 400);
    });
}

#[test]
fn bridge_claim_rejects_unmapped_asset_without_minting() {
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(2);
        let record = BridgeTransferRecord {
            source_chain_id: source_chain(),
            destination_chain_id: dest_chain(),
            source_asset: AssetId::derive(&source_chain(), &Sha256::hash(b"coin")),
            amount: 400,
            sender: addr(9),
            recipient: recipient.clone(),
            nonce: 0,
        };

        // Minimal source: write the record directly and prove it.
        let mut source = QmdbState::init(context.child("src"), "unmapped-src")
            .await
            .unwrap();
        put_transfer_record(&mut source, &record);
        let source_root = source.commit().await.unwrap();
        let bounds = source.operation_bounds().await;
        let proof = source
            .proof(bounds.start, NonZeroU64::new(1024).unwrap())
            .await
            .unwrap();

        // Destination has an attestor and an anchor, but no asset mapping.
        let mut dest = QmdbState::init(context.child("dst"), "unmapped-dst")
            .await
            .unwrap();
        let attestor = key(3);
        BridgeGenesis::new(dest_chain())
            .with_attestor(Address::external(&attestor.public_key()))
            .apply(&mut dest);
        let anchor = Transaction::from(BridgeTransaction::sign(
            &attestor,
            0,
            BridgeOperation::AnchorForeignRoot {
                source_chain_id: source_chain(),
                view: 7,
                state_root: source_root,
            },
        ));
        CoinsRuntime::apply(
            &mut dest,
            RuntimeContext::default(),
            &anchor,
            &mut VecEventSink::new(),
        )
        .await
        .unwrap();

        // Claim fails because the asset is unmapped; nothing is consumed or minted.
        let claimer = key(4);
        let claim = Transaction::from(BridgeTransaction::sign(
            &claimer,
            0,
            BridgeOperation::Claim {
                source_chain_id: source_chain(),
                source_view: 7,
                record: record.clone(),
                proof,
            },
        ));
        let err = CoinsRuntime::apply(
            &mut dest,
            RuntimeContext::default(),
            &claim,
            &mut VecEventSink::new(),
        )
        .await
        .expect_err("unmapped asset");
        assert!(matches!(err, RuntimeError::UnmappedAsset));

        // The record was not consumed, so a later (mapped) claim could still succeed.
        assert!(
            !nunchi_bridge::is_consumed(&dest, &source_chain(), &record.record_id())
                .await
                .unwrap()
        );
    });
}

#[test]
fn bridge_claim_settlement_failure_leaves_no_event_or_consumption() {
    // If minting fails after the claim verifies, the whole operation reverts: no TransferClaimed
    // event escapes to the sink and the record is not marked consumed.
    deterministic::Runner::default().start(|context| async move {
        let recipient = addr(2);
        let record = BridgeTransferRecord {
            source_chain_id: source_chain(),
            destination_chain_id: dest_chain(),
            source_asset: AssetId::derive(&source_chain(), &Sha256::hash(b"coin")),
            amount: 400,
            sender: addr(9),
            recipient,
            nonce: 0,
        };

        let mut source = QmdbState::init(context.child("src"), "settle-fail-src")
            .await
            .unwrap();
        put_transfer_record(&mut source, &record);
        let source_root = source.commit().await.unwrap();
        let bounds = source.operation_bounds().await;
        let proof = source
            .proof(bounds.start, NonZeroU64::new(1024).unwrap())
            .await
            .unwrap();

        // Destination maps the asset to a coin capped below the transfer amount, so bridge_mint
        // overflows the max supply.
        let mut dest = QmdbState::init(context.child("dst"), "settle-fail-dst")
            .await
            .unwrap();
        let issuer = key(5);
        let mut ev = VecEventSink::new();
        let create_capped = Transaction::from(nunchi_coins::Transaction::sign(
            &issuer,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new(
                    TokenSymbol::new("CAP").unwrap(),
                    TokenName::new("Capped").unwrap(),
                    9,
                    0,
                    Some(100),
                ),
            },
        ));
        CoinsRuntime::apply(&mut dest, RuntimeContext::default(), &create_capped, &mut ev)
            .await
            .unwrap();
        let capped = TokenCreated::decode(ev.events()[0].value.as_ref())
            .unwrap()
            .token
            .id;

        let attestor = key(3);
        BridgeGenesis::new(dest_chain())
            .with_attestor(Address::external(&attestor.public_key()))
            .apply(&mut dest);
        set_asset_coin(&mut dest, &record.source_asset, &capped);
        let anchor = Transaction::from(BridgeTransaction::sign(
            &attestor,
            0,
            BridgeOperation::AnchorForeignRoot {
                source_chain_id: source_chain(),
                view: 7,
                state_root: source_root,
            },
        ));
        CoinsRuntime::apply(
            &mut dest,
            RuntimeContext::default(),
            &anchor,
            &mut VecEventSink::new(),
        )
        .await
        .unwrap();

        // The claim verifies, but minting 400 exceeds the cap of 100 -> the whole op reverts.
        let claimer = key(4);
        let claim = Transaction::from(BridgeTransaction::sign(
            &claimer,
            0,
            BridgeOperation::Claim {
                source_chain_id: source_chain(),
                source_view: 7,
                record: record.clone(),
                proof,
            },
        ));
        let mut claim_events = VecEventSink::new();
        let err = CoinsRuntime::apply(
            &mut dest,
            RuntimeContext::default(),
            &claim,
            &mut claim_events,
        )
        .await
        .expect_err("mint should overflow the cap");
        assert!(matches!(
            err,
            RuntimeError::Coins(nunchi_coins::LedgerError::MaxSupplyExceeded { .. })
        ));

        // No event escaped, and the record was not consumed.
        assert!(claim_events.is_empty(), "no event should escape a failed claim");
        assert!(
            !nunchi_bridge::is_consumed(&dest, &source_chain(), &record.record_id())
                .await
                .unwrap()
        );
    });
}
