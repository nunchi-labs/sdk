use bytes::Bytes;
use commonware_consensus::types::Height;
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::Runner as _;
use jsonrpsee::core::params::ObjectParams;
use nunchi_common::{receipts_root, Event, EventAttribute, TransactionEvents};
use nunchi_rpc::{encode_hex, RpcRouter};

use crate::{
    rpc::{
        EventQueryResponse, EventStreamResponse, EventsRpc, FinalizedEventsResponse,
        TransactionQueryResponse,
    },
    FinalizedEventArchive, FinalizedEvents, MAX_EVENT_QUERY_LIMIT,
};

fn event(value: &'static [u8]) -> Event {
    Event::new(
        Bytes::from_static(b"coins"),
        Bytes::from_static(b"minted"),
        1,
        vec![EventAttribute::new(
            Bytes::from_static(b"account"),
            Bytes::from_static(value),
        )],
    )
}

fn batch(height: u64, tx_label: &'static [u8], event: Event) -> FinalizedEvents {
    let tx_digest = Sha256::hash(tx_label);
    let transaction = TransactionEvents::new(0, tx_digest, vec![event]).expect("transaction");
    FinalizedEvents {
        height: Height::new(height),
        block_digest: Sha256::hash(&height.to_be_bytes()),
        block_timestamp: 1_000 + height,
        receipts_root: receipts_root(&[transaction.receipt]),
        transactions: vec![transaction],
    }
}

fn module(archive: FinalizedEventArchive) -> jsonrpsee::RpcModule<()> {
    let mut router = RpcRouter::new(());
    crate::rpc::register(&mut router, EventsRpc::new(archive)).expect("register events RPC");
    router.into_module()
}

#[test]
fn event_rpc_queries_archive() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let archive = FinalizedEventArchive::new();
        let first = batch(1, b"tx-1", event(b"alice"));
        let second = batch(2, b"tx-2", event(b"bob"));
        archive.insert(first.clone()).expect("insert first");
        archive.insert(second.clone()).expect("insert second");
        let module = module(archive);

        let mut height_params = ObjectParams::new();
        height_params.insert("height", 1u64).expect("height param");
        let by_height: Option<FinalizedEventsResponse> = module
            .call("events.batch_by_height", height_params)
            .await
            .expect("height response");
        assert_eq!(
            by_height.unwrap().block_digest,
            encode_hex(&first.block_digest)
        );

        let mut block_params = ObjectParams::new();
        block_params
            .insert("block_digest", encode_hex(&second.block_digest))
            .expect("block digest param");
        let by_block: Option<FinalizedEventsResponse> = module
            .call("events.batch_by_block", block_params)
            .await
            .expect("block response");
        assert_eq!(by_block.unwrap().height, 2);

        let mut tx_params = ObjectParams::new();
        tx_params
            .insert(
                "transaction_digest",
                encode_hex(&first.transactions[0].receipt.tx_digest),
            )
            .expect("transaction digest param");
        let by_transaction: TransactionQueryResponse = module
            .call("events.transaction", tx_params)
            .await
            .expect("transaction response");
        assert_eq!(by_transaction.transactions.len(), 1);
        assert_eq!(by_transaction.transactions[0].height, 1);

        let mut query_params = ObjectParams::new();
        query_params
            .insert("module", "coins")
            .expect("module param");
        query_params.insert("kind", "minted").expect("kind param");
        query_params.insert("version", 1u16).expect("version param");
        query_params.insert("key", "account").expect("key param");
        query_params
            .insert("from_height", Some(2u64))
            .expect("from height param");
        query_params
            .insert("limit", Some(10usize))
            .expect("limit param");
        let events: EventQueryResponse = module
            .call("events.query", query_params)
            .await
            .expect("event query response");
        assert_eq!(events.events.len(), 1);
        assert_eq!(events.events[0].height, 2);
        assert_eq!(events.events[0].event.attributes[0].value, "626f62");

        let mut stream_params = ObjectParams::new();
        stream_params
            .insert("from_height", 1u64)
            .expect("stream from height param");
        stream_params
            .insert("limit", Some(2usize))
            .expect("stream limit param");
        let stream: EventStreamResponse = module
            .call("events.stream", stream_params)
            .await
            .expect("stream response");
        assert_eq!(stream.batches.len(), 2);
        assert_eq!(stream.next_height, Some(3));

        let mut default_stream_params = ObjectParams::new();
        default_stream_params
            .insert("from_height", 2u64)
            .expect("default stream from height param");
        let stream: EventStreamResponse = module
            .call("events.stream", default_stream_params)
            .await
            .expect("default stream response");
        assert_eq!(stream.batches.len(), 1);
    });
}

#[test]
fn event_rpc_rejects_oversized_query_limit() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let module = module(FinalizedEventArchive::new());
        let mut params = ObjectParams::new();
        params.insert("module", "coins").expect("module param");
        params.insert("kind", "minted").expect("kind param");
        params.insert("version", 1u16).expect("version param");
        params.insert("key", "account").expect("key param");
        params
            .insert("from_height", Option::<u64>::None)
            .expect("from height param");
        params
            .insert("limit", Some(MAX_EVENT_QUERY_LIMIT + 1))
            .expect("limit param");

        let error = module
            .call::<_, EventQueryResponse>("events.query", params)
            .await
            .expect_err("oversized limit should be rejected");
        assert!(error.to_string().contains("limit exceeds maximum"));
    });
}
