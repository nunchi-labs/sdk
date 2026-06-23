mod common;

use common::network::{TestNetworkBuilder, ValidatorConfig};
use commonware_cryptography::{Hasher, Sha256};
use commonware_runtime::{deterministic, Clock, Runner as _};
use nunchi_coins::Address;
use nunchi_coins_chain::{rpc, Transaction};
use nunchi_crypto::PrivateKey;
use nunchi_hermes_oracle::{feed_id_from_hermes_id, parse_hermes_price_update, FeedObservation};
use nunchi_oracle::{
    FeedId, MarketId, OracleConfig, OracleOperation, OracleStatus, Price, SourceId,
    Transaction as OracleTransaction, UpdaterPolicy,
};
use nunchi_rpc::{encode_hex, ServerBuilder};
use reqwest::header::ACCEPT;
use std::{
    io::Read,
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const VALIDATORS: u32 = 4;
const SAMPLES: usize = 10;
const BTC_USD_PRICE_ID: &str = "e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43";

fn oracle_market() -> MarketId {
    MarketId(Sha256::hash(b"coins-chain-live-hermes-btc-usd-market"))
}

fn oracle_source() -> SourceId {
    SourceId(Sha256::hash(b"coins-chain-live-hermes-source"))
}

fn authority_key(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn price(raw_value: i128, raw_decimals: u8) -> Price {
    if raw_decimals >= 6 {
        Price::new(raw_value / 10i128.pow(u32::from(raw_decimals - 6)), 6)
    } else {
        Price::new(raw_value * 10i128.pow(u32::from(6 - raw_decimals)), 6)
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

struct BlockingHermesStream {
    response: reqwest::blocking::Response,
    raw: String,
}

impl BlockingHermesStream {
    fn connect() -> Self {
        let response = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("build Hermes client")
            .get("https://hermes.pyth.network/v2/updates/price/stream")
            .header(ACCEPT, "text/event-stream")
            .query(&[("ids[]", BTC_USD_PRICE_ID), ("parsed", "true")])
            .send()
            .expect("connect to Hermes stream")
            .error_for_status()
            .expect("Hermes returned error status");
        Self {
            response,
            raw: String::new(),
        }
    }

    fn next_after(&mut self, min_publish_time_ms: Option<u64>) -> (FeedObservation, u128) {
        let started = Instant::now();
        let mut chunk = [0u8; 4096];

        loop {
            let len = self.response.read(&mut chunk).expect("read Hermes stream");
            assert!(len > 0, "Hermes stream closed before an update");
            let text = std::str::from_utf8(&chunk[..len]).expect("Hermes stream emitted non-UTF8");
            self.raw.push_str(text);

            loop {
                let Some((observation, consumed)) =
                    pop_sse_event(&self.raw).map(|(event, consumed)| {
                        (
                            parse_sse_observation(event).expect("parse Hermes stream event"),
                            consumed,
                        )
                    })
                else {
                    break;
                };
                self.raw.drain(..consumed);
                let Some(observation) = observation else {
                    continue;
                };
                if min_publish_time_ms.is_some_and(|min| observation.publish_time_ms <= min) {
                    continue;
                }
                return (observation, started.elapsed().as_millis());
            }
        }
    }
}

fn pop_sse_event(raw: &str) -> Option<(&str, usize)> {
    let index = raw.find("\n\n").or_else(|| raw.find("\r\n\r\n"))?;
    let separator_len = if raw[index..].starts_with("\r\n\r\n") {
        4
    } else {
        2
    };
    Some((&raw[..index], index + separator_len))
}

fn parse_sse_observation(
    event: &str,
) -> Result<Option<FeedObservation>, nunchi_hermes_oracle::HermesError> {
    let mut data = String::new();
    for line in event.lines() {
        let line = line.trim_end_matches('\r');
        let Some(value) = line.strip_prefix("data:") else {
            continue;
        };
        if !data.is_empty() {
            data.push('\n');
        }
        data.push_str(value.trim_start());
    }
    if data.is_empty() {
        return Ok(None);
    }
    parse_hermes_price_update(&data, BTC_USD_PRICE_ID)
}

struct RpcServer {
    url: String,
    stop: mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl RpcServer {
    fn start(submitter: nunchi_mempool::MempoolHandle<Transaction>) -> Self {
        let (address_tx, address_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            commonware_runtime::tokio::Runner::default().start(|_| async move {
                let module = rpc::standalone_chain_mempool_module(submitter)
                    .expect("build chain mempool RPC module");
                let server = ServerBuilder::default()
                    .build("127.0.0.1:0")
                    .await
                    .expect("bind chain mempool RPC server");
                let address = server.local_addr().expect("RPC server address");
                let handle = server.start(module);
                address_tx.send(address).expect("send RPC server address");
                while stop_rx.try_recv().is_err() {
                    ::tokio::time::sleep(Duration::from_millis(10)).await;
                }
                handle.stop().expect("stop RPC server");
            });
        });
        let address = address_rx.recv().expect("receive RPC server address");
        Self {
            url: format!("http://{address}"),
            stop: stop_tx,
            thread: Some(thread),
        }
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join RPC server thread");
        }
    }
}

#[test]
#[ignore = "live benchmark: calls public Hermes and measures local oracle finalization"]
fn public_hermes_btc_usd_update_finalizes() {
    let mut hermes = BlockingHermesStream::connect();
    let (first_observation, first_stream_wait_ms) = hermes.next_after(None);
    let start_time = UNIX_EPOCH + Duration::from_millis(current_time_ms());
    let executor = deterministic::Runner::from(
        deterministic::Config::default()
            .with_start_time(start_time)
            .with_timeout(Some(Duration::from_secs(120))),
    );
    let wall_started = Instant::now();

    executor.start(|mut context| async move {
        let mut network = TestNetworkBuilder::new(VALIDATORS)
            .with_validator_config(ValidatorConfig {
                leader_timeout: Duration::from_millis(250),
                certification_timeout: Duration::from_millis(500),
            })
            .build(&mut context)
            .await;
        network.start_all().await;

        let admin = authority_key(9_000);
        let updater = authority_key(9_001);
        let admin_id = Address::from(admin.public_key());
        let updater_id = Address::from(updater.public_key());
        let market = oracle_market();
        let source = oracle_source();
        let feed: FeedId = feed_id_from_hermes_id(BTC_USD_PRICE_ID).expect("valid BTC/USD feed ID");
        let submitter = network.submitter(0);
        let rpc = RpcServer::start(submitter.clone());

        let configure = rpc_submit(
            &network,
            &rpc.url,
            OracleTransaction::sign(
                &admin,
                0,
                OracleOperation::ConfigureMarket {
                    market,
                    config: OracleConfig {
                        admin: admin_id,
                        price_decimals: 6,
                        max_staleness_ms: 10 * 60 * 1_000,
                        max_confidence_bps: 500,
                        high_volatility_bps: 10_000,
                        divergence_warn_bps: 500,
                        divergence_halt_bps: 2_000,
                        source_priority: vec![source],
                        allow_negative: false,
                    },
                },
            )
            .into(),
        )
        .await;
        let set_updater = rpc_submit(
            &network,
            &rpc.url,
            OracleTransaction::sign(
                &admin,
                1,
                OracleOperation::SetUpdater {
                    market,
                    source,
                    updater: updater_id,
                    policy: UpdaterPolicy { enabled: true },
                },
            )
            .into(),
        )
        .await;

        wait_finalized(&network, &rpc.url, &configure).await;
        wait_finalized(&network, &rpc.url, &set_updater).await;

        let mut observations = vec![(first_observation, first_stream_wait_ms)];
        let mut latest_publish_time_ms = first_observation.publish_time_ms;
        let mut stats = Vec::with_capacity(SAMPLES);

        for sample in 0..SAMPLES {
            let (observation, stream_wait_ms) = if sample == 0 {
                observations.pop().expect("first observation")
            } else {
                let next = hermes.next_after(Some(latest_publish_time_ms));
                latest_publish_time_ms = next.0.publish_time_ms;
                next
            };
            let publish_age_ms = current_time_ms().saturating_sub(observation.publish_time_ms);
            let submit_sim_ms = network
                .context()
                .current()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let submit_wall = Instant::now();
            let update = rpc_submit(
                &network,
                &rpc.url,
                OracleTransaction::sign(
                    &updater,
                    sample as u64,
                    OracleOperation::SubmitFeedUpdate {
                        market,
                        source,
                        feed,
                        raw_value: observation.raw_value,
                        raw_decimals: observation.raw_decimals,
                        publish_time_ms: observation.publish_time_ms,
                        confidence: observation.confidence,
                    },
                )
                .into(),
            )
            .await;

            let finalized_height = wait_finalized(&network, &rpc.url, &update).await;
            wait_oracle_price(
                &network,
                market,
                price(observation.raw_value, observation.raw_decimals),
            )
            .await;
            let finalized_sim_ms = network
                .context()
                .current()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let submit_to_finalized_wall_ms = submit_wall.elapsed().as_millis();
            let submit_to_applied_sim_ms = finalized_sim_ms.saturating_sub(submit_sim_ms);
            stats.push(submit_to_finalized_wall_ms);
            println!(
                "sample={} hermes_wait_ms={} publish_age_ms={} finalized_height={} submit_to_finalized_wall_ms={} submit_to_applied_sim_ms={}",
                sample,
                stream_wait_ms,
                publish_age_ms,
                finalized_height,
                submit_to_finalized_wall_ms,
                submit_to_applied_sim_ms
            );
        }

        print_stats("submit_to_finalized_wall_ms", &stats);
        println!("total_wall_ms={}", wall_started.elapsed().as_millis());
    });
}

async fn rpc_submit(
    network: &common::network::TestNetwork<'_>,
    url: &str,
    transaction: Transaction,
) -> String {
    let accepted: rpc::SubmitTransactionResponse = rpc_call(
        network,
        url,
        "chain.submit_transaction",
        serde_json::json!({ "transaction": encode_hex(&transaction) }),
    )
    .await;
    accepted.hash
}

async fn wait_finalized(network: &common::network::TestNetwork<'_>, url: &str, hash: &str) -> u64 {
    loop {
        let status: rpc::TransactionStatusResponse = rpc_call(
            network,
            url,
            "chain.transaction_status",
            serde_json::json!({ "hash": hash }),
        )
        .await;
        match status.status.as_str() {
            "finalized" => return status.height.expect("finalized status includes height"),
            "dropped" => panic!("transaction dropped: {:?}", status.drop_reason),
            _ => network.context().sleep(Duration::from_millis(10)).await,
        }
    }
}

async fn rpc_call<T: serde::de::DeserializeOwned + Send + 'static>(
    network: &common::network::TestNetwork<'_>,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> T {
    let url = url.to_string();
    let method = method.to_string();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let response: serde_json::Value = reqwest::blocking::Client::new()
            .post(url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .expect("send JSON-RPC request")
            .error_for_status()
            .expect("JSON-RPC HTTP status")
            .json()
            .expect("decode JSON-RPC response");
        if let Some(error) = response.get("error") {
            panic!("JSON-RPC error: {error}");
        }
        let result = serde_json::from_value(
            response
                .get("result")
                .expect("JSON-RPC response missing result")
                .clone(),
        )
        .expect("decode JSON-RPC result");
        sender.send(result).expect("send JSON-RPC result");
    });
    loop {
        match receiver.try_recv() {
            Ok(result) => return result,
            Err(mpsc::TryRecvError::Empty) => {
                network.context().sleep(Duration::from_millis(1)).await;
            }
            Err(mpsc::TryRecvError::Disconnected) => panic!("JSON-RPC worker disconnected"),
        }
    }
}

fn print_stats(name: &str, samples: &[u128]) {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let sum: u128 = sorted.iter().sum();
    let avg = sum as f64 / sorted.len() as f64;
    let percentile = |numerator: usize, denominator: usize| -> u128 {
        let index = ((sorted.len() - 1) * numerator).div_ceil(denominator);
        sorted[index]
    };
    println!(
        "{name} count={} min={} avg={avg:.1} p50={} p95={} max={}",
        sorted.len(),
        sorted[0],
        percentile(50, 100),
        percentile(95, 100),
        sorted[sorted.len() - 1]
    );
}

async fn wait_oracle_price(
    network: &common::network::TestNetwork<'_>,
    market: MarketId,
    expected: Price,
) {
    loop {
        let ledgers = network.oracle_ledgers().await;
        if ledgers.len() == VALIDATORS as usize {
            let mut all_updated = true;
            for ledger in ledgers {
                let state = ledger.oracle(&market).await.expect("read oracle state");
                if !matches!(
                    state,
                    Some(state)
                        if state.status == OracleStatus::Fresh
                            && state.oracle_price == Some(expected)
                ) {
                    all_updated = false;
                    break;
                }
            }
            if all_updated {
                return;
            }
        }
        network.context().sleep(Duration::from_millis(10)).await;
    }
}
