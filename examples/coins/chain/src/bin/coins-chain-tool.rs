use clap::{Parser, Subcommand};
use commonware_codec::DecodeExt;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519, Signer};
use commonware_formatting::from_hex;
use commonware_runtime::{tokio as cw_tokio, Runner as _, Supervisor as _};
use futures::{stream, StreamExt};
use nunchi_coins::{
    rpc::{NonceResponse, SubmitTransactionResponse, SubmitTransactionsResponse},
    Address, AllocationGenesis, CoinId, CoinOperation, CoinSpec, CoinsGenesis, PrivateKey,
    TokenFactory, TokenGenesis, TokenName, TokenSymbol, Transaction,
};
use nunchi_coins_chain::{
    genesis::ChainGenesis, testnet::NodeConfig, PublicKey, MAX_SUPPORTED_MODE, NAMESPACE,
};
use nunchi_dkg::{Storage, StorageKey, StorageProtector};
use nunchi_rpc::encode_hex;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    error::Error,
    num::NonZeroU32,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, time};

#[derive(Debug, Parser)]
#[command(about = "Operator tools for the coins-chain example")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write a deterministic demo genesis file with funded transfer accounts.
    Genesis(GenesisArgs),
    /// Submit signed transfer transactions to a validator RPC endpoint.
    Spam(SpamArgs),
    /// Submit signed transfer transactions with an async rate-controlled load generator.
    Load(LoadArgs),
    /// Print the current DKG epoch and output from validator storage.
    DkgOutput(DkgOutputArgs),
}

#[derive(Debug, Parser)]
struct GenesisArgs {
    #[arg(long, default_value = "genesis.json")]
    out: PathBuf,
    #[arg(long, default_value_t = 8)]
    accounts: usize,
    #[arg(long, default_value_t = 10_000)]
    seed: u64,
    #[arg(long, default_value = "NCH")]
    symbol: String,
    #[arg(long, default_value = "Nunchi")]
    name: String,
    #[arg(long, default_value_t = 6)]
    decimals: u8,
    #[arg(long, default_value_t = 1_000_000_000u128)]
    initial_balance: u128,
    #[arg(long)]
    max_supply: Option<u128>,
}

#[derive(Debug, Parser)]
struct SpamArgs {
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    #[arg(long, default_value_t = 8)]
    accounts: usize,
    #[arg(long, default_value_t = 10_000)]
    seed: u64,
    #[arg(long)]
    coin: Option<String>,
    /// Create a zero-supply token and mint each spam account's starting balance before transfers.
    #[arg(long)]
    bootstrap: bool,
    #[arg(long, default_value = "NCH")]
    symbol: String,
    #[arg(long, default_value = "Nunchi")]
    name: String,
    #[arg(long, default_value_t = 6)]
    decimals: u8,
    #[arg(long, default_value_t = 1_000_000_000u128)]
    initial_balance: u128,
    #[arg(long)]
    max_supply: Option<u128>,
    #[arg(long, default_value_t = 1)]
    amount: u128,
    #[arg(long)]
    limit: Option<u64>,
    #[arg(long, default_value_t = 25)]
    interval_ms: u64,
}

#[derive(Debug, Parser)]
struct LoadArgs {
    /// Comma-separated validator RPC endpoints.
    #[arg(long, value_delimiter = ',', default_value = "http://127.0.0.1:8545")]
    rpcs: Vec<String>,
    #[arg(long, default_value_t = 1_024)]
    accounts: usize,
    #[arg(long, default_value_t = 10_000)]
    seed: u64,
    #[arg(long)]
    coin: Option<String>,
    /// Create a zero-supply token and mint each load account before transfers.
    #[arg(long)]
    bootstrap: bool,
    /// Number of issuer transactions to admit before waiting for finalization during bootstrap.
    #[arg(long, default_value_t = 32)]
    bootstrap_window: usize,
    #[arg(long, default_value = "NCH")]
    symbol: String,
    #[arg(long, default_value = "Nunchi")]
    name: String,
    #[arg(long, default_value_t = 6)]
    decimals: u8,
    #[arg(long, default_value_t = 1_000_000_000u128)]
    initial_balance: u128,
    #[arg(long)]
    max_supply: Option<u128>,
    #[arg(long, default_value_t = 1)]
    amount: u128,
    #[arg(long, default_value_t = 1_000)]
    target_tps: u64,
    #[arg(long)]
    limit: Option<u64>,
    #[arg(long, default_value_t = 60)]
    duration_secs: u64,
    #[arg(long, default_value_t = 2_000)]
    in_flight: usize,
    /// Number of transactions packed into each submit_transactions request.
    #[arg(long, default_value_t = 1)]
    batch_size: usize,
    #[arg(long, default_value_t = 64)]
    nonce_query_concurrency: usize,
}

#[derive(Debug, Parser)]
struct DkgOutputArgs {
    #[arg(long)]
    config: PathBuf,
}

#[derive(Debug, Serialize)]
struct RpcRequest<P> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: P,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
struct NonceParams {
    account: String,
}

#[derive(Clone, Debug, Serialize)]
struct SubmitParams {
    transaction: String,
}

#[derive(Clone, Debug, Serialize)]
struct SubmitManyParams {
    transactions: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct EmptyParams {}

#[derive(Debug, Deserialize)]
struct FactoryNonceResponse {
    nonce: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Genesis(args) => write_genesis(args),
        Command::Spam(args) => spam(args),
        Command::Load(args) => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(load(args))
        }
        Command::DkgOutput(args) => print_dkg_output(args),
    }
}

fn print_dkg_output(args: DkgOutputArgs) -> Result<(), Box<dyn Error>> {
    let config = NodeConfig::read(&args.config)?;
    let private_key = decode_config_value::<ed25519::PrivateKey>(&config.private_key)?;
    let public_key = private_key.public_key();
    let dkg_storage_key = decode_storage_key(&config.dkg_storage_key)?;
    let max_participants = NonZeroU32::new(config.peer_config.max_participants_per_round())
        .ok_or("empty validator set")?;
    let runtime = cw_tokio::Runner::new(
        cw_tokio::Config::new().with_storage_directory(config.storage_dir.clone()),
    );
    runtime.start(|context| async move {
        let storage = Storage::<_, MinSig, PublicKey>::init(
            context.child("dkg_storage"),
            &config.name,
            StorageProtector::new(dkg_storage_key),
            NAMESPACE.to_vec(),
            public_key,
            max_participants,
            MAX_SUPPORTED_MODE,
        )
        .await?;
        let (epoch, state) = storage.epoch().ok_or("missing dkg epoch")?;
        let output = state.output.ok_or("current dkg epoch has no output")?;
        println!("epoch {}", epoch.get());
        println!("output {}", encode_hex(&output));
        Ok(())
    })
}

fn write_genesis(args: GenesisArgs) -> Result<(), Box<dyn Error>> {
    let keys = account_keys(args.accounts, args.seed)?;
    let spec = genesis_token_spec(
        &args.symbol,
        &args.name,
        args.decimals,
        args.accounts,
        args.initial_balance,
        args.max_supply,
    )?;
    let issuer = account(&keys[0]);
    let coin = TokenFactory::derive_coin_id(&issuer, 0, &spec);
    let allocations = keys
        .iter()
        .map(|key| AllocationGenesis {
            account: account(key),
            amount: args.initial_balance,
        })
        .collect();
    let genesis = ChainGenesis {
        authority: None,
        coins: Some(CoinsGenesis {
            account_policies: Vec::new(),
            tokens: vec![TokenGenesis {
                issuer: issuer.clone(),
                spec,
                allocations,
            }],
            fees: None,
        }),
        oracle: None,
    };

    if let Some(parent) = args
        .out
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.out, serde_json::to_vec_pretty(&genesis)?)?;

    println!("wrote {}", args.out.display());
    println!("issuer {issuer}");
    println!("coin {}", encode_hex(&coin));
    println!(
        "accounts {}..{}",
        args.seed,
        args.seed + u64::try_from(args.accounts.saturating_sub(1))?
    );
    Ok(())
}

fn spam(args: SpamArgs) -> Result<(), Box<dyn Error>> {
    let keys = account_keys(args.accounts, args.seed)?;
    let accounts = keys.iter().map(account).collect::<Vec<_>>();
    let spec = spam_token_spec(&args)?;
    let client = reqwest::blocking::Client::new();
    let mut rpc_id = 0u64;
    let coin = match args.coin {
        Some(ref coin) => parse_coin(coin)?,
        None if args.bootstrap => {
            let response: FactoryNonceResponse = rpc(
                &client,
                &args.rpc,
                next_rpc_id(&mut rpc_id),
                "coins.factory_nonce",
                EmptyParams {},
            )?;
            let coin = TokenFactory::derive_coin_id(&accounts[0], response.nonce, &spec);
            println!("factory nonce {}", response.nonce);
            coin
        }
        None => TokenFactory::derive_coin_id(&accounts[0], 0, &spec),
    };
    let mut next_nonces = accounts
        .iter()
        .map(|account| {
            rpc_id += 1;
            let response: NonceResponse = rpc(
                &client,
                &args.rpc,
                rpc_id,
                "coins.nonce",
                NonceParams {
                    account: account.to_string(),
                },
            )?;
            Ok(response.nonce)
        })
        .collect::<Result<Vec<u64>, Box<dyn Error>>>()?;

    if args.bootstrap {
        bootstrap_accounts(
            &client,
            &args.rpc,
            &mut rpc_id,
            &mut next_nonces,
            &keys[0],
            &accounts,
            coin,
            spec,
            args.coin.is_none(),
            args.initial_balance,
        )?;
    }

    let interval = Duration::from_millis(args.interval_ms);
    let mut submitted = 0u64;
    loop {
        if let Some(limit) = args.limit {
            if submitted >= limit {
                break;
            }
        }

        let index = usize::try_from(submitted % u64::try_from(keys.len())?)?;
        let to_index = (index + 1) % keys.len();
        let transaction = Transaction::sign(
            &keys[index],
            next_nonces[index],
            CoinOperation::Transfer {
                coin,
                from: accounts[index].clone(),
                to: accounts[to_index].clone(),
                amount: args.amount,
            },
        );
        let response: SubmitTransactionResponse = rpc(
            &client,
            &args.rpc,
            next_rpc_id(&mut rpc_id),
            "coins.submit_transaction",
            SubmitParams {
                transaction: encode_hex(&transaction),
            },
        )?;

        next_nonces[index] += 1;
        submitted += 1;
        if submitted == 1 || submitted.is_multiple_of(100) {
            println!("submitted {submitted} latest={}", response.hash);
        }
        if !interval.is_zero() {
            thread::sleep(interval);
        }
    }

    println!("submitted {submitted}");
    Ok(())
}

async fn load(args: LoadArgs) -> Result<(), Box<dyn Error>> {
    if args.rpcs.is_empty() || args.rpcs.iter().any(|rpc| rpc.trim().is_empty()) {
        return Err("at least one RPC endpoint is required".into());
    }
    if args.target_tps == 0 {
        return Err("target-tps must be greater than zero".into());
    }
    if args.in_flight == 0 {
        return Err("in-flight must be greater than zero".into());
    }
    if args.batch_size == 0 {
        return Err("batch-size must be greater than zero".into());
    }

    let keys = account_keys(args.accounts, args.seed)?;
    let accounts = keys.iter().map(account).collect::<Vec<_>>();
    let spec = load_token_spec(&args)?;
    let client = reqwest::Client::new();
    let rpc_id = Arc::new(AtomicU64::new(0));
    let primary_rpc = args.rpcs[0].clone();
    let coin = match args.coin {
        Some(ref coin) => parse_coin(coin)?,
        None if args.bootstrap => {
            let response: FactoryNonceResponse = rpc_async_retry(
                &client,
                &primary_rpc,
                &rpc_id,
                "coins.factory_nonce",
                EmptyParams {},
            )
            .await
            .map_err(boxed_error)?;
            let coin = TokenFactory::derive_coin_id(&accounts[0], response.nonce, &spec);
            println!("factory nonce {}", response.nonce);
            coin
        }
        None => TokenFactory::derive_coin_id(&accounts[0], 0, &spec),
    };

    println!(
        "querying nonces for {} accounts with concurrency {}",
        accounts.len(),
        args.nonce_query_concurrency
    );
    let mut next_nonces = query_nonces(
        &client,
        &primary_rpc,
        &rpc_id,
        &accounts,
        args.nonce_query_concurrency,
    )
    .await?;

    if args.bootstrap {
        bootstrap_accounts_async(
            &client,
            &primary_rpc,
            &rpc_id,
            &mut next_nonces,
            &keys[0],
            &accounts,
            coin,
            spec,
            args.coin.is_none(),
            args.initial_balance,
            args.bootstrap_window,
        )
        .await?;
    }

    run_load(args, client, rpc_id, keys, accounts, next_nonces, coin).await
}

#[allow(clippy::too_many_arguments)]
async fn bootstrap_accounts_async(
    client: &reqwest::Client,
    rpc_url: &str,
    rpc_id: &Arc<AtomicU64>,
    next_nonces: &mut [u64],
    issuer_key: &PrivateKey,
    accounts: &[Address],
    coin: CoinId,
    spec: CoinSpec,
    create_token: bool,
    initial_balance: u128,
    bootstrap_window: usize,
) -> Result<(), Box<dyn Error>> {
    let window = bootstrap_window.max(1);
    let issuer = account(issuer_key);
    let mut pending = 0usize;
    let mut submitted = 0usize;

    if create_token {
        let transaction = Transaction::sign(
            issuer_key,
            next_nonces[0],
            CoinOperation::CreateToken { spec },
        );
        submit_transaction_async_retry(client, rpc_url, rpc_id, &transaction)
            .await
            .map_err(boxed_error)?;
        next_nonces[0] += 1;
        pending += 1;
        submitted += 1;
        println!("created token {}", encode_hex(&coin));
    }

    for account in accounts {
        let transaction = Transaction::sign(
            issuer_key,
            next_nonces[0],
            CoinOperation::Mint {
                coin,
                to: account.clone(),
                amount: initial_balance,
            },
        );
        submit_transaction_async_retry(client, rpc_url, rpc_id, &transaction)
            .await
            .map_err(boxed_error)?;
        next_nonces[0] += 1;
        pending += 1;
        submitted += 1;

        if pending >= window {
            wait_for_nonce(client, rpc_url, rpc_id, &issuer, next_nonces[0]).await?;
            pending = 0;
            println!("bootstrap finalized {submitted} issuer txs");
        }
    }

    if pending > 0 {
        wait_for_nonce(client, rpc_url, rpc_id, &issuer, next_nonces[0]).await?;
    }

    println!("bootstrap finalized {submitted} issuer txs");
    Ok(())
}

async fn run_load(
    args: LoadArgs,
    client: reqwest::Client,
    rpc_id: Arc<AtomicU64>,
    keys: Vec<PrivateKey>,
    accounts: Vec<Address>,
    next_nonces: Vec<u64>,
    coin: CoinId,
) -> Result<(), Box<dyn Error>> {
    let submitted = Arc::new(AtomicU64::new(0));
    let accepted = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let retried = Arc::new(AtomicU64::new(0));
    let sample_error = Arc::new(Mutex::new(None::<String>));
    let semaphore = Arc::new(Semaphore::new(args.in_flight));
    let started = Instant::now();
    let deadline = started + Duration::from_secs(args.duration_secs);
    // Batches keep retrying past the submission deadline: a dropped batch
    // leaves permanent nonce holes that wedge every lane it touches.
    let retry_deadline = deadline + Duration::from_secs(60);
    // Sticky account -> RPC buckets: all of an account's transactions go to
    // one validator, so a failure on another endpoint can never fragment its
    // nonce sequence across pools.
    let mut buckets: Vec<Vec<String>> = vec![Vec::new(); args.rpcs.len()];
    let tick = Duration::from_millis(10);
    let mut ticker = time::interval(tick);
    let mut carry = 0u64;
    let per_second = 1_000u64;
    let per_tick_denominator = per_second / 10;

    println!(
        "load start accounts={} rpcs={} target_tps={} in_flight={} batch_size={} duration={}s coin={}",
        keys.len(),
        args.rpcs.len(),
        args.target_tps,
        args.in_flight,
        args.batch_size,
        args.duration_secs,
        encode_hex(&coin)
    );

    let progress = tokio::spawn(progress_reporter(
        submitted.clone(),
        accepted.clone(),
        failed.clone(),
        retried.clone(),
        sample_error.clone(),
        started,
    ));

    loop {
        ticker.tick().await;
        if Instant::now() >= deadline {
            break;
        }
        if let Some(limit) = args.limit {
            if submitted.load(Ordering::Relaxed) >= limit {
                break;
            }
        }

        carry = carry.saturating_add(args.target_tps);
        let mut permits = carry / per_tick_denominator;
        carry %= per_tick_denominator;
        if permits == 0 {
            continue;
        }

        while permits > 0 {
            if let Some(limit) = args.limit {
                if submitted.load(Ordering::Relaxed) >= limit {
                    break;
                }
            }

            let sequence = submitted.fetch_add(1, Ordering::Relaxed);
            let account_index = usize::try_from(sequence % u64::try_from(keys.len())?)?;
            let account_round = sequence / u64::try_from(keys.len())?;
            let to_index = (account_index + 1) % keys.len();
            let transaction = Transaction::sign(
                &keys[account_index],
                next_nonces[account_index] + account_round,
                CoinOperation::Transfer {
                    coin,
                    from: accounts[account_index].clone(),
                    to: accounts[to_index].clone(),
                    amount: args.amount,
                },
            );
            let rpc_index = account_index % args.rpcs.len();
            buckets[rpc_index].push(encode_hex(&transaction));
            permits -= 1;

            if buckets[rpc_index].len() >= args.batch_size {
                let transactions = std::mem::take(&mut buckets[rpc_index]);
                let permit = semaphore.clone().acquire_owned().await?;
                tokio::spawn(submit_batch_until(
                    permit,
                    client.clone(),
                    args.rpcs[rpc_index].clone(),
                    rpc_id.clone(),
                    transactions,
                    accepted.clone(),
                    failed.clone(),
                    retried.clone(),
                    sample_error.clone(),
                    retry_deadline,
                ));
            }
        }
    }

    // Flush partial buckets so the tail of every nonce sequence lands.
    for (rpc_index, bucket) in buckets.iter_mut().enumerate() {
        if bucket.is_empty() {
            continue;
        }
        let transactions = std::mem::take(bucket);
        let permit = semaphore.clone().acquire_owned().await?;
        tokio::spawn(submit_batch_until(
            permit,
            client.clone(),
            args.rpcs[rpc_index].clone(),
            rpc_id.clone(),
            transactions,
            accepted.clone(),
            failed.clone(),
            retried.clone(),
            sample_error.clone(),
            retry_deadline,
        ));
    }

    let permits = semaphore
        .acquire_many(u32::try_from(args.in_flight)?)
        .await?;
    drop(permits);
    progress.abort();
    println!(
        "load done submitted={} accepted={} failed={} elapsed={:.2}s",
        submitted.load(Ordering::Relaxed),
        accepted.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
        started.elapsed().as_secs_f64(),
    );
    if let Ok(sample) = sample_error.lock() {
        if let Some(error) = sample.as_ref() {
            println!("sample error: {error}");
        }
    }
    Ok(())
}

async fn progress_reporter(
    submitted: Arc<AtomicU64>,
    accepted: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
    retried: Arc<AtomicU64>,
    sample_error: Arc<Mutex<Option<String>>>,
    started: Instant,
) {
    let mut ticker = time::interval(Duration::from_secs(1));
    let mut last_submitted = 0u64;
    let mut last_accepted = 0u64;
    loop {
        ticker.tick().await;
        let total_submitted = submitted.load(Ordering::Relaxed);
        let total_accepted = accepted.load(Ordering::Relaxed);
        let submitted_rate = total_submitted.saturating_sub(last_submitted);
        let accepted_rate = total_accepted.saturating_sub(last_accepted);
        last_submitted = total_submitted;
        last_accepted = total_accepted;
        let sample = sample_error
            .lock()
            .ok()
            .and_then(|sample| sample.as_ref().cloned())
            .unwrap_or_default();
        println!(
            "elapsed={:.0}s submitted={} accepted={} failed={} retried={} submit/s={} accept/s={} {}",
            started.elapsed().as_secs_f64(),
            total_submitted,
            total_accepted,
            failed.load(Ordering::Relaxed),
            retried.load(Ordering::Relaxed),
            submitted_rate,
            accepted_rate,
            sample
        );
    }
}

fn record_sample_error(sample_error: &Arc<Mutex<Option<String>>>, error: String) {
    if let Ok(mut sample) = sample_error.lock() {
        if sample.is_none() {
            *sample = Some(error);
        }
    }
}

async fn query_nonces(
    client: &reqwest::Client,
    rpc_url: &str,
    rpc_id: &Arc<AtomicU64>,
    accounts: &[Address],
    concurrency: usize,
) -> Result<Vec<u64>, Box<dyn Error>> {
    let concurrency = concurrency.max(1);
    let mut next_nonces = vec![0; accounts.len()];
    let stream = stream::iter(
        accounts
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, account)| {
                let client = client.clone();
                let rpc_url = rpc_url.to_string();
                let rpc_id = rpc_id.clone();
                async move {
                    let response: NonceResponse = rpc_async_retry(
                        &client,
                        &rpc_url,
                        &rpc_id,
                        "coins.nonce",
                        NonceParams {
                            account: account.to_string(),
                        },
                    )
                    .await?;
                    Ok::<_, String>((index, response.nonce))
                }
            }),
    )
    .buffer_unordered(concurrency);
    tokio::pin!(stream);

    while let Some(result) = stream.next().await {
        let (index, nonce) = result.map_err(boxed_error)?;
        next_nonces[index] = nonce;
    }
    Ok(next_nonces)
}

async fn wait_for_nonce(
    client: &reqwest::Client,
    rpc_url: &str,
    rpc_id: &Arc<AtomicU64>,
    account: &Address,
    target: u64,
) -> Result<(), Box<dyn Error>> {
    loop {
        let response: NonceResponse = rpc_async_retry(
            client,
            rpc_url,
            rpc_id,
            "coins.nonce",
            NonceParams {
                account: account.to_string(),
            },
        )
        .await
        .map_err(boxed_error)?;
        if response.nonce >= target {
            return Ok(());
        }
        time::sleep(Duration::from_millis(250)).await;
    }
}

/// Submit one batch, retrying transport failures until `retry_deadline`.
/// Batches are never abandoned early: each one carries consecutive nonces
/// for its accounts, and a dropped batch would leave permanent nonce holes
/// that wedge every lane behind it.
#[allow(clippy::too_many_arguments)]
async fn submit_batch_until(
    permit: tokio::sync::OwnedSemaphorePermit,
    client: reqwest::Client,
    rpc_url: String,
    rpc_id: Arc<AtomicU64>,
    transactions: Vec<String>,
    accepted: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
    retried: Arc<AtomicU64>,
    sample_error: Arc<Mutex<Option<String>>>,
    retry_deadline: Instant,
) {
    let mut pending = transactions;
    let mut delay = Duration::from_millis(100);
    loop {
        match rpc_async::<SubmitTransactionsResponse, _>(
            &client,
            &rpc_url,
            next_async_rpc_id(&rpc_id),
            "coins.submit_transactions",
            SubmitManyParams {
                transactions: pending.clone(),
            },
        )
        .await
        {
            Ok(response) => {
                let mut ok = 0u64;
                let mut err = 0u64;
                let mut first_error = None;
                let mut requeue = Vec::new();
                for (result, transaction) in response.results.into_iter().zip(&pending) {
                    if result.hash.is_some() && result.error.is_none() {
                        ok += 1;
                        continue;
                    }
                    let error = result
                        .error
                        .unwrap_or_else(|| "submit result had no hash".to_string());
                    // An earlier attempt already pooled the transaction.
                    if error.contains("already pending") {
                        ok += 1;
                        continue;
                    }
                    // Pool capacity rejections are backpressure, not
                    // failures: dropping the transaction would leave a
                    // permanent nonce hole in its lane.
                    if error.contains("queue is full") || error.contains("pool is full") {
                        requeue.push(transaction.clone());
                        continue;
                    }
                    err += 1;
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                accepted.fetch_add(ok, Ordering::Relaxed);
                if err > 0 {
                    failed.fetch_add(err, Ordering::Relaxed);
                    if let Some(err) = first_error {
                        record_sample_error(&sample_error, err);
                    }
                }
                if requeue.is_empty() {
                    break;
                }
                if Instant::now() >= retry_deadline {
                    failed.fetch_add(
                        u64::try_from(requeue.len()).unwrap_or(u64::MAX),
                        Ordering::Relaxed,
                    );
                    record_sample_error(&sample_error, "gave up on backpressured batch".into());
                    break;
                }
                pending = requeue;
                retried.fetch_add(1, Ordering::Relaxed);
                time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(2));
            }
            Err(error) if Instant::now() < retry_deadline => {
                retried.fetch_add(1, Ordering::Relaxed);
                record_sample_error(&sample_error, error);
                time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(2));
            }
            Err(error) => {
                failed.fetch_add(
                    u64::try_from(pending.len()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                record_sample_error(&sample_error, error);
                break;
            }
        }
    }
    drop(permit);
}

async fn submit_transaction_async_retry(
    client: &reqwest::Client,
    rpc_url: &str,
    rpc_id: &Arc<AtomicU64>,
    transaction: &Transaction,
) -> Result<SubmitTransactionResponse, String> {
    rpc_async_retry(
        client,
        rpc_url,
        rpc_id,
        "coins.submit_transaction",
        SubmitParams {
            transaction: encode_hex(transaction),
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn bootstrap_accounts(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    rpc_id: &mut u64,
    next_nonces: &mut [u64],
    issuer_key: &PrivateKey,
    accounts: &[Address],
    coin: CoinId,
    spec: CoinSpec,
    create_token: bool,
    initial_balance: u128,
) -> Result<(), Box<dyn Error>> {
    if create_token {
        let transaction = Transaction::sign(
            issuer_key,
            next_nonces[0],
            CoinOperation::CreateToken { spec },
        );
        let response = submit_transaction(client, rpc_url, rpc_id, &transaction)?;
        next_nonces[0] += 1;
        println!("created token {} tx={}", encode_hex(&coin), response.hash);
    }

    for account in accounts {
        let transaction = Transaction::sign(
            issuer_key,
            next_nonces[0],
            CoinOperation::Mint {
                coin,
                to: account.clone(),
                amount: initial_balance,
            },
        );
        let response = submit_transaction(client, rpc_url, rpc_id, &transaction)?;
        next_nonces[0] += 1;
        println!("minted {initial_balance} to {account} tx={}", response.hash);
    }

    Ok(())
}

fn submit_transaction(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    rpc_id: &mut u64,
    transaction: &Transaction,
) -> Result<SubmitTransactionResponse, Box<dyn Error>> {
    rpc(
        client,
        rpc_url,
        next_rpc_id(rpc_id),
        "coins.submit_transaction",
        SubmitParams {
            transaction: encode_hex(transaction),
        },
    )
}

fn account_keys(count: usize, seed: u64) -> Result<Vec<PrivateKey>, Box<dyn Error>> {
    if count < 2 {
        return Err("at least two accounts are required".into());
    }
    (0..count)
        .map(|offset| Ok(PrivateKey::from_seed(seed + u64::try_from(offset)?)))
        .collect()
}

fn account(key: &PrivateKey) -> Address {
    Address::from(key.public_key())
}

fn spam_token_spec(args: &SpamArgs) -> Result<CoinSpec, Box<dyn Error>> {
    let initial_supply = if args.bootstrap {
        0
    } else {
        initial_supply(args.accounts, args.initial_balance)?
    };
    token_spec(
        &args.symbol,
        &args.name,
        args.decimals,
        initial_supply,
        args.max_supply,
    )
}

fn load_token_spec(args: &LoadArgs) -> Result<CoinSpec, Box<dyn Error>> {
    let initial_supply = if args.bootstrap {
        0
    } else {
        initial_supply(args.accounts, args.initial_balance)?
    };
    token_spec(
        &args.symbol,
        &args.name,
        args.decimals,
        initial_supply,
        args.max_supply,
    )
}

fn genesis_token_spec(
    symbol: &str,
    name: &str,
    decimals: u8,
    accounts: usize,
    initial_balance: u128,
    max_supply: Option<u128>,
) -> Result<CoinSpec, Box<dyn Error>> {
    token_spec(
        symbol,
        name,
        decimals,
        initial_supply(accounts, initial_balance)?,
        max_supply,
    )
}

fn initial_supply(accounts: usize, initial_balance: u128) -> Result<u128, Box<dyn Error>> {
    initial_balance
        .checked_mul(u128::try_from(accounts)?)
        .ok_or_else(|| "initial supply overflow".into())
}

fn token_spec(
    symbol: &str,
    name: &str,
    decimals: u8,
    initial_supply: u128,
    max_supply: Option<u128>,
) -> Result<CoinSpec, Box<dyn Error>> {
    Ok(CoinSpec::new(
        TokenSymbol::new(symbol)?,
        TokenName::new(name)?,
        decimals,
        initial_supply,
        max_supply,
    ))
}

fn parse_coin(value: &str) -> Result<CoinId, Box<dyn Error>> {
    let bytes = from_hex(value).ok_or("coin id must be hex")?;
    Ok(CoinId::decode(bytes.as_ref())?)
}

fn decode_config_value<T>(value: &str) -> Result<T, Box<dyn Error>>
where
    T: DecodeExt<()>,
{
    let bytes = from_hex(value).ok_or("config value must be hex")?;
    Ok(T::decode(bytes.as_ref())?)
}

fn decode_storage_key(value: &str) -> Result<StorageKey, Box<dyn Error>> {
    let bytes = from_hex(value).ok_or("dkg storage key must be hex")?;
    bytes
        .try_into()
        .map_err(|_| "dkg storage key must be 32 bytes".into())
}

fn next_rpc_id(id: &mut u64) -> u64 {
    *id += 1;
    *id
}

fn next_async_rpc_id(id: &AtomicU64) -> u64 {
    id.fetch_add(1, Ordering::Relaxed) + 1
}

fn boxed_error(error: String) -> Box<dyn Error> {
    std::io::Error::other(error).into()
}

fn rpc<T, P>(
    client: &reqwest::blocking::Client,
    url: &str,
    id: u64,
    method: &'static str,
    params: P,
) -> Result<T, Box<dyn Error>>
where
    T: DeserializeOwned,
    P: Serialize,
{
    let response = client
        .post(url)
        .json(&RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        })
        .send()?
        .error_for_status()?
        .json::<RpcResponse<T>>()?;
    match (response.result, response.error) {
        (Some(result), None) => Ok(result),
        (_, Some(error)) => {
            let data = error
                .data
                .map(|data| format!(": {data}"))
                .unwrap_or_default();
            Err(format!("rpc error {} {}{}", error.code, error.message, data).into())
        }
        (None, None) => Err("rpc response had no result".into()),
    }
}

async fn rpc_async_retry<T, P>(
    client: &reqwest::Client,
    url: &str,
    rpc_id: &Arc<AtomicU64>,
    method: &'static str,
    params: P,
) -> Result<T, String>
where
    T: DeserializeOwned,
    P: Clone + Serialize,
{
    let mut delay = Duration::from_millis(100);
    let mut last_error = None;
    for attempt in 1..=8 {
        match rpc_async(
            client,
            url,
            next_async_rpc_id(rpc_id),
            method,
            params.clone(),
        )
        .await
        {
            Ok(response) => return Ok(response),
            Err(error) if is_retryable_rpc_error(&error) && attempt < 8 => {
                last_error = Some(error);
                time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(2));
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| format!("{method} failed after retries")))
}

async fn rpc_async<T, P>(
    client: &reqwest::Client,
    url: &str,
    id: u64,
    method: &'static str,
    params: P,
) -> Result<T, String>
where
    T: DeserializeOwned,
    P: Serialize,
{
    let response = client
        .post(url)
        .json(&RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        })
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("http status {status}: {body}"));
    }
    let response = response
        .json::<RpcResponse<T>>()
        .await
        .map_err(|error| error.to_string())?;
    match (response.result, response.error) {
        (Some(result), None) => Ok(result),
        (_, Some(error)) => {
            let data = error
                .data
                .map(|data| format!(": {data}"))
                .unwrap_or_default();
            Err(format!(
                "rpc error {} {}{}",
                error.code, error.message, data
            ))
        }
        (None, None) => Err("rpc response had no result".to_string()),
    }
}

fn is_retryable_rpc_error(error: &str) -> bool {
    error.contains("429")
        || error.contains("Too Many Requests")
        || error.contains("connection")
        || error.contains("timed out")
        // reqwest transport failures (dropped tunnels, refused sockets)
        || error.contains("error sending request")
}
