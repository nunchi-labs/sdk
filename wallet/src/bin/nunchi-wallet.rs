use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use nunchi_wallet::{
    client::{parse_coin_id_hex, transaction_digest_hex, WalletRpcClient},
    keystore::WalletKeystore,
    record::{load_private_key, parse_address},
    CreateWalletOptions, ListWalletsOptions, WalletLookupOptions,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "nunchi-wallet", about = "Native Nunchi chain wallet")]
struct Cli {
    #[arg(long, default_value_os_t = WalletKeystore::default_root())]
    wallet_root: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Create {
        #[arg(short, long)]
        name: String,
        #[arg(long, default_value_t = 0)]
        chain_id: u64,
        #[arg(long)]
        insecure_store: bool,
    },
    List,
    Show {
        #[arg(short, long)]
        name: String,
    },
    Address {
        #[arg(short, long)]
        name: String,
    },
    SubmitTransfer {
        #[arg(short, long)]
        name: String,
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        chain_id: u64,
        #[arg(long)]
        coin: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
        #[arg(long, default_value_t = 0)]
        nonce: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Create {
            name,
            chain_id,
            insecure_store,
        } => {
            let created = nunchi_wallet::create_wallet(
                &CreateWalletOptions::new(cli.wallet_root, name, chain_id)
                    .insecure_store(insecure_store),
            )?;
            println!("{}", serde_json::to_string_pretty(&created.summary)?);
        }
        Command::List => {
            let wallets = nunchi_wallet::list_wallets(&ListWalletsOptions::new(cli.wallet_root))?;
            println!("{}", serde_json::to_string_pretty(&wallets)?);
        }
        Command::Show { name } => {
            let wallet =
                nunchi_wallet::show_wallet(&WalletLookupOptions::new(cli.wallet_root, name))?;
            println!("{}", serde_json::to_string_pretty(&wallet)?);
        }
        Command::Address { name } => {
            let wallet =
                nunchi_wallet::show_wallet(&WalletLookupOptions::new(cli.wallet_root, name))?;
            println!("{}", wallet.address);
        }
        Command::SubmitTransfer {
            name,
            rpc,
            chain_id,
            coin,
            from,
            to,
            amount,
            nonce,
        } => {
            let lookup = WalletLookupOptions::new(cli.wallet_root, name);
            let signer = load_private_key(&lookup).context("load wallet private key")?;
            let summary = nunchi_wallet::show_wallet(&lookup)?;
            if summary.chain_id != chain_id {
                bail!(
                    "wallet chain_id {} does not match --chain-id {}",
                    summary.chain_id,
                    chain_id
                );
            }
            let from = match from {
                Some(value) => parse_address(&value).map_err(|err| anyhow::anyhow!(err))?,
                None => parse_address(&summary.address).map_err(|err| anyhow::anyhow!(err))?,
            };
            let to = parse_address(&to).map_err(|err| anyhow::anyhow!(err))?;
            let to_address = to.to_string();
            let coin = parse_coin_id_hex(&coin).map_err(|err| anyhow::anyhow!(err))?;
            let amount = amount
                .parse::<u128>()
                .context("amount must be a valid u128")?;
            let tx =
                WalletRpcClient::build_transfer(&signer, chain_id, nonce, coin, from, to, amount);
            let client = WalletRpcClient::new(rpc)?;
            let response = client.submit_coins_transaction(&tx).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "submitted_hash": response.hash,
                    "local_digest": transaction_digest_hex(&tx),
                    "from": summary.address,
                    "to": to_address,
                    "chain_id": chain_id,
                    "nonce": nonce,
                }))?
            );
        }
    }
    Ok(())
}
