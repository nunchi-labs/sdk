use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "Workspace automation tasks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate deployment artifacts.
    Generate {
        #[command(subcommand)]
        chain: GenerateCommand,
    },
}

#[derive(Debug, Subcommand)]
enum GenerateCommand {
    /// Generate coins-chain validator configs and manifest.
    CoinsChain(nunchi_xtask::coins_chain::Generate),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate { chain } => match chain {
            GenerateCommand::CoinsChain(cmd) => {
                let manifest_path = cmd.run()?;
                println!("{}", manifest_path.display());
            }
        },
    }
    Ok(())
}
