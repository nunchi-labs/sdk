use crate::{generate_local, manifest_path, ChainCommand, Cli, Command};
use clap::Parser as _;
use nunchi_coins_chain::testnet::{LocalTestnetManifest, NodeConfig};
use std::fs;

fn chain_command(args: &[&str]) -> ChainCommand {
    match Cli::parse_from(args).command {
        Command::Generate { chain } | Command::Up { chain } => chain,
        Command::Run { .. } => panic!("expected a chain command"),
    }
}

#[test]
fn coins_chain_forwards_secondaries_and_indexer_url() {
    let generate = chain_command(&[
        "narae",
        "generate",
        "coins-chain",
        "--validators",
        "3",
        "--secondaries",
        "2",
        "--indexer-url",
        "https://indexer.example.com",
    ])
    .generate();

    assert_eq!(generate.validators, 3);
    assert_eq!(generate.secondaries, 2);
    assert_eq!(
        generate.indexer_url.as_deref(),
        Some("https://indexer.example.com")
    );
}

#[test]
fn coins_chain_defaults_leave_uploads_disabled() {
    let generate = chain_command(&["narae", "up", "coins-chain"]).generate();

    assert_eq!(generate.validators, 4);
    assert_eq!(generate.secondaries, 0);
    assert!(generate.indexer_url.is_none());
}

#[test]
fn generated_configs_carry_the_requested_indexer_url() {
    let out = std::env::temp_dir().join(format!("narae-generate-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out);

    let written = generate_local(chain_command(&[
        "narae",
        "generate",
        "coins-chain",
        "--validators",
        "2",
        "--secondaries",
        "1",
        "--out",
        out.to_str().unwrap(),
        "--indexer-url",
        "https://indexer.example.com",
    ]))
    .expect("generate testnet");

    assert_eq!(written, manifest_path(&out));
    let manifest = LocalTestnetManifest::read(&written).unwrap();
    assert_eq!(manifest.nodes.len(), 3);
    for node in &manifest.nodes {
        let config = NodeConfig::read(&node.config_path).unwrap();
        assert_eq!(
            config.indexer_url.as_deref(),
            Some("https://indexer.example.com")
        );
    }

    let _ = fs::remove_dir_all(&out);
}
