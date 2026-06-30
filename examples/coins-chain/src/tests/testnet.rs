//! Standalone local-testnet support: config generation and a real-network node runner.
//!
//! [`generate_local_testnet`] performs a trusted setup (key generation plus an initial threshold
//! deal) and writes one TOML config per validator alongside a manifest that process runners such
//! as `narae` consume. [`run_node`] boots a single validator from one of those configs on the
//! tokio runtime with authenticated peer discovery, and serves the aggregated JSON-RPC module.

use commonware_cryptography::{bls12381::primitives::group, ed25519};
use std::collections::HashSet;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU32,
    path::PathBuf,
};

use crate::testnet::*;

#[test]
fn generated_testnet_has_unique_ports_dirs_and_complete_peer_sets() {
    let dir = std::env::temp_dir().join(format!("coins-chain-testnet-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);

    let manifest = generate_local_testnet(LocalTestnetConfig {
        validators: 4,
        base_port: 40_000,
        base_rpc_port: 41_000,
        base_metrics_port: 42_000,
        base_data_dir: dir.clone(),
        bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        public_ips: None,
        storage_dir: None,
        indexer_url: None,
        seed: 7,
    })
    .expect("generate testnet");

    assert_eq!(manifest.nodes.len(), 4);
    let ports = manifest
        .nodes
        .iter()
        .map(|node| node.port)
        .collect::<HashSet<_>>();
    assert_eq!(ports.len(), 4);
    let rpc_ports = manifest
        .nodes
        .iter()
        .map(|node| node.rpc_port)
        .collect::<HashSet<_>>();
    assert_eq!(rpc_ports.len(), 4);
    let metrics_ports = manifest
        .nodes
        .iter()
        .map(|node| node.metrics_port)
        .collect::<HashSet<_>>();
    assert_eq!(metrics_ports.len(), 4);
    let dirs = manifest
        .nodes
        .iter()
        .map(|node| node.data_dir.clone())
        .collect::<HashSet<_>>();
    assert_eq!(dirs.len(), 4);

    for node in &manifest.nodes {
        let config = NodeConfig::read(&node.config_path).expect("read node config");
        assert_eq!(config.peer_config.participants.len(), 4);
        assert_eq!(config.bootstrappers.len(), 3);
        assert!(!config
            .bootstrappers
            .iter()
            .any(|bootstrapper| bootstrapper.address.port() == node.port));
        assert_eq!(config.rpc_address.port(), node.rpc_port);
        assert_eq!(config.metrics_address.port(), node.metrics_port);

        // The threshold material must round-trip from the written config.
        let max_participants =
            NonZeroU32::new(config.peer_config.max_participants_per_round()).unwrap();
        decode_output(&config.output, max_participants).expect("decode output");
        decode_unit::<group::Share>(&config.share, "share").expect("decode share");
        decode_unit::<ed25519::PrivateKey>(&config.private_key, "private_key")
            .expect("decode private key");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn generated_testnet_can_advertise_remote_hosts() {
    let dir =
        std::env::temp_dir().join(format!("coins-chain-remote-testnet-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);

    let public_ips = vec![
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
    ];
    let storage_dir = PathBuf::from("/var/lib/nunchi/coins-chain");
    let manifest = generate_local_testnet(LocalTestnetConfig {
        validators: 2,
        base_port: 30_000,
        base_rpc_port: 8_545,
        base_metrics_port: 9_090,
        base_data_dir: dir.clone(),
        bind_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        public_ips: Some(public_ips.clone()),
        storage_dir: Some(storage_dir.clone()),
        indexer_url: Some("https://indexer.example.com/coins-chain".to_string()),
        seed: 8,
    })
    .expect("generate remote testnet");

    let first = NodeConfig::read(&manifest.nodes[0].config_path).expect("read first config");
    let second = NodeConfig::read(&manifest.nodes[1].config_path).expect("read second config");

    assert_eq!(first.listen_address.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(first.dialable_address.ip(), public_ips[0]);
    assert_eq!(first.bootstrappers[0].address.ip(), public_ips[1]);
    assert_eq!(first.storage_dir, storage_dir);
    assert_eq!(
        first.indexer_url.as_deref(),
        Some("https://indexer.example.com/coins-chain")
    );
    assert_eq!(second.dialable_address.ip(), public_ips[1]);
    assert_eq!(second.bootstrappers[0].address.ip(), public_ips[0]);
    assert_eq!(
        second.indexer_url.as_deref(),
        Some("https://indexer.example.com/coins-chain")
    );

    let _ = fs::remove_dir_all(dir);
}
