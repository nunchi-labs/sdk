//! Standalone local-testnet support: config generation and a real-network node runner.
//!
//! [`generate_local_testnet`] performs a trusted setup (key generation plus an initial threshold
//! deal) and writes one TOML config per validator alongside a manifest that process runners such
//! as `narae` consume. [`run_node`] boots a single validator from one of those configs on the
//! tokio runtime with authenticated peer discovery, and serves the aggregated JSON-RPC module.

use commonware_cryptography::{bls12381::primitives::group, ed25519};
use std::collections::HashSet;
use std::{fs, num::NonZeroU32};

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
    let mut dkg_storage_keys = HashSet::new();

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
        let dkg_storage_key =
            decode_storage_key(&config.dkg_storage_key).expect("decode dkg storage key");
        assert_ne!(config.dkg_storage_key, config.private_key);
        assert!(dkg_storage_keys.insert(dkg_storage_key));
    }
    assert_eq!(dkg_storage_keys.len(), 4);

    let _ = fs::remove_dir_all(dir);
}
