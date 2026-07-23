//! Standalone local-testnet support: config generation and a real-network node runner.
//!
//! [`generate_local_testnet`] performs a trusted setup (key generation plus an initial threshold
//! deal) and writes one TOML config per validator alongside a manifest that process runners such
//! as `narae` consume. [`run_node`] boots a single validator from one of those configs on the
//! tokio runtime with authenticated peer discovery, and serves the aggregated JSON-RPC module.

use commonware_cryptography::{bls12381::primitives::group, ed25519, Signer as _};
use commonware_macros::select;
use commonware_p2p::{
    authenticated::discovery::{self, Network},
    Ingress, Manager, Receiver as _, Recipients, Sender as _,
};
use commonware_runtime::{deterministic, Clock as _, Quota, Runner as _, Supervisor as _};
use commonware_utils::{ordered::Set, Hostname, NZU32};
use std::collections::HashSet;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    path::PathBuf,
    time::Duration,
};

use crate::{testnet::*, NAMESPACE, BLOCKS_PER_EPOCH};

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
        genesis_path: None,
        indexer_url: None,
        seed: 7,
    })
    .expect("generate testnet");

    assert_eq!(manifest.nodes.len(), 4);
    assert_eq!(manifest.indexer.participants, 4);
    assert!(!manifest.indexer.identity.is_empty());
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
        assert_eq!(config.epoch_length, BLOCKS_PER_EPOCH);

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

#[test]
fn node_config_uses_default_epoch_length_when_omitted_and_reads_overrides() {
    let dir = std::env::temp_dir().join(format!(
        "coins-chain-epoch-config-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let manifest = generate_local_testnet(LocalTestnetConfig {
        validators: 1,
        base_port: 43_000,
        base_rpc_port: 44_000,
        base_metrics_port: 45_000,
        base_data_dir: dir.clone(),
        bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        public_ips: None,
        storage_dir: None,
        genesis_path: None,
        indexer_url: None,
        seed: 11,
    })
    .expect("generate testnet");
    let path = &manifest.nodes[0].config_path;
    let raw = fs::read_to_string(path).expect("read generated config");

    let legacy = raw.replace("epoch_length = 200000\n", "");
    fs::write(path, legacy).expect("write legacy config");
    assert_eq!(
        NodeConfig::read(path)
            .expect("read legacy config")
            .epoch_length,
        BLOCKS_PER_EPOCH
    );

    let configured = raw.replace("epoch_length = 200000", "epoch_length = 100");
    fs::write(path, configured).expect("write configured config");
    assert_eq!(
        NodeConfig::read(path)
            .expect("read configured config")
            .epoch_length
            .get(),
        100
    );

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
        genesis_path: None,
        indexer_url: Some("https://indexer.example.com/coins-chain".to_string()),
        seed: 8,
    })
    .expect("generate remote testnet");

    assert_eq!(manifest.indexer.participants, 2);
    assert!(!manifest.indexer.identity.is_empty());

    let first = NodeConfig::read(&manifest.nodes[0].config_path).expect("read first config");
    let second = NodeConfig::read(&manifest.nodes[1].config_path).expect("read second config");
    let first_raw = fs::read_to_string(&manifest.nodes[0].config_path).expect("read first config");

    assert_eq!(first.listen_address.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(first.dialable_address.ip(), Some(public_ips[0]));
    assert_eq!(first.bootstrappers[0].address.ip(), Some(public_ips[1]));
    assert!(first_raw.contains("dialable_address = \"192.0.2.10:30000\""));
    assert!(first_raw.contains("address = \"192.0.2.11:30001\""));
    assert_eq!(first.storage_dir, storage_dir);
    assert_eq!(
        first.indexer_url.as_deref(),
        Some("https://indexer.example.com/coins-chain")
    );
    assert_eq!(second.dialable_address.ip(), Some(public_ips[1]));
    assert_eq!(second.bootstrappers[0].address.ip(), Some(public_ips[0]));
    assert_eq!(
        second.indexer_url.as_deref(),
        Some("https://indexer.example.com/coins-chain")
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn peer_addresses_round_trip_dns_and_ipv6_as_strings() {
    let dir = std::env::temp_dir().join(format!(
        "coins-chain-address-round-trip-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let manifest = generate_local_testnet(LocalTestnetConfig {
        validators: 2,
        base_port: 32_000,
        base_rpc_port: 33_000,
        base_metrics_port: 34_000,
        base_data_dir: dir.clone(),
        bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        public_ips: None,
        storage_dir: None,
        genesis_path: None,
        indexer_url: None,
        seed: 9,
    })
    .expect("generate testnet");
    let path = &manifest.nodes[0].config_path;
    let mut config = NodeConfig::read(path).expect("read generated config");
    config.dialable_address = Ingress::Dns {
        host: Hostname::new("validator-0.example.com").unwrap(),
        port: 30_000,
    };
    config.bootstrappers[0].address = Ingress::Dns {
        host: Hostname::new("validator-1.example.com").unwrap(),
        port: 30_001,
    };
    config.write(path).expect("write DNS config");

    let raw = fs::read_to_string(path).expect("read DNS config");
    assert!(raw.contains("dialable_address = \"validator-0.example.com:30000\""));
    assert!(raw.contains("address = \"validator-1.example.com:30001\""));
    let decoded = NodeConfig::read(path).expect("read DNS config");
    assert_eq!(decoded.dialable_address, config.dialable_address);
    assert_eq!(
        decoded.bootstrappers[0].address,
        config.bootstrappers[0].address
    );

    config.dialable_address = Ingress::Socket(SocketAddr::new(
        IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>().unwrap()),
        30_000,
    ));
    config.write(path).expect("write IPv6 config");
    let raw = fs::read_to_string(path).expect("read IPv6 config");
    assert!(raw.contains("dialable_address = \"[2001:db8::10]:30000\""));
    assert_eq!(
        NodeConfig::read(path)
            .expect("read IPv6 config")
            .dialable_address,
        config.dialable_address
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn invalid_peer_addresses_are_rejected_through_node_config_read() {
    let dir = std::env::temp_dir().join(format!(
        "coins-chain-invalid-addresses-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let manifest = generate_local_testnet(LocalTestnetConfig {
        validators: 1,
        base_port: 35_000,
        base_rpc_port: 36_000,
        base_metrics_port: 37_000,
        base_data_dir: dir.clone(),
        bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        public_ips: None,
        storage_dir: None,
        genesis_path: None,
        indexer_url: None,
        seed: 10,
    })
    .expect("generate testnet");
    let valid_path = &manifest.nodes[0].config_path;
    let valid = fs::read_to_string(valid_path).expect("read generated config");
    let valid_address = "dialable_address = \"127.0.0.1:35000\"";
    assert!(valid.contains(valid_address));

    let cases = [
        ("validator.example.com", "missing a port"),
        ("validator.example.com:not-a-port", "invalid peer address port"),
        ("validator.example.com:65536", "invalid peer address port"),
        ("-validator.example.com:30000", "invalid peer address hostname"),
        (
            "https://validator.example.com:30000",
            "must not contain a URL scheme or path",
        ),
        ("2001:db8::10:30000", "must use bracketed socket syntax"),
    ];
    for (index, (address, expected)) in cases.into_iter().enumerate() {
        let path = dir.join(format!("invalid-{index}.toml"));
        let invalid = valid.replace(
            valid_address,
            &format!("dialable_address = \"{address}\""),
        );
        fs::write(&path, invalid).expect("write invalid config");
        let error = NodeConfig::read(&path).expect_err("invalid address should fail");
        assert!(
            error.to_string().contains(expected),
            "unexpected error for {address}: {error}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

fn parse_dns_address_through_node_config(address: &str, seed: u64) -> Ingress {
    let dir = std::env::temp_dir().join(format!(
        "coins-chain-parse-dns-{seed}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let manifest = generate_local_testnet(LocalTestnetConfig {
        validators: 1,
        base_port: 38_000,
        base_rpc_port: 38_100,
        base_metrics_port: 38_200,
        base_data_dir: dir.clone(),
        bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        public_ips: None,
        storage_dir: None,
        genesis_path: None,
        indexer_url: None,
        seed,
    })
    .expect("generate parser fixture");
    let path = &manifest.nodes[0].config_path;
    let valid = fs::read_to_string(path).expect("read parser fixture");
    let dns = valid.replace(
        "dialable_address = \"127.0.0.1:38000\"",
        &format!("dialable_address = \"{address}\""),
    );
    fs::write(path, dns).expect("write parser fixture");
    let ingress = NodeConfig::read(path)
        .expect("parse DNS address")
        .dialable_address;
    let _ = fs::remove_dir_all(dir);
    ingress
}

fn reconnect_config(
    key: ed25519::PrivateKey,
    listen: SocketAddr,
    dialable: Ingress,
    bootstrappers: Vec<(ed25519::PublicKey, Ingress)>,
) -> discovery::Config<ed25519::PrivateKey> {
    let mut config = discovery::Config::local(
        key,
        NAMESPACE,
        listen,
        dialable,
        bootstrappers,
        1024 * 1024,
    );
    config.peer_connection_cooldown = Duration::from_millis(100);
    config.dial_frequency = Duration::from_millis(50);
    config.gossip_bit_vec_frequency = Duration::from_millis(100);
    config
}

fn run_dns_bootstrapper_redeployment(seed: u64, dns: Ingress) -> String {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(20))),
    );
    runner.start(|context| async move {
        let key_a = ed25519::PrivateKey::from_seed(100);
        let key_b = ed25519::PrivateKey::from_seed(101);
        let public_a = key_a.public_key();
        let public_b = key_b.public_key();
        let peers = Set::try_from(vec![public_a.clone(), public_b.clone()]).unwrap();
        let socket_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)), 39_000);
        let socket_b1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11)), 39_000);
        let socket_b2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 12)), 39_000);
        let unreachable_a = Ingress::Socket(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 250)),
            49_000,
        ));
        context.resolver_register("validator-b-bootstrap.test", Some(vec![socket_b1.ip()]));

        let config_b = reconnect_config(key_b.clone(), socket_b1, dns.clone(), vec![]);
        let (mut network_b, mut oracle_b) =
            Network::new(context.child("b_initial").child("network"), config_b);
        oracle_b.track(0, peers.clone());
        let (mut sender_b, mut receiver_b) =
            network_b.register(0, Quota::per_second(NZU32!(100)), 128);
        let handle_b = network_b.start();

        let config_a = reconnect_config(
            key_a,
            socket_a,
            unreachable_a,
            vec![(public_b.clone(), dns.clone())],
        );
        assert!(config_a.allow_dns);
        let (mut network_a, mut oracle_a) =
            Network::new(context.child("a").child("network"), config_a);
        oracle_a.track(0, peers.clone());
        let (mut sender_a, mut receiver_a) =
            network_a.register(0, Quota::per_second(NZU32!(100)), 128);
        let _handle_a = network_a.start();

        let initial_exchange = async {
            loop {
                sender_a.send(
                    Recipients::One(public_b.clone()),
                    b"a-before".to_vec(),
                    true,
                );
                select! {
                    result = receiver_b.recv() => {
                        let (from, message) = result.unwrap();
                        assert_eq!(from, public_a);
                        assert_eq!(message.as_ref(), b"a-before");
                        break;
                    },
                    _ = context.sleep(Duration::from_millis(50)) => {},
                }
            }
            loop {
                sender_b.send(
                    Recipients::One(public_a.clone()),
                    b"b-before".to_vec(),
                    true,
                );
                select! {
                    result = receiver_a.recv() => {
                        let (from, message) = result.unwrap();
                        assert_eq!(from, public_b);
                        assert_eq!(message.as_ref(), b"b-before");
                        break;
                    },
                    _ = context.sleep(Duration::from_millis(50)) => {},
                }
            }
        };
        select! {
            _ = initial_exchange => {},
            _ = context.sleep(Duration::from_secs(5)) => panic!("initial DNS connection timed out"),
        }

        handle_b.abort();
        drop(sender_b);
        drop(receiver_b);
        context.resolver_register("validator-b-bootstrap.test", Some(vec![socket_b2.ip()]));

        // The restarted peer has no bootstrappers and A advertises an unreachable address, so B
        // cannot initiate the replacement connection.
        let config_b = reconnect_config(key_b, socket_b2, dns, vec![]);
        let (mut network_b, mut oracle_b) =
            Network::new(context.child("b_restarted").child("network"), config_b);
        oracle_b.track(0, peers);
        let (_sender_b, mut receiver_b) =
            network_b.register(0, Quota::per_second(NZU32!(100)), 128);
        let _handle_b = network_b.start();

        let reconnected = async {
            loop {
                sender_a.send(
                    Recipients::One(public_b.clone()),
                    b"a-after".to_vec(),
                    true,
                );
                select! {
                    result = receiver_b.recv() => {
                        let (from, message) = result.unwrap();
                        assert_eq!(from, public_a);
                        assert_eq!(message.as_ref(), b"a-after");
                        break;
                    },
                    _ = context.sleep(Duration::from_millis(50)) => {},
                }
            }
        };
        select! {
            _ = reconnected => {},
            _ = context.sleep(Duration::from_secs(5)) => panic!("DNS bootstrapper did not reconnect"),
        }
        context.auditor().state()
    })
}

#[test]
fn dns_bootstrapper_is_resolved_again_after_redeployment() {
    let dns = parse_dns_address_through_node_config("validator-b-bootstrap.test:39000", 11);
    let first = run_dns_bootstrapper_redeployment(42, dns.clone());
    let second = run_dns_bootstrapper_redeployment(42, dns);
    assert_eq!(first, second);
}

fn run_discovered_dns_redeployment(seed: u64, dns: Ingress) -> String {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(20))),
    );
    runner.start(|context| async move {
        let key_a = ed25519::PrivateKey::from_seed(200);
        let key_b = ed25519::PrivateKey::from_seed(201);
        let key_c = ed25519::PrivateKey::from_seed(202);
        let public_a = key_a.public_key();
        let public_b = key_b.public_key();
        let public_c = key_c.public_key();
        let peers = Set::try_from(vec![
            public_a.clone(),
            public_b.clone(),
            public_c.clone(),
        ])
        .unwrap();
        let socket_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 10)), 40_000);
        let socket_b1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 11)), 40_000);
        let socket_b2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 12)), 40_000);
        let socket_c = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, 13)), 40_000);
        let unreachable_a = Ingress::Socket(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 1, 250)),
            50_000,
        ));
        context.resolver_register("validator-b-discovered.test", Some(vec![socket_b1.ip()]));

        let config_c = reconnect_config(key_c, socket_c, socket_c.into(), vec![]);
        let (mut network_c, mut oracle_c) =
            Network::new(context.child("c").child("network"), config_c);
        oracle_c.track(0, peers.clone());
        let (_sender_c, _receiver_c) =
            network_c.register(0, Quota::per_second(NZU32!(100)), 128);
        let _handle_c = network_c.start();

        let config_b = reconnect_config(
            key_b.clone(),
            socket_b1,
            dns.clone(),
            vec![(public_c.clone(), socket_c.into())],
        );
        let (mut network_b, mut oracle_b) =
            Network::new(context.child("b_initial").child("network"), config_b);
        oracle_b.track(0, peers.clone());
        let (mut sender_b, mut receiver_b) =
            network_b.register(0, Quota::per_second(NZU32!(100)), 128);
        let handle_b = network_b.start();

        // A only knows C initially. It must learn B's DNS ingress through discovery.
        let config_a = reconnect_config(
            key_a,
            socket_a,
            unreachable_a,
            vec![(public_c, socket_c.into())],
        );
        let (mut network_a, mut oracle_a) =
            Network::new(context.child("a").child("network"), config_a);
        oracle_a.track(0, peers.clone());
        let (mut sender_a, mut receiver_a) =
            network_a.register(0, Quota::per_second(NZU32!(100)), 128);
        let _handle_a = network_a.start();

        let learned_and_connected = async {
            loop {
                sender_a.send(
                    Recipients::One(public_b.clone()),
                    b"a-before".to_vec(),
                    true,
                );
                select! {
                    result = receiver_b.recv() => {
                        let (from, message) = result.unwrap();
                        assert_eq!(from, public_a);
                        assert_eq!(message.as_ref(), b"a-before");
                        break;
                    },
                    _ = context.sleep(Duration::from_millis(50)) => {},
                }
            }
            loop {
                sender_b.send(
                    Recipients::One(public_a.clone()),
                    b"b-before".to_vec(),
                    true,
                );
                select! {
                    result = receiver_a.recv() => {
                        let (from, message) = result.unwrap();
                        assert_eq!(from, public_b);
                        assert_eq!(message.as_ref(), b"b-before");
                        break;
                    },
                    _ = context.sleep(Duration::from_millis(50)) => {},
                }
            }
        };
        select! {
            _ = learned_and_connected => {},
            _ = context.sleep(Duration::from_secs(7)) => panic!("A did not discover B's DNS ingress"),
        }

        handle_b.abort();
        drop(sender_b);
        drop(receiver_b);
        context.resolver_register("validator-b-discovered.test", Some(vec![socket_b2.ip()]));

        // B has no bootstrapper after restart and A's advertised address is unreachable. A must
        // retain the discovered hostname, resolve it again, and dial B at its replacement IP.
        let config_b = reconnect_config(key_b, socket_b2, dns, vec![]);
        let (mut network_b, mut oracle_b) =
            Network::new(context.child("b_restarted").child("network"), config_b);
        oracle_b.track(0, peers);
        let (_sender_b, mut receiver_b) =
            network_b.register(0, Quota::per_second(NZU32!(100)), 128);
        let _handle_b = network_b.start();

        let reconnected = async {
            loop {
                sender_a.send(
                    Recipients::One(public_b.clone()),
                    b"a-after".to_vec(),
                    true,
                );
                select! {
                    result = receiver_b.recv() => {
                        let (from, message) = result.unwrap();
                        assert_eq!(from, public_a);
                        assert_eq!(message.as_ref(), b"a-after");
                        break;
                    },
                    _ = context.sleep(Duration::from_millis(50)) => {},
                }
            }
        };
        select! {
            _ = reconnected => {},
            _ = context.sleep(Duration::from_secs(7)) => panic!("discovered DNS peer did not reconnect"),
        }
        context.auditor().state()
    })
}

#[test]
fn discovered_dns_address_is_resolved_again_after_redeployment() {
    let dns = parse_dns_address_through_node_config("validator-b-discovered.test:40000", 12);
    let first = run_discovered_dns_redeployment(84, dns.clone());
    let second = run_discovered_dns_redeployment(84, dns);
    assert_eq!(first, second);
}
