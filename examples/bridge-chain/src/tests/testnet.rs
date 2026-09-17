use commonware_cryptography::{ed25519, Signer as _};
use commonware_macros::select;
use commonware_p2p::{
    authenticated::discovery::{self, Network},
    Ingress, Manager, Receiver as _, Recipients, Sender as _,
};
use commonware_runtime::{deterministic, Clock as _, Runner as _, Supervisor as _};
use commonware_utils::{ordered::Set, Hostname, NZU32};
use governor::Quota;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use crate::{
    testnet::{
        generate_bridge_pair, BootstrapperConfig, BootstrapperConfigError, LocalBridgePairConfig,
        NodeConfig,
    },
    NAMESPACE,
};

fn replace_bootstrapper_array(raw: &str, replacement: &str) -> String {
    let start = raw
        .find("bootstrappers = [")
        .expect("bootstrapper array missing");
    let mut end = start;
    for line in raw[start..].split_inclusive('\n') {
        end += line.len();
        if line.trim_end().ends_with(']') {
            break;
        }
    }
    format!("{}{replacement}\n{}", &raw[..start], &raw[end..])
}

fn fixture(name: &str, validators: u32, base_port: u16) -> (PathBuf, NodeConfig) {
    let dir = std::env::temp_dir().join(format!(
        "bridge-chain-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let manifest = generate_bridge_pair(LocalBridgePairConfig {
        validators,
        base_port_a: base_port,
        base_rpc_port_a: base_port + 100,
        base_port_b: base_port + 200,
        base_rpc_port_b: base_port + 300,
        base_data_dir: dir,
        seed_a: 7,
        seed_b: 99,
    })
    .expect("generate bridge pair");
    let path = manifest.nodes[0].config_path.clone();
    let config = NodeConfig::read(&path).expect("read generated config");
    (path, config)
}

#[test]
fn generated_peer_addresses_keep_socket_string_format() {
    let (path, config) = fixture("socket-addresses", 2, 30_000);
    let raw = fs::read_to_string(&path).expect("read generated config");

    assert!(raw.contains("dialable_address = \"127.0.0.1:30000\""));
    assert!(raw.contains(&format!("\"{}\"", config.bootstrappers[0])));
    assert!(raw.contains("bootstrappers = ["));
    assert!(!raw.contains("[[bootstrappers]]"));
    assert!(!raw.lines().any(|line| line.starts_with("public_key =")));
    assert!(!raw.lines().any(|line| line.starts_with("address =")));
    assert_eq!(
        config.dialable_address.ip(),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    assert_eq!(
        config.bootstrappers[0].address.ip(),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );

    let dir = path.parent().unwrap().parent().unwrap();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn peer_addresses_round_trip_dns_and_ipv6_as_strings() {
    let (path, mut config) = fixture("address-round-trip", 2, 31_000);
    config.dialable_address = Ingress::Dns {
        host: Hostname::new("validator-0.bridge.example.com").unwrap(),
        port: 30_000,
    };
    config.bootstrappers[0].address = Ingress::Dns {
        host: Hostname::new("validator-1.bridge.example.com").unwrap(),
        port: 30_001,
    };
    config.write(&path).expect("write DNS config");

    let raw = fs::read_to_string(&path).expect("read DNS config");
    assert!(raw.contains("dialable_address = \"validator-0.bridge.example.com:30000\""));
    assert!(raw.contains(&format!("\"{}\"", config.bootstrappers[0])));
    let decoded = NodeConfig::read(&path).expect("read DNS config");
    assert_eq!(decoded.dialable_address, config.dialable_address);
    assert_eq!(
        decoded.bootstrappers[0].address,
        config.bootstrappers[0].address
    );

    config.dialable_address = Ingress::Socket(SocketAddr::new(
        IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>().unwrap()),
        30_000,
    ));
    config.bootstrappers[0].address = Ingress::Socket(SocketAddr::new(
        IpAddr::V6("2001:db8::11".parse::<Ipv6Addr>().unwrap()),
        30_001,
    ));
    config.write(&path).expect("write IPv6 config");
    let raw = fs::read_to_string(&path).expect("read IPv6 config");
    assert!(raw.contains("dialable_address = \"[2001:db8::10]:30000\""));
    assert!(raw.contains(&format!("\"{}\"", config.bootstrappers[0])));
    assert_eq!(
        NodeConfig::read(&path)
            .expect("read IPv6 config")
            .dialable_address,
        config.dialable_address
    );

    let malformed_path = path.with_file_name("malformed-bootstrapper.toml");
    let malformed = raw.replace(&config.bootstrappers[0].to_string(), "not-a-bootstrapper");
    fs::write(&malformed_path, malformed).expect("write malformed bootstrapper config");
    let error = NodeConfig::read(&malformed_path).expect_err("malformed bootstrapper should fail");
    assert!(error.to_string().contains("missing the '@' separator"));

    let legacy_path = path.with_file_name("legacy-bootstrapper.toml");
    let legacy = replace_bootstrapper_array(
        &raw,
        &format!(
            "[[bootstrappers]]\npublic_key = \"{}\"\naddress = \"127.0.0.1:30001\"",
            config.bootstrappers[0].public_key
        ),
    );
    fs::write(&legacy_path, legacy).expect("write legacy bootstrapper config");
    assert!(matches!(
        NodeConfig::read(&legacy_path),
        Err(crate::testnet::Error::TomlDeserialize(_))
    ));

    let dir = path.parent().unwrap().parent().unwrap();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn bootstrapper_config_parses_and_formats_canonical_addresses() {
    let public_key = ed25519::PrivateKey::from_seed(77).public_key();
    let key = public_key.to_string();

    let ipv4: BootstrapperConfig = format!("{key}@192.0.2.1:30001").parse().unwrap();
    assert_eq!(ipv4.public_key, public_key);
    assert_eq!(
        ipv4.address,
        Ingress::Socket("192.0.2.1:30001".parse().unwrap())
    );
    assert_eq!(ipv4.to_string(), format!("{key}@192.0.2.1:30001"));

    let ipv6: BootstrapperConfig = format!("{key}@[2001:db8::1]:30002").parse().unwrap();
    assert_eq!(
        ipv6.address,
        Ingress::Socket("[2001:db8::1]:30002".parse().unwrap())
    );
    assert_eq!(ipv6.to_string(), format!("{key}@[2001:db8::1]:30002"));

    let dns: BootstrapperConfig = format!("{key}@Bootstrap.Example.COM:30003").parse().unwrap();
    assert_eq!(
        dns.address,
        Ingress::Dns {
            host: Hostname::new("bootstrap.example.com").unwrap(),
            port: 30_003,
        }
    );
    assert_eq!(
        dns.to_string(),
        format!("{key}@bootstrap.example.com:30003")
    );
    assert_eq!(dns.to_string().parse::<BootstrapperConfig>().unwrap(), dns);
}

#[test]
fn bootstrapper_config_rejects_invalid_keys_separators_and_addresses() {
    let key = ed25519::PrivateKey::from_seed(78).public_key().to_string();

    assert!(matches!(
        "missing-separator".parse::<BootstrapperConfig>(),
        Err(BootstrapperConfigError::MissingSeparator)
    ));
    assert!(matches!(
        "@127.0.0.1:30001".parse::<BootstrapperConfig>(),
        Err(BootstrapperConfigError::MissingPublicKey)
    ));
    assert!(matches!(
        format!("{key}@").parse::<BootstrapperConfig>(),
        Err(BootstrapperConfigError::MissingAddress)
    ));
    assert!(matches!(
        format!("{key}@@127.0.0.1:30001").parse::<BootstrapperConfig>(),
        Err(BootstrapperConfigError::MultipleSeparators)
    ));

    let invalid_keys = [
        key.to_uppercase(),
        format!("0x{key}"),
        format!("0X{key}"),
        key[..63].to_string(),
        format!("{key}0"),
        format!(" {}", &key[..63]),
        format!("{}\t", &key[..63]),
        format!("{}\r", &key[..63]),
        format!("{}\n", &key[..63]),
        format!("{}g", &key[..63]),
    ];
    for invalid_key in invalid_keys {
        assert!(
            matches!(
                format!("{invalid_key}@127.0.0.1:30001").parse::<BootstrapperConfig>(),
                Err(BootstrapperConfigError::InvalidPublicKeyHex)
            ),
            "unexpected result for {invalid_key:?}"
        );
    }
    assert!(matches!(
        format!("02{}@127.0.0.1:30001", "00".repeat(31)).parse::<BootstrapperConfig>(),
        Err(BootstrapperConfigError::InvalidPublicKey(_))
    ));

    let invalid_addresses = [
        "validator.example.com",
        ":30001",
        "validator.example.com:",
        "validator.example.com:not-a-port",
        "https://validator.example.com:30001",
        "validator.example.com/path:30001",
        "2001:db8::1:30001",
    ];
    for address in invalid_addresses {
        assert!(
            matches!(
                format!("{key}@{address}").parse::<BootstrapperConfig>(),
                Err(BootstrapperConfigError::InvalidAddress(_))
            ),
            "unexpected result for {address}"
        );
    }
}

#[test]
fn node_config_lowercases_dns_addresses() {
    assert_eq!(
        parse_dns_address_through_node_config("Validator-B.Example.COM:39000", 13),
        Ingress::Dns {
            host: Hostname::new("validator-b.example.com").unwrap(),
            port: 39_000,
        }
    );
}

#[test]
fn empty_bootstrapper_array_round_trips() {
    let (path, config) = fixture("empty-bootstrappers", 1, 36_000);
    let raw = fs::read_to_string(&path).expect("read generated config");

    assert!(config.bootstrappers.is_empty());
    assert!(raw.contains("bootstrappers = []"));

    let dir = path.parent().unwrap().parent().unwrap();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn invalid_peer_addresses_are_rejected_through_node_config_read() {
    let (valid_path, _) = fixture("invalid-addresses", 1, 35_000);
    let dir = valid_path.parent().unwrap().parent().unwrap();
    let valid = fs::read_to_string(&valid_path).expect("read generated config");
    let valid_address = "dialable_address = \"127.0.0.1:35000\"";
    assert!(valid.contains(valid_address));

    let cases = [
        ("validator.example.com", "missing a port"),
        (":30000", "missing a host"),
        ("validator.example.com:", "missing a port"),
        ("validator.example.com:not-a-port", "invalid peer address port"),
        ("validator.example.com:65536", "invalid peer address port"),
        ("-validator.example.com:30000", "invalid peer address hostname"),
        (
            "https://validator.example.com:30000",
            "must not contain a URL scheme or path",
        ),
        (
            "validator.example.com/path:30000",
            "invalid peer address hostname",
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
    let (path, _) = fixture(&format!("parse-dns-{seed}"), 1, 38_000);
    let raw = fs::read_to_string(&path).expect("read parser fixture");
    let dns = raw.replace(
        "dialable_address = \"127.0.0.1:38000\"",
        &format!("dialable_address = \"{address}\""),
    );
    fs::write(&path, dns).expect("write parser fixture");
    let ingress = NodeConfig::read(&path)
        .expect("parse DNS address")
        .dialable_address;
    let dir = path.parent().unwrap().parent().unwrap();
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
        context.resolver_register("validator-b-bridge.test", Some(vec![socket_b1.ip()]));

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
        context.resolver_register("validator-b-bridge.test", Some(vec![socket_b2.ip()]));

        // B cannot initiate the replacement connection, so A must resolve B's hostname again.
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
    let dns = parse_dns_address_through_node_config("validator-b-bridge.test:39000", 11);
    let first = run_dns_bootstrapper_redeployment(42, dns.clone());
    let second = run_dns_bootstrapper_redeployment(42, dns);
    assert_eq!(first, second);
}
