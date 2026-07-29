use commonware_cryptography::{ed25519, Signer};
use commonware_math::algebra::Random;
use commonware_utils::{ordered::Set, test_rng, TryCollect};

use crate::setup::PeerConfig;

fn make_config(
    participants: usize,
    per_round: Vec<u32>,
) -> PeerConfig<ed25519::PublicKey> {
    let mut rng = test_rng();
    let keys: Set<_> = (0..participants)
        .map(|_| ed25519::PrivateKey::random(&mut rng).public_key())
        .try_collect()
        .unwrap();
    PeerConfig {
        num_participants_per_round: per_round,
        participants: keys,
    }
}

#[test]
fn dealers_round_zero_takes_first_n_participants() {
    let config = make_config(5, vec![3]);
    let dealers = config.dealers(0);
    assert_eq!(dealers.len(), 3);
    // Round 0 takes the first N participants, not a random sample.
    let first_three: Set<_> = config
        .participants
        .iter()
        .take(3)
        .cloned()
        .try_collect()
        .unwrap();
    assert_eq!(dealers, first_three);
}

#[test]
fn dealers_round_n_is_deterministic() {
    let config = make_config(10, vec![5]);
    assert_eq!(config.dealers(3), config.dealers(3));
    assert_eq!(config.dealers(7), config.dealers(7));
}

#[test]
fn num_participants_in_round_cycles() {
    let config = make_config(10, vec![3, 4]);
    assert_eq!(config.num_participants_in_round(0), 3);
    assert_eq!(config.num_participants_in_round(1), 4);
    assert_eq!(config.num_participants_in_round(2), 3);
    assert_eq!(config.num_participants_in_round(3), 4);
}

#[test]
fn max_participants_per_round_returns_max() {
    let config = make_config(10, vec![3, 7, 5]);
    assert_eq!(config.max_participants_per_round(), 7);
}

#[test]
fn dealers_returns_correct_count() {
    let config = make_config(10, vec![5]);
    let dealers = config.dealers(1);
    assert_eq!(dealers.len(), 5);
}
