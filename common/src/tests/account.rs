use commonware_codec::{DecodeExt, Encode, FixedSize};
use nunchi_crypto::PrivateKey;
use std::str::FromStr;

use crate::{Address, Bech32Error, MultisigPolicy, ADDRESS_HRP};

#[test]
fn addresses_share_a_fixed_width_space_and_roundtrip() {
    let ed = PrivateKey::ed25519_from_seed(1).public_key();
    let secp = PrivateKey::secp256r1_from_seed(1).public_key();
    let ed_address = Address::external(&ed);
    let secp_address = Address::external(&secp);

    assert_eq!(
        ed_address.encode().len(),
        commonware_cryptography::sha256::Digest::SIZE
    );
    assert_eq!(
        secp_address.encode().len(),
        commonware_cryptography::sha256::Digest::SIZE
    );
    assert_ne!(ed_address, secp_address);
    assert_eq!(
        Address::decode(ed_address.encode().as_ref()).unwrap(),
        ed_address
    );
}

#[test]
fn address_derivation_separates_external_and_multisig_accounts() {
    let signer = PrivateKey::ed25519_from_seed(1).public_key();
    let policy = MultisigPolicy::new(1, vec![signer.clone()]).unwrap();

    assert_ne!(Address::external(&signer), Address::multisig(&policy));
}

#[test]
fn module_address_derivation_is_stable_and_domain_separated() {
    let signer = PrivateKey::ed25519_from_seed(1).public_key();
    let policy = MultisigPolicy::new(1, vec![signer.clone()]).unwrap();
    let module = Address::module(b"test/module", b"collector");

    assert_eq!(module, Address::module(b"test/module", b"collector"));
    assert_ne!(module, Address::module(b"test/module", b"issuer"));
    assert_ne!(module, Address::module(b"other/module", b"collector"));
    assert_ne!(module, Address::external(&signer));
    assert_ne!(module, Address::multisig(&policy));
}

#[test]
fn external_address_roundtrips_through_bech32() {
    let signer = PrivateKey::ed25519_from_seed(1).public_key();
    let address = Address::external(&signer);
    let encoded = address.to_bech32();

    assert!(encoded.starts_with(&format!("{ADDRESS_HRP}1")));
    assert_eq!(Address::from_bech32(&encoded).unwrap(), address);
}

#[test]
fn multisig_address_roundtrips_through_bech32() {
    let alice = PrivateKey::ed25519_from_seed(1).public_key();
    let bob = PrivateKey::secp256r1_from_seed(2).public_key();
    let policy = MultisigPolicy::new(2, vec![alice, bob]).unwrap();
    let address = Address::multisig(&policy);

    assert_eq!(Address::from_bech32(&address.to_bech32()).unwrap(), address);
}

#[test]
fn display_and_fromstr_use_bech32_address_encoding() {
    let signer = PrivateKey::ed25519_from_seed(1).public_key();
    let address = Address::external(&signer);

    assert_eq!(address.to_string(), address.to_bech32());
    assert_eq!(Address::from_str(&address.to_string()).unwrap(), address);
}

#[test]
fn bech32_address_rejects_wrong_hrp() {
    let signer = PrivateKey::ed25519_from_seed(1).public_key();
    let address = Address::external(&signer);
    let hrp = bech32::Hrp::parse("bad").unwrap();
    let wrong = bech32::encode::<bech32::Bech32>(hrp, address.encode().as_ref()).unwrap();

    assert!(matches!(
        Address::from_bech32(&wrong),
        Err(Bech32Error::WrongHrp { .. })
    ));
}

#[test]
fn bech32_address_rejects_bad_checksum() {
    let signer = PrivateKey::ed25519_from_seed(1).public_key();
    let address = Address::external(&signer);
    let mut encoded = address.to_bech32();
    let last = encoded.pop().unwrap();
    encoded.push(if last == 'q' { 'p' } else { 'q' });

    assert!(matches!(
        Address::from_bech32(&encoded),
        Err(Bech32Error::Decode(_))
    ));
}

#[test]
fn bech32_address_rejects_wrong_payload_length() {
    let hrp = bech32::Hrp::parse(ADDRESS_HRP).unwrap();
    let encoded = bech32::encode::<bech32::Bech32>(hrp, &[1, 2, 3]).unwrap();

    assert!(matches!(
        Address::from_bech32(&encoded),
        Err(Bech32Error::WrongLength {
            expected: Address::SIZE,
            actual: 3,
        })
    ));
}

#[test]
fn bech32_address_rejects_empty_string() {
    assert!(matches!(
        Address::from_bech32(""),
        Err(Bech32Error::Decode(_))
    ));
}
