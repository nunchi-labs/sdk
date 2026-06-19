use commonware_codec::{DecodeExt, Encode, FixedSize};
use nunchi_crypto::PrivateKey;

use crate::{Address, MultisigPolicy};

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
