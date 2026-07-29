use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{ed25519, Signer as _};
use nunchi_common::MAX_MULTISIG_SIGNERS;
use nunchi_crypto::PrivateKey;

use crate::{AuthorityOperation, MultisigPolicy, MAX_VALIDATORS};

fn configure(owners: usize, validators: usize) -> AuthorityOperation {
    AuthorityOperation::Configure {
        policy: MultisigPolicy {
            owners: (0..owners as u64)
                .map(|s| PrivateKey::from_seed(s).public_key())
                .collect(),
            threshold: 1,
        },
        initial_validators: (0..validators as u64)
            .map(|s| ed25519::PrivateKey::from_seed(s).public_key())
            .collect(),
        epoch: 0,
    }
}

#[test]
fn decode_roundtrips_within_bounds() {
    let operation = configure(MAX_MULTISIG_SIGNERS, MAX_VALIDATORS);
    let decoded = AuthorityOperation::decode(operation.encode()).unwrap();
    assert_eq!(decoded, operation);
}

#[test]
fn decode_rejects_oversized_owner_list() {
    let operation = configure(MAX_MULTISIG_SIGNERS + 1, 0);
    assert!(AuthorityOperation::decode(operation.encode()).is_err());
}

#[test]
fn decode_rejects_oversized_validator_list() {
    let operation = configure(1, MAX_VALIDATORS + 1);
    assert!(AuthorityOperation::decode(operation.encode()).is_err());
}
