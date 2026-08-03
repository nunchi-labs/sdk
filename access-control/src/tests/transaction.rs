use crate::{AccessControlOperation, RoleId, ScopeId};
use commonware_codec::{DecodeExt, Encode};
use nunchi_common::Address;
use nunchi_crypto::PrivateKey;

fn account(seed: u64) -> Address {
    Address::external(&PrivateKey::ed25519_from_seed(seed).public_key())
}

#[test]
fn operation_codec_uses_stable_tags() {
    let scope = ScopeId::module(b"example");
    let operations = [
        AccessControlOperation::GrantRole {
            scope,
            role: RoleId::new(1),
            account: account(1),
        },
        AccessControlOperation::RevokeRole {
            scope,
            role: RoleId::new(1),
            account: account(1),
        },
        AccessControlOperation::ProposeOwnershipTransfer {
            scope,
            proposed_owner: account(2),
        },
        AccessControlOperation::CancelOwnershipTransfer { scope },
        AccessControlOperation::AcceptOwnership { scope },
    ];

    for (tag, operation) in operations.into_iter().enumerate() {
        let encoded = operation.encode();
        assert_eq!(encoded[0], tag as u8);
        assert_eq!(AccessControlOperation::decode(encoded).unwrap(), operation);
    }
    assert!(AccessControlOperation::decode([99].as_slice()).is_err());
}
