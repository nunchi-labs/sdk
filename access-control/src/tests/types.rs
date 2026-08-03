use crate::{RoleId, Scope, ScopeId};
use commonware_codec::{DecodeExt, Encode};
use nunchi_common::Address;
use nunchi_crypto::PrivateKey;

#[test]
fn scope_derivation_separates_modules_and_resources() {
    let module = ScopeId::module(b"example");
    let other_module = ScopeId::module(b"other");
    let resource = ScopeId::resource(b"example", b"resource-a");
    let other_resource = ScopeId::resource(b"example", b"resource-b");

    assert_ne!(module, other_module);
    assert_ne!(module, resource);
    assert_ne!(resource, other_resource);
    assert_eq!(resource, ScopeId::resource(b"example", b"resource-a"));
}

#[test]
fn public_types_roundtrip() {
    let owner = Address::external(&PrivateKey::ed25519_from_seed(1).public_key());
    let scope = Scope::new(ScopeId::module(b"example"), owner);
    let role = RoleId::new(42);

    assert_eq!(Scope::decode(scope.encode()).unwrap(), scope);
    assert_eq!(RoleId::decode(role.encode()).unwrap(), role);
    assert_eq!(role.get(), 42);
}
