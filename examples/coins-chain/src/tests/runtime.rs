use nunchi_authority::AuthorityError;
use nunchi_coins::LedgerError;

use crate::runtime::*;

#[test]
fn runtime_error_classifies_storage_errors() {
    assert!(RuntimeError::Coins(LedgerError::Storage("disk".into())).is_storage());
    assert!(RuntimeError::Authority(AuthorityError::Storage("disk".into())).is_storage());

    assert!(!RuntimeError::Authority(AuthorityError::NotConfigured).is_storage());
    assert!(!RuntimeError::Coins(LedgerError::InvalidTokenSpec("bad")).is_storage());
}
