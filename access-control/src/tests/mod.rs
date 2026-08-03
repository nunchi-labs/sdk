use crate::AccessControlLedger;
use commonware_runtime::deterministic;
use nunchi_common::{Address, QmdbState};
use nunchi_crypto::PrivateKey;

mod events;
mod genesis;
mod ledger;
mod transaction;
mod types;

async fn ledger(
    context: deterministic::Context,
) -> AccessControlLedger<QmdbState<deterministic::Context>> {
    let db = QmdbState::init(context, "access-control-test")
        .await
        .expect("initialize state");
    AccessControlLedger::new(db)
}

fn address(key: &PrivateKey) -> Address {
    Address::external(&key.public_key())
}
