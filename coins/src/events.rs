use bytes::Bytes;
use commonware_codec::Encode;
use nunchi_common::{Event, EventAttribute};

use crate::{AccountPolicy, Address, CoinId, CoinSpec};

const MODULE: &[u8] = b"coins";
const VERSION: u16 = 1;

pub(crate) fn account_policy_registered(account: &Address, policy: &AccountPolicy) -> Event {
    event(
        b"account_policy_registered",
        vec![attr(b"account", account), attr(b"policy", policy)],
    )
}

pub(crate) fn token_created(coin: &CoinId, issuer: &Address, spec: &CoinSpec) -> Event {
    event(
        b"token_created",
        vec![
            attr(b"coin", coin),
            attr(b"issuer", issuer),
            attr(b"spec", spec),
        ],
    )
}

pub(crate) fn minted(coin: &CoinId, to: &Address, amount: &u128) -> Event {
    event(
        b"minted",
        vec![
            attr(b"coin", coin),
            attr(b"to", to),
            attr(b"amount", amount),
        ],
    )
}

pub(crate) fn burned(coin: &CoinId, from: &Address, amount: &u128) -> Event {
    event(
        b"burned",
        vec![
            attr(b"coin", coin),
            attr(b"from", from),
            attr(b"amount", amount),
        ],
    )
}

pub(crate) fn transferred(coin: &CoinId, from: &Address, to: &Address, amount: &u128) -> Event {
    event(
        b"transferred",
        vec![
            attr(b"coin", coin),
            attr(b"from", from),
            attr(b"to", to),
            attr(b"amount", amount),
        ],
    )
}

fn event(kind: &'static [u8], attributes: Vec<EventAttribute>) -> Event {
    Event::new(
        Bytes::from_static(MODULE),
        Bytes::from_static(kind),
        VERSION,
        attributes,
    )
}

fn attr<T: Encode>(key: &'static [u8], value: &T) -> EventAttribute {
    EventAttribute::new(Bytes::from_static(key), value.encode())
}
