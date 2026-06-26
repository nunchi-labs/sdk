use super::{Address, CoinId, MultisigPolicy, TokenDefinition};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use nunchi_common::Event;

pub const ACCOUNT_POLICY_REGISTERED_EVENT: &[u8] = b"coins.account_policy_registered.v1";
pub const TOKEN_CREATED_EVENT: &[u8] = b"coins.token_created.v1";
pub const MINTED_EVENT: &[u8] = b"coins.minted.v1";
pub const BURNED_EVENT: &[u8] = b"coins.burned.v1";
pub const TRANSFERRED_EVENT: &[u8] = b"coins.transferred.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountPolicyRegistered {
    pub account_id: Address,
    pub policy: MultisigPolicy,
}

impl Write for AccountPolicyRegistered {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.account_id.write(buf);
        self.policy.write(buf);
    }
}

impl Read for AccountPolicyRegistered {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            account_id: Address::read(buf)?,
            policy: MultisigPolicy::read(buf)?,
        })
    }
}

impl EncodeSize for AccountPolicyRegistered {
    fn encode_size(&self) -> usize {
        self.account_id.encode_size() + self.policy.encode_size()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenCreated {
    pub token: TokenDefinition,
}

impl Write for TokenCreated {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.token.write(buf);
    }
}

impl Read for TokenCreated {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            token: TokenDefinition::read(buf)?,
        })
    }
}

impl EncodeSize for TokenCreated {
    fn encode_size(&self) -> usize {
        self.token.encode_size()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Minted {
    pub coin: CoinId,
    pub to: Address,
    pub amount: u128,
    pub total_supply: u128,
}

impl Write for Minted {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.coin.write(buf);
        self.to.write(buf);
        self.amount.write(buf);
        self.total_supply.write(buf);
    }
}

impl Read for Minted {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            coin: CoinId::read(buf)?,
            to: Address::read(buf)?,
            amount: u128::read(buf)?,
            total_supply: u128::read(buf)?,
        })
    }
}

impl EncodeSize for Minted {
    fn encode_size(&self) -> usize {
        self.coin.encode_size()
            + self.to.encode_size()
            + self.amount.encode_size()
            + self.total_supply.encode_size()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Burned {
    pub coin: CoinId,
    pub from: Address,
    pub amount: u128,
    pub total_supply: u128,
}

impl Write for Burned {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.coin.write(buf);
        self.from.write(buf);
        self.amount.write(buf);
        self.total_supply.write(buf);
    }
}

impl Read for Burned {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            coin: CoinId::read(buf)?,
            from: Address::read(buf)?,
            amount: u128::read(buf)?,
            total_supply: u128::read(buf)?,
        })
    }
}

impl EncodeSize for Burned {
    fn encode_size(&self) -> usize {
        self.coin.encode_size()
            + self.from.encode_size()
            + self.amount.encode_size()
            + self.total_supply.encode_size()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transferred {
    pub coin: CoinId,
    pub from: Address,
    pub to: Address,
    pub amount: u128,
}

impl Write for Transferred {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.coin.write(buf);
        self.from.write(buf);
        self.to.write(buf);
        self.amount.write(buf);
    }
}

impl Read for Transferred {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            coin: CoinId::read(buf)?,
            from: Address::read(buf)?,
            to: Address::read(buf)?,
            amount: u128::read(buf)?,
        })
    }
}

impl EncodeSize for Transferred {
    fn encode_size(&self) -> usize {
        self.coin.encode_size()
            + self.from.encode_size()
            + self.to.encode_size()
            + self.amount.encode_size()
    }
}

pub fn account_policy_registered_event(value: AccountPolicyRegistered) -> Event {
    Event::new(
        bytes::Bytes::from_static(ACCOUNT_POLICY_REGISTERED_EVENT),
        value.encode(),
    )
}

pub fn token_created_event(value: TokenCreated) -> Event {
    Event::new(bytes::Bytes::from_static(TOKEN_CREATED_EVENT), value.encode())
}

pub fn minted_event(value: Minted) -> Event {
    Event::new(bytes::Bytes::from_static(MINTED_EVENT), value.encode())
}

pub fn burned_event(value: Burned) -> Event {
    Event::new(bytes::Bytes::from_static(BURNED_EVENT), value.encode())
}

pub fn transferred_event(value: Transferred) -> Event {
    Event::new(bytes::Bytes::from_static(TRANSFERRED_EVENT), value.encode())
}
