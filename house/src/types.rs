use commonware_codec::{EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_clob::{MarketId, Side};
use nunchi_common::Address;

/// Maximum vaults tracked by one house ledger instance.
pub const MAX_VAULTS: usize = 1024;
/// Maximum authorized submitter keys retained for one vault.
pub const MAX_SUBMITTERS_PER_VAULT: usize = 64;
/// Maximum markets one vault policy may allow.
pub const MAX_ALLOWED_MARKETS: usize = 256;
/// Maximum markets with tracked inventory retained for one vault.
pub const MAX_VAULT_MARKETS: usize = 256;
/// Denominator for basis-point policy parameters.
pub const BPS_DENOMINATOR: u128 = 10_000;

/// Stable identifier for a house vault.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VaultId(pub Digest);

impl Write for VaultId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for VaultId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl FixedSize for VaultId {
    const SIZE: usize = Digest::SIZE;
}

/// Operating mode shared by vaults and clearing markets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Live,
    Frozen,
    Halt,
}

impl Mode {
    /// Whether exposure-increasing actions are allowed.
    pub fn allows_increase(self) -> bool {
        matches!(self, Self::Live)
    }

    /// Whether any state mutation beyond cancellation is allowed.
    pub fn allows_activity(self) -> bool {
        !matches!(self, Self::Halt)
    }
}

impl Write for Mode {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Live => 0_u8.write(buf),
            Self::Frozen => 1_u8.write(buf),
            Self::Halt => 2_u8.write(buf),
        }
    }
}

impl Read for Mode {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Live),
            1 => Ok(Self::Frozen),
            2 => Ok(Self::Halt),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Mode {
    fn encode_size(&self) -> usize {
        1
    }
}

/// Signed net base inventory for one vault in one market.
///
/// Encoded as an explicit sign plus magnitude so state stays independent of
/// platform signed-integer codec behavior. A zero magnitude is always encoded
/// with a positive sign.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NetInventory {
    pub negative: bool,
    pub base: u128,
}

impl NetInventory {
    /// Net inventory of zero.
    pub fn flat() -> Self {
        Self::default()
    }

    pub fn is_flat(self) -> bool {
        self.base == 0
    }

    /// Absolute net base exposure.
    pub fn magnitude(self) -> u128 {
        self.base
    }

    /// Apply a clearing fill to this inventory.
    ///
    /// A `Bid` fill adds long exposure and an `Ask` fill adds short exposure.
    /// Returns `None` on magnitude overflow.
    pub fn apply(self, side: Side, base: u128) -> Option<Self> {
        let signed_long = !self.negative;
        let adds_long = matches!(side, Side::Bid);
        let next = if self.is_flat() || signed_long == adds_long {
            Self {
                negative: !adds_long,
                base: self.base.checked_add(base)?,
            }
        } else if base <= self.base {
            Self {
                negative: self.negative,
                base: self.base - base,
            }
        } else {
            Self {
                negative: !self.negative,
                base: base - self.base,
            }
        };
        Some(next.normalized())
    }

    /// Base quantity of `side` that reduces this inventory toward flat.
    pub fn reducing_capacity(self, side: Side) -> u128 {
        match (side, self.negative) {
            (Side::Ask, false) => self.base,
            (Side::Bid, true) => self.base,
            _ => 0,
        }
    }

    fn normalized(self) -> Self {
        if self.base == 0 {
            Self::flat()
        } else {
            self
        }
    }
}

impl Write for NetInventory {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        let sign: u8 = if self.negative { 1 } else { 0 };
        sign.write(buf);
        self.base.write(buf);
    }
}

impl Read for NetInventory {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let negative = match u8::read(buf)? {
            0 => false,
            1 => true,
            tag => return Err(Error::InvalidEnum(tag)),
        };
        let base = u128::read(buf)?;
        if negative && base == 0 {
            return Err(Error::Invalid("NetInventory", "negative zero"));
        }
        Ok(Self { negative, base })
    }
}

impl EncodeSize for NetInventory {
    fn encode_size(&self) -> usize {
        1 + self.base.encode_size()
    }
}

/// Risk policy caps for one vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultPolicy {
    /// Maximum quote notional reserved or exposed per market through clearing.
    pub max_market_allocation: u128,
    /// Maximum absolute net base inventory per market.
    pub max_net_inventory: u128,
    /// House leverage ceiling: exposure value must stay at or below
    /// `quote_balance * max_leverage_bps / BPS_DENOMINATOR`.
    pub max_leverage_bps: u32,
    /// Markets this vault may take exposure in. An empty list allows none.
    pub allowed_markets: Vec<MarketId>,
}

impl VaultPolicy {
    pub fn allows_market(&self, market: &MarketId) -> bool {
        self.allowed_markets.contains(market)
    }
}

impl Write for VaultPolicy {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.max_market_allocation.write(buf);
        self.max_net_inventory.write(buf);
        self.max_leverage_bps.write(buf);
        self.allowed_markets.write(buf);
    }
}

impl Read for VaultPolicy {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            max_market_allocation: u128::read(buf)?,
            max_net_inventory: u128::read(buf)?,
            max_leverage_bps: u32::read(buf)?,
            allowed_markets: Vec::read_cfg(
                buf,
                &(RangeCfg::new(0..=MAX_ALLOWED_MARKETS), ()),
            )?,
        })
    }
}

impl EncodeSize for VaultPolicy {
    fn encode_size(&self) -> usize {
        self.max_market_allocation.encode_size()
            + self.max_net_inventory.encode_size()
            + self.max_leverage_bps.encode_size()
            + self.allowed_markets.encode_size()
    }
}

/// A house vault: capital, policy, and operating mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vault {
    pub id: VaultId,
    pub owner: Address,
    /// Free quote capital. Reserved amounts are tracked per market and
    /// excluded from this balance.
    pub quote_balance: u128,
    pub policy: VaultPolicy,
    pub mode: Mode,
    pub created_at_height: u64,
    pub created_at_ms: u64,
}

impl Write for Vault {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.owner.write(buf);
        self.quote_balance.write(buf);
        self.policy.write(buf);
        self.mode.write(buf);
        self.created_at_height.write(buf);
        self.created_at_ms.write(buf);
    }
}

impl Read for Vault {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: VaultId::read(buf)?,
            owner: Address::read(buf)?,
            quote_balance: u128::read(buf)?,
            policy: VaultPolicy::read(buf)?,
            mode: Mode::read(buf)?,
            created_at_height: u64::read(buf)?,
            created_at_ms: u64::read(buf)?,
        })
    }
}

impl EncodeSize for Vault {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.owner.encode_size()
            + self.quote_balance.encode_size()
            + self.policy.encode_size()
            + self.mode.encode_size()
            + self.created_at_height.encode_size()
            + self.created_at_ms.encode_size()
    }
}
