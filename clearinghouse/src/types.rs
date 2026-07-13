use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use nunchi_clob::MarketId as ClobMarketId;
use nunchi_perpetuals::MarketId as PerpsMarketId;

/// Stable identifier for a registered settlement market.
pub type SettlementMarketId = Digest;

/// Consumer domain that receives settled CLOB fills.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementDomain {
    Perps(PerpsMarketId),
}

/// Registered mapping from a CLOB market to a settlement consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementMarket {
    pub id: SettlementMarketId,
    pub clob_market: ClobMarketId,
    pub domain: SettlementDomain,
}

/// Derive a settlement market id from its CLOB market and domain.
pub fn derive_settlement_market_id(
    clob_market: &ClobMarketId,
    domain: &SettlementDomain,
) -> SettlementMarketId {
    let mut hasher = Sha256::new();
    hasher.update(super::CLEARINGHOUSE_NAMESPACE);
    hasher.update(b"/settlement-market/");
    hasher.update(clob_market.encode().as_ref());
    match domain {
        SettlementDomain::Perps(market) => {
            hasher.update(&[0u8]);
            hasher.update(market.encode().as_ref());
        }
    }
    hasher.finalize()
}

impl Write for SettlementDomain {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Perps(market) => {
                0u8.write(buf);
                market.write(buf);
            }
        }
    }
}

impl Read for SettlementDomain {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Perps(PerpsMarketId::read(buf)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for SettlementDomain {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Perps(market) => market.encode_size(),
        }
    }
}

impl Write for SettlementMarket {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.clob_market.write(buf);
        self.domain.write(buf);
    }
}

impl Read for SettlementMarket {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: SettlementMarketId::read(buf)?,
            clob_market: ClobMarketId::read(buf)?,
            domain: SettlementDomain::read(buf)?,
        })
    }
}

impl EncodeSize for SettlementMarket {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.clob_market.encode_size() + self.domain.encode_size()
    }
}
