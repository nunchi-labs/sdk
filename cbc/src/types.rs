use commonware_codec::{EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_clob::{MarketId, Side};
use nunchi_common::Address;
use nunchi_house::{Mode, VaultId};

/// Maximum markets registered for batch clearing on one ledger instance.
pub const MAX_CLEARING_MARKETS: usize = 1024;
/// Maximum pending intents retained for one market.
pub const MAX_PENDING_INTENTS: usize = 4096;
/// Maximum fills recorded on one batch result.
pub const MAX_FILLS_PER_BATCH: usize = MAX_PENDING_INTENTS;
/// Maximum rejected intent ids recorded on one batch result.
pub const MAX_REJECTED_PER_BATCH: usize = MAX_PENDING_INTENTS;

/// Stable identifier for a batch clearing intent.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntentId(pub Digest);

impl Write for IntentId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for IntentId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(Digest::read(buf)?))
    }
}

impl FixedSize for IntentId {
    const SIZE: usize = Digest::SIZE;
}

/// Per-market batch clearing parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchParams {
    /// Account allowed to update clearing parameters and mode.
    pub admin: Address,
    /// Account allowed to close and clear batches.
    ///
    /// The keeper also posts the registry-approved oracle price with each
    /// clearing call; this is a documented trust seam until chain-level
    /// oracle wiring supplies the price directly.
    pub keeper: Address,
    /// Minimum blocks between clearings.
    pub cadence_blocks: u64,
    /// Maximum distance between the clearing price and the oracle price.
    pub oracle_band_bps: u32,
    /// Cap on total pending notional per market.
    pub max_batch_notional: u128,
    /// Cap on one vault's pending notional per market.
    pub max_submitter_notional: u128,
    /// Batches clearing less than this base quantity record no fills.
    pub min_clearing_qty: u128,
    pub price_tick: u128,
    pub size_tick: u128,
}

impl Write for BatchParams {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.admin.write(buf);
        self.keeper.write(buf);
        self.cadence_blocks.write(buf);
        self.oracle_band_bps.write(buf);
        self.max_batch_notional.write(buf);
        self.max_submitter_notional.write(buf);
        self.min_clearing_qty.write(buf);
        self.price_tick.write(buf);
        self.size_tick.write(buf);
    }
}

impl Read for BatchParams {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            admin: Address::read(buf)?,
            keeper: Address::read(buf)?,
            cadence_blocks: u64::read(buf)?,
            oracle_band_bps: u32::read(buf)?,
            max_batch_notional: u128::read(buf)?,
            max_submitter_notional: u128::read(buf)?,
            min_clearing_qty: u128::read(buf)?,
            price_tick: u128::read(buf)?,
            size_tick: u128::read(buf)?,
        })
    }
}

impl EncodeSize for BatchParams {
    fn encode_size(&self) -> usize {
        self.admin.encode_size()
            + self.keeper.encode_size()
            + self.cadence_blocks.encode_size()
            + self.oracle_band_bps.encode_size()
            + self.max_batch_notional.encode_size()
            + self.max_submitter_notional.encode_size()
            + self.min_clearing_qty.encode_size()
            + self.price_tick.encode_size()
            + self.size_tick.encode_size()
    }
}

/// Mutable clearing state for one market.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarketClearingState {
    pub mode: Mode,
    /// Number assigned to the next cleared batch.
    pub batch_number: u64,
    pub last_clear_height: u64,
    /// Monotonic sequence for intent ordering.
    pub sequence: u64,
    /// Total `limit_price * remaining_base` over pending intents.
    pub pending_notional: u128,
}

impl MarketClearingState {
    pub fn new() -> Self {
        Self {
            mode: Mode::Live,
            batch_number: 0,
            last_clear_height: 0,
            sequence: 0,
            pending_notional: 0,
        }
    }
}

impl Default for MarketClearingState {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for MarketClearingState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.mode.write(buf);
        self.batch_number.write(buf);
        self.last_clear_height.write(buf);
        self.sequence.write(buf);
        self.pending_notional.write(buf);
    }
}

impl Read for MarketClearingState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            mode: Mode::read(buf)?,
            batch_number: u64::read(buf)?,
            last_clear_height: u64::read(buf)?,
            sequence: u64::read(buf)?,
            pending_notional: u128::read(buf)?,
        })
    }
}

impl EncodeSize for MarketClearingState {
    fn encode_size(&self) -> usize {
        self.mode.encode_size()
            + self.batch_number.encode_size()
            + self.last_clear_height.encode_size()
            + self.sequence.encode_size()
            + self.pending_notional.encode_size()
    }
}

/// Lifecycle state of a batch intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentStatus {
    Pending,
    PartiallyFilled,
    Filled,
    Cancelled,
    Expired,
    Rejected,
}

impl IntentStatus {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Pending | Self::PartiallyFilled)
    }
}

impl Write for IntentStatus {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Pending => 0_u8.write(buf),
            Self::PartiallyFilled => 1_u8.write(buf),
            Self::Filled => 2_u8.write(buf),
            Self::Cancelled => 3_u8.write(buf),
            Self::Expired => 4_u8.write(buf),
            Self::Rejected => 5_u8.write(buf),
        }
    }
}

impl Read for IntentStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Pending),
            1 => Ok(Self::PartiallyFilled),
            2 => Ok(Self::Filled),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::Expired),
            5 => Ok(Self::Rejected),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for IntentStatus {
    fn encode_size(&self) -> usize {
        1
    }
}

/// A signed liquidity-management intent resting in a market's batch queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchIntent {
    pub id: IntentId,
    pub market: MarketId,
    pub vault: VaultId,
    pub submitter: Address,
    pub side: Side,
    pub limit_price: u128,
    pub original_base: u128,
    pub remaining_base: u128,
    pub filled_base: u128,
    pub reduce_only: bool,
    pub expiry_height: u64,
    pub sequence: u64,
    pub status: IntentStatus,
    pub submitted_at_height: u64,
    pub submitted_at_ms: u64,
}

impl BatchIntent {
    /// Worst-case quote notional of the remaining quantity.
    pub fn remaining_notional(&self) -> Option<u128> {
        self.limit_price.checked_mul(self.remaining_base)
    }
}

impl Write for BatchIntent {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.market.write(buf);
        self.vault.write(buf);
        self.submitter.write(buf);
        self.side.write(buf);
        self.limit_price.write(buf);
        self.original_base.write(buf);
        self.remaining_base.write(buf);
        self.filled_base.write(buf);
        self.reduce_only.write(buf);
        self.expiry_height.write(buf);
        self.sequence.write(buf);
        self.status.write(buf);
        self.submitted_at_height.write(buf);
        self.submitted_at_ms.write(buf);
    }
}

impl Read for BatchIntent {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: IntentId::read(buf)?,
            market: MarketId::read(buf)?,
            vault: VaultId::read(buf)?,
            submitter: Address::read(buf)?,
            side: Side::read(buf)?,
            limit_price: u128::read(buf)?,
            original_base: u128::read(buf)?,
            remaining_base: u128::read(buf)?,
            filled_base: u128::read(buf)?,
            reduce_only: bool::read(buf)?,
            expiry_height: u64::read(buf)?,
            sequence: u64::read(buf)?,
            status: IntentStatus::read(buf)?,
            submitted_at_height: u64::read(buf)?,
            submitted_at_ms: u64::read(buf)?,
        })
    }
}

impl EncodeSize for BatchIntent {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.market.encode_size()
            + self.vault.encode_size()
            + self.submitter.encode_size()
            + self.side.encode_size()
            + self.limit_price.encode_size()
            + self.original_base.encode_size()
            + self.remaining_base.encode_size()
            + self.filled_base.encode_size()
            + self.reduce_only.encode_size()
            + self.expiry_height.encode_size()
            + self.sequence.encode_size()
            + self.status.encode_size()
            + self.submitted_at_height.encode_size()
            + self.submitted_at_ms.encode_size()
    }
}

/// Aggregate fill for one intent in one cleared batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClearingFill {
    pub intent: IntentId,
    pub vault: VaultId,
    pub side: Side,
    pub base_quantity: u128,
    pub quote_quantity: u128,
}

impl Write for ClearingFill {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.intent.write(buf);
        self.vault.write(buf);
        self.side.write(buf);
        self.base_quantity.write(buf);
        self.quote_quantity.write(buf);
    }
}

impl Read for ClearingFill {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            intent: IntentId::read(buf)?,
            vault: VaultId::read(buf)?,
            side: Side::read(buf)?,
            base_quantity: u128::read(buf)?,
            quote_quantity: u128::read(buf)?,
        })
    }
}

impl EncodeSize for ClearingFill {
    fn encode_size(&self) -> usize {
        self.intent.encode_size()
            + self.vault.encode_size()
            + self.side.encode_size()
            + self.base_quantity.encode_size()
            + self.quote_quantity.encode_size()
    }
}

/// Terminal disposition of one batch clearing attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchOutcome {
    /// Fills executed at the recorded clearing price.
    Cleared,
    /// No executable volume at or above the minimum clearing quantity.
    NoCross,
    /// The volume-maximizing price fell outside the oracle band.
    OutsideBand,
}

impl Write for BatchOutcome {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Cleared => 0_u8.write(buf),
            Self::NoCross => 1_u8.write(buf),
            Self::OutsideBand => 2_u8.write(buf),
        }
    }
}

impl Read for BatchOutcome {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Cleared),
            1 => Ok(Self::NoCross),
            2 => Ok(Self::OutsideBand),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for BatchOutcome {
    fn encode_size(&self) -> usize {
        1
    }
}

/// Public record of one batch clearing attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchResult {
    pub market: MarketId,
    pub batch_number: u64,
    pub outcome: BatchOutcome,
    pub oracle_price: u128,
    /// Zero unless `outcome` is `Cleared`.
    pub clearing_price: u128,
    /// Total base quantity matched on each side.
    pub total_base: u128,
    pub fills: Vec<ClearingFill>,
    /// Intents removed from the queue by this clearing attempt.
    pub rejected: Vec<IntentId>,
    pub cleared_at_height: u64,
    pub cleared_at_ms: u64,
}

impl Write for BatchResult {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.market.write(buf);
        self.batch_number.write(buf);
        self.outcome.write(buf);
        self.oracle_price.write(buf);
        self.clearing_price.write(buf);
        self.total_base.write(buf);
        self.fills.write(buf);
        self.rejected.write(buf);
        self.cleared_at_height.write(buf);
        self.cleared_at_ms.write(buf);
    }
}

impl Read for BatchResult {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            market: MarketId::read(buf)?,
            batch_number: u64::read(buf)?,
            outcome: BatchOutcome::read(buf)?,
            oracle_price: u128::read(buf)?,
            clearing_price: u128::read(buf)?,
            total_base: u128::read(buf)?,
            fills: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_FILLS_PER_BATCH), ()))?,
            rejected: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_REJECTED_PER_BATCH), ()))?,
            cleared_at_height: u64::read(buf)?,
            cleared_at_ms: u64::read(buf)?,
        })
    }
}

impl EncodeSize for BatchResult {
    fn encode_size(&self) -> usize {
        self.market.encode_size()
            + self.batch_number.encode_size()
            + self.outcome.encode_size()
            + self.oracle_price.encode_size()
            + self.clearing_price.encode_size()
            + self.total_base.encode_size()
            + self.fills.encode_size()
            + self.rejected.encode_size()
            + self.cleared_at_height.encode_size()
            + self.cleared_at_ms.encode_size()
    }
}
