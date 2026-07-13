//! Helpers for turning off-chain matcher output into clearinghouse transactions.

use crate::{ClearinghouseOperation, Transaction};
use nunchi_clob::Fill;
use nunchi_crypto::PrivateKey;

/// Build signed clearinghouse transactions that commit memclob fills and settle perps.
pub fn commit_and_settle_transactions(
    fills: &[Fill],
    settler: &PrivateKey,
    start_nonce: u64,
) -> Vec<Transaction> {
    fills
        .iter()
        .enumerate()
        .map(|(idx, fill)| {
            Transaction::sign(
                settler,
                start_nonce + idx as u64,
                ClearinghouseOperation::CommitAndSettleFill { fill: fill.clone() },
            )
        })
        .collect()
}
