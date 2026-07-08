use std::{collections::BTreeMap, future::Future};

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_runtime::{deterministic, Runner as _};
use nunchi_clob::{MarketId, Side};
use nunchi_common::{Address, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;
use nunchi_house::{
    genesis_vault_id, reserve_clearing_quote, settle_clearing_fill, HouseDB, HouseGenesis,
    HouseLedger, HouseVaultGenesis, Mode, NetInventory, VaultId,
};

use crate::{
    BatchOutcome, BatchParams, CbcError, CbcLedger, CbcOperation, IntentId, IntentStatus,
    Transaction,
};

#[derive(Default)]
struct MemoryStore {
    values: BTreeMap<Digest, Option<Vec<u8>>>,
}

impl StateStore for MemoryStore {
    async fn get(&self, key: &Digest) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.values.get(key).cloned().flatten())
    }

    fn set(&mut self, key: Digest, value: Vec<u8>) {
        self.values.insert(key, Some(value));
    }

    fn remove(&mut self, key: Digest) {
        self.values.insert(key, None);
    }
}

fn run_test<F, Fut>(test: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    deterministic::Runner::default().start(|_| test());
}

fn context(height: u64) -> RuntimeContext {
    RuntimeContext {
        epoch: 0,
        height,
        timestamp_ms: height * 1_000,
        block_digest: None,
    }
}

fn market() -> MarketId {
    MarketId(Sha256::hash(b"clearing-market"))
}

fn market_hex() -> String {
    commonware_formatting::hex(market().encode().as_ref())
}

fn params(admin: &Address, keeper: &Address) -> BatchParams {
    BatchParams {
        admin: admin.clone(),
        keeper: keeper.clone(),
        cadence_blocks: 1,
        oracle_band_bps: 50,
        max_batch_notional: 1_000_000_000_000,
        max_submitter_notional: 20_000_000,
        min_clearing_qty: 1,
        price_tick: 1,
        size_tick: 1,
    }
}

fn vault_genesis(owner: &Address, balance: u128) -> HouseVaultGenesis {
    HouseVaultGenesis {
        owner: owner.to_bech32(),
        quote_balance: balance,
        max_market_allocation: 20_000_000,
        max_net_inventory: 2_000,
        max_leverage_bps: 30_000,
        allowed_markets: vec![market_hex()],
        mode: "live".to_string(),
        submitters: Vec::new(),
    }
}

async fn setup(
    vault_balances: &[(PrivateKey, u128)],
) -> (CbcLedger<MemoryStore>, Vec<VaultId>) {
    let mut house = HouseLedger::new(MemoryStore::default());
    let vaults = vault_balances
        .iter()
        .map(|(owner, balance)| vault_genesis(&Address::external(&owner.public_key()), *balance))
        .collect();
    house
        .apply_genesis(&HouseGenesis { vaults })
        .await
        .unwrap();
    let ids = vault_balances
        .iter()
        .enumerate()
        .map(|(index, (owner, _))| {
            genesis_vault_id(&Address::external(&owner.public_key()), index as u64)
        })
        .collect();
    (CbcLedger::new(house.into_inner()), ids)
}

fn register_tx(signer: &PrivateKey, nonce: u64, params: BatchParams) -> Transaction {
    Transaction::sign(
        signer,
        nonce,
        CbcOperation::RegisterMarket {
            market: market(),
            params,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn submit_tx(
    signer: &PrivateKey,
    nonce: u64,
    vault: VaultId,
    side: Side,
    limit_price: u128,
    base_quantity: u128,
    reduce_only: bool,
    expiry_height: u64,
) -> Transaction {
    Transaction::sign(
        signer,
        nonce,
        CbcOperation::SubmitIntent {
            market: market(),
            vault,
            side,
            limit_price,
            base_quantity,
            reduce_only,
            expiry_height,
        },
    )
}

fn clear_tx(signer: &PrivateKey, nonce: u64, oracle_price: u128) -> Transaction {
    Transaction::sign(
        signer,
        nonce,
        CbcOperation::CloseAndClearBatch {
            market: market(),
            oracle_price,
        },
    )
}

async fn balance(ledger: &CbcLedger<MemoryStore>, vault: &VaultId) -> u128 {
    HouseDB::vault(ledger.db(), vault)
        .await
        .unwrap()
        .unwrap()
        .quote_balance
}

async fn inventory(ledger: &CbcLedger<MemoryStore>, vault: &VaultId) -> NetInventory {
    HouseDB::inventory(ledger.db(), vault, &market())
        .await
        .unwrap()
}

/// Free balance plus outstanding clearing reservations.
async fn total_quote(ledger: &CbcLedger<MemoryStore>, vault: &VaultId) -> u128 {
    balance(ledger, vault).await
        + HouseDB::reserved(ledger.db(), vault, &market())
            .await
            .unwrap()
}

#[test]
fn transaction_codec_round_trips() {
    let signer = PrivateKey::from_seed(1);
    let admin = Address::external(&signer.public_key());
    let tx = register_tx(&signer, 0, params(&admin, &admin));
    let encoded = tx.encode();
    assert_eq!(Transaction::decode(encoded).unwrap(), tx);

    let submit = submit_tx(
        &signer,
        1,
        VaultId(Sha256::hash(b"vault")),
        Side::Bid,
        10_000,
        700,
        false,
        50,
    );
    let encoded = submit.encode();
    assert_eq!(Transaction::decode(encoded).unwrap(), submit);
}

#[test]
fn register_market_requires_admin_signature() {
    run_test(|| async {
        let admin = PrivateKey::from_seed(1);
        let other = PrivateKey::from_seed(2);
        let admin_address = Address::external(&admin.public_key());
        let keeper_address = Address::external(&other.public_key());
        let (mut ledger, _) = setup(&[(admin.clone(), 0)]).await;

        let unauthorized = register_tx(&other, 0, params(&admin_address, &keeper_address));
        let err = ledger
            .apply_transaction(&unauthorized, context(1))
            .await
            .unwrap_err();
        assert_eq!(err, CbcError::UnauthorizedAdmin);

        ledger
            .apply_transaction(
                &register_tx(&admin, 0, params(&admin_address, &keeper_address)),
                context(1),
            )
            .await
            .unwrap();
        assert_eq!(ledger.markets().await.unwrap(), vec![market()]);

        let duplicate = register_tx(&admin, 1, params(&admin_address, &keeper_address));
        let err = ledger
            .apply_transaction(&duplicate, context(2))
            .await
            .unwrap_err();
        assert_eq!(err, CbcError::MarketAlreadyRegistered);
    });
}

#[test]
fn submit_requires_authorized_submitter_and_reserves_notional() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let outsider = PrivateKey::from_seed(2);
        let owner_address = Address::external(&owner.public_key());
        let (mut ledger, vaults) = setup(&[(owner.clone(), 10_000_000)]).await;
        let vault = vaults[0];

        ledger
            .apply_transaction(
                &register_tx(&owner, 0, params(&owner_address, &owner_address)),
                context(1),
            )
            .await
            .unwrap();

        let unauthorized = submit_tx(&outsider, 0, vault, Side::Bid, 10_000, 100, false, 50);
        let err = ledger
            .apply_transaction(&unauthorized, context(2))
            .await
            .unwrap_err();
        assert_eq!(err, CbcError::UnauthorizedSubmitter);

        ledger
            .apply_transaction(
                &submit_tx(&owner, 1, vault, Side::Bid, 10_000, 100, false, 50),
                context(2),
            )
            .await
            .unwrap();
        assert_eq!(balance(&ledger, &vault).await, 9_000_000);
        assert_eq!(ledger.pending_intents(&market()).await.unwrap().len(), 1);

        let over_cap = submit_tx(&owner, 2, vault, Side::Bid, 10_000, 2_000, false, 50);
        let err = ledger
            .apply_transaction(&over_cap, context(3))
            .await
            .unwrap_err();
        assert_eq!(err, CbcError::SubmitterNotionalExceeded);
    });
}

#[test]
fn cancel_releases_reservation_and_gates_by_identity() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let outsider = PrivateKey::from_seed(2);
        let owner_address = Address::external(&owner.public_key());
        let (mut ledger, vaults) = setup(&[(owner.clone(), 10_000_000)]).await;
        let vault = vaults[0];

        ledger
            .apply_transaction(
                &register_tx(&owner, 0, params(&owner_address, &owner_address)),
                context(1),
            )
            .await
            .unwrap();
        let submit = submit_tx(&owner, 1, vault, Side::Bid, 10_000, 100, false, 50);
        let intent = IntentId(submit.digest());
        ledger.apply_transaction(&submit, context(2)).await.unwrap();
        assert_eq!(balance(&ledger, &vault).await, 9_000_000);

        let foreign_cancel =
            Transaction::sign(&outsider, 0, CbcOperation::CancelIntent { intent });
        let err = ledger
            .apply_transaction(&foreign_cancel, context(3))
            .await
            .unwrap_err();
        assert_eq!(err, CbcError::UnauthorizedCancel);

        let cancel = Transaction::sign(&owner, 2, CbcOperation::CancelIntent { intent });
        ledger.apply_transaction(&cancel, context(3)).await.unwrap();
        assert_eq!(balance(&ledger, &vault).await, 10_000_000);
        assert!(ledger.pending_intents(&market()).await.unwrap().is_empty());
        assert_eq!(
            ledger.intent(&intent).await.unwrap().unwrap().status,
            IntentStatus::Cancelled
        );

        let double_cancel = Transaction::sign(&owner, 3, CbcOperation::CancelIntent { intent });
        let err = ledger
            .apply_transaction(&double_cancel, context(4))
            .await
            .unwrap_err();
        assert_eq!(err, CbcError::IntentClosed);
    });
}

#[test]
fn keeper_and_cadence_gate_clearing() {
    run_test(|| async {
        let admin = PrivateKey::from_seed(1);
        let keeper = PrivateKey::from_seed(2);
        let admin_address = Address::external(&admin.public_key());
        let keeper_address = Address::external(&keeper.public_key());
        let (mut ledger, _) = setup(&[(admin.clone(), 0)]).await;

        let mut market_params = params(&admin_address, &keeper_address);
        market_params.cadence_blocks = 10;
        ledger
            .apply_transaction(&register_tx(&admin, 0, market_params), context(1))
            .await
            .unwrap();

        let not_keeper = clear_tx(&admin, 1, 10_000);
        let err = ledger
            .apply_transaction(&not_keeper, context(20))
            .await
            .unwrap_err();
        assert_eq!(err, CbcError::UnauthorizedKeeper);

        let too_soon = clear_tx(&keeper, 0, 10_000);
        let err = ledger
            .apply_transaction(&too_soon, context(5))
            .await
            .unwrap_err();
        assert_eq!(err, CbcError::CadenceNotElapsed);

        ledger
            .apply_transaction(&clear_tx(&keeper, 0, 10_000), context(10))
            .await
            .unwrap();
        let result = ledger.batch_result(&market(), 0).await.unwrap().unwrap();
        assert_eq!(result.outcome, BatchOutcome::NoCross);
    });
}

#[test]
fn prd_worked_example_clears_at_oracle_price() {
    run_test(|| async {
        let house_owner = PrivateKey::from_seed(1);
        let mm_a = PrivateKey::from_seed(2);
        let mm_b = PrivateKey::from_seed(3);
        let keeper = PrivateKey::from_seed(4);
        let house_address = Address::external(&house_owner.public_key());
        let keeper_address = Address::external(&keeper.public_key());
        let (mut ledger, vaults) = setup(&[
            (house_owner.clone(), 30_000_000),
            (mm_a.clone(), 10_000_000),
            (mm_b.clone(), 10_000_000),
        ])
        .await;
        let (house_vault, mm_a_vault, mm_b_vault) = (vaults[0], vaults[1], vaults[2]);

        ledger
            .apply_transaction(
                &register_tx(&house_owner, 0, params(&house_address, &keeper_address)),
                context(1),
            )
            .await
            .unwrap();

        reserve_clearing_quote(&mut ledger.db, &house_vault, &market(), 12_000_000)
            .await
            .unwrap();
        settle_clearing_fill(
            &mut ledger.db,
            &house_vault,
            &market(),
            Side::Bid,
            1_200,
            12_000_000,
            12_000_000,
            10_000,
        )
        .await
        .unwrap();
        assert_eq!(
            inventory(&ledger, &house_vault).await,
            NetInventory {
                negative: false,
                base: 1_200
            }
        );

        ledger
            .apply_transaction(
                &submit_tx(&house_owner, 1, house_vault, Side::Ask, 9_990, 1_200, false, 99),
                context(2),
            )
            .await
            .unwrap();
        ledger
            .apply_transaction(
                &submit_tx(&mm_a, 0, mm_a_vault, Side::Bid, 10_006, 700, false, 99),
                context(2),
            )
            .await
            .unwrap();
        ledger
            .apply_transaction(
                &submit_tx(&mm_b, 0, mm_b_vault, Side::Bid, 10_002, 300, false, 99),
                context(2),
            )
            .await
            .unwrap();

        let pre_total = total_quote(&ledger, &house_vault).await
            + total_quote(&ledger, &mm_a_vault).await
            + total_quote(&ledger, &mm_b_vault).await;

        ledger
            .apply_transaction(&clear_tx(&keeper, 0, 10_000), context(3))
            .await
            .unwrap();

        let result = ledger.batch_result(&market(), 0).await.unwrap().unwrap();
        assert_eq!(result.outcome, BatchOutcome::Cleared);
        assert_eq!(result.clearing_price, 10_000);
        assert_eq!(result.total_base, 1_000);
        assert_eq!(result.fills.len(), 3);

        assert_eq!(
            inventory(&ledger, &house_vault).await,
            NetInventory {
                negative: false,
                base: 200
            }
        );
        assert_eq!(
            inventory(&ledger, &mm_a_vault).await,
            NetInventory {
                negative: false,
                base: 700
            }
        );
        assert_eq!(
            inventory(&ledger, &mm_b_vault).await,
            NetInventory {
                negative: false,
                base: 300
            }
        );

        assert_eq!(balance(&ledger, &house_vault).await, 28_000_000);
        assert_eq!(balance(&ledger, &mm_a_vault).await, 3_000_000);
        assert_eq!(balance(&ledger, &mm_b_vault).await, 7_000_000);
        let post_total = total_quote(&ledger, &house_vault).await
            + total_quote(&ledger, &mm_a_vault).await
            + total_quote(&ledger, &mm_b_vault).await;
        assert_eq!(pre_total, post_total);

        let pending = ledger.pending_intents(&market()).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].vault, house_vault);
        assert_eq!(pending[0].remaining_base, 200);
        assert_eq!(pending[0].status, IntentStatus::PartiallyFilled);
    });
}

#[test]
fn frozen_market_requires_reduce_only_submissions() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let owner_address = Address::external(&owner.public_key());
        let (mut ledger, vaults) = setup(&[(owner.clone(), 10_000_000)]).await;
        let vault = vaults[0];

        ledger
            .apply_transaction(
                &register_tx(&owner, 0, params(&owner_address, &owner_address)),
                context(1),
            )
            .await
            .unwrap();
        ledger
            .apply_transaction(
                &Transaction::sign(
                    &owner,
                    1,
                    CbcOperation::SetClearingMode {
                        market: market(),
                        mode: Mode::Frozen,
                    },
                ),
                context(2),
            )
            .await
            .unwrap();

        let increase = submit_tx(&owner, 2, vault, Side::Bid, 10_000, 100, false, 50);
        let err = ledger
            .apply_transaction(&increase, context(3))
            .await
            .unwrap_err();
        assert_eq!(err, CbcError::FrozenRequiresReduceOnly);
    });
}

#[test]
fn expired_intents_are_retired_on_clearing() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let owner_address = Address::external(&owner.public_key());
        let (mut ledger, vaults) = setup(&[(owner.clone(), 10_000_000)]).await;
        let vault = vaults[0];

        ledger
            .apply_transaction(
                &register_tx(&owner, 0, params(&owner_address, &owner_address)),
                context(1),
            )
            .await
            .unwrap();
        let submit = submit_tx(&owner, 1, vault, Side::Bid, 10_000, 100, false, 5);
        let intent = IntentId(submit.digest());
        ledger.apply_transaction(&submit, context(2)).await.unwrap();
        assert_eq!(balance(&ledger, &vault).await, 9_000_000);

        ledger
            .apply_transaction(&clear_tx(&owner, 2, 10_000), context(6))
            .await
            .unwrap();

        assert_eq!(
            ledger.intent(&intent).await.unwrap().unwrap().status,
            IntentStatus::Expired
        );
        assert_eq!(balance(&ledger, &vault).await, 10_000_000);
        assert!(ledger.pending_intents(&market()).await.unwrap().is_empty());
        let result = ledger.batch_result(&market(), 0).await.unwrap().unwrap();
        assert_eq!(result.outcome, BatchOutcome::NoCross);
        assert_eq!(result.rejected, vec![intent]);
    });
}

#[test]
fn out_of_band_price_leaves_queue_untouched() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let counterparty = PrivateKey::from_seed(2);
        let owner_address = Address::external(&owner.public_key());
        let (mut ledger, vaults) = setup(&[
            (owner.clone(), 10_000_000),
            (counterparty.clone(), 10_000_000),
        ])
        .await;
        let (buyer, seller) = (vaults[0], vaults[1]);

        ledger
            .apply_transaction(
                &register_tx(&owner, 0, params(&owner_address, &owner_address)),
                context(1),
            )
            .await
            .unwrap();
        ledger
            .apply_transaction(
                &submit_tx(&owner, 1, buyer, Side::Bid, 11_000, 100, false, 99),
                context(2),
            )
            .await
            .unwrap();
        ledger
            .apply_transaction(
                &submit_tx(&counterparty, 0, seller, Side::Ask, 11_000, 100, false, 99),
                context(2),
            )
            .await
            .unwrap();

        ledger
            .apply_transaction(&clear_tx(&owner, 2, 10_000), context(3))
            .await
            .unwrap();

        let result = ledger.batch_result(&market(), 0).await.unwrap().unwrap();
        assert_eq!(result.outcome, BatchOutcome::OutsideBand);
        assert_eq!(result.total_base, 0);
        assert_eq!(ledger.pending_intents(&market()).await.unwrap().len(), 2);
        assert!(inventory(&ledger, &buyer).await.is_flat());
        assert!(inventory(&ledger, &seller).await.is_flat());
    });
}

#[test]
fn reduce_only_is_capped_to_reducing_capacity() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let counterparty = PrivateKey::from_seed(2);
        let owner_address = Address::external(&owner.public_key());
        let (mut ledger, vaults) = setup(&[
            (owner.clone(), 10_000_000),
            (counterparty.clone(), 10_000_000),
        ])
        .await;
        let (long_vault, buyer_vault) = (vaults[0], vaults[1]);

        ledger
            .apply_transaction(
                &register_tx(&owner, 0, params(&owner_address, &owner_address)),
                context(1),
            )
            .await
            .unwrap();

        reserve_clearing_quote(&mut ledger.db, &long_vault, &market(), 500_000)
            .await
            .unwrap();
        settle_clearing_fill(
            &mut ledger.db,
            &long_vault,
            &market(),
            Side::Bid,
            50,
            500_000,
            500_000,
            10_000,
        )
        .await
        .unwrap();

        ledger
            .apply_transaction(
                &submit_tx(&owner, 1, long_vault, Side::Ask, 10_000, 100, true, 99),
                context(2),
            )
            .await
            .unwrap();
        ledger
            .apply_transaction(
                &submit_tx(&counterparty, 0, buyer_vault, Side::Bid, 10_000, 100, false, 99),
                context(2),
            )
            .await
            .unwrap();

        ledger
            .apply_transaction(&clear_tx(&owner, 2, 10_000), context(3))
            .await
            .unwrap();

        let result = ledger.batch_result(&market(), 0).await.unwrap().unwrap();
        assert_eq!(result.outcome, BatchOutcome::Cleared);
        assert_eq!(result.total_base, 50);
        assert!(inventory(&ledger, &long_vault).await.is_flat());
        assert_eq!(
            inventory(&ledger, &buyer_vault).await,
            NetInventory {
                negative: false,
                base: 50
            }
        );
    });
}

#[test]
fn submission_order_rations_the_heavy_side() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let first_seller = PrivateKey::from_seed(2);
        let second_seller = PrivateKey::from_seed(3);
        let owner_address = Address::external(&owner.public_key());
        let (mut ledger, vaults) = setup(&[
            (owner.clone(), 10_000_000),
            (first_seller.clone(), 10_000_000),
            (second_seller.clone(), 10_000_000),
        ])
        .await;
        let (buyer, seller_one, seller_two) = (vaults[0], vaults[1], vaults[2]);

        ledger
            .apply_transaction(
                &register_tx(&owner, 0, params(&owner_address, &owner_address)),
                context(1),
            )
            .await
            .unwrap();
        let first = submit_tx(&first_seller, 0, seller_one, Side::Ask, 10_000, 60, false, 99);
        let second = submit_tx(&second_seller, 0, seller_two, Side::Ask, 10_000, 60, false, 99);
        ledger.apply_transaction(&first, context(2)).await.unwrap();
        ledger.apply_transaction(&second, context(2)).await.unwrap();
        ledger
            .apply_transaction(
                &submit_tx(&owner, 1, buyer, Side::Bid, 10_000, 80, false, 99),
                context(2),
            )
            .await
            .unwrap();

        ledger
            .apply_transaction(&clear_tx(&owner, 2, 10_000), context(3))
            .await
            .unwrap();

        let result = ledger.batch_result(&market(), 0).await.unwrap().unwrap();
        assert_eq!(result.outcome, BatchOutcome::Cleared);
        assert_eq!(result.total_base, 80);
        assert_eq!(
            ledger
                .intent(&IntentId(first.digest()))
                .await
                .unwrap()
                .unwrap()
                .filled_base,
            60
        );
        assert_eq!(
            ledger
                .intent(&IntentId(second.digest()))
                .await
                .unwrap()
                .unwrap()
                .filled_base,
            20
        );
        assert_eq!(
            inventory(&ledger, &seller_two).await,
            NetInventory {
                negative: true,
                base: 20
            }
        );
    });
}
