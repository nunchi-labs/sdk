use std::{collections::BTreeMap, future::Future};

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
use commonware_formatting::hex;
use commonware_runtime::{deterministic, Runner as _};
use nunchi_clob::{MarketId, Side};
use nunchi_common::{Address, RuntimeContext, StateError, StateStore};
use nunchi_crypto::PrivateKey;

use crate::{
    authorized_submitter, genesis_vault_id, release_clearing_quote, reserve_clearing_quote,
    settle_clearing_fill, HouseError, HouseGenesis, HouseLedger, HouseOperation,
    HouseVaultGenesis, Mode, NetInventory, Transaction, VaultId, VaultPolicy,
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

fn market(seed: &'static [u8]) -> MarketId {
    MarketId(Sha256::hash(seed))
}

fn policy(markets: Vec<MarketId>) -> VaultPolicy {
    VaultPolicy {
        max_market_allocation: 60_000,
        max_net_inventory: 1_000,
        max_leverage_bps: 10_000,
        allowed_markets: markets,
    }
}

fn create_vault_tx(signer: &PrivateKey, nonce: u64, policy: VaultPolicy) -> Transaction {
    Transaction::sign(signer, nonce, HouseOperation::CreateVault { policy })
}

fn deposit_tx(signer: &PrivateKey, nonce: u64, vault: VaultId, amount: u128) -> Transaction {
    Transaction::sign(signer, nonce, HouseOperation::Deposit { vault, amount })
}

fn withdraw_tx(signer: &PrivateKey, nonce: u64, vault: VaultId, amount: u128) -> Transaction {
    Transaction::sign(signer, nonce, HouseOperation::Withdraw { vault, amount })
}

async fn funded_vault(
    ledger: &mut HouseLedger<MemoryStore>,
    signer: &PrivateKey,
    markets: Vec<MarketId>,
    balance: u128,
) -> VaultId {
    let create = create_vault_tx(signer, 0, policy(markets));
    let vault = VaultId(create.digest());
    ledger.apply_transaction(&create, context(1)).await.unwrap();
    ledger
        .apply_transaction(&deposit_tx(signer, 1, vault, balance), context(2))
        .await
        .unwrap();
    vault
}

#[test]
fn transaction_codec_round_trips() {
    let signer = PrivateKey::from_seed(1);
    let tx = create_vault_tx(&signer, 0, policy(vec![market(b"m1"), market(b"m2")]));
    let encoded = tx.encode();

    assert_eq!(Transaction::decode(encoded).unwrap(), tx);
}

#[test]
fn net_inventory_applies_fills_across_zero() {
    let flat = NetInventory::flat();
    let long = flat.apply(Side::Bid, 5).unwrap();
    assert_eq!(long, NetInventory { negative: false, base: 5 });
    assert_eq!(long.reducing_capacity(Side::Ask), 5);
    assert_eq!(long.reducing_capacity(Side::Bid), 0);

    let short = long.apply(Side::Ask, 8).unwrap();
    assert_eq!(short, NetInventory { negative: true, base: 3 });
    assert_eq!(short.reducing_capacity(Side::Bid), 3);

    let back_to_flat = short.apply(Side::Bid, 3).unwrap();
    assert!(back_to_flat.is_flat());
    assert!(!back_to_flat.negative);

    let encoded = short.encode();
    assert_eq!(NetInventory::decode(encoded).unwrap(), short);

    let negative_zero = [1_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(NetInventory::decode(&negative_zero[..]).is_err());
}

#[test]
fn genesis_seeds_vaults_with_submitters() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let submitter = PrivateKey::from_seed(2);
        let owner_address = Address::external(&owner.public_key());
        let submitter_address = Address::external(&submitter.public_key());
        let mut ledger = HouseLedger::new(MemoryStore::default());

        ledger
            .apply_genesis(&HouseGenesis {
                vaults: vec![HouseVaultGenesis {
                    owner: owner_address.to_bech32(),
                    quote_balance: 500_000,
                    max_market_allocation: 60_000,
                    max_net_inventory: 1_000,
                    max_leverage_bps: 10_000,
                    allowed_markets: vec![hex(market(b"m1").encode().as_ref())],
                    mode: "live".to_string(),
                    submitters: vec![submitter_address.to_bech32()],
                }],
            })
            .await
            .unwrap();

        let id = genesis_vault_id(&owner_address, 0);
        let vault = ledger.vault(&id).await.unwrap().unwrap();
        assert_eq!(vault.owner, owner_address);
        assert_eq!(vault.quote_balance, 500_000);
        assert_eq!(vault.policy.allowed_markets, vec![market(b"m1")]);
        assert_eq!(vault.mode, Mode::Live);
        assert!(authorized_submitter(ledger.db(), &id, &submitter_address)
            .await
            .unwrap());
        assert_eq!(ledger.vaults().await.unwrap().len(), 1);
    });
}

#[test]
fn deposit_and_withdraw_adjust_balance() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let vault = funded_vault(&mut ledger, &owner, vec![market(b"m1")], 1_000).await;

        ledger
            .apply_transaction(&withdraw_tx(&owner, 2, vault, 400), context(3))
            .await
            .unwrap();
        assert_eq!(
            ledger.vault(&vault).await.unwrap().unwrap().quote_balance,
            600
        );

        let err = ledger
            .apply_transaction(&withdraw_tx(&owner, 3, vault, 601), context(4))
            .await
            .unwrap_err();
        assert_eq!(err, HouseError::InsufficientBalance);
    });
}

#[test]
fn non_owner_cannot_manage_vault() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let attacker = PrivateKey::from_seed(2);
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let vault = funded_vault(&mut ledger, &owner, vec![market(b"m1")], 1_000).await;

        let deposit = ledger
            .apply_transaction(&deposit_tx(&attacker, 0, vault, 10), context(3))
            .await
            .unwrap_err();
        assert_eq!(deposit, HouseError::NotVaultOwner);

        let mode = Transaction::sign(
            &attacker,
            0,
            HouseOperation::SetVaultMode {
                vault,
                mode: Mode::Halt,
            },
        );
        let err = ledger.apply_transaction(&mode, context(4)).await.unwrap_err();
        assert_eq!(err, HouseError::NotVaultOwner);
    });
}

#[test]
fn withdraw_requires_live_mode() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let vault = funded_vault(&mut ledger, &owner, vec![market(b"m1")], 1_000).await;

        let freeze = Transaction::sign(
            &owner,
            2,
            HouseOperation::SetVaultMode {
                vault,
                mode: Mode::Frozen,
            },
        );
        ledger.apply_transaction(&freeze, context(3)).await.unwrap();

        let err = ledger
            .apply_transaction(&withdraw_tx(&owner, 3, vault, 100), context(4))
            .await
            .unwrap_err();
        assert_eq!(err, HouseError::VaultNotLive);
    });
}

#[test]
fn withdraw_requires_flat_book() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let m = market(b"m1");
        let vault = funded_vault(&mut ledger, &owner, vec![m], 100_000).await;

        reserve_clearing_quote(&mut ledger.db, &vault, &m, 50_000)
            .await
            .unwrap();
        settle_clearing_fill(&mut ledger.db, &vault, &m, Side::Bid, 100, 40_000, 50_000, 400)
            .await
            .unwrap();

        let err = ledger
            .apply_transaction(&withdraw_tx(&owner, 2, vault, 100), context(5))
            .await
            .unwrap_err();
        assert_eq!(err, HouseError::VaultNotFlat);

        settle_clearing_fill(&mut ledger.db, &vault, &m, Side::Ask, 100, 45_000, 0, 400)
            .await
            .unwrap();
        ledger
            .apply_transaction(&withdraw_tx(&owner, 2, vault, 100), context(6))
            .await
            .unwrap();
    });
}

#[test]
fn submitter_toggle_controls_authorization() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let submitter = PrivateKey::from_seed(2);
        let submitter_address = Address::external(&submitter.public_key());
        let owner_address = Address::external(&owner.public_key());
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let vault = funded_vault(&mut ledger, &owner, vec![market(b"m1")], 1_000).await;

        assert!(authorized_submitter(ledger.db(), &vault, &owner_address)
            .await
            .unwrap());
        assert!(!authorized_submitter(ledger.db(), &vault, &submitter_address)
            .await
            .unwrap());

        let enable = Transaction::sign(
            &owner,
            2,
            HouseOperation::SetAuthorizedSubmitter {
                vault,
                submitter: submitter_address.clone(),
                enabled: true,
            },
        );
        ledger.apply_transaction(&enable, context(3)).await.unwrap();
        assert!(authorized_submitter(ledger.db(), &vault, &submitter_address)
            .await
            .unwrap());

        let disable = Transaction::sign(
            &owner,
            3,
            HouseOperation::SetAuthorizedSubmitter {
                vault,
                submitter: submitter_address.clone(),
                enabled: false,
            },
        );
        ledger.apply_transaction(&disable, context(4)).await.unwrap();
        assert!(!authorized_submitter(ledger.db(), &vault, &submitter_address)
            .await
            .unwrap());
    });
}

#[test]
fn duplicate_policy_market_rejected() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let tx = create_vault_tx(&owner, 0, policy(vec![market(b"m1"), market(b"m1")]));

        let err = ledger.apply_transaction(&tx, context(1)).await.unwrap_err();
        assert_eq!(err, HouseError::InvalidPolicy("duplicate allowed market"));
    });
}

#[test]
fn reservations_move_balance_and_respect_caps() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let m = market(b"m1");
        let vault = funded_vault(&mut ledger, &owner, vec![m], 100_000).await;

        reserve_clearing_quote(&mut ledger.db, &vault, &m, 50_000)
            .await
            .unwrap();
        assert_eq!(
            ledger.vault(&vault).await.unwrap().unwrap().quote_balance,
            50_000
        );
        assert_eq!(ledger.reserved(&vault, &m).await.unwrap(), 50_000);

        let over_allocation = reserve_clearing_quote(&mut ledger.db, &vault, &m, 20_000)
            .await
            .unwrap_err();
        assert_eq!(over_allocation, HouseError::AllocationExceeded);

        let other = market(b"m2");
        let not_allowed = reserve_clearing_quote(&mut ledger.db, &vault, &other, 1_000)
            .await
            .unwrap_err();
        assert_eq!(not_allowed, HouseError::MarketNotAllowed);

        release_clearing_quote(&mut ledger.db, &vault, &m, 50_000)
            .await
            .unwrap();
        assert_eq!(
            ledger.vault(&vault).await.unwrap().unwrap().quote_balance,
            100_000
        );

        let underflow = release_clearing_quote(&mut ledger.db, &vault, &m, 1)
            .await
            .unwrap_err();
        assert_eq!(underflow, HouseError::ReservationUnderflow);
    });
}

#[test]
fn settlement_round_trip_updates_inventory_and_balance() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let m = market(b"m1");
        let vault = funded_vault(&mut ledger, &owner, vec![m], 100_000).await;

        reserve_clearing_quote(&mut ledger.db, &vault, &m, 50_000)
            .await
            .unwrap();
        let long = settle_clearing_fill(
            &mut ledger.db,
            &vault,
            &m,
            Side::Bid,
            100,
            40_000,
            50_000,
            400,
        )
        .await
        .unwrap();
        assert_eq!(long, NetInventory { negative: false, base: 100 });
        assert_eq!(
            ledger.vault(&vault).await.unwrap().unwrap().quote_balance,
            60_000
        );
        assert_eq!(ledger.reserved(&vault, &m).await.unwrap(), 0);
        assert_eq!(ledger.inventory_index(&vault).await.unwrap(), vec![m]);

        let flat = settle_clearing_fill(&mut ledger.db, &vault, &m, Side::Ask, 100, 45_000, 0, 400)
            .await
            .unwrap();
        assert!(flat.is_flat());
        assert_eq!(
            ledger.vault(&vault).await.unwrap().unwrap().quote_balance,
            105_000
        );
        assert!(ledger.inventory_index(&vault).await.unwrap().is_empty());
    });
}

#[test]
fn frozen_vault_is_reduce_only_and_halted_vault_rejects() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let m = market(b"m1");
        let vault = funded_vault(&mut ledger, &owner, vec![m], 100_000).await;

        reserve_clearing_quote(&mut ledger.db, &vault, &m, 50_000)
            .await
            .unwrap();
        settle_clearing_fill(&mut ledger.db, &vault, &m, Side::Bid, 100, 40_000, 50_000, 400)
            .await
            .unwrap();

        let freeze = Transaction::sign(
            &owner,
            2,
            HouseOperation::SetVaultMode {
                vault,
                mode: Mode::Frozen,
            },
        );
        ledger.apply_transaction(&freeze, context(3)).await.unwrap();

        reserve_clearing_quote(&mut ledger.db, &vault, &m, 10_000)
            .await
            .unwrap();
        let increase = settle_clearing_fill(
            &mut ledger.db,
            &vault,
            &m,
            Side::Bid,
            10,
            4_000,
            10_000,
            400,
        )
        .await
        .unwrap_err();
        assert_eq!(increase, HouseError::ModeForbidsIncrease);

        let reduce = settle_clearing_fill(&mut ledger.db, &vault, &m, Side::Ask, 40, 16_000, 0, 400)
            .await
            .unwrap();
        assert_eq!(reduce, NetInventory { negative: false, base: 60 });

        let halt = Transaction::sign(
            &owner,
            3,
            HouseOperation::SetVaultMode {
                vault,
                mode: Mode::Halt,
            },
        );
        ledger.apply_transaction(&halt, context(4)).await.unwrap();
        let halted = settle_clearing_fill(&mut ledger.db, &vault, &m, Side::Ask, 10, 4_000, 0, 400)
            .await
            .unwrap_err();
        assert_eq!(halted, HouseError::VaultHalted);
    });
}

#[test]
fn exposure_caps_bind_on_increase() {
    run_test(|| async {
        let owner = PrivateKey::from_seed(1);
        let mut ledger = HouseLedger::new(MemoryStore::default());
        let m = market(b"m1");
        let vault = funded_vault(&mut ledger, &owner, vec![m], 100_000).await;

        reserve_clearing_quote(&mut ledger.db, &vault, &m, 60_000)
            .await
            .unwrap();
        let over_net = settle_clearing_fill(
            &mut ledger.db,
            &vault,
            &m,
            Side::Bid,
            1_001,
            50_050,
            60_000,
            50,
        )
        .await
        .unwrap_err();
        assert_eq!(over_net, HouseError::NetInventoryExceeded);

        let over_leverage = settle_clearing_fill(
            &mut ledger.db,
            &vault,
            &m,
            Side::Bid,
            1_000,
            60_000,
            60_000,
            200,
        )
        .await
        .unwrap_err();
        assert_eq!(over_leverage, HouseError::LeverageExceeded);
    });
}
