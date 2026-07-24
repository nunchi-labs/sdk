use async_trait::async_trait;
use commonware_codec::{Encode, EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::sha256::Digest;
use nunchi_common::{Address, Namespace, StateStore};

use crate::{
    CostsError, LedgerMutationV1, RateCardChangeSet, RateCardEntry, Reservation, CreditAccount, AccountProfile,
    StatusHistoryEntry, UntrackedSourceV1, WriterRole,
    StoredValueLedger,
    COSTS_NAMESPACE,
};

const NS: Namespace = Namespace::new(COSTS_NAMESPACE);

#[repr(u8)]
#[derive(Clone, Copy)]
enum Table {
    Nonce = 0,
    Account = 1,
    Writer = 2,
    Event = 3,
    Rail = 4,
    Reservation = 5,
    UntrackedSource = 6,
    ActiveRate = 7,
    StagedRate = 8,
    RateChangeSet = 9,
    Profile = 10,
    StatusHistory = 11,
    StatusHistoryCount = 12,
    AccountWriter = 13,
    OnboardingRef = 14,
    Journal = 15,
    JournalCount = 16,
    RateHistory = 17,
    RateHistoryCount = 18,
    ActivationEpoch = 19,
    /// Bounded, append-only onboarding order. This is deliberately a list of
    /// opaque `account_id`s only; it is used to materialize approved global rate
    /// defaults to already-onboarded custodial accounts.
    AccountRegistryCount = 20,
    AccountRegistry = 21,
    GlobalRateRegistryCount = 22,
    GlobalRateRegistry = 23,
    /// Whether a account/key's active materialization came from a global default
    /// (rather than a account-owned override). This keeps subsequent global
    /// propagation from treating its own previous materialization as an
    /// override.
    GlobalRateMaterialization = 24,
    /// Per-history-revision provenance. A derived global snapshot must never
    /// masquerade as an explicit account override during scoped lookup.
    RateHistoryGlobalMaterialization = 25,
    StoredValueLedger = 26,
}

impl From<Table> for u8 {
    fn from(table: Table) -> Self {
        table as Self
    }
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    value.encode().as_ref().to_vec()
}

fn decoded<T: Read<Cfg = ()>>(bytes: &[u8]) -> Result<T, CostsError> {
    let mut buf = bytes;
    T::read(&mut buf).map_err(|err| CostsError::Storage(err.to_string()))
}

fn decode_fingerprint(bytes: &[u8]) -> Result<String, CostsError> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| CostsError::Storage("invalid idempotency fingerprint".to_string()))
}

fn nonce_key(account: &Address) -> Digest {
    NS.key(Table::Nonce, account.encode().as_ref())
}

fn account_key(account_id: &str) -> Digest {
    NS.key(Table::Account, account_id.as_bytes())
}

fn writer_key(role: WriterRole, writer: &Address) -> Digest {
    let mut key = Vec::with_capacity(1 + writer.encode_size());
    role.write(&mut key);
    writer.write(&mut key);
    NS.key(Table::Writer, &key)
}

fn account_writer_key(role: WriterRole, account_id: &str, writer: &Address) -> Digest {
    let mut key = Vec::with_capacity(1 + account_id.len() + writer.encode_size() + 2);
    role.write(&mut key);
    key.extend_from_slice(account_id.as_bytes());
    key.push(0);
    writer.write(&mut key);
    NS.key(Table::AccountWriter, &key)
}

fn external_ref_key(external_ref: &str) -> Digest {
    NS.key(Table::OnboardingRef, external_ref.as_bytes())
}

fn event_key(event_id: &str) -> Digest {
    NS.key(Table::Event, event_id.as_bytes())
}

fn profile_key(account_id: &str) -> Digest {
    NS.key(Table::Profile, account_id.as_bytes())
}

fn status_history_count_key(account_id: &str) -> Digest {
    NS.key(Table::StatusHistoryCount, account_id.as_bytes())
}

fn status_history_key(account_id: &str, sequence: u64) -> Digest {
    let mut material = account_id.as_bytes().to_vec();
    material.extend_from_slice(&sequence.to_be_bytes());
    NS.key(Table::StatusHistory, &material)
}

fn rail_key(rail_ref: &str) -> Digest {
    NS.key(Table::Rail, rail_ref.as_bytes())
}

fn reservation_key(reservation_id: &str) -> Digest {
    NS.key(Table::Reservation, reservation_id.as_bytes())
}

fn untracked_source_key(source_id: &str) -> Digest {
    NS.key(Table::UntrackedSource, source_id.as_bytes())
}

fn rate_material(account_id: &str, event_category: &str, task_key: &str) -> Vec<u8> {
    let mut material = Vec::with_capacity(account_id.len() + event_category.len() + task_key.len() + 2);
    material.extend_from_slice(account_id.as_bytes());
    material.push(0);
    material.extend_from_slice(event_category.as_bytes());
    material.push(0);
    material.extend_from_slice(task_key.as_bytes());
    material
}

fn active_rate_key(account_id: &str, event_category: &str, task_key: &str) -> Digest {
    NS.key(Table::ActiveRate, &rate_material(account_id, event_category, task_key))
}

fn staged_rate_key(change_set_id: &str, entry: &RateCardEntry) -> Digest {
    let mut material = change_set_id.as_bytes().to_vec();
    material.push(0);
    material.extend_from_slice(&rate_material(&entry.account_id, &entry.event_category, &entry.task_key));
    NS.key(Table::StagedRate, &material)
}

fn rate_change_set_key(change_set_id: &str) -> Digest {
    NS.key(Table::RateChangeSet, change_set_id.as_bytes())
}

fn activation_epoch_key() -> Digest {
    NS.key(Table::ActivationEpoch, b"global")
}

fn account_registry_count_key() -> Digest {
    NS.key(Table::AccountRegistryCount, b"all")
}

fn account_registry_key(sequence: u64) -> Digest {
    NS.key(Table::AccountRegistry, &sequence.to_be_bytes())
}

fn global_rate_registry_count_key() -> Digest {
    NS.key(Table::GlobalRateRegistryCount, b"all")
}

fn global_rate_registry_key(sequence: u64) -> Digest {
    NS.key(Table::GlobalRateRegistry, &sequence.to_be_bytes())
}

fn global_rate_materialization_key(account_id: &str, event_category: &str, task_key: &str) -> Digest {
    NS.key(Table::GlobalRateMaterialization, &rate_material(account_id, event_category, task_key))
}

fn rate_history_count_key(account_id: &str, event_category: &str, task_key: &str) -> Digest {
    NS.key(Table::RateHistoryCount, &rate_material(account_id, event_category, task_key))
}

fn rate_history_global_materialization_key(account_id: &str, event_category: &str, task_key: &str, sequence: u64) -> Digest {
    let mut material = rate_material(account_id, event_category, task_key);
    material.extend_from_slice(&sequence.to_be_bytes());
    NS.key(Table::RateHistoryGlobalMaterialization, &material)
}

fn rate_history_key(account_id: &str, event_category: &str, task_key: &str, sequence: u64) -> Digest {
    let mut material = rate_material(account_id, event_category, task_key);
    material.extend_from_slice(&sequence.to_be_bytes());
    NS.key(Table::RateHistory, &material)
}

fn journal_count_key() -> Digest {
    NS.key(Table::JournalCount, b"all")
}

fn journal_key(sequence: u64) -> Digest {
    NS.key(Table::Journal, &sequence.to_be_bytes())
}

fn stored_value_ledger_key() -> Digest { NS.key(Table::StoredValueLedger, b"v2") }

/// Typed state access required by [`crate::CostsLedger`].
#[async_trait]
pub trait CostsDB {
    async fn nonce(&self, account: &Address) -> Result<u64, CostsError>;
    fn set_nonce(&mut self, account: &Address, nonce: u64);

    async fn account(&self, account_id: &str) -> Result<Option<CreditAccount>, CostsError>;
    fn set_account(&mut self, account_id: &str, account: CreditAccount);

    async fn profile(&self, account_id: &str) -> Result<Option<AccountProfile>, CostsError>;
    fn set_profile(&mut self, profile: AccountProfile);
    async fn status_history_count(&self, account_id: &str) -> Result<u64, CostsError>;
    fn set_status_history_count(&mut self, account_id: &str, count: u64);
    async fn status_history(
        &self,
        account_id: &str,
        sequence: u64,
    ) -> Result<Option<StatusHistoryEntry>, CostsError>;
    fn set_status_history(&mut self, account_id: &str, entry: StatusHistoryEntry);

    async fn writer(&self, role: WriterRole, writer: &Address) -> Result<bool, CostsError>;
    fn set_writer(&mut self, role: WriterRole, writer: &Address, enabled: bool);
    async fn account_writer(
        &self,
        role: WriterRole,
        account_id: &str,
        writer: &Address,
    ) -> Result<bool, CostsError>;
    fn set_account_writer(&mut self, role: WriterRole, account_id: &str, writer: &Address, enabled: bool);

    async fn onboarding_account(&self, external_ref: &str) -> Result<Option<String>, CostsError>;
    fn set_onboarding_account(&mut self, external_ref: &str, account_id: &str);
    /// Return the number of programmatically-onboarded account accounts. The
    /// ledger bounds every scan of this registry before it writes state.
    async fn account_registry_count(&self) -> Result<u64, CostsError>;
    fn set_account_registry_count(&mut self, count: u64);
    async fn account_registry_account(&self, sequence: u64) -> Result<Option<String>, CostsError>;
    fn set_account_registry_account(&mut self, sequence: u64, account_id: &str);

    async fn global_rate_registry_count(&self) -> Result<u64, CostsError>;
    fn set_global_rate_registry_count(&mut self, count: u64);
    async fn global_rate_registry_entry(&self, sequence: u64) -> Result<Option<RateCardEntry>, CostsError>;
    fn set_global_rate_registry_entry(&mut self, sequence: u64, entry: RateCardEntry);
    async fn global_rate_materialized(&self, account_id: &str, event_category: &str, task_key: &str) -> Result<bool, CostsError>;
    fn set_global_rate_materialized(&mut self, account_id: &str, event_category: &str, task_key: &str, materialized: bool);

    async fn event_fingerprint(&self, event_id: &str) -> Result<Option<String>, CostsError>;
    fn mark_event(&mut self, event_id: &str, fingerprint: &str);

    async fn rail_fingerprint(&self, rail_ref: &str) -> Result<Option<String>, CostsError>;
    fn mark_rail(&mut self, rail_ref: &str, fingerprint: &str);

    async fn reservation(&self, reservation_id: &str) -> Result<Option<Reservation>, CostsError>;
    fn set_reservation(&mut self, reservation: Reservation);

    async fn untracked_source(&self, source_id: &str) -> Result<Option<UntrackedSourceV1>, CostsError>;
    fn set_untracked_source(&mut self, source: UntrackedSourceV1);

    async fn active_rate(
        &self,
        account_id: &str,
        event_category: &str,
        task_key: &str,
    ) -> Result<Option<RateCardEntry>, CostsError>;
    fn set_active_rate(&mut self, entry: RateCardEntry);
    async fn rate_history_count(&self, account_id: &str, event_category: &str, task_key: &str) -> Result<u64, CostsError>;
    fn set_rate_history_count(&mut self, account_id: &str, event_category: &str, task_key: &str, count: u64);
    async fn rate_history_entry(&self, account_id: &str, event_category: &str, task_key: &str, sequence: u64) -> Result<Option<RateCardEntry>, CostsError>;
    fn set_rate_history_entry(&mut self, entry: RateCardEntry, sequence: u64);
    async fn rate_history_global_materialization(&self, account_id: &str, event_category: &str, task_key: &str, sequence: u64) -> Result<bool, CostsError>;
    fn set_rate_history_global_materialization(&mut self, account_id: &str, event_category: &str, task_key: &str, sequence: u64, materialized: bool);

    async fn staged_rate(
        &self,
        change_set_id: &str,
        entry: &RateCardEntry,
    ) -> Result<Option<RateCardEntry>, CostsError>;
    fn set_staged_rate(&mut self, change_set_id: &str, entry: RateCardEntry);

    async fn rate_change_set(
        &self,
        change_set_id: &str,
    ) -> Result<Option<RateCardChangeSet>, CostsError>;
    fn set_rate_change_set(&mut self, change_set: RateCardChangeSet);
    /// Global high-watermark for approved rate activations. A change set may
    /// never reuse or move this monotonic control-plane epoch backwards.
    async fn activation_epoch_high_watermark(&self) -> Result<u64, CostsError>;
    fn set_activation_epoch_high_watermark(&mut self, epoch: u64);

    async fn journal_count(&self) -> Result<u64, CostsError>;
    fn set_journal_count(&mut self, count: u64);
    async fn journal_entry(&self, sequence: u64) -> Result<Option<LedgerMutationV1>, CostsError>;
    fn set_journal_entry(&mut self, entry: LedgerMutationV1);

    async fn stored_value_ledger(&self) -> Result<StoredValueLedger, CostsError>;
    fn set_stored_value_ledger(&mut self, ledger: StoredValueLedger);
}

#[async_trait]
impl<S: StateStore + Send + Sync> CostsDB for S {
    async fn nonce(&self, account: &Address) -> Result<u64, CostsError> {
        match StateStore::get(self, &nonce_key(account))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_nonce(&mut self, account: &Address, nonce: u64) {
        StateStore::set(self, nonce_key(account), encoded(&nonce));
    }

    async fn account(&self, account_id: &str) -> Result<Option<CreditAccount>, CostsError> {
        match StateStore::get(self, &account_key(account_id))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_account(&mut self, account_id: &str, account: CreditAccount) {
        StateStore::set(self, account_key(account_id), encoded(&account));
    }

    async fn profile(&self, account_id: &str) -> Result<Option<AccountProfile>, CostsError> {
        match StateStore::get(self, &profile_key(account_id))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_profile(&mut self, profile: AccountProfile) {
        StateStore::set(self, profile_key(&profile.account_id), encoded(&profile));
    }

    async fn status_history_count(&self, account_id: &str) -> Result<u64, CostsError> {
        match StateStore::get(self, &status_history_count_key(account_id))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_status_history_count(&mut self, account_id: &str, count: u64) {
        StateStore::set(self, status_history_count_key(account_id), encoded(&count));
    }

    async fn status_history(
        &self,
        account_id: &str,
        sequence: u64,
    ) -> Result<Option<StatusHistoryEntry>, CostsError> {
        match StateStore::get(self, &status_history_key(account_id, sequence))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_status_history(&mut self, account_id: &str, entry: StatusHistoryEntry) {
        StateStore::set(self, status_history_key(account_id, entry.sequence), encoded(&entry));
    }

    async fn writer(&self, role: WriterRole, writer: &Address) -> Result<bool, CostsError> {
        match StateStore::get(self, &writer_key(role, writer))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(false),
        }
    }

    fn set_writer(&mut self, role: WriterRole, writer: &Address, enabled: bool) {
        StateStore::set(self, writer_key(role, writer), encoded(&enabled));
    }

    async fn account_writer(
        &self,
        role: WriterRole,
        account_id: &str,
        writer: &Address,
    ) -> Result<bool, CostsError> {
        match StateStore::get(self, &account_writer_key(role, account_id, writer))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(false),
        }
    }

    fn set_account_writer(&mut self, role: WriterRole, account_id: &str, writer: &Address, enabled: bool) {
        StateStore::set(self, account_writer_key(role, account_id, writer), encoded(&enabled));
    }

    async fn onboarding_account(&self, external_ref: &str) -> Result<Option<String>, CostsError> {
        match StateStore::get(self, &external_ref_key(external_ref))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decode_fingerprint(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_onboarding_account(&mut self, external_ref: &str, account_id: &str) {
        StateStore::set(self, external_ref_key(external_ref), account_id.as_bytes().to_vec());
    }

    async fn account_registry_count(&self) -> Result<u64, CostsError> {
        match StateStore::get(self, &account_registry_count_key())
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_account_registry_count(&mut self, count: u64) {
        StateStore::set(self, account_registry_count_key(), encoded(&count));
    }

    async fn account_registry_account(&self, sequence: u64) -> Result<Option<String>, CostsError> {
        match StateStore::get(self, &account_registry_key(sequence))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| CostsError::Storage("invalid account registry entry".to_string())),
            None => Ok(None),
        }
    }

    fn set_account_registry_account(&mut self, sequence: u64, account_id: &str) {
        StateStore::set(self, account_registry_key(sequence), account_id.as_bytes().to_vec());
    }

    async fn global_rate_registry_count(&self) -> Result<u64, CostsError> {
        match StateStore::get(self, &global_rate_registry_count_key()).await.map_err(|err| CostsError::Storage(err.to_string()))? {
            Some(bytes) => decoded(&bytes), None => Ok(0),
        }
    }

    fn set_global_rate_registry_count(&mut self, count: u64) {
        StateStore::set(self, global_rate_registry_count_key(), encoded(&count));
    }

    async fn global_rate_registry_entry(&self, sequence: u64) -> Result<Option<RateCardEntry>, CostsError> {
        match StateStore::get(self, &global_rate_registry_key(sequence)).await.map_err(|err| CostsError::Storage(err.to_string()))? {
            Some(bytes) => decoded(&bytes).map(Some), None => Ok(None),
        }
    }

    fn set_global_rate_registry_entry(&mut self, sequence: u64, entry: RateCardEntry) {
        StateStore::set(self, global_rate_registry_key(sequence), encoded(&entry));
    }

    async fn global_rate_materialized(&self, account_id: &str, event_category: &str, task_key: &str) -> Result<bool, CostsError> {
        match StateStore::get(self, &global_rate_materialization_key(account_id, event_category, task_key)).await.map_err(|err| CostsError::Storage(err.to_string()))? {
            Some(bytes) => decoded(&bytes), None => Ok(false),
        }
    }

    fn set_global_rate_materialized(&mut self, account_id: &str, event_category: &str, task_key: &str, materialized: bool) {
        StateStore::set(self, global_rate_materialization_key(account_id, event_category, task_key), encoded(&materialized));
    }

    async fn event_fingerprint(&self, event_id: &str) -> Result<Option<String>, CostsError> {
        match StateStore::get(self, &event_key(event_id))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decode_fingerprint(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn mark_event(&mut self, event_id: &str, fingerprint: &str) {
        StateStore::set(self, event_key(event_id), fingerprint.as_bytes().to_vec());
    }

    async fn rail_fingerprint(&self, rail_ref: &str) -> Result<Option<String>, CostsError> {
        match StateStore::get(self, &rail_key(rail_ref))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decode_fingerprint(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn mark_rail(&mut self, rail_ref: &str, fingerprint: &str) {
        StateStore::set(self, rail_key(rail_ref), fingerprint.as_bytes().to_vec());
    }

    async fn reservation(&self, reservation_id: &str) -> Result<Option<Reservation>, CostsError> {
        match StateStore::get(self, &reservation_key(reservation_id))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_reservation(&mut self, reservation: Reservation) {
        StateStore::set(self, reservation_key(&reservation.reservation_id), encoded(&reservation));
    }

    async fn untracked_source(&self, source_id: &str) -> Result<Option<UntrackedSourceV1>, CostsError> {
        match StateStore::get(self, &untracked_source_key(source_id))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_untracked_source(&mut self, source: UntrackedSourceV1) {
        StateStore::set(self, untracked_source_key(&source.source_id), encoded(&source));
    }

    async fn active_rate(
        &self,
        account_id: &str,
        event_category: &str,
        task_key: &str,
    ) -> Result<Option<RateCardEntry>, CostsError> {
        match StateStore::get(self, &active_rate_key(account_id, event_category, task_key))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_active_rate(&mut self, entry: RateCardEntry) {
        StateStore::set(
            self,
            active_rate_key(&entry.account_id, &entry.event_category, &entry.task_key),
            encoded(&entry),
        );
    }

    async fn rate_history_count(&self, account_id: &str, event_category: &str, task_key: &str) -> Result<u64, CostsError> {
        match StateStore::get(self, &rate_history_count_key(account_id, event_category, task_key)).await.map_err(|err| CostsError::Storage(err.to_string()))? {
            Some(bytes) => decoded(&bytes), None => Ok(0),
        }
    }

    fn set_rate_history_count(&mut self, account_id: &str, event_category: &str, task_key: &str, count: u64) {
        StateStore::set(self, rate_history_count_key(account_id, event_category, task_key), encoded(&count));
    }

    async fn rate_history_entry(&self, account_id: &str, event_category: &str, task_key: &str, sequence: u64) -> Result<Option<RateCardEntry>, CostsError> {
        match StateStore::get(self, &rate_history_key(account_id, event_category, task_key, sequence)).await.map_err(|err| CostsError::Storage(err.to_string()))? {
            Some(bytes) => decoded(&bytes).map(Some), None => Ok(None),
        }
    }

    fn set_rate_history_entry(&mut self, entry: RateCardEntry, sequence: u64) {
        StateStore::set(self, rate_history_key(&entry.account_id, &entry.event_category, &entry.task_key, sequence), encoded(&entry));
    }

    async fn rate_history_global_materialization(&self, account_id: &str, event_category: &str, task_key: &str, sequence: u64) -> Result<bool, CostsError> {
        match StateStore::get(self, &rate_history_global_materialization_key(account_id, event_category, task_key, sequence)).await.map_err(|err| CostsError::Storage(err.to_string()))? {
            Some(bytes) => decoded(&bytes), None => Ok(false),
        }
    }

    fn set_rate_history_global_materialization(&mut self, account_id: &str, event_category: &str, task_key: &str, sequence: u64, materialized: bool) {
        StateStore::set(self, rate_history_global_materialization_key(account_id, event_category, task_key, sequence), encoded(&materialized));
    }

    async fn staged_rate(
        &self,
        change_set_id: &str,
        entry: &RateCardEntry,
    ) -> Result<Option<RateCardEntry>, CostsError> {
        match StateStore::get(self, &staged_rate_key(change_set_id, entry))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_staged_rate(&mut self, change_set_id: &str, entry: RateCardEntry) {
        StateStore::set(self, staged_rate_key(change_set_id, &entry), encoded(&entry));
    }

    async fn rate_change_set(
        &self,
        change_set_id: &str,
    ) -> Result<Option<RateCardChangeSet>, CostsError> {
        match StateStore::get(self, &rate_change_set_key(change_set_id))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_rate_change_set(&mut self, change_set: RateCardChangeSet) {
        StateStore::set(
            self,
            rate_change_set_key(&change_set.change_set_id),
            encoded(&change_set),
        );
    }

    async fn activation_epoch_high_watermark(&self) -> Result<u64, CostsError> {
        match StateStore::get(self, &activation_epoch_key()).await.map_err(|err| CostsError::Storage(err.to_string()))? {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_activation_epoch_high_watermark(&mut self, epoch: u64) {
        StateStore::set(self, activation_epoch_key(), encoded(&epoch));
    }

    async fn journal_count(&self) -> Result<u64, CostsError> {
        match StateStore::get(self, &journal_count_key())
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes),
            None => Ok(0),
        }
    }

    fn set_journal_count(&mut self, count: u64) {
        StateStore::set(self, journal_count_key(), encoded(&count));
    }

    async fn journal_entry(&self, sequence: u64) -> Result<Option<LedgerMutationV1>, CostsError> {
        match StateStore::get(self, &journal_key(sequence))
            .await
            .map_err(|err| CostsError::Storage(err.to_string()))?
        {
            Some(bytes) => decoded(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn set_journal_entry(&mut self, entry: LedgerMutationV1) {
        StateStore::set(self, journal_key(entry.sequence), encoded(&entry));
    }

    async fn stored_value_ledger(&self) -> Result<StoredValueLedger, CostsError> {
        match StateStore::get(self, &stored_value_ledger_key()).await.map_err(|err| CostsError::Storage(err.to_string()))? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|err| CostsError::Storage(err.to_string())),
            None => Ok(StoredValueLedger::default()),
        }
    }

    fn set_stored_value_ledger(&mut self, ledger: StoredValueLedger) {
        let bytes = serde_json::to_vec(&ledger).expect("stored value ledger serializes");
        StateStore::set(self, stored_value_ledger_key(), bytes);
    }
}
