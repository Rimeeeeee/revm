//! This module contains [`Journal`] struct and implements [`JournalTr`] trait for it.
//!
//! Entry submodule contains [`JournalEntry`] and [`JournalEntryTr`] traits.
//! and inner submodule contains [`JournalInner`] struct that contains state.
pub mod inner;
pub mod warm_addresses;

pub use context_interface::journaled_state::entry::{JournalEntry, JournalEntryTr};
pub use inner::{JournalCfg, JournalInner};

use bytecode::Bytecode;
use context_interface::{
    context::{SStoreResult, SelfDestructResult, StateLoad},
    journaled_state::{
        account::JournaledAccount, AccountInfoLoad, AccountLoad, JournalCheckpoint,
        JournalLoadError, JournalTr, TransferError, WarmAccessSnapshot,
    },
};
use core::ops::{Deref, DerefMut};
use database_interface::Database;
use primitives::{
    eip7906::TxTraceParam, hardfork::SpecId, Address, AddressMap, AddressSet, Bytes, HashSet, Log,
    StorageKey, StorageValue, B256, U256,
};
use state::{Account, EvmState};
use std::vec::Vec;

/// A journal of state changes internal to the EVM
///
/// On each additional call, the depth of the journaled state is increased (`depth`) and a new
/// journal is added.
///
/// The journal contains every state change that happens within that call, making it possible to
/// revert changes made in a specific call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Journal<DB, ENTRY = JournalEntry>
where
    ENTRY: JournalEntryTr,
{
    /// Database
    pub database: DB,
    /// Inner journal state.
    pub inner: JournalInner<ENTRY>,
}

impl<DB, ENTRY> Deref for Journal<DB, ENTRY>
where
    ENTRY: JournalEntryTr,
{
    type Target = JournalInner<ENTRY>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<DB, ENTRY> DerefMut for Journal<DB, ENTRY>
where
    ENTRY: JournalEntryTr,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<DB, ENTRY: JournalEntryTr> Journal<DB, ENTRY> {
    /// Creates a new JournaledState by copying state data from a JournalInit and provided database.
    /// This allows reusing the state, logs, and other data from a previous execution context while
    /// connecting it to a different database backend.
    pub const fn new_with_inner(database: DB, inner: JournalInner<ENTRY>) -> Self {
        Self { database, inner }
    }

    /// Consumes the [`Journal`] and returns [`JournalInner`].
    ///
    /// If you need to preserve the original journal, use [`Self::to_inner`] instead which clones
    /// the state.
    pub fn into_init(self) -> JournalInner<ENTRY> {
        self.inner
    }
}

impl<DB, ENTRY: JournalEntryTr + Clone> Journal<DB, ENTRY> {
    /// Creates a new [`JournalInner`] by cloning all internal state data (state, storage, logs,
    /// etc) This allows creating a new journaled state with the same state data but without
    /// carrying over the original database.
    ///
    /// This is useful when you want to reuse the current state for a new transaction or
    /// execution context, but want to start with a fresh database.
    pub fn to_inner(&self) -> JournalInner<ENTRY> {
        self.inner.clone()
    }
}

impl<DB: Database, ENTRY: JournalEntryTr> Journal<DB, ENTRY> {}

impl<DB: Database, ENTRY: JournalEntryTr> JournalTr for Journal<DB, ENTRY> {
    type Database = DB;
    type State = EvmState;
    type JournaledAccount<'a>
        = JournaledAccount<'a, DB, ENTRY>
    where
        ENTRY: 'a,
        DB: 'a;

    fn new(database: DB) -> Journal<DB, ENTRY> {
        Self {
            inner: JournalInner::new(),
            database,
        }
    }

    fn db_and_state(&self) -> (&Self::Database, &Self::State) {
        (&self.database, &self.inner.state)
    }

    #[inline]
    fn db_and_state_mut(&mut self) -> (&mut Self::Database, &mut Self::State) {
        (&mut self.database, &mut self.inner.state)
    }

    fn sload(
        &mut self,
        address: Address,
        key: StorageKey,
    ) -> Result<StateLoad<StorageValue>, <Self::Database as Database>::Error> {
        self.inner
            .sload_assume_account_present(&mut self.database, address, key, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    fn sstore(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
    ) -> Result<StateLoad<SStoreResult>, <Self::Database as Database>::Error> {
        self.inner.eip7906_diff = None;
        self.inner
            .sstore_assume_account_present(&mut self.database, address, key, value, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    fn protocol_sload(
        &mut self,
        address: Address,
        key: StorageKey,
    ) -> Result<StorageValue, DB::Error> {
        let id = self.inner.transaction_id;
        let account_cold = self
            .inner
            .state
            .get(&address)
            .is_none_or(|account| account.is_cold_transaction_id(id));
        let slot_cold = self
            .inner
            .state
            .get(&address)
            .and_then(|account| account.storage.get(&key))
            .is_none_or(|slot| slot.is_cold_transaction_id(id));
        self.load_account(address)?;
        let result = self.sload(address, key).map(|load| load.data);
        let account = self
            .inner
            .state
            .get_mut(&address)
            .expect("loaded protocol account");
        if account_cold {
            account.mark_cold();
        }
        if slot_cold {
            if let Some(slot) = account.storage.get_mut(&key) {
                slot.mark_cold();
            }
        }
        result
    }

    fn protocol_sstore(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
    ) -> Result<(), DB::Error> {
        self.protocol_sload(address, key)?;
        let id = self.inner.transaction_id;
        let account = &self.inner.state[&address];
        let account_cold = account.is_cold_transaction_id(id);
        let slot_cold = account.storage[&key].is_cold_transaction_id(id);
        let result = self.sstore(address, key, value).map(|_| ());
        let account = self
            .inner
            .state
            .get_mut(&address)
            .expect("loaded protocol account");
        if account_cold {
            account.mark_cold();
        }
        if slot_cold {
            account
                .storage
                .get_mut(&key)
                .expect("loaded protocol slot")
                .mark_cold();
        }
        result
    }

    fn tload(&mut self, address: Address, key: StorageKey) -> StorageValue {
        self.inner.tload(address, key)
    }

    fn tstore(&mut self, address: Address, key: StorageKey, value: StorageValue) {
        self.inner.tstore(address, key, value)
    }

    fn log(&mut self, log: Log) {
        self.inner.log(log)
    }

    #[inline]
    fn logs(&self) -> &[Log] {
        &self.inner.logs
    }

    fn prepare_eip7906(&mut self) {
        if self.inner.eip7906_diff.is_none() {
            self.inner.eip7906_diff = Some(Eip7906Diff::new(
                &self.inner.state,
                &self.inner.logs,
                self.inner.transaction_id,
                self.inner.journal.len(),
            ));
        }
    }

    fn eip7906_txtrace(&self, param: U256, index: U256) -> Option<U256> {
        let selector = TxTraceParam::try_from(u8::try_from(param).ok()?).ok()?;
        let index = usize::try_from(index).ok()?;
        if selector.requires_zero_index() && index != 0 {
            return None;
        }

        let fallback;
        let diff = match &self.inner.eip7906_diff {
            Some(diff) => diff,
            None => {
                fallback = Eip7906Diff::new(
                    &self.inner.state,
                    &self.inner.logs,
                    self.inner.transaction_id,
                    self.inner.journal.len(),
                );
                &fallback
            }
        };
        eip7906_trace_value(diff, &self.inner.logs, selector, index)
    }

    fn eip7906_event_data(&self, event_index: U256) -> Option<Bytes> {
        let index = usize::try_from(event_index).ok()?;
        Some(self.inner.logs.get(index)?.data.data.clone())
    }

    #[inline]
    fn take_logs(&mut self) -> Vec<Log> {
        self.inner.take_logs()
    }

    fn selfdestruct(
        &mut self,
        address: Address,
        target: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SelfDestructResult>, JournalLoadError<<Self::Database as Database>::Error>>
    {
        self.inner.eip7906_diff = None;
        self.inner
            .selfdestruct(&mut self.database, address, target, skip_cold_load)
    }

    #[inline]
    fn warm_access_list(&mut self, access_list: AddressMap<HashSet<StorageKey>>) {
        self.inner.warm_addresses.set_access_list(access_list);
    }

    #[inline]
    fn warm_coinbase_account(&mut self, address: Address) {
        self.inner.warm_addresses.set_coinbase(address);
    }

    #[inline]
    fn warm_precompiles(&mut self, precompiles: &AddressSet) {
        self.inner
            .warm_addresses
            .set_precompile_addresses(precompiles);
    }

    #[inline]
    fn precompile_addresses(&self) -> &AddressSet {
        self.inner.warm_addresses.precompiles()
    }

    #[inline]
    fn is_account_cold(&self, address: Address) -> bool {
        self.inner.is_account_cold(address)
    }

    /// Returns call depth.
    #[inline]
    fn depth(&self) -> usize {
        self.inner.depth
    }

    #[inline]
    fn set_spec_id(&mut self, spec_id: SpecId) {
        self.inner.cfg.spec = spec_id;
    }

    #[inline]
    fn set_eip7708_config(&mut self, disabled: bool, eip8246_delayed_clear_disabled: bool) {
        self.inner
            .set_eip7708_config(disabled, eip8246_delayed_clear_disabled);
    }

    #[inline]
    fn transfer(
        &mut self,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Result<Option<TransferError>, DB::Error> {
        if !balance.is_zero() {
            self.inner.eip7906_diff = None;
        }
        self.inner.transfer(&mut self.database, from, to, balance)
    }

    #[inline]
    fn transfer_loaded(
        &mut self,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Option<TransferError> {
        if !balance.is_zero() {
            self.inner.eip7906_diff = None;
        }
        self.inner.transfer_loaded(from, to, balance)
    }

    #[inline]
    fn touch_account(&mut self, address: Address) {
        self.inner.touch(address);
    }

    #[inline]
    #[expect(deprecated)]
    fn caller_accounting_journal_entry(
        &mut self,
        address: Address,
        old_balance: U256,
        bump_nonce: bool,
    ) {
        self.inner.eip7906_diff = None;
        self.inner
            .caller_accounting_journal_entry(address, old_balance, bump_nonce);
    }

    /// Increments the balance of the account.
    #[inline]
    fn balance_incr(
        &mut self,
        address: Address,
        balance: U256,
    ) -> Result<(), <Self::Database as Database>::Error> {
        self.inner.eip7906_diff = None;
        self.inner
            .balance_incr(&mut self.database, address, balance)
    }

    /// Increments the nonce of the account.
    #[inline]
    #[expect(deprecated)]
    fn nonce_bump_journal_entry(&mut self, address: Address) {
        self.inner.eip7906_diff = None;
        self.inner.nonce_bump_journal_entry(address)
    }

    #[inline]
    fn load_account(&mut self, address: Address) -> Result<StateLoad<&Account>, DB::Error> {
        self.inner.load_account(&mut self.database, address)
    }

    #[inline]
    fn load_account_mut_skip_cold_load(
        &mut self,
        address: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<Self::JournaledAccount<'_>>, JournalLoadError<DB::Error>> {
        self.inner.eip7906_diff = None;
        self.inner
            .load_account_mut_optional(&mut self.database, address, skip_cold_load)
    }

    #[inline]
    fn load_account_mut_optional_code(
        &mut self,
        address: Address,
        load_code: bool,
    ) -> Result<StateLoad<Self::JournaledAccount<'_>>, DB::Error> {
        self.inner.eip7906_diff = None;
        self.inner
            .load_account_mut_optional_code(&mut self.database, address, load_code, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    #[inline]
    fn load_account_with_code(
        &mut self,
        address: Address,
    ) -> Result<StateLoad<&Account>, DB::Error> {
        self.inner.load_code(&mut self.database, address)
    }

    #[inline]
    fn load_account_delegated(
        &mut self,
        address: Address,
    ) -> Result<StateLoad<AccountLoad>, DB::Error> {
        self.inner
            .load_account_delegated(&mut self.database, address)
    }

    #[inline]
    fn checkpoint(&mut self) -> JournalCheckpoint {
        self.inner.checkpoint()
    }

    #[inline]
    fn checkpoint_commit(&mut self) {
        self.inner.checkpoint_commit()
    }

    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        self.inner.checkpoint_revert(checkpoint)
    }

    fn warm_access_snapshot(&self) -> WarmAccessSnapshot {
        let transaction_id = self.inner.transaction_id;
        let accesses = self
            .inner
            .state
            .iter()
            .filter_map(|(address, account)| {
                if account.is_cold_transaction_id(transaction_id) {
                    return None;
                }
                let slots = account
                    .storage
                    .iter()
                    .filter_map(|(key, slot)| {
                        (!slot.is_cold_transaction_id(transaction_id)).then_some(*key)
                    })
                    .collect();
                Some((*address, slots))
            })
            .collect();
        WarmAccessSnapshot { accesses }
    }

    fn supports_eip8141(&self) -> bool {
        // Implementation capability; transaction validation checks fork activation.
        true
    }

    fn restore_warm_access_snapshot(&mut self, snapshot: &WarmAccessSnapshot) {
        let transaction_id = self.inner.transaction_id;
        for (address, slots) in &snapshot.accesses {
            if let Some(account) = self.inner.state.get_mut(address) {
                account.mark_warm_with_transaction_id(transaction_id);
                for key in slots {
                    if let Some(slot) = account.storage.get_mut(key) {
                        slot.mark_warm_with_transaction_id(transaction_id);
                    }
                }
            }
        }
    }

    fn clear_transient_storage(&mut self) {
        self.inner.transient_storage.clear();
    }

    #[inline]
    fn set_code_with_hash(&mut self, address: Address, code: Bytecode, hash: B256) {
        self.inner.eip7906_diff = None;
        self.inner.set_code_with_hash(address, code, hash);
    }

    fn adopt_code_with_hash(&mut self, address: Address, code: Bytecode, hash: B256) {
        self.set_code_with_hash(address, code, hash);
        self.inner
            .journal
            .push(ENTRY::code_adoption_changed(address, false));
        self.inner
            .state
            .get_mut(&address)
            .unwrap()
            .status
            .insert(state::AccountStatus::CodeAdopted);
    }

    #[inline]
    fn create_account_checkpoint(
        &mut self,
        caller: Address,
        address: Address,
        balance: U256,
        spec_id: SpecId,
    ) -> Result<JournalCheckpoint, TransferError> {
        self.inner.eip7906_diff = None;
        // Ignore error.
        self.inner
            .create_account_checkpoint(caller, address, balance, spec_id)
    }

    #[inline]
    fn commit_tx(&mut self) {
        self.inner.commit_tx()
    }

    #[inline]
    fn discard_tx(&mut self) {
        self.inner.discard_tx();
    }

    /// Clear current journal resetting it to initial state and return changes state.
    #[inline]
    fn finalize(&mut self) -> Self::State {
        self.inner.finalize()
    }

    #[inline]
    fn sload_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        skip_cold_load: bool,
    ) -> Result<StateLoad<StorageValue>, JournalLoadError<<Self::Database as Database>::Error>>
    {
        self.inner
            .sload_assume_account_present(&mut self.database, address, key, skip_cold_load)
    }

    #[inline]
    fn sstore_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, JournalLoadError<<Self::Database as Database>::Error>>
    {
        self.inner.eip7906_diff = None;
        self.inner.sstore_assume_account_present(
            &mut self.database,
            address,
            key,
            value,
            skip_cold_load,
        )
    }

    #[inline]
    fn load_account_info_skip_cold_load(
        &mut self,
        address: Address,
        load_code: bool,
        skip_cold_load: bool,
    ) -> Result<AccountInfoLoad<'_>, JournalLoadError<<Self::Database as Database>::Error>> {
        let spec = self.inner.cfg.spec;
        self.inner
            .load_account_optional(&mut self.database, address, load_code, skip_cold_load)
            .map(|a| {
                AccountInfoLoad::new(&a.data.info, a.is_cold, a.state_clear_aware_is_empty(spec))
            })
    }
}

/// Indexed, transaction-local view frozen while the read-only ASSERT suffix runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Eip7906Diff {
    journal_index: usize,
    balances: Vec<(Address, U256, U256)>,
    slots: Vec<(Address, StorageKey, U256, U256)>,
    deployments: Vec<(Address, B256, B256)>,
    nonces: Vec<(Address, u64, u64)>,
}

impl Eip7906Diff {
    fn new(
        state: &EvmState,
        _logs: &[Log],
        transaction_id: state::TransactionId,
        journal_index: usize,
    ) -> Self {
        let slots = eip7906_storage_changes(state, transaction_id);
        Self {
            journal_index,
            balances: eip7906_balance_changes(state, transaction_id),
            slots,
            deployments: eip7906_deployments(state, transaction_id),
            nonces: eip7906_nonce_changes(state, transaction_id),
        }
    }
}

fn eip7906_balance_changes(
    state: &EvmState,
    transaction_id: state::TransactionId,
) -> Vec<(Address, U256, U256)> {
    let mut changes = state
        .iter()
        .filter_map(|(address, account)| {
            if account.transaction_id != transaction_id {
                return None;
            }
            let before = account.original_info().balance;
            let after = account.info.balance;
            (before != after).then_some((*address, before, after))
        })
        .collect::<Vec<_>>();
    changes.sort_unstable_by_key(|(address, ..)| *address);
    changes
}

fn eip7906_storage_changes(
    state: &EvmState,
    transaction_id: state::TransactionId,
) -> Vec<(Address, StorageKey, U256, U256)> {
    let mut changes = state
        .iter()
        .flat_map(|(address, account)| {
            account
                .changed_storage_slots()
                .filter(move |(_, slot)| slot.transaction_id == transaction_id)
                .map(move |(key, slot)| {
                    (*address, *key, slot.original_value(), slot.present_value())
                })
        })
        .collect::<Vec<_>>();
    changes.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    changes
}

fn eip7906_deployments(
    state: &EvmState,
    transaction_id: state::TransactionId,
) -> Vec<(Address, B256, B256)> {
    let mut deployments = state
        .iter()
        .filter_map(|(address, account)| {
            if account.transaction_id != transaction_id {
                return None;
            }
            let before = account.original_info().code_hash;
            let after = account.info.code_hash;
            (before != after).then_some((*address, before, after))
        })
        .collect::<Vec<_>>();
    deployments.sort_unstable_by_key(|(address, ..)| *address);
    deployments
}

fn eip7906_nonce_changes(
    state: &EvmState,
    transaction_id: state::TransactionId,
) -> Vec<(Address, u64, u64)> {
    let mut changes = state
        .iter()
        .filter_map(|(address, account)| {
            if account.transaction_id != transaction_id {
                return None;
            }
            let before = account.original_info().nonce;
            let after = account.info.nonce;
            (before != after).then_some((*address, before, after))
        })
        .collect::<Vec<_>>();
    changes.sort_unstable_by_key(|(address, ..)| *address);
    changes
}

fn eip7906_trace_value(
    diff: &Eip7906Diff,
    logs: &[Log],
    selector: TxTraceParam,
    index: usize,
) -> Option<U256> {
    match selector {
        TxTraceParam::BalancesChanged => Some(U256::from(diff.balances.len())),
        TxTraceParam::SlotsChanged => Some(U256::from(diff.slots.len())),
        TxTraceParam::CodesChanged => Some(U256::from(diff.deployments.len())),
        TxTraceParam::NoncesChanged => Some(U256::from(diff.nonces.len())),
        TxTraceParam::BalanceChangeAddress
        | TxTraceParam::BalanceBefore
        | TxTraceParam::BalanceAfter => eip7906_balance_trace_value(diff, selector, index),
        TxTraceParam::SlotChangeAddress
        | TxTraceParam::SlotKey
        | TxTraceParam::SlotValueBefore
        | TxTraceParam::SlotValueAfter => eip7906_storage_trace_value(diff, selector, index),
        TxTraceParam::CodeChangeAddress
        | TxTraceParam::CodeHashBefore
        | TxTraceParam::CodeHashAfter => eip7906_deployment_trace_value(diff, selector, index),
        TxTraceParam::NonceChangeAddress | TxTraceParam::NonceBefore | TxTraceParam::NonceAfter => {
            let (address, before, after) = *diff.nonces.get(index)?;
            Some(match selector {
                TxTraceParam::NonceChangeAddress => U256::from_be_slice(address.as_slice()),
                TxTraceParam::NonceBefore => U256::from(before),
                TxTraceParam::NonceAfter => U256::from(after),
                _ => unreachable!(),
            })
        }
        TxTraceParam::EventsCount => Some(U256::from(logs.len())),
        TxTraceParam::EventAddress
        | TxTraceParam::EventTopicCount
        | TxTraceParam::EventTopic0
        | TxTraceParam::EventTopic1
        | TxTraceParam::EventTopic2
        | TxTraceParam::EventTopic3
        | TxTraceParam::EventDataLength => eip7906_event_trace_value(logs, selector, index),
        TxTraceParam::GasPreCharge | TxTraceParam::GasPayerAddress => None,
    }
}

fn eip7906_balance_trace_value(
    diff: &Eip7906Diff,
    selector: TxTraceParam,
    index: usize,
) -> Option<U256> {
    let (address, before, after) = *diff.balances.get(index)?;
    Some(match selector {
        TxTraceParam::BalanceChangeAddress => U256::from_be_slice(address.as_slice()),
        TxTraceParam::BalanceBefore => before,
        TxTraceParam::BalanceAfter => after,
        _ => unreachable!("only balance selectors are dispatched here"),
    })
}

fn eip7906_storage_trace_value(
    diff: &Eip7906Diff,
    selector: TxTraceParam,
    index: usize,
) -> Option<U256> {
    let (address, key, before, after) = *diff.slots.get(index)?;
    Some(match selector {
        TxTraceParam::SlotChangeAddress => U256::from_be_slice(address.as_slice()),
        TxTraceParam::SlotKey => key,
        TxTraceParam::SlotValueBefore => before,
        TxTraceParam::SlotValueAfter => after,
        _ => unreachable!("only storage selectors are dispatched here"),
    })
}

fn eip7906_deployment_trace_value(
    diff: &Eip7906Diff,
    selector: TxTraceParam,
    index: usize,
) -> Option<U256> {
    let (address, before, after) = *diff.deployments.get(index)?;
    Some(match selector {
        TxTraceParam::CodeChangeAddress => U256::from_be_slice(address.as_slice()),
        TxTraceParam::CodeHashBefore => U256::from_be_bytes(before.0),
        TxTraceParam::CodeHashAfter => U256::from_be_bytes(after.0),
        _ => unreachable!("only deployment selectors are dispatched here"),
    })
}

fn eip7906_event_trace_value(logs: &[Log], selector: TxTraceParam, index: usize) -> Option<U256> {
    let event = logs.get(index)?;
    let topics = event.data.topics();
    Some(match selector {
        TxTraceParam::EventAddress => U256::from_be_slice(event.address.as_slice()),
        TxTraceParam::EventTopicCount => U256::from(topics.len()),
        TxTraceParam::EventTopic0 => U256::from_be_bytes(topics.first()?.0),
        TxTraceParam::EventTopic1 => U256::from_be_bytes(topics.get(1)?.0),
        TxTraceParam::EventTopic2 => U256::from_be_bytes(topics.get(2)?.0),
        TxTraceParam::EventTopic3 => U256::from_be_bytes(topics.get(3)?.0),
        TxTraceParam::EventDataLength => U256::from(event.data.data.len()),
        _ => unreachable!("only event selectors are dispatched here"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use context_interface::journaled_state::account::JournaledAccountTr;
    use database::{CacheDB, EmptyDB};
    use primitives::{address, LogData, KECCAK_EMPTY};

    const ACCOUNT: Address = address!("1000000000000000000000000000000000000001");
    const OTHER: Address = address!("2000000000000000000000000000000000000002");
    const SLOT: U256 = U256::from_limbs([7, 0, 0, 0]);

    fn trace(journal: &Journal<CacheDB<EmptyDB>>, param: TxTraceParam, index: usize) -> U256 {
        journal
            .eip7906_txtrace(U256::from(u8::from(param)), U256::from(index))
            .unwrap()
    }

    #[test]
    fn trace_enumerates_net_code_and_nonce_changes_in_address_order() {
        let mut journal = Journal::new(CacheDB::<EmptyDB>::default());
        let before = KECCAK_EMPTY;
        let after = primitives::keccak256([0x00]);
        // Loading a sender without changing its account nonce must not enumerate it.
        journal.load_account(ACCOUNT).unwrap();
        {
            let mut account = journal.load_account_mut(OTHER).unwrap().data;
            account.set_nonce(1);
            account.set_code(after, Bytecode::new_legacy(Bytes::from_static(&[0x00])));
        }
        journal.prepare_eip7906();
        assert_eq!(
            trace(&journal, TxTraceParam::NoncesChanged, 0),
            U256::from(1)
        );
        assert_eq!(
            trace(&journal, TxTraceParam::NonceChangeAddress, 0),
            U256::from_be_slice(OTHER.as_slice())
        );
        assert_eq!(trace(&journal, TxTraceParam::NonceBefore, 0), U256::ZERO);
        assert_eq!(trace(&journal, TxTraceParam::NonceAfter, 0), U256::from(1));
        assert_eq!(
            trace(&journal, TxTraceParam::CodeHashBefore, 0),
            U256::from_be_bytes(before.0)
        );
        assert_eq!(
            trace(&journal, TxTraceParam::CodeHashAfter, 0),
            U256::from_be_bytes(after.0)
        );
        journal.load_account_mut(ACCOUNT).unwrap().data.set_nonce(2);
        journal.prepare_eip7906();
        assert_eq!(
            trace(&journal, TxTraceParam::NoncesChanged, 0),
            U256::from(2)
        );
        assert_eq!(
            trace(&journal, TxTraceParam::NonceChangeAddress, 0),
            U256::from_be_slice(ACCOUNT.as_slice())
        );
        assert!(journal
            .eip7906_txtrace(U256::from(0x0e), U256::from(2))
            .is_none());
        assert!(journal
            .eip7906_txtrace(U256::from(0x1b), U256::ZERO)
            .is_none());
        assert!(journal
            .eip7906_txtrace(U256::from(3), U256::from(1))
            .is_none());
    }

    #[test]
    fn retained_state_is_not_a_current_transaction_diff() {
        let mut journal = Journal::new(CacheDB::<EmptyDB>::default());
        journal
            .load_account_mut(ACCOUNT)
            .unwrap()
            .data
            .set_balance(U256::from(12));
        journal.sstore(ACCOUNT, SLOT, U256::from(4)).unwrap();
        journal.prepare_eip7906();
        assert_eq!(
            trace(&journal, TxTraceParam::BalancesChanged, 0),
            U256::from(1)
        );
        journal.commit_tx();
        assert_eq!(
            trace(&journal, TxTraceParam::BalancesChanged, 0),
            U256::ZERO
        );
        assert_eq!(trace(&journal, TxTraceParam::SlotsChanged, 0), U256::ZERO);
        journal
            .load_account_mut(ACCOUNT)
            .unwrap()
            .data
            .set_balance(U256::from(15));
        journal.sstore(ACCOUNT, SLOT, U256::from(7)).unwrap();
        journal.prepare_eip7906();
        assert_eq!(
            trace(&journal, TxTraceParam::BalanceBefore, 0),
            U256::from(12)
        );
        assert_eq!(
            trace(&journal, TxTraceParam::SlotValueBefore, 0),
            U256::from(4)
        );
        journal.discard_tx();
        assert_eq!(trace(&journal, TxTraceParam::SlotsChanged, 0), U256::ZERO);
    }

    #[test]
    fn frozen_indices_survive_static_reverts_but_not_body_rollback() {
        let mut journal = Journal::new(CacheDB::<EmptyDB>::default());
        journal.load_account(ACCOUNT).unwrap();
        let body = journal.checkpoint();
        journal.sstore(ACCOUNT, SLOT, U256::from(1)).unwrap();
        journal.log(Log {
            address: ACCOUNT,
            data: LogData::new(vec![], Bytes::new()).unwrap(),
        });
        journal.prepare_eip7906();
        let slots_ptr = journal.inner.eip7906_diff.as_ref().unwrap().slots.as_ptr();
        for _ in 0..20 {
            let child = journal.checkpoint();
            journal.load_account(OTHER).unwrap();
            journal.checkpoint_revert(child);
            journal.prepare_eip7906();
            assert_eq!(
                journal.inner.eip7906_diff.as_ref().unwrap().slots.as_ptr(),
                slots_ptr
            );
            assert_eq!(trace(&journal, TxTraceParam::EventsCount, 0), U256::from(1));
        }
        journal.checkpoint_revert(body);
        journal.prepare_eip7906();
        assert_eq!(trace(&journal, TxTraceParam::SlotsChanged, 0), U256::ZERO);
        assert_eq!(trace(&journal, TxTraceParam::EventsCount, 0), U256::ZERO);
    }
}
