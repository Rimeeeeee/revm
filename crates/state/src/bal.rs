//! Block Access List (BAL) data structures for efficient state access in blockchain execution.
//!
//! This module provides types for managing Block Access Lists, which optimize state access
//! by pre-computing and organizing data that will be accessed during block execution.
//!
//! ## Key Types
//!
//! - [`BlockAccessIndex`]: block access index
//! - **`Bal`**: Main BAL structure containing a map of accounts
//! - **`BalWrites<T>`**: Array of (index, value) pairs representing sequential writes to a state
//!   item
//! - **`AccountBal`**: Complete BAL structure for an account (balance, nonce, code, and storage)
//! - **`AccountInfoBal`**: Account info BAL data (nonce, balance, code)
//! - **`StorageBal`**: Storage-level BAL data for an account

pub mod account;
pub mod alloy;
pub mod writes;

pub use account::{AccountBal, AccountInfoBal, StorageBal};
pub use alloy_eip7928::BlockAccessIndex;
pub use writes::BalWrites;

use crate::{Account, AccountId, AccountInfo};
use alloy_eip7928::BlockAccessList as AlloyBal;
use primitives::{Address, AddressIndexMap, StorageKey, StorageValue};

/// BAL structure.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bal {
    /// Accounts bal.
    pub accounts: AddressIndexMap<AccountBal>,
}

impl FromIterator<(Address, AccountBal)> for Bal {
    fn from_iter<I: IntoIterator<Item = (Address, AccountBal)>>(iter: I) -> Self {
        Self {
            accounts: iter.into_iter().collect(),
        }
    }
}

impl Bal {
    /// Create a new BAL builder.
    pub fn new() -> Self {
        Self {
            accounts: AddressIndexMap::default(),
        }
    }

    /// Pretty print the entire BAL structure in a human-readable format.
    #[cfg(feature = "std")]
    pub fn pretty_print(&self) {
        println!("=== Block Access List (BAL) ===");
        println!("Total accounts: {}", self.accounts.len());
        println!();

        if self.accounts.is_empty() {
            println!("(empty)");
            return;
        }

        // Sort accounts by address before printing
        let mut sorted_accounts: Vec<_> = self.accounts.iter().collect();
        sorted_accounts.sort_unstable_by_key(|(address, _)| *address);

        for (idx, (address, account)) in sorted_accounts.into_iter().enumerate() {
            println!("Account #{idx} - Address: {address:?}");
            println!("  Account Info:");

            // Print nonce writes
            if account.account_info.nonce.is_empty() {
                println!("    Nonce: (read-only, no writes)");
            } else {
                println!("    Nonce writes:");
                for (bal_index, nonce) in &account.account_info.nonce.writes {
                    println!("      [{bal_index}] -> {nonce}");
                }
            }

            // Print balance writes
            if account.account_info.balance.is_empty() {
                println!("    Balance: (read-only, no writes)");
            } else {
                println!("    Balance writes:");
                for (bal_index, balance) in &account.account_info.balance.writes {
                    println!("      [{bal_index}] -> {balance}");
                }
            }

            // Print code writes
            if account.account_info.code.is_empty() {
                println!("    Code: (read-only, no writes)");
            } else {
                println!("    Code writes:");
                for (bal_index, (code_hash, bytecode)) in &account.account_info.code.writes {
                    println!(
                        "      [{}] -> hash: {:?}, size: {} bytes",
                        bal_index,
                        code_hash,
                        bytecode.len()
                    );
                }
            }

            // Print storage writes
            println!("  Storage:");
            if account.storage.storage.is_empty() {
                println!("    (no storage slots)");
            } else {
                println!("    Total slots: {}", account.storage.storage.len());
                for (storage_key, storage_writes) in &account.storage.storage {
                    println!("    Slot: {storage_key:#x}");
                    if storage_writes.is_empty() {
                        println!("      (read-only, no writes)");
                    } else {
                        println!("      Writes:");
                        for (bal_index, value) in &storage_writes.writes {
                            println!("        [{bal_index}] -> {value:?}");
                        }
                    }
                }
            }

            println!();
        }
        println!("=== End of BAL ===");
    }

    #[inline]
    /// Extend BAL with account.
    pub fn update_account(
        &mut self,
        bal_index: BlockAccessIndex,
        address: Address,
        account: &Account,
    ) {
        let bal_account = self.accounts.entry(address).or_default();
        bal_account.update(bal_index, account);
    }

    /// Populate account from BAL. Return true if account info got changed.
    pub fn populate_account_info(
        &self,
        account_id: AccountId,
        bal_index: BlockAccessIndex,
        account: &mut AccountInfo,
    ) -> Result<bool, BalError> {
        let Some((_, bal_account)) = self.accounts.get_index(account_id.get()) else {
            return Err(BalError::InvalidAccountId { account_id });
        };
        account.account_id = Some(account_id);

        Ok(bal_account.populate_account_info(bal_index, account))
    }

    /// Populate storage slot from BAL.
    ///
    /// If slot is not found in BAL, it will return an error.
    #[inline]
    pub fn populate_storage_slot_by_account_id(
        &self,
        account_id: AccountId,
        bal_index: BlockAccessIndex,
        key: StorageKey,
        value: &mut StorageValue,
    ) -> Result<(), BalError> {
        let Some((address, bal_account)) = self.accounts.get_index(account_id.get()) else {
            return Err(BalError::InvalidAccountId { account_id });
        };

        if let Some(bal_value) = bal_account.storage.get(address, key, bal_index)? {
            *value = bal_value;
        };

        Ok(())
    }

    /// Populate storage slot from BAL by account address.
    #[inline]
    pub fn populate_storage_slot(
        &self,
        account_address: Address,
        bal_index: BlockAccessIndex,
        key: StorageKey,
        value: &mut StorageValue,
    ) -> Result<(), BalError> {
        let Some(bal_account) = self.accounts.get(&account_address) else {
            return Err(BalError::AccountNotFound {
                address: account_address,
            });
        };

        if let Some(bal_value) = bal_account.storage.get(&account_address, key, bal_index)? {
            *value = bal_value;
        };
        Ok(())
    }

    /// Get storage from BAL.
    pub fn account_storage(
        &self,
        account_id: AccountId,
        key: StorageKey,
        bal_index: BlockAccessIndex,
    ) -> Result<StorageValue, BalError> {
        let Some((address, bal_account)) = self.accounts.get_index(account_id.get()) else {
            return Err(BalError::InvalidAccountId { account_id });
        };

        let Some(storage_value) = bal_account.storage.get(address, key, bal_index)? else {
            return Err(BalError::SlotNotFound {
                address: *address,
                slot: key,
            });
        };

        Ok(storage_value)
    }

    /// Consume `Bal` and create a canonical EIP-7928 [`AlloyBal`].
    ///
    /// The returned access list is ordered deterministically: accounts are
    /// sorted lexicographically by address, and each account's nested reads and
    /// changes are sorted by [`AccountBal::into_alloy_account`].
    ///
    /// This matches the EIP-7928 ordering requirements:
    /// <https://eips.ethereum.org/EIPS/eip-7928#ordering-uniqueness-and-determinism>.
    pub fn into_alloy_bal(self) -> AlloyBal {
        let mut alloy_bal = AlloyBal::from_iter(
            self.accounts
                .into_iter()
                .map(|(address, account)| account.into_alloy_account(address)),
        );
        alloy_bal.sort_unstable_by_key(|a| a.address);
        alloy_bal
    }
}

/// Error returned when a BAL (Block Access List, [EIP-7928]) lookup
/// cannot find data the caller expected to be present.
///
/// A BAL is supposed to enumerate every account and storage slot a block
/// will touch, so when execution queries the BAL for an entry that is
/// missing, the BAL is either malformed or being consulted for state that
/// it does not cover. Each variant identifies which kind of lookup failed
/// and carries the key that was queried so callers can report it.
///
/// Produced by [`Bal`] read paths ([`Bal::populate_account_info`],
/// [`Bal::populate_storage_slot`], [`Bal::populate_storage_slot_by_account_id`],
/// [`Bal::account_storage`], [`StorageBal::get`], [`StorageBal::get_bal_writes`])
/// and surfaced through `BalState` / `BalDatabase` in `revm-database-interface`,
/// where it is wrapped into `EvmDatabaseError::Bal` before reaching the EVM.
///
/// [EIP-7928]: https://eips.ethereum.org/EIPS/eip-7928
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BalError {
    /// The address was not present in the BAL's accounts map.
    ///
    /// Returned by address-keyed lookups (e.g. `BalState::get_account_id`,
    /// `BalState::storage`, `Bal::populate_storage_slot`) when the BAL is
    /// attached but does not list this account. Means the BAL is
    /// incomplete for the access being attempted.
    AccountNotFound {
        /// Address that was not found.
        address: Address,
    },
    /// The supplied [`AccountId`] index is out of range for the BAL's
    /// accounts map.
    ///
    /// `AccountId`s are positional indices into the BAL — they are only
    /// valid for the same BAL they were obtained from. This variant
    /// indicates a stale or mismatched id was used (e.g. an id from a
    /// different BAL, or one created before the current BAL was built).
    InvalidAccountId {
        /// Account id that was supplied.
        account_id: AccountId,
    },
    /// The account exists in the BAL but the requested storage slot is not
    /// listed under it.
    ///
    /// Returned by storage lookups when the account is covered by the BAL
    /// yet this particular slot was not declared. As with
    /// [`BalError::AccountNotFound`], this indicates the BAL is incomplete
    /// for the access being attempted.
    SlotNotFound {
        /// Address of the account whose slot was missing.
        address: Address,
        /// Storage slot that was not found.
        slot: StorageKey,
    },
}

impl core::fmt::Display for BalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AccountNotFound { address } => {
                write!(f, "Account {address} not found in BAL")
            }
            Self::InvalidAccountId { account_id } => {
                write!(f, "Invalid BAL account id {}", account_id.get())
            }
            Self::SlotNotFound { address, slot } => {
                write!(f, "Slot {slot:#x} not found in BAL for account {address}")
            }
        }
    }
}

impl core::error::Error for BalError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eip7928::{
        AccountChanges as AlloyAccountChanges, BalanceChange as AlloyBalanceChange,
        CodeChange as AlloyCodeChange, NonceChange as AlloyNonceChange,
        SlotChanges as AlloySlotChanges, StorageChange as AlloyStorageChange,
    };
    use bytecode::Bytecode;
    use primitives::{Bytes, B256, U256};
    use std::collections::BTreeMap;

    fn code(byte: u8) -> (B256, Bytecode) {
        let bytecode = Bytecode::new_raw(vec![byte].into());
        (bytecode.hash_slow(), bytecode)
    }

    const fn idx(index: u64) -> BlockAccessIndex {
        BlockAccessIndex::new(index)
    }

    #[test]
    fn into_alloy_bal_canonicalizes_eip_7928_ordering() {
        let low_address = Address::with_last_byte(1);
        let high_address = Address::with_last_byte(2);

        let unordered_account = AccountBal {
            account_info: AccountInfoBal {
                nonce: BalWrites {
                    writes: vec![(idx(9), 90), (idx(4), 40)],
                    ..Default::default()
                },
                balance: BalWrites {
                    writes: vec![(idx(5), U256::from(50)), (idx(2), U256::from(20))],
                    ..Default::default()
                },
                code: BalWrites {
                    writes: vec![(idx(7), code(7)), (idx(3), code(3))],
                    ..Default::default()
                },
                code_adoptions: Default::default(),
            },
            storage: StorageBal {
                storage: BTreeMap::from([
                    (
                        U256::from(4),
                        BalWrites {
                            writes: vec![(idx(8), U256::from(80)), (idx(6), U256::from(60))],
                            ..Default::default()
                        },
                    ),
                    (U256::from(1), BalWrites::default()),
                    (
                        U256::from(2),
                        BalWrites {
                            writes: vec![(idx(3), U256::from(30)), (idx(1), U256::from(10))],
                            ..Default::default()
                        },
                    ),
                    (U256::from(3), BalWrites::default()),
                ]),
            },
        };

        let alloy_bal = Bal::from_iter([
            (high_address, AccountBal::default()),
            (low_address, unordered_account),
        ])
        .into_alloy_bal();

        assert_eq!(
            alloy_bal
                .iter()
                .map(|account| account.address)
                .collect::<Vec<_>>(),
            vec![low_address, high_address]
        );

        let account = &alloy_bal[0];
        assert_eq!(account.storage_reads, vec![U256::from(1), U256::from(3)]);
        assert_eq!(
            account
                .storage_changes
                .iter()
                .map(|slot| slot.slot)
                .collect::<Vec<_>>(),
            vec![U256::from(2), U256::from(4)]
        );
        assert_eq!(
            account.storage_changes[0]
                .changes
                .iter()
                .map(|change| change.block_access_index)
                .collect::<Vec<_>>(),
            vec![idx(1), idx(3)]
        );
        assert_eq!(
            account.storage_changes[1]
                .changes
                .iter()
                .map(|change| change.block_access_index)
                .collect::<Vec<_>>(),
            vec![idx(6), idx(8)]
        );
        assert_eq!(
            account
                .balance_changes
                .iter()
                .map(|change| change.block_access_index)
                .collect::<Vec<_>>(),
            vec![idx(2), idx(5)]
        );
        assert_eq!(
            account
                .nonce_changes
                .iter()
                .map(|change| change.block_access_index)
                .collect::<Vec<_>>(),
            vec![idx(4), idx(9)]
        );
        assert_eq!(
            account
                .code_changes
                .iter()
                .map(|change| change.block_access_index)
                .collect::<Vec<_>>(),
            vec![idx(3), idx(7)]
        );
    }

    #[test]
    fn try_from_alloy_decodes_block_access_list() {
        let address = Address::with_last_byte(1);
        let code_bytes = Bytes::from_static(&[0x60, 0x00]);
        let alloy_bal = vec![AlloyAccountChanges {
            address,
            code_changes: vec![AlloyCodeChange::new(idx(1), code_bytes.clone())],
            ..Default::default()
        }];

        let bal = Bal::try_from_alloy(alloy_bal).unwrap();
        let account = bal.accounts.get(&address).unwrap();
        let (_, bytecode) = &account.account_info.code.writes[0].1;

        assert_eq!(bytecode.original_bytes(), code_bytes);
    }

    #[test]
    fn clone_from_alloy_matches_owned_conversion() {
        let address = Address::with_last_byte(1);
        let code_bytes = Bytes::from_static(&[0x60, 0x00]);
        let alloy_bal = vec![AlloyAccountChanges {
            address,
            storage_changes: vec![AlloySlotChanges::new(
                U256::from(1),
                vec![AlloyStorageChange::new(idx(1), U256::from(10))],
            )],
            storage_reads: vec![U256::from(2)],
            balance_changes: vec![AlloyBalanceChange::new(idx(2), U256::from(20))],
            nonce_changes: vec![AlloyNonceChange::new(idx(3), 30)],
            code_changes: vec![AlloyCodeChange::new(idx(4), code_bytes.clone())],
        }];

        let borrowed = Bal::clone_from_alloy(&alloy_bal).unwrap();
        let owned = Bal::try_from_alloy(alloy_bal.clone()).unwrap();

        assert_eq!(borrowed, owned);
        assert_eq!(alloy_bal[0].code_changes[0].new_code(), &code_bytes);
    }

    #[test]
    fn try_from_alloy_errors_on_invalid_code_change() {
        let alloy_bal = vec![AlloyAccountChanges {
            address: Address::with_last_byte(1),
            code_changes: vec![AlloyCodeChange::new(idx(1), vec![0xef, 0x01, 0xde].into())],
            ..Default::default()
        }];

        assert!(Bal::try_from_alloy(alloy_bal).is_err());
    }

    #[test]
    fn clone_from_alloy_errors_on_invalid_code_change() {
        let alloy_bal = vec![AlloyAccountChanges {
            address: Address::with_last_byte(1),
            code_changes: vec![AlloyCodeChange::new(idx(1), vec![0xef, 0x01, 0xde].into())],
            ..Default::default()
        }];

        assert!(Bal::clone_from_alloy(&alloy_bal).is_err());
    }
    #[test]
    fn adoption_resolves_only_earlier_deposits_and_roundtrips_as_hash() {
        let code = Bytes::from_static(&[0x60, 42, 0x00]);
        let hash = primitives::keccak256(&code);
        let source = Address::with_last_byte(1);
        let target = Address::with_last_byte(2);
        for deposited_at in [1, 2, 3] {
            let input = vec![
                AlloyAccountChanges {
                    address: source,
                    code_changes: vec![AlloyCodeChange::new(idx(deposited_at), code.clone())],
                    ..Default::default()
                },
                AlloyAccountChanges {
                    address: target,
                    code_changes: vec![AlloyCodeChange::new_hash(idx(2), hash)],
                    ..Default::default()
                },
            ];
            let bal = Bal::try_from_alloy(input.clone()).unwrap();
            assert_eq!(Bal::clone_from_alloy(&input).unwrap(), bal);
            let mut info = AccountInfo::default();
            assert!(bal.accounts[&target].populate_account_info(idx(3), &mut info));
            assert_eq!(info.code_hash, hash);
            assert_eq!(
                info.code.as_ref().map(Bytecode::original_bytes),
                (deposited_at < 2).then_some(code.clone())
            );
            assert_eq!(bal.into_alloy_bal(), input);
        }
    }

    #[test]
    fn code_adoption_returning_to_original_removes_bal_write() {
        let original = AccountInfo::default();
        let mut account = Account::from(original.clone());
        account.info = original
            .clone()
            .with_code(Bytecode::new_legacy(Bytes::from_static(&[0x00])));
        account.status.insert(crate::AccountStatus::CodeAdopted);
        let mut bal = AccountBal::default();
        bal.update(idx(1), &account);
        assert_eq!(bal.code_adoptions.len(), 1);
        assert_eq!(bal.code.writes.len(), 1);
        account.info = original;
        bal.update(idx(1), &account);
        assert!(bal.code.writes.is_empty());
        assert!(bal.code_adoptions.is_empty());
    }

    fn record_system_call_code(
        bal: &mut AccountBal,
        index: u64,
        original: &AccountInfo,
        present: &AccountInfo,
        adopted: bool,
    ) {
        let mut account = Account::from(original.clone());
        account.info = present.clone();
        account.mark_touch();
        if adopted {
            account.status.insert(crate::AccountStatus::CodeAdopted);
        }
        bal.update(idx(index), &account);
    }

    #[test]
    fn code_adoption_survives_later_system_calls_at_the_same_index() {
        let original = AccountInfo::default().with_code(code(0).1);
        let first = AccountInfo::default().with_code(code(1).1);
        let second = AccountInfo::default().with_code(code(2).1);
        for index in [0, 1] {
            for readopt in [false, true] {
                let mut bal = AccountBal::default();
                record_system_call_code(&mut bal, index, &original, &first, true);
                let final_info = if readopt { &second } else { &first };
                record_system_call_code(&mut bal, index, &first, final_info, readopt);
                record_system_call_code(&mut bal, index, final_info, final_info, false);

                let account = bal.into_alloy_account(Address::with_last_byte(1));
                assert_eq!(
                    account.code_changes.len(),
                    1,
                    "index={index}, readopt={readopt}"
                );
                assert_eq!(account.code_changes[0].block_access_index, idx(index));
                assert_eq!(
                    account.code_changes[0].adopted_code_hash(),
                    Some(final_info.code_hash)
                );
            }
        }
    }

    #[test]
    fn system_call_readoption_to_original_removes_the_net_change() {
        let original = AccountInfo::default().with_code(code(0).1);
        let adopted = AccountInfo::default().with_code(code(1).1);
        let mut bal = AccountBal::default();
        record_system_call_code(&mut bal, 0, &original, &adopted, true);
        record_system_call_code(&mut bal, 0, &adopted, &original, true);
        assert!(bal.code.writes.is_empty());
        assert!(bal.code_adoptions.is_empty());
    }

    #[test]
    fn system_call_adoptions_keep_distinct_access_indices() {
        let original = AccountInfo::default().with_code(code(0).1);
        let first = AccountInfo::default().with_code(code(1).1);
        let second = AccountInfo::default().with_code(code(2).1);
        let mut bal = AccountBal::default();
        for (index, before, after) in [
            (0, &original, &first),
            (1, &first, &second),
            (2, &second, &original),
        ] {
            record_system_call_code(&mut bal, index, before, after, true);
            record_system_call_code(&mut bal, index, after, after, false);
        }
        let account = bal.into_alloy_account(Address::with_last_byte(1));
        assert_eq!(account.code_changes.len(), 3);
        for (change, (index, info)) in
            account
                .code_changes
                .iter()
                .zip([(0, &first), (1, &second), (2, &original)])
        {
            assert_eq!(change.block_access_index, idx(index));
            assert_eq!(change.adopted_code_hash(), Some(info.code_hash));
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn system_call_code_baseline_survives_serialization() {
        let original = AccountInfo::default().with_code(code(0).1);
        let adopted = AccountInfo::default().with_code(code(1).1);
        let mut bal = AccountBal::default();
        let empty = postcard::to_allocvec(&bal).unwrap();
        assert_eq!(postcard::from_bytes::<AccountBal>(&empty).unwrap(), bal);

        record_system_call_code(&mut bal, 0, &original, &adopted, true);
        let encoded = postcard::to_allocvec(&bal).unwrap();
        let mut decoded: AccountBal = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, bal);
        record_system_call_code(&mut decoded, 0, &adopted, &original, true);
        assert!(decoded.code.writes.is_empty());
        assert!(decoded.code_adoptions.is_empty());
    }

    #[test]
    fn system_call_storage_writes_keep_the_phase_baseline() {
        let key = U256::from(7);
        for index in [0, 1] {
            let mut bal = StorageBal::default();
            for (before, after) in [(0, 42), (42, 42), (42, 42)] {
                let storage = crate::EvmStorage::from_iter([(
                    key,
                    crate::EvmStorageSlot::new_changed(
                        U256::from(before),
                        U256::from(after),
                        crate::TransactionId::ZERO,
                    ),
                )]);
                bal.update(idx(index), &storage);
            }
            assert_eq!(bal.storage[&key].writes, vec![(idx(index), U256::from(42))]);

            let restored = crate::EvmStorage::from_iter([(
                key,
                crate::EvmStorageSlot::new_changed(
                    U256::from(42),
                    U256::ZERO,
                    crate::TransactionId::ZERO,
                ),
            )]);
            bal.update(idx(index), &restored);
            assert!(bal.storage[&key].writes.is_empty());
        }
    }

    #[test]
    fn system_call_account_writes_keep_the_phase_baseline() {
        let original = AccountInfo::default()
            .with_balance(U256::from(10))
            .with_nonce(1);
        let changed = AccountInfo::default()
            .with_balance(U256::from(12))
            .with_nonce(2);
        let mut bal = AccountBal::default();
        record_system_call_code(&mut bal, 0, &original, &changed, false);
        record_system_call_code(&mut bal, 0, &changed, &changed, false);
        assert_eq!(bal.balance.writes, vec![(idx(0), U256::from(12))]);
        assert_eq!(bal.nonce.writes, vec![(idx(0), 2)]);
        record_system_call_code(&mut bal, 0, &changed, &original, false);
        assert!(bal.balance.writes.is_empty());
        assert!(bal.nonce.writes.is_empty());
    }
}
