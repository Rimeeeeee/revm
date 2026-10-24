//! Alloy BAL types conversions.

// Re-export Alloy BAL types.
pub use alloy_eip7928::{
    AccountChanges as AlloyAccountChanges, BalanceChange as AlloyBalanceChange,
    BlockAccessList as AlloyBal, CodeChange as AlloyCodeChange, NonceChange as AlloyNonceChange,
    StorageChange as AlloyStorageChange,
};

use crate::bal::{AccountBal, Bal, BalWrites};
use bytecode::{Bytecode, BytecodeDecodeError};
use primitives::{AddressIndexMap, B256, U256};
use std::vec::Vec;

impl Bal {
    /// Convert an EIP-7928 [`AlloyBal`] into a [`Bal`].
    ///
    /// # Errors
    ///
    /// Returns [`BytecodeDecodeError`] if any account code change contains bytecode
    /// rejected by [`Bytecode::new_raw_checked`]. This currently happens for malformed
    /// EIP-7702 bytecode, such as bytes with the EIP-7702 magic prefix but an invalid
    /// length or unsupported version.
    #[inline]
    pub fn try_from_alloy(alloy_bal: AlloyBal) -> Result<Self, BytecodeDecodeError> {
        let mut accounts =
            AddressIndexMap::with_capacity_and_hasher(alloy_bal.len(), Default::default());
        for alloy_account in alloy_bal {
            let (address, account_bal) = AccountBal::try_from_alloy(alloy_account)?;
            accounts.insert(address, account_bal);
        }

        let mut bal = Self { accounts };
        bal.resolve_adopted_code();
        Ok(bal)
    }

    /// Clone EIP-7928 [`AlloyAccountChanges`] into a [`Bal`] without consuming the source.
    ///
    /// # Errors
    ///
    /// Returns [`BytecodeDecodeError`] if any account code change contains bytecode
    /// rejected by [`Bytecode::new_raw_checked`]. This currently happens for malformed
    /// EIP-7702 bytecode, such as bytes with the EIP-7702 magic prefix but an invalid
    /// length or unsupported version.
    #[inline]
    pub fn clone_from_alloy(
        alloy_bal: &[AlloyAccountChanges],
    ) -> Result<Self, BytecodeDecodeError> {
        let mut accounts =
            AddressIndexMap::with_capacity_and_hasher(alloy_bal.len(), Default::default());
        for alloy_account in alloy_bal {
            let (address, account_bal) = AccountBal::clone_from_alloy(alloy_account)?;
            accounts.insert(address, account_bal);
        }

        let mut bal = Self { accounts };
        bal.resolve_adopted_code();
        Ok(bal)
    }

    /// Resolve hash adoptions against bytecode deposited earlier in this block.
    fn resolve_adopted_code(&mut self) {
        let mut deposited: primitives::HashMap<B256, (crate::bal::BlockAccessIndex, Bytecode)> =
            primitives::HashMap::default();
        for account in self.accounts.values() {
            for (index, (hash, code)) in &account.account_info.code.writes {
                if !account.account_info.code_adoptions.contains(index) {
                    let entry = deposited.entry(*hash).or_insert((*index, code.clone()));
                    if *index < entry.0 {
                        *entry = (*index, code.clone());
                    }
                }
            }
        }
        for account in self.accounts.values_mut() {
            for (index, (hash, code)) in &mut account.account_info.code.writes {
                if account.account_info.code_adoptions.contains(index) {
                    if let Some((deposited_index, deposited_code)) = deposited.get(hash) {
                        if deposited_index < index {
                            *code = deposited_code.clone();
                        }
                    }
                }
            }
        }
    }
}

impl TryFrom<AlloyBal> for Bal {
    type Error = BytecodeDecodeError;

    #[inline]
    fn try_from(alloy_bal: AlloyBal) -> Result<Self, Self::Error> {
        Self::try_from_alloy(alloy_bal)
    }
}

impl From<Vec<AlloyBalanceChange>> for BalWrites<U256> {
    fn from(value: Vec<AlloyBalanceChange>) -> Self {
        Self {
            writes: value
                .into_iter()
                .map(|change| (change.block_access_index, change.post_balance))
                .collect(),
        }
    }
}

impl From<&[AlloyBalanceChange]> for BalWrites<U256> {
    fn from(value: &[AlloyBalanceChange]) -> Self {
        Self {
            writes: value
                .iter()
                .map(|change| (change.block_access_index, change.post_balance))
                .collect(),
        }
    }
}

impl From<Vec<AlloyNonceChange>> for BalWrites<u64> {
    fn from(value: Vec<AlloyNonceChange>) -> Self {
        Self {
            writes: value
                .into_iter()
                .map(|change| (change.block_access_index, change.new_nonce))
                .collect(),
        }
    }
}

impl From<&[AlloyNonceChange]> for BalWrites<u64> {
    fn from(value: &[AlloyNonceChange]) -> Self {
        Self {
            writes: value
                .iter()
                .map(|change| (change.block_access_index, change.new_nonce))
                .collect(),
        }
    }
}

impl From<Vec<AlloyStorageChange>> for BalWrites<U256> {
    fn from(value: Vec<AlloyStorageChange>) -> Self {
        Self {
            writes: value
                .into_iter()
                .map(|change| (change.block_access_index, change.new_value))
                .collect(),
        }
    }
}

impl From<&[AlloyStorageChange]> for BalWrites<U256> {
    fn from(value: &[AlloyStorageChange]) -> Self {
        Self {
            writes: value
                .iter()
                .map(|change| (change.block_access_index, change.new_value))
                .collect(),
        }
    }
}

impl TryFrom<Vec<AlloyCodeChange>> for BalWrites<(B256, Bytecode)> {
    type Error = BytecodeDecodeError;

    fn try_from(value: Vec<AlloyCodeChange>) -> Result<Self, Self::Error> {
        Ok(Self {
            writes: value
                .into_iter()
                .map(|change| {
                    // convert bytes to bytecode.
                    let hash = change.code_hash();
                    let index = change.block_access_index;
                    Bytecode::new_raw_checked(change.into_code())
                        .map(|bytecode| (index, (hash, bytecode)))
                })
                .collect::<Result<Vec<_>, Self::Error>>()?,
        })
    }
}

impl TryFrom<&[AlloyCodeChange]> for BalWrites<(B256, Bytecode)> {
    type Error = BytecodeDecodeError;

    fn try_from(value: &[AlloyCodeChange]) -> Result<Self, Self::Error> {
        Ok(Self {
            writes: value
                .iter()
                .map(|change| {
                    let hash = change.code_hash();
                    Bytecode::new_raw_checked(change.new_code().clone())
                        .map(|bytecode| (change.block_access_index, (hash, bytecode)))
                })
                .collect::<Result<Vec<_>, Self::Error>>()?,
        })
    }
}
