//! [EIP-7906] transaction assertion constants and selector types.
//!
//! [EIP-7906]: <https://eips.ethereum.org/EIPS/eip-7906>

/// `TXTRACE` opcode byte.
pub const TXTRACE_OPCODE: u8 = 0xB6;
/// `EVENTDATACOPY` opcode byte.
pub const EVENTDATACOPY_OPCODE: u8 = 0xB7;

/// Default warm-read gas charged by `TXTRACE`.
pub const TXTRACE_GAS_COST: u64 = 100;
/// Fixed gas charged by `EVENTDATACOPY`, before memory expansion and copying.
pub const EVENTDATACOPY_GAS_COST: u64 = 3;

/// A `TXTRACE` selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TxTraceParam {
    /// Number of accounts with a net balance change.
    BalancesChanged = 0x00,
    /// Number of address and slot pairs with a net storage change.
    SlotsChanged = 0x01,
    /// Number of accounts with a net code-hash change.
    CodesChanged = 0x02,
    /// Number of accounts with a net account-nonce change.
    NoncesChanged = 0x03,
    /// Address for a balance-change entry.
    BalanceChangeAddress = 0x04,
    /// Balance at transaction start.
    BalanceBefore = 0x05,
    /// Balance at the time of the assertion.
    BalanceAfter = 0x06,
    /// Address for a storage-change entry.
    SlotChangeAddress = 0x07,
    /// Storage value at transaction start.
    SlotValueBefore = 0x08,
    /// Storage value at the time of the assertion.
    SlotValueAfter = 0x09,
    /// Key for a storage-change entry.
    SlotKey = 0x0a,
    /// Address for a code-change entry.
    CodeChangeAddress = 0x0b,
    /// Stored code hash at transaction start.
    CodeHashBefore = 0x0c,
    /// Stored code hash at the time of the assertion.
    CodeHashAfter = 0x0d,
    /// Address for a nonce-change entry.
    NonceChangeAddress = 0x0e,
    /// Account nonce at transaction start.
    NonceBefore = 0x0f,
    /// Account nonce at the time of the assertion.
    NonceAfter = 0x10,
    /// Number of transaction events.
    EventsCount = 0x11,
    /// Emitting address of an event.
    EventAddress = 0x12,
    /// Number of topics in an event.
    EventTopicCount = 0x13,
    /// First event topic.
    EventTopic0 = 0x14,
    /// Second event topic.
    EventTopic1 = 0x15,
    /// Third event topic.
    EventTopic2 = 0x16,
    /// Fourth event topic.
    EventTopic3 = 0x17,
    /// Length of the event data in bytes.
    EventDataLength = 0x18,
    /// Amount collected from the payer on payment approval.
    GasPreCharge = 0x19,
    /// Address that approved payment.
    GasPayerAddress = 0x1a,
}

impl TxTraceParam {
    /// Returns whether this selector requires its index operand to be zero.
    pub const fn requires_zero_index(self) -> bool {
        matches!(
            self,
            Self::BalancesChanged
                | Self::SlotsChanged
                | Self::CodesChanged
                | Self::NoncesChanged
                | Self::EventsCount
                | Self::GasPreCharge
                | Self::GasPayerAddress
        )
    }
}

macro_rules! selector_conversions {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        impl From<$name> for u8 {
            fn from(value: $name) -> Self {
                value as Self
            }
        }

        impl TryFrom<u8> for $name {
            type Error = u8;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $(x if x == Self::$variant as u8 => Ok(Self::$variant),)+
                    _ => Err(value),
                }
            }
        }
    };
}

selector_conversions!(TxTraceParam {
    BalancesChanged,
    SlotsChanged,
    CodesChanged,
    NoncesChanged,
    BalanceChangeAddress,
    BalanceBefore,
    BalanceAfter,
    SlotChangeAddress,
    SlotValueBefore,
    SlotValueAfter,
    SlotKey,
    CodeChangeAddress,
    CodeHashBefore,
    CodeHashAfter,
    NonceChangeAddress,
    NonceBefore,
    NonceAfter,
    EventsCount,
    EventAddress,
    EventTopicCount,
    EventTopic0,
    EventTopic1,
    EventTopic2,
    EventTopic3,
    EventDataLength,
    GasPreCharge,
    GasPayerAddress,
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_ranges_are_complete_and_reject_reserved_values() {
        for value in 0x00..=0x1A {
            assert_eq!(u8::from(TxTraceParam::try_from(value).unwrap()), value);
        }
        assert_eq!(TxTraceParam::try_from(0x1B), Err(0x1B));
    }
}
