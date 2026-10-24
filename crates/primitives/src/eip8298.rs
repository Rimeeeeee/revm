//! EIP-8298 SETCODEFROM code reuse.
//!
//! Specification: <https://github.com/ethereum/EIPs/blob/fa39156/EIPS/eip-8298.md>.

use crate::{address, Address};

/// Contracts called by the protocol from the system address during block processing.
pub const SYSTEM_CONTRACTS: [Address; 6] = [
    address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02"),
    address!("0000F90827F1C53a10cb7A02335B175320002935"),
    address!("00000961Ef480Eb55e80D19ad83579A64c007002"),
    address!("0000BBdDc7CE488642fb579F8B00f3a590007251"),
    address!("0000BFF46984E3725691FA540A8C7589300D8282"),
    address!("000064D678505AD48F8CCB093BC65613800E8282"),
];

/// Returns whether SETCODEFROM is forbidden for this execution-context account.
pub fn is_system_contract(address: Address) -> bool {
    SYSTEM_CONTRACTS.contains(&address)
}
