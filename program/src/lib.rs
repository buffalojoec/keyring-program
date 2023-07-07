#![deny(missing_docs)]
#![cfg_attr(not(test), forbid(unsafe_code))]

//! Crate defining the Keyring Program

pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
pub mod tlv;

// #[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;

solana_program::declare_id!("GBvWerDWxo4yN8cJJU8CiGNhuK3WydCu19LcBRSL9ydX");
