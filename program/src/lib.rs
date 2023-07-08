#![deny(missing_docs)]
#![cfg_attr(not(test), forbid(unsafe_code))]

//! Crate defining the Keyring Program

mod entrypoint;
pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
pub mod tlv;

solana_program::declare_id!("4ZXqc9x6DkRthFYxSwTqfDKpX55FfyckoXAdS34xECPu");
