#![deny(missing_docs)]
#![cfg_attr(not(test), forbid(unsafe_code))]

//! Crate defining the Keyring Program

mod entrypoint;
pub mod instruction;
pub mod processor;
pub mod state;

solana_program::declare_id!("4UucrowYQqM6yHeRgoMW2HB2998W9cnVS6tx6nPMdpVn");
