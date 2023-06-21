//! Crate defining the Keyring Program

#![deny(missing_docs)]
#![cfg_attr(not(test), forbid(unsafe_code))]

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;
pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
