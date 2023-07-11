//! Crate defining the Keyring Program Client

#![deny(missing_docs)]
#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod error;
pub mod keyring;
pub mod keystore;
