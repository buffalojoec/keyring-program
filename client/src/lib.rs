//! Crate defining the Keyring Program Client

#![deny(missing_docs)]
#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod algorithm;
pub mod error;
pub mod keyring;

pub use spl_keyring_program::{state, tlv};
