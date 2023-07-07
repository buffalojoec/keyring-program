//! Error types for the Keyring Client

use {
    solana_sdk::program_error::ProgramError, spl_token_client::client::ProgramClientError,
    thiserror::Error,
};

/// Error types for the Keyring Client
#[derive(Error, Debug)]
pub enum KeyringError {
    /// Client errors
    #[error("client error: {0}")]
    Client(ProgramClientError),
    /// Program errors
    #[error("program error: {0}")]
    Program(#[from] ProgramError),
    /// Keystore not found
    #[error("Keystore not found")]
    KeystoreNotFound,
}
