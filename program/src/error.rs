//! Program errors

use spl_program_error::*;

/// Errors focused on the format of the provided keystore entry buffer
#[spl_program_error]
pub enum KeyringProgramError {
    /// Invalid format for keystore entry: Entry
    #[error("Invalid format for keystore entry: Entry")]
    InvalidFormatForEntry,
    /// Invalid format for keystore entry: Key
    #[error("Invalid format for keystore entry: Key")]
    InvalidFormatForKey,
    /// Invalid format for keystore entry: Config
    #[error("Invalid format for keystore entry: Config")]
    InvalidFormatForConfig,
    /// Invalid format for keystore entry: Config Entry
    #[error("Invalid format for keystore entry: Config Entry")]
    InvalidFormatForConfigEntry,
    /// Keystore entry not found
    #[error("Keystore entry not found")]
    KeystoreEntryNotFound,
}
