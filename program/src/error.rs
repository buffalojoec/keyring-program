//! Program errors

use spl_program_error::*;

/// Errors that can be returned by the Keyring program.
#[spl_program_error]
pub enum KeyringProgramError {
    /// Placeholder
    #[error("Placeholder")]
    Placeholder,
}
