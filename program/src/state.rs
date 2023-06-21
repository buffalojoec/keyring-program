//! Keyring Program state types

use {
    solana_program::{entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey},
    spl_type_length_value::discriminator::Discriminator,
};

/// Struct for managing a slice of keystore entries.
///
/// The data within a keystore account is managed using nested TLV entries.
/// * T: The new entry discriminator (marks the start of a new keystore entry)
/// * L: The length of the entry
/// * V: The data of the entry
///     * (Encryption key)
///         * T: The algorithm discriminator (provided by sRFC workflow)
///         * L: The length of the key
///         * V: The key itself
///     * (Additional configurations)
///         * T: The configuration discriminator (marks additional
///           configurations are present)
///         * L: The total length of the configuration data
///         * V: The configuration data
///             * (Configuration: `K, V`)
///                 * T: The configuration key (provided by sRFC workflow)
///                 * L: The configuration value length
///                 * T: The configuration value
///
/// Entries are deserialized using a recursive TLV traversal method
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Keystore {}
impl Keystore {
    /// String literal seed prefix
    const SEED_PREFIX: &'static str = "keystore";
    /// The TLV discriminator for keystore entries without additional
    /// configurations: [0, 0, 0, 0, 0, 0, 0, 0]
    const NEW_ENTRY_DISCRIMINATOR: Discriminator = Discriminator::new([0u8; 8]);
    /// The TLV discriminator for keystore entries _with_ additional
    /// configurations: [1, 1, 1, 1, 1, 1, 1, 1]
    const CONFIGURATION_DISCRIMINATOR: Discriminator = Discriminator::new([1u8; 8]);

    /// Returns the seeds for this account as a vector of slices
    pub fn seeds<'s>(authority: &'s Pubkey) -> Vec<&'s [u8]> {
        vec![Self::SEED_PREFIX.as_bytes(), authority.as_ref()]
    }

    /// Returns the program-derived address and bump seed for this account type
    /// using the provided arguments
    pub fn pda(program_id: &Pubkey, authority: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&Self::seeds(authority), program_id)
    }

    /// Validates a passed `Pubkey` against the `Pubkey` returned from the
    /// `pda(&self, ..)` method, then returns the bump seed
    pub fn check_pda(
        program_id: &Pubkey,
        authority: &Pubkey,
        pda: &Pubkey,
    ) -> Result<u8, ProgramError> {
        let (pda_check, bump_seed) = Self::pda(program_id, authority);
        if pda != &pda_check {
            return Err(ProgramError::InvalidSeeds);
        }
        Ok(bump_seed)
    }

    /// Adds a new keystore entry to an existing buffer using nested TLV
    pub fn add_key(keystore_data: &mut [u8], new_key_data: Vec<u8>) -> ProgramResult {
        // TODO!
        Ok(())
    }

    /// Removes a keystore entry from an existing buffer using recursive TLV
    /// traversal
    pub fn remove_key(keystore_data: &mut [u8], remove_key_data: Vec<u8>) -> ProgramResult {
        // TODO!
        Ok(())
    }
}
