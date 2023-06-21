//! Keyring Program state types

use {
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_program::{
        account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
        pubkey::Pubkey,
    },
    spl_type_length_value::discriminator::Discriminator,
};

/// Key-value entry for additional encryption algorithm configurations
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct KeystoreEntryConfigEntry {
    /// Configuration key discriminator
    pub key_discriminator: [u8; 8],
    /// Length of the configuration value
    pub value_length: u32,
    /// Configuration value
    pub value: Vec<u8>,
}

/// Configurations section in a keystore entry
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct KeystoreEntryConfig {
    /// Configuration discriminator
    pub config_discriminator: [u8; 8],
    /// Length of the configuration section
    pub config_length: u32,
    /// Vector of configuration entries
    pub entries: Vec<KeystoreEntryConfigEntry>,
}

/// Key section in a keystore entry
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct KeystoreEntryKey {
    /// Key discriminator (encryption algorithm)
    pub key_discriminator: [u8; 8],
    /// Length of the encryption key
    pub key_length: u32,
    /// Encryption key
    pub key: Vec<u8>,
}

/// A keystore entry
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct KeystoreEntry {
    /// Entry discriminator
    pub entry_discriminator: [u8; 8],
    /// Length of the entry
    pub entry_length: u32,
    /// Encryption key
    pub key: KeystoreEntryKey,
    /// Additional configurations
    pub config: Option<KeystoreEntryConfig>,
}

/// Struct for managing a vector of keystore entries.
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
#[derive(Clone, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct Keystore {
    entries: Vec<KeystoreEntry>,
}
impl Keystore {
    /// String literal seed prefix
    const SEED_PREFIX: &'static str = "keystore";

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
    pub fn add_key(keystore_info: &AccountInfo<'_>, add_key_data: Vec<u8>) -> ProgramResult {
        let mut keystore = Self::try_from_slice(&keystore_info.data.borrow())?;
        let add_key = KeystoreEntry::try_from_slice(&add_key_data)?;
        keystore.entries.push(add_key);
        keystore.serialize(&mut *keystore_info.data.borrow_mut())?;
        Ok(())
    }

    /// Removes a keystore entry from an existing buffer using recursive TLV
    /// traversal
    pub fn remove_key(keystore_info: &AccountInfo<'_>, remove_key_data: Vec<u8>) -> ProgramResult {
        let mut keystore = Self::try_from_slice(&keystore_info.data.borrow())?;
        let remove_key = KeystoreEntry::try_from_slice(&remove_key_data)?;
        keystore.entries.retain(|entry| entry != &remove_key);
        keystore.serialize(&mut *keystore_info.data.borrow_mut())?;
        Ok(())
    }
}
